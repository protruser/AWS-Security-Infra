"""Lambda Remediation: 대시보드에서 승인된 조치를 실행한다.

입력(event):
  {"event_id": "...", "action": "block_ip" | "restart_service" | "disable_access_key",
   "approver": "admin", "params": {...}}          # params 는 없으면 이벤트 로그에서 찾는다.
결과: remediation_history 행 추가 + security_events.status 갱신 + 결과 JSON 반환.
허용된 조치 3개 외에는 실행하지 않는다.
"""
import ipaddress
import json
import logging
import os
import time

import boto3
from common import db

logger = logging.getLogger()
logger.setLevel(logging.INFO)

IP_SET_NAME = os.environ.get("WAF_IP_SET_NAME", "")
IP_SET_ID = os.environ.get("WAF_IP_SET_ID", "")
INSTANCE_IDS = json.loads(os.environ.get("INSTANCE_IDS", "{}"))
PROTECTED_CIDRS = [ipaddress.ip_network(c) for c in json.loads(os.environ.get("PROTECTED_CIDRS", "[]"))]

# 서버에서 실행할 수 있는 명령은 여기에 적힌 것뿐이다.
RESTART_COMMANDS = {
    "k3s": "k3s kubectl rollout restart deployment --all -n default",
    "shop_app": "docker restart shop-app",
    "dashboard": "docker restart dashboard",
}


class RemediationError(Exception):
    pass


def block_ip(params):
    ip = ipaddress.ip_address(params.get("ip") or "")
    if ip.version != 4 or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise RemediationError(f"차단할 수 없는 IP: {ip}")
    if any(ip in net for net in PROTECTED_CIDRS):
        raise RemediationError(f"관리자 IP 대역은 차단하지 않는다: {ip}")
    waf = boto3.client("wafv2")
    for _ in range(3):
        cur = waf.get_ip_set(Name=IP_SET_NAME, Scope="REGIONAL", Id=IP_SET_ID)
        addrs = cur["IPSet"]["Addresses"]
        cidr = f"{ip}/32"
        if cidr in addrs:
            return f"이미 차단됨: {cidr}"
        try:
            waf.update_ip_set(Name=IP_SET_NAME, Scope="REGIONAL", Id=IP_SET_ID,
                              Addresses=addrs + [cidr], LockToken=cur["LockToken"])
            return f"WAF IP 차단 목록에 추가: {cidr}"
        except waf.exceptions.WAFOptimisticLockException:
            continue
    raise RemediationError("WAF IP 집합 갱신 충돌이 반복됨")


def restart_service(params):
    target = params.get("target")
    if target not in RESTART_COMMANDS or target not in INSTANCE_IDS:
        raise RemediationError(f"허용되지 않은 대상: {target}")
    ssm = boto3.client("ssm")
    cmd = ssm.send_command(InstanceIds=[INSTANCE_IDS[target]], DocumentName="AWS-RunShellScript",
                           Parameters={"commands": [RESTART_COMMANDS[target]]}, TimeoutSeconds=60)
    cid = cmd["Command"]["CommandId"]
    for _ in range(20):
        time.sleep(3)
        try:
            inv = ssm.get_command_invocation(CommandId=cid, InstanceId=INSTANCE_IDS[target])
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            if inv["Status"] != "Success":
                raise RemediationError(f"SSM {inv['Status']}: {inv.get('StandardErrorContent', '')[:200]}")
            return f"{target} 재시작 완료"
    raise RemediationError("SSM 명령이 제한 시간 안에 끝나지 않음")


def disable_access_key(params):
    user = params.get("userName")
    if not user:
        raise RemediationError("userName 이 없음")
    iam = boto3.client("iam")
    key_id = params.get("accessKeyId")
    done = []
    for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
        if k["Status"] == "Active" and (not key_id or k["AccessKeyId"] == key_id):
            iam.update_access_key(UserName=user, AccessKeyId=k["AccessKeyId"], Status="Inactive")
            done.append(k["AccessKeyId"])
    if not done:
        raise RemediationError(f"{user}: 비활성화할 활성 Access Key 가 없음")
    return f"{user} Access Key 비활성화: {', '.join(done)}"


ACTIONS = {"block_ip": block_ip, "restart_service": restart_service, "disable_access_key": disable_access_key}


def _params_from_event(row, params):
    """params 에 없는 값은 이벤트에 저장된 값에서 채운다."""
    merged = dict(params or {})
    merged.setdefault("ip", row.get("attacker_ip"))
    try:
        extracted = (json.loads(row.get("logs") or "{}").get("extracted")) or {}
    except ValueError:
        extracted = {}
    for k in ("userName", "accessKeyId"):
        if extracted.get(k):
            merged.setdefault(k, extracted[k])
    return merged


def lambda_handler(event, _context):
    event_id, action = event.get("event_id"), event.get("action")
    approver = event.get("approver") or "-"
    if action not in ACTIONS:
        return {"ok": False, "message": f"지원하지 않는 조치: {action}"}

    conn = db.get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM security_events WHERE id=%s", (event_id,))
        row = cur.fetchone()
        if not row:
            return {"ok": False, "message": f"이벤트 없음: {event_id}"}
        cur.execute(
            "INSERT INTO remediation_history (event_id, action_type, method, approver, status, result) "
            "VALUES (%s,%s,%s,%s,'진행 중','진행 중')",
            (event_id, action, event.get("method") or "수동", approver))
        history_id = cur.lastrowid

    try:
        detail = ACTIONS[action](_params_from_event(row, event.get("params")))
        ok, result = True, "성공"
    except Exception as exc:   # 실패도 이력에 남긴다
        logger.exception("remediation failed")
        ok, result, detail = False, "실패", str(exc)[:500]

    with conn.cursor() as cur:
        cur.execute("UPDATE remediation_history SET status=%s, result=%s, result_detail=%s, "
                    "completed_at=UTC_TIMESTAMP() WHERE id=%s",
                    ("완료" if ok else "실패", result, detail, history_id))
        if ok:
            cur.execute("UPDATE security_events SET status='조치 완료'"
                        + (", blocked=TRUE, block_result='성공'" if action == "block_ip" else "")
                        + " WHERE id=%s", (event_id,))
        else:
            cur.execute("UPDATE security_events SET status='조치 실패' WHERE id=%s", (event_id,))
    return {"ok": ok, "action": action, "message": detail, "history_id": history_id}
