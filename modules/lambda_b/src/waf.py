"""WAF 로그 -> 이상 징후 이벤트 변환. (Lambda B)

WAF 로그 레코드(JSON)를 (공격유형, 출발지 IP) 별로 묶어 security_events 행 하나로 만든다.
"""
import hashlib
import json
import re
from collections import defaultdict

from common.scenarios import SCENARIOS

SQLI_RE = re.compile(r"(union(\s|\+|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\s*\(|information_schema|;\s*drop\s+table|--\s*$)", re.I)
XSS_RE = re.compile(r"(<\s*script|onerror\s*=|onload\s*=|javascript:|%3cscript)", re.I)
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.%2f|%2e%2e|/etc/passwd|/\.git|/\.env|phpmyadmin|wp-admin|/admin\b)", re.I)


def _rule_ids(rec):
    """이 요청에서 **실제로 걸린** 규칙 ID 만 모은다.

    ruleGroupList 에는 요청이 거쳐 간 모든 규칙 그룹이 들어 있으므로(걸리지 않았어도),
    ruleGroupId 는 쓰지 않는다. 걸린 규칙은 terminatingRule / nonTerminatingMatchingRules 에만 있다.
    """
    ids = []
    if rec.get("terminatingRuleId") and rec["terminatingRuleId"] != "Default_Action":
        ids.append(rec["terminatingRuleId"])
    for g in rec.get("ruleGroupList") or []:
        if g.get("terminatingRule"):
            ids.append(g["terminatingRule"].get("ruleId") or "")
        for r in g.get("nonTerminatingMatchingRules") or []:
            ids.append(r.get("ruleId") or "")
    return [i for i in ids if i]


def classify_record(rec, login_paths):
    """레코드 하나가 걸리는 공격 유형 집합. 정상 요청이면 빈 집합."""
    req = rec.get("httpRequest") or {}
    text = f"{req.get('uri', '')}?{req.get('args', '')}"
    rules = " ".join(_rule_ids(rec))
    hits = set()
    if "SQLi" in rules or SQLI_RE.search(text):
        hits.add("sqli")
    if "CrossSiteScripting" in rules or XSS_RE.search(text):
        hits.add("xss")
    if "LFI" in rules or "PathTraversal" in rules or TRAVERSAL_RE.search(text):
        hits.add("dir")
    if (req.get("httpMethod") or "").upper() == "POST" and (req.get("uri") or "") in login_paths:
        hits.add("brute")
    return hits


def detect(records, source, window_start, cfg):
    """records: WAF 로그 dict 목록, source: 'shop' | 'admin', window_start: epoch(초).

    같은 창(window)을 다시 처리해도 같은 id 가 나오도록 id 에 창 시작 시각을 넣는다.
    """
    groups = defaultdict(list)            # (type, ip) -> records
    uris = defaultdict(set)               # ip -> 요청한 서로 다른 경로
    for rec in records:
        ip = (rec.get("httpRequest") or {}).get("clientIp")
        if not ip:
            continue
        uris[ip].add((rec.get("httpRequest") or {}).get("uri"))
        for kind in classify_record(rec, cfg["login_paths"]):
            groups[(kind, ip)].append(rec)
    # 정상 요청도 짧은 시간에 서로 다른 경로를 훑으면 디렉터리 탐색으로 본다.
    for ip, seen in uris.items():
        if len(seen) >= cfg["dir_distinct_uris"] and ("dir", ip) not in groups:
            groups[("dir", ip)] = [r for r in records if (r.get("httpRequest") or {}).get("clientIp") == ip]

    events = []
    for (kind, ip), recs in groups.items():
        if kind == "brute" and len(recs) < cfg["brute_threshold"]:
            continue
        events.append(_to_event(kind, ip, recs, source, window_start, cfg))
    return events


def _severity(kind, count, cfg):
    if kind in ("sqli", "brute") and count >= cfg["critical_count"]:
        return "Critical"
    return {"sqli": "High", "brute": "High", "xss": "Medium", "dir": "Medium"}[kind]


def _to_event(kind, ip, recs, source, window_start, cfg):
    # brute_admin 은 맵 강조(관리자 경로 표시)를 위한 조회 키일 뿐이다.
    # scenario_type 은 화면 필터가 쓰는 7개 시나리오 값(brute)으로 고정한다.
    lookup_key = "brute_admin" if (kind == "brute" and source == "admin") else kind
    scenario = SCENARIOS[lookup_key]
    blocked_n = sum(1 for r in recs if r.get("action") == "BLOCK")
    if blocked_n == len(recs):
        result, status = "성공", "자동 완료"           # WAF 가 이미 전부 막았다
    elif blocked_n:
        result, status = "부분", "승인 대기"
    else:
        result, status = "실패", "승인 대기"           # 하나도 못 막음: 조치 필요
    first = (recs[0].get("httpRequest") or {})
    rules = sorted({i for r in recs for i in _rule_ids(r)})
    samples = [
        {"time": r.get("timestamp"), "action": r.get("action"), "httpRequest": r.get("httpRequest")}
        for r in recs[:3]
    ]
    key = f"waf-{source}-{kind}-{ip}-{window_start}"
    return {
        "id": key if len(key) < 250 else "waf-" + hashlib.sha1(key.encode()).hexdigest(),
        "service": "AWS WAF",
        "scenario_type": kind,
        "severity": _severity(kind, len(recs), cfg),
        "title": f"{scenario['title']} ({len(recs)}건)",
        "asset": "Admin ALB / Dashboard" if source == "admin" else "Shop ALB / Flask App",
        "detected_at": _fmt(max((r.get("timestamp") or 0) for r in recs) / 1000),
        "status": status,
        "recommendation": scenario["recommendation"],
        "auto_remediation": status != "자동 완료",
        "highlight_assets": scenario["highlight"],
        "attack_path": scenario["path"],
        "attacker_ip": ip,
        "request_url": f"{first.get('httpMethod', '')} {first.get('uri', '')}?{first.get('args', '')}".strip("? "),
        "rule_name": ", ".join(rules) or None,
        "blocked": blocked_n == len(recs),
        "block_result": result,
        "logs": json.dumps(
            {"source": "waf-logs", "waf": source, "count": len(recs), "blocked": blocked_n, "samples": samples},
            ensure_ascii=False, default=str),
    }


def _fmt(epoch):
    import datetime as dt
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
