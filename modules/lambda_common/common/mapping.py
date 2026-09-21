"""Security Hub finding(ASFF) -> security_events 행 변환. (Lambda A)"""
import hashlib
import json
import re

from .scenarios import SCENARIOS

SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFORMATIONAL": "Info",
}

CRED_HINTS = ("UnauthorizedAccess:IAMUser", "CredentialAccess", "InstanceCredentialExfiltration",
              "Persistence:IAMUser", "PrivilegeEscalation:IAMUser", "Stealth:IAMUser")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _ts(value):
    """ASFF ISO8601(2026-09-21T03:04:05.123Z) -> MySQL DATETIME(UTC)."""
    if not value:
        return None
    return value.replace("T", " ").rstrip("Z").split(".")[0]


def _remote_ip(f):
    action = f.get("Action") or {}
    candidates = [
        (action.get("NetworkConnectionAction") or {}).get("RemoteIpDetails"),
        (action.get("AwsApiCallAction") or {}).get("RemoteIpDetails"),
    ]
    for probe in (action.get("PortProbeAction") or {}).get("PortProbeDetails") or []:
        candidates.append(probe.get("RemoteIpDetails"))
    for c in candidates:
        ip = (c or {}).get("IpAddressV4")
        if ip and IPV4.match(ip):
            return ip
    return None


def _access_key_user(f):
    for r in f.get("Resources") or []:
        d = (r.get("Details") or {}).get("AwsIamAccessKey") or {}
        if d.get("UserName"):
            return d.get("UserName"), d.get("AccessKeyId") or d.get("PrincipalId")
        d = (r.get("Details") or {}).get("AccessKey") or {}
        if d.get("UserName"):
            return d.get("UserName"), d.get("AccessKeyId")
    return None, None


def classify(f):
    """finding 이 대시보드 7개 시나리오 중 무엇인지 고른다."""
    product = (f.get("ProductName") or "").lower()
    types = " ".join(f.get("Types") or []) + " " + (f.get("GeneratorId") or "")
    rtype = ((f.get("Resources") or [{}])[0]).get("Type") or ""
    if "guardduty" in product:
        if "Portscan" in types or "PortProbe" in types:
            return "port"
        if any(h in types for h in CRED_HINTS):
            return "cred"
        return "generic"
    if "inspector" in product:
        return "vuln"
    if "analyzer" in product:
        return "s3" if "S3" in rtype else "generic"
    return "generic"


def finding_to_event(f):
    """저장할 필요가 없는 finding 이면 None."""
    if (f.get("Compliance") or {}).get("Status") == "PASSED":
        return None
    if f.get("RecordState") == "ARCHIVED" or (f.get("Workflow") or {}).get("Status") in (
        "RESOLVED", "SUPPRESSED"):
        return None

    kind = classify(f)
    sc = SCENARIOS[kind]
    resource = (f.get("Resources") or [{}])[0]
    ip = _remote_ip(f)
    user, key_id = _access_key_user(f)
    severity = SEVERITY.get((f.get("Severity") or {}).get("Label"), "Info")
    auto = (kind == "port" and ip is not None) or (kind == "cred" and user is not None)

    return {
        "id": "sh-" + hashlib.sha1(f["Id"].encode()).hexdigest()[:32],
        "service": f.get("ProductName") or "Security Hub",
        "severity": severity,
        "title": (f.get("Title") or sc["title"])[:255],
        "asset": ((resource.get("Type") or "") + " " + (resource.get("Id") or "").split("/")[-1]).strip()[:255] or None,
        "detected_at": _ts(f.get("UpdatedAt") or f.get("CreatedAt")),
        "status": "승인 대기" if auto else "검토 필요",
        "recommendation": sc["recommendation"],
        "auto_remediation": auto,
        "highlight_assets": sc["highlight"],
        "attack_path": sc["path"],
        "attacker_ip": ip,
        "request_url": None,
        "rule_name": ",".join(f.get("Types") or [])[:255] or None,
        "blocked": None,
        "block_result": None,
        # Remediation Lambda 가 params 를 다시 찾을 수 있도록 추출값을 함께 저장한다.
        "logs": json.dumps(
            {
                "source": "securityhub",
                "scenario": kind,
                "extracted": {"userName": user, "accessKeyId": key_id, "ip": ip},
                "finding": f,
            },
            ensure_ascii=False,
            default=str,
        ),
    }
