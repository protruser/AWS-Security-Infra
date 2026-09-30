"""Security Hub finding(ASFF) -> security_events 행 변환. (Lambda A)"""
import hashlib
import json
import os
import re
import urllib.request

from .scenarios import SCENARIOS

SEVERITY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFORMATIONAL": "Info",
}

CRED_HINTS = ("UnauthorizedAccess:IAMUser", "CredentialAccess", "InstanceCredentialExfiltration",
              "Persistence:IAMUser", "PrivilegeEscalation:IAMUser", "Stealth:IAMUser",
              # 실제로 관측된 root 자격증명 사용, 침투테스트 도구의 IAM 자격증명
              # 사용도 자격증명 오남용이라 "cred"로 분류돼야 하는데 기존 목록에
              # 없어서 계속 generic으로 빠졌다.
              "Policy:IAMUser/RootCredentialUsage", "PenTest:IAMUser")
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
        # 5번 시나리오(취약 컨테이너 이미지)는 ECR 이미지 취약점만 해당한다.
        # EC2 인스턴스 패키지 취약점은 7개 시나리오 밖이라 generic으로 둔다.
        return "vuln" if "Ecr" in rtype else "generic"
    if "analyzer" in product:
        return "s3" if "S3" in rtype else "generic"
    return "generic"


_LONG_HEX = re.compile(r"^[0-9a-f]{20,}$", re.I)

# ECR 저장소 이름(마지막 경로 조각) -> 이미지를 빌드하는 GitHub 레포. 이 프로젝트는
# 이미지 태그로 git 커밋 SHA를 쓰므로, 태그가 곧 그 레포의 커밋을 가리킨다.
_GITHUB_REPO_BY_ECR_NAME = {
    "dashboard": "protruser/AWS-security",
    "shop-app": "protruser/AWS-Security-Service",
    "nginx": "protruser/AWS-Security-Service",
}
_commit_subject_cache = {}


def _commit_subject(github_repo, sha):
    """커밋 제목 한 줄(예: "flood 시나리오 추가"). 실패(네트워크·rate limit·404 등)
    하면 조용히 None을 반환한다 - 이 조회 하나 때문에 탐지 이벤트 저장 자체가
    막히면 안 되므로 타임아웃을 짧게 두고 예외를 전부 삼킨다. 같은 (레포, SHA)는
    이 Lambda 실행 환경이 살아있는 동안(웜 스타트) 캐시해서 재호출하지 않는다."""
    cache_key = (github_repo, sha)
    if cache_key in _commit_subject_cache:
        return _commit_subject_cache[cache_key]
    subject = None
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{github_repo}/commits/{sha}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "wonny-sec-lambda-a"},
        )
        token = os.environ.get("GITHUB_TOKEN", "").strip()
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=3) as response:
            # 커밋 API 응답은 변경 파일이 많으면 수백 KB까지도 간다. 앞부분만
            # 읽으면 JSON이 중간에 잘려서 파싱 자체가 실패한다(실제로 겪은 버그).
            data = json.loads(response.read(2_000_000))
        message = ((data.get("commit") or {}).get("message") or "").strip()
        subject = message.splitlines()[0][:120] if message else None
    except Exception:
        subject = None
    _commit_subject_cache[cache_key] = subject
    return subject


def _asset_label(resource):
    """사람이 읽을 수 있는 자산 이름. ECR 컨테이너 이미지는 Id 끝이 항상
    '.../sha256:<64자리 해시>'라서 기존처럼 Id의 마지막 경로만 쓰면 해시만 남는다.
    이 프로젝트는 이미지 태그로도 git 커밋 SHA(40자리)를 쓰기 때문에, 태그를
    그대로 붙여도 여전히 알아볼 수 없다. 대신 그 커밋의 제목을 가져와서 보여준다
    (예: "AwsEcrContainerImage wonny-sec/dashboard (flood 시나리오 추가)").
    커밋 조회가 안 되면 'latest' 같은 읽을 수 있는 태그 -> 저장소 이름 순으로
    물러난다."""
    kind = resource.get("Type") or ""
    if kind == "AwsEcrContainerImage":
        details = ((resource.get("Details") or {}).get("AwsEcrContainerImage")) or {}
        repo = details.get("RepositoryName")
        if repo:
            tags = details.get("ImageTags") or []
            sha_tag = next((t for t in tags if t and _LONG_HEX.match(t)), None)
            github_repo = _GITHUB_REPO_BY_ECR_NAME.get(repo.split("/")[-1])
            subject = _commit_subject(github_repo, sha_tag) if github_repo and sha_tag else None
            if subject:
                return f"{kind} {repo} ({subject})"
            readable_tag = next((t for t in tags if t and not _LONG_HEX.match(t)), None)
            return f"{kind} {repo}:{readable_tag}" if readable_tag else f"{kind} {repo}"
    return ((kind + " " + (resource.get("Id") or "").split("/")[-1]).strip()) or None


def _event_id(f, kind, resource):
    """컨테이너 이미지 취약점(vuln)은 원본 finding Id에 이미지 다이제스트가
    포함돼 있어서, 같은 CVE라도 이미지를 새로 빌드(=push)할 때마다 다른
    finding Id를 받는다. 그 결과 아직 안 고친 같은 취약점이 push할 때마다
    "새 이벤트"로 계속 쌓였다 - 레포+CVE+패키지 기준으로 안정적인 id를
    만들어서, 같은 취약점이 재스캔돼도 기존 이벤트가 갱신되게 한다
    (status는 upsert 시 일부러 안 덮어써서 이미 예외 처리/조치 완료된
    건 다시 안 열린다 - db.py의 UPSERT_EVENT 참고).
    다른 시나리오(port/cred 등)는 기존처럼 원본 finding Id를 그대로 쓴다."""
    if kind != "vuln":
        return "sh-" + hashlib.sha1(f["Id"].encode()).hexdigest()[:32]

    details = ((resource.get("Details") or {}).get("AwsEcrContainerImage")) or {}
    repo = details.get("RepositoryName") or ""
    vulns = f.get("Vulnerabilities") or []
    cve = (vulns[0].get("Id") if vulns else None) or ""
    if not cve:
        match = re.search(r"CVE-\d{4}-\d{4,}", f.get("Title") or "", re.I)
        cve = match.group(0).upper() if match else ""
    package = ""
    if vulns:
        pkgs = vulns[0].get("VulnerablePackages") or []
        if pkgs:
            package = pkgs[0].get("Name") or ""
    if not (repo and cve):
        # 레포·CVE를 못 찾으면 안정적인 키를 만들 수 없으니 기존 방식으로 물러난다.
        return "sh-" + hashlib.sha1(f["Id"].encode()).hexdigest()[:32]
    key = f"vuln|{repo}|{cve}|{package}"
    return "sh-" + hashlib.sha1(key.encode()).hexdigest()[:32]


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
        "id": _event_id(f, kind, resource),
        "service": f.get("ProductName") or "Security Hub",
        "scenario_type": kind,
        "severity": severity,
        "title": (f.get("Title") or sc["title"])[:255],
        "asset": (_asset_label(resource) or "")[:255] or None,
        "detected_at": _ts(f.get("UpdatedAt") or f.get("CreatedAt")),
        "status": "승인 대기" if auto else "검토 필요",
        # 역할 키 탈취(IAM 사용자 없음)는 Access Key 비활성화가 불가능하므로 역할 세션 폐기를 권고한다.
        "recommendation": sc["recommendation_role"] if kind == "cred" and user is None else sc["recommendation"],
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
