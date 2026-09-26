"""대시보드 ArchitectureMap 의 자산 ID(src/data/architecture.ts)와 시나리오별 표시 경로.

highlight_assets / attack_path 의 값은 대시보드 자산 ID 와 정확히 같아야 맵이 강조된다.
"""

SHOP_PATH = ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp"]
ADMIN_PATH = ["attacker", "igw", "adminWAF", "dashALB", "dashEC2"]

SCENARIOS = {
    "sqli": {
        "title": "SQL Injection 시도 탐지",
        "highlight": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"],
        "path": SHOP_PATH,
        "recommendation": "공격 IP 차단 및 WAF SQLi 규칙 BLOCK 전환, Flask 입력값 검증 점검",
    },
    "xss": {
        "title": "XSS 공격 시도 탐지",
        "highlight": ["attacker", "igw", "shopWAF", "cwLogs"],
        "path": ["attacker", "igw", "shopWAF"],
        "recommendation": "공격 IP 차단 및 CSP 헤더·출력 인코딩 점검",
    },
    "dir": {
        "title": "디렉터리 탐색/스캔 탐지",
        "highlight": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "cwLogs"],
        "path": ["attacker", "igw", "shopWAF", "shopALB", "k3s"],
        "recommendation": "출발지 IP 차단 및 Rate Limit 임계치 하향 검토",
    },
    "brute": {
        "title": "로그인 무차별 대입 탐지",
        "highlight": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "flaskApp", "cwLogs"],
        "path": SHOP_PATH,
        "recommendation": "출발지 IP 차단 및 로그인 잠금·MFA 정책 검토",
    },
    "brute_admin": {
        "title": "관리자 로그인 무차별 대입 탐지",
        "highlight": ["attacker", "igw", "adminWAF", "dashALB", "dashEC2", "cwLogs"],
        "path": ADMIN_PATH,
        "recommendation": "출발지 IP 차단 및 관리자 접근 CIDR·MFA 점검",
    },
    "flood": {
        "title": "대량 요청 과부하 탐지 (Rate Limit)",
        "highlight": ["attacker", "igw", "shopWAF", "shopALB", "k3s", "cwLogs"],
        "path": SHOP_PATH,
        "recommendation": "공격 IP 차단 및 Rate Limit 임계치·차단 유지시간 조정 검토",
    },
    "flood_admin": {
        "title": "관리자 ALB 대량 요청 과부하 탐지 (Rate Limit)",
        "highlight": ["attacker", "igw", "adminWAF", "dashALB", "dashEC2", "cwLogs"],
        "path": ADMIN_PATH,
        "recommendation": "공격 IP 차단 및 관리자 Rate Limit 임계치 조정 검토",
    },
    "port": {
        "title": "포트 스캔 탐지",
        "highlight": ["vpcFlow", "cwLogs", "guardDuty", "securityHub", "k3s"],
        "path": ["k3s"],
        "recommendation": "출발지 IP 차단 및 불필요한 Security Group 포트 제거",
    },
    "cred": {
        "title": "탈취 자격증명 사용 탐지",
        "highlight": ["cloudTrail", "s3Logs", "guardDuty", "accessAnalyzer", "securityHub"],
        "path": [],
        "recommendation": "해당 IAM 사용자의 Access Key 즉시 비활성화 후 CloudTrail 에서 이 키의 호출 내역 확인",
        # IAM 사용자가 없는 역할·임시 자격증명(예: InstanceCredentialExfiltration)은 비활성화할
        # Access Key 가 없다. 대시보드(app.py ROLE_CRED_RECOMMENDATION)와 같은 문구를 쓴다.
        "recommendation_role": (
            "해당 역할의 활성 세션 폐기(IAM 역할 → Revoke active sessions), CloudTrail 에서 이 자격증명의 "
            "호출 내역 확인, 자격증명을 발급한 EC2 의 침해 여부 점검, 역할이 읽을 수 있는 Secret 교체"
        ),
    },
    "vuln": {
        "title": "취약 컨테이너 이미지/패키지 발견",
        "highlight": ["ecr", "inspector", "securityHub", "k3s"],
        "path": [],
        "recommendation": "취약 패키지 업그레이드 후 이미지 재빌드 및 롤링 배포",
    },
    "s3": {
        "title": "S3 외부 접근 가능 설정 탐지",
        "highlight": ["accessAnalyzer", "securityHub", "s3Logs"],
        "path": [],
        "recommendation": "버킷 정책·퍼블릭 액세스 차단 설정 검토",
    },
    "generic": {
        "title": "보안 서비스 finding",
        "highlight": ["securityHub"],
        "path": [],
        "recommendation": "finding 내용을 검토하고 필요한 조치를 진행",
    },
}
