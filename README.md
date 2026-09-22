# wonny-sec 인프라 팀 가이드

이 문서는 `infra` 레포(Terraform)를 처음 보는 팀원도 전체 그림을 따라올 수 있게 쓴
가이드입니다. "지금 뭐가 실제로 돌고 있는지", "뭘 고치면 되고 뭘 건드리면 안 되는지",
"Docker 이미지는 언제 어떻게 만들어지는지"까지 한 문서에서 확인할 수 있게 정리했어요.

> 마지막 업데이트: 2026-09-22 (인프라 담당이 직접 AWS에서 실측 확인하며 작성)

---

## 1. 이 프로젝트는 레포 3개로 나뉘어 있어요

| 레포 | GitHub | 역할 | 브랜치 |
|---|---|---|---|
| **infra** | `protruser/AWS-Security-Infra` | 이 레포. Terraform으로 AWS 인프라 전체(네트워크/서버/보안서비스/Lambda) 생성 | `gyu` (작업 브랜치) |
| **dashboard** | `protruser/AWS-security` | 보안관제 대시보드(React + Flask). 대시보드 EC2에 배포됨 | `wonny` (배포에 쓰는 최신 브랜치, `gyu`는 안 씀) |
| **service** | `protruser/AWS-Security-Service` | 일부러 취약하게 만든 쇼핑몰 앱(Flask). shop-app EC2에 배포 예정 | `vuln_service` (실제 코드는 여기, `main`은 거의 비어있음) |

세 레포가 배포되는 대상은 전부 **이 `infra` 레포가 Terraform으로 미리 만들어둔 EC2**예요.
즉 다른 두 레포는 "무슨 서버에 뭘 올릴지"를 여기(infra)가 먼저 준비해두고, 그 위에
자기 코드를 올리는 구조예요.

---

## 2. 지금 실제로 뭐가 돌고 있는지 (현재 상태)

EC2 5대를 만들었지만, **그 안에 진짜 앱이 올라간 것도 있고 아직 자리표시자(placeholder)뿐인 것도 있어요.**

| # | 서버 | 역할 | 지금 상태 |
|---|---|---|---|
| ① | k3s-nginx | 원래 쇼핑몰 앱을 여기(쿠버네티스)에 올릴 계획 | 🟡 자리표시자 nginx pod만 떠 있음. shop-app EC2로 라우팅하는 설정 아직 없음 |
| ② | dashboard | 보안관제 대시보드 | ✅ **진짜 앱 운영 중** (React+Flask, Docker 컨테이너로 배포됨) |
| ③ | shop-app | 쇼핑몰 Flask 앱 | 🟡 자리표시자 nginx만 떠 있음. `service` 레포 GitHub Actions로 배포 예정(아래 5번 참고) |
| ③ | shop-db | 쇼핑몰 MySQL | ✅ 컨테이너 떠 있음 (아직 쇼핑몰 앱이 없어서 실사용 데이터는 없음) |
| ④ | security-db | 보안탐지결과 MySQL | ✅ **실제로 탐지 데이터 쌓이는 중** (Lambda A/B가 계속 씀) |

**보안 서비스/탐지 파이프라인은 전부 실제로 동작 중**이에요 (GuardDuty, Inspector, Access
Analyzer, Security Hub, WAF → Lambda A/B → `security_events` 테이블 → 대시보드 표시까지
end-to-end로 확인됨). 자세한 현황은 `docs/01_보안서비스_반영현황.md` 참고하세요.

**아직 안 된 것 (다음 할 일)**:
- k3s 안의 nginx를 shop-app EC2로 프록시하도록 설정 (지금은 shop ALB로 접속해도 그냥 nginx
  기본 페이지만 뜸)
- `service` 레포 GitHub Actions로 shop-app 실제 배포 (OIDC/SSM 권한은 오늘 다 고쳐서 이제
  될 거예요, 재실행 확인 필요)
- Attack Lab(7개 시나리오 의도적으로 재현하는 기능)
- dashboard 배포를 GitHub Actions로 자동화 (지금은 사람이 수동으로 SSM 통해 배포, 아래 4번 참고)

---

## 3. 전체 아키텍처

```text
Internet
  │
  ├─ WAF(shop)  → Shop ALB(80)  → ① k3s EC2:30443(NodePort) → ③ shop-app EC2:8443 → ③ shop-db EC2:3306
  │                                  (지금은 nginx 자리표시자, ③까지 라우팅 설정 안 됨)
  │
  └─ WAF(admin) → Admin ALB(80, 관리자 IP만 허용) → ② dashboard EC2:8443 → ④ security-db EC2:3306

[탐지 파이프라인]
GuardDuty / Inspector / Access Analyzer
   → Security Hub → EventBridge → Lambda A → security_events 테이블
Shop/Admin WAF 로그 → (5분마다) Lambda B → security_events 테이블
CloudWatch 지표(k3s/shop-app/shop-db만) → (5분마다) Lambda C → service_metrics 테이블

[조치 실행]
대시보드에서 "조치 승인" 클릭 → Flask가 Lambda Remediation 직접 호출
   → WAF IP 차단 / SSM으로 서버 재시작 / IAM Access Key 비활성화
```

VPC `10.0.0.0/16`, 프라이빗 서브넷 4개(①10.0.1.0/24, ②10.0.2.0/24, ③10.0.3.0/24 —
shop-app/shop-db 둘 다 여기, ④10.0.4.0/24), 퍼블릭 서브넷 2개(ALB용). NAT Gateway 1개.

---

## 4. Docker 이미지는 언제 어떻게 만들어지나요

**이미지 만드는 방법이 지금 두 앱이 서로 달라요** — 하나는 자동화(GitHub Actions), 하나는
아직 수동이에요.

### service(쇼핑몰) — GitHub Actions로 자동 빌드/배포 (정석)

`service` 레포 `.github/workflows/deploy-shop-app.yml`이 `vuln_service` 브랜치에 push되면
자동으로 실행돼요:

```
git push (vuln_service)
   → GitHub Actions 실행
   → pytest 테스트
   → OIDC로 AWS 로그인 (wonny-sec-github-deploy 역할, 임시 자격증명, 키 저장 안 함)
   → docker build (service 레포의 Dockerfile 사용)
   → ECR에 push (796897109622.dkr.ecr.ap-northeast-2.amazonaws.com/wonny-sec/shop-app:<커밋SHA>)
   → SSM으로 shop-app EC2(i-096ca08c26002111e)에 "이 이미지 pull해서 컨테이너 교체해" 명령
   → shop-app EC2가 ECR에서 이미지 pull, 기존 컨테이너 내리고 새로 띄움
   → 헬스체크 실패하면 자동으로 이전 이미지로 롤백 (deploy/shop-app/deploy.sh)
```

이게 **원래 의도된 정상 흐름**이에요. Dockerfile은 `service` 레포 루트에 딱 1개 있어요.

### dashboard — 지금은 사람이 수동으로 (임시)

dashboard는 아직 GitHub Actions가 없어요. 로컬에 Docker가 없는 상황이라, 지금까지는:

```
(로컬) git checkout wonny 브랜치
   → 소스를 tar로 압축해서 S3에 업로드
   → SSM으로 dashboard EC2한테 "S3에서 받아서 네가 직접 docker build 해" 시킴
   → dashboard EC2 안에서 이미지 빌드됨 (ECR 안 씀, EC2 로컬에만 이미지 있음)
   → 기존 컨테이너 내리고 새 이미지로 교체
```

Dockerfile은 `dashboard` 레포(`wonny` 브랜치) 루트에 딱 1개 있어요 (2단계 빌드: node로
React 빌드 → 그 결과물을 Flask가 `static/`으로 같이 서빙). **이 방식은 임시방편**이에요 —
나중에 dashboard도 `service`처럼 GitHub Actions로 옮기는 게 맞아요 (ECR 레포
`wonny-sec/dashboard`는 이미 만들어져 있고 비어있는 상태).

### 공통으로 알아둘 것

- ECR 레포 3개 다 `image_tag_mutability = "IMMUTABLE"` — 같은 태그로 덮어쓰기 불가. 그래서
  보통 커밋 SHA를 태그로 써요 (service 워크플로가 이렇게 함).
- 컨테이너는 전부 `--restart unless-stopped`로 떠서, EC2를 중지했다 다시 켜면 Docker가
  알아서 컨테이너를 재시작해요 (이미지를 다시 만들 필요 없음).

---

## 5. GitHub Actions ↔ AWS 연동 (OIDC)

레포별 GitHub Actions가 AWS에 로그인하는 방법은 **OIDC(OpenID Connect)**예요 — AWS
Access Key를 GitHub Secrets에 영구 저장 안 하고, 매 실행마다 GitHub이 발급한 임시 토큰으로
AWS가 몇 분짜리 임시 자격증명을 빌려주는 방식이에요.

**관련 코드**: `modules/compute/ecr_github_oidc.tf` 하나에 다 있어요 (IAM 역할, 신뢰정책,
ECR/SSM 권한).

**값 설정 위치**: `terraform.tfvars`(gitignore됨, git에 없음)의 `github_repository`,
`github_oidc_provider_arn`.

**⚠️ 겪었던 함정 — 신뢰정책의 `sub` 조건값**:

GitHub OIDC 토큰의 `sub` 클레임이 단순히 `owner/repo` 형식이 아니라, 최근 GitHub 정책
변경으로 **조직/레포 이름에 불변 숫자 ID가 붙어서** 옵니다 (레포 이름 재사용 공격 방지 목적):

```
repo:protruser@137254772/AWS-Security-Service@1378937222:environment:production
```

`github_repository` 변수에 그냥 `"protruser/AWS-Security-Service"`만 넣으면 절대 매칭이
안 돼서 `AssumeRoleWithWebIdentity`가 계속 거부돼요. **실제 값은 워크플로에 있는 "Inspect
OIDC claims" 스텝을 한 번 실행해서 로그에 찍힌 `sub` 값을 그대로 복사**해야 해요. 지금은
이미 맞는 값으로 설정돼 있어요.

**⚠️ 겪었던 함정 2 — `ssm:GetCommandInvocation` 권한**:

이 액션은 EC2 인스턴스 ARN으로 리소스 범위를 제한하는 걸 지원 안 해요 (커맨드 실행 결과가
ARN으로 식별되는 리소스가 아니라서). `ssm:SendCommand`랑 같은 statement에 묶어서 인스턴스
ARN으로 제한하면 `AccessDeniedException`이 나요 — **반드시 별도 statement로 분리하고
`Resource = "*"`로 줘야 해요.** (지금 코드에 이미 반영돼 있음)

**dashboard 레포도 GitHub Actions 쓰려면**: 지금 `github_repository`는 `service` 레포
하나만 등록돼 있어요. dashboard도 쓰려면 신뢰정책에 dashboard 레포도 추가해야 해요 (여러
레포 허용하려면 `ecr_github_oidc.tf`의 조건 로직을 리스트로 바꾸는 작업 필요).

---

## 6. 뭘 건드려도 되고, 뭘 Terraform에서만 해야 하나요

이게 제일 헷갈리는 부분이라 명확히 정리할게요. 기준은 **"Terraform이 그걸 알고
있냐(state에 기록돼 있냐) 아니냐"**예요.

### ✅ 완전히 안전 — EC2 안에서 하는 모든 작업

`.env` 파일 수정, Docker 컨테이너 재시작/재생성, 로그 확인 같은 건 EC2 인스턴스 내부의
일이에요. Terraform은 서버가 "처음 부팅할 때" 실행하는 `user_data` 스크립트만 알고
있지, 부팅 이후 서버 안에서 뭘 하든 전혀 신경 안 써요. **AWS 콘솔에서 EC2 → 인스턴스 →
연결(Connect) → Session Manager**로 들어가서 자유롭게 작업하셔도, `terraform apply`를
몇 번을 돌려도 절대 안 사라져요.

> `.env` 파일 고칠 때 주의: 파일만 고치고 컨테이너를 재생성(`docker rm -f` →
> `docker run`)하지 않으면 반영 안 돼요. `docker restart`도 안 통해요 — 환경변수는
> 컨테이너를 처음 만들 때 딱 한 번만 "굽는" 방식이라서요.

### ⚠️ 조건부 안전 — EC2 인스턴스 자체(교체 여부)

`user_data`(부팅 스크립트)가 바뀌면 Terraform은 기본적으로 그 서버를 통째로 교체해요.
dashboard/shop-db/security-db는 `lifecycle { ignore_changes = [user_data] }`로 보호돼
있어서 안전한데, **k3s/shop-app은 아직 이 보호가 없어요.** 나중에 이 두 서버에도 진짜
앱을 올리면 똑같이 보호를 걸어야 해요 (`modules/compute/compute.tf` 참고).

### ❌ 위험 — Terraform이 관리하는 AWS 리소스 자체

타깃그룹 설정, 보안그룹 규칙, IAM 정책, Lambda 함수 설정, WAF 룰, ALB 리스너처럼
`.tf` 코드에 정의돼 있고 `terraform.tfstate`에 기록된 것들이에요. 콘솔에서 직접 고치면
**다음 `terraform apply` 때 코드에 적힌 대로 조용히 원상복구돼요** (콘솔에서 한 변경이
사라짐). 급하게 콘솔에서 뭔가 바꿨으면, **그 즉시 `.tf` 코드에도 똑같이 반영**해두세요.
가장 안전한 방법은 코드부터 고치고 `terraform plan`으로 확인한 다음 `apply`하는
순서예요.

### 한 줄 요약

> **"서버 안에서" 하는 거면 다 안전, "AWS 리소스 설정 자체"를 콘솔에서 고치는 거면
> 반드시 `.tf` 코드도 같이 고쳐야 안 날아감.**

---

## 7. 자주 겪을 문제들 (트러블슈팅)

### 관리자 대시보드 접속이 갑자기 안 돼요

`admin_cidrs`(`terraform.tfvars`)에 등록된 IP만 접속 가능해요. 집/회사 인터넷의 공인
IP는 유동적이라 시간이 지나면 바뀔 수 있어요. `https://checkip.amazonaws.com`으로 현재
IP 확인하고, `terraform.tfvars`의 `admin_cidrs` 값을 바꿔서 apply하면 돼요 (보안그룹
2개만 in-place로 바뀜, 안전함).

### 대시보드 admin_url이 504/타임아웃

타깃그룹 프로토콜(HTTP/HTTPS)이나 헬스체크 경로가 실제 앱이랑 안 맞으면 이런 증상이
나요. `modules/edge/alb_waf.tf`의 `aws_lb_target_group.admin` 설정(`protocol`,
`health_check.path`)이 실제 컨테이너가 서빙하는 방식(HTTP인지 HTTPS인지, `/health`인지
`/api/health`인지)과 정확히 일치하는지 먼저 확인하세요.

### 타깃그룹 프로토콜/헬스체크 경로를 고쳤는데 apply가 `ResourceInUse` 에러로 실패

기본적으로 Terraform은 "교체" 리소스를 **먼저 지우고 나중에 만드는** 순서라서, 리스너가
아직 참조 중인 타깃그룹을 지우려다 막혀요. `lifecycle { create_before_destroy = true }`
를 걸고, 고정 `name` 대신 `name_prefix`를 써야 새 걸 먼저 만들고 옮긴 뒤 지울 수 있어요
(지금 `aws_lb_target_group.admin`에 이미 적용돼 있음, 예시로 참고).

### `.env` 비밀번호를 바꿨는데 예전 값으로 로그인됨

컨테이너를 재생성 안 해서 그래요. 6번 항목 참고 — `docker rm -f` → `docker run` 순서로
다시 띄워야 해요.

### DB 비밀번호를 손으로 옮겨 적었더니 연결이 깨짐

Secrets Manager 값을 JSON으로 조회하면 특수문자가 `<`(=`<`) 같은 식으로 이스케이프
돼서 나올 수 있어요. `.env`에 그대로 붙여넣으면 실제 비밀번호랑 안 맞아요. **가능하면
`DB_SECRET_ID`(Secrets Manager 이름)만 넣고, 서버가 IAM 권한으로 직접 조회하게 하세요**
— 비밀번호를 손으로 옮길 일 자체를 없애는 게 제일 안전해요.

---

## 8. Terraform 폴더 구조

루트(`main.tf`)는 모듈을 연결만 하고, 리소스는 `modules/` 아래에 있어요.

| 경로 | 내용 |
|---|---|
| `modules/network` | VPC / Subnet / NAT / Security Group / VPC Endpoint |
| `modules/security` | KMS / Secrets Manager / S3 로그 / CloudTrail / Flow Logs / GuardDuty / Inspector / Access Analyzer / Security Hub / WAF 로그 그룹 |
| `modules/compute` | EC2 5대 / IAM / ECR / GitHub OIDC (`user_data/` 포함) |
| `modules/edge` | ALB / WAF / ACM / Route53 |
| `modules/lambda_a` | Security Hub finding → `security_events` (이벤트 기반) |
| `modules/lambda_b` | WAF 로그 분석 → `security_events` (5분마다) |
| `modules/lambda_c` | CloudWatch 지표 → `service_metrics` (5분마다, k3s/shop-app/shop-db 3대만) |
| `modules/lambda_remediation` | 대시보드 승인 → WAF 차단/SSM 재시작/Access Key 비활성화 |
| `modules/lambda_common` | Lambda A/B/C/Remediation이 같이 쓰는 DB·매핑 코드, 단위 테스트 |
| `docs/` | 실행방법(`00_*`), 보안서비스 반영현황(`01_*`), 아키텍처 범위, KMS 수정 이력 |

Lambda 4개는 `terraform plan` 전에 각각 `src/build.sh`로 패키지를 먼저 만들어야 해요:

```sh
bash modules/lambda_a/src/build.sh
bash modules/lambda_b/src/build.sh
bash modules/lambda_c/src/build.sh
bash modules/lambda_remediation/src/build.sh
terraform plan -out=review.tfplan
```

로직 테스트(AWS/DB 연결 없이 가능): `python3 modules/lambda_common/tests/test_lambdas.py`

---

## 9. Security MySQL(`security-db`) 테이블 구조

| 테이블 | 용도 |
|---|---|
| `security_events` | 탐지된 보안 이벤트. `scenario_type`은 7개 값 중 하나로 고정: `sqli, dir, brute, cred, vuln, xss, port` |
| `remediation_history` | 이벤트별 조치 이력(누가/언제/성공여부). `security_events.id`를 외래키로 참조 |
| `service_metrics` | CPU/메모리/지연시간/에러율 등 운영 지표 이력(3일 보관). k3s/shop-app/shop-db만 대상 |

스키마는 `modules/lambda_common/common/db.py`에 있고, `CREATE TABLE IF NOT EXISTS`라서
어느 Lambda가 먼저 실행돼도 자동으로 만들어져요.

---

## 10. 실행 방법 (Windows CMD 기준)

```cmd
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars

terraform init
terraform fmt
terraform validate
terraform plan -out=review.tfplan
terraform apply review.tfplan
```

`terraform.tfvars`에서 최소한 확인할 것: `admin_cidrs`(본인 공인 IP), `enable_security_services`,
`github_repository`/`github_oidc_provider_arn`(GitHub Actions 쓸 레포만).

주요 output:

```cmd
terraform output shop_url
terraform output admin_url
terraform output instance_ids
```

삭제 전 확인 → 실제 삭제:

```cmd
terraform plan -destroy -out=destroy.tfplan
terraform apply destroy.tfplan
```

더 자세한 단계별 설명은 `docs/00_실행방법_설명서.md`, 명령어만 빠르게 보려면
`docs/00_빠른실행.txt`를 참고하세요.

---

## 11. 비용/보안 관련 주의사항

- NAT Gateway, ALB, EC2, 로그 저장 등에 비용이 발생해요. 당장 안 쓰면 EC2는
  **중지(Stop)**해두세요 (터미네이트 아님 — 디스크 데이터 보존되고, 다시 시작하면
  컨테이너도 자동 복구됨).
- SSH 22 인바운드는 아예 안 만들어요. 전부 **SSM Session Manager**로 접속해요.
- `terraform.tfstate`, `*.tfplan`, `terraform.tfvars`, `.env`, `*.pem`은 **git에 올리면
  안 돼요** (`.gitignore`에 이미 포함).
- DB 비밀번호는 전부 `random_password`로 Terraform이 자동 생성 → Secrets Manager에
  KMS 암호화로 저장. 코드/설정 파일 어디에도 평문 비밀번호가 없어요.

---

궁금한 거 생기면 여기부터 찾아보시고, 그래도 모르겠으면 인프라 담당한테 물어보세요 🙂
