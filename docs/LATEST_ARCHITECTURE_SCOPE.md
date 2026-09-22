# 최신 아키텍처 Terraform 반영 범위

## 반영됨 (인프라 + 배포 코드)
- ① K3s/nginx EC2, ② Dashboard EC2, ③ Flask App + Shopping MySQL EC2, ④ Security MySQL EC2
- Shop WAF/ALB와 Admin WAF/ALB 경로 분리
- GuardDuty / Inspector / Access Analyzer / Security Hub
- CloudTrail / VPC Flow Logs / CloudWatch를 지원 데이터 계층으로 유지
- Macie 제외
- Shield Standard는 별도 리소스 미생성
- KMS 정식 Key Policy 반영
- SNS는 구독자가 없어 제거함 (EventBridge → Lambda A 직결)
- **Lambda A / B / C / Remediation 코드와 배포까지 완료, 실제 운영 중**
  - Lambda A: Security Hub Finding → security_events
  - Lambda B: WAF 로그 분석(5분마다) → security_events
  - Lambda C: CloudWatch 지표(5분마다) → service_metrics
  - Lambda Remediation: 대시보드 승인 → WAF 차단 / SSM 재시작 / Access Key 비활성화
- **Dashboard 애플리케이션 실제 배포 완료** (Docker, Flask가 빌드된 React 정적 파일까지 같이 서빙). 로컬에 Docker가 없어서
  EC2 위에서 직접 빌드하는 방식(S3로 소스 전달 + SSM RunShellScript)을 사용, ECR은 아직 안 씀.
- dashboard EC2는 `lifecycle { ignore_changes = [user_data] }`로 보호되어 있어 `terraform apply`로 초기화되지 않음
  (shop_db/security_db도 동일하게 보호됨. k3s/shop_app EC2는 아직 자리표시자라 보호 없음)

## 아직 안 된 것
- shop-app 실제 앱 배포 (k3s EC2와 shop-app EC2 둘 다 여전히 자리표시자 nginx만 떠 있음.
  SG 설계상 `shop ALB → k3s(NodePort) → shop-app(8443)` 경로인데 아직 실제로 연결 안 됨)
- WAF 로그 분석 후 Security Hub ASFF Finding 변환 (지금은 Lambda B가 `security_events`에 직접 저장하는
  방식으로 대체, Security Hub로 되돌려보내는 건 안 함)
- 실제 공격 시나리오 재현 (Attack Lab)
- GitHub Actions 배포 자동화 (지금은 전부 SSM 수동 배포. OIDC 역할은 `service` 레포용으로만 만들어져 있음)
