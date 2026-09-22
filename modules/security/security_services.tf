# Latest security scenario mapping:
# - WAF: SQLi / XSS / directory search / brute-force login
# - GuardDuty: port scan / compromised credential scenario
# - Inspector: vulnerable EC2/ECR image
# - IAM Access Analyzer: supporting evidence for excessive/external access
# - Security Hub: aggregate supported findings
# - CloudTrail / VPC Flow Logs / CloudWatch: supporting data sources
# - Shield Standard: AWS default protection, no Terraform activation resource

resource "aws_guardduty_detector" "main" {
  count = var.enable_security_services ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_inspector2_enabler" "main" {
  count = var.enable_security_services ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR"]
}

resource "aws_accessanalyzer_analyzer" "main" {
  count = var.enable_security_services ? 1 : 0

  analyzer_name = "${var.project}-account-analyzer"
  type          = "ACCOUNT"
}

resource "aws_securityhub_account" "main" {
  count = var.enable_security_services ? 1 : 0

  enable_default_standards = true
}

# Security Hub에 유입된 finding을 Lambda A로 전달 (DB 저장 -> 대시보드 표시).
# SNS 이메일 알림은 구독자가 없어(notification_email 비어있음) 사용하지 않으므로 제거함.
# WAF 자체는 Security Hub에 직접 finding을 보내지 않으므로,
# WAF 로그 기반의 커스텀 finding 변환은 별도 Lambda/애플리케이션 로직에서 구현한다.
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  count = var.enable_security_services ? 1 : 0

  name        = "${var.project}-securityhub-findings"
  description = "Forward imported Security Hub findings to Lambda A"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  depends_on = [aws_securityhub_account.main]
}
