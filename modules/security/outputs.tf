output "shop_kms_key_arn" {
  value = aws_kms_key.shop.arn
}

output "security_kms_key_arn" {
  value = aws_kms_key.security.arn
}

output "shop_db_secret_arn" {
  value = aws_secretsmanager_secret.shop_db.arn
}

output "security_db_secret_arn" {
  value = aws_secretsmanager_secret.security_db.arn
}

output "security_logs_bucket_arn" {
  value = aws_s3_bucket.security_logs.arn
}

output "security_logs_bucket" {
  value = aws_s3_bucket.security_logs.bucket
}

output "shop_waf_log_group_arn" {
  value = aws_cloudwatch_log_group.shop_waf.arn
}

output "admin_waf_log_group_arn" {
  value = aws_cloudwatch_log_group.admin_waf.arn
}

output "vpc_flow_log_group_arn" {
  value = aws_cloudwatch_log_group.vpc_flow.arn
}

output "securityhub_rule_name" {
  description = "Security Hub finding EventBridge 규칙 이름 (보안 서비스 비활성화 시 null)"
  value       = try(aws_cloudwatch_event_rule.securityhub_findings[0].name, null)
}

output "securityhub_rule_arn" {
  value = try(aws_cloudwatch_event_rule.securityhub_findings[0].arn, null)
}
