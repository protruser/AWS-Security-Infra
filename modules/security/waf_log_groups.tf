resource "aws_cloudwatch_log_group" "shop_waf" {
  name              = "aws-waf-logs-${var.project}-shop"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.security.arn
}

resource "aws_cloudwatch_log_group" "admin_waf" {
  name              = "aws-waf-logs-${var.project}-admin"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.security.arn
}
