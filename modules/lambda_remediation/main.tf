# Lambda Remediation: 대시보드에서 승인된 조치를 실행 (WAF IP 차단 / SSM 서비스 재시작 / IAM Access Key 비활성화)
# 코드: src/remediation.py (+ ../lambda_common). 배포 전 src/build.sh 로 패키지 생성

data "archive_file" "this" {
  type        = "zip"
  source_dir  = "${path.module}/src/build"
  output_path = "${path.module}/src/remediation.zip"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "secret_read" {
  statement {
    actions   = ["secretsmanager:GetSecretValue", "kms:Decrypt"]
    resources = [var.db_secret_arn, var.kms_key_arn]
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.project}-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "vpc" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "secret" {
  name   = "${var.project}-remediation-secret-read"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.secret_read.json
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.project}-remediation"
  retention_in_days = 30
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  instance_arns = [
    for id in values(var.instance_ids) :
    "arn:aws:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/${id}"
  ]
}

# 실행할 수 있는 조치에 필요한 권한만 준다.
data "aws_iam_policy_document" "actions" {
  statement {
    sid       = "WafBlockList"
    actions   = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
    resources = [var.waf_ip_set_arn]
  }

  statement {
    sid     = "RestartViaSsm"
    actions = ["ssm:SendCommand"]
    resources = concat(
      local.instance_arns,
      ["arn:aws:ssm:${data.aws_region.current.name}::document/AWS-RunShellScript"]
    )
  }

  statement {
    sid       = "SsmResult"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }

  statement {
    sid       = "DisableAccessKey"
    actions   = ["iam:ListAccessKeys", "iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }
}

resource "aws_iam_role_policy" "actions" {
  name   = "${var.project}-remediation-actions"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.actions.json
}

resource "aws_lambda_function" "this" {
  function_name    = "${var.project}-remediation"
  description      = "승인된 보안 조치 실행"
  role             = aws_iam_role.this.arn
  runtime          = "python3.12"
  handler          = "remediation.lambda_handler"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = 90
  memory_size      = 256


  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [var.security_group_id]
  }

  environment {
    variables = {
      DB_SECRET_ARN   = var.db_secret_arn
      WAF_IP_SET_NAME = var.waf_ip_set_name
      WAF_IP_SET_ID   = var.waf_ip_set_id
      INSTANCE_IDS    = jsonencode(var.instance_ids)
      PROTECTED_CIDRS = jsonencode(var.protected_cidrs)
    }
  }

  depends_on = [aws_iam_role_policy_attachment.vpc, aws_cloudwatch_log_group.this]
}
