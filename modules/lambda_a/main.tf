# Lambda A: Security Hub -> EventBridge -> Lambda A -> Security MySQL(security_events)
# 코드: src/lambda_a.py (+ ../lambda_common). 배포 전 src/build.sh 로 패키지 생성

data "archive_file" "lambda_a" {
  type        = "zip"
  source_dir  = "${path.module}/src/build"
  output_path = "${path.module}/src/lambda_a.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_a" {
  name               = "${var.project}-lambda-a-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# CloudWatch Logs + VPC ENI 생성 권한
resource "aws_iam_role_policy_attachment" "lambda_a_vpc" {
  role       = aws_iam_role.lambda_a.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Security DB 접속 정보만 읽는다.
data "aws_iam_policy_document" "secret_read" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "kms:Decrypt"
    ]

    resources = [
      var.db_secret_arn,
      var.kms_key_arn
    ]
  }
}

resource "aws_iam_role_policy" "lambda_a_secret" {
  name   = "${var.project}-lambda-a-secret-read"
  role   = aws_iam_role.lambda_a.id
  policy = data.aws_iam_policy_document.secret_read.json
}

resource "aws_cloudwatch_log_group" "lambda_a" {
  name              = "/aws/lambda/${var.project}-lambda-a"
  retention_in_days = 30
}

resource "aws_lambda_function" "lambda_a" {
  function_name    = "${var.project}-lambda-a"
  description      = "Security Hub finding -> security_events"
  role             = aws_iam_role.lambda_a.arn
  runtime          = "python3.12"
  handler          = "lambda_a.lambda_handler"
  filename         = data.archive_file.lambda_a.output_path
  source_code_hash = data.archive_file.lambda_a.output_base64sha256
  timeout          = 30
  memory_size      = 256

  # 동시 실행을 제한해 DB 연결 폭주를 막는다.
  reserved_concurrent_executions = 5

  # 서로 다른 AZ의 private subnet 2개 (NAT 경유로 Secrets Manager 접근)
  vpc_config {
    subnet_ids         = [var.subnet_ids[0], var.subnet_ids[1]]
    security_group_ids = [var.security_group_id]
  }

  environment {
    variables = {
      DB_SECRET_ARN = var.db_secret_arn
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_a_vpc,
    aws_cloudwatch_log_group.lambda_a
  ]
}

# 기존 Security Hub 규칙(securityhub_findings)에 Lambda A 를 두 번째 타깃으로 추가한다. (SNS 알림은 그대로 유지)
resource "aws_cloudwatch_event_target" "securityhub_to_lambda_a" {
  count = var.enable_security_services ? 1 : 0

  rule      = var.event_rule_name
  target_id = "LambdaA"
  arn       = aws_lambda_function.lambda_a.arn
}

resource "aws_lambda_permission" "eventbridge_lambda_a" {
  count = var.enable_security_services ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_a.function_name
  principal     = "events.amazonaws.com"
  source_arn    = var.event_rule_arn
}
