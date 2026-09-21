# Lambda B: (5분마다) WAF 로그 분석 -> 이상 징후를 Security MySQL(security_events)에 저장
# 코드: src/lambda_b.py, src/waf.py (+ ../lambda_common). 배포 전 src/build.sh 로 패키지 생성

data "archive_file" "this" {
  type        = "zip"
  source_dir  = "${path.module}/src/build"
  output_path = "${path.module}/src/lambda-b.zip"
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
  name               = "${var.project}-lambda-b-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "vpc" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "secret" {
  name   = "${var.project}-lambda-b-secret-read"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.secret_read.json
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.project}-lambda-b"
  retention_in_days = 30
}

# WAF 로그 그룹 읽기 전용
data "aws_iam_policy_document" "logs_read" {
  statement {
    actions   = ["logs:FilterLogEvents", "logs:GetLogEvents"]
    resources = ["${var.shop_waf_log_group_arn}:*", "${var.admin_waf_log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs_read" {
  name   = "${var.project}-lambda-b-waf-logs-read"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.logs_read.json
}

resource "aws_lambda_function" "this" {
  function_name    = "${var.project}-lambda-b"
  description      = "WAF 로그 분석 -> security_events"
  role             = aws_iam_role.this.arn
  runtime          = "python3.12"
  handler          = "lambda_b.lambda_handler"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = 120
  memory_size      = 512

  # 같은 구간을 두 번 처리하지 않도록 동시 실행 1개
  reserved_concurrent_executions = 1

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [var.security_group_id]
  }

  environment {
    variables = {
      DB_SECRET_ARN       = var.db_secret_arn
      SHOP_WAF_LOG_GROUP  = var.shop_waf_log_group_name
      ADMIN_WAF_LOG_GROUP = var.admin_waf_log_group_name
      LOGIN_PATHS         = var.login_paths
      BRUTE_THRESHOLD     = tostring(var.brute_threshold)
    }
  }

  depends_on = [aws_iam_role_policy_attachment.vpc, aws_cloudwatch_log_group.this]
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.project}-lambda-b-schedule"
  description         = "WAF 로그 분석 Lambda B 를 5분마다 실행"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "LambdaB"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
