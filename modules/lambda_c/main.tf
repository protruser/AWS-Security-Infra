# Lambda C: (5분마다) CloudWatch 지표 -> Security MySQL(service_metrics)
# 보안 시나리오가 아니라 CPU/메모리/지연시간/처리량/에러율/서비스 상태를 모아 대시보드 하단에 보여주기 위함.
# 코드: src/lambda_c.py (+ ../lambda_common). 배포 전 src/build.sh 로 패키지 생성

data "archive_file" "this" {
  type        = "zip"
  source_dir  = "${path.module}/src/build"
  output_path = "${path.module}/src/lambda-c.zip"
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
  name               = "${var.project}-lambda-c-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "vpc" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "secret" {
  name   = "${var.project}-lambda-c-secret-read"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.secret_read.json
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${var.project}-lambda-c"
  retention_in_days = 30
}

# CloudWatch 지표 조회 전용 (조회만, PutMetricData 는 서버의 CloudWatch Agent 몫이라 여기엔 없다)
data "aws_iam_policy_document" "metrics_read" {
  statement {
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "metrics_read" {
  name   = "${var.project}-lambda-c-metrics-read"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.metrics_read.json
}

resource "aws_lambda_function" "this" {
  function_name    = "${var.project}-lambda-c"
  description      = "CloudWatch 지표 -> service_metrics"
  role             = aws_iam_role.this.arn
  runtime          = "python3.12"
  handler          = "lambda_c.lambda_handler"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = 60
  memory_size      = 256

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [var.security_group_id]
  }

  environment {
    variables = {
      DB_SECRET_ARN      = var.db_secret_arn
      INSTANCE_IDS       = jsonencode(var.instance_ids)
      SHOP_LB_ARN_SUFFIX = var.shop_lb_arn_suffix
      SHOP_TG_ARN_SUFFIX = var.shop_tg_arn_suffix
    }
  }

  depends_on = [aws_iam_role_policy_attachment.vpc, aws_cloudwatch_log_group.this]
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.project}-lambda-c-schedule"
  description         = "인프라 상태 수집 Lambda C 를 5분마다 실행"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "LambdaC"
  arn       = aws_lambda_function.this.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
