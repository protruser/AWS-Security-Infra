# 서버 역할에 추가하는 권한.
# - ECR 이미지 pull: 서버마다 자기 저장소 하나만
# - 대시보드 조회 권한: boto3 수집기가 AWS 보안 서비스 결과를 읽기 위한 읽기 전용 권한

locals {
  ecr_pull_repos = {
    "k3s"       = [aws_ecr_repository.nginx.arn]
    "shop-app"  = [aws_ecr_repository.shop_app.arn]
    "dashboard" = [aws_ecr_repository.dashboard.arn]
  }
}

data "aws_iam_policy_document" "ecr_pull" {
  for_each = local.ecr_pull_repos

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage"
    ]
    resources = each.value
  }
}

resource "aws_iam_role_policy" "ecr_pull" {
  for_each = local.ecr_pull_repos

  name   = "${var.project}-${each.key}-ecr-pull"
  role   = aws_iam_role.ec2[each.key].id
  policy = data.aws_iam_policy_document.ecr_pull[each.key].json
}

data "aws_iam_policy_document" "dashboard_aws_read" {
  # 보안 서비스 탐지 결과 조회 (전부 읽기 전용)
  statement {
    sid = "SecurityServicesRead"
    actions = [
      "guardduty:Get*",
      "guardduty:List*",
      "inspector2:Get*",
      "inspector2:List*",
      "inspector2:BatchGet*",
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
      "access-analyzer:Get*",
      "access-analyzer:List*",
      "cloudtrail:LookupEvents",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "wafv2:Get*",
      "wafv2:List*",
      "ec2:Describe*"
    ]
    resources = ["*"]
  }

  # WAF 로그 / VPC Flow Logs 조회
  statement {
    sid = "LogsRead"
    actions = [
      "logs:FilterLogEvents",
      "logs:GetLogEvents",
      "logs:StartQuery"
    ]
    resources = [
      "${var.shop_waf_log_group_arn}:*",
      "${var.admin_waf_log_group_arn}:*",
      "${var.vpc_flow_log_group_arn}:*"
    ]
  }

  statement {
    sid = "LogsDescribe"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetQueryResults",
      "logs:StopQuery"
    ]
    resources = ["*"]
  }

  # CloudTrail 로그 버킷 읽기
  statement {
    sid     = "LogBucketRead"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      var.security_logs_bucket_arn,
      "${var.security_logs_bucket_arn}/*"
    ]
  }
}

resource "aws_iam_role_policy" "dashboard_aws_read" {
  name   = "${var.project}-dashboard-aws-read"
  role   = aws_iam_role.ec2["dashboard"].id
  policy = data.aws_iam_policy_document.dashboard_aws_read.json
}
