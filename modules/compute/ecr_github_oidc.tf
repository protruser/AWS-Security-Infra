resource "aws_ecr_repository" "nginx" {
  name                 = "${var.project}/nginx"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.shop_kms_key_arn
  }
}

resource "aws_ecr_repository" "shop_app" {
  name                 = "${var.project}/shop-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.shop_kms_key_arn
  }
}

resource "aws_ecr_repository" "dashboard" {
  name                 = "${var.project}/dashboard"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.security_kms_key_arn
  }
}

data "aws_iam_policy_document" "github_oidc_assume" {
  count = var.github_repository != "" && var.github_oidc_provider_arn != "" ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:production"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  count = var.github_repository != "" && var.github_oidc_provider_arn != "" ? 1 : 0

  name               = "${var.project}-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_oidc_assume[0].json
}

data "aws_iam_policy_document" "github_deploy" {
  count = var.github_repository != "" && var.github_oidc_provider_arn != "" ? 1 : 0

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:GetDownloadUrlForLayer",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart"
    ]

    resources = [
      aws_ecr_repository.nginx.arn,
      aws_ecr_repository.shop_app.arn,
      aws_ecr_repository.dashboard.arn
    ]
  }

  statement {
    actions = ["ssm:SendCommand"]

    resources = [
      aws_instance.k3s.arn,
      aws_instance.shop_app.arn,
      aws_instance.dashboard.arn,
      "arn:aws:ssm:${var.region}::document/AWS-RunShellScript"
    ]
  }

  # ssm:GetCommandInvocation 은 EC2/문서 ARN으로 리소스 범위를 제한하는 걸 지원하지
  # 않는 액션이라(커맨드 실행 결과 자체는 ARN으로 식별되는 리소스가 아님), 위
  # SendCommand 문과 같이 묶어서 인스턴스 ARN으로 제한하면 AccessDeniedException이
  # 남. 이 액션만 따로 statement를 분리해서 "*"로 허용해야 한다.
  statement {
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  count = var.github_repository != "" && var.github_oidc_provider_arn != "" ? 1 : 0

  name   = "${var.project}-github-deploy"
  role   = aws_iam_role.github_deploy[0].id
  policy = data.aws_iam_policy_document.github_deploy[0].json
}
