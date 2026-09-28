# 인프라 레포(AWS-Security-Infra)의 GitHub Actions 가 Terraform 을 돌릴 때 쓰는 역할.
# - terraform-plan : PR 검사(fmt/validate/plan)용. 읽기 전용 + state 읽기 + 락.
# - terraform-apply: 최종 승인 후 배포용. production / terraform-production environment 에서만 assume 가능.
#     production           : 사람이 올린 PR 이 gyu 에 머지된 뒤 GitHub 승인(terraform-apply.yml)
#     terraform-production : 대시보드 최종 승인(서명)을 받은 AI 패치 배포(terraform-patch-deploy.yml)
#
# 레포가 public 이라 fork 에서 PR 이 올 수 있는데, fork PR 의 pull_request 이벤트에는
# OIDC 토큰이 발급되지 않아서 plan 역할도 쓸 수 없다. 워크플로에서
# pull_request_target 으로 fork 코드를 실행하는 일은 절대 없어야 한다.

locals {
  terraform_ci_enabled = var.terraform_ci_repository != "" && var.github_oidc_provider_arn != ""

  terraform_state_bucket_arn = "arn:aws:s3:::${var.terraform_state_bucket}"
  terraform_state_object_arn = "arn:aws:s3:::${var.terraform_state_bucket}/${var.terraform_state_key}"

  # AI 패치 검증(terraform-patch.yml)이 만든 plan 파일. state 버킷의 별도 prefix 에
  # 전용 KMS 키로 암호화해 저장하고, 배포 때 버전 ID 로 정확히 그 파일을 가져온다.
  terraform_patch_plan_arn = "arn:aws:s3:::${var.terraform_state_bucket}/terraform-patches/*"

  terraform_ci_role_arns = [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project}-terraform-plan",
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.project}-terraform-apply"
  ]
}

# ---------- AI 패치 plan 암호화 ----------

resource "aws_kms_key" "terraform_plans" {
  count = local.terraform_ci_enabled ? 1 : 0

  description             = "${var.project} Terraform patch plan files"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "terraform_plans" {
  count = local.terraform_ci_enabled ? 1 : 0

  name          = "alias/${var.project}-terraform-plans"
  target_key_id = aws_kms_key.terraform_plans[0].key_id
}

# ---------- plan ----------

data "aws_iam_policy_document" "terraform_plan_assume" {
  count = local.terraform_ci_enabled ? 1 : 0

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

    # 같은 레포 브랜치에서 올라온 PR, 그리고 gyu 에 머지된 뒤 승인 요청 전에
    # 돌리는 plan(terraform-apply.yml 의 plan job)에서만 쓴다.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.terraform_ci_repository}:pull_request",
        "repo:${var.terraform_ci_repository}:ref:refs/heads/${var.terraform_ci_branch}"
      ]
    }
  }
}

resource "aws_iam_role" "terraform_plan" {
  count = local.terraform_ci_enabled ? 1 : 0

  name               = "${var.project}-terraform-plan"
  assume_role_policy = data.aws_iam_policy_document.terraform_plan_assume[0].json
}

resource "aws_iam_role_policy_attachment" "terraform_plan_readonly" {
  count = local.terraform_ci_enabled ? 1 : 0

  role       = aws_iam_role.terraform_plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ReadOnlyAccess 만으로 부족한 것:
# - S3 네이티브 락: plan 도 <key>.tflock 을 만들고 지운다.
# - aws_secretsmanager_secret_version refresh: secret 값을 읽어야 한다(값은 이미 state 에 있음).
data "aws_iam_policy_document" "terraform_plan" {
  count = local.terraform_ci_enabled ? 1 : 0

  statement {
    actions   = ["s3:ListBucket"]
    resources = [local.terraform_state_bucket_arn]
  }

  statement {
    actions   = ["s3:GetObject"]
    resources = [local.terraform_state_object_arn]
  }

  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.terraform_state_object_arn}.tflock"]
  }

  statement {
    actions   = ["s3:PutObject"]
    resources = [local.terraform_patch_plan_arn]
  }

  statement {
    actions   = ["kms:GenerateDataKey", "kms:Encrypt"]
    resources = [aws_kms_key.terraform_plans[0].arn]
  }

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.shop_db_secret_arn, var.security_db_secret_arn]
  }

  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.shop_kms_key_arn, var.security_kms_key_arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "terraform_plan" {
  count = local.terraform_ci_enabled ? 1 : 0

  name   = "${var.project}-terraform-plan"
  role   = aws_iam_role.terraform_plan[0].id
  policy = data.aws_iam_policy_document.terraform_plan[0].json
}

# ---------- apply ----------

data "aws_iam_policy_document" "terraform_apply_assume" {
  count = local.terraform_ci_enabled ? 1 : 0

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

    # environment 로 들어간 job 만. 허용 브랜치(gyu)는 두 environment 모두
    # GitHub 설정에서 강제한다. production 은 GitHub 승인자, terraform-production 은
    # 대시보드 서명 검증(scripts/verify_patch_authorization.py)이 승인 역할을 한다.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.terraform_ci_repository}:environment:production",
        "repo:${var.terraform_ci_repository}:environment:terraform-production"
      ]
    }
  }
}

resource "aws_iam_role" "terraform_apply" {
  count = local.terraform_ci_enabled ? 1 : 0

  name               = "${var.project}-terraform-apply"
  assume_role_policy = data.aws_iam_policy_document.terraform_apply_assume[0].json
}

# 이 스택은 VPC/EC2/IAM/KMS/WAF/보안 서비스까지 다 만들어서 범위를 좁힌 권한으로는
# apply 가 불가능하다. 그래서 AdministratorAccess 를 주고, AI 가 만든 변경이
# 사람 리뷰를 우회해 넘어오더라도 되돌릴 수 없는 일은 못 하도록 아래 Deny 를 건다.
resource "aws_iam_role_policy_attachment" "terraform_apply_admin" {
  count = local.terraform_ci_enabled ? 1 : 0

  role       = aws_iam_role.terraform_apply[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_iam_policy_document" "terraform_apply_guard" {
  count = local.terraform_ci_enabled ? 1 : 0

  # CI 역할 두 개의 신뢰관계/권한은 CI 로 못 바꾼다(자기 권한 확장 방지).
  # 이 두 역할을 고칠 때는 관리자가 로컬에서 apply 한다.
  statement {
    effect = "Deny"
    actions = [
      "iam:AttachRolePolicy",
      "iam:DeleteRole",
      "iam:DeleteRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy",
      "iam:PutRolePermissionsBoundary",
      "iam:PutRolePolicy",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole"
    ]
    resources = local.terraform_ci_role_arns
  }

  # 장기 자격증명과 OIDC 신뢰 설정은 만들거나 바꾸지 못한다.
  statement {
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:CreateUser",
      "iam:CreateOpenIDConnectProvider",
      "iam:DeleteOpenIDConnectProvider",
      "iam:UpdateOpenIDConnectProviderThumbprint",
      "iam:AddClientIDToOpenIDConnectProvider",
      "iam:RemoveClientIDFromOpenIDConnectProvider"
    ]
    resources = ["*"]
  }

  # state 버킷 설정과 이전 state 버전은 건드리지 못한다(state 쓰기와 락은 허용).
  statement {
    effect = "Deny"
    actions = [
      "s3:DeleteBucket",
      "s3:DeleteBucketPolicy",
      "s3:PutBucketPolicy",
      "s3:PutBucketVersioning",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutEncryptionConfiguration",
      "s3:PutLifecycleConfiguration"
    ]
    resources = [local.terraform_state_bucket_arn]
  }

  statement {
    effect    = "Deny"
    actions   = ["s3:DeleteObjectVersion"]
    resources = ["${local.terraform_state_bucket_arn}/*"]
  }

  # 승인된 plan 을 복호화하는 키. CI 로 지우거나 정책을 바꾸면 배포 증거가 사라진다.
  statement {
    effect = "Deny"
    actions = [
      "kms:DisableKey",
      "kms:PutKeyPolicy",
      "kms:ScheduleKeyDeletion"
    ]
    resources = [aws_kms_key.terraform_plans[0].arn]
  }
}

resource "aws_iam_role_policy" "terraform_apply_guard" {
  count = local.terraform_ci_enabled ? 1 : 0

  name   = "${var.project}-terraform-apply-guard"
  role   = aws_iam_role.terraform_apply[0].id
  policy = data.aws_iam_policy_document.terraform_apply_guard[0].json
}
