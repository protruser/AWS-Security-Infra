# 콘솔에서 수동으로 만든 IAM 사용자를 Terraform으로 가져와 관리한다.
# 액세스 키의 시크릿 값과 콘솔 로그인 비밀번호는 생성 시점 이후로 AWS가
# 다시 보여주지 않아 Terraform이 그대로 가져올 방법이 없다 - 사용자
# 자체(이름/경로/태그)와 권한 연결까지만 Terraform으로 관리하고, 액세스
# 키/비밀번호는 계속 콘솔에서 그대로 둔다(재생성해서 안 쓰는 기존 키가
# 무효화되는 걸 막기 위함).

resource "aws_iam_user" "admin" {
  name = "admin"
  path = "/"

  # 액세스 키 ID를 그대로 태그 키로 써서 어떤 키가 뭔지 기억해 둔 용도.
  tags = {
    "AKIA3TCWE4Z3P6P7RW5Y" = "terraform-key-2"
    "AKIA3TCWE4Z3N3UZBQ4C" = "terraform-key"
  }
}

resource "aws_iam_user_policy_attachment" "admin_administrator" {
  user       = aws_iam_user.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "tom" {
  name = "tom"
  path = "/"

  tags = {
    "AKIA3TCWE4Z3PTKIIANG" = "tom-access"
  }
}

resource "aws_iam_user_policy_attachment" "tom_change_password" {
  user       = aws_iam_user.tom.name
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}

data "aws_iam_policy_document" "tom_access" {
  statement {
    actions = [
      "sts:GetCallerIdentity",
      "iam:ListUsers",
      "iam:ListRoles",
      "iam:ListAccessKeys",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "tom_access" {
  name        = "tom-access"
  description = "Credential Misuse Test Policy"
  policy      = data.aws_iam_policy_document.tom_access.json
}

resource "aws_iam_user_policy_attachment" "tom_access" {
  user       = aws_iam_user.tom.name
  policy_arn = aws_iam_policy.tom_access.arn
}
