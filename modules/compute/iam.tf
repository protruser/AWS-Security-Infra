data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ec2" {
  for_each = local.instance_role_names

  name               = "${var.project}-${each.key}-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  for_each = local.instance_role_names

  role       = aws_iam_role.ec2[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CPU는 AWS가 기본 제공하지만 메모리는 CloudWatch Agent가 직접 올려야 해서 전 서버에 붙인다.
# (Agent 설정 조회 + cloudwatch:PutMetricData 를 포함하는 AWS 관리형 정책)
resource "aws_iam_role_policy_attachment" "cw_agent" {
  for_each = local.instance_role_names

  role       = aws_iam_role.ec2[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2" {
  for_each = local.instance_role_names

  name = "${var.project}-${each.key}-profile"
  role = aws_iam_role.ec2[each.key].name
}

data "aws_iam_policy_document" "shop_secret_read" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "kms:Decrypt"
    ]

    resources = [
      var.shop_db_secret_arn,
      var.shop_kms_key_arn
    ]
  }
}

resource "aws_iam_role_policy" "shop_app_secret" {
  name   = "${var.project}-shop-secret-read"
  role   = aws_iam_role.ec2["shop-app"].id
  policy = data.aws_iam_policy_document.shop_secret_read.json
}

resource "aws_iam_role_policy" "shop_db_secret" {
  name   = "${var.project}-shop-db-secret-read"
  role   = aws_iam_role.ec2["shop-db"].id
  policy = data.aws_iam_policy_document.shop_secret_read.json
}

data "aws_iam_policy_document" "security_secret_read" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
      "kms:Decrypt"
    ]

    resources = [
      var.security_db_secret_arn,
      var.security_kms_key_arn
    ]
  }
}

resource "aws_iam_role_policy" "dashboard_secret" {
  name   = "${var.project}-security-secret-read"
  role   = aws_iam_role.ec2["dashboard"].id
  policy = data.aws_iam_policy_document.security_secret_read.json
}

resource "aws_iam_role_policy" "security_db_secret" {
  name   = "${var.project}-security-db-secret-read"
  role   = aws_iam_role.ec2["security-db"].id
  policy = data.aws_iam_policy_document.security_secret_read.json
}
