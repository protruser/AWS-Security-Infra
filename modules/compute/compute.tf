locals {
  docker_install    = file("${path.module}/user_data/docker_install.sh")
  cw_agent_install  = file("${path.module}/user_data/cwagent_install.sh")
  placeholder_image = "nginx:stable-alpine"

  # 점검용 도구. app_packages 의 mariadb105 는 MySQL 클라이언트(DB 연결 확인용).
  base_packages = "jq git htop"
  app_packages  = "jq git htop mariadb105"
}

# 모든 서버는 첫 부팅 때 Docker 를 설치한다.
# - k3s-nginx: k3s 를 설치하고 NodePort 30443 으로 자리표시자 nginx 를 띄운다.
# - shop-app / dashboard: 같은 포트에서 /health 를 주는 자리표시자 컨테이너를 띄운다.
# - shop-mysql / security-mysql: Secrets Manager 접속 정보로 MySQL 컨테이너를 띄운다.
# 실제 앱은 이후 GitHub Actions 가 ECR 이미지로 교체한다.
# depends_on: 서버가 켜질 때 SSM/ECR 권한이 이미 붙어 있도록 순서를 강제한다.
# user_data_replace_on_change: user_data 는 첫 부팅에만 실행되므로 바뀌면 서버를 교체한다.
#   (DB 서버는 데이터가 쌓이기 시작하면 이 옵션을 끄거나 ignore_changes 로 바꿔야 한다.)

resource "aws_instance" "k3s" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.k3s
  subnet_id              = var.private_subnet_ids["service"]
  vpc_security_group_ids = [var.security_group_ids["k3s"]]
  iam_instance_profile   = aws_iam_instance_profile.ec2["k3s"].name

  user_data = templatefile("${path.module}/user_data/k3s_nginx.sh.tftpl", {
    docker_install    = local.docker_install
    cw_agent_install  = local.cw_agent_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.base_packages
    k3s_channel       = var.k3s_channel
    node_port         = 30443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = var.shop_kms_key_arn
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm["k3s"],
    aws_iam_role_policy.ecr_pull["k3s"]
  ]

  tags = {
    Name = "${var.server_name_prefix}-01-k3s-nginx"
    Role = "k3s-nginx"
  }
}

resource "aws_instance" "dashboard" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.dashboard
  subnet_id              = var.private_subnet_ids["dashboard"]
  vpc_security_group_ids = [var.security_group_ids["dashboard"]]
  iam_instance_profile   = aws_iam_instance_profile.ec2["dashboard"].name

  user_data = templatefile("${path.module}/user_data/app_placeholder.sh.tftpl", {
    docker_install    = local.docker_install
    cw_agent_install  = local.cw_agent_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.app_packages
    container_name    = "dashboard"
    port              = 8443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = var.security_kms_key_arn
    volume_type = "gp3"
    volume_size = 20
  }

  # 컨테이너 안의 boto3 가 인스턴스 역할 자격증명을 받으려면 IMDS 홉이 2 여야 한다.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm["dashboard"],
    aws_iam_role_policy.ecr_pull["dashboard"],
    aws_iam_role_policy.dashboard_secret,
    aws_iam_role_policy.dashboard_aws_read
  ]

  tags = {
    Name = "${var.server_name_prefix}-02-dashboard"
    Role = "dashboard"
  }
}

resource "aws_instance" "shop_app" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.shop_app
  subnet_id              = var.private_subnet_ids["shop_db"]
  vpc_security_group_ids = [var.security_group_ids["shop_app"]]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-app"].name

  user_data = templatefile("${path.module}/user_data/app_placeholder.sh.tftpl", {
    docker_install    = local.docker_install
    cw_agent_install  = local.cw_agent_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.app_packages
    container_name    = "shop-app"
    port              = 8443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = var.shop_kms_key_arn
    volume_type = "gp3"
    volume_size = 20
  }

  # 컨테이너 안의 앱이 Secrets Manager 를 읽을 수 있도록 IMDS 홉을 2 로 둔다.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm["shop-app"],
    aws_iam_role_policy.ecr_pull["shop-app"],
    aws_iam_role_policy.shop_app_secret
  ]

  tags = {
    Name = "${var.server_name_prefix}-03-shop-app"
    Role = "shop-app"
  }
}

# DB 서버는 Secrets Manager 의 접속 정보로 MySQL 컨테이너를 만든다.
resource "aws_instance" "shop_db" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.shop_db
  subnet_id              = var.private_subnet_ids["shop_db"]
  vpc_security_group_ids = [var.security_group_ids["shop_db"]]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-db"].name

  user_data = templatefile("${path.module}/user_data/mysql.sh.tftpl", {
    docker_install   = local.docker_install
    cw_agent_install = local.cw_agent_install
    mysql_image      = var.mysql_image
    region           = var.region
    secret_id        = var.shop_db_secret_arn
    extra_packages   = local.base_packages
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = var.shop_kms_key_arn
    volume_type = "gp3"
    volume_size = 30
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm["shop-db"],
    aws_iam_role_policy.shop_db_secret
  ]

  tags = {
    Name = "${var.server_name_prefix}-04-shop-mysql"
    Role = "shop-db"
  }

  # 데이터가 쌓이는 DB 서버는 user_data(설치 스크립트)가 바뀌어도 재생성하지 않는다.
  # (템플릿은 계속 최신으로 유지하되, 이미 떠 있는 서버는 건드리지 않는다. 새 항목은 SSM으로 수동 적용.)
  lifecycle {
    ignore_changes = [user_data]
  }
}

resource "aws_instance" "security_db" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.security_db
  subnet_id              = var.private_subnet_ids["security_db"]
  vpc_security_group_ids = [var.security_group_ids["security_db"]]
  iam_instance_profile   = aws_iam_instance_profile.ec2["security-db"].name

  user_data = templatefile("${path.module}/user_data/mysql.sh.tftpl", {
    docker_install   = local.docker_install
    cw_agent_install = local.cw_agent_install
    mysql_image      = var.mysql_image
    region           = var.region
    secret_id        = var.security_db_secret_arn
    extra_packages   = local.base_packages
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = var.security_kms_key_arn
    volume_type = "gp3"
    volume_size = 30
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [
    aws_iam_role_policy_attachment.ssm["security-db"],
    aws_iam_role_policy.security_db_secret
  ]

  tags = {
    Name = "${var.server_name_prefix}-05-security-mysql"
    Role = "security-db"
  }

  # 이미 탐지 데이터가 쌓이고 있는 서버라서, user_data가 바뀌어도 재생성하지 않는다.
  lifecycle {
    ignore_changes = [user_data]
  }
}
