locals {
  docker_install    = file("${path.module}/user_data/docker_install.sh")
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
  subnet_id              = aws_subnet.private["service"].id
  vpc_security_group_ids = [aws_security_group.k3s.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["k3s"].name

  user_data = templatefile("${path.module}/user_data/k3s_nginx.sh.tftpl", {
    docker_install    = local.docker_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.base_packages
    k3s_channel       = var.k3s_channel
    node_port         = 30443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
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
  subnet_id              = aws_subnet.private["dashboard"].id
  vpc_security_group_ids = [aws_security_group.dashboard.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["dashboard"].name

  user_data = templatefile("${path.module}/user_data/app_placeholder.sh.tftpl", {
    docker_install    = local.docker_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.app_packages
    container_name    = "dashboard"
    port              = 8443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.security.arn
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
  subnet_id              = aws_subnet.private["shop_db"].id
  vpc_security_group_ids = [aws_security_group.shop_app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-app"].name

  user_data = templatefile("${path.module}/user_data/app_placeholder.sh.tftpl", {
    docker_install    = local.docker_install
    placeholder_image = local.placeholder_image
    extra_packages    = local.app_packages
    container_name    = "shop-app"
    port              = 8443
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
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
  subnet_id              = aws_subnet.private["shop_db"].id
  vpc_security_group_ids = [aws_security_group.shop_db.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-db"].name

  user_data = templatefile("${path.module}/user_data/mysql.sh.tftpl", {
    docker_install = local.docker_install
    mysql_image    = var.mysql_image
    region         = var.region
    secret_id      = aws_secretsmanager_secret.shop_db.arn
    extra_packages = local.base_packages
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
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
    Name = "${var.server_name_prefix}-03-shop-mysql"
    Role = "shop-db"
  }
}

resource "aws_instance" "security_db" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.security_db
  subnet_id              = aws_subnet.private["security_db"].id
  vpc_security_group_ids = [aws_security_group.security_db.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["security-db"].name

  user_data = templatefile("${path.module}/user_data/mysql.sh.tftpl", {
    docker_install = local.docker_install
    mysql_image    = var.mysql_image
    region         = var.region
    secret_id      = aws_secretsmanager_secret.security_db.arn
    extra_packages = local.base_packages
  })
  user_data_replace_on_change = true

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.security.arn
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
    Name = "${var.server_name_prefix}-04-security-mysql"
    Role = "security-db"
  }
}
