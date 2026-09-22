# 루트는 모듈을 연결만 한다. 실제 리소스는 modules/ 아래에 있다.
#
#   network   VPC / Subnet / NAT / Security Group / VPC Endpoint
#   security  KMS / Secrets Manager / S3 로그 / CloudTrail / Flow Logs / GuardDuty 등 / WAF 로그 그룹
#   compute   EC2 5대 / IAM / ECR / GitHub OIDC
#   edge      ALB / WAF / ACM / Route53
#   lambda_a            Security Hub finding -> Security MySQL
#   lambda_b            WAF 로그 분석 -> Security MySQL (5분마다)
#   lambda_c            CloudWatch 지표(CPU/메모리/지연/처리량/에러율/상태) -> Security MySQL (5분마다)
#   lambda_remediation  대시보드 승인 -> WAF IP 차단 / SSM 재시작 / Access Key 비활성화

module "network" {
  source = "./modules/network"

  project              = var.project
  region               = var.region
  vpc_cidr             = var.vpc_cidr
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  admin_cidrs          = var.admin_cidrs
  enable_vpc_endpoints = var.enable_vpc_endpoints
}

module "security" {
  source = "./modules/security"

  project                  = var.project
  region                   = var.region
  vpc_id                   = module.network.vpc_id
  shop_db_private_ip       = module.compute.shop_db_private_ip
  security_db_private_ip   = module.compute.security_db_private_ip
  enable_security_services = var.enable_security_services
  force_destroy_buckets    = var.force_destroy_buckets
}

module "compute" {
  source = "./modules/compute"

  project                  = var.project
  region                   = var.region
  server_name_prefix       = var.server_name_prefix
  instance_types           = var.instance_types
  mysql_image              = var.mysql_image
  k3s_channel              = var.k3s_channel
  github_repositories      = var.github_repositories
  github_oidc_provider_arn = var.github_oidc_provider_arn

  private_subnet_ids = module.network.private_subnet_ids
  security_group_ids = module.network.security_group_ids

  shop_kms_key_arn         = module.security.shop_kms_key_arn
  security_kms_key_arn     = module.security.security_kms_key_arn
  shop_db_secret_arn       = module.security.shop_db_secret_arn
  security_db_secret_arn   = module.security.security_db_secret_arn
  shop_waf_log_group_arn   = module.security.shop_waf_log_group_arn
  admin_waf_log_group_arn  = module.security.admin_waf_log_group_arn
  vpc_flow_log_group_arn   = module.security.vpc_flow_log_group_arn
  security_logs_bucket_arn = module.security.security_logs_bucket_arn
}

module "edge" {
  source = "./modules/edge"

  project               = var.project
  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  security_group_ids    = module.network.security_group_ids
  k3s_instance_id       = module.compute.instance_ids["k3s"]
  dashboard_instance_id = module.compute.instance_ids["dashboard"]

  shop_waf_log_group_arn  = module.security.shop_waf_log_group_arn
  admin_waf_log_group_arn = module.security.admin_waf_log_group_arn

  shop_rate_limit      = var.shop_rate_limit
  admin_rate_limit     = var.admin_rate_limit
  enable_custom_domain = var.enable_custom_domain
  route53_zone_id      = var.route53_zone_id
  shop_domain          = var.shop_domain
  admin_domain         = var.admin_domain
}

module "lambda_a" {
  source = "./modules/lambda_a"

  project                  = var.project
  enable_security_services = var.enable_security_services

  subnet_ids        = local.lambda_subnet_ids
  security_group_id = module.network.security_group_ids["lambda"]
  db_secret_arn     = module.security.security_db_secret_arn
  kms_key_arn       = module.security.security_kms_key_arn

  event_rule_name = module.security.securityhub_rule_name
  event_rule_arn  = module.security.securityhub_rule_arn
}

module "lambda_b" {
  source = "./modules/lambda_b"

  project           = var.project
  subnet_ids        = local.lambda_subnet_ids
  security_group_id = module.network.security_group_ids["lambda"]
  db_secret_arn     = module.security.security_db_secret_arn
  kms_key_arn       = module.security.security_kms_key_arn

  shop_waf_log_group_arn   = module.security.shop_waf_log_group_arn
  admin_waf_log_group_arn  = module.security.admin_waf_log_group_arn
  shop_waf_log_group_name  = module.security.shop_waf_log_group_name
  admin_waf_log_group_name = module.security.admin_waf_log_group_name
}

module "lambda_c" {
  source = "./modules/lambda_c"

  project           = var.project
  subnet_ids        = local.lambda_subnet_ids
  security_group_id = module.network.security_group_ids["lambda"]
  db_secret_arn     = module.security.security_db_secret_arn
  kms_key_arn       = module.security.security_kms_key_arn

  # dashboard/security_db는 지표 수집 대상에서 제외 (k3s/shop_app/shop_db 3대만)
  instance_ids = {
    k3s      = module.compute.instance_ids["k3s"]
    shop_app = module.compute.instance_ids["shop_app"]
    shop_db  = module.compute.instance_ids["shop_db"]
  }

  shop_lb_arn_suffix = module.edge.shop_lb_arn_suffix
  shop_tg_arn_suffix = module.edge.shop_tg_arn_suffix
}

module "lambda_remediation" {
  source = "./modules/lambda_remediation"

  project           = var.project
  subnet_ids        = local.lambda_subnet_ids
  security_group_id = module.network.security_group_ids["lambda"]
  db_secret_arn     = module.security.security_db_secret_arn
  kms_key_arn       = module.security.security_kms_key_arn

  waf_ip_set_id   = module.edge.blocked_ip_set.id
  waf_ip_set_name = module.edge.blocked_ip_set.name
  waf_ip_set_arn  = module.edge.blocked_ip_set.arn

  instance_ids = {
    k3s       = module.compute.instance_ids["k3s"]
    shop_app  = module.compute.instance_ids["shop_app"]
    dashboard = module.compute.instance_ids["dashboard"]
  }
  protected_cidrs = var.admin_cidrs
}
