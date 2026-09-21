locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "Terraform"
  }

  # Lambda 는 서로 다른 AZ 의 private subnet 2개에 둔다. (NAT 경유로 AWS API / Secrets Manager 접근)
  lambda_subnet_ids = [module.network.private_subnet_ids["dashboard"], module.network.private_subnet_ids["security_db"]]
}
