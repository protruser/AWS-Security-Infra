output "vpc_id" {
  value = module.network.vpc_id
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "shop_alb_dns" {
  value = module.edge.shop_alb_dns
}

output "admin_alb_dns" {
  value = module.edge.admin_alb_dns
}

output "shop_url" {
  value = var.enable_custom_domain ? "https://${var.shop_domain}" : "http://${module.edge.shop_alb_dns}"
}

output "admin_url" {
  value = var.enable_custom_domain ? "https://${var.admin_domain}" : "http://${module.edge.admin_alb_dns}"
}

output "security_log_bucket" {
  value = module.security.security_logs_bucket
}

output "ecr_repositories" {
  value = module.compute.ecr_repositories
}

output "github_deploy_role_arn" {
  value = module.compute.github_deploy_role_arn
}

output "instance_ids" {
  description = "GitHub Actions(SSM) 배포 대상 서버 ID"
  value       = module.compute.instance_ids
}
