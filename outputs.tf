output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = {
    for k, v in aws_subnet.private : k => v.id
  }
}

output "shop_alb_dns" {
  value = aws_lb.shop.dns_name
}

output "admin_alb_dns" {
  value = aws_lb.admin.dns_name
}

output "shop_url" {
  value = var.enable_custom_domain ? "https://${var.shop_domain}" : "http://${aws_lb.shop.dns_name}"
}

output "admin_url" {
  value = var.enable_custom_domain ? "https://${var.admin_domain}" : "http://${aws_lb.admin.dns_name}"
}

output "security_log_bucket" {
  value = aws_s3_bucket.security_logs.bucket
}

output "ecr_repositories" {
  value = {
    nginx     = aws_ecr_repository.nginx.repository_url
    shop_app  = aws_ecr_repository.shop_app.repository_url
    dashboard = aws_ecr_repository.dashboard.repository_url
  }
}

output "github_deploy_role_arn" {
  value = try(aws_iam_role.github_deploy[0].arn, null)
}

output "instance_ids" {
  description = "GitHub Actions(SSM) 배포 대상 서버 ID"
  value = {
    k3s         = aws_instance.k3s.id
    shop_app    = aws_instance.shop_app.id
    dashboard   = aws_instance.dashboard.id
    shop_db     = aws_instance.shop_db.id
    security_db = aws_instance.security_db.id
  }
}
