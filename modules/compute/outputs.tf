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

output "shop_db_private_ip" {
  value = aws_instance.shop_db.private_ip
}

output "security_db_private_ip" {
  value = aws_instance.security_db.private_ip
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
