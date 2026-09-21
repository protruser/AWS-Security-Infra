output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = { for k, v in aws_subnet.public : k => v.id }
}

output "private_subnet_ids" {
  value = { for k, v in aws_subnet.private : k => v.id }
}

output "security_group_ids" {
  value = {
    shop_alb    = aws_security_group.shop_alb.id
    admin_alb   = aws_security_group.admin_alb.id
    k3s         = aws_security_group.k3s.id
    shop_app    = aws_security_group.shop_app.id
    shop_db     = aws_security_group.shop_db.id
    dashboard   = aws_security_group.dashboard.id
    lambda      = aws_security_group.lambda.id
    security_db = aws_security_group.security_db.id
  }
}
