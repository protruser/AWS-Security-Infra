output "shop_alb_dns" {
  value = aws_lb.shop.dns_name
}

output "admin_alb_dns" {
  value = aws_lb.admin.dns_name
}
