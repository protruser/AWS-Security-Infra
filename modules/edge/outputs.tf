output "shop_alb_dns" {
  value = aws_lb.shop.dns_name
}

output "admin_alb_dns" {
  value = aws_lb.admin.dns_name
}

output "blocked_ip_set" {
  value = {
    id   = aws_wafv2_ip_set.blocked.id
    name = aws_wafv2_ip_set.blocked.name
    arn  = aws_wafv2_ip_set.blocked.arn
  }
}
