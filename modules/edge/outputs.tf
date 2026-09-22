output "shop_alb_dns" {
  value = aws_lb.shop.dns_name
}

output "admin_alb_dns" {
  value = aws_lb.admin.dns_name
}

# CloudWatch에서 ALB/대상 그룹 지표(지연시간·처리량·에러율·정상 대상 수)를 조회할 때 쓰는 식별자.
output "shop_lb_arn_suffix" {
  value = aws_lb.shop.arn_suffix
}

output "shop_tg_arn_suffix" {
  value = aws_lb_target_group.shop.arn_suffix
}

output "admin_lb_arn_suffix" {
  value = aws_lb.admin.arn_suffix
}

output "admin_tg_arn_suffix" {
  value = aws_lb_target_group.admin.arn_suffix
}

output "blocked_ip_set" {
  value = {
    id   = aws_wafv2_ip_set.blocked.id
    name = aws_wafv2_ip_set.blocked.name
    arn  = aws_wafv2_ip_set.blocked.arn
  }
}
