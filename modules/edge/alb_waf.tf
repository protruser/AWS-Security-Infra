resource "aws_lb" "shop" {
  name               = "${var.project}-shop-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [var.security_group_ids["shop_alb"]]
  subnets            = values(var.public_subnet_ids)

  tags = {
    Name = "${var.project}-shop-alb"
  }
}

resource "aws_lb" "admin" {
  name               = "${var.project}-admin-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [var.security_group_ids["admin_alb"]]
  subnets            = values(var.public_subnet_ids)

  tags = {
    Name = "${var.project}-admin-alb"
  }
}

resource "aws_lb_target_group" "shop" {
  name     = "${var.project}-shop-tg"
  port     = 30443
  protocol = "HTTPS"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/health"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_target_group" "admin" {
  # 고정 name 대신 name_prefix를 써서 교체 시 새 타깃그룹을 먼저 만들고
  # (create_before_destroy) 리스너를 옮긴 뒤 기존 것을 지우게 한다.
  # (고정 name이면 기존 그룹이 아직 있는 동안 같은 이름으로 새로 못 만듦)
  # aws_lb_target_group의 name_prefix는 6자 제한이 있다.
  name_prefix = "admtg-"
  port        = 8443
  # 대시보드 컨테이너(gunicorn)는 TLS 없이 평범한 HTTP로 8443을 서빙한다.
  # ALB가 HTTPS로 백엔드에 접속을 시도하면 TLS 핸드셰이크가 실패/타임아웃되어
  # 502/504 및 헬스체크 unhealthy(Target.Timeout)로 이어진다.
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTP"
    # Flask 앱의 실제 헬스체크 라우트는 /api/health 뿐이다 (옛 nginx
    # 플레이스홀더의 /health 를 그대로 쓰면 404로 계속 unhealthy 처리됨).
    path                = "/api/health"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }

  tags = {
    Name = "${var.project}-admin-tg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group_attachment" "shop" {
  target_group_arn = aws_lb_target_group.shop.arn
  target_id        = var.k3s_instance_id
  port             = 30443
}

resource "aws_lb_target_group_attachment" "admin" {
  target_group_arn = aws_lb_target_group.admin.arn
  target_id        = var.dashboard_instance_id
  port             = 8443
}

# 도메인이 없을 때: ALB 기본 DNS로 HTTP 접속
resource "aws_lb_listener" "shop_http_forward" {
  count = var.enable_custom_domain ? 0 : 1

  load_balancer_arn = aws_lb.shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.shop.arn
  }
}

resource "aws_lb_listener" "admin_http_forward" {
  count = var.enable_custom_domain ? 0 : 1

  load_balancer_arn = aws_lb.admin.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.admin.arn
  }
}

# 도메인이 있을 때: HTTP -> HTTPS
resource "aws_lb_listener" "shop_http_redirect" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "admin_http_redirect" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.admin.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl" "shop" {
  name  = "${var.project}-shop-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockedIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-blocked-ips"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSCommonRules"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSSQLiRules"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimit"
    priority = 30

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.shop_rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-shop-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl" "admin" {
  name  = "${var.project}-admin-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockedIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-admin-blocked-ips"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSCommonRules"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-admin-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AdminRateLimit"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.admin_rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-admin-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-admin-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "shop" {
  resource_arn = aws_lb.shop.arn
  web_acl_arn  = aws_wafv2_web_acl.shop.arn
}

resource "aws_wafv2_web_acl_association" "admin" {
  resource_arn = aws_lb.admin.arn
  web_acl_arn  = aws_wafv2_web_acl.admin.arn
}


resource "aws_wafv2_web_acl_logging_configuration" "shop" {
  resource_arn            = aws_wafv2_web_acl.shop.arn
  log_destination_configs = [var.shop_waf_log_group_arn]
}

resource "aws_wafv2_web_acl_logging_configuration" "admin" {
  resource_arn            = aws_wafv2_web_acl.admin.arn
  log_destination_configs = [var.admin_waf_log_group_arn]
}

# Lambda Remediation 이 채우는 공격 IP 차단 목록. 주소 목록은 Lambda 가 관리하므로 Terraform 은 건드리지 않는다.
resource "aws_wafv2_ip_set" "blocked" {
  name               = "${var.project}-blocked-ips"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  lifecycle {
    ignore_changes = [addresses]
  }
}
