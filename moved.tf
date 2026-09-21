# 기존 단일 루트 구성에서 모듈 구조로 옮기면서 리소스 주소만 바뀌도록 하는 moved 블록.
# 이 블록이 있어야 terraform apply 때 리소스를 삭제/재생성하지 않고 state 주소만 이동한다.
# 모든 환경에서 apply 가 끝난 뒤에는 삭제해도 된다.

moved {
  from = aws_ecr_repository.dashboard
  to   = module.compute.aws_ecr_repository.dashboard
}

moved {
  from = aws_ecr_repository.nginx
  to   = module.compute.aws_ecr_repository.nginx
}

moved {
  from = aws_ecr_repository.shop_app
  to   = module.compute.aws_ecr_repository.shop_app
}

moved {
  from = aws_iam_instance_profile.ec2
  to   = module.compute.aws_iam_instance_profile.ec2
}

moved {
  from = aws_iam_role.ec2
  to   = module.compute.aws_iam_role.ec2
}

moved {
  from = aws_iam_role.github_deploy
  to   = module.compute.aws_iam_role.github_deploy
}

moved {
  from = aws_iam_role_policy.dashboard_aws_read
  to   = module.compute.aws_iam_role_policy.dashboard_aws_read
}

moved {
  from = aws_iam_role_policy.dashboard_secret
  to   = module.compute.aws_iam_role_policy.dashboard_secret
}

moved {
  from = aws_iam_role_policy.ecr_pull
  to   = module.compute.aws_iam_role_policy.ecr_pull
}

moved {
  from = aws_iam_role_policy.github_deploy
  to   = module.compute.aws_iam_role_policy.github_deploy
}

moved {
  from = aws_iam_role_policy.security_db_secret
  to   = module.compute.aws_iam_role_policy.security_db_secret
}

moved {
  from = aws_iam_role_policy.shop_app_secret
  to   = module.compute.aws_iam_role_policy.shop_app_secret
}

moved {
  from = aws_iam_role_policy.shop_db_secret
  to   = module.compute.aws_iam_role_policy.shop_db_secret
}

moved {
  from = aws_iam_role_policy_attachment.ssm
  to   = module.compute.aws_iam_role_policy_attachment.ssm
}

moved {
  from = aws_instance.dashboard
  to   = module.compute.aws_instance.dashboard
}

moved {
  from = aws_instance.k3s
  to   = module.compute.aws_instance.k3s
}

moved {
  from = aws_instance.security_db
  to   = module.compute.aws_instance.security_db
}

moved {
  from = aws_instance.shop_app
  to   = module.compute.aws_instance.shop_app
}

moved {
  from = aws_instance.shop_db
  to   = module.compute.aws_instance.shop_db
}

moved {
  from = aws_acm_certificate.admin
  to   = module.edge.aws_acm_certificate.admin
}

moved {
  from = aws_acm_certificate.shop
  to   = module.edge.aws_acm_certificate.shop
}

moved {
  from = aws_acm_certificate_validation.admin
  to   = module.edge.aws_acm_certificate_validation.admin
}

moved {
  from = aws_acm_certificate_validation.shop
  to   = module.edge.aws_acm_certificate_validation.shop
}

moved {
  from = aws_lb.admin
  to   = module.edge.aws_lb.admin
}

moved {
  from = aws_lb.shop
  to   = module.edge.aws_lb.shop
}

moved {
  from = aws_lb_listener.admin_http_forward
  to   = module.edge.aws_lb_listener.admin_http_forward
}

moved {
  from = aws_lb_listener.admin_http_redirect
  to   = module.edge.aws_lb_listener.admin_http_redirect
}

moved {
  from = aws_lb_listener.admin_https
  to   = module.edge.aws_lb_listener.admin_https
}

moved {
  from = aws_lb_listener.shop_http_forward
  to   = module.edge.aws_lb_listener.shop_http_forward
}

moved {
  from = aws_lb_listener.shop_http_redirect
  to   = module.edge.aws_lb_listener.shop_http_redirect
}

moved {
  from = aws_lb_listener.shop_https
  to   = module.edge.aws_lb_listener.shop_https
}

moved {
  from = aws_lb_target_group.admin
  to   = module.edge.aws_lb_target_group.admin
}

moved {
  from = aws_lb_target_group.shop
  to   = module.edge.aws_lb_target_group.shop
}

moved {
  from = aws_lb_target_group_attachment.admin
  to   = module.edge.aws_lb_target_group_attachment.admin
}

moved {
  from = aws_lb_target_group_attachment.shop
  to   = module.edge.aws_lb_target_group_attachment.shop
}

moved {
  from = aws_route53_record.admin
  to   = module.edge.aws_route53_record.admin
}

moved {
  from = aws_route53_record.admin_validation
  to   = module.edge.aws_route53_record.admin_validation
}

moved {
  from = aws_route53_record.shop
  to   = module.edge.aws_route53_record.shop
}

moved {
  from = aws_route53_record.shop_validation
  to   = module.edge.aws_route53_record.shop_validation
}

moved {
  from = aws_wafv2_web_acl.admin
  to   = module.edge.aws_wafv2_web_acl.admin
}

moved {
  from = aws_wafv2_web_acl.shop
  to   = module.edge.aws_wafv2_web_acl.shop
}

moved {
  from = aws_wafv2_web_acl_association.admin
  to   = module.edge.aws_wafv2_web_acl_association.admin
}

moved {
  from = aws_wafv2_web_acl_association.shop
  to   = module.edge.aws_wafv2_web_acl_association.shop
}

moved {
  from = aws_wafv2_web_acl_logging_configuration.admin
  to   = module.edge.aws_wafv2_web_acl_logging_configuration.admin
}

moved {
  from = aws_wafv2_web_acl_logging_configuration.shop
  to   = module.edge.aws_wafv2_web_acl_logging_configuration.shop
}

moved {
  from = aws_eip.nat
  to   = module.network.aws_eip.nat
}

moved {
  from = aws_internet_gateway.main
  to   = module.network.aws_internet_gateway.main
}

moved {
  from = aws_nat_gateway.main
  to   = module.network.aws_nat_gateway.main
}

moved {
  from = aws_route_table.private
  to   = module.network.aws_route_table.private
}

moved {
  from = aws_route_table.public
  to   = module.network.aws_route_table.public
}

moved {
  from = aws_route_table_association.private
  to   = module.network.aws_route_table_association.private
}

moved {
  from = aws_route_table_association.public
  to   = module.network.aws_route_table_association.public
}

moved {
  from = aws_security_group.admin_alb
  to   = module.network.aws_security_group.admin_alb
}

moved {
  from = aws_security_group.dashboard
  to   = module.network.aws_security_group.dashboard
}

moved {
  from = aws_security_group.k3s
  to   = module.network.aws_security_group.k3s
}

moved {
  from = aws_security_group.lambda
  to   = module.network.aws_security_group.lambda
}

moved {
  from = aws_security_group.security_db
  to   = module.network.aws_security_group.security_db
}

moved {
  from = aws_security_group.shop_alb
  to   = module.network.aws_security_group.shop_alb
}

moved {
  from = aws_security_group.shop_app
  to   = module.network.aws_security_group.shop_app
}

moved {
  from = aws_security_group.shop_db
  to   = module.network.aws_security_group.shop_db
}

moved {
  from = aws_security_group.vpce
  to   = module.network.aws_security_group.vpce
}

moved {
  from = aws_subnet.private
  to   = module.network.aws_subnet.private
}

moved {
  from = aws_subnet.public
  to   = module.network.aws_subnet.public
}

moved {
  from = aws_vpc.main
  to   = module.network.aws_vpc.main
}

moved {
  from = aws_vpc_endpoint.interface
  to   = module.network.aws_vpc_endpoint.interface
}

moved {
  from = aws_vpc_endpoint.s3
  to   = module.network.aws_vpc_endpoint.s3
}

moved {
  from = aws_accessanalyzer_analyzer.main
  to   = module.security.aws_accessanalyzer_analyzer.main
}

moved {
  from = aws_cloudtrail.main
  to   = module.security.aws_cloudtrail.main
}

moved {
  from = aws_cloudwatch_event_rule.securityhub_findings
  to   = module.security.aws_cloudwatch_event_rule.securityhub_findings
}

moved {
  from = aws_cloudwatch_event_target.securityhub_to_sns
  to   = module.security.aws_cloudwatch_event_target.securityhub_to_sns
}

moved {
  from = aws_cloudwatch_log_group.admin_waf
  to   = module.security.aws_cloudwatch_log_group.admin_waf
}

moved {
  from = aws_cloudwatch_log_group.shop_waf
  to   = module.security.aws_cloudwatch_log_group.shop_waf
}

moved {
  from = aws_cloudwatch_log_group.vpc_flow
  to   = module.security.aws_cloudwatch_log_group.vpc_flow
}

moved {
  from = aws_flow_log.vpc
  to   = module.security.aws_flow_log.vpc
}

moved {
  from = aws_guardduty_detector.main
  to   = module.security.aws_guardduty_detector.main
}

moved {
  from = aws_iam_role.flow_logs
  to   = module.security.aws_iam_role.flow_logs
}

moved {
  from = aws_iam_role_policy.flow_logs
  to   = module.security.aws_iam_role_policy.flow_logs
}

moved {
  from = aws_inspector2_enabler.main
  to   = module.security.aws_inspector2_enabler.main
}

moved {
  from = aws_kms_alias.security
  to   = module.security.aws_kms_alias.security
}

moved {
  from = aws_kms_alias.shop
  to   = module.security.aws_kms_alias.shop
}

moved {
  from = aws_kms_key.security
  to   = module.security.aws_kms_key.security
}

moved {
  from = aws_kms_key.shop
  to   = module.security.aws_kms_key.shop
}

moved {
  from = aws_s3_bucket.security_logs
  to   = module.security.aws_s3_bucket.security_logs
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.security_logs
  to   = module.security.aws_s3_bucket_lifecycle_configuration.security_logs
}

moved {
  from = aws_s3_bucket_policy.security_logs
  to   = module.security.aws_s3_bucket_policy.security_logs
}

moved {
  from = aws_s3_bucket_public_access_block.security_logs
  to   = module.security.aws_s3_bucket_public_access_block.security_logs
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.security_logs
  to   = module.security.aws_s3_bucket_server_side_encryption_configuration.security_logs
}

moved {
  from = aws_s3_bucket_versioning.security_logs
  to   = module.security.aws_s3_bucket_versioning.security_logs
}

moved {
  from = aws_secretsmanager_secret.security_db
  to   = module.security.aws_secretsmanager_secret.security_db
}

moved {
  from = aws_secretsmanager_secret.shop_db
  to   = module.security.aws_secretsmanager_secret.shop_db
}

moved {
  from = aws_secretsmanager_secret_version.security_db
  to   = module.security.aws_secretsmanager_secret_version.security_db
}

moved {
  from = aws_secretsmanager_secret_version.shop_db
  to   = module.security.aws_secretsmanager_secret_version.shop_db
}

moved {
  from = aws_securityhub_account.main
  to   = module.security.aws_securityhub_account.main
}

moved {
  from = aws_sns_topic.security_alerts
  to   = module.security.aws_sns_topic.security_alerts
}

moved {
  from = aws_sns_topic_policy.security_alerts
  to   = module.security.aws_sns_topic_policy.security_alerts
}

moved {
  from = aws_sns_topic_subscription.email
  to   = module.security.aws_sns_topic_subscription.email
}

moved {
  from = random_password.security_db
  to   = module.security.random_password.security_db
}

moved {
  from = random_password.shop_db
  to   = module.security.random_password.shop_db
}
