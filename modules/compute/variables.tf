variable "project" { type = string }
variable "region" { type = string }
variable "server_name_prefix" { type = string }
variable "mysql_image" { type = string }
variable "k3s_channel" { type = string }
variable "github_repository" { type = string }
variable "github_oidc_provider_arn" { type = string }

variable "instance_types" {
  type = object({
    k3s         = string
    shop_app    = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })
}

variable "private_subnet_ids" { type = map(string) }
variable "security_group_ids" { type = map(string) }

variable "shop_kms_key_arn" { type = string }
variable "security_kms_key_arn" { type = string }
variable "shop_db_secret_arn" { type = string }
variable "security_db_secret_arn" { type = string }
variable "shop_waf_log_group_arn" { type = string }
variable "admin_waf_log_group_arn" { type = string }
variable "vpc_flow_log_group_arn" { type = string }
variable "security_logs_bucket_arn" { type = string }
