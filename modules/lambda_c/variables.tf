variable "project" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_id" { type = string }
variable "db_secret_arn" { type = string }
variable "kms_key_arn" { type = string }

variable "instance_ids" {
  type        = map(string)
  description = "지표를 모을 서버 3대(k3s / shop_app / shop_db). dashboard/security_db는 제외."
}

variable "shop_lb_arn_suffix" { type = string }
variable "shop_tg_arn_suffix" { type = string }
