variable "project" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_id" { type = string }
variable "db_secret_arn" { type = string }
variable "kms_key_arn" { type = string }

variable "instance_ids" {
  type        = map(string)
  description = "지표를 모을 서버 5대. 키는 k3s / dashboard / shop_app / shop_db / security_db 로 고정."
}

variable "shop_lb_arn_suffix" { type = string }
variable "shop_tg_arn_suffix" { type = string }
variable "admin_lb_arn_suffix" { type = string }
variable "admin_tg_arn_suffix" { type = string }
