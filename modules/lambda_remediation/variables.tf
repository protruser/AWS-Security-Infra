variable "project" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_id" { type = string }
variable "db_secret_arn" { type = string }
variable "kms_key_arn" { type = string }
variable "waf_ip_set_name" { type = string }
variable "waf_ip_set_id" { type = string }
variable "waf_ip_set_arn" { type = string }

variable "instance_ids" {
  type        = map(string)
  description = "재시작을 허용할 서버 (k3s / shop_app / dashboard)"
}

variable "protected_cidrs" {
  type        = list(string)
  description = "절대 차단하지 않을 대역(관리자 IP)"
}
