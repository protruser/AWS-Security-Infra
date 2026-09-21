variable "project" { type = string }
variable "enable_security_services" { type = bool }

variable "subnet_ids" {
  type        = list(string)
  description = "서로 다른 AZ의 private subnet 2개"
}

variable "security_group_id" { type = string }
variable "db_secret_arn" { type = string }
variable "kms_key_arn" { type = string }

variable "event_rule_name" {
  type        = string
  description = "Security Hub finding EventBridge 규칙 이름"
  default     = null
}

variable "event_rule_arn" {
  type    = string
  default = null
}
