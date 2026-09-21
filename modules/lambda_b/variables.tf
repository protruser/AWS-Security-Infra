variable "project" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_id" { type = string }
variable "db_secret_arn" { type = string }
variable "kms_key_arn" { type = string }
variable "shop_waf_log_group_arn" { type = string }
variable "admin_waf_log_group_arn" { type = string }
variable "shop_waf_log_group_name" { type = string }
variable "admin_waf_log_group_name" { type = string }

variable "login_paths" {
  type        = string
  description = "무차별 대입을 감시할 로그인 경로(쉼표 구분). 쇼핑몰 앱의 실제 경로로 맞춘다."
  default     = "/login,/api/login,/api/auth/login"
}

variable "brute_threshold" {
  type        = number
  description = "5분 동안 같은 IP 의 로그인 POST 가 이 횟수 이상이면 탐지"
  default     = 10
}
