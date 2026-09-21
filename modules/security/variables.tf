variable "project" { type = string }
variable "region" { type = string }
variable "vpc_id" { type = string }
variable "shop_db_private_ip" { type = string }
variable "security_db_private_ip" { type = string }
variable "enable_security_services" { type = bool }
variable "notification_email" { type = string }
variable "force_destroy_buckets" { type = bool }
