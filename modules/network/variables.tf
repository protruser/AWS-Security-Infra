variable "project" { type = string }
variable "region" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnet_cidrs" { type = list(string) }

variable "private_subnet_cidrs" {
  type = object({
    service     = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })
}

variable "admin_cidrs" { type = list(string) }
variable "enable_vpc_endpoints" { type = bool }
