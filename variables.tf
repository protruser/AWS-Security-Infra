variable "region" {
  type        = string
  description = "AWS region"
  default     = "ap-northeast-2"
}

variable "project" {
  type        = string
  description = "Resource name prefix"
  default     = "wonny-sec"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type = list(string)
  default = [
    "10.0.10.0/24",
    "10.0.20.0/24"
  ]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "ALB 사용을 위해 서로 다른 AZ의 Public Subnet이 최소 2개 필요합니다."
  }
}

variable "private_subnet_cidrs" {
  type = object({
    service     = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })

  default = {
    service     = "10.0.1.0/24"
    dashboard   = "10.0.2.0/24"
    shop_db     = "10.0.3.0/24"
    security_db = "10.0.4.0/24"
  }
}

variable "admin_cidrs" {
  type        = list(string)
  description = "관리자 대시보드 접근 허용 공인 IP/CIDR"
}

variable "enable_custom_domain" {
  type        = bool
  description = "Route53 + ACM + HTTPS 사용 여부"
  default     = false
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 Public Hosted Zone ID"
  default     = ""
}

variable "shop_domain" {
  type        = string
  description = "예: shop.example.com"
  default     = ""
}

variable "admin_domain" {
  type        = string
  description = "예: security.example.com"
  default     = ""
}

variable "enable_security_services" {
  type    = bool
  default = true
}

variable "enable_vpc_endpoints" {
  type        = bool
  description = "SSM/Logs/ECR/Secrets Interface Endpoint 생성. 비용 발생."
  default     = false
}

variable "force_destroy_buckets" {
  type    = bool
  default = false
}

variable "instance_types" {
  type = object({
    k3s         = string
    shop_app    = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })

  default = {
    k3s         = "t3.small"
    shop_app    = "t3.small"
    dashboard   = "t3.small"
    shop_db     = "t3.small"
    security_db = "t3.small"
  }
}

variable "shop_rate_limit" {
  type        = number
  description = "WAF 5분 기준 IP별 요청 한도"
  default     = 1000
}

variable "admin_rate_limit" {
  type        = number
  description = "관리자 WAF 5분 기준 IP별 요청 한도"
  default     = 300
}

variable "github_repository" {
  type        = string
  description = "예: owner/repository"
  default     = ""
}

variable "github_oidc_provider_arn" {
  type        = string
  description = "기존 GitHub Actions OIDC Provider ARN. 없으면 비워둠."
  default     = ""
}

variable "mysql_image" {
  type        = string
  description = "DB 서버에서 실행할 MySQL Docker 이미지"
  default     = "mysql:8.0"
}

variable "k3s_channel" {
  type        = string
  description = "k3s 설치 채널(stable, latest, v1.xx 등). 재현성이 필요하면 특정 버전 채널로 고정"
  default     = "stable"
}

variable "server_name_prefix" {
  type        = string
  description = "EC2 서버 Name 태그 접두사. 이름표만 바뀌며 다른 리소스에는 영향 없음."
  default     = "dragon"
}
