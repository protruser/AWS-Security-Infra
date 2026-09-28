terraform {
  required_version = ">= 1.10.0"

  # state 는 로컬이 아니라 S3 에 둔다(GitHub Actions 에서도 같은 state 를 쓰기 위함).
  # 버킷은 이 스택의 관리 대상이 아니다. 락은 S3 네이티브 락(.tflock)을 쓴다.
  backend "s3" {
    bucket       = "wonny-terraform-state"
    key          = "production/terraform.tfstate"
    region       = "ap-northeast-2"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}
