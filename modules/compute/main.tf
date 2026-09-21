data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

locals {
  instance_role_names = toset([
    "k3s",
    "shop-app",
    "dashboard",
    "shop-db",
    "security-db"
  ])
}
