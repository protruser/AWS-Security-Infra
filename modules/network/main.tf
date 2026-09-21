data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  public_subnets = {
    public_a = {
      cidr     = var.public_subnet_cidrs[0]
      az_index = 0
    }
    public_b = {
      cidr     = var.public_subnet_cidrs[1]
      az_index = 1
    }
  }

  private_subnets = {
    service = {
      cidr     = var.private_subnet_cidrs.service
      az_index = 0
      name     = "01-service"
    }
    dashboard = {
      cidr     = var.private_subnet_cidrs.dashboard
      az_index = 1
      name     = "02-dashboard"
    }
    shop_db = {
      cidr     = var.private_subnet_cidrs.shop_db
      az_index = 0
      name     = "03-shop-db"
    }
    security_db = {
      cidr     = var.private_subnet_cidrs.security_db
      az_index = 1
      name     = "04-security-db"
    }
  }
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project}-igw"
  }
}

resource "aws_subnet" "public" {
  for_each = local.public_subnets

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = data.aws_availability_zones.available.names[each.value.az_index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-${each.key}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  for_each = local.private_subnets

  vpc_id                  = aws_vpc.main.id
  cidr_block              = each.value.cidr
  availability_zone       = data.aws_availability_zones.available.names[each.value.az_index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-${each.value.name}"
    Tier = "private"
  }
}

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public["public_a"].id

  depends_on = [aws_internet_gateway.main]

  tags = {
    Name = "${var.project}-nat"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Name = "${var.project}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  for_each = aws_subnet.private

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}
