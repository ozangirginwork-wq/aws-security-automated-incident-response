terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ---------------------------------------------------------
# LAB 6 - AWS Security Detection & Automated Incident Response
#
# This VPC and security group act as the protected target
# for our incident-response automation.
#
# No EC2 instances, NAT Gateways, load balancers,
# or databases are created.
# ---------------------------------------------------------

resource "aws_vpc" "lab6" {
  cidr_block = "10.60.0.0/16"

  tags = {
    Name    = "lab6-incident-response"
    Project = "Lab6"
  }
}

# ---------------------------------------------------------
# Protected Security Group
# ---------------------------------------------------------

resource "aws_security_group" "protected" {
  name        = "lab6-protected-sg"
  description = "Security group protected by automated incident response"
  vpc_id      = aws_vpc.lab6.id

  tags = {
    Name    = "lab6-protected-sg"
    Project = "Lab6"
  }
}
# ---------------------------------------------------------
# Restrict Default Security Group
# ---------------------------------------------------------
# Explicitly manage the VPC default security group with
# no ingress or egress rules.
# ---------------------------------------------------------

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.lab6.id

  ingress = []
  egress  = []

  tags = {
    Name    = "lab6-restricted-default-sg"
    Project = "Lab6"
  }
}