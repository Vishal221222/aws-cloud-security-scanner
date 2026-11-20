terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "private_artifacts" {
  bucket = var.bucket_name

  tags = {
    Name        = "private-security-artifacts"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "private_artifacts" {
  bucket                  = aws_s3_bucket.private_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "private_artifacts" {
  bucket = aws_s3_bucket.private_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "private_artifacts" {
  bucket = aws_s3_bucket.private_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# No ingress is allowed by default. Add explicit, narrow ingress blocks only
# after documenting why the service must be reachable and from which CIDRs.
resource "aws_security_group" "restricted_workload" {
  name        = "restricted-workload"
  description = "Example security group with no inbound access by default"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow outbound traffic; tighten for the workload's actual requirements"
  }

  tags = {
    Name        = "restricted-workload"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
