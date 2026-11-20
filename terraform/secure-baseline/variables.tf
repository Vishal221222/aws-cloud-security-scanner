variable "aws_region" {
  description = "AWS region for the example resources."
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Globally unique S3 bucket name for the private artifacts example."
  type        = string
}

variable "vpc_id" {
  description = "Existing VPC ID in the selected region."
  type        = string
}

variable "environment" {
  description = "Environment tag."
  type        = string
  default     = "lab"
}
