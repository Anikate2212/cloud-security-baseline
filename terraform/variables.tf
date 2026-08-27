variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming/tagging"
  type        = string
  default     = "cloud-security-baseline"
}
