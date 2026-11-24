variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "cloud-security-baseline"
}

variable "alert_email" {
  description = "Email subscribed to security alerts. Set in terraform.tfvars (gitignored)."
  type        = string
}

variable "provisioner_user_name" {
  description = "Existing IAM user that runs Terraform. Moved into a group so it no longer holds a directly attached policy (CIS 1.15)."
  type        = string
  default     = "anikate-cli"
}

variable "alert_min_severity" {
  description = "Lowest GuardDuty severity that pages a human. 4 = Medium, 7 = High."
  type        = number
  default     = 4
}

variable "enable_default_vpc_flow_logs" {
  description = "Also turn on flow logs for the region's default VPC (CIS requires flow logs on every VPC)."
  type        = bool
  default     = true
}
