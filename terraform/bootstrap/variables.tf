variable "aws_region" {
  description = "Region for the state bucket and budget"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for resource names"
  type        = string
  default     = "cloud-security-baseline"
}

variable "alert_email" {
  description = "Email that receives budget alerts. Set in terraform.tfvars (gitignored)."
  type        = string
}

variable "monthly_budget_usd" {
  description = "Monthly cost ceiling for the account, in USD"
  type        = string
  default     = "10"
}
