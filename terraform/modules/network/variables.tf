variable "project_name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "enable_default_vpc_flow_logs" {
  description = "Set false if the region's default VPC has been deleted"
  type        = bool
}
