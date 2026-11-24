variable "project_name" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "kms_key_arn" {
  description = "CMK used for the trail, its bucket, and its log group"
  type        = string
}
