variable "project_name" {
  type = string
}

variable "log_group_name" {
  description = "CloudWatch log group receiving the CloudTrail stream"
  type        = string
}

variable "sns_topic_arn" {
  description = "Topic the alarms notify"
  type        = string
}
