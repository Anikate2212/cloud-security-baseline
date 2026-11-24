variable "project_name" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "alert_min_severity" {
  description = "Lowest GuardDuty severity that triggers an alert (4 = Medium)"
  type        = number

  validation {
    condition     = var.alert_min_severity >= 1 && var.alert_min_severity <= 10
    error_message = "GuardDuty severity runs from 1 to 10."
  }
}
