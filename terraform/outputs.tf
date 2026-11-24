output "cloudtrail_bucket_name" {
  description = "S3 bucket holding CloudTrail logs"
  value       = module.cloudtrail.bucket_name
}

output "cloudtrail_arn" {
  description = "ARN of the multi-region trail"
  value       = module.cloudtrail.trail_arn
}

output "guardduty_detector_id" {
  description = "Needed to generate sample findings for the alerting test"
  value       = module.guardduty.detector_id
}

output "alert_lambda_name" {
  description = "Lambda that formats GuardDuty findings"
  value       = module.alerting.lambda_name
}

output "sns_topic_arn" {
  description = "Topic every security alert is published to"
  value       = module.alerting.sns_topic_arn
}

output "vpc_id" {
  description = "Baseline VPC"
  value       = module.network.vpc_id
}
