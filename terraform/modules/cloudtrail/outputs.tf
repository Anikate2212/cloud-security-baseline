output "bucket_name" {
  value = aws_s3_bucket.cloudtrail_logs.id
}

output "trail_arn" {
  value = aws_cloudtrail.main.arn
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}
