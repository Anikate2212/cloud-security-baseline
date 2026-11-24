# The original CloudTrail resources were written at the root of this folder.
# They now live in modules/cloudtrail. Without these blocks Terraform would
# DESTROY the existing trail and bucket and create new ones, losing the
# audit history. "moved" tells Terraform it's the same object at a new
# address, so the plan shows a move, not a replacement.
moved {
  from = aws_s3_bucket.cloudtrail_logs
  to   = module.cloudtrail.aws_s3_bucket.cloudtrail_logs
}
moved {
  from = aws_s3_bucket_public_access_block.cloudtrail_logs
  to   = module.cloudtrail.aws_s3_bucket_public_access_block.cloudtrail_logs
}
moved {
  from = aws_s3_bucket_server_side_encryption_configuration.cloudtrail_logs
  to   = module.cloudtrail.aws_s3_bucket_server_side_encryption_configuration.cloudtrail_logs
}
moved {
  from = aws_s3_bucket_policy.cloudtrail_logs
  to   = module.cloudtrail.aws_s3_bucket_policy.cloudtrail_logs
}
moved {
  from = aws_cloudtrail.main
  to   = module.cloudtrail.aws_cloudtrail.main
}
