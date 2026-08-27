# --------------------------------------------------------------------------
# S3 bucket to store CloudTrail logs
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  # force_destroy = false on purpose: we don't want `terraform destroy`
  # accidentally wiping audit logs. You'd have to empty it manually first.
  force_destroy = false

  tags = {
    Project = var.project_name
    Purpose = "cloudtrail-logging"
  }
}

# Pulls your AWS account ID automatically so the bucket name is
# globally unique without you having to hardcode anything sensitive.
data "aws_caller_identity" "current" {}

# --------------------------------------------------------------------------
# Block ALL public access to this bucket. Logs should never be public.
# --------------------------------------------------------------------------

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# --------------------------------------------------------------------------
# Encrypt everything in the bucket at rest, using AES256 (SSE-S3).
# --------------------------------------------------------------------------

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --------------------------------------------------------------------------
# Bucket policy: this is the important security piece.
# CloudTrail's service principal needs explicit permission to:
#   1. Check the bucket's ACL (GetBucketAcl)
#   2. Write log files into it (PutObject), but ONLY under a path
#      that includes ITS OWN account ID, which prevents one CloudTrail
#      from writing into another account's log path even by mistake.
# No other principal gets any access — this is why we also did the
# public access block above, as defense in depth.
# --------------------------------------------------------------------------

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# --------------------------------------------------------------------------
# The CloudTrail itself.
# is_multi_region_trail = true means it captures API activity across
# ALL AWS regions, not just us-east-1 — important because an attacker
# (or a mistake) in an unused region would otherwise go unlogged.
# enable_log_file_validation = true lets you cryptographically verify
# logs haven't been tampered with after the fact — a real auditor/
# incident responder would check this.
# --------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Project = var.project_name
  }
}
