# ==========================================================================
# CloudTrail: the account's audit log. Every API call (who, what, when,
# from where) is recorded. Two destinations, two jobs:
#   S3              → long-term, tamper-evident archive for investigations
#   CloudWatch Logs → near real-time stream that the monitoring module
#                     turns into alarms (root login, IAM changes, etc.)
# ==========================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${var.project_name}-trail"
  # Built as a string (not aws_cloudtrail.main.arn) because the bucket
  # policy must exist BEFORE the trail. Referencing the trail would create
  # a dependency cycle.
  trail_arn = "arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
}

# --------------------------------------------------------------------------
# Log archive bucket
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for a single-account baseline; versioning plus log file validation protect integrity.
  #checkov:skip=CKV2_AWS_62:No downstream consumer for object-created events; real-time analysis uses the CloudWatch Logs stream instead.
  bucket = "${var.project_name}-cloudtrail-logs-${local.account_id}"

  # false on purpose: `terraform destroy` must never silently wipe audit
  # logs. Emptying the bucket is a deliberate, manual step.
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning: if an attacker (or a mistake) overwrites or deletes a log
# file, the previous version is still there.
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Upgraded from SSE-S3 (AES256) to SSE-KMS with our own key. Objects
# written before this change stay readable; new ones use the CMK.
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true # cuts KMS request costs by ~99%
  }
}

# Retention: 90 days hot, then cheaper storage, deleted after 1 year.
# Real orgs often keep 1 to 7 years for compliance; one year is a
# reasonable floor for a portfolio account and keeps cost near zero.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "archive-then-expire"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail_logs]
}

# Who accessed the audit logs? S3 server access logging answers that.
# (CIS: access logging on the CloudTrail bucket)
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "cloudtrail-bucket/"
}

# --------------------------------------------------------------------------
# Bucket policy. Only CloudTrail can write, only for OUR trail, only into
# OUR account's prefix, and only over TLS.
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
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

# --------------------------------------------------------------------------
# Access-log bucket (receives S3 server access logs for the bucket above)
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This IS the access-log bucket; logging it into itself would loop.
  #checkov:skip=CKV_AWS_145:S3 server access log delivery does not support SSE-KMS targets, so SSE-S3 is the only option here.
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope for a single-account baseline.
  #checkov:skip=CKV2_AWS_62:No consumer for object-created events on access logs.
  bucket        = "${var.project_name}-access-logs-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"
    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogsDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.cloudtrail_logs.arn }
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

# --------------------------------------------------------------------------
# CloudWatch Logs stream of the trail (feeds the CIS alarms)
# --------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_cwl" {
  name               = "${var.project_name}-cloudtrail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

# Least privilege: write log events to ONE log group. Nothing else.
data "aws_iam_policy_document" "cloudtrail_to_cwl" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cwl" {
  name   = "write-trail-log-group"
  role   = aws_iam_role.cloudtrail_to_cwl.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cwl.json
}

# --------------------------------------------------------------------------
# The trail
# --------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_252:Per-file delivery notifications aren't needed; alerting is driven by CloudWatch metric filters.
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id

  # All regions: an attacker who spins up resources in a region you never
  # use would otherwise be invisible.
  is_multi_region_trail         = true
  include_global_service_events = true # IAM, STS, CloudFront live in "global"

  # SHA-256 digest files let you PROVE a log wasn't edited after delivery.
  #
  enable_log_file_validation = true

  kms_key_id = var.kms_key_arn # CIS: trail logs encrypted with KMS

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cwl.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_to_cwl,
  ]
}
