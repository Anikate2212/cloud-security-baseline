# ==========================================================================
# AWS Config: records the configuration of every resource over time and
# continuously evaluates it against rules. Where CloudTrail answers "who
# changed it?", Config answers "what did it look like before, and is it
# compliant right now?"
#
# The managed rules below re-check this baseline's own controls, so drift
# (someone disables flow logs in the console) shows up as NON_COMPLIANT.
# ==========================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  rules = {
    "cloudtrail-enabled"             = { id = "CLOUD_TRAIL_ENABLED", params = null }
    "cloudtrail-multi-region"        = { id = "MULTI_REGION_CLOUD_TRAIL_ENABLED", params = null }
    "cloudtrail-log-validation"      = { id = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED", params = null }
    "cloudtrail-encryption"          = { id = "CLOUD_TRAIL_ENCRYPTION_ENABLED", params = null }
    "root-account-mfa"               = { id = "ROOT_ACCOUNT_MFA_ENABLED", params = null }
    "root-no-access-keys"            = { id = "IAM_ROOT_ACCESS_KEY_CHECK", params = null }
    "iam-users-no-direct-policies"   = { id = "IAM_USER_NO_POLICIES_CHECK", params = null }
    "access-keys-rotated"            = { id = "ACCESS_KEYS_ROTATED", params = jsonencode({ maxAccessKeyAge = "90" }) }
    "iam-password-policy"            = { id = "IAM_PASSWORD_POLICY", params = jsonencode({ MinimumPasswordLength = "14", PasswordReusePrevention = "24", MaxPasswordAge = "90" }) }
    "s3-account-public-access-block" = { id = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC", params = null }
    "vpc-flow-logs-enabled"          = { id = "VPC_FLOW_LOGS_ENABLED", params = null }
    "vpc-default-sg-closed"          = { id = "VPC_DEFAULT_SECURITY_GROUP_CLOSED", params = null }
    "ebs-encryption-by-default"      = { id = "EC2_EBS_ENCRYPTION_BY_DEFAULT", params = null }
    "kms-key-rotation"               = { id = "CMK_BACKING_KEY_ROTATION_ENABLED", params = null }
    "guardduty-enabled"              = { id = "GUARDDUTY_ENABLED_CENTRALIZED", params = null }
  }
}

# --------------------------------------------------------------------------
# Delivery bucket (configuration snapshots and history)
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "config" {
  #checkov:skip=CKV_AWS_18:Access logging for Config snapshots adds cost; CloudTrail records API access to this bucket.
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope for a single-account baseline.
  #checkov:skip=CKV2_AWS_62:No consumer for object-created events on Config snapshots.
  bucket        = "${var.project_name}-config-${local.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms" # AWS-managed aws/s3 key
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "expire-config-history"
    status = "Enabled"
    filter {}

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

  depends_on = [aws_s3_bucket_versioning.config]
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.config]
}

# --------------------------------------------------------------------------
# Recorder role: AWS's managed read-only Config policy, plus write access
# to exactly one bucket prefix.
# --------------------------------------------------------------------------

data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.project_name}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "deliver-to-config-bucket"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

# --------------------------------------------------------------------------
# Recorder, delivery channel, and on-switch (order matters, hence depends_on)
# --------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # IAM users, roles, policies
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.project_name}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config,
    aws_iam_role_policy.config_delivery,
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "managed" {
  for_each = local.rules

  name = each.key

  source {
    owner             = "AWS"
    source_identifier = each.value.id
  }

  input_parameters = each.value.params

  depends_on = [aws_config_configuration_recorder_status.main]
}
