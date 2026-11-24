# ==========================================================================
# BOOTSTRAP: resources that must exist BEFORE the main baseline.
#
# 1. Remote state bucket. Terraform state contains every resource ID, ARN,
#    and sometimes secrets in plain text. It can't live on one laptop, and
#    it can't be committed to Git. It goes in an encrypted, versioned,
#    private S3 bucket.
# 2. A cost budget, so a misconfiguration costs an email, not a bill.
#
# Chicken-and-egg: this folder can't store its own state in a bucket it
# hasn't created yet, so bootstrap state stays local (and gitignored).
# That's normal, and it's tiny: one bucket and one budget.
# ==========================================================================

terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
      Component = "bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

# --------------------------------------------------------------------------
# State bucket
# --------------------------------------------------------------------------

resource "aws_s3_bucket" "tf_state" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for a single-account portfolio baseline; versioning covers accidental deletion.
  #checkov:skip=CKV2_AWS_62:No consumer for object-created events on the state bucket.
  #checkov:skip=CKV_AWS_18:Access logging for a single-user state bucket adds cost with no reviewer; CloudTrail already records management API calls.
  bucket = "${var.project_name}-tfstate-${data.aws_caller_identity.current.account_id}"

  # Losing state means Terraform forgets what it owns. Never auto-delete.
  force_destroy = false
}

# Versioning = every state write is kept. If state gets corrupted or a bad
# apply overwrites it, you roll back to the previous version.
resource "aws_s3_bucket_versioning" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  rule {
    apply_server_side_encryption_by_default {
      # aws:kms with no key ID = AWS-managed key (aws/s3). Free, and every
      # decrypt is logged in CloudTrail. A customer-managed key would add
      # $1/month for little gain on a single-user bucket.
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket                  = aws_s3_bucket.tf_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Old state versions pile up on every apply. Keep 90 days of history.
resource "aws_s3_bucket_lifecycle_configuration" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id

  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Deny any request that isn't over TLS. Encryption at rest means little if
# state can be read in transit over plain HTTP. (CIS: deny non-TLS S3 access)
resource "aws_s3_bucket_policy" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.tf_state.arn,
          "${aws_s3_bucket.tf_state.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.tf_state]
}

# --------------------------------------------------------------------------
# Budget alert. Emails at 80% of actual spend and when AWS FORECASTS you'll
# pass 100%. The forecast alert is the useful one: it warns you mid-month.
# --------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_usd
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
