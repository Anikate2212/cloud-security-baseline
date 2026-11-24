# ==========================================================================
# One customer-managed KMS key for the baseline's sensitive data:
# CloudTrail logs, CloudWatch log groups, the SNS alert topic, and the
# Lambda's environment variables.
#
# Why customer-managed instead of the free AWS-managed keys?
#   1. CloudWatch alarms can't publish to an SNS topic encrypted with the
#      AWS-managed key. A key policy we control is the only way to grant it.
#   2. We decide who can decrypt audit logs. Reading CloudTrail now needs
#      BOTH s3:GetObject AND kms:Decrypt, a second, separate permission.
#   3. Disabling or deleting this key is itself alarmed (monitoring module).
# Cost: $1/month plus negligible API calls.
# ==========================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_arn  = "arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${var.project_name}-trail"
}

resource "aws_kms_key" "baseline" {
  description             = "${var.project_name}: encrypts audit logs, alerts, and log groups"
  enable_key_rotation     = true # new key material yearly (CIS: KMS rotation)
  deletion_window_in_days = 7    # minimum; a deleted key makes its data unreadable forever
  policy                  = data.aws_iam_policy_document.key_policy.json
}

resource "aws_kms_alias" "baseline" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.baseline.key_id
}

data "aws_iam_policy_document" "key_policy" {
  #checkov:skip=CKV_AWS_111:False positive. In a KMS key policy, Resource "*" means this key only; service statements are pinned with SourceArn/SourceAccount/EncryptionContext conditions.
  #checkov:skip=CKV_AWS_356:Same as above: "*" in a key policy refers to the key itself.
  #checkov:skip=CKV_AWS_109:Same as above: kms:* is granted only to this account root, which delegates to IAM (the AWS default and required to avoid key lockout).
  # Without this statement, IAM policies can't grant access to the key at
  # all, and you can lock yourself out of your own key. It delegates control
  # to IAM in THIS account only. It does not make the key public.
  statement {
    sid       = "EnableIAMPolicies"
    actions   = ["kms:*"]
    resources = ["*"] # in a key policy, "*" means "this key"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudTrail may encrypt with this key, but only for OUR trail.
  # The SourceArn condition blocks the "confused deputy" problem: another
  # account's trail can't trick CloudTrail into using our key.
  statement {
    sid       = "AllowCloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribeKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
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

  # CloudWatch Logs encrypts log groups in this account and region only.
  statement {
    sid = "AllowCloudWatchLogs"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:*"]
    }
  }

  # CloudWatch alarms publish to the encrypted SNS topic.
  statement {
    sid       = "AllowCloudWatchAlarmsToPublish"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}
