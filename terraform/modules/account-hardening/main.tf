# ==========================================================================
# Account-wide safe defaults. Each of these is one resource that closes a
# whole class of mistakes for every future resource in the account.
# ==========================================================================

# Password policy for any human console user. Length beats complexity
# rules, but CIS asks for both. Reuse prevention stops "Password1!" ->
# "Password2!" cycling.
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
  max_password_age               = 90
}

# IAM Access Analyzer continuously checks resource policies (S3, KMS, IAM
# roles, Lambda, SQS...) and reports anything shared OUTSIDE this account.
# Free for the external-access analyzer.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "${var.project_name}-analyzer"
  type          = "ACCOUNT"
}

# Every new EBS volume and snapshot in this region is encrypted, even if
# whoever launches the instance forgets. No per-volume setting to miss.
resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

# Account-level S3 Block Public Access. Overrides any single bucket's
# settings, so one bad bucket policy can't make data public. This is the
# guardrail behind most "S3 bucket leak" headlines.
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
