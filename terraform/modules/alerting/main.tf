# ==========================================================================
# Detection -> response pipeline
#
#   GuardDuty finding
#     -> EventBridge rule (drops anything below the severity threshold)
#     -> Lambda (formats the finding into a readable alert, measures latency)
#     -> SNS topic (encrypted) -> email
#   Lambda failures -> SQS dead-letter queue (no alert is silently lost)
#
# Design choice: severity filtering happens in EventBridge, not in the
# Lambda. Low findings never invoke anything, so they cost nothing and
# can't create alert fatigue. They stay visible in the GuardDuty console.
# ==========================================================================

data "aws_caller_identity" "current" {}

locals {
  account_id    = data.aws_caller_identity.current.account_id
  function_name = "${var.project_name}-guardduty-alert"
}

# --------------------------------------------------------------------------
# SNS topic. Also used by the CIS alarms in the monitoring module.
# --------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-security-alerts"
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "topic" {
  # Principals in this account (governed by their own IAM policies).
  statement {
    sid = "AccountOwnerAccess"
    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish",
    ]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudWatch alarms from this account only.
  statement {
    sid       = "AllowCloudWatchAlarms"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.alerts.arn]
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

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.topic.json
}

# AWS emails a confirmation link. Nothing is delivered until it's clicked.
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --------------------------------------------------------------------------
# Dead-letter queue for failed Lambda invocations
# --------------------------------------------------------------------------

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.function_name}-dlq"
  message_retention_seconds = 1209600 # 14 days, the SQS maximum
  sqs_managed_sse_enabled   = true
}

# --------------------------------------------------------------------------
# Lambda function
# --------------------------------------------------------------------------

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/alert_formatter.py"
  output_path = "${path.module}/build/alert_formatter.zip"
}

# Created explicitly (not left to Lambda) so it gets retention and
# encryption. Lambda's auto-created log groups keep logs forever, unencrypted
# with our key.
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# Every statement is scoped to the one resource this function touches.
data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  # The topic is KMS-encrypted, so publishing needs the key too. This is
  # also what decrypts the function's environment variables.
  statement {
    sid       = "UseBaselineKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }

  statement {
    sid       = "SendToDeadLetterQueue"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # X-Ray write APIs don't support resource-level scoping
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "guardduty-alert-least-privilege"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "alert" {
  #checkov:skip=CKV_AWS_117:Placing the function in a VPC would need a NAT gateway or VPC endpoints to reach SNS (~$7-32/month) for no security gain; it handles no inbound traffic.
  #checkov:skip=CKV_AWS_115:Reserved concurrency fails on new accounts with the default 10-execution limit; EventBridge volume here is tiny.
  #checkov:skip=CKV_AWS_272:Code signing requires an AWS Signer profile; out of scope for a single-function portfolio pipeline. Code integrity is enforced by Git + CI.
  function_name    = local.function_name
  description      = "Formats GuardDuty findings into readable alerts and publishes to SNS"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.13"
  handler          = "alert_formatter.handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 15
  memory_size      = 128
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  tracing_config {
    mode = "Active"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
  ]
}

# --------------------------------------------------------------------------
# EventBridge rule: GuardDuty findings at or above the threshold
# --------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.project_name}-guardduty-findings"
  description = "GuardDuty findings with severity >= ${var.alert_min_severity}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.alert_min_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "format-and-notify"
  arn       = aws_lambda_function.alert.arn
}

# Resource-based permission: only THIS rule may invoke the function.
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowGuardDutyRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
