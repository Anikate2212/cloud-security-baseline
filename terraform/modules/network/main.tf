# ==========================================================================
# Network baseline: a private VPC with full flow logging, plus flow logs
# on the region's default VPC so no network in the region is unlogged.
#
# Flow logs record every connection attempt (src/dst IP, port, protocol,
# ACCEPT/REJECT). They don't capture packet contents. During an incident
# they answer "what did this instance talk to, and when?"
# ==========================================================================

data "aws_caller_identity" "current" {}

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Private subnet only. No internet gateway and no NAT gateway, so nothing
# here is reachable from the internet. (A NAT gateway would also add
# ~$32/month, which matters in a portfolio account.)
resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-a"
  }
}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only names[0] is used, once, at subnet creation; AZ names sort alphabetically so new zones append and never shift it.
  state = "available"
}

# Every VPC gets a "default" security group that, out of the box, allows
# all traffic between its members. Anything launched without an explicit
# SG lands in it. Managing it here with NO rules strips every rule, so
# forgetting to pick a security group fails closed instead of open.
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-default-sg-locked"
  }
}

# --------------------------------------------------------------------------
# Flow log delivery: CloudWatch Logs, encrypted with the baseline CMK.
# --------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.project_name}"
  retention_in_days = 365
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    # Confused-deputy protection: only flow logs from OUR account can use
    # this role.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "${var.project_name}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

# Scoped to the one log group. AWS's own docs example uses "*" here; that
# would let this role write into ANY log group in the account.
data "aws_iam_policy_document" "flow_logs" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.flow_logs.arn,
      "${aws_cloudwatch_log_group.flow_logs.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write-flow-log-group"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs.json
}

# ALL = accepted and rejected traffic. Rejected traffic is often the more
# interesting half: it's scanning and probing that the network blocked.
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn

  tags = {
    Name = "${var.project_name}-vpc-flow-log"
  }
}

# The default VPC exists in every region unless deleted, and it's where
# resources land when someone doesn't pick a VPC. CIS wants flow logs on
# every VPC, so it gets logged too.
data "aws_vpc" "default" {
  count   = var.enable_default_vpc_flow_logs ? 1 : 0
  default = true
}

resource "aws_flow_log" "default_vpc" {
  count           = var.enable_default_vpc_flow_logs ? 1 : 0
  vpc_id          = data.aws_vpc.default[0].id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn

  tags = {
    Name = "${var.project_name}-default-vpc-flow-log"
  }
}

# Same fail-closed treatment for the default VPC's default security group.
resource "aws_default_security_group" "default_vpc" {
  count  = var.enable_default_vpc_flow_logs ? 1 : 0
  vpc_id = data.aws_vpc.default[0].id

  tags = {
    Name = "default-vpc-default-sg-locked"
  }
}
