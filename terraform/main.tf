# ==========================================================================
# Cloud Security Baseline: root module
#
# Each control lives in its own module under ./modules so it can be read,
# reviewed, and reused on its own. This file only wires them together.
#
# Data flow:
#   kms ──────────────► encrypts CloudTrail, CloudWatch Logs, SNS, Lambda env
#   cloudtrail ───────► S3 (archive) + CloudWatch Logs (real-time)
#   monitoring ───────► CIS metric filters on the CloudTrail log group → alarms → SNS
#   guardduty ────────► findings → EventBridge → Lambda (alerting) → SNS → email
#   network ──────────► VPC + flow logs; default security group locked down
#   config ───────────► continuous compliance checks against managed rules
#   iam / account-hardening ► who can do what, and account-wide safe defaults
# ==========================================================================

module "kms" {
  source       = "./modules/kms"
  project_name = var.project_name
  aws_region   = var.aws_region
}

module "cloudtrail" {
  source       = "./modules/cloudtrail"
  project_name = var.project_name
  aws_region   = var.aws_region
  kms_key_arn  = module.kms.key_arn
}

module "account_hardening" {
  source       = "./modules/account-hardening"
  project_name = var.project_name
}

module "iam" {
  source                = "./modules/iam"
  project_name          = var.project_name
  provisioner_user_name = var.provisioner_user_name
}

module "guardduty" {
  source = "./modules/guardduty"
}

module "network" {
  source                       = "./modules/network"
  project_name                 = var.project_name
  kms_key_arn                  = module.kms.key_arn
  enable_default_vpc_flow_logs = var.enable_default_vpc_flow_logs
}

module "config" {
  source       = "./modules/config"
  project_name = var.project_name
}

module "alerting" {
  source             = "./modules/alerting"
  project_name       = var.project_name
  kms_key_arn        = module.kms.key_arn
  alert_email        = var.alert_email
  alert_min_severity = var.alert_min_severity
}

module "monitoring" {
  source         = "./modules/monitoring"
  project_name   = var.project_name
  log_group_name = module.cloudtrail.log_group_name
  sns_topic_arn  = module.alerting.sns_topic_arn
}
