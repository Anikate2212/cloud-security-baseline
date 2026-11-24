# ==========================================================================
# CIS "Monitoring" controls: real-time alarms on high-risk API activity.
#
# How it works: CloudTrail streams every API call into a CloudWatch log
# group. Each metric filter below matches one kind of risky event and
# increments a counter. Each alarm fires when its counter is >= 1 in a
# 5-minute window and emails the SNS topic.
#
# The filter patterns follow the CIS AWS Foundations Benchmark so that
# Prowler (and auditors) recognize them.
#
# Cost: the first 10 alarms are free, then $0.10/alarm/month (~$0.50 here).
# ==========================================================================

locals {
  cis_alarms = {
    "unauthorized-api-calls" = {
      description = "API calls denied for lack of permission (recon or misconfigured automation)"
      pattern     = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    }
    "console-login-without-mfa" = {
      description = "Console sign-in without MFA"
      pattern     = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
    }
    "root-account-usage" = {
      description = "Any use of the root user"
      pattern     = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    }
    "iam-policy-changes" = {
      description = "IAM policy created, changed, attached, or detached"
      pattern     = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
    }
    "cloudtrail-config-changes" = {
      description = "Trail created, updated, deleted, or logging stopped"
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    }
    "console-auth-failures" = {
      description = "Failed console sign-ins (brute force indicator)"
      pattern     = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    }
    "kms-key-disable-or-deletion" = {
      description = "Customer-managed KMS key disabled or scheduled for deletion"
      pattern     = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    }
    "s3-bucket-policy-changes" = {
      description = "S3 bucket ACL, policy, CORS, lifecycle, or replication changed"
      pattern     = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    }
    "aws-config-changes" = {
      description = "AWS Config recorder or delivery channel changed or stopped"
      pattern     = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    }
    "security-group-changes" = {
      description = "Security group created, deleted, or rules changed"
      pattern     = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    }
    "nacl-changes" = {
      description = "Network ACL created, deleted, or changed"
      pattern     = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    }
    "network-gateway-changes" = {
      description = "Internet or customer gateway created, attached, or deleted"
      pattern     = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    }
    "route-table-changes" = {
      description = "Route or route table created, replaced, or deleted"
      pattern     = "{ ($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }"
    }
    "vpc-changes" = {
      description = "VPC created, deleted, modified, or peered"
      pattern     = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    }
    "organizations-changes" = {
      description = "AWS Organizations structure or policies changed"
      pattern     = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.cis_alarms

  name           = "cis-${each.key}"
  log_group_name = var.log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_alarms

  alarm_name          = "cis-${each.key}"
  alarm_description   = each.value.description
  namespace           = "CISBenchmark"
  metric_name         = aws_cloudwatch_log_metric_filter.cis[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"

  # No matching events = no data points. That's the normal, healthy state,
  # so missing data must NOT count as an alarm.
  treat_missing_data = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
}
