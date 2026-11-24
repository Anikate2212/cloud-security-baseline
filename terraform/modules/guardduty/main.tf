# ==========================================================================
# GuardDuty: managed threat detection. It reads CloudTrail events, VPC
# flow logs, and DNS logs behind the scenes (no setup needed) and flags
# things like crypto-mining, credential exfiltration, calls from known-bad
# IPs, and reconnaissance. Findings flow to EventBridge -> alerting module.
#
# Cost: 30-day free trial, then usage-based. A near-idle account is
# typically a few dollars a month or less. The budget alert covers this.
# ==========================================================================

resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:Standalone account with no AWS Organization, so there is no delegated admin to enroll in.
  enable = true

  # How often UPDATES to existing findings are re-published. New findings
  # are always published within about 5 minutes regardless.
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# S3 Protection: watches S3 data events (GetObject, PutObject...) for
# suspicious access patterns, e.g. a bulk download from an unusual IP.
resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
