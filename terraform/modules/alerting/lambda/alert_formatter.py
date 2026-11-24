"""
GuardDuty finding -> human-readable alert.

EventBridge already filtered by severity before invoking this function, so
every event that reaches here is worth a human's attention. This function's
job is to turn ~150 lines of raw finding JSON into something a responder
can act on in 10 seconds: what happened, how bad, which resource, and a
direct link to the finding in the console.

It also measures detection-to-alert latency (time from GuardDuty updating
the finding to this alert going out) and logs it, so the pipeline's speed
is a number you can point to, not a guess.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client("sns")
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def severity_label(score: float) -> str:
    """GuardDuty's published severity bands."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def affected_resource(resource: dict) -> str:
    """Pull the most useful identifier out of the finding's resource block."""
    rtype = resource.get("resourceType", "Unknown")

    if rtype == "Instance":
        return f"EC2 instance {resource.get('instanceDetails', {}).get('instanceId', '?')}"
    if rtype == "AccessKey":
        details = resource.get("accessKeyDetails", {})
        return (
            f"Access key {details.get('accessKeyId', '?')} "
            f"(user: {details.get('userName', '?')})"
        )
    if rtype == "S3Bucket":
        buckets = resource.get("s3BucketDetails", [])
        names = ", ".join(b.get("name", "?") for b in buckets) or "?"
        return f"S3 bucket(s) {names}"
    return rtype


def latency_seconds(updated_at: str | None) -> float | None:
    """Seconds between GuardDuty's last update to the finding and now."""
    if not updated_at:
        return None
    try:
        updated = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    return round((datetime.now(timezone.utc) - updated).total_seconds(), 1)


def handler(event, context):
    detail = event.get("detail", {})

    score = float(detail.get("severity", 0))
    label = severity_label(score)
    finding_type = detail.get("type", "Unknown")
    title = detail.get("title", "GuardDuty finding")
    region = detail.get("region", event.get("region", "us-east-1"))
    finding_id = detail.get("id", "")
    account = detail.get("accountId", "")
    is_sample = detail.get("service", {}).get("additionalInfo", {}).get("sample", False)
    latency = latency_seconds(detail.get("updatedAt"))

    console_url = (
        f"https://{region}.console.aws.amazon.com/guardduty/home"
        f"?region={region}#/findings?macros=current&fId={finding_id}"
    )

    prefix = "[SAMPLE] " if is_sample else ""
    # SNS email subjects are capped at 100 characters.
    subject = f"{prefix}[{label}] GuardDuty: {finding_type}"[:100]

    body = "\n".join(
        [
            f"{prefix}{title}",
            "",
            f"Severity:  {label} ({score})",
            f"Type:      {finding_type}",
            f"Resource:  {affected_resource(detail.get('resource', {}))}",
            f"Account:   {account}",
            f"Region:    {region}",
            f"Seen:      {detail.get('service', {}).get('count', 1)} time(s), "
            f"last at {detail.get('updatedAt', '?')}",
            "",
            "What happened:",
            detail.get("description", "(no description)"),
            "",
            f"Open in console: {console_url}",
        ]
    )

    sns.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=body)

    # Structured log line: easy to query later with CloudWatch Logs Insights,
    # e.g. `stats avg(latency_seconds) by severity`.
    logger.info(
        json.dumps(
            {
                "event": "alert_sent",
                "finding_id": finding_id,
                "type": finding_type,
                "severity": label,
                "sample": is_sample,
                "latency_seconds": latency,
            }
        )
    )

    return {"status": "sent", "severity": label, "latency_seconds": latency}
