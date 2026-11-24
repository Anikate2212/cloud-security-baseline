# Results

All numbers come from real runs in my AWS account on 2026-11-24. Raw scanner output is kept out of the repo because it includes the account ID and a full list of weaknesses.

## CIS AWS Foundations Benchmark v7.0 (Prowler 5.52, us-east-1)

| Scan | Passed | Failed | Pass rate |
|---|---|---|---|
| Before (CloudTrail + logging bucket only) | 21 | 38 | **35.6%** |
| After (full baseline) | 68 | 16 | **81.0%** |

Failures by CIS section:

| Section | Before | After |
|---|---|---|
| Identity and Access Management | 9 | 4 |
| Storage | 7 | 7 |
| Logging | 6 | 3 |
| Monitoring | 16 | 2 |

Prowler counts one result per resource, so the total grew from 59 to 84 as the baseline added resources. The pass rate is the fair comparison; failures still dropped from 38 to 16.

### Remaining failures and why

| Check | Count | Why it still fails |
|---|---|---|
| `s3_bucket_no_mfa_delete` | 5 | MFA Delete can only be enabled by the root user through the CLI, not Terraform. Versioning, TLS-only policies, and CloudTrail log file validation cover integrity. Accepted. |
| `iam_aws_attached_policy_no_administrative_privileges` | 1 | The documented Terraform-user exception (admin via the `terraform-provisioners` group, no MFA enforcement possible on access keys). Planned fix: OIDC / assumed-role credentials. |
| `iam_root_hardware_mfa_enabled` | 1 | Root has virtual MFA; this check requires a physical security key. |
| `securityhub_enabled`, `macie_is_enabled` | 2 | Paid services, deliberately out of scope. Prowler covers the benchmark for free here. |
| `cloudtrail_s3_dataevents_read_enabled` / `_write_enabled` | 2 | S3 object-level data events are billed per event. GuardDuty S3 Protection already watches S3 data access for threats. |
| `cloudwatch_log_metric_filter_aws_organizations_changes` | 1 | The filter exists and alarms, but its pattern doesn't match the exact form Prowler's v7.0 check expects. No AWS Organization exists in this account, so it has no events to catch either way. |
| `iam_user_accesskey_unused` | 1 | Resolved after the scan: the Terraform user's 89-day-old key was rotated (create new, deactivate old, verify, delete). |
| `iam_check_saml_providers_sts` | 1 | No identity-provider federation in a single-user account. |
| `apigateway_restapi_logging_enabled`, `s3_bucket_secure_transport_policy` (+1 MFA Delete) | 2 | Resources from a separate, older project in the same account, outside this baseline's scope. Its bucket is now protected by the account-level S3 Block Public Access this baseline enabled. |

## Alerting pipeline

| Test | Result |
|---|---|
| Direct Lambda invoke (synthetic event) | Formatted email delivered in under 1 minute |
| GuardDuty sample finding, end to end (GuardDuty → EventBridge → Lambda → SNS) | Email delivered in **under 1 minute**; Lambda-measured detection-to-alert latency **5.0 seconds** |
| First sample finding on a brand-new detector | Never published to EventBridge. A detector created ~3 minutes earlier wasn't publishing yet; traced layer by layer (finding existed, rule matched nothing, no Lambda errors, empty DLQ) and confirmed with a second sample a few minutes later |
| Severity filter on real data | GuardDuty raised a real `Policy:IAMUser/RootCredentialUsage` finding (severity 2.0, Low) from my own root sign-in; correctly **not** emailed |

## CIS real-time alarms

8 of the 15 alarms fired on real activity during deployment and validation, each within roughly 5 to 10 minutes:

| Alarm | Real trigger |
|---|---|
| `cis-cloudtrail-config-changes` | Terraform updating the trail |
| `cis-vpc-changes` | Terraform creating the VPC |
| `cis-s3-bucket-policy-changes` | Terraform writing bucket policies |
| `cis-iam-policy-changes` | Terraform IAM policies, and manually detaching the Terraform user's direct policy |
| `cis-security-group-changes` | Terraform stripping rules from default security groups |
| `cis-aws-config-changes` | Terraform creating the Config recorder |
| `cis-unauthorized-api-calls` | AccessDenied events during deployment and scanning |
| `cis-root-account-usage` + `cis-console-auth-failures` | My own root console sign-in, including failed attempts |

The unauthorized-API-calls alarm is the noisiest; in production it would be tuned or routed to a lower-priority channel.

## Static analysis (Checkov)

294 passed, 0 failed, 23 skipped. Every skip has an inline `#checkov:skip` with a written justification.
