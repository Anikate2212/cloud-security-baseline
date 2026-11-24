# Design decisions

Each entry: what I chose, what I rejected, and why.

## State and structure

**Remote state in S3 with native locking, no DynamoDB table.**
Terraform 1.10+ can lock state with a lock file in the same bucket (`use_lockfile = true`), so the extra DynamoDB table is no longer needed. The bucket is versioned (roll back a corrupted state), encrypted, private, and denies non-TLS requests. The bootstrap stack that creates it keeps its own state locally, which is the standard answer to the chicken-and-egg problem.

**Bucket name passed at `init` time, not hardcoded.**
It contains the account ID. Account IDs aren't secrets, but there's no reason to publish one in a public repo either.

**One module per control, wired together in a root module.**
Each control can be reviewed on its own, and the CloudTrail resources were moved into a module with `moved` blocks so Terraform relocated them in state instead of destroying and recreating the trail (which would have broken the audit history).

## Encryption

**One customer-managed KMS key instead of AWS-managed keys.**
Two concrete reasons: CloudWatch alarms can't publish to an SNS topic encrypted with the AWS-managed key, and a key policy I control means reading audit logs needs `kms:Decrypt` in addition to `s3:GetObject`. Cost is $1/month. Service statements in the key policy are pinned with `aws:SourceArn` / `aws:SourceAccount` / encryption-context conditions to prevent confused-deputy use.

**Exception: the access-log bucket uses SSE-S3.**
S3 server access log delivery does not support SSE-KMS targets. Documented as a Checkov skip.

## Detection and alerting

**Severity filtering in EventBridge, formatting in Lambda.**
Findings below Medium never invoke anything, so they cost nothing and can't cause alert fatigue; they're still in the GuardDuty console. The Lambda only does what EventBridge can't: turn raw JSON into a readable message with a console link, and log detection-to-alert latency as structured JSON.

**Dead-letter queue on the Lambda.**
If formatting or publishing fails after Lambda's built-in retries, the event lands in SQS instead of disappearing. A silent failure in an alerting pipeline is worse than a loud one.

**CIS metric filters use the benchmark's own patterns.**
So scanners and auditors recognize them. Trade-off: the unauthorized-API-calls alarm is noisy (a security scan itself triggers AccessDenied). In production I'd tune it with exclusions or route it to a lower-priority channel instead of email.

**Missing data treated as not breaching.**
No matching events means the metric has no data points, which is the healthy state.

## Identity

**Permissions only through groups.**
`console-admins` (admin + force-MFA), `security-auditors` (SecurityAudit + ViewOnly + force-MFA), `terraform-provisioners` (admin). No user has a directly attached policy.

**Documented exception: the Terraform user has admin without MFA enforcement.**
It authenticates with long-term access keys, which can't carry an MFA flag, so the force-MFA policy would lock it out. Mitigations: keys only (no console password), permissions via a group, keys stored in a password manager and rotated, and every call is logged and alarmed. The proper fix is to remove long-lived keys entirely: GitHub Actions OIDC or an assumed role with session credentials.

**Support role assumable only with MFA.**
So opening an AWS Support case during an incident never requires the root user.

## Network

**Private subnet only, no NAT gateway.**
Nothing here needs outbound internet, and a NAT gateway costs ~$32/month.

**Default security groups managed with zero rules.**
Anything launched without an explicit security group fails closed instead of open. Applied to both the baseline VPC and the default VPC.

**Flow logs on the default VPC too.**
It's where resources land when nobody picks a VPC, so it's the one most likely to hold something unexpected.

**Account-level S3 Block Public Access even though an older project bucket served a public site.**
A single exception would have weakened the whole baseline. The bucket and its data are untouched; only public reads stopped. The right way to bring that site back is CloudFront with Origin Access Control, which keeps the bucket private.

## Accepted gaps (out of scope, deliberately)

| Gap | Why not here |
|---|---|
| Security Hub | Per-check pricing; Prowler covers the same benchmark for free in this project. |
| MFA Delete on the CloudTrail bucket | Can only be enabled by the root user via CLI, not Terraform. Versioning + log file validation cover integrity. |
| Cross-region replication of logs | Single-account portfolio; doubles storage for no reviewer. |
| AWS Organizations + SCPs | Would add a guardrail no IAM admin can bypass (e.g. deny `cloudtrail:StopLogging`). Next project. |
| Lambda in a VPC | Needs NAT or VPC endpoints to reach SNS; no inbound traffic to protect. |
