# Cloud Security Baseline (AWS + Terraform)

![terraform-security](https://github.com/Anikate2212/cloud-security-baseline/actions/workflows/terraform-security.yml/badge.svg)

A Terraform baseline that takes a fresh AWS account to a hardened, monitored state aligned with the **CIS AWS Foundations Benchmark**: audit logging, threat detection, real-time alerting, continuous compliance checks, least-privilege IAM, and network visibility. Every control is code, every exception is documented, and the result is measured with an independent scanner.

**Status:** Complete. Results in [docs/results.md](docs/results.md).

## Results

| Metric | Value |
|---|---|
| CIS AWS Foundations v7.0 pass rate (Prowler, us-east-1) | **35.6% → 81.0%** (failures 38 → 16) |
| GuardDuty finding to alert | **5 seconds** measured in Lambda, email in **under 1 minute** |
| CIS real-time alarms | **15**; 8 fired on real activity during deployment, including my own root sign-in |
| Static security scan (Checkov) | **0 failed**, 23 suppressions, each justified inline |

## Architecture

```
API call ─► CloudTrail ─► S3 archive (KMS, versioned, access-logged)
                     └──► CloudWatch Logs ─► 15 CIS metric filters ─► alarms ─┐
GuardDuty ─► EventBridge (severity ≥ 4) ─► Lambda (format, measure) ──────────┼─► SNS (KMS) ─► email
                                              └─ failures ─► SQS DLQ          │
AWS Config (15 rules) · IAM guardrails · VPC flow logs · account defaults ────┘
```

Full diagram and module map: [docs/architecture.md](docs/architecture.md)

## What's deployed

| Area | Controls | CIS area |
|---|---|---|
| Audit logging | Multi-region CloudTrail with log file validation, KMS encryption, CloudWatch Logs integration; archive bucket versioned, access-logged, TLS-only | Logging |
| Real-time monitoring | 15 metric filters and alarms on the CloudTrail stream | Monitoring |
| Threat detection | GuardDuty with S3 Protection; EventBridge → Lambda → SNS alerting with a dead-letter queue | Monitoring |
| Continuous compliance | AWS Config recorder with 15 managed rules re-checking this baseline for drift | Logging |
| Identity | Permissions only through groups; force-MFA policy for humans; strict password policy; IAM Access Analyzer; MFA-gated support role | IAM |
| Storage | Account-level S3 Block Public Access; TLS-only bucket policies; EBS encryption by default | Storage |
| Network | Private VPC; default security groups stripped of all rules; flow logs on every VPC in the region | Networking, Logging |
| Encryption | One customer-managed KMS key with rotation, scoped key policy with confused-deputy conditions | Logging |
| Pipeline | GitHub Actions: `terraform fmt`, `validate`, Checkov with SARIF upload to the Security tab | n/a |

## Key decisions

Short version (full reasoning in [docs/design-decisions.md](docs/design-decisions.md)):

- **Severity filtering in EventBridge, not Lambda.** Low findings never invoke anything, so there's no cost and no alert fatigue.
- **Customer-managed KMS key.** Required for CloudWatch alarms to publish to an encrypted topic, and it makes reading audit logs need a second, separate permission.
- **Remote state with S3 native locking.** Versioned, encrypted, TLS-only; no DynamoDB table needed on Terraform 1.10+.
- **Refactored into modules with `moved` blocks**, so the existing trail was relocated in state rather than destroyed and recreated.
- **One documented exception:** the Terraform user keeps admin without MFA enforcement because access keys can't carry MFA. Next step is OIDC or assumed-role credentials.

## Repository layout

```
terraform/
├── bootstrap/            # state bucket + budget (local state, run once)
├── main.tf               # wires the modules together
├── moved.tf              # state moves from the original flat layout
└── modules/
    ├── kms/  cloudtrail/  monitoring/  guardduty/  alerting/
    ├── network/  config/  iam/  account-hardening/
tests/                    # sample GuardDuty event for the Lambda
docs/                     # architecture, decisions, deployment, results
.github/workflows/        # CI security gates
```

## Deploy it

Step-by-step, including the alerting tests and teardown: [docs/deployment.md](docs/deployment.md)

```bash
cd terraform/bootstrap && terraform init && terraform apply
cd ..
terraform init \
  -backend-config="bucket=$(terraform -chdir=bootstrap output -raw state_bucket)"
terraform plan -out=tfplan && terraform apply tfplan
```

## What I'd add next

- AWS Organizations with a Service Control Policy denying `cloudtrail:StopLogging` and `guardduty:DeleteDetector`, a guardrail no IAM admin can bypass
- Replace the Terraform user's access keys with GitHub Actions OIDC and run `plan` in CI
- Automated containment: a Lambda that disables a compromised access key on a high-severity credential finding (this feeds my Incident Response Simulation project)
