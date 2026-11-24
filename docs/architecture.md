# Architecture

```mermaid
flowchart LR
    subgraph Account["AWS account (us-east-1 home region)"]
        API["Any API call<br/>(console, CLI, SDK)"]

        subgraph Logging["Audit logging"]
            CT["CloudTrail<br/>multi-region, validated"]
            S3CT[("S3: CloudTrail archive<br/>SSE-KMS, versioned")]
            S3AL[("S3: access logs")]
            CWL["CloudWatch Logs<br/>/aws/cloudtrail/*"]
        end

        subgraph Detect["Detection"]
            MF["15 CIS metric filters"]
            AL["CloudWatch alarms"]
            GD["GuardDuty<br/>+ S3 Protection"]
            EB["EventBridge rule<br/>severity >= 4"]
            LM["Lambda<br/>format + latency"]
            DLQ[("SQS DLQ")]
        end

        subgraph Notify["Notification"]
            SNS["SNS topic<br/>KMS-encrypted"]
            EM["Email"]
        end

        subgraph Posture["Posture and guardrails"]
            CFG["AWS Config<br/>15 managed rules"]
            IAM["IAM: groups, force-MFA,<br/>password policy, Access Analyzer"]
            ACC["Account defaults:<br/>S3 public block, EBS encryption"]
        end

        subgraph Net["Network"]
            VPC["VPC (private only)<br/>default SG locked"]
            FL["VPC Flow Logs<br/>main + default VPC"]
        end

        KMS{{"KMS CMK<br/>rotation on"}}
    end

    API --> CT
    CT --> S3CT
    S3CT -. access logging .-> S3AL
    CT --> CWL --> MF --> AL --> SNS
    CT -. analyzed by .-> GD
    FL -. analyzed by .-> GD
    VPC --> FL
    GD --> EB --> LM --> SNS --> EM
    LM -. on failure .-> DLQ
    KMS -. encrypts .-> S3CT
    KMS -. encrypts .-> CWL
    KMS -. encrypts .-> SNS
```

## Module map

| Module | What it creates | Why it exists |
|---|---|---|
| `bootstrap/` | Remote-state S3 bucket, monthly budget | State holds every resource ID and can hold secrets; it must be encrypted, versioned, and off the laptop. The budget turns runaway cost into an email. |
| `kms` | One customer-managed key with rotation | Gives us a key policy to control who can decrypt audit logs and lets CloudWatch alarms publish to an encrypted topic. |
| `cloudtrail` | Multi-region trail, archive bucket, access-log bucket, CloudWatch Logs stream | The audit record every investigation starts from. |
| `monitoring` | 15 metric filters and alarms on the CloudTrail stream | Real-time alerts on root use, IAM/policy changes, disabled logging, network changes, failed logins. |
| `guardduty` | Detector with S3 Protection | Managed threat detection over CloudTrail, flow logs, and DNS. |
| `alerting` | EventBridge rule, Lambda, SNS topic, DLQ | Turns findings into readable alerts within minutes. |
| `network` | Private VPC, locked default SGs, flow logs on every VPC | Network visibility and a fail-closed default. |
| `config` | Recorder, delivery bucket, 15 managed rules | Continuous compliance: drift shows up as NON_COMPLIANT. |
| `iam` | Force-MFA policy, admin/auditor/provisioner groups, support role | Least privilege through groups; MFA for humans. |
| `account-hardening` | Password policy, Access Analyzer, EBS default encryption, account S3 public access block | One-time switches that protect every future resource. |
