# Results

All numbers come from real runs in my AWS account. Raw scanner output is kept out of the repo because it includes the account ID and a full list of weaknesses.

## CIS AWS Foundations Benchmark (Prowler, us-east-1)

| Scan | Date | Benchmark | Checks passed | Pass rate |
|---|---|---|---|---|
| Before (CloudTrail only) | YYYY-MM-DD | CIS vX.X | X / Y | X% |
| After (full baseline) | YYYY-MM-DD | CIS vX.X | X / Y | X% |

**Remaining failures and why:**

| Check | Reason it still fails |
|---|---|
| _fill in from the after-scan_ | _accepted gap / manual step / out of scope_ |

## Alerting pipeline

| Test | Result |
|---|---|
| Direct Lambda invoke | email received: yes/no |
| GuardDuty sample finding, end to end | email received in ~X min; Lambda-measured latency X s |
| CIS alarm (security group change) | email received in ~X min |

## CI

| Gate | Result |
|---|---|
| `terraform fmt` / `validate` | passing |
| Checkov | 294 passed, 0 failed, 23 skipped (each skip justified inline) |
