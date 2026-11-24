# Deployment walkthrough

Tested from a Linux VM with Terraform 1.10+ and AWS CLI v2, authenticated as an IAM user (never root).

## 0. Prerequisites

```bash
terraform -version          # 1.10 or newer (S3 native state locking)
aws sts get-caller-identity # confirms who you are; must NOT be root
pipx install prowler        # compliance scanner, used before and after
```

## 1. Baseline scan (before deploying)

```bash
prowler aws --list-compliance | grep -i cis        # pick the newest CIS version
prowler aws --compliance cis_<version>_aws -f us-east-1 -o ~/prowler-before
```

Record the CIS pass percentage from the summary in `docs/results.md`. Keep the raw output out of Git: it contains the account ID and every weakness in the account.

## 2. Bootstrap: state bucket and budget

```bash
cd terraform/bootstrap
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init
terraform apply
```

Bootstrap state stays local by design (it creates the bucket the main stack's state lives in).

## 3. Main stack

```bash
cd ..   # terraform/
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init -migrate-state \
  -backend-config="bucket=$(terraform -chdir=bootstrap output -raw state_bucket)"
```

If a local `terraform.tfstate` exists from an earlier apply, answer `yes` to copy it to S3. Then:

```bash
terraform fmt -recursive
terraform plan -out=tfplan
```

**Check the plan before applying.** Existing CloudTrail resources must show as *moved*, never *destroy*. Then:

```bash
terraform apply tfplan
```

## 4. Post-apply manual steps

These can't (or shouldn't) be done by Terraform:

1. **Confirm the SNS subscription.** Click the link in the "AWS Notification - Subscription Confirmation" email. Nothing is delivered until you do.
2. **Remove the Terraform user's direct policy.** It now gets admin through the `terraform-provisioners` group:
   ```bash
   aws iam list-attached-user-policies --user-name anikate-cli
   aws iam detach-user-policy --user-name anikate-cli \
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   aws sts get-caller-identity   # still works = group access is live
   ```
3. **Root account** (console, signed in as root, once): MFA enabled, no access keys. Then sign out of root.
4. **Access key age**: if the Terraform user's key is older than 90 days, rotate it (create new, update `aws configure` and the password manager, delete old).

## 5. Test the alerting pipeline

**a. Direct Lambda test** (verifies formatting, KMS, and SNS permissions):

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw alert_lambda_name)" \
  --payload fileb://../tests/sample-guardduty-event.json /tmp/lambda-out.json
cat /tmp/lambda-out.json
```

Expect `{"status": "sent", ...}` and an email within a minute.

**b. End-to-end through GuardDuty and EventBridge.** Always pass `--finding-types`; without it GuardDuty generates one sample of every finding type and you'll get dozens of emails.

```bash
date -u
aws guardduty create-sample-findings \
  --detector-id "$(terraform output -raw guardduty_detector_id)" \
  --finding-types "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
```

Wait for the email (usually under 5 minutes), then read the measured latency:

```bash
aws logs tail "/aws/lambda/$(terraform output -raw alert_lambda_name)" --since 30m | grep alert_sent
```

**c. CIS alarm test** (verifies CloudTrail → CloudWatch Logs → metric filter → alarm → SNS):

```bash
VPC=$(terraform output -raw vpc_id)
SG=$(aws ec2 create-security-group --group-name alarm-test --description "CIS alarm test" \
      --vpc-id "$VPC" --query GroupId --output text)
aws ec2 delete-security-group --group-id "$SG"
```

The `cis-security-group-changes` alarm email arrives in roughly 5 to 15 minutes (CloudTrail delivery delay plus the 5-minute alarm period).

## 6. Final scan

Wait about 15 minutes after apply so Config and Access Analyzer finish their first evaluation, then:

```bash
prowler aws --compliance cis_<version>_aws -f us-east-1 -o ~/prowler-after
```

Expect some emails: the scan itself triggers AccessDenied events, which the unauthorized-API-calls alarm reports. That's the alarm working.

## 7. Cost and teardown

Rough monthly cost for an otherwise idle account (estimate, check Cost Explorer for real numbers):

| Item | Approx. |
|---|---|
| KMS customer-managed key | $1.00 |
| CloudWatch alarms (15; first 10 free) | $0.50 |
| GuardDuty (after 30-day trial) | low single dollars, usage-based |
| AWS Config (recorded items + rule evaluations) | under $2 |
| CloudWatch Logs, S3, Lambda, SNS, SQS | cents |

The budget alert emails at 80% of $10 actual and at 100% forecast.

**Teardown:** `terraform destroy` stops at the four S3 buckets on purpose (`force_destroy = false`, so logs are never deleted by accident). Empty them first, including old versions, in the S3 console ("Empty" button), then re-run `terraform destroy`. Destroy the bootstrap stack last. The KMS key enters a 7-day pending-deletion window.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `detector already exists` | GuardDuty was enabled manually before | `terraform import module.guardduty.aws_guardduty_detector.main <id>` (id from `aws guardduty list-detectors`) |
| `MaxNumberOfConfigurationRecordersExceeded` | A Config recorder already exists in the region | Delete it (`aws configservice describe-configuration-recorders`, then `delete-configuration-recorder`) or import it |
| `no matching EC2 VPC found` | Default VPC was deleted | Set `enable_default_vpc_flow_logs = false` in `terraform.tfvars` |
| `InsufficientEncryptionPolicyException` on CloudTrail | Key policy not yet propagated | Re-run `terraform apply` after a minute |
