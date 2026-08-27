# Cloud Security Baseline (AWS + Terraform)

**Status:** 🚧 In Progress

A Terraform-based security baseline for AWS accounts, implementing centralized logging, threat detection, least-privilege IAM, and network visibility as reusable, version-controlled infrastructure.

## Why this project

Most AWS environments start without basic security guardrails in place. This project builds out a baseline that any new AWS account should have from day one — the kind of foundational hardening a Cloud Security Engineer would be expected to implement and maintain.

## Planned Architecture

- **AWS CloudTrail** — account-wide API activity logging, sent to a dedicated, access-restricted S3 bucket
- **Amazon GuardDuty** — continuous threat detection across the account
- **IAM** — least-privilege roles and policies, no wildcard permissions, enforced via Terraform rather than manual console changes
- **VPC Flow Logs** — network traffic visibility at the VPC level
- **Lambda + SNS** — automated alerting pipeline that reacts to GuardDuty findings and notifies via email/SNS topic

## Tools

- Terraform (Infrastructure as Code)
- AWS (CloudTrail, GuardDuty, IAM, VPC, Lambda, SNS, S3)

## What this demonstrates

- Infrastructure as Code discipline (no manual console changes, everything reproducible)
- Core AWS security service configuration
- Secure-by-default account baselining
- Automated detection-to-alert pipeline design

## Setup

*Coming soon — deployment instructions will be added as the Terraform modules are built out.*

## Roadmap

- [ ] CloudTrail + S3 logging bucket
- [ ] IAM baseline roles/policies
- [ ] GuardDuty enablement
- [ ] VPC Flow Logs
- [ ] Lambda/SNS alerting pipeline
- [ ] Architecture diagram
- [ ] Deployment walkthrough
