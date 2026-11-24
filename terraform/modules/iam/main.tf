# ==========================================================================
# IAM baseline. Principles:
#   1. Permissions go to GROUPS and ROLES, never directly to users. Adding
#      or removing access is one membership change, and audits read one
#      group instead of every user.
#   2. Humans need MFA. The force-MFA policy denies almost everything until
#      the session is MFA-authenticated.
#   3. Machine identities are explicit exceptions, isolated and documented.
# ==========================================================================

data "aws_caller_identity" "current" {}

# --------------------------------------------------------------------------
# Force-MFA policy (based on AWS's published example)
# A user can sign in, set up their own MFA device, and change their own
# password. Everything else is denied until they authenticate with MFA.
# Note "$${aws:username}": the double $ stops Terraform from interpolating;
# IAM fills in the caller's username at request time.
# --------------------------------------------------------------------------

data "aws_iam_policy_document" "force_mfa" {
  statement {
    sid       = "AllowViewAccountInfo"
    actions   = ["iam:GetAccountPasswordPolicy", "iam:ListVirtualMFADevices"]
    resources = ["*"] # these List/Get actions don't support resource scoping
  }

  statement {
    sid       = "AllowManageOwnPasswordAndUser"
    actions   = ["iam:ChangePassword", "iam:GetUser"]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }

  statement {
    sid       = "AllowCreateOwnVirtualMFA"
    actions   = ["iam:CreateVirtualMFADevice"]
    resources = ["arn:aws:iam::*:mfa/*"]
  }

  statement {
    sid = "AllowManageOwnUserMFA"
    actions = [
      "iam:DeactivateMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ResyncMFADevice",
    ]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }

  # The guardrail. NotAction + Deny = "deny everything EXCEPT these".
  # BoolIfExists: long-term access keys carry no MFA flag at all, so a
  # missing flag counts as "no MFA" and is denied too.
  statement {
    sid    = "DenyAllExceptMFASetupIfNoMFA"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ChangePassword",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "iam:GetAccountPasswordPolicy",
      "sts:GetSessionToken",
    ]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "force_mfa" {
  name        = "${var.project_name}-force-mfa"
  description = "Deny all actions except MFA self-setup until the session is MFA-authenticated"
  policy      = data.aws_iam_policy_document.force_mfa.json
}

# --------------------------------------------------------------------------
# Human groups
# --------------------------------------------------------------------------

# Full admin, but only after MFA.
resource "aws_iam_group" "console_admins" {
  name = "console-admins"
}

resource "aws_iam_group_policy_attachment" "console_admins_admin" {
  #checkov:skip=CKV_AWS_274:Break-glass human admins need full access; the same group carries the force-MFA policy, so it is unusable without MFA.
  group      = aws_iam_group.console_admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group_policy_attachment" "console_admins_mfa" {
  group      = aws_iam_group.console_admins.name
  policy_arn = aws_iam_policy.force_mfa.arn
}

# Read-only security review: can see every configuration, can change
# nothing. This is what an auditor or a scanner like Prowler needs.
resource "aws_iam_group" "security_auditors" {
  name = "security-auditors"
}

resource "aws_iam_group_policy_attachment" "auditors_security_audit" {
  group      = aws_iam_group.security_auditors.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_group_policy_attachment" "auditors_view_only" {
  group      = aws_iam_group.security_auditors.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_group_policy_attachment" "auditors_mfa" {
  group      = aws_iam_group.security_auditors.name
  policy_arn = aws_iam_policy.force_mfa.arn
}

# --------------------------------------------------------------------------
# Machine identity: the user that runs Terraform.
#
# DOCUMENTED EXCEPTION: this group has AdministratorAccess WITHOUT the
# force-MFA policy. Terraform authenticates with long-term access keys,
# which can't carry MFA, so force-MFA would lock it out. Mitigations:
#   - no console password on this user, keys only
#   - permissions come through this group, not a direct attachment
#   - every call it makes lands in CloudTrail and the CIS alarms
# Next step in a real org: replace the keys with GitHub Actions OIDC or an
# assumed role, so there are no long-lived credentials at all.
# --------------------------------------------------------------------------

resource "aws_iam_group" "terraform_provisioners" {
  name = "terraform-provisioners"
}

resource "aws_iam_group_policy_attachment" "provisioners_admin" {
  #checkov:skip=CKV_AWS_274:Documented exception. Terraform provisions IAM, KMS, and every other service in the baseline; next step is OIDC/assumed-role with scoped permissions.
  group      = aws_iam_group.terraform_provisioners.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Non-exclusive membership: adds the user to this group without touching
# any other group memberships.
resource "aws_iam_user_group_membership" "provisioner" {
  user   = var.provisioner_user_name
  groups = [aws_iam_group.terraform_provisioners.name]
}

# --------------------------------------------------------------------------
# Support role. CIS asks for a role that can open AWS Support cases, so
# incident handling doesn't require root. Assumable only with MFA.
# --------------------------------------------------------------------------

data "aws_iam_policy_document" "support_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "support" {
  name               = "${var.project_name}-support"
  assume_role_policy = data.aws_iam_policy_document.support_assume.json
}

resource "aws_iam_role_policy_attachment" "support" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}
