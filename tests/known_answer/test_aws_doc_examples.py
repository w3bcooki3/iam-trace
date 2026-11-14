"""Known-answer tests: every worked example in AWS's policy evaluation documentation.

Policies are copied from the AWS docs. Expected outcomes are the ones the docs state.
tests/known_answer/SOURCES.md lists each example with its URL.
"""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace import Decision, Policy, PolicySet, PolicyType, Principal, Request, evaluate

# ---------------------------------------------------------------------------
# Example 1. "Example identity-based and resource-based policy evaluation"
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-basics.html
# ---------------------------------------------------------------------------

CARLOS_IDENTITY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowS3ListRead",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:GetAccountPublicAccessBlock",
                "s3:ListAccessPoints",
                "s3:ListAllMyBuckets",
            ],
            "Resource": "arn:aws:s3:::*",
        },
        {
            "Sid": "AllowS3Self",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/*",
                "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar",
            ],
        },
        {"Sid": "DenyS3Logs", "Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::*log*"},
    ],
}

CARLOS_BUCKET = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:user/carlossalazar"},
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/*",
                "arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar",
            ],
        }
    ],
}


def _carlos(resource: str) -> Any:
    return evaluate(
        Request(
            principal=Principal.from_arn("arn:aws:iam::123456789012:user/carlossalazar"),
            action="s3:PutObject",
            resource=resource,
            resource_account="123456789012",
        ),
        PolicySet(
            identity=[Policy.parse(CARLOS_IDENTITY, policy_id="carlos-identity", policy_type=PolicyType.IDENTITY)],
            resource=[Policy.parse(CARLOS_BUCKET, policy_id="carlos-bucket", policy_type=PolicyType.RESOURCE)],
        ),
    )


def test_basics_carlos_logs_bucket_denied() -> None:
    r = _carlos("arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar-logs/file.txt")
    assert r.decision is Decision.EXPLICIT_DENY
    assert r.trace[0].matches[0].sid == "DenyS3Logs"


def test_basics_carlos_own_bucket_allowed() -> None:
    r = _carlos("arn:aws:s3:::amzn-s3-demo-bucket-carlossalazar/file.txt")
    assert r.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# Example 2. "Cross-account policy evaluation logic", example with the Demo role
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
# ---------------------------------------------------------------------------

DEMO_IDENTITY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "AllowS3ListRead", "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
        {
            "Sid": "AllowS3ProductionObjectActions",
            "Effect": "Allow",
            "Action": "s3:*Object*",
            "Resource": "arn:aws:s3:::amzn-s3-demo-bucket-production/*",
        },
        {
            "Sid": "DenyS3Logs",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": ["arn:aws:s3:::*log*", "arn:aws:s3:::*log*/*"],
        },
    ],
}

PRODUCTION_BUCKET = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject*", "s3:PutObject*", "s3:ReplicateObject", "s3:RestoreObject"],
            "Principal": {"AWS": "arn:aws:iam::111111111111:role/Demo"},
            "Resource": "arn:aws:s3:::amzn-s3-demo-bucket-production/*",
        }
    ],
}

DEMO_SESSION = Principal.from_arn("arn:aws:sts::111111111111:assumed-role/Demo/carlos")


def _demo(resource: str, bucket_policy: dict[str, Any] | None) -> Any:
    resources = []
    if bucket_policy:
        resources.append(Policy.parse(bucket_policy, policy_id="production-bucket", policy_type=PolicyType.RESOURCE))
    return evaluate(
        Request(principal=DEMO_SESSION, action="s3:PutObject", resource=resource, resource_account="222222222222"),
        PolicySet(
            identity=[Policy.parse(DEMO_IDENTITY, policy_id="demo-identity", policy_type=PolicyType.IDENTITY)],
            resource=resources,
        ),
    )


def test_cross_account_logs_bucket_denied() -> None:
    r = _demo("arn:aws:s3:::amzn-s3-demo-bucket-production-logs/file.txt", None)
    assert r.decision is Decision.EXPLICIT_DENY


def test_cross_account_production_bucket_allowed() -> None:
    r = _demo("arn:aws:s3:::amzn-s3-demo-bucket-production/file.txt", PRODUCTION_BUCKET)
    assert r.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# Example 3. Permissions boundaries: Shirley, Zhang and Nikhil
# https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
# ---------------------------------------------------------------------------

SHIRLEY_BOUNDARY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:*", "cloudwatch:*", "ec2:*"], "Resource": "*"}],
}
SHIRLEY_POLICY = {
    "Version": "2012-10-17",
    "Statement": {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"},
}

X_COMPANY_BOUNDARIES = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ServiceBoundaries",
            "Effect": "Allow",
            "Action": ["s3:*", "cloudwatch:*", "ec2:*", "dynamodb:*"],
            "Resource": "*",
        },
        {
            "Sid": "AllowIAMConsoleForCredentials",
            "Effect": "Allow",
            "Action": ["iam:ListUsers", "iam:GetAccountPasswordPolicy"],
            "Resource": "*",
        },
        {
            "Sid": "AllowManageOwnPasswordAndAccessKeys",
            "Effect": "Allow",
            "Action": [
                "iam:*AccessKey*",
                "iam:ChangePassword",
                "iam:GetUser",
                "iam:*ServiceSpecificCredential*",
                "iam:*SigningCertificate*",
            ],
            "Resource": ["arn:aws:iam::*:user/${aws:username}"],
        },
        {
            "Sid": "DenyS3Logs",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": ["arn:aws:s3:::logs", "arn:aws:s3:::logs/*"],
        },
        {
            "Sid": "DenyEC2Production",
            "Effect": "Deny",
            "Action": "ec2:*",
            "Resource": "arn:aws:ec2:*:*:instance/i-1234567890abcdef0",
        },
    ],
}

DELEGATED_USER_BOUNDARY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CreateOrChangeOnlyWithBoundary",
            "Effect": "Allow",
            "Action": [
                "iam:AttachUserPolicy",
                "iam:CreateUser",
                "iam:DeleteUserPolicy",
                "iam:DetachUserPolicy",
                "iam:PutUserPermissionsBoundary",
                "iam:PutUserPolicy",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"iam:PermissionsBoundary": "arn:aws:iam::123456789012:policy/XCompanyBoundaries"}
            },
        },
        {
            "Sid": "CloudWatchAndOtherIAMTasks",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:*",
                "iam:CreateAccessKey",
                "iam:CreateGroup",
                "iam:CreateLoginProfile",
                "iam:CreatePolicy",
                "iam:DeleteGroup",
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:DeleteUser",
                "iam:GetAccountPasswordPolicy",
                "iam:GetGroup",
                "iam:GetLoginProfile",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRolePolicy",
                "iam:GetUser",
                "iam:GetUserPolicy",
                "iam:ListAccessKeys",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListEntitiesForPolicy",
                "iam:ListGroups",
                "iam:ListGroupsForUser",
                "iam:ListMFADevices",
                "iam:ListPolicies",
                "iam:ListPolicyVersions",
                "iam:ListRolePolicies",
                "iam:ListSSHPublicKeys",
                "iam:ListServiceSpecificCredentials",
                "iam:ListSigningCertificates",
                "iam:ListUserPolicies",
                "iam:ListUsers",
                "iam:SetDefaultPolicyVersion",
                "iam:SimulateCustomPolicy",
                "iam:SimulatePrincipalPolicy",
                "iam:UpdateGroup",
                "iam:UpdateLoginProfile",
                "iam:UpdateUser",
            ],
            "NotResource": "arn:aws:iam::123456789012:user/Maria",
        },
        {
            "Sid": "NoBoundaryPolicyEdit",
            "Effect": "Deny",
            "Action": [
                "iam:CreatePolicyVersion",
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:SetDefaultPolicyVersion",
            ],
            "Resource": [
                "arn:aws:iam::123456789012:policy/XCompanyBoundaries",
                "arn:aws:iam::123456789012:policy/DelegatedUserBoundary",
            ],
        },
        {
            "Sid": "NoBoundaryUserDelete",
            "Effect": "Deny",
            "Action": "iam:DeleteUserPermissionsBoundary",
            "Resource": "*",
        },
    ],
}

DELEGATED_USER_PERMISSIONS = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "IAM", "Effect": "Allow", "Action": "iam:*", "Resource": "*"},
        {
            "Sid": "CloudWatchLimited",
            "Effect": "Allow",
            "Action": [
                "cloudwatch:GetDashboard",
                "cloudwatch:GetMetricData",
                "cloudwatch:ListDashboards",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:ListMetrics",
            ],
            "Resource": "*",
        },
        {
            "Sid": "S3BucketContents",
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::ZhangBucket",
        },
    ],
}

# Nikhil's identity policies are the AWS managed policies IAMFullAccess and
# AmazonS3ReadOnlyAccess. Only the statements relevant to the examples are reproduced here; the
# full documents are on the AWS managed policy reference pages.
IAM_FULL_ACCESS = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
S3_READ_ONLY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}],
}

ACCT = "123456789012"
ZHANG = Principal.from_arn(f"arn:aws:iam::{ACCT}:user/Zhang")
NIKHIL = Principal.from_arn(f"arn:aws:iam::{ACCT}:user/Nikhil")


def _p(doc: dict[str, Any], pid: str, t: PolicyType) -> Policy:
    return Policy.parse(doc, policy_id=pid, policy_type=t)


def _zhang(action: str, resource: str, context: dict[str, Any] | None = None) -> Any:
    return evaluate(
        Request(principal=ZHANG, action=action, resource=resource, resource_account=ACCT, context=context or {}),
        PolicySet(
            identity=[_p(DELEGATED_USER_PERMISSIONS, "DelegatedUserPermissions", PolicyType.IDENTITY)],
            boundary=_p(DELEGATED_USER_BOUNDARY, "DelegatedUserBoundary", PolicyType.BOUNDARY),
        ),
    )


def _nikhil(action: str, resource: str, resource_policy: dict[str, Any] | None = None) -> Any:
    return evaluate(
        Request(principal=NIKHIL, action=action, resource=resource, resource_account=ACCT),
        PolicySet(
            identity=[
                _p(IAM_FULL_ACCESS, "IAMFullAccess", PolicyType.IDENTITY),
                _p(S3_READ_ONLY, "AmazonS3ReadOnlyAccess", PolicyType.IDENTITY),
            ],
            boundary=_p(X_COMPANY_BOUNDARIES, "XCompanyBoundaries", PolicyType.BOUNDARY),
            resource=[_p(resource_policy, "resource", PolicyType.RESOURCE)] if resource_policy else [],
        ),
    )


def test_boundary_shirley_create_user_fails() -> None:
    # "It fails because the permissions boundary does not allow the iam:CreateUser operation."
    r = evaluate(
        Request(
            principal=Principal.from_arn(f"arn:aws:iam::{ACCT}:user/Shirley"),
            action="iam:CreateUser",
            resource=f"arn:aws:iam::{ACCT}:user/new",
            resource_account=ACCT,
        ),
        PolicySet(
            identity=[_p(SHIRLEY_POLICY, "shirley", PolicyType.IDENTITY)],
            boundary=_p(SHIRLEY_BOUNDARY, "shirley-boundary", PolicyType.BOUNDARY),
        ),
    )
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "permissions_boundary"


@pytest.mark.parametrize("action", ["s3:GetObject", "ec2:DescribeInstances", "cloudwatch:GetDashboard"])
def test_boundary_shirley_has_no_permissions(action: str) -> None:
    # "Given these two policies, Shirley does not have permission to perform any operations in AWS."
    r = evaluate(
        Request(
            principal=Principal.from_arn(f"arn:aws:iam::{ACCT}:user/Shirley"),
            action=action,
            resource="*",
            resource_account=ACCT,
        ),
        PolicySet(
            identity=[_p(SHIRLEY_POLICY, "shirley", PolicyType.IDENTITY)],
            boundary=_p(SHIRLEY_BOUNDARY, "shirley-boundary", PolicyType.BOUNDARY),
        ),
    )
    assert not r.allowed


def test_boundary_zhang_create_user_without_boundary_fails() -> None:
    r = _zhang("iam:CreateUser", f"arn:aws:iam::{ACCT}:user/Nikhil")
    assert not r.allowed


def test_boundary_zhang_create_user_with_boundary_succeeds() -> None:
    r = _zhang(
        "iam:CreateUser",
        f"arn:aws:iam::{ACCT}:user/Nikhil",
        {"iam:PermissionsBoundary": f"arn:aws:iam::{ACCT}:policy/XCompanyBoundaries"},
    )
    assert r.allowed


def test_boundary_zhang_cannot_list_his_bucket() -> None:
    # "he cannot perform any S3 operations, regardless of his permissions policy."
    assert not _zhang("s3:ListBucket", "arn:aws:s3:::ZhangBucket").allowed


def test_boundary_zhang_cannot_edit_boundary_policies() -> None:
    r = _zhang("iam:CreatePolicyVersion", f"arn:aws:iam::{ACCT}:policy/XCompanyBoundaries")
    assert r.decision is Decision.EXPLICIT_DENY


def test_boundary_nikhil_changes_own_password() -> None:
    assert _nikhil("iam:ChangePassword", f"arn:aws:iam::{ACCT}:user/Nikhil").allowed


def test_boundary_nikhil_cannot_change_other_password() -> None:
    assert not _nikhil("iam:ChangePassword", f"arn:aws:iam::{ACCT}:user/Maria").allowed


def test_boundary_nikhil_cannot_create_users() -> None:
    assert not _nikhil("iam:CreateUser", f"arn:aws:iam::{ACCT}:user/someone").allowed


def test_boundary_nikhil_cannot_edit_own_policies() -> None:
    assert not _nikhil("iam:PutUserPolicy", f"arn:aws:iam::{ACCT}:user/Nikhil").allowed


def test_boundary_nikhil_reads_s3() -> None:
    assert _nikhil("s3:GetObject", "arn:aws:s3:::some-bucket/key").allowed


def test_boundary_nikhil_logs_bucket_explicitly_denied_despite_resource_policy() -> None:
    # "An explicit deny in any policy type results in a request being denied."
    logs_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/Nikhil"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::logs/*",
            }
        ],
    }
    r = _nikhil("s3:PutObject", "arn:aws:s3:::logs/file", logs_policy)
    assert r.decision is Decision.EXPLICIT_DENY


def test_boundary_nikhil_secret_via_resource_policy() -> None:
    # "implicit denies in permissions boundaries do not limit resource-based policies."
    # The docs give no JSON for this case; the secret policy below is the minimal one described.
    secret = f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:app-AbCdEf"
    secret_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ACCT}:user/Nikhil"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    assert _nikhil("secretsmanager:GetSecretValue", secret, secret_policy).allowed
