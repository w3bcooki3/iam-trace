"""Write the sample account the web app loads (examples/sample/).

The sample is a made-up account (111122223333) built so that every part of iam-trace has
something to show:

- attack paths: one step (a Lambda function's code run as an admin role), a role that can attach
  any policy to itself, two steps (SAML sign-in, a support role, then that function), PassRole to
  a service, a policy version rewrite, and a technique an SCP blocks;
- conditions: break-glass needs MFA; a permissions boundary takes away a contractor's iam:*;
- entry points: GitHub Actions (OIDC), a partner account (with an ExternalId), SAML sign-in,
  console users without MFA and old access keys from the credential report;
- data access: S3 (public, shared with a partner, KMS encrypted), a KMS key, Secrets Manager
  secrets (AWS managed and customer key), a DynamoDB table, an SNS topic and an SQS queue;
- unused access: last accessed data in which some roles never used most of what they're allowed;
- a Terraform plan that would open a new path;
- the Who can screen is pre-filled with a query about it.

Run it after changing the sample; tests/unit/test_sample.py fails if the files are out of date:

    python3 scripts/build_sample.py
"""

from __future__ import annotations

import copy
import csv
import io
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "examples" / "sample"
A = "111122223333"
PARTNER = "444455556666"
R = "us-east-1"
KEY = f"arn:aws:kms:{R}:{A}:key/5d1c3b2a-7e6f-4a8b-9c0d-1e2f3a4b5c6d"
GITHUB = f"arn:aws:iam::{A}:oidc-provider/token.actions.githubusercontent.com"
SAML = f"arn:aws:iam::{A}:saml-provider/ExampleIdP"
ADMIN = {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}


def iam(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: str | list[str], resource: str | list[str] = "*", **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def trust(principal: dict[str, Any], action: str = "sts:AssumeRole", **extra: Any) -> dict[str, Any]:
    return doc({"Effect": "Allow", "Principal": principal, "Action": action, **extra})


def inline(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {"PolicyName": name, "PolicyDocument": doc(*statements)}


def managed(name: str) -> dict[str, str]:
    return {"PolicyName": name, "PolicyArn": iam("policy", name)}


def role(
    name: str,
    assume: dict[str, Any],
    policies: list[dict[str, Any]] = (),  # type: ignore[assignment]
    attached: list[dict[str, str]] = (),  # type: ignore[assignment]
    profile: bool = False,
    boundary: str | None = None,
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "RoleName": name,
        "Arn": iam("role", name),
        "Path": "/",
        "AssumeRolePolicyDocument": assume,
        "RolePolicyList": list(policies),
        "AttachedManagedPolicies": list(attached),
    }
    if profile:
        r["InstanceProfileList"] = [{"InstanceProfileName": name, "Arn": iam("instance-profile", name), "Path": "/"}]
    if boundary:
        r["PermissionsBoundary"] = {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": iam("policy", boundary),
        }
    return r


def user(
    name: str,
    groups: list[str],
    policies: list[dict[str, Any]] = (),  # type: ignore[assignment]
    attached: list[dict[str, str]] = (),  # type: ignore[assignment]
    boundary: str | None = None,
) -> dict[str, Any]:
    u: dict[str, Any] = {
        "UserName": name,
        "Arn": iam("user", name),
        "Path": "/",
        "GroupList": groups,
        "UserPolicyList": list(policies),
        "AttachedManagedPolicies": list(attached),
    }
    if boundary:
        u["PermissionsBoundary"] = {
            "PermissionsBoundaryType": "Policy",
            "PermissionsBoundaryArn": iam("policy", boundary),
        }
    return u


def policy(name: str, *versions: dict[str, Any], arn: str | None = None) -> dict[str, Any]:
    vs = [
        {"VersionId": f"v{i + 1}", "IsDefaultVersion": i == len(versions) - 1, "Document": v}
        for i, v in enumerate(versions)
    ]
    return {
        "PolicyName": name,
        "Arn": arn or iam("policy", name),
        "DefaultVersionId": f"v{len(versions)}",
        "PolicyVersionList": vs,
    }


ROOT_TRUST = {"AWS": f"arn:aws:iam::{A}:root"}


def auth_details() -> dict[str, Any]:
    users = [
        # A developer: through the group she can update a Lambda function that runs as an admin
        # role (one step), and assume app-deployer, which can attach any policy to itself (two).
        user("alice", ["developers"]),
        # A contractor allowed iam:* inline, but his permissions boundary only allows S3 and
        # DynamoDB, so none of it is effective.
        user(
            "bob",
            ["contractors"],
            [inline("everything-in-iam", allow("iam:*"))],
            boundary="contractor-boundary",
        ),
        # A CI user that can hand an admin role to a new Lambda function.
        user(
            "ci-bot",
            [],
            [
                inline(
                    "deploy-functions",
                    allow(["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction"]),
                    allow("iam:PassRole", iam("role", "lambda-admin")),
                )
            ],
        ),
        # An old user that can write a new version of the policy attached to itself.
        user(
            "dev-legacy",
            [],
            [
                inline(
                    "manage-own-policy",
                    allow(["iam:CreatePolicyVersion", "iam:GetPolicy"], iam("policy", "legacy-app")),
                )
            ],
            [managed("legacy-app")],
        ),
    ]
    groups = [
        {
            "GroupName": "developers",
            "Arn": iam("group", "developers"),
            "Path": "/",
            "GroupPolicyList": [
                inline("assume-app-deployer", allow("sts:AssumeRole", iam("role", "app-deployer"))),
                inline(
                    "break-glass-with-mfa",
                    allow(
                        "sts:AssumeRole",
                        iam("role", "break-glass"),
                        Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                    ),
                ),
            ],
            "AttachedManagedPolicies": [managed("DeveloperAccess")],
        },
        {
            "GroupName": "contractors",
            "Arn": iam("group", "contractors"),
            "Path": "/",
            "GroupPolicyList": [
                inline(
                    "read-orders",
                    allow(["dynamodb:GetItem", "dynamodb:Query"], f"arn:aws:dynamodb:{R}:{A}:table/example-orders"),
                )
            ],
            "AttachedManagedPolicies": [],
        },
    ]
    roles = [
        role(
            "app-deployer",
            trust(ROOT_TRUST),
            [
                inline(
                    "manage-app-roles",
                    allow(["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:GetRole"], iam("role", "app-*")),
                    allow("cloudformation:*"),
                )
            ],
        ),
        role("lambda-admin", trust({"Service": "lambda.amazonaws.com"}), attached=[ADMIN]),
        role("ec2-admin", trust({"Service": "ec2.amazonaws.com"}), attached=[ADMIN], profile=True),
        role(
            "report-runner",
            trust({"Service": "lambda.amazonaws.com"}),
            [
                inline(
                    "read-reports",
                    allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::example-reports/*"),
                    allow("kms:Decrypt", KEY),
                    allow(["dynamodb:Query", "dynamodb:GetItem"], f"arn:aws:dynamodb:{R}:{A}:table/example-orders"),
                    allow("sqs:SendMessage", f"arn:aws:sqs:{R}:{A}:example-jobs"),
                )
            ],
        ),
        role(
            "github-deploy",
            trust(
                {"Federated": GITHUB},
                "sts:AssumeRoleWithWebIdentity",
                Condition={
                    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
                    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/web:*"},
                },
            ),
            [
                inline(
                    "deploy",
                    allow(["s3:PutObject", "s3:DeleteObject"], "arn:aws:s3:::example-public-assets/*"),
                    allow(
                        ["cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DescribeStacks"]
                    ),
                    allow("iam:PassRole", iam("role", "cfn-exec")),
                )
            ],
        ),
        role("cfn-exec", trust({"Service": "cloudformation.amazonaws.com"}), attached=[ADMIN]),
        role(
            "partner-audit",
            trust(
                {"AWS": f"arn:aws:iam::{PARTNER}:root"},
                Condition={"StringEquals": {"sts:ExternalId": "example-audit-7731"}},
            ),
            [
                inline(
                    "audit",
                    allow(["iam:Get*", "iam:List*", "cloudtrail:LookupEvents", "config:Describe*"]),
                    allow(
                        "secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:{R}:{A}:secret:example-api-token-*"
                    ),
                    allow("kms:Decrypt", KEY),
                )
            ],
        ),
        role(
            "sso-readonly",
            trust(
                {"Federated": SAML},
                "sts:AssumeRoleWithSAML",
                Condition={"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
            ),
            [
                inline(
                    "read",
                    allow(["s3:GetObject", "s3:ListBucket", "dynamodb:Scan", "ec2:Describe*"]),
                    allow("sts:AssumeRole", iam("role", "app-support")),
                )
            ],
        ),
        # Support staff who sign in through SAML can switch to this role, which can change the
        # code of a function that runs as lambda-admin: a path of two steps.
        role(
            "app-support",
            trust({"AWS": iam("role", "sso-readonly")}),
            [
                inline(
                    "fix-payments",
                    allow(
                        ["lambda:UpdateFunctionCode", "lambda:GetFunction"],
                        f"arn:aws:lambda:{R}:{A}:function:payments-api",
                    ),
                    allow("logs:*"),
                )
            ],
        ),
        role(
            "break-glass",
            trust(ROOT_TRUST, Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}),
            attached=[ADMIN],
        ),
        # Allowed far more than it uses: the unused-access screen's main example.
        role(
            "analytics",
            trust({"Service": "glue.amazonaws.com"}),
            [
                inline(
                    "analytics",
                    allow(["athena:*", "glue:*", "redshift:*", "s3:GetObject", "s3:ListBucket", "sns:Publish"]),
                )
            ],
        ),
    ]
    policies = [
        policy("AdministratorAccess", doc(allow("*")), arn=ADMIN["PolicyArn"]),
        policy(
            "DeveloperAccess",
            doc(
                allow(["ec2:Describe*", "lambda:Get*", "lambda:List*", "logs:*", "cloudwatch:Get*"]),
                allow(
                    ["lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"],
                    [
                        f"arn:aws:lambda:{R}:{A}:function:payments-api",
                        f"arn:aws:lambda:{R}:{A}:function:nightly-report",
                    ],
                ),
            ),
        ),
        policy("contractor-boundary", doc(allow(["s3:*", "dynamodb:*"]))),
        policy(
            "legacy-app",
            doc(allow(["s3:ListAllMyBuckets"])),
            doc(allow(["s3:ListAllMyBuckets", "s3:GetObject"], ["arn:aws:s3:::*"])),
        ),
    ]
    return {"UserDetailList": users, "GroupDetailList": groups, "RoleDetailList": roles, "Policies": policies}


def previous_auth_details() -> dict[str, Any]:
    """The same account a month earlier, for the Account drift screen. Since then: ci-bot was
    allowed to pass the lambda-admin role (a new path to admin); bob, a contractor, was given
    iam:*, which his permission boundary makes ineffective; dev-legacy was created; and old-ops,
    a forgotten admin user, was deleted."""
    data = copy.deepcopy(auth_details())
    data["UserDetailList"] = [u for u in data["UserDetailList"] if u["UserName"] != "dev-legacy"]
    for u in data["UserDetailList"]:
        if u["UserName"] == "bob":
            u["UserPolicyList"] = [p for p in u["UserPolicyList"] if p["PolicyName"] != "everything-in-iam"]
        if u["UserName"] == "ci-bot":  # could deploy functions, but not yet pass them the admin role
            for p in u["UserPolicyList"]:
                p["PolicyDocument"]["Statement"] = [
                    st for st in p["PolicyDocument"]["Statement"] if st["Action"] != "iam:PassRole"
                ]
    data["UserDetailList"].append(user("old-ops", [], attached=[ADMIN]))
    return data


def scps() -> list[dict[str, Any]]:
    return [
        doc({"Sid": "FullAWSAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}),
        doc(
            {
                "Sid": "ApprovedRegionsOnly",
                "Effect": "Deny",
                "NotAction": ["iam:*", "sts:*", "organizations:*", "support:*", "cloudfront:*", "route53:*"],
                "Resource": "*",
                "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["us-east-1", "eu-west-1"]}},
            },
            {
                # Glue development endpoints run code as a role: a known escalation technique
                # (glue-002) the analytics role would otherwise have.
                "Sid": "NoGlueDevEndpoints",
                "Effect": "Deny",
                "Action": ["glue:CreateDevEndpoint", "glue:UpdateDevEndpoint"],
                "Resource": "*",
            },
            {
                "Sid": "StayInTheOrganization",
                "Effect": "Deny",
                "Action": "organizations:LeaveOrganization",
                "Resource": "*",
            },
        ),
    ]


def inventory() -> dict[str, Any]:
    topic = f"arn:aws:sns:{R}:{A}:example-alerts"
    queue = f"arn:aws:sqs:{R}:{A}:example-jobs"
    return {
        "Version": 1,
        "Collected": sorted(
            [
                "dynamodb-table",
                "ec2-instance",
                "kms-key",
                "lambda-function",
                "s3-bucket",
                "secretsmanager-secret",
                "sns-topic",
                "sqs-queue",
            ]
        ),
        "Resources": [
            {"Arn": f"arn:aws:lambda:{R}:{A}:function:nightly-report", "Role": iam("role", "report-runner")},
            {"Arn": f"arn:aws:lambda:{R}:{A}:function:payments-api", "Role": iam("role", "lambda-admin")},
            {"Arn": f"arn:aws:ec2:{R}:{A}:instance/i-0123456789abcdef0", "Role": iam("instance-profile", "ec2-admin")},
            {
                "Arn": "arn:aws:s3:::example-reports",
                "KmsKey": KEY,
                "Policy": doc(
                    {
                        "Sid": "PartnerRead",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{PARTNER}:root"},
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::example-reports/*",
                    }
                ),
                "PublicAccessBlock": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            },
            {
                "Arn": "arn:aws:s3:::example-public-assets",
                "Policy": doc(
                    {
                        "Sid": "PublicRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::example-public-assets/*",
                    }
                ),
            },
            {
                "Arn": KEY,
                "Policy": doc(
                    {"Sid": "Account", "Effect": "Allow", "Principal": ROOT_TRUST, "Action": "kms:*", "Resource": "*"},
                    {
                        "Sid": "PartnerDecrypt",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{PARTNER}:root"},
                        "Action": "kms:Decrypt",
                        "Resource": "*",
                    },
                ),
            },
            {
                # On the AWS managed key, so the partner named in its policy still can't read it.
                "Arn": f"arn:aws:secretsmanager:{R}:{A}:secret:example-db-password-Q1w2E3",
                "Policy": doc(
                    {
                        "Sid": "PartnerRead",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{PARTNER}:root"},
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": "*",
                    }
                ),
            },
            {"Arn": f"arn:aws:secretsmanager:{R}:{A}:secret:example-api-token-R4t5Y6", "KmsKey": KEY},
            {"Arn": f"arn:aws:dynamodb:{R}:{A}:table/example-orders", "KmsKey": KEY},
            {
                "Arn": topic,
                "Policy": doc(
                    {
                        "Sid": "EventsPublish",
                        "Effect": "Allow",
                        "Principal": {"Service": "events.amazonaws.com"},
                        "Action": "sns:Publish",
                        "Resource": topic,
                    }
                ),
            },
            {
                "Arn": queue,
                "KmsKey": "alias/aws/sqs",
                "Policy": doc(
                    {
                        "Sid": "FromAlerts",
                        "Effect": "Allow",
                        "Principal": {"Service": "sns.amazonaws.com"},
                        "Action": "sqs:SendMessage",
                        "Resource": queue,
                        "Condition": {"ArnEquals": {"aws:SourceArn": topic}},
                    }
                ),
            },
        ],
    }


CRED_FIELDS = [
    "user",
    "arn",
    "user_creation_time",
    "password_enabled",
    "password_last_used",
    "password_last_changed",
    "password_next_rotation",
    "mfa_active",
    "access_key_1_active",
    "access_key_1_last_rotated",
    "access_key_1_last_used_date",
    "access_key_1_last_used_region",
    "access_key_1_last_used_service",
    "access_key_2_active",
    "access_key_2_last_rotated",
    "access_key_2_last_used_date",
    "access_key_2_last_used_region",
    "access_key_2_last_used_service",
    "cert_1_active",
    "cert_1_last_rotated",
    "cert_2_active",
    "cert_2_last_rotated",
]


def credential_report() -> str:
    na = "N/A"

    def row(
        name: str,
        arn: str,
        created: str,
        pw: tuple[str, str, str],
        mfa: bool,
        key: tuple[str, str, str, str, str] | None,
    ) -> dict[str, str]:
        k = key or ("false", na, na, na, na)
        return dict(
            zip(
                CRED_FIELDS,
                [name, arn, created, *pw, na, str(mfa).lower(), *k, "false", na, na, na, na, "false", na, "false", na],
                strict=True,
            )
        )

    rows = [
        row(
            "<root_account>",
            f"arn:aws:iam::{A}:root",
            "2022-04-01T09:00:00+00:00",
            ("not_supported", "2026-03-02T10:12:00+00:00", "not_supported"),
            True,
            None,
        ),
        row(
            "alice",
            iam("user", "alice"),
            "2024-01-15T10:00:00+00:00",
            ("true", "2026-11-19T08:30:00+00:00", "2026-06-01T09:00:00+00:00"),
            True,
            ("true", "2026-08-03T12:00:00+00:00", "2026-11-19T09:12:00+00:00", "us-east-1", "lambda"),
        ),
        row(
            "bob",
            iam("user", "bob"),
            "2025-02-10T14:00:00+00:00",
            ("true", "2026-10-30T16:45:00+00:00", "2025-02-10T14:00:00+00:00"),
            False,
            ("true", "2025-02-10T14:05:00+00:00", na, na, na),
        ),
        row(
            "ci-bot",
            iam("user", "ci-bot"),
            "2023-07-20T09:00:00+00:00",
            ("false", na, na),
            False,
            ("true", "2024-12-01T09:00:00+00:00", "2026-11-20T02:00:00+00:00", "us-east-1", "lambda"),
        ),
        row(
            "dev-legacy",
            iam("user", "dev-legacy"),
            "2021-05-04T11:00:00+00:00",
            ("true", "2025-12-12T10:00:00+00:00", "2021-05-04T11:00:00+00:00"),
            False,
            ("true", "2021-05-04T11:10:00+00:00", "2025-11-02T13:00:00+00:00", "eu-west-1", "s3"),
        ),
    ]
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=CRED_FIELDS, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return out.getvalue()


def last_accessed() -> dict[str, Any]:
    when = "2026-11-20T09:00:00+00:00"

    def svc(ns: str, name: str, last: str | None, actions: list[tuple[str, str]] = ()) -> dict[str, Any]:  # type: ignore[assignment]
        s: dict[str, Any] = {
            "ServiceName": name,
            "ServiceNamespace": ns,
            "TotalAuthenticatedEntities": 1 if last else 0,
        }
        if last:
            s["LastAuthenticated"] = last
            s["LastAuthenticatedRegion"] = R
        if actions:
            s["TrackedActionsLastAccessed"] = [
                {"ActionName": a, "LastAccessedTime": t, "LastAccessedRegion": R} for a, t in actions
            ]
        return s

    def report(*services: dict[str, Any]) -> dict[str, Any]:
        return {
            "JobStatus": "COMPLETED",
            "JobType": "ACTION_LEVEL",
            "JobCreationDate": "2026-11-20T08:59:00+00:00",
            "JobCompletionDate": when,
            "ServicesLastAccessed": list(services),
        }

    recent = "2026-11-18T10:00:00+00:00"
    old = "2026-02-01T10:00:00+00:00"
    return {
        "Reports": {
            iam("user", "alice"): report(
                svc("lambda", "AWS Lambda", recent, [("UpdateFunctionCode", recent), ("GetFunction", recent)]),
                svc("logs", "Amazon CloudWatch Logs", recent),
                svc("ec2", "Amazon EC2", recent),
                svc("sts", "AWS Security Token Service", recent),
                svc("cloudwatch", "Amazon CloudWatch", None),
            ),
            iam("user", "bob"): report(
                svc("s3", "Amazon S3", None),
                svc("dynamodb", "Amazon DynamoDB", recent),
                svc("iam", "AWS Identity and Access Management", None),
            ),
            iam("user", "ci-bot"): report(
                svc("lambda", "AWS Lambda", recent, [("CreateFunction", recent)]),
                svc("iam", "AWS Identity and Access Management", recent),
            ),
            iam("user", "dev-legacy"): report(
                svc("iam", "AWS Identity and Access Management", None), svc("s3", "Amazon S3", old)
            ),
            iam("role", "app-deployer"): report(
                svc("iam", "AWS Identity and Access Management", old),
                svc("cloudformation", "AWS CloudFormation", recent),
            ),
            iam("role", "report-runner"): report(
                svc("s3", "Amazon S3", recent),
                svc("kms", "AWS Key Management Service", recent),
                svc("dynamodb", "Amazon DynamoDB", recent),
                svc("sqs", "Amazon SQS", recent),
            ),
            iam("role", "github-deploy"): report(
                svc("s3", "Amazon S3", recent),
                svc("cloudformation", "AWS CloudFormation", recent),
                svc("iam", "AWS Identity and Access Management", recent),
            ),
            iam("role", "partner-audit"): report(
                svc("iam", "AWS Identity and Access Management", recent),
                svc("cloudtrail", "AWS CloudTrail", None),
                svc("config", "AWS Config", None),
                svc("secretsmanager", "AWS Secrets Manager", old),
                svc("kms", "AWS Key Management Service", old),
            ),
            iam("role", "sso-readonly"): report(
                svc("s3", "Amazon S3", recent),
                svc("dynamodb", "Amazon DynamoDB", None),
                svc("ec2", "Amazon EC2", recent),
                svc("sts", "AWS Security Token Service", recent),
            ),
            iam("role", "app-support"): report(
                svc("lambda", "AWS Lambda", old), svc("logs", "Amazon CloudWatch Logs", recent)
            ),
            iam("role", "break-glass"): report(),
            iam("role", "analytics"): report(
                svc("athena", "Amazon Athena", recent),
                svc("glue", "AWS Glue", None),
                svc("redshift", "Amazon Redshift", None),
                svc("s3", "Amazon S3", recent),
                svc("sns", "Amazon SNS", None),
            ),
        }
    }


def terraform_plan() -> dict[str, Any]:
    def change(address: str, type_: str, name: str, actions: list[str], before: Any, after: Any) -> dict[str, Any]:
        return {
            "address": address,
            "type": type_,
            "name": name,
            "change": {"actions": actions, "before": before, "after": after, "after_unknown": {}},
        }

    release_trust = json.dumps(
        trust(
            {"Federated": GITHUB},
            "sts:AssumeRoleWithWebIdentity",
            Condition={"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
        )
    )
    old_runner = json.dumps(doc(allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::example-reports/*")))
    new_runner = json.dumps(
        doc(allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::example-reports/*"), allow("kms:Decrypt", KEY))
    )
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "resource_changes": [
            # A new role for releases that any GitHub repository's workflow could assume (the
            # trust policy checks the audience but not the repository), allowed to hand
            # lambda-admin to a new function: a new path to admin, and a new entry point.
            change(
                "aws_iam_role.release",
                "aws_iam_role",
                "release",
                ["create"],
                None,
                {"name": "release", "path": "/", "assume_role_policy": release_trust, "tags": {"team": "platform"}},
            ),
            change(
                "aws_iam_role_policy.release",
                "aws_iam_role_policy",
                "release",
                ["create"],
                None,
                {
                    "role": "release",
                    "name": "deploy",
                    "policy": json.dumps(
                        doc(
                            allow(["lambda:CreateFunction", "lambda:InvokeFunction"]),
                            allow("iam:PassRole", iam("role", "lambda-admin")),
                        )
                    ),
                },
            ),
            change(
                "aws_iam_role_policy.report_runner",
                "aws_iam_role_policy",
                "report_runner",
                ["update"],
                {"role": "report-runner", "name": "read-reports", "policy": old_runner},
                {"role": "report-runner", "name": "read-reports", "policy": new_runner},
            ),
            change(
                "aws_iam_user_policy.bob",
                "aws_iam_user_policy",
                "bob",
                ["delete"],
                {"user": "bob", "name": "everything-in-iam", "policy": json.dumps(doc(allow("iam:*")))},
                None,
            ),
        ],
        "configuration": {"root_module": {"resources": []}},
    }


# What the web app puts in the tool screens when the sample loads: the principal the attack graph
# starts from, and a Who can query.
QUERIES = {
    "start": iam("user", "alice"),
    "whocan": {
        "action": "secretsmanager:GetSecretValue",
        "resource": f"arn:aws:secretsmanager:{R}:{A}:secret:example-api-token-R4t5Y6",
    },
}


def files() -> dict[str, str]:
    def j(v: Any) -> str:
        return json.dumps(v, indent=2) + "\n"

    return {
        "auth-details.json": j(auth_details()),
        "auth-details-previous.json": j(previous_auth_details()),
        "scps.json": j(scps()),
        "inventory.json": j(inventory()),
        "credential-report.csv": credential_report(),
        "last-accessed.json": j(last_accessed()),
        "terraform-plan.json": j(terraform_plan()),
        "queries.json": j(QUERIES),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in files().items():
        (OUT / name).write_text(text, encoding="utf-8")
        print(f"wrote examples/sample/{name}")


if __name__ == "__main__":
    main()
