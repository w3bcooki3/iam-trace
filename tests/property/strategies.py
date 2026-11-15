"""Hypothesis strategies: random policies, requests and small accounts.

The vocabulary is small on purpose. With a few principals, a few dozen actions and a handful of
resources, random accounts often contain escalation paths, Denies that matter and conditions
that decide, which is where bugs hide.
"""

from __future__ import annotations

import os
from typing import Any

from hypothesis import settings
from hypothesis import strategies as st


def examples(normal: int, deep: int) -> settings:
    """Fewer examples for slow tests in normal runs; many more with HYPOTHESIS_PROFILE=deep."""
    return settings(max_examples=deep if os.environ.get("HYPOTHESIS_PROFILE") == "deep" else normal)


A = "111122223333"
OTHER = "444455556666"

USERS = ["u0", "u1", "u2"]
ROLES = ["r0", "r1", "r2", "r3"]
GROUPS = ["g0", "g1"]
MANAGED = ["m0", "m1"]


def arn(kind: str, name: str, account: str = A) -> str:
    return f"arn:aws:iam::{account}:{kind}/{name}"


ACTIONS = [
    "iam:PassRole",
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "sts:AssumeRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreatePolicyVersion",
    "iam:AddUserToGroup",
    "iam:PutGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
    "s3:GetObject",
    "s3:PutObject",
    "kms:Decrypt",
]
PATTERNS = ["*", "iam:*", "ec2:*", "lambda:*", "s3:*", "iam:Put*", "iam:*AccessKey*", "sts:*"]
# Actions requests can use: the vocabulary plus some outside any pattern but "*".
REQUEST_ACTIONS = [*ACTIONS, "dynamodb:GetItem", "sqs:SendMessage", "iam:ListUsers"]

RESOURCES = [
    "*",
    *(arn("user", u) for u in USERS),
    *(arn("role", r) for r in ROLES),
    *(arn("group", g) for g in GROUPS),
    *(arn("policy", m) for m in MANAGED),
    arn("role", "*"),
    arn("user", "u*"),
    "arn:aws:s3:::bucket/*",
    "arn:aws:s3:::bucket/reports/*",
]
REQUEST_RESOURCES = [r for r in RESOURCES if "*" not in r] + [
    "arn:aws:s3:::bucket/reports/a.csv",
    "arn:aws:s3:::bucket/other.txt",
    f"arn:aws:kms:us-east-1:{A}:key/k1",
]

CONDITIONS: list[dict[str, Any]] = [
    {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    {"StringEquals": {"aws:RequestedRegion": ["eu-west-1", "us-east-1"]}},
    {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
    {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    {"StringEquals": {"aws:PrincipalTag/team": "ops"}},
    {"StringLike": {"aws:PrincipalArn": f"arn:aws:iam::{A}:role/r*"}},
]


def one_or_list(values: list[str]) -> Any:
    return values[0] if len(values) == 1 else values


@st.composite
def statements(draw: st.DrawFn, *, effect: str | None = None, conditions: bool = True) -> dict[str, Any]:
    eff = effect or draw(st.sampled_from(["Allow", "Allow", "Allow", "Deny"]))
    acts = draw(st.lists(st.sampled_from(ACTIONS + PATTERNS), min_size=1, max_size=3, unique=True))
    res = draw(st.lists(st.sampled_from(RESOURCES), min_size=1, max_size=2, unique=True))
    s: dict[str, Any] = {"Effect": eff}
    if draw(st.integers(0, 9)) == 0:
        s["NotAction"] = one_or_list(acts)
    else:
        s["Action"] = one_or_list(acts)
    if draw(st.integers(0, 14)) == 0:
        s["NotResource"] = one_or_list(res)
    else:
        s["Resource"] = one_or_list(res)
    if conditions and draw(st.integers(0, 4)) == 0:
        s["Condition"] = draw(st.sampled_from(CONDITIONS))
    return s


def document(sts: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": sts}


@st.composite
def policies(draw: st.DrawFn, *, min_size: int = 1, max_size: int = 4, conditions: bool = True) -> dict[str, Any]:
    return document(draw(st.lists(statements(conditions=conditions), min_size=min_size, max_size=max_size)))


@st.composite
def requests_ctx(draw: st.DrawFn) -> dict[str, Any]:
    ctx: dict[str, Any] = {}
    if draw(st.booleans()):
        ctx["aws:MultiFactorAuthPresent"] = draw(st.sampled_from(["true", "false"]))
    if draw(st.booleans()):
        ctx["aws:RequestedRegion"] = draw(st.sampled_from(["us-east-1", "eu-west-1", "ap-south-1"]))
    if draw(st.booleans()):
        ctx["aws:SourceIp"] = draw(st.sampled_from(["10.1.2.3", "192.0.2.10"]))
    return ctx


@st.composite
def trust_policies(draw: st.DrawFn) -> dict[str, Any]:
    principals: dict[str, Any] = {}
    kind = draw(st.integers(0, 5))
    if kind <= 1:
        principals["AWS"] = f"arn:aws:iam::{A}:root"
    elif kind == 2:
        principals["AWS"] = arn("user", draw(st.sampled_from(USERS)))
    elif kind == 3:
        principals["AWS"] = f"arn:aws:iam::{OTHER}:root"
    if kind >= 3 or draw(st.booleans()):
        principals["Service"] = draw(st.sampled_from(["ec2.amazonaws.com", "lambda.amazonaws.com"]))
    s: dict[str, Any] = {"Effect": "Allow", "Principal": principals, "Action": "sts:AssumeRole"}
    if draw(st.integers(0, 5)) == 0:
        s["Condition"] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    return document([s])


@st.composite
def accounts(draw: st.DrawFn) -> dict[str, Any]:
    """An account export: a few users, roles, groups and customer managed policies.

    One role is often an admin, so paths to admin are common."""
    managed = [
        {
            "PolicyName": m,
            "Arn": arn("policy", m),
            "DefaultVersionId": "v1",
            "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": draw(policies())}],
        }
        for m in MANAGED
    ]

    def attached() -> list[dict[str, str]]:
        names = draw(st.lists(st.sampled_from(MANAGED), max_size=1, unique=True))
        return [{"PolicyName": m, "PolicyArn": arn("policy", m)} for m in names]

    def inline() -> list[dict[str, Any]]:
        return [{"PolicyName": "p", "PolicyDocument": draw(policies())}] if draw(st.integers(0, 4)) else []

    groups = [
        {"GroupName": g, "Arn": arn("group", g), "GroupPolicyList": inline(), "AttachedManagedPolicies": attached()}
        for g in GROUPS
    ]
    users = [
        {
            "UserName": u,
            "Arn": arn("user", u),
            "UserPolicyList": inline(),
            "AttachedManagedPolicies": attached(),
            "GroupList": draw(st.lists(st.sampled_from(GROUPS), max_size=2, unique=True)),
            **({"Tags": [{"Key": "team", "Value": "ops"}]} if draw(st.integers(0, 3)) == 0 else {}),
        }
        for u in USERS
    ]
    admin = draw(st.sampled_from([*ROLES, None]))
    roles = []
    for r in ROLES:
        pols = inline()
        if r == admin:
            pols = [
                {
                    "PolicyName": "admin",
                    "PolicyDocument": document([{"Effect": "Allow", "Action": "*", "Resource": "*"}]),
                }
            ]
        roles.append(
            {
                "RoleName": r,
                "Arn": arn("role", r),
                "AssumeRolePolicyDocument": draw(trust_policies()),
                "RolePolicyList": pols,
                "AttachedManagedPolicies": [] if r == admin else attached(),
            }
        )
    return {"UserDetailList": users, "RoleDetailList": roles, "GroupDetailList": groups, "Policies": managed}


PRINCIPAL_ARNS = [arn("user", u) for u in USERS] + [arn("role", r) for r in ROLES]
