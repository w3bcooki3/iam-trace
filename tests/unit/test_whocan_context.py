"""Who can and data access try the context a real request would carry.

A plain check has no region, no transport and no MFA. A region-restricting SCP then denies
everything, and the screens would say nobody can read anything. Like the escalation analysis,
a denied check is tried again with the values the conditions name: values the caller chooses
make it allowed; MFA, a network location or a time window make it allowed with "requires".
"""

from __future__ import annotations

from typing import Any

from iamtrace.data import data_access
from iamtrace.escalate import Environment
from iamtrace.model import Policy, PolicyType
from iamtrace.whocan import allowed_principals, who_can

A = "111122223333"
BUCKET = "arn:aws:s3:::data"


def doc(*st: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(st)}


def env(*statements: dict[str, Any]) -> Environment:
    return Environment.from_auth_details(
        {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [
                {
                    "RoleName": "app",
                    "Arn": f"arn:aws:iam::{A}:role/app",
                    "AssumeRolePolicyDocument": doc(),
                    "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}],
                    "AttachedManagedPolicies": [],
                }
            ],
            "Policies": [],
        }
    )


REGION_SCP = [
    [
        Policy.parse(
            doc({"Effect": "Allow", "Action": "*", "Resource": "*"}), policy_id="all", policy_type=PolicyType.SCP
        ),
        Policy.parse(
            doc(
                {
                    "Effect": "Deny",
                    "NotAction": ["iam:*", "sts:*"],
                    "Resource": "*",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-1"]}},
                }
            ),
            policy_id="regions",
            policy_type=PolicyType.SCP,
        ),
    ]
]


def test_a_region_scp_does_not_hide_access() -> None:
    e = env({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    found = allowed_principals(e, "s3:GetObject", f"{BUCKET}/x", scps=REGION_SCP)
    assert list(found) == [f"arn:aws:iam::{A}:role/app"]
    assert "requires" not in found[f"arn:aws:iam::{A}:role/app"]
    assert not allowed_principals(e, "s3:GetObject", f"{BUCKET}/x", scps=REGION_SCP, try_context=False)
    assert data_access(e, BUCKET, "read", scps=REGION_SCP)["direct"]


def test_mfa_is_reported_as_required() -> None:
    e = env(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }
    )
    r = who_can(e, "s3:GetObject", f"{BUCKET}/x")
    [d] = r["direct"]
    assert d["requires"][0]["kind"] == "mfa"


def test_a_deny_no_context_lifts_stays_denied() -> None:
    e = env(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        },
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalTag/team": "x"}},
        },
    )
    # SecureTransport=false denies, but the caller can use TLS; PrincipalTag is not set: allowed.
    assert allowed_principals(e, "s3:GetObject", f"{BUCKET}/x")
    e2 = env({"Effect": "Deny", "Action": "*", "Resource": "*"}, {"Effect": "Allow", "Action": "*", "Resource": "*"})
    assert not allowed_principals(e2, "s3:GetObject", f"{BUCKET}/x")
