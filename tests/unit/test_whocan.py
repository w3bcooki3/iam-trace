"""Who can: direct access, access through escalation, and principals outside the export."""

from __future__ import annotations

import json
from typing import Any

from iamtrace.escalate import Environment
from iamtrace.model import Policy, PolicyType
from iamtrace.whocan import who_can, who_can_text

A = "111122223333"
DEV = f"arn:aws:iam::{A}:user/dev"
OPS = f"arn:aws:iam::{A}:role/ops"
ADMIN = f"arn:aws:iam::{A}:role/admin"
INTERN = f"arn:aws:iam::{A}:user/intern"
OBJ = "arn:aws:s3:::reports/q3.csv"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def trust_account() -> dict[str, Any]:
    return doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})


def env() -> Environment:
    return Environment.from_auth_details(
        {
            "UserDetailList": [
                {
                    "UserName": "dev",
                    "Arn": DEV,
                    "UserPolicyList": [
                        {
                            "PolicyName": "assume",
                            "PolicyDocument": doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": OPS}),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                    "GroupList": [],
                },
                {
                    "UserName": "intern",
                    "Arn": INTERN,
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": [],
                    "GroupList": [],
                },
            ],
            "GroupDetailList": [],
            "RoleDetailList": [
                {
                    "RoleName": "ops",
                    "Arn": OPS,
                    "AssumeRolePolicyDocument": trust_account(),
                    "RolePolicyList": [
                        {
                            "PolicyName": "read",
                            "PolicyDocument": doc(
                                {
                                    "Sid": "Read",
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": "arn:aws:s3:::reports/*",
                                }
                            ),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
                {
                    "RoleName": "admin",
                    "Arn": ADMIN,
                    "AssumeRolePolicyDocument": doc(
                        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ),
                    "RolePolicyList": [
                        {
                            "PolicyName": "all",
                            "PolicyDocument": doc({"Effect": "Allow", "Action": "*", "Resource": "*"}),
                        }
                    ],
                    "AttachedManagedPolicies": [],
                },
            ],
            "Policies": [],
        }
    )


def test_direct_and_through_escalation() -> None:
    r = who_can(env(), "s3:GetObject", OBJ)
    assert [d["principal"] for d in r["direct"]] == [ADMIN, OPS]
    ops = next(d for d in r["direct"] if d["principal"] == OPS)
    assert ops["granted_by"] == [f"{OPS} inline read / Read"]
    (dev,) = r["via"]
    assert dev["principal"] == DEV and dev["through"] == OPS
    assert [s["technique"] for s in dev["steps"]] == ["sts-001"]
    assert r["cannot"] == 1  # the intern


def test_scp_takes_access_away() -> None:
    scp = Policy.from_json(
        json.dumps(
            doc(
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Deny", "Action": "s3:*", "Resource": "*"},
            )
        ),
        policy_id="scp",
        policy_type=PolicyType.SCP,
    )
    r = who_can(env(), "s3:GetObject", OBJ, scps=[[scp]])
    assert r["direct"] == [] and r["via"] == []


def test_resource_policy_grants_and_outsiders() -> None:
    bucket = Policy.from_json(
        json.dumps(
            doc(
                {
                    "Sid": "Intern",
                    "Effect": "Allow",
                    "Principal": {"AWS": INTERN},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::reports/*",
                },
                {
                    "Sid": "Partner",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::reports/*",
                },
                {
                    "Sid": "Public",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::reports/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
                },
            )
        ),
        policy_id="bucket",
        policy_type=PolicyType.RESOURCE,
    )
    r = who_can(env(), "s3:GetObject", OBJ, resource_policy=bucket)
    intern = next(d for d in r["direct"] if d["principal"] == INTERN)
    assert intern["granted_by"] == ["bucket / Intern"]
    outside = {o["principal"]: o for o in r["outside"]}
    assert set(outside) == {"arn:aws:iam::444455556666:root", "*"}
    assert outside["*"]["what"] == "anyone (public)" and outside["*"]["conditional"]


def test_text() -> None:
    text = who_can_text(who_can(env(), "s3:GetObject", OBJ))
    assert "Checked 4 principals: 2 directly, 1 through escalation, 1 cannot." in text
    assert f"{DEV} -> [sts-001] {OPS}" in text


def test_cli_and_web(tmp_path: Any, capsys: Any) -> None:
    from iamtrace import web_api
    from iamtrace.cli import main

    data = {
        "UserDetailList": [
            {
                "UserName": "dev",
                "Arn": DEV,
                "UserPolicyList": [
                    {
                        "PolicyName": "read",
                        "PolicyDocument": doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}),
                    }
                ],
                "AttachedManagedPolicies": [],
                "GroupList": [],
            }
        ],
        "RoleDetailList": [],
        "GroupDetailList": [],
        "Policies": [],
    }
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps(data))
    assert main(["who-can", "--auth-details", str(auth), "--action", "s3:GetObject", "--resource", OBJ]) == 0
    assert "Checked 1 principals: 1 directly" in capsys.readouterr().out
    out = json.loads(web_api.who_can_query(json.dumps(data), "s3:GetObject", OBJ))
    assert [d["principal"] for d in out["result"]["direct"]] == [DEV]
    assert "error" in json.loads(web_api.who_can_query(json.dumps(data), " ", OBJ))
