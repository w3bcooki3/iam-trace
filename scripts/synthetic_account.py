"""Write a large made-up account export, for measuring speed.

    python3 scripts/synthetic_account.py 200 > /tmp/account-200.json   # 200 users and 200 roles

The account is random but repeatable (a fixed seed per size). It mixes what real accounts have:
users in groups, customer managed policies shared between principals, roles that trust the
account, services or other roles, a few admins, MFA and network conditions, PassRole to services,
and Deny statements. Nothing in it is real.
"""

from __future__ import annotations

import json
import random
import sys
from typing import Any

A = "111122223333"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


SERVICES = ["ec2", "lambda", "s3", "dynamodb", "sqs", "sns", "logs", "cloudwatch", "kms", "secretsmanager", "ecr"]
SERVICE_PRINCIPALS = ["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "glue.amazonaws.com"]
MFA = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
NETWORK = {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}}


def build(n: int) -> dict[str, Any]:
    rnd = random.Random(n)
    roles = [f"role-{i}" for i in range(n)]
    users = [f"user-{i}" for i in range(n)]
    groups = [f"group-{i}" for i in range(max(4, n // 20))]
    managed = [f"policy-{i}" for i in range(max(6, n // 10))]
    admins = set(rnd.sample(roles, max(2, n // 60)))

    def work() -> dict[str, Any]:
        svc = rnd.sample(SERVICES, rnd.randint(1, 3))
        acts = [f"{s}:{rnd.choice(['Get*', 'List*', 'Describe*', 'Put*', '*'])}" for s in svc]
        st: dict[str, Any] = {"Effect": "Allow", "Action": acts, "Resource": "*"}
        if rnd.random() < 0.1:
            st["Condition"] = rnd.choice([MFA, NETWORK])
        return st

    def risky() -> dict[str, Any]:
        kind = rnd.random()
        if kind < 0.35:
            return {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": [arn("role", r) for r in rnd.sample(roles, 2)],
            }
        if kind < 0.55:
            return {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": arn("role", rnd.choice(roles))}
        if kind < 0.7:
            return {
                "Effect": "Allow",
                "Action": ["ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction"],
                "Resource": "*",
            }
        if kind < 0.8:
            return {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": arn("user", rnd.choice(users))}
        if kind < 0.9:
            return {
                "Effect": "Allow",
                "Action": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
                "Resource": arn("role", rnd.choice(roles)),
            }
        return {"Effect": "Allow", "Action": "iam:AddUserToGroup", "Resource": arn("group", rnd.choice(groups))}

    def statements() -> list[dict[str, Any]]:
        sts = [work() for _ in range(rnd.randint(1, 3))]
        if rnd.random() < 0.3:
            sts.append(risky())
        if rnd.random() < 0.08:
            sts.append(
                {
                    "Effect": "Deny",
                    "Action": "iam:*",
                    "Resource": "*",
                    "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
                }
            )
        return sts

    def attach() -> list[dict[str, str]]:
        return [{"PolicyName": m, "PolicyArn": arn("policy", m)} for m in rnd.sample(managed, rnd.randint(0, 2))]

    def trust() -> dict[str, Any]:
        k = rnd.random()
        if k < 0.4:
            p: dict[str, Any] = {"Service": rnd.choice(SERVICE_PRINCIPALS)}
        elif k < 0.8:
            p = {"AWS": f"arn:aws:iam::{A}:root"}
        else:
            p = {"AWS": [arn("role", r) for r in rnd.sample(roles, 2)]}
        st: dict[str, Any] = {"Effect": "Allow", "Principal": p, "Action": "sts:AssumeRole"}
        if "AWS" in p and rnd.random() < 0.2:
            st["Condition"] = MFA
        return doc(st)

    group_admin = groups[0]
    return {
        "UserDetailList": [
            {
                "UserName": u,
                "Arn": arn("user", u),
                "UserPolicyList": [{"PolicyName": "own", "PolicyDocument": doc(*statements())}]
                if rnd.random() < 0.6
                else [],
                "AttachedManagedPolicies": attach(),
                "GroupList": rnd.sample(groups, rnd.randint(0, 2)),
            }
            for u in users
        ],
        "GroupDetailList": [
            {
                "GroupName": g,
                "Arn": arn("group", g),
                "GroupPolicyList": [
                    {
                        "PolicyName": "group",
                        "PolicyDocument": doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
                        if g == group_admin
                        else doc(*statements()),
                    }
                ],
                "AttachedManagedPolicies": attach(),
            }
            for g in groups
        ],
        "RoleDetailList": [
            {
                "RoleName": r,
                "Arn": arn("role", r),
                "AssumeRolePolicyDocument": trust(),
                "RolePolicyList": [
                    {
                        "PolicyName": "own",
                        "PolicyDocument": doc({"Effect": "Allow", "Action": "*", "Resource": "*"})
                        if r in admins
                        else doc(*statements()),
                    }
                ],
                "AttachedManagedPolicies": [] if r in admins else attach(),
            }
            for r in roles
        ],
        "Policies": [
            {
                "PolicyName": m,
                "Arn": arn("policy", m),
                "DefaultVersionId": "v1",
                "AttachmentCount": 1,
                "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": doc(*statements())}],
            }
            for m in managed
        ],
    }


if __name__ == "__main__":
    json.dump(build(int(sys.argv[1]) if len(sys.argv) > 1 else 200), sys.stdout)
