"""Fix plan alternatives: narrowing the statements that grant a permission, and one SCP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamtrace.catalog import default_catalog
from iamtrace.escalate import Environment, analyze
from iamtrace.fixplan import fix_plan, fix_plan_text

A = "111122223333"
DEV = f"arn:aws:iam::{A}:user/dev"
ROOT = Path(__file__).resolve().parents[2]
CAT = default_catalog()


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})
EC2_TRUST = doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def user(name: str, *statements: dict[str, Any], managed: list[str] | None = None) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [{"PolicyName": m.rsplit("/", 1)[-1], "PolicyArn": m} for m in managed or []],
        "GroupList": [],
    }


def role(name: str, trust: dict[str, Any], *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": arn("role", name),
        "AssumeRolePolicyDocument": trust,
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
    }


def managed(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "PolicyName": name,
        "Arn": arn("policy", name),
        "DefaultVersionId": "v1",
        "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": doc(*statements)}],
    }


def account(
    users: list[dict[str, Any]], roles: list[dict[str, Any]], policies: list[dict[str, Any]] | None = None
) -> Environment:
    return Environment.from_auth_details(
        {"UserDetailList": users, "GroupDetailList": [], "RoleDetailList": roles, "Policies": policies or []}
    )


def example() -> Environment:
    return Environment.from_auth_details(json.loads((ROOT / "examples/account/auth-details.json").read_text()))


def plan_for(env: Environment, start: str = DEV) -> dict[str, Any]:
    return fix_plan(env, start=start, catalog=CAT)


# --- narrowed Allow statements ----------------------------------------------------------------


def test_example_splits_the_statement_and_lists_the_other_roles() -> None:
    plan = plan_for(example())
    n = plan["narrowed"]
    assert n["complete"] and n["verified"]
    [edit] = n["edits"]
    assert edit["policy"].endswith("role/ops inline deploy")
    assert edit["kind"] == "inline"
    assert edit["affects"] == [arn("role", "ops")]
    sts = edit["document"]["Statement"]
    run = next(s for s in sts if s["Action"] == "ec2:RunInstances")
    assert run["Resource"] == "*"
    passrole = next(s for s in sts if s["Action"] == "iam:PassRole")
    assert arn("role", "ec2-admin") not in passrole["Resource"]
    # Admin roles are not offered either: passing one would open the same kind of path.
    assert arn("role", "break-glass") not in passrole["Resource"]
    assert arn("role", "report-runner") in passrole["Resource"]
    assert any("created later" in x for x in edit["also_removes"])


def test_exact_arn_is_simply_removed() -> None:
    env = account(
        [
            user(
                "dev",
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [arn("role", "admin"), arn("role", "app")]},
            )
        ],
        [role("admin", TRUST, ADMIN), role("app", TRUST)],
    )
    n = plan_for(env)["narrowed"]
    assert n["verified"]
    [st] = n["edits"][0]["document"]["Statement"]
    assert st["Resource"] == arn("role", "app")
    assert n["edits"][0]["also_removes"] == []


def test_action_denied_everywhere_is_removed_from_the_list() -> None:
    admin = role("admin", EC2_TRUST, ADMIN)
    env = account(
        [
            user(
                "dev",
                {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": arn("role", "admin")},
                {"Effect": "Allow", "Action": ["ec2:RunInstances", "s3:GetObject"], "Resource": "*"},
            )
        ],
        [admin],
    )
    plan = fix_plan(env, start=DEV, catalog=CAT)
    n = plan["narrowed"]
    assert n["verified"]
    # The cheapest Deny is iam:PassRole on the admin role: that statement then grants nothing.
    sts = n["edits"][0]["document"]["Statement"]
    assert all("iam:PassRole" not in json.dumps(s) for s in sts)
    assert any(s["Action"] == ["ec2:RunInstances", "s3:GetObject"] for s in sts)


def test_small_wildcard_is_expanded_without_the_action() -> None:
    env = account([user("dev", {"Effect": "Allow", "Action": "iam:Put*Policy", "Resource": DEV})], [])
    n = plan_for(env)["narrowed"]
    assert n["verified"]
    acts = n["edits"][0]["document"]["Statement"][0]["Action"]
    assert "iam:PutUserPolicy" not in acts
    assert "iam:PutRolePolicy" in acts


def test_large_wildcard_cannot_be_narrowed_readably() -> None:
    env = account([user("dev", {"Effect": "Allow", "Action": "iam:*", "Resource": DEV})], [])
    plan = plan_for(env)
    n = plan["narrowed"]
    assert not n["complete"]
    assert "actions" in n["problems"][0]
    assert plan["verified"]  # the Deny plan still stands


def test_shared_managed_policy_names_everyone_it_affects() -> None:
    pol = managed(
        "deployers",
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": [arn("role", "admin"), arn("role", "app")]},
    )
    env = account(
        [user("dev", managed=[pol["Arn"]]), user("ci", managed=[pol["Arn"]])],
        [role("admin", TRUST, ADMIN), role("app", TRUST)],
        [pol],
    )
    n = plan_for(env)["narrowed"]
    edit = n["edits"][0]
    assert edit["kind"] == "managed"
    assert sorted(edit["affects"]) == [arn("user", "ci"), DEV]


def test_narrowed_plan_is_proven_by_analysis() -> None:
    env = example()
    plan = plan_for(env)
    fixed = plan["narrowed"]["_fixed_env"]
    assert not any(p["open"] for p in analyze(fixed, start=DEV)["paths"])


# --- SCP ---------------------------------------------------------------------------------------


def test_scp_version_is_one_verified_policy() -> None:
    plan = plan_for(example())
    scp = plan["scp"]
    assert scp["verified"]
    [st] = scp["policy"]["Statement"]
    assert st["Effect"] == "Deny" and st["Action"] == "iam:PassRole"
    assert st["Condition"]["ArnEquals"]["aws:PrincipalArn"] == arn("role", "ops")
    assert scp["size"] < 5120
    assert any("management account" in note for note in scp["notes"])


def test_text_shows_the_alternatives() -> None:
    text = fix_plan_text(plan_for(example()))
    assert "Instead of the Deny" in text
    assert "As one SCP" in text


def test_a_policy_left_with_nothing_is_deleted() -> None:
    env = account([user("dev", {"Effect": "Allow", "Action": "iam:PutUserPolicy", "Resource": DEV})], [])
    n = plan_for(env)["narrowed"]
    assert n["verified"]
    [edit] = n["edits"]
    assert edit["delete"] is True and edit["document"] is None
    assert "Delete" in fix_plan_text(plan_for(env))
