"""Fix plan: the smallest set of denials that cuts every path to admin, proven by analysing again."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.escalate import Environment, analyze
from iamtrace.fixplan import fix_plan, fix_plan_text, min_hitting_set

A = "111122223333"
DEV = f"arn:aws:iam::{A}:user/dev"
ROOT = Path(__file__).resolve().parents[2]


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: str | list[str], resource: str | list[str] = "*") -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


TRUST_ACCOUNT = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})


def trust_service(service: str) -> dict[str, Any]:
    return doc({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})


def user(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
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


def account(users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> Environment:
    return Environment.from_auth_details(
        {"UserDetailList": users, "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )


ADMIN_ROLE = role("admin", TRUST_ACCOUNT, allow("*"))


def example() -> Environment:
    return Environment.from_auth_details(json.loads((ROOT / "examples/account/auth-details.json").read_text()))


def still_reaches_admin(env: Environment, start: str | None) -> bool:
    return bool(analyze(env, start=start)["paths"])


# --- the solver ----------------------------------------------------------------------------------


def test_hitting_set_is_exact_where_greedy_is_not() -> None:
    # Greedy takes "x" first (it hits three sets) and then needs two more: cost 3.
    # The optimum is {"a", "b"}: cost 2.
    sets = [frozenset(s) for s in (["a", "x"], ["a", "x"], ["b", "x"], ["a", "c"], ["b", "d"])]
    chosen, optimal = min_hitting_set(sets, {k: 1.0 for k in "abcdx"})
    assert optimal
    assert chosen == {"a", "b"}


def test_hitting_set_respects_costs() -> None:
    sets = [frozenset({"cheap1", "dear"}), frozenset({"cheap2", "dear"})]
    chosen, _ = min_hitting_set(sets, {"cheap1": 1.0, "cheap2": 1.0, "dear": 3.0})
    assert chosen == {"cheap1", "cheap2"}
    chosen, _ = min_hitting_set(sets, {"cheap1": 2.0, "cheap2": 2.0, "dear": 3.0})
    assert chosen == {"dear"}


def test_hitting_set_with_no_option_is_reported() -> None:
    with pytest.raises(ValueError):
        min_hitting_set([frozenset()], {})


# --- plans -----------------------------------------------------------------------------------------


def test_example_account_is_fixed_and_proven() -> None:
    env = example()
    plan = fix_plan(env, start=DEV)
    assert plan["status"] == "fixed"
    assert plan["verified"] is True
    assert plan["optimal"] is True
    assert plan["paths_before"] >= 1 and plan["paths_after"] == 0
    assert len(plan["changes"]) == 1
    change = plan["changes"][0]
    assert change["effect"] == "Deny"
    assert change["scope"] == "targeted"
    # Equal cost cuts: the one nearer admin also fixes role/ops, so it is preferred.
    assert change["principal"] == arn("role", "ops")
    assert change["actions"] == ["iam:PassRole"]
    assert change["resources"] == [arn("role", "ec2-admin")]
    assert arn("role", "ops") in plan["also_fixed"]
    # The original environment is untouched.
    assert still_reaches_admin(env, DEV)


def test_policies_are_valid_deny_documents_and_apply() -> None:
    env = example()
    plan = fix_plan(env, start=DEV)
    for principal, policy in plan["policies"].items():
        assert principal in env.nodes
        assert policy["Version"] == "2012-10-17"
        for st in policy["Statement"]:
            assert st["Effect"] == "Deny"
            assert st["Action"] and st["Resource"]


def test_two_separate_routes_both_get_cut() -> None:
    env = account(
        [user("dev", allow("sts:AssumeRole", [arn("role", "a"), arn("role", "b")]))],
        [
            role("a", TRUST_ACCOUNT, allow("sts:AssumeRole", arn("role", "admin"))),
            role("b", TRUST_ACCOUNT, allow("sts:AssumeRole", arn("role", "admin"))),
            ADMIN_ROLE,
        ],
    )
    plan = fix_plan(env, start=DEV)
    # Cutting only dev -> a would leave dev -> b -> admin: the plan must cover both routes, with
    # two targeted denials (cheaper than denying sts:AssumeRole everywhere).
    assert plan["verified"]
    assert plan["paths_after"] == 0
    assert len(plan["changes"]) == 2
    assert all(c["scope"] == "targeted" for c in plan["changes"])
    assert not still_reaches_admin(plan["_fixed_env"], DEV)


def test_one_permission_breaking_several_techniques_is_one_change() -> None:
    # dev can pass the admin role to EC2 and to Lambda: both techniques need iam:PassRole on it.
    admin = role(
        "admin",
        doc(
            {
                "Effect": "Allow",
                "Principal": {"Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ),
        allow("*"),
    )
    env = account(
        [
            user(
                "dev",
                allow("iam:PassRole", arn("role", "admin")),
                allow(["ec2:RunInstances", "lambda:CreateFunction", "lambda:InvokeFunction"]),
            )
        ],
        [admin],
    )
    report = analyze(env, start=DEV)
    techniques = {t["id"] for t in report["principals"][0]["techniques"] if t["confidence"] == "confirmed"}
    assert len([t for t in techniques if t.startswith(("ec2-", "lambda-"))]) >= 2
    plan = fix_plan(env, start=DEV)
    assert plan["verified"]
    assert len(plan["changes"]) == 1
    assert plan["changes"][0]["actions"] == ["iam:PassRole"]
    assert len(plan["changes"][0]["breaks"]) >= 2


def test_self_escalation_is_cut_on_the_principal_itself() -> None:
    env = account([user("dev", allow("iam:PutUserPolicy", DEV))], [])
    plan = fix_plan(env, start=DEV)
    assert plan["status"] == "fixed"
    assert plan["verified"]
    change = plan["changes"][0]
    assert change["actions"] == ["iam:PutUserPolicy"]
    assert change["resources"] == [DEV]
    assert not analyze(plan["_fixed_env"], start=DEV)["principals"][0]["admin_equivalent"]


def test_start_that_is_already_admin_has_no_plan() -> None:
    env = account([user("dev", allow("*"))], [])
    plan = fix_plan(env, start=DEV)
    assert plan["status"] == "start-is-admin"
    assert plan["changes"] == []


def test_nothing_to_fix() -> None:
    env = account([user("dev", allow("s3:GetObject"))], [ADMIN_ROLE])
    plan = fix_plan(env, start=DEV)
    assert plan["status"] == "nothing-to-fix"
    assert plan["changes"] == []
    assert plan["verified"] is True


def test_whole_account_mode_fixes_every_starting_principal() -> None:
    env = example()
    plan = fix_plan(env)
    assert plan["status"] == "fixed"
    assert plan["verified"]
    fixed = plan["_fixed_env"]
    report = analyze(fixed)
    # Nobody has an open path left; the break-glass path that needs MFA is kept on purpose.
    assert not any(p["open"] for p in report["paths"])
    assert all(p["end"].endswith("break-glass") for p in report["paths"])


def test_granted_by_names_the_statement() -> None:
    env = example()
    plan = fix_plan(env, start=DEV)
    granted = plan["changes"][0]["granted_by"]
    assert granted, "the statement that allows the permission should be named"
    assert all("policy" in g and "statement" in g for g in granted)
    assert any("ops" in g["policy"] for g in granted)


def test_text_output() -> None:
    plan = fix_plan(example(), start=DEV)
    text = fix_plan_text(plan)
    assert "Verified" in text
    assert "iam:PassRole" in text
    assert '"Effect": "Deny"' in text


def test_prefers_targeted_denials_over_denying_everywhere() -> None:
    # dev can launch EC2 instances and pass one role. Denying ec2:RunInstances everywhere would
    # also work, but denying iam:PassRole on that role alone breaks less.
    admin = role("admin", trust_service("ec2.amazonaws.com"), allow("*"))
    env = account([user("dev", allow("iam:PassRole", arn("role", "admin")), allow("ec2:RunInstances"))], [admin])
    plan = fix_plan(env, start=DEV)
    assert plan["verified"]
    assert [c["actions"] for c in plan["changes"]] == [["iam:PassRole"]]
    assert plan["changes"][0]["scope"] == "targeted"


# --- command line ------------------------------------------------------------------------------


def test_cli_fix_writes_policies(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    code = main(
        [
            "fix",
            "--auth-details",
            str(ROOT / "examples/account/auth-details.json"),
            "--principal",
            DEV,
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith("Verified")
    files = list(tmp_path.glob("*.iam-trace-fix.json"))
    assert [f.name for f in files] == ["role-ops.iam-trace-fix.json"]
    assert (tmp_path / "role-ops-inline-deploy.narrowed.json").exists()
    assert json.loads((tmp_path / "iam-trace-fix.scp.json").read_text())["Statement"][0]["Effect"] == "Deny"
    assert json.loads(files[0].read_text())["Statement"][0]["Effect"] == "Deny"


def test_cli_fix_json(capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    assert main(["fix", "--auth-details", str(ROOT / "examples/account/auth-details.json"), "--format", "json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["verified"] is True
    assert not any(k.startswith("_") for k in plan)


def test_cli_fix_unknown_principal(capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    code = main(
        [
            "fix",
            "--auth-details",
            str(ROOT / "examples/account/auth-details.json"),
            "--principal",
            "arn:aws:iam::1:user/x",
        ]
    )
    assert code != 0
    assert "not in the account export" in capsys.readouterr().err
