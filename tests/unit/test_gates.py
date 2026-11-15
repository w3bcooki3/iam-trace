"""Condition-aware analysis: tags from the export, attacker-chosen values, and gated paths."""

from __future__ import annotations

from typing import Any

from iamtrace.escalate import Environment, analyze, escalate_text
from iamtrace.gates import find_gates, kind_of, summary

A = "111122223333"
DEV = f"arn:aws:iam::{A}:user/dev"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})


def assume(target: str, condition: dict[str, Any] | None = None, resource: str | None = None) -> dict[str, Any]:
    st: dict[str, Any] = {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": resource or arn("role", target)}
    if condition:
        st["Condition"] = condition
    return st


def user(name: str, *statements: dict[str, Any], tags: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
        "GroupList": [],
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    }


def role(name: str, *statements: dict[str, Any], tags: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": arn("role", name),
        "AssumeRolePolicyDocument": TRUST,
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
        "Tags": [{"Key": k, "Value": v} for k, v in (tags or {}).items()],
    }


ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}


def account(users: list[dict[str, Any]], roles: list[dict[str, Any]]) -> Environment:
    return Environment.from_auth_details(
        {"UserDetailList": users, "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )


def paths(env: Environment, **kw: Any) -> list[dict[str, Any]]:
    return analyze(env, start=DEV, **kw)["paths"]


# --- the gate search ----------------------------------------------------------------------------


def test_key_kinds() -> None:
    assert kind_of("aws:MultiFactorAuthPresent") == "mfa"
    assert kind_of("aws:SourceIp") == "network"
    assert kind_of("aws:RequestedRegion") == "attacker"
    assert kind_of("aws:RequestTag/team") == "attacker"
    assert kind_of("aws:PrincipalArn") is None
    assert summary([]) == "open"
    assert summary([("mfa", "aws:MultiFactorAuthPresent", "true")]) == "needs MFA"


def test_find_gates_returns_none_without_searchable_conditions() -> None:
    from iamtrace.model import Policy, PolicyType

    pol = Policy.parse(doc(assume("x")), policy_id="p", policy_type=PolicyType.IDENTITY)
    assert find_gates(lambda ctx: True, {}, [pol]) is None


# --- paths --------------------------------------------------------------------------------------


def test_mfa_gated_step_is_found_and_labelled() -> None:
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account([user("dev", assume("admin", mfa))], [role("admin", ADMIN)])
    [p] = paths(env)
    assert p["open"] is False
    assert [r["kind"] for r in p["requires"]] == ["mfa"]
    assert p["steps"][0]["requires"][0]["key"] == "aws:MultiFactorAuthPresent"


def test_without_conditions_the_gated_step_is_not_found() -> None:
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account([user("dev", assume("admin", mfa))], [role("admin", ADMIN)])
    assert paths(env, conditions=False) == []


def test_region_condition_is_open_because_the_attacker_chooses_it() -> None:
    region = {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}
    env = account([user("dev", assume("admin", region))], [role("admin", ADMIN)])
    [p] = paths(env)
    assert p["open"] is True and p["requires"] == []


def test_source_ip_condition_is_a_network_gate() -> None:
    ip = {"IpAddress": {"aws:SourceIp": "10.20.0.0/16"}}
    env = account([user("dev", assume("admin", ip))], [role("admin", ADMIN)])
    [p] = paths(env)
    [r] = p["requires"]
    assert r["kind"] == "network"
    assert r["value"].startswith("10.20.")


def test_deny_without_mfa_gates_everything() -> None:
    deny = {
        "Effect": "Deny",
        "NotAction": ["iam:ChangePassword", "sts:GetSessionToken"],
        "Resource": "*",
        "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}},
    }
    env = account([user("dev", assume("admin"), deny)], [role("admin", ADMIN)])
    [p] = paths(env)
    assert [r["kind"] for r in p["requires"]] == ["mfa"]


def test_principal_tags_come_from_the_export() -> None:
    cond = {"StringEquals": {"aws:PrincipalTag/team": "platform"}}
    tagged = account([user("dev", assume("admin", cond), tags={"team": "platform"})], [role("admin", ADMIN)])
    assert paths(tagged)[0]["open"] is True
    other = account([user("dev", assume("admin", cond), tags={"team": "sales"})], [role("admin", ADMIN)])
    assert paths(other) == []


def test_resource_tags_of_the_target_role_come_from_the_export() -> None:
    cond = {"StringEquals": {"aws:ResourceTag/tier": "dev"}}
    st = assume("", cond, resource="*")
    env = account(
        [user("dev", st)],
        [
            role(
                "sandbox",
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": arn("role", "admin")},
                tags={"tier": "dev"},
            ),
            role("admin", ADMIN, tags={"tier": "prod"}),
        ],
    )
    [p] = paths(env)
    # dev cannot assume admin directly (tier=prod); it goes through sandbox (tier=dev).
    assert [s["to"] for s in p["steps"]] == [arn("role", "sandbox"), arn("role", "admin")]


def test_an_open_path_is_preferred_over_a_shorter_gated_one() -> None:
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account(
        [user("dev", assume("admin", mfa), assume("hop"))],
        [role("hop", assume("admin")), role("admin", ADMIN)],
    )
    ps = paths(env)
    assert ps[0]["open"] is True
    assert len(ps[0]["steps"]) == 2


def test_admin_only_with_mfa_makes_the_path_gated() -> None:
    breakglass = {**ADMIN, "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    env = account([user("dev", assume("breakglass"))], [role("breakglass", breakglass)])
    report = analyze(env, start=DEV)
    bg = next(p for p in report["principals"] if p["arn"].endswith("breakglass"))
    assert bg["admin_equivalent"] and bg["admin_requires"][0]["kind"] == "mfa"
    [p] = report["paths"]
    assert p["open"] is False
    assert p["steps"][0].get("requires") is None  # the step itself is open; the admin access is not


def test_text_output_marks_gated_paths() -> None:
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account([user("dev", assume("admin", mfa))], [role("admin", ADMIN)])
    text = escalate_text(analyze(env, start=DEV))
    assert "needs MFA" in text


def test_fix_plan_leaves_gated_paths_unless_asked() -> None:
    from iamtrace.fixplan import fix_plan, fix_plan_text

    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account([user("dev", assume("admin", mfa))], [role("admin", ADMIN)])
    plan = fix_plan(env, start=DEV)
    assert plan["status"] == "nothing-to-fix"
    assert plan["gated_left"] == 1
    assert "--include-gated" in fix_plan_text(plan)
    plan = fix_plan(env, start=DEV, include_gated=True)
    assert plan["verified"] and plan["changes"][0]["actions"] == ["sts:AssumeRole"]
    assert plan["gated_left"] == 0


def test_fix_plan_cuts_the_open_path_and_reports_the_gated_one() -> None:
    from iamtrace.fixplan import fix_plan

    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    env = account(
        [user("dev", assume("breakglass", mfa), assume("hop"))],
        [role("hop", assume("admin")), role("admin", ADMIN), role("breakglass", ADMIN)],
    )
    plan = fix_plan(env, start=DEV)
    assert plan["verified"]
    # Left: dev -> breakglass, which needs MFA.
    assert plan["gated_left"] == 1
    assert all("breakglass" not in r for c in plan["changes"] for r in c["resources"])
    after = analyze(plan["_fixed_env"], start=DEV)["paths"]
    assert after and all(not p["open"] for p in after)
    assert all(p["steps"][0]["to"].endswith("breakglass") for p in after)


def test_cli_strict_context(tmp_path: Any, capsys: Any) -> None:
    import json

    from iamtrace.cli import main

    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    data = {
        "UserDetailList": [user("dev", assume("admin", mfa))],
        "GroupDetailList": [],
        "RoleDetailList": [role("admin", ADMIN)],
        "Policies": [],
    }
    f = tmp_path / "auth.json"
    f.write_text(json.dumps(data))
    main(["escalate", "--auth-details", str(f), "--principal", DEV])
    assert "needs MFA" in capsys.readouterr().out
    main(["escalate", "--auth-details", str(f), "--principal", DEV, "--strict-context"])
    assert "none found" in capsys.readouterr().out
