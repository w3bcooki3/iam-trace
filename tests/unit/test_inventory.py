"""Resource inventory: existing Lambda functions, EC2 instances, ... and the roles they run as turn
"possible" existing-resource techniques into confirmed findings, or rule them out."""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.escalate import Environment, analyze
from iamtrace.inventory import KINDS, TECHNIQUE_KIND, load_inventory
from iamtrace.model import PolicyError

ACCT = "111122223333"
DEV = f"arn:aws:iam::{ACCT}:user/dev"
BILLING_ROLE = f"arn:aws:iam::{ACCT}:role/billing-admin"
REPORTS_ROLE = f"arn:aws:iam::{ACCT}:role/reports"
WEB_ROLE = f"arn:aws:iam::{ACCT}:role/web"
BILLING_FN = f"arn:aws:lambda:us-east-1:{ACCT}:function:billing"
REPORTS_FN = f"arn:aws:lambda:us-east-1:{ACCT}:function:reports"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-0abc"
WEB_PROFILE = f"arn:aws:iam::{ACCT}:instance-profile/web"


def _trust(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
    }


def _role(name: str, service: str, actions: str, profile: str | None = None) -> dict[str, Any]:
    r: dict[str, Any] = {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "AssumeRolePolicyDocument": _trust(service),
        "RolePolicyList": [
            {
                "PolicyName": "p",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
                },
            }
        ],
        "AttachedManagedPolicies": [],
    }
    if profile:
        r["InstanceProfileList"] = [{"InstanceProfileName": name, "Arn": profile}]
    return r


def export(dev_statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "UserDetailList": [
            {
                "UserName": "dev",
                "Arn": DEV,
                "UserPolicyList": [
                    {"PolicyName": "dev", "PolicyDocument": {"Version": "2012-10-17", "Statement": dev_statements}}
                ],
                "AttachedManagedPolicies": [],
                "GroupList": [],
            }
        ],
        "GroupDetailList": [],
        "RoleDetailList": [
            _role("billing-admin", "lambda.amazonaws.com", "*"),
            _role("reports", "lambda.amazonaws.com", "s3:GetObject"),
            _role("web", "ec2.amazonaws.com", "dynamodb:GetItem", WEB_PROFILE),
        ],
        "Policies": [],
    }


UPDATE_CODE = {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"}

INVENTORY = {
    "Version": 1,
    "Collected": ["lambda-function", "ec2-instance"],
    "Resources": [
        {"Arn": BILLING_FN, "Role": BILLING_ROLE},
        {"Arn": REPORTS_FN, "Role": REPORTS_ROLE},
        {"Arn": INSTANCE, "Role": WEB_PROFILE},
    ],
}


def techniques(report: dict[str, Any], arn: str = DEV) -> dict[str, dict[str, Any]]:
    p = next(p for p in report["principals"] if p["arn"] == arn)
    return {t["id"]: t for t in p["techniques"]}


def run(dev_statements: list[dict[str, Any]], inventory: dict[str, Any] | None) -> dict[str, Any]:
    env = Environment.from_auth_details(export(dev_statements))
    if inventory is not None:
        env.resources = load_inventory(inventory, env)
    return analyze(env, start=DEV)


# --- the mapping itself ---------------------------------------------------------------------


def test_every_mapped_technique_exists_and_every_kind_is_described() -> None:
    from iamtrace.escalate import technique_catalog

    ids = {t["id"]: t for t in technique_catalog()}
    for tid, kind in TECHNIQUE_KIND.items():
        assert tid in ids, tid
        # Existing-resource techniques, and new-passrole ones that pass no role (a change set on
        # a stack that already has a service role).
        no_passrole = all(p.lower() != "iam:passrole" for p in ids[tid]["permissions"])
        assert ids[tid]["category"] == "existing-passrole" or no_passrole, tid
        assert kind in KINDS, kind


# --- analysis -------------------------------------------------------------------------------


def test_without_inventory_existing_function_technique_is_possible() -> None:
    t = techniques(run([UPDATE_CODE], None))
    assert t["lambda-003"]["confidence"] == "possible"


def test_inventory_confirms_and_names_the_function_and_role() -> None:
    report = run([UPDATE_CODE], INVENTORY)
    t = techniques(report)["lambda-003"]
    assert t["confidence"] == "confirmed"
    assert t["targets"] == [BILLING_ROLE, REPORTS_ROLE]
    assert t["via"] == [BILLING_FN, REPORTS_FN]
    # billing-admin is admin, so dev now has a confirmed path to admin.
    assert [p["steps"][-1]["to"] for p in report["paths"]] == [BILLING_ROLE]


def test_resource_scoped_permission_reaches_only_that_function() -> None:
    stmt = {"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": REPORTS_FN}
    t = techniques(run([stmt], INVENTORY))["lambda-003"]
    assert t["targets"] == [REPORTS_ROLE]
    assert t["via"] == [REPORTS_FN]


def test_explicit_deny_on_a_function_is_respected() -> None:
    deny = {"Effect": "Deny", "Action": "lambda:*", "Resource": BILLING_FN}
    report = run([UPDATE_CODE, deny], INVENTORY)
    assert techniques(report)["lambda-003"]["targets"] == [REPORTS_ROLE]
    assert report["paths"] == []


def test_collected_kind_with_no_reachable_resource_rules_the_technique_out() -> None:
    inv = {**INVENTORY, "Resources": [{"Arn": INSTANCE, "Role": WEB_PROFILE}]}
    assert "lambda-003" not in techniques(run([UPDATE_CODE], inv))


def test_kind_not_collected_stays_possible() -> None:
    inv = {"Version": 1, "Collected": ["ec2-instance"], "Resources": []}
    assert techniques(run([UPDATE_CODE], inv))["lambda-003"]["confidence"] == "possible"


def test_instance_profile_resolves_to_its_role() -> None:
    stmt = {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": "*"}
    t = techniques(run([stmt], INVENTORY))["ssm-002"]
    assert t["confidence"] == "confirmed"
    assert t["targets"] == [WEB_ROLE]
    assert t["via"] == [INSTANCE]


def test_role_outside_the_export_is_confirmed_without_an_edge() -> None:
    other = "arn:aws:iam::444455556666:role/elsewhere"
    inv = {"Version": 1, "Collected": ["lambda-function"], "Resources": [{"Arn": BILLING_FN, "Role": other}]}
    report = run([UPDATE_CODE], inv)
    t = techniques(report)["lambda-003"]
    assert t["confidence"] == "confirmed"
    assert t["targets"] == [other]
    assert report["paths"] == []
    assert [p["arn"] for p in report["principals"]] == [DEV]


def test_resource_without_a_role_is_not_a_finding() -> None:
    inv = {"Version": 1, "Collected": ["ec2-instance"], "Resources": [{"Arn": INSTANCE}]}
    stmt = {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": "*"}
    assert "ssm-002" not in techniques(run([stmt], inv))


# --- loading --------------------------------------------------------------------------------


def test_load_rejects_other_json() -> None:
    env = Environment.from_auth_details(export([UPDATE_CODE]))
    with pytest.raises(PolicyError):
        load_inventory({"Resources": "nope"}, env)
    with pytest.raises(PolicyError):
        load_inventory([], env)
    with pytest.raises(PolicyError):
        load_inventory({"Collected": ["lambda-function"], "Resources": [{"Role": BILLING_ROLE}]}, env)


def test_load_warns_about_unknown_kinds_and_profiles() -> None:
    env = Environment.from_auth_details(export([UPDATE_CODE]))
    inv = load_inventory(
        {
            "Collected": ["lambda-function", "spaceship"],
            "Resources": [
                {"Arn": "arn:aws:sqs:us-east-1:111122223333:queue", "Role": BILLING_ROLE},
                {"Arn": INSTANCE, "Role": f"arn:aws:iam::{ACCT}:instance-profile/missing"},
            ],
        },
        env,
    )
    text = " ".join(inv.warnings)
    assert (
        "spaceship" in text
        and "arn:aws:sqs:us-east-1:111122223333:queue" in text
        and "instance-profile/missing" in text
    )
    assert inv.collected == {"lambda-function"}


# --- command line ---------------------------------------------------------------------------


def test_cli_inventory(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from iamtrace.cli import main

    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps(export([UPDATE_CODE])))
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps(INVENTORY))
    assert main(["escalate", "--auth-details", str(auth), "--principal", DEV, "--inventory", str(inv)]) == 0
    out = capsys.readouterr().out
    assert f"via:     {BILLING_FN}" in out
    assert "Resource inventory: 1 ec2-instance, 2 lambda-function." in out
    assert "role/billing-admin" in out.split("Escalation paths")[1]


def test_cli_inventory_needs_an_export(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from iamtrace.cli import main

    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({"Version": "2012-10-17", "Statement": [UPDATE_CODE]}))
    assert main(["escalate", "--policy", str(pol), "--inventory", str(pol)]) == 2
    assert "--auth-details" in capsys.readouterr().err


def test_grouped_evaluation_matches_one_by_one() -> None:
    """Resources are evaluated once per group of matching patterns; the answer must equal
    evaluating every resource on its own, including Denies inside an allowed range, other
    accounts and patterns with policy variables."""
    fn = lambda name, acct=ACCT: f"arn:aws:lambda:us-east-1:{acct}:function:{name}"  # noqa: E731
    names = ["report-a", "report-b", "report-secret", "billing", "dev-tools"]
    resources = [{"Arn": fn(n), "Role": BILLING_ROLE} for n in names]
    resources.append({"Arn": fn("report-x", "444455556666"), "Role": BILLING_ROLE})
    inv = {"Collected": ["lambda-function"], "Resources": resources}
    stmts = [
        {
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionCode",
            "Resource": f"arn:aws:lambda:*:{ACCT}:function:report-*",
        },
        {"Effect": "Deny", "Action": "lambda:*", "Resource": fn("report-secret")},
        {
            "Effect": "Allow",
            "Action": "lambda:UpdateFunctionCode",
            "Resource": "arn:aws:lambda:*:*:function:${aws:username}-*",
        },
    ]
    report = run(stmts, inv)
    got = techniques(report)["lambda-003"]["via"]
    assert got == sorted([fn("report-a"), fn("report-b"), fn("dev-tools")])
    # Without the variable pattern the grouped path is taken; same answer, minus dev-tools.
    report = run(stmts[:2], inv)
    assert techniques(report)["lambda-003"]["via"] == [fn("report-a"), fn("report-b")]
