"""Privilege-escalation detection: single-principal techniques and multi-principal paths."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.cli import main
from iamtrace.escalate import Environment, analyze

ACCT = "111122223333"
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def trust(principal: Any) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    }


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def user(
    name: str,
    *inline: dict[str, Any],
    groups: list[str] | None = None,
    managed: list[str] | None = None,
    boundary: str | None = None,
) -> dict[str, Any]:
    u: dict[str, Any] = {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCT}:user/{name}",
        "Path": "/",
        "GroupList": groups or [],
        "UserPolicyList": [{"PolicyName": f"inline{i}", "PolicyDocument": d} for i, d in enumerate(inline)],
        "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[1], "PolicyArn": a} for a in managed or []],
    }
    if boundary:
        u["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary}
    return u


def role(
    name: str, trust_doc: dict[str, Any], *inline: dict[str, Any], managed: list[str] | None = None
) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "Path": "/",
        "AssumeRolePolicyDocument": trust_doc,
        "RolePolicyList": [{"PolicyName": f"inline{i}", "PolicyDocument": d} for i, d in enumerate(inline)],
        "AttachedManagedPolicies": [{"PolicyName": a.rsplit("/", 1)[1], "PolicyArn": a} for a in managed or []],
    }


def managed(arn: str, document: dict[str, Any]) -> dict[str, Any]:
    return {
        "PolicyName": arn.rsplit("/", 1)[1],
        "Arn": arn,
        "DefaultVersionId": "v2",
        "PolicyVersionList": [
            {"VersionId": "v1", "IsDefaultVersion": False, "Document": doc()},
            {"VersionId": "v2", "IsDefaultVersion": True, "Document": document},
        ],
    }


def env(
    users: list[dict[str, Any]] = (),
    roles: list[dict[str, Any]] = (),
    groups: list[dict[str, Any]] = (),
    policies: list[dict[str, Any]] = (),
) -> Environment:
    return Environment.from_auth_details(
        {
            "UserDetailList": list(users),
            "RoleDetailList": list(roles),
            "GroupDetailList": list(groups),
            "Policies": list(policies),
        }
    )


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
DEV = f"arn:aws:iam::{ACCT}:user/dev"


def ids(findings: list[dict[str, Any]]) -> set[str]:
    return {f["id"] for f in findings}


def principal_report(report: dict[str, Any], arn: str) -> dict[str, Any]:
    return next(p for p in report["principals"] if p["arn"] == arn)


def test_lambda_passrole_path_to_admin_role() -> None:
    e = env(
        users=[
            user(
                "dev",
                doc(
                    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{ACCT}:role/lambda-admin"},
                    {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"},
                ),
            )
        ],
        roles=[role("lambda-admin", trust({"Service": "lambda.amazonaws.com"}), managed=[ADMIN_ARN])],
        policies=[managed(ADMIN_ARN, ADMIN)],
    )
    r = analyze(e, start=DEV)
    dev = principal_report(r, DEV)
    assert "lambda-001" in ids(dev["techniques"])
    lam = next(t for t in dev["techniques"] if t["id"] == "lambda-001")
    assert lam["targets"] == [f"arn:aws:iam::{ACCT}:role/lambda-admin"]
    assert lam["source"]["pathfinding"] == "https://pathfinding.cloud/paths/lambda-001"
    assert "rhinosecuritylabs.com" in lam["source"]["first_documented"]
    assert r["paths"][0]["steps"][0]["technique"] == "lambda-001"
    assert r["paths"][0]["end_admin"]


def test_passrole_to_role_not_trusting_service_is_not_a_path() -> None:
    e = env(
        users=[user("dev", doc({"Effect": "Allow", "Action": ["iam:PassRole", "lambda:*"], "Resource": "*"}))],
        roles=[role("ec2-admin", trust({"Service": "ec2.amazonaws.com"}), managed=[ADMIN_ARN])],
        policies=[managed(ADMIN_ARN, ADMIN)],
    )
    r = analyze(e, start=DEV)
    assert "lambda-001" not in ids(principal_report(r, DEV)["techniques"])
    assert r["paths"] == []


def test_assume_role_chain_to_self_escalating_role() -> None:
    ops = f"arn:aws:iam::{ACCT}:role/ops"
    e = env(
        users=[user("dev", doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": ops}))],
        roles=[
            role(
                "ops",
                trust({"AWS": f"arn:aws:iam::{ACCT}:root"}),
                doc({"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": ops}),
            )
        ],
    )
    r = analyze(e, start=DEV)
    assert ids(principal_report(r, ops)["techniques"]) >= {"iam-005"}
    path = r["paths"][0]
    assert [s["technique"] for s in path["steps"]] == ["sts-001"]
    assert path["end"] == ops
    assert path["end_admin"]


def test_trust_policy_must_allow_assume_role() -> None:
    e = env(
        users=[user("dev", doc({"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}))],
        roles=[role("ops", trust({"AWS": f"arn:aws:iam::{ACCT}:user/someone-else"}), managed=[ADMIN_ARN])],
        policies=[managed(ADMIN_ARN, ADMIN)],
    )
    assert analyze(e, start=DEV)["paths"] == []


def test_create_policy_version_on_attached_policy() -> None:
    mine = f"arn:aws:iam::{ACCT}:policy/dev-policy"
    e = env(
        users=[user("dev", managed=[mine])],
        policies=[managed(mine, doc({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": mine}))],
    )
    t = principal_report(analyze(e, start=DEV), DEV)
    assert "iam-001" in ids(t["techniques"])
    assert t["admin_equivalent"]


def test_group_policies_count() -> None:
    e = env(
        users=[user("dev", groups=["devs"])],
        groups=[
            {
                "GroupName": "devs",
                "Arn": f"arn:aws:iam::{ACCT}:group/devs",
                "GroupPolicyList": [
                    {
                        "PolicyName": "g",
                        "PolicyDocument": doc({"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}),
                    }
                ],
                "AttachedManagedPolicies": [],
            }
        ],
    )
    e2 = env(
        users=[*e.raw["UserDetailList"], user("admin", managed=[ADMIN_ARN])],
        groups=e.raw["GroupDetailList"],
        policies=[managed(ADMIN_ARN, ADMIN)],
    )
    r = analyze(e2, start=DEV)
    assert "iam-002" in ids(principal_report(r, DEV)["techniques"])
    assert any(p["end"] == f"arn:aws:iam::{ACCT}:user/admin" for p in r["paths"])


def test_boundary_blocks_technique() -> None:
    bnd = f"arn:aws:iam::{ACCT}:policy/boundary"
    e = env(
        users=[user("dev", doc({"Effect": "Allow", "Action": "iam:*", "Resource": "*"}), boundary=bnd)],
        policies=[managed(bnd, doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))],
    )
    t = principal_report(analyze(e, start=DEV), DEV)
    assert t["techniques"] == []
    assert not t["admin_equivalent"]


def test_url_encoded_documents_are_decoded() -> None:
    import urllib.parse

    encoded = urllib.parse.quote(
        json.dumps(doc({"Effect": "Allow", "Action": "iam:CreateLoginProfile", "Resource": "*"}))
    )
    e = env(users=[user("dev"), user("other")])
    e.raw["UserDetailList"][0]["UserPolicyList"] = [{"PolicyName": "enc", "PolicyDocument": encoded}]
    e = Environment.from_auth_details(e.raw)
    assert "iam-004" in ids(principal_report(analyze(e, start=DEV), DEV)["techniques"])


def test_existing_passrole_is_reported_as_possible() -> None:
    e = env(
        users=[user("dev", doc({"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": "*"}))],
        roles=[role("fn", trust({"Service": "lambda.amazonaws.com"}), managed=[ADMIN_ARN])],
        policies=[managed(ADMIN_ARN, ADMIN)],
    )
    t = next(x for x in principal_report(analyze(e, start=DEV), DEV)["techniques"] if x["id"] == "lambda-003")
    assert t["confidence"] == "possible"
    assert t["targets"] == [f"arn:aws:iam::{ACCT}:role/fn"]


def test_admin_is_flagged_without_paths() -> None:
    e = env(users=[user("root-ish", managed=[ADMIN_ARN])], policies=[managed(ADMIN_ARN, ADMIN)])
    r = analyze(e)
    assert principal_report(r, f"arn:aws:iam::{ACCT}:user/root-ish")["admin_equivalent"]


def test_blast_radius_with_catalog(catalog: Any) -> None:
    e = env(users=[user("dev", doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}))])
    r = analyze(e, start=DEV, catalog=catalog)
    br = r["blast_radius"]
    assert br["principals"] == [DEV]
    assert br["actions_by_access_level"]["Read"] == 3


# --- CLI -------------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, data: Any) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


def test_cli_escalate_auth_details(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    e = {
        "UserDetailList": [
            user("dev", doc({"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"})),
            user("admin", managed=[ADMIN_ARN]),
        ],
        "RoleDetailList": [],
        "GroupDetailList": [],
        "Policies": [managed(ADMIN_ARN, ADMIN)],
    }
    f = _write(tmp_path, "auth.json", e)
    assert main(["escalate", "--auth-details", f, "--principal", DEV]) == 0
    out = capsys.readouterr().out
    assert "iam-002" in out and "user/admin" in out
    assert main(["escalate", "--auth-details", f, "--principal", DEV, "--fail-on", "admin"]) == 1
    capsys.readouterr()
    assert main(["escalate", "--auth-details", f, "--principal", DEV, "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert any(res["ruleId"] == "iam-002" for res in sarif["runs"][0]["results"])


def test_cli_escalate_policy_baseline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old = _write(tmp_path, "old.json", doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))
    new = _write(
        tmp_path, "new.json", doc({"Effect": "Allow", "Action": ["s3:*", "iam:PutRolePolicy"], "Resource": "*"})
    )
    assert main(["escalate", "--policy", new, "--baseline", old, "--fail-on", "new", "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert {f["id"] for f in data["new_findings"]} == {"iam-005"}
    assert main(["escalate", "--policy", old, "--baseline", old, "--fail-on", "new"]) == 0
    capsys.readouterr()


def test_prefilter_never_changes_results() -> None:
    """The may_allow pre-filter is an optimisation only: findings must be identical without it."""
    import random

    from iamtrace import escalate as esc

    actions = [
        "iam:*",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:PutRolePolicy",
        "iam:AttachUserPolicy",
        "sts:AssumeRole",
        "lambda:*",
        "ec2:RunInstances",
        "glue:*",
        "s3:*",
        "iam:Get*",
        "*",
    ]
    for seed in range(12):
        rng = random.Random(seed)

        def pol(rng: random.Random = rng) -> dict[str, Any]:
            st: dict[str, Any] = {
                "Effect": rng.choice(["Allow", "Allow", "Deny"]),
                "Resource": rng.choice(["*", f"arn:aws:iam::{ACCT}:role/r*"]),
            }
            st["NotAction" if rng.random() < 0.15 else "Action"] = rng.sample(actions, 2)
            return doc(st)

        users = [user(f"u{i}", pol(), pol()) for i in range(4)]
        roles = [
            role(
                f"r{i}",
                trust(
                    rng.choice(
                        [
                            {"AWS": f"arn:aws:iam::{ACCT}:root"},
                            {"AWS": f"arn:aws:iam::{ACCT}:user/u0"},
                            {"Service": "lambda.amazonaws.com"},
                        ]
                    )
                ),
                pol(),
            )
            for i in range(4)
        ]
        e = env(users=users, roles=roles)
        fast = analyze(e)
        original = esc._Analyzer.may_allow
        try:
            esc._Analyzer.may_allow = lambda self, node, action: True  # type: ignore[method-assign]
            slow = analyze(e)
        finally:
            esc._Analyzer.may_allow = original  # type: ignore[method-assign]
        assert fast == slow, f"seed {seed}"
