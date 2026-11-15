"""Terraform plans: review the IAM changes, and what they do to the account."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.catalog import default_catalog
from iamtrace.terraform import TerraformError, extract, review, review_markdown, review_text

ROOT = Path(__file__).resolve().parents[2]
CAT = default_catalog()
A = "111122223333"


def doc(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(action: str | list[str], resource: str = "*") -> str:
    return doc({"Effect": "Allow", "Action": action, "Resource": resource})


def rc(
    address: str,
    actions: list[str],
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    unknown: dict[str, Any] | None = None,
) -> dict[str, Any]:
    kind = address.split(".")[-2]
    return {
        "address": address,
        "type": kind,
        "name": address.split(".")[-1],
        "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}},
    }


def plan(*changes: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
        "resource_changes": list(changes),
        "configuration": {"root_module": config or {"resources": []}},
    }


def export() -> dict[str, Any]:
    return json.loads((ROOT / "examples/account/auth-details.json").read_text())


PUBLIC_READ = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"})
TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})
GH_OPEN = doc(
    {
        "Effect": "Allow",
        "Principal": {"Federated": f"arn:aws:iam::{A}:oidc-provider/token.actions.githubusercontent.com"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}},
    }
)


# --- reading the plan ---------------------------------------------------------------------------


def test_extracts_every_kind_of_iam_document() -> None:
    p = plan(
        rc(
            "aws_iam_policy.deploy",
            ["create"],
            None,
            {"name": "deploy", "path": "/", "policy": allow("s3:*")},
        ),
        rc(
            "aws_iam_role.app",
            ["update"],
            {"name": "app", "assume_role_policy": TRUST, "inline_policy": []},
            {
                "name": "app",
                "assume_role_policy": GH_OPEN,
                "inline_policy": [{"name": "x", "policy": allow("sqs:*")}],
            },
        ),
        rc(
            "aws_iam_role_policy.ops",
            ["delete"],
            {
                "role": "ops",
                "name": "deploy",
                "policy": allow("iam:PassRole"),
            },
            None,
        ),
        rc(
            "aws_s3_bucket_policy.reports",
            ["create"],
            None,
            {
                "bucket": "reports",
                "policy": doc(
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::reports/*",
                    }
                ),
            },
        ),
        rc("aws_iam_role.unchanged", ["no-op"], {"name": "u"}, {"name": "u"}),
    )
    docs = extract(p)
    kinds = sorted((d.address, d.kind, d.action) for d in docs)
    assert kinds == [
        ("aws_iam_policy.deploy", "managed", "create"),
        ("aws_iam_role.app", "inline", "create"),  # a new inline_policy block on an updated role
        ("aws_iam_role.app", "trust", "update"),
        ("aws_iam_role_policy.ops", "inline", "delete"),
        ("aws_s3_bucket_policy.reports", "resource", "create"),
    ]


def test_unknown_documents_are_reported_not_guessed() -> None:
    p = plan(rc("aws_iam_role_policy.x", ["create"], None, {"role": "app", "name": "x"}, unknown={"policy": True}))
    [d] = extract(p)
    assert d.unknown is True
    out = review(p, CAT)
    assert any("not known until apply" in n for n in out["notes"])


def test_rejects_other_json() -> None:
    with pytest.raises(TerraformError):
        extract({"Version": "2012-10-17", "Statement": []})


# --- reviewing the documents ----------------------------------------------------------------------


def test_new_risky_patterns_and_escalation_are_flagged() -> None:
    p = plan(
        rc(
            "aws_iam_role_policy.ci",
            ["update"],
            {"role": "ci", "name": "ci", "policy": allow("s3:GetObject")},
            {
                "role": "ci",
                "name": "ci",
                "policy": doc(
                    {"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
                ),
            },
        ),
        rc("aws_iam_role.gh", ["create"], None, {"name": "gh", "assume_role_policy": GH_OPEN}),
    )
    out = review(p, CAT)
    by = {(d["address"], d["kind"]): d for d in out["documents"]}
    ci = by[("aws_iam_role_policy.ci", "inline")]
    assert any(t["id"] == "ec2-001" for t in ci["new_escalations"])
    assert any(f["rule"] == "passrole-any-role" for f in ci["new_checks"])
    gh = by[("aws_iam_role.gh", "trust")]
    assert any(f["rule"] == "open-federated-trust" for f in gh["new_checks"])
    assert out["summary"]["new_escalations"] >= 1


# --- what the plan does to the account -----------------------------------------------------------


def test_a_plan_that_opens_a_path_to_admin() -> None:
    # A new role trusted by every GitHub repository that can assume ops: a new entry point and a
    # new path to admin through ops -> ec2-admin.
    p = plan(
        rc("aws_iam_role.release", ["create"], None, {"name": "release", "path": "/", "assume_role_policy": GH_OPEN}),
        rc(
            "aws_iam_role_policy.release",
            ["create"],
            None,
            {
                "role": "release",
                "name": "assume-ops",
                "policy": doc(
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": f"arn:aws:iam::{A}:role/ops"}
                ),
            },
        ),
    )
    out = review(p, CAT, export=export())
    acct = out["account"]
    starts = {x["start"] for x in acct["new_paths"]}
    assert f"arn:aws:iam::{A}:role/release" in starts
    assert any(e["principal"].endswith("role/release") and e["rating"] == "Critical" for e in acct["new_entry_points"])
    assert out["summary"]["new_paths"] >= 1


def test_a_plan_that_closes_a_path() -> None:
    narrowed = doc(
        {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{A}:role/report-runner"},
    )
    p = plan(
        rc(
            "aws_iam_role_policy.ops",
            ["update"],
            {
                "role": "ops",
                "name": "deploy",
                "policy": allow(["iam:PassRole", "ec2:RunInstances"]),
            },
            {"role": "ops", "name": "deploy", "policy": narrowed},
        )
    )
    acct = review(p, CAT, export=export())["account"]
    assert acct["new_paths"] == []
    assert any(x["start"].endswith("user/dev") for x in acct["removed_paths"])


def test_attachment_of_a_policy_created_in_the_same_plan() -> None:
    admin = allow("*")
    config = {
        "resources": [
            {
                "address": "aws_iam_role_policy_attachment.ra",
                "expressions": {
                    "role": {"constant_value": "report-runner"},
                    "policy_arn": {"references": ["aws_iam_policy.everything.arn", "aws_iam_policy.everything"]},
                },
            }
        ]
    }
    p = plan(
        rc(
            "aws_iam_policy.everything",
            ["create"],
            None,
            {"name": "everything", "path": "/", "policy": admin},
            unknown={"arn": True},
        ),
        rc(
            "aws_iam_role_policy_attachment.ra",
            ["create"],
            None,
            {"role": "report-runner"},
            unknown={"policy_arn": True},
        ),
        config=config,
    )
    acct = review(p, CAT, export=export())["account"]
    assert f"arn:aws:iam::{A}:role/report-runner" in acct["new_admins"]


def test_deleting_a_role_removes_it() -> None:
    p = plan(
        rc("aws_iam_role.github_deploy", ["delete"], {"name": "github-deploy", "assume_role_policy": GH_OPEN}, None)
    )
    acct = review(p, CAT, export=export())["account"]
    assert any(e["principal"].endswith("role/github-deploy") for e in acct["removed_entry_points"])


def test_text_and_markdown() -> None:
    p = plan(rc("aws_iam_role.gh", ["create"], None, {"name": "gh", "assume_role_policy": GH_OPEN}))
    out = review(p, CAT, export=export())
    assert "aws_iam_role.gh" in review_text(out)
    md = review_markdown(out)
    assert md.startswith("<!-- iam-trace-terraform -->")
    assert "New entry points" in md


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    p = plan(rc("aws_iam_role.gh", ["create"], None, {"name": "gh", "assume_role_policy": GH_OPEN}))
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(p))
    args = ["terraform", str(f), "--auth-details", str(ROOT / "examples/account/auth-details.json")]
    assert main(args) == 0
    assert "aws_iam_role.gh" in capsys.readouterr().out
    assert main([*args, "--fail-on", "new-entry-point"]) == 1
    capsys.readouterr()
    assert main([*args, "--format", "markdown"]) == 0
    assert capsys.readouterr().out.startswith("<!-- iam-trace-terraform -->")


def test_markdown_escaping_keeps_entities_whole() -> None:
    from iamtrace.diff import md_text

    out = md_text("the token's subject #1 <b>")
    assert "&\\#" not in out and "&lt;b&gt;" in out and "\\#1" in out
