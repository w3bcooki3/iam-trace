"""Semantic diff: what a policy change grants or takes away, ignoring presentation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.catalog import Catalog
from iamtrace.cli import main
from iamtrace.diff import diff_policies, resource_subsumes
from iamtrace.model import Policy, PolicyType


def P(*statements: dict[str, Any], t: PolicyType = PolicyType.IDENTITY) -> Policy:
    return Policy.parse({"Version": "2012-10-17", "Statement": list(statements)}, policy_id="p", policy_type=t)


def actions(change: list[dict[str, Any]]) -> set[str]:
    return {c["action"] for c in change}


BASE = {
    "Sid": "Read",
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
}


def test_reorder_only_is_no_change(catalog: Catalog) -> None:
    old = P(BASE, {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"})
    new = P(
        {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": ["*"]},
        {
            "Sid": "Renamed",
            "Effect": "Allow",
            "Action": ["s3:ListBucket", "s3:GetObject"],
            "Resource": ["arn:aws:s3:::b/*", "arn:aws:s3:::b"],
        },
    )
    d = diff_policies(old, new, catalog)
    assert d["unchanged"]


def test_split_statement_is_no_change(catalog: Catalog) -> None:
    old = P(BASE)
    new = P(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": ["arn:aws:s3:::b", "arn:aws:s3:::b/*"]},
    )
    assert diff_policies(old, new, catalog)["unchanged"]


def test_wildcard_written_out_is_no_change(catalog: Catalog) -> None:
    old = P({"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"})
    new = P(
        {"Effect": "Allow", "Action": ["s3:GetBucketPolicy", "s3:GetObject", "s3:GetObjectTagging"], "Resource": "*"}
    )
    assert diff_policies(old, new, catalog)["unchanged"]


def test_new_action_is_reported_with_access_level(catalog: Catalog) -> None:
    old = P(BASE)
    new = P(BASE, {"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"})
    d = diff_policies(old, new, catalog)
    added = d["changes"]["newly_allowed"]
    assert actions(added) == {"iam:PutRolePolicy"}
    assert added[0]["access_level"] == "Permissions management"
    assert added[0]["highlight"]


def test_passrole_is_highlighted_although_not_permissions_management(catalog: Catalog) -> None:
    d = diff_policies(P(BASE), P(BASE, {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}), catalog)
    entry = d["changes"]["newly_allowed"][0]
    assert entry["access_level"] == "Write"
    assert entry["highlight"]
    assert "escalation" in entry["highlight_reason"]


def test_wildcard_expansion_lists_every_new_action(catalog: Catalog) -> None:
    d = diff_policies(P(BASE), P(BASE, {"Effect": "Allow", "Action": "s3:Put*", "Resource": "*"}), catalog)
    assert actions(d["changes"]["newly_allowed"]) == {
        "s3:PutBucketPolicy",
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:PutObjectTagging",
    }


def test_broader_resource_is_newly_allowed(catalog: Catalog) -> None:
    old = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/public/*"})
    new = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    d = diff_policies(old, new, catalog)
    assert d["changes"]["newly_allowed"][0]["resources"] == ["arn:aws:s3:::b/*"]
    # The narrower old grant is covered by the new one, so nothing is "no longer allowed".
    assert d["changes"]["no_longer_allowed"] == []


def test_narrower_resource_is_no_longer_allowed(catalog: Catalog) -> None:
    old = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"})
    new = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/public/*"})
    d = diff_policies(old, new, catalog)
    assert d["changes"]["newly_allowed"] == []
    assert d["changes"]["no_longer_allowed"][0]["resources"] == ["arn:aws:s3:::b/*"]


def test_removing_a_condition_broadens(catalog: Catalog) -> None:
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    old = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": cond})
    new = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    d = diff_policies(old, new, catalog)
    assert actions(d["changes"]["newly_allowed"]) == {"s3:GetObject"}
    assert d["changes"]["no_longer_allowed"] == []


def test_adding_a_condition_narrows(catalog: Catalog) -> None:
    cond = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    old = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    new = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": cond})
    d = diff_policies(old, new, catalog)
    assert d["changes"]["newly_allowed"] == []
    assert actions(d["changes"]["no_longer_allowed"]) == {"s3:GetObject"}
    assert d["changes"]["no_longer_allowed"][0]["conditions"] == {}


def test_condition_value_reorder_is_no_change(catalog: Catalog) -> None:
    old = P(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.0.2.0/24"]}},
        }
    )
    new = P(
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"IpAddress": {"AWS:SourceIP": ["192.0.2.0/24", "10.0.0.0/8"]}},
        }
    )
    assert diff_policies(old, new, catalog)["unchanged"]


def test_deny_changes(catalog: Catalog) -> None:
    old = P(BASE, {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"})
    new = P(BASE, {"Effect": "Deny", "Action": "s3:PutObject", "Resource": "*"})
    d = diff_policies(old, new, catalog)
    assert actions(d["changes"]["newly_denied"]) == {"s3:PutObject"}
    assert actions(d["changes"]["deny_removed"]) == {"s3:DeleteObject"}


def test_not_action_allow_expands_to_complement(catalog: Catalog) -> None:
    old = P({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    new = P({"Effect": "Allow", "NotAction": ["iam:*", "sts:*"], "Resource": "*"})
    d = diff_policies(old, new, catalog)
    added = actions(d["changes"]["newly_allowed"])
    assert "ec2:RunInstances" in added
    assert not any(a.startswith(("iam:", "sts:")) for a in added)
    assert "s3:GetObject" not in added


def test_unknown_action_kept(catalog: Catalog) -> None:
    d = diff_policies(P(BASE), P(BASE, {"Effect": "Allow", "Action": "newsvc:DoThing", "Resource": "*"}), catalog)
    entry = d["changes"]["newly_allowed"][0]
    assert entry["action"] == "newsvc:DoThing"
    assert entry["access_level"] == "Unknown"


def test_resource_policy_principals(catalog: Catalog) -> None:
    t = PolicyType.RESOURCE
    old = P({"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "s3:GetObject", "Resource": "*"}, t=t)
    new = P(
        {
            "Effect": "Allow",
            "Principal": {"AWS": ["111122223333", "444455556666"]},
            "Action": "s3:GetObject",
            "Resource": "*",
        },
        t=t,
    )
    d = diff_policies(old, new, catalog)
    assert d["changes"]["newly_allowed"][0]["principals"] == ["AWS:444455556666"]


@pytest.mark.parametrize(
    "broad,narrow,expected",
    [
        ("*", "arn:aws:s3:::b/*", True),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/*", True),
        ("arn:aws:s3:::b/*", "arn:aws:s3:::b/x", True),
        ("arn:aws:s3:::b/a*", "arn:aws:s3:::b/*", False),
        ("arn:aws:s3:::b/x", "arn:aws:s3:::b/x", True),
        ("arn:aws:s3:::b/x", "*", False),
    ],
)
def test_resource_subsumes(broad: str, narrow: str, expected: bool) -> None:
    assert resource_subsumes(broad, narrow) is expected


def _write(tmp_path: Path, name: str, doc: dict) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


def test_cli_diff_formats_and_exit_codes(catalog_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old = _write(tmp_path, "old.json", {"Version": "2012-10-17", "Statement": [BASE]})
    new = _write(
        tmp_path,
        "new.json",
        {
            "Version": "2012-10-17",
            "Statement": [BASE, {"Effect": "Allow", "Action": ["iam:PassRole", "s3:PutObject"], "Resource": "*"}],
        },
    )
    assert main(["diff", old, new, "--catalog", str(catalog_dir)]) == 0
    text = capsys.readouterr().out
    assert "Newly allowed" in text and "iam:PassRole" in text and "s3:PutObject" in text

    assert main(["diff", old, new, "--catalog", str(catalog_dir), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {c["action"] for c in data["changes"]["newly_allowed"]} == {"iam:PassRole", "s3:PutObject"}

    assert main(["diff", old, new, "--catalog", str(catalog_dir), "--format", "sarif"]) == 0
    sarif = json.loads(capsys.readouterr().out)
    levels = {r["message"]["text"].split()[0]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["iam:PassRole"] == "warning"

    assert main(["diff", old, new, "--catalog", str(catalog_dir), "--format", "markdown"]) == 0
    assert "| <code>iam:PassRole</code>" in capsys.readouterr().out

    assert main(["diff", old, new, "--catalog", str(catalog_dir), "--fail-on", "highlighted"]) == 1
    assert main(["diff", old, old, "--catalog", str(catalog_dir), "--fail-on", "any"]) == 0
    capsys.readouterr()


def test_cli_diff_new_file(catalog_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    new = _write(tmp_path, "new.json", {"Version": "2012-10-17", "Statement": [BASE]})
    assert main(["diff", "/dev/null", new, "--catalog", str(catalog_dir), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {c["action"] for c in data["changes"]["newly_allowed"]} == {"s3:GetObject", "s3:ListBucket"}
