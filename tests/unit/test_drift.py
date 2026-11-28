"""Drift: what changed in an account between two exports."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.catalog import default_catalog
from iamtrace.cli import main
from iamtrace.drift import drift, drift_markdown, drift_text
from iamtrace.model import PolicyError

ROOT = Path(__file__).resolve().parents[2]
CAT = default_catalog()
SAMPLE = ROOT / "examples" / "sample" / "auth-details.json"
A = "111122223333"


def sample() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SAMPLE.read_text())
    return data


def role(export: dict[str, Any], name: str) -> dict[str, Any]:
    return next(r for r in export["RoleDetailList"] if r["RoleName"] == name)


def inline(export: dict[str, Any], name: str, *actions: str) -> None:
    role(export, name)["RolePolicyList"].append(
        {
            "PolicyName": "added",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}],
            },
        }
    )


def changed(r: dict[str, Any], name: str) -> dict[str, Any]:
    return next(c for c in r["changed"] if c["principal"].endswith("/" + name))


def test_same_export_is_unchanged() -> None:
    r = drift(sample(), sample(), CAT)
    assert r["verdict"] == "unchanged"
    assert not r["changed"] and not r["principals_added"] and not r["principals_removed"]
    assert "No change" in drift_text(r)


def test_new_escalation_permission_is_worse_and_sensitive() -> None:
    new = sample()
    inline(new, "report-runner", "iam:CreateAccessKey")
    r = drift(sample(), new, CAT)
    assert r["verdict"] == "worse"
    assert r["summary"]["new_paths"] > 0
    c = changed(r, "report-runner")
    assert [e["action"] for e in c["newly_allowed"]] == ["iam:CreateAccessKey"]
    assert c["sensitive"] == 1
    assert "! iam:CreateAccessKey on *" in drift_text(r)


def test_harmless_new_access_is_changed_not_worse() -> None:
    new = sample()
    inline(new, "report-runner", "cloudwatch:GetMetricData")
    r = drift(sample(), new, CAT)
    assert r["verdict"] == "changed"
    c = changed(r, "report-runner")
    assert c["sensitive"] == 0
    assert "+ cloudwatch:GetMetricData on *" in drift_text(r)


def test_moving_a_statement_between_policies_is_no_change() -> None:
    old, new = sample(), sample()
    inline(old, "report-runner", "cloudwatch:GetMetricData")
    inline(new, "report-runner", "cloudwatch:GetMetricData")
    role(new, "report-runner")["RolePolicyList"][-1]["PolicyName"] = "renamed"
    assert drift(old, new, CAT)["verdict"] == "unchanged"


def test_wider_trust_is_reported() -> None:
    new = sample()
    role(new, "analytics")["AssumeRolePolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}
    )
    r = drift(sample(), new, CAT)
    c = changed(r, "analytics")
    assert c["trust"] and c["trust"]["changes"]["newly_allowed"]
    assert "can now be assumed by arn:aws:iam::999988887777:root" in drift_text(r)
    assert r["summary"]["trust_changed"] == 1


def test_added_admin_and_removed_user() -> None:
    old, new = sample(), sample()
    new["UserDetailList"] = [u for u in new["UserDetailList"] if u["UserName"] != "ci-bot"]
    new["UserDetailList"].append(
        {
            "UserName": "temp",
            "UserId": "AIDATEMP",
            "Arn": f"arn:aws:iam::{A}:user/temp",
            "Path": "/",
            "GroupList": [],
            "UserPolicyList": [],
            "AttachedManagedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ],
        }
    )
    r = drift(old, new, CAT)
    assert r["principals_added"] == [f"arn:aws:iam::{A}:user/temp"]
    assert r["principals_removed"] == [f"arn:aws:iam::{A}:user/ci-bot"]
    assert f"arn:aws:iam::{A}:user/temp" in r["account"]["new_admins"]
    assert r["verdict"] == "worse"
    md = drift_markdown(r)
    assert "user/temp" in md and "Admin-equivalent principals | 1 | 0" in md


def test_group_membership_change_is_reported() -> None:
    new = sample()
    alice = next(u for u in new["UserDetailList"] if u["UserName"] == "alice")
    alice["GroupList"] = []
    r = drift(sample(), new, CAT)
    c = changed(r, "alice")
    assert c["left_groups"] and c["no_longer_allowed"]
    assert "left group" in drift_text(r)


def test_different_accounts_are_noted() -> None:
    new = json.loads(json.dumps(sample()).replace(A, "444455556666"))
    r = drift(sample(), new, CAT)
    assert any("different accounts" in n for n in r["notes"])


def test_not_an_export_is_an_error() -> None:
    with pytest.raises(PolicyError):
        drift(sample(), {"Version": "2012-10-17", "Statement": []}, CAT)


def test_cli_fail_on(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(json.dumps(sample()))
    harmless = sample()
    inline(harmless, "report-runner", "cloudwatch:GetMetricData")
    new.write_text(json.dumps(harmless))
    assert main(["drift", str(old), str(old), "--fail-on", "any"]) == 0
    assert main(["drift", str(old), str(new), "--fail-on", "worse"]) == 0
    assert main(["drift", str(old), str(new), "--fail-on", "any"]) == 1
    worse = copy.deepcopy(harmless)
    inline(worse, "report-runner", "iam:CreateAccessKey")
    new.write_text(json.dumps(worse))
    assert main(["drift", str(old), str(new), "--fail-on", "worse"]) == 1
    capsys.readouterr()
    assert main(["drift", str(old), str(new), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "worse"


def test_access_the_boundary_blocks_is_not_sensitive() -> None:
    old, new = sample(), sample()
    bob_old = next(u for u in old["UserDetailList"] if u["UserName"] == "bob")
    bob_old["UserPolicyList"] = []  # bob's iam:* is new; his boundary allows only S3 and DynamoDB
    r = drift(old, new, CAT)
    c = changed(r, "bob")
    assert c["newly_allowed"] and c["blocked_by_boundary"] == len(c["newly_allowed"])
    assert c["sensitive"] == 0
    assert r["summary"]["principals_grew"] == 0
    assert "no effect, the permission boundary does not allow them" in drift_text(r)


def test_sample_previous_export_tells_the_story() -> None:
    previous = json.loads((ROOT / "examples" / "sample" / "auth-details-previous.json").read_text())
    r = drift(previous, sample(), CAT)
    assert r["verdict"] == "worse"
    assert [p["start"] for p in r["account"]["new_paths"]] == [f"arn:aws:iam::{A}:user/ci-bot"]
    assert r["principals_added"] == [f"arn:aws:iam::{A}:user/dev-legacy"]
    assert r["principals_removed"] == [f"arn:aws:iam::{A}:user/old-ops"]
