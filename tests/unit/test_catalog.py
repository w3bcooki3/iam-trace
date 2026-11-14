"""Catalog refresh, access-level mapping and wildcard expansion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamtrace.catalog import Catalog, CatalogMissing, access_level
from iamtrace.catalog.refresh import compact_service
from iamtrace.cli import main


@pytest.mark.parametrize(
    "props,expected",
    [
        ({"IsPermissionManagement": True, "IsWrite": True}, "Permissions management"),
        ({"IsTaggingOnly": True, "IsWrite": True}, "Tagging"),
        ({"IsWrite": True}, "Write"),
        ({"IsList": True}, "List"),
        ({"IsList": False, "IsWrite": False, "IsPermissionManagement": False, "IsTaggingOnly": False}, "Read"),
        ({"IsDataPlane": True}, "Read"),
        (None, "Unknown"),
        ({}, "Unknown"),
    ],
)
def test_access_level_mapping(props: dict | None, expected: str) -> None:
    assert access_level(props) == expected


def test_compact_service_handles_missing_fields() -> None:
    out = compact_service({"Name": "x", "Actions": [{"Name": "Do"}]})
    assert out["actions"]["Do"]["access_level"] == "Unknown"
    assert out["actions"]["Do"]["resource_types"] == []
    assert out["resources"] == {}


def test_refresh_writes_deterministic_layout(catalog_dir: Path) -> None:
    meta = json.loads((catalog_dir / "meta.json").read_text())
    assert meta["service_count"] == len(list((catalog_dir / "services").glob("*.json")))
    iam = json.loads((catalog_dir / "services" / "iam.json").read_text())
    assert list(iam["actions"]) == sorted(iam["actions"])
    assert iam["actions"]["PassRole"]["condition_keys"] == ["iam:AssociatedResourceArn", "iam:PassedToService"]


def test_expand_wildcards(catalog: Catalog) -> None:
    names = [a.full_name for a in catalog.expand("s3:Get*")]
    assert names == ["s3:GetBucketPolicy", "s3:GetObject", "s3:GetObjectTagging"]
    assert {a.full_name for a in catalog.expand("S3:*OBJECT")} == {"s3:DeleteObject", "s3:GetObject", "s3:PutObject"}
    assert len(catalog.expand("*")) == len(catalog)
    assert catalog.expand("nosuchservice:*") == []


def test_expand_not(catalog: Catalog) -> None:
    rest = catalog.expand_not(["s3:*", "iam:*"])
    assert all(a.service not in ("s3", "iam") for a in rest)
    assert any(a.full_name == "ec2:RunInstances" for a in rest)


def test_get_is_case_insensitive(catalog: Catalog) -> None:
    info = catalog.get("IAM:passrole")
    assert info and info.access_level == "Write"


def test_missing_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("IAMTRACE_CATALOG", raising=False)
    monkeypatch.setattr("iamtrace.catalog.PACKAGED", tmp_path / "none")
    with pytest.raises(CatalogMissing):
        Catalog.load()


def test_cli_expand(catalog_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["expand", "--catalog", str(catalog_dir), "iam:*Policy*"]) == 0
    out = capsys.readouterr().out
    assert "iam:PutRolePolicy" in out
    assert "Permissions management" in out


def test_cli_expand_json_and_policy(catalog_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "p.json"
    p.write_text(
        json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["lambda:*Function*"], "Resource": "*"},
                    {
                        "Effect": "Deny",
                        "NotAction": [
                            "s3:*",
                            "iam:*",
                            "sts:*",
                            "ec2:*",
                            "kms:*",
                            "sqs:*",
                            "secretsmanager:*",
                            "cloudformation:*",
                            "glue:*",
                            "ssm:*",
                            "lambda:Get*",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        )
    )
    assert main(["expand", "--catalog", str(catalog_dir), "--policy", str(p), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    first, second = data["statements"]
    assert {a["action"] for a in first["actions"]} == {
        "lambda:CreateFunction",
        "lambda:GetFunction",
        "lambda:InvokeFunction",
        "lambda:ListFunctions",
        "lambda:UpdateFunctionCode",
    }
    assert second["not_action"] is True
    assert {a["action"] for a in second["actions"]} == {
        "lambda:AddPermission",
        "lambda:CreateEventSourceMapping",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "lambda:ListFunctions",
        "lambda:UpdateFunctionCode",
    }


def test_cli_expand_unknown_pattern_warns(catalog_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["expand", "--catalog", str(catalog_dir), "s3:Nope*"]) == 0
    assert "matches no known action" in capsys.readouterr().out


def test_cli_catalog_info(catalog_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", "info", "--catalog", str(catalog_dir)]) == 0
    assert "actions" in capsys.readouterr().out


def test_refresh_refuses_to_replace_a_non_catalog_directory(tmp_path: Path) -> None:
    from iamtrace.catalog.refresh import refresh
    from tests.fixtures.servicereference import fake_fetch

    precious = tmp_path / "documents"
    precious.mkdir()
    (precious / "thesis.docx").write_text("do not delete")
    with pytest.raises(RuntimeError, match="not an iam-trace catalog"):
        refresh(precious, fetch=fake_fetch, log=lambda _: None)
    assert (precious / "thesis.docx").read_text() == "do not delete"


def test_refresh_replaces_an_existing_catalog(catalog_dir: Path, tmp_path: Path) -> None:
    import shutil

    from iamtrace.catalog.refresh import refresh
    from tests.fixtures.servicereference import fake_fetch

    target = tmp_path / "cat"
    shutil.copytree(catalog_dir, target)
    refresh(target, fetch=fake_fetch, log=lambda _: None)
    assert (target / "meta.json").exists()


@pytest.mark.parametrize("name", ["../../etc", "a/b", "", "UPPER", "x" * 80])
def test_refresh_rejects_unexpected_service_names(name: str) -> None:
    with pytest.raises(RuntimeError, match="unexpected service name"):
        compact_service({"Name": name, "Actions": []})


def test_refresh_rejects_unexpected_urls(tmp_path: Path) -> None:
    from iamtrace.catalog.refresh import refresh

    def fetch(url: str) -> object:
        return [{"service": "evil", "url": "https://attacker.example/evil.json"}]

    with pytest.raises(RuntimeError, match="unexpected URL"):
        refresh(tmp_path / "out", fetch=fetch, log=lambda _: None)
