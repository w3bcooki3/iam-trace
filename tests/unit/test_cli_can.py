"""`iam-trace can` end to end through the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamtrace.cli import main


def write(tmp_path: Path, name: str, doc: dict) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return str(p)


@pytest.fixture
def identity_file(tmp_path: Path) -> str:
    return write(
        tmp_path,
        "identity.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "ReadBucket", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
                {"Sid": "NoSecrets", "Effect": "Deny", "Action": "s3:*", "Resource": "arn:aws:s3:::b/secret/*"},
            ],
        },
    )


ARGS = ["can", "--principal", "arn:aws:iam::111122223333:user/alice", "--action", "s3:GetObject"]


def test_can_allow_text(identity_file: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [*ARGS, "--resource", "arn:aws:s3:::b/x", "--resource-account", "111122223333", "--identity", identity_file]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "Decision: Allow" in out
    assert "ReadBucket" in out


def test_can_deny_json(identity_file: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            *ARGS,
            "--resource",
            "arn:aws:s3:::b/secret/x",
            "--resource-account",
            "111122223333",
            "--identity",
            identity_file,
            "--format",
            "json",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["decision"] == "ExplicitDeny"
    assert data["trace"][0]["matches"][0]["statement"] == "NoSecrets"


def test_can_sarif(identity_file: str, capsys: pytest.CaptureFixture[str]) -> None:
    main(
        [
            *ARGS,
            "--resource",
            "arn:aws:s3:::b/x",
            "--resource-account",
            "111122223333",
            "--identity",
            identity_file,
            "--format",
            "sarif",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["ruleId"] == "can/Allow"


def test_can_context_multivalue(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = write(
        tmp_path,
        "p.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:CreateTags",
                    "Resource": "*",
                    "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}},
                }
            ],
        },
    )
    base = [
        "can",
        "--principal",
        "arn:aws:iam::111122223333:user/a",
        "--action",
        "ec2:CreateTags",
        "--identity",
        f,
        "--resource-account",
        "111122223333",
    ]
    assert main([*base, "--context", "aws:TagKeys=env", "--context", "aws:TagKeys=team"]) == 0
    assert main([*base, "--context", "aws:TagKeys=env", "--context", "aws:TagKeys=owner"]) == 1


def test_can_invalid_policy_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = write(tmp_path, "bad.json", {"Statement": [{"Effect": "Perhaps", "Action": "*", "Resource": "*"}]})
    assert main([*ARGS, "--identity", f]) == 2
    assert "Effect must be Allow or Deny" in capsys.readouterr().err
