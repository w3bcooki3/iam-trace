"""The `check` command: inputs, output formats and --fail-on exit codes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamtrace.cli import main

EXAMPLES = Path(__file__).parents[2] / "examples"


def _write(tmp_path: Path, name: str, doc: object) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


ADMIN = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
TYPO = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObjects", "Resource": "*"}}


def test_text_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", _write(tmp_path, "admin.json", ADMIN)]) == 0
    out = capsys.readouterr().out
    assert "[HIGH] full-admin" in out and "Fix:" in out


@pytest.mark.parametrize(("fail_on", "code"), [("never", 0), ("high", 0), ("medium", 0), ("low", 1)])
def test_fail_on_thresholds(tmp_path: Path, capsys: pytest.CaptureFixture[str], fail_on: str, code: int) -> None:
    # The only finding is low severity.
    assert main(["check", _write(tmp_path, "typo.json", TYPO), "--fail-on", fail_on]) == code


def test_account_export_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--auth-details", str(EXAMPLES / "account" / "auth-details.json"), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["high"] >= 1
    assert {f["rule"] for f in report["findings"]} >= {"passrole-any-role"}


def test_needs_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check"]) == 2
    assert "policy files" in capsys.readouterr().err


def test_files_and_export_together_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = _write(tmp_path, "a.json", ADMIN)
    assert main(["check", f, "--auth-details", f]) == 2


def test_unreadable_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", str(tmp_path / "missing.json")]) == 2
