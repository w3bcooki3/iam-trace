"""IAM credential report: which users really have keys, passwords and MFA."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from iamtrace.credentials import CredentialError, parse_credential_report
from iamtrace.entry import entry_points, entry_points_text
from iamtrace.escalate import Environment

A = "111122223333"
NOW = "2026-11-15T00:00:00+00:00"
HEADER = (
    "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
    "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
    "access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,"
    "access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,"
    "access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,"
    "cert_2_active,cert_2_last_rotated"
)


def row(
    user: str,
    *,
    password: bool = False,
    mfa: bool = False,
    key1: tuple[str, str] | None = None,  # (last rotated, last used or "N/A")
    key2: tuple[str, str] | None = None,
    arn: str | None = None,
) -> str:
    def key(k: tuple[str, str] | None) -> list[str]:
        if k is None:
            return ["false", "N/A", "N/A", "N/A", "N/A"]
        return ["true", k[0], k[1], "us-east-1" if k[1] != "N/A" else "N/A", "s3" if k[1] != "N/A" else "N/A"]

    cells = [
        user,
        arn or f"arn:aws:iam::{A}:user/{user}",
        "2024-01-01T00:00:00+00:00",
        "true" if password else "false",
        "2026-11-01T00:00:00+00:00" if password else "N/A",
        "2026-01-01T00:00:00+00:00" if password else "N/A",
        "N/A",
        "true" if mfa else "false",
        *key(key1),
        *key(key2),
        "false",
        "N/A",
        "false",
        "N/A",
    ]
    return ",".join(cells)


def report(*rows: str) -> str:
    return "\n".join([HEADER, *rows]) + "\n"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def user(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": f"arn:aws:iam::{A}:user/{name}",
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
        "GroupList": [],
    }


def account(*users: dict[str, Any]) -> Environment:
    return Environment.from_auth_details(
        {"UserDetailList": list(users), "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    )


ADMIN = {"Effect": "Allow", "Action": "*", "Resource": "*"}
READ = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}


# --- parsing -----------------------------------------------------------------------------------


def test_parses_csv_and_derives_facts() -> None:
    text = report(
        row("alice", password=True, mfa=False, key1=("2025-01-01T00:00:00+00:00", "2026-11-10T00:00:00+00:00"))
    )
    creds = parse_credential_report(text, now=NOW)
    alice = creds.users[f"arn:aws:iam::{A}:user/alice"]
    assert alice.password and not alice.mfa
    [k] = alice.active_keys
    assert k.number == 1
    assert k.age_days == 683
    assert k.unused_days == 5


def test_parses_the_aws_cli_json_output() -> None:
    text = report(row("bob", key1=("2026-10-01T00:00:00+00:00", "N/A")))
    wrapped = json.dumps(
        {"Content": base64.b64encode(text.encode()).decode(), "ReportFormat": "text/csv", "GeneratedTime": NOW}
    )
    creds = parse_credential_report(wrapped)
    bob = creds.users[f"arn:aws:iam::{A}:user/bob"]
    assert bob.active_keys[0].never_used
    assert creds.generated == NOW


def test_root_row() -> None:
    root = row(
        "<root_account>",
        password=True,
        mfa=False,
        key1=("2020-01-01T00:00:00+00:00", "N/A"),
        arn=f"arn:aws:iam::{A}:root",
    )
    creds = parse_credential_report(report(root), now=NOW)
    assert creds.root is not None
    assert creds.root.active_keys and not creds.root.mfa


@pytest.mark.parametrize("text", ["", "not,a,report\n1,2,3\n", "{}", '{"Content": "!!!"}'])
def test_rejects_other_files(text: str) -> None:
    with pytest.raises(CredentialError):
        parse_credential_report(text)


# --- entry points -------------------------------------------------------------------------------


def test_user_without_credentials_is_not_an_entry_point() -> None:
    env = account(user("idle", ADMIN), user("active", ADMIN))
    creds = parse_credential_report(
        report(row("idle"), row("active", key1=("2026-10-01T00:00:00+00:00", "2026-11-14T00:00:00+00:00"))), now=NOW
    )
    out = entry_points(env, credentials=creds)
    names = [e["principal"].rsplit("/", 1)[-1] for e in out["entries"]]
    assert names == ["active"]
    assert out["summary"]["no_credentials"] == 1


def test_stale_and_unused_keys_rank_higher_and_are_explained() -> None:
    env = account(user("fresh", READ), user("stale", READ))
    creds = parse_credential_report(
        report(
            row("fresh", key1=("2026-10-01T00:00:00+00:00", "2026-11-14T00:00:00+00:00")),
            row("stale", key1=("2024-02-01T00:00:00+00:00", "2025-03-01T00:00:00+00:00")),
        ),
        now=NOW,
    )
    out = entry_points(env, credentials=creds)
    first = out["entries"][0]
    assert first["principal"].endswith("/stale")
    assert "1 active access key" in first["exposure"]["who"]
    assert "not used for 624 days" in first["exposure"]["detail"]
    assert "Remove" in first["exposure"]["fix"]


def test_password_without_mfa_is_called_out() -> None:
    env = account(user("console", READ))
    creds = parse_credential_report(report(row("console", password=True, mfa=False)), now=NOW)
    [e] = entry_points(env, credentials=creds)["entries"]
    assert "password without MFA" in e["exposure"]["who"]
    assert "MFA" in e["exposure"]["fix"]


def test_root_access_keys_are_critical() -> None:
    env = account(user("dev", READ))
    root = row(
        "<root_account>",
        password=True,
        mfa=True,
        key1=("2021-01-01T00:00:00+00:00", "N/A"),
        arn=f"arn:aws:iam::{A}:root",
    )
    creds = parse_credential_report(report(root, row("dev")), now=NOW)
    out = entry_points(env, credentials=creds)
    top = out["entries"][0]
    assert top["principal"] == f"arn:aws:iam::{A}:root"
    assert top["rating"] == "Critical"
    assert "root" in top["why"].lower()
    assert "Delete the root user's access keys" in top["exposure"]["fix"]


def test_without_a_report_every_user_is_listed_as_before() -> None:
    env = account(user("a", READ), user("b", READ))
    out = entry_points(env)
    assert len(out["entries"]) == 2
    assert all("does not say" in e["exposure"]["detail"] for e in out["entries"])


def test_report_users_missing_from_the_export_are_warned_about() -> None:
    env = account(user("dev", READ))
    creds = parse_credential_report(
        report(row("dev"), row("ghost", key1=("2026-01-01T00:00:00+00:00", "N/A"))), now=NOW
    )
    out = entry_points(env, credentials=creds)
    assert any("ghost" in w for w in out["warnings"])


def test_text_mentions_the_report() -> None:
    env = account(user("dev", READ))
    creds = parse_credential_report(report(row("dev", key1=("2026-10-01T00:00:00+00:00", "N/A"))), now=NOW)
    text = entry_points_text(entry_points(env, credentials=creds))
    assert "never used" in text


# --- collecting and the command line ---------------------------------------------------------------


def test_collect_waits_until_the_report_is_ready() -> None:
    from iamtrace.credentials import collect_credential_report

    calls: list[list[str]] = []
    states = iter(["STARTED", "INPROGRESS", "COMPLETE"])
    content = base64.b64encode(report(row("dev")).encode()).decode()

    def run(args: list[str]) -> Any:
        calls.append(args)
        if args[1] == "generate-credential-report":
            return {"State": next(states)}
        return {"Content": content, "ReportFormat": "text/csv", "GeneratedTime": NOW}

    text = collect_credential_report(run, sleep=lambda s: None)
    assert [c[1] for c in calls] == ["generate-credential-report"] * 3 + ["get-credential-report"]
    assert parse_credential_report(text).users


def test_collect_gives_up() -> None:
    from iamtrace.collect import CollectError
    from iamtrace.credentials import collect_credential_report

    with pytest.raises(CollectError):
        collect_credential_report(lambda a: {"State": "STARTED"}, sleep=lambda s: None, tries=3)


def test_cli_entry_points_with_a_report(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    data = {"UserDetailList": [user("idle", ADMIN)], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    (tmp_path / "auth.json").write_text(json.dumps(data))
    (tmp_path / "creds.csv").write_text(report(row("idle")))
    assert (
        main(
            [
                "entry-points",
                "--auth-details",
                str(tmp_path / "auth.json"),
                "--credential-report",
                str(tmp_path / "creds.csv"),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "No entry points" in out or "left out" in out
    (tmp_path / "bad.csv").write_text("nope\n")
    assert (
        main(
            [
                "entry-points",
                "--auth-details",
                str(tmp_path / "auth.json"),
                "--credential-report",
                str(tmp_path / "bad.csv"),
            ]
        )
        == 2
    )
    assert "not a credential report" in capsys.readouterr().err
