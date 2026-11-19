from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.collect import CollectError
from iamtrace.escalate import Environment
from iamtrace.usage import (
    UsageError,
    collect_usage,
    parse_usage,
    trim_statement,
    unused_access,
    unused_text,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "account"
A = "111122223333"
GEN = "2026-11-10T09:00:00+00:00"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def report(**services: str | None) -> dict[str, Any]:
    """A report: service namespace -> when last used (None: never)."""
    return {
        "JobStatus": "COMPLETED",
        "JobCompletionDate": GEN,
        "ServicesLastAccessed": [
            {"ServiceName": ns, "ServiceNamespace": ns, **({"LastAuthenticated": t} if t else {})}
            for ns, t in services.items()
        ],
    }


def usage(reports: dict[str, dict[str, Any]]) -> str:
    return json.dumps({"Reports": reports})


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def account(
    users: dict[str, list[dict[str, Any]]],
    groups: dict[str, list[dict[str, Any]]] | None = None,
    members: dict[str, list[str]] | None = None,
    managed: dict[str, dict[str, Any]] | None = None,
    attach: dict[str, list[str]] | None = None,
) -> Environment:
    def attached(name: str) -> list[dict[str, str]]:
        return [{"PolicyName": m.rsplit("/", 1)[-1], "PolicyArn": m} for m in (attach or {}).get(name, [])]

    return Environment.from_auth_details(
        {
            "UserDetailList": [
                {
                    "UserName": u,
                    "Arn": arn("user", u),
                    "UserPolicyList": [{"PolicyName": "own", "PolicyDocument": doc(*sts)}] if sts else [],
                    "AttachedManagedPolicies": attached(u),
                    "GroupList": (members or {}).get(u, []),
                }
                for u, sts in users.items()
            ],
            "GroupDetailList": [
                {
                    "GroupName": g,
                    "Arn": arn("group", g),
                    "GroupPolicyList": [{"PolicyName": "shared", "PolicyDocument": doc(*sts)}],
                    "AttachedManagedPolicies": [],
                }
                for g, sts in (groups or {}).items()
            ],
            "RoleDetailList": [],
            "Policies": [
                {
                    "PolicyName": m.rsplit("/", 1)[-1],
                    "Arn": m,
                    "DefaultVersionId": "v1",
                    "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": d}],
                }
                for m, d in (managed or {}).items()
            ],
        }
    )


# --- reading reports ---------------------------------------------------------------------------


def test_reads_the_example() -> None:
    u = parse_usage((EXAMPLES / "last-accessed.json").read_text())
    ops = u[arn("role", "ops")]
    assert ops.idle_days("ec2") == 0
    assert ops.idle_days("iam") is None
    assert ops.services["ec2"].actions == {"ec2:RunInstances": ops.services["ec2"].last}


@pytest.mark.parametrize(
    "text, message",
    [
        ("nope", "invalid JSON at line 1"),
        ("[]", "Reports"),
        ('{"Reports": {"x": {}}}', "not the output of get-service-last-accessed-details"),
        ('{"Reports": {"x": {"JobStatus": "IN_PROGRESS", "ServicesLastAccessed": []}}}', "IN_PROGRESS"),
        ('{"Reports": {"x": {"ServicesLastAccessed": []}}}', "JobCompletionDate"),
    ],
)
def test_bad_input_says_what_is_wrong(text: str, message: str) -> None:
    with pytest.raises(UsageError, match=message):
        parse_usage(text)


def test_the_window_is_counted_from_when_the_report_was_made() -> None:
    u = parse_usage(usage({"u": report(s3="2026-08-12T09:00:00Z", ec2="2026-08-11T09:00:00Z")}))["u"]
    assert u.idle_days("s3") == 90 and u.unused("s3", 90)
    assert not u.unused("s3", 91)
    assert u.unused("ec2", 90)
    assert not u.unused("dynamodb", 1)  # not in the report: nothing is known about it


# --- trimming one statement ----------------------------------------------------------------------


def test_drops_patterns_of_unused_services_only() -> None:
    st = {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:*", "dynamodb:Query"], "Resource": "*"}
    [out], removed = trim_statement(st, {"ec2", "sqs"})
    assert out["Action"] == ["s3:GetObject", "dynamodb:Query"]
    assert removed == ["ec2"]


def test_a_statement_with_nothing_left_goes() -> None:
    assert trim_statement({"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}, {"ec2"}) == ([], ["ec2"])


def test_keeps_passrole_when_iam_goes() -> None:
    st = {"Effect": "Allow", "Action": ["iam:*", "ec2:RunInstances"], "Resource": "*"}
    [out], removed = trim_statement(st, {"iam"})
    assert out["Action"] == ["ec2:RunInstances", "iam:PassRole"]
    assert removed == ["iam"]


def test_an_exact_passrole_is_left_where_it_is() -> None:
    st = {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
    assert trim_statement(st, {"iam"}) == ([st], [])


def test_allow_everything_becomes_everything_but_the_unused_services() -> None:
    st = {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}
    out, removed = trim_statement(st, {"rds", "iam"})
    assert out[0] == {
        "Effect": "Allow",
        "NotAction": ["iam:*", "rds:*"],
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
    }
    # PassRole comes back as its own statement, with the same resources and conditions.
    assert out[1] == {
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "true"}},
    }
    assert removed == ["iam", "rds"]


def test_notaction_grows() -> None:
    st = {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}
    [out], removed = trim_statement(st, {"s3", "sqs"})
    assert out["NotAction"] == ["s3:*", "sqs:*"]
    assert removed == ["sqs"]


def test_notaction_naming_one_action_does_not_exclude_the_service() -> None:
    # Found by tests/property: "lambda:CreateFunction" in NotAction still allows lambda:Invoke*.
    st = {"Effect": "Allow", "NotAction": "lambda:CreateFunction", "Resource": "*"}
    [out], removed = trim_statement(st, {"lambda"})
    assert out["NotAction"] == ["lambda:CreateFunction", "lambda:*"] and removed == ["lambda"]


def test_deny_statements_are_untouched() -> None:
    st = {"Effect": "Deny", "Action": "ec2:*", "Resource": "*"}
    assert trim_statement(st, {"ec2"}) == ([st], [])


# --- the account -----------------------------------------------------------------------------------


def test_the_example_closes_a_path() -> None:
    env = Environment.from_auth_details(json.loads((EXAMPLES / "auth-details.json").read_text()))
    r = unused_access(env, parse_usage((EXAMPLES / "last-accessed.json").read_text()))
    by_policy = {e["policy"]: e for e in r["edits"]}
    gh = by_policy[f"{arn('role', 'github-deploy')} inline deploy"]
    assert gh["delete"] and gh["removes"] == ["sts"] and gh["idle_days"] == {"sts": 199}
    # ops never shows IAM use (it only passes roles), and keeps iam:PassRole untouched.
    assert f"{arn('role', 'ops')} inline deploy" not in by_policy
    admin = by_policy["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert admin["kind"] == "aws-managed" and admin["keeps_passrole"]
    assert sorted(admin["affects"]) == [arn("role", "break-glass"), arn("role", "ec2-admin")]
    assert "s3" not in admin["removes"]  # ec2-admin uses S3
    imp = r["impact"]
    assert [(p["start"], p["end"]) for p in imp["closed"]] == [(arn("role", "github-deploy"), arn("role", "ec2-admin"))]
    idle = [p["arn"] for p in r["principals"] if p.get("idle")]
    assert idle == [arn("role", "break-glass"), arn("role", "github-deploy")]
    text = unused_text(r)
    assert "Unless kept for emergencies" in text and "closes: role/github-deploy -> role/ec2-admin" in text


def test_a_shared_policy_loses_only_what_nobody_uses() -> None:
    shared = [{"Effect": "Allow", "Action": ["s3:*", "ec2:*", "sqs:*"], "Resource": "*"}]
    env = account({"a": [], "b": []}, groups={"team": shared}, members={"a": ["team"], "b": ["team"]})
    u = parse_usage(
        usage(
            {
                arn("user", "a"): report(s3=GEN, ec2=None, sqs=None),
                arn("user", "b"): report(s3=None, ec2=GEN, sqs=None),
            }
        )
    )
    [e] = unused_access(env, u)["edits"]
    assert e["kind"] == "group" and e["removes"] == ["sqs"]
    assert e["document"]["Statement"][0]["Action"] == ["s3:*", "ec2:*"]


def test_a_policy_shared_with_someone_without_a_report_is_left_alone() -> None:
    pol = f"arn:aws:iam::{A}:policy/shared"
    env = account(
        {"a": [], "b": []},
        managed={pol: doc({"Effect": "Allow", "Action": "sqs:*", "Resource": "*"})},
        attach={"a": [pol], "b": [pol]},
    )
    r = unused_access(env, parse_usage(usage({arn("user", "a"): report(sqs=None)})))
    assert r["edits"] == []
    assert r["skipped"] == [{"policy": pol, "reason": f"no last accessed report for {arn('user', 'b')}"}]


def test_a_customer_managed_policy_with_nothing_left_is_deleted() -> None:
    pol = f"arn:aws:iam::{A}:policy/old"
    env = account(
        {"a": []}, managed={pol: doc({"Effect": "Allow", "Action": "sqs:*", "Resource": "*"})}, attach={"a": [pol]}
    )
    [e] = unused_access(env, parse_usage(usage({arn("user", "a"): report(sqs=None)})))["edits"]
    assert e["delete"] and e["document"] is None and e["kind"] == "managed"


def test_nothing_unused_means_no_edits() -> None:
    env = account({"a": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    r = unused_access(env, parse_usage(usage({arn("user", "a"): report(s3=GEN)})))
    assert r["edits"] == [] and r["impact"]["paths_before"] == r["impact"]["paths_after"]
    assert "No policy can lose a service" in unused_text(r)


# --- collecting ------------------------------------------------------------------------------------


class FakeIam:
    def __init__(self, ready_after: int = 1, fail: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.polls: dict[str, int] = {}
        self.ready_after, self.fail = ready_after, fail

    def __call__(self, args: list[str]) -> Any:
        self.calls.append(args)
        assert args[0] == "iam" and args[1].startswith(("generate-service-last", "get-service-last"))
        if args[1] == "generate-service-last-accessed-details":
            assert args[args.index("--granularity") + 1] == "ACTION_LEVEL"
            return {"JobId": "job-" + args[args.index("--arn") + 1].rsplit("/", 1)[-1]}
        job = args[args.index("--job-id") + 1]
        if "--marker" in args:
            return {
                "JobStatus": "COMPLETED",
                "ServicesLastAccessed": [{"ServiceNamespace": "sqs"}],
                "IsTruncated": False,
            }
        self.polls[job] = self.polls.get(job, 0) + 1
        if self.fail:
            return {"JobStatus": "FAILED", "Error": {"Message": "denied"}}
        if self.polls[job] < self.ready_after:
            return {"JobStatus": "IN_PROGRESS"}
        return {
            "JobStatus": "COMPLETED",
            "JobCompletionDate": GEN,
            "ServicesLastAccessed": [{"ServiceNamespace": "s3"}],
            "IsTruncated": True,
            "Marker": "m1",
        }


def test_collect_starts_every_job_then_polls_and_pages() -> None:
    fake = FakeIam(ready_after=2)
    waits: list[float] = []
    text = collect_usage(fake, [arn("user", "a"), arn("role", "r")], sleep=waits.append)
    assert [c[1] for c in fake.calls[:2]] == ["generate-service-last-accessed-details"] * 2
    data = json.loads(text)
    assert [s["ServiceNamespace"] for s in data["Reports"][arn("user", "a")]["ServicesLastAccessed"]] == ["s3", "sqs"]
    assert "Marker" not in data["Reports"][arn("user", "a")]
    assert waits == [2]
    assert set(parse_usage(text)) == {arn("user", "a"), arn("role", "r")}


def test_collect_reports_a_failed_job() -> None:
    with pytest.raises(CollectError, match="denied"):
        collect_usage(FakeIam(fail=True), [arn("user", "a")], sleep=lambda s: None)


def test_collect_gives_up_after_a_while() -> None:
    with pytest.raises(CollectError, match="not ready in time"):
        collect_usage(FakeIam(ready_after=99), [arn("user", "a")], sleep=lambda s: None, tries=3)


# --- the command line --------------------------------------------------------------------------------


def test_cli_unused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    args = [
        "unused",
        "--auth-details",
        str(EXAMPLES / "auth-details.json"),
        "--usage",
        str(EXAMPLES / "last-accessed.json"),
    ]
    assert main([*args, "--out-dir", str(tmp_path)]) == 0
    assert "closes: role/github-deploy -> role/ec2-admin" in capsys.readouterr().out
    written = json.loads((tmp_path / "policy-AdministratorAccess.trimmed.json").read_text())
    assert written["Statement"][1] == {"Effect": "Allow", "Resource": "*", "Action": "iam:PassRole"}
    assert main([*args, "--format", "json", "--days", "300"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["days"] == 300
    assert all(e["policy"] != f"{arn('role', 'github-deploy')} inline deploy" for e in data["edits"])


def test_cli_unused_bad_usage_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace.cli import main

    bad = tmp_path / "u.json"
    bad.write_text("{}")
    assert main(["unused", "--auth-details", str(EXAMPLES / "auth-details.json"), "--usage", str(bad)]) == 2
    assert "Reports" in capsys.readouterr().err
