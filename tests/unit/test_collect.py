"""The inventory collector, driven by a fake AWS CLI (no network, no credentials)."""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.collect import COLLECTORS, CollectError, collect
from iamtrace.inventory import KINDS, kind_of

ACCT = "111122223333"


class FakeAws:
    """Answers the calls the collector makes; anything unexpected fails the test."""

    def __init__(self, fail: set[tuple[str, str]] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail or set()

    def __call__(self, args: list[str]) -> Any:
        self.calls.append(args)
        service, op = args[0], args[1]
        region = args[args.index("--region") + 1] if "--region" in args else ""
        if (service, region) in self.fail:
            raise CollectError("An error occurred (AccessDeniedException) when calling the operation")
        if (service, op) == ("sts", "get-caller-identity"):
            return {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/auditor"}
        if (service, op) == ("ec2", "describe-regions"):
            return {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]}
        r = region
        answers: dict[tuple[str, str], Any] = {
            ("lambda", "list-functions"): {
                "Functions": [
                    {"FunctionArn": f"arn:aws:lambda:{r}:{ACCT}:function:f-{r}", "Role": f"arn:aws:iam::{ACCT}:role/fn"}
                ]
            },
            ("ec2", "describe-instances"): {
                "Reservations": [
                    {
                        "OwnerId": ACCT,
                        "Instances": [
                            {
                                "InstanceId": "i-1",
                                "State": {"Name": "running"},
                                "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/web"},
                            },
                            {"InstanceId": "i-2", "State": {"Name": "terminated"}},
                            {"InstanceId": "i-3", "State": {"Name": "stopped"}},
                        ],
                    }
                ]
            },
            ("codebuild", "list-projects"): {"projects": [f"p{i}" for i in range(150)] if r == "us-east-1" else []},
            ("cloudformation", "describe-stacks"): {
                "Stacks": [
                    {
                        "StackId": f"arn:aws:cloudformation:{r}:{ACCT}:stack/s/1",
                        "RoleARN": f"arn:aws:iam::{ACCT}:role/cfn",
                        "StackStatus": "CREATE_COMPLETE",
                    },
                    {"StackId": f"arn:aws:cloudformation:{r}:{ACCT}:stack/t/2", "StackStatus": "UPDATE_COMPLETE"},
                ]
            },
            ("glue", "get-dev-endpoints"): {"DevEndpoints": []},
            ("sagemaker", "list-notebook-instances"): {
                "NotebookInstances": [
                    {
                        "NotebookInstanceName": "nb",
                        "NotebookInstanceArn": f"arn:aws:sagemaker:{r}:{ACCT}:notebook-instance/nb",
                    }
                ]
            },
            ("sagemaker", "describe-notebook-instance"): {"RoleArn": f"arn:aws:iam::{ACCT}:role/sm"},
            ("stepfunctions", "list-state-machines"): {"stateMachines": []},
            ("apprunner", "list-services"): {"ServiceSummaryList": []},
        }
        if (service, op) == ("codebuild", "batch-get-projects"):
            names = args[args.index("--names") + 1 :]
            assert len(names) <= 100
            return {
                "projects": [
                    {"arn": f"arn:aws:codebuild:{r}:{ACCT}:project/{n}", "serviceRole": f"arn:aws:iam::{ACCT}:role/cb"}
                    for n in names
                ]
            }
        if (service, op) in answers:
            return answers[(service, op)]
        raise AssertionError(f"unexpected call {args}")


def test_collector_for_every_kind() -> None:
    assert set(COLLECTORS) == set(KINDS)


def test_collects_every_region_and_kind() -> None:
    aws = FakeAws()
    inv = collect(aws)
    assert inv["Account"] == ACCT
    assert inv["Regions"] == ["eu-west-1", "us-east-1"]
    assert inv["Collected"] == list(COLLECTORS)
    assert inv["Errors"] == []
    arns = [r["Arn"] for r in inv["Resources"]]
    assert all(kind_of(a) for a in arns), [a for a in arns if not kind_of(a)]
    assert sum(1 for a in arns if ":codebuild:" in a) == 150  # two BatchGetProjects calls
    assert f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-2" not in arns  # terminated
    stack_without_role = next(r for r in inv["Resources"] if r["Arn"].endswith("stack/t/2"))
    assert "Role" not in stack_without_role
    # Read-only: every call lists, describes or gets.
    for call in aws.calls:
        assert call[1].split("-")[0] in ("list", "describe", "get", "batch"), call


def test_a_failed_region_leaves_the_kind_uncollected() -> None:
    inv = collect(FakeAws(fail={("apprunner", "eu-west-1")}), regions=["us-east-1", "eu-west-1"])
    assert "apprunner-service" not in inv["Collected"]
    assert "lambda-function" in inv["Collected"]
    assert inv["Errors"] == [
        {
            "kind": "apprunner-service",
            "region": "eu-west-1",
            "error": "An error occurred (AccessDeniedException) when calling the operation",
        }
    ]


def test_choose_kinds_and_regions() -> None:
    aws = FakeAws()
    inv = collect(aws, regions=["us-east-1"], kinds=["lambda-function"])
    assert inv["Collected"] == ["lambda-function"]
    assert not any(c[0] == "ec2" for c in aws.calls)


@pytest.mark.parametrize("regions", [["us-east-1; rm -rf /"], ["--profile"], [""]])
def test_rejects_bad_region_names(regions: list[str]) -> None:
    with pytest.raises(CollectError):
        collect(FakeAws(), regions=regions)


def test_rejects_unknown_kind() -> None:
    with pytest.raises(CollectError):
        collect(FakeAws(), regions=["us-east-1"], kinds=["spaceship"])


def test_cli_collect_writes_a_file_the_analysis_reads(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from iamtrace import cli
    from iamtrace.escalate import Environment
    from iamtrace.inventory import load_inventory

    monkeypatch.setattr(cli, "aws_cli", lambda profile=None: FakeAws())
    out = tmp_path / "inv.json"
    assert cli.main(["inventory", "collect", "--regions", "us-east-1", "--out", str(out)]) == 0
    assert "resources; collected:" in capsys.readouterr().err
    env = Environment.from_auth_details({"UserDetailList": [], "RoleDetailList": []})
    inv = load_inventory(json.loads(out.read_text()), env)
    assert "lambda-function" in inv.collected and inv.of_kind("lambda-function")


def test_cli_without_aws_cli(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from iamtrace import cli
    from iamtrace import collect as collect_mod

    monkeypatch.setattr(collect_mod.shutil, "which", lambda _: None)
    assert cli.main(["inventory", "collect", "--regions", "us-east-1"]) == 2
    assert "AWS CLI" in capsys.readouterr().err
