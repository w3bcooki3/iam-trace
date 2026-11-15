"""The inventory collector, driven by a fake AWS CLI (no network, no credentials)."""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.collect import COLLECTORS, DATA_KINDS, CollectError, collect
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
        data = self.data_answer(service, op, args, r)
        if data is not None:
            return data
        if (service, op) in answers:
            return answers[(service, op)]
        raise AssertionError(f"unexpected call {args}")

    def data_answer(self, service: str, op: str, args: list[str], region: str) -> Any:
        """Two buckets (one with a policy, KMS encryption and Block Public Access) and one key."""
        missing = {
            "get-bucket-policy": "NoSuchBucketPolicy",
            "get-bucket-encryption": "ServerSideEncryptionConfigurationNotFoundError",
            "get-public-access-block": "NoSuchPublicAccessBlockConfiguration",
        }
        bucket = args[args.index("--bucket") + 1] if "--bucket" in args else ""
        if (service, op) == ("s3control", "get-public-access-block"):
            raise CollectError("An error occurred (NoSuchPublicAccessBlockConfiguration)")
        if (service, op) == ("s3api", "list-buckets"):
            return {"Buckets": [{"Name": "reports"}, {"Name": "logs"}]}
        if service == "s3api" and bucket == "logs":
            raise CollectError(f"An error occurred ({missing[op]})")
        if (service, op) == ("s3api", "get-bucket-policy"):
            return {"Policy": '{"Version":"2012-10-17","Statement":[]}'}
        if (service, op) == ("s3api", "get-bucket-encryption"):
            key = f"arn:aws:kms:us-east-1:{ACCT}:key/k1"
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key}}
                    ]
                }
            }
        if (service, op) == ("s3api", "get-public-access-block"):
            return {"PublicAccessBlockConfiguration": {"BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
        if (service, op) == ("kms", "list-keys"):
            return {"Keys": [{"KeyId": "k1"}, {"KeyId": "aws1"}] if region == "us-east-1" else []}
        if (service, op) == ("kms", "describe-key"):
            key_id = args[args.index("--key-id") + 1]
            manager = "CUSTOMER" if key_id == "k1" else "AWS"
            return {"KeyMetadata": {"Arn": f"arn:aws:kms:{region}:{ACCT}:key/{key_id}", "KeyManager": manager}}
        if (service, op) == ("kms", "get-key-policy"):
            return {"Policy": '{"Version":"2012-10-17","Statement":[]}'}
        return None


def test_collector_for_every_kind() -> None:
    assert set(COLLECTORS) | set(DATA_KINDS) == set(KINDS)


def test_collects_every_region_and_kind() -> None:
    aws = FakeAws()
    inv = collect(aws)
    assert inv["Account"] == ACCT
    assert inv["Regions"] == ["eu-west-1", "us-east-1"]
    assert inv["Collected"] == [*DATA_KINDS, *COLLECTORS]
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


def test_collects_buckets_and_keys_with_their_policies() -> None:
    from iamtrace.escalate import Environment
    from iamtrace.inventory import load_inventory

    inv = collect(FakeAws(), regions=["us-east-1"], kinds=["s3-bucket", "kms-key"])
    assert inv["Collected"] == ["s3-bucket", "kms-key"]
    by_arn = {r["Arn"]: r for r in inv["Resources"]}
    reports = by_arn["arn:aws:s3:::reports"]
    assert reports["KmsKey"].endswith("key/k1")
    assert reports["PublicAccessBlock"]["RestrictPublicBuckets"] is True
    assert "Policy" in reports
    assert set(by_arn["arn:aws:s3:::logs"]) == {"Arn"}  # no policy, no encryption, no block: all "missing"
    assert [a for a in by_arn if ":kms:" in a] == [f"arn:aws:kms:us-east-1:{ACCT}:key/k1"]  # AWS managed skipped
    env = Environment.from_auth_details(
        {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    )
    loaded = load_inventory(inv, env)
    assert loaded.find("arn:aws:s3:::reports").kms_key.endswith("key/k1")  # type: ignore[union-attr]
