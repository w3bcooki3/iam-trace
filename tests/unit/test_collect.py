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
        data = self.data_answer(service, op, args, r) or self.compute_answer(service, op, args, r)
        if data is not None:
            return data
        if (service, op) in answers:
            return answers[(service, op)]
        raise AssertionError(f"unexpected call {args}")

    def compute_answer(self, service: str, op: str, args: list[str], r: str) -> Any:
        """Batch, ECS, launch templates and Bedrock AgentCore, in us-east-1 only."""
        here = r == "us-east-1"
        role = f"arn:aws:iam::{ACCT}:role"
        if (service, op) == ("batch", "describe-job-definitions"):
            assert args[args.index("--status") + 1] == "ACTIVE"
            jd = f"arn:aws:batch:{r}:{ACCT}:job-definition"
            return {
                "jobDefinitions": [
                    {"jobDefinitionArn": f"{jd}/single:3", "containerProperties": {"jobRoleArn": f"{role}/batch-job"}},
                    {
                        "jobDefinitionArn": f"{jd}/multinode:1",
                        "nodeProperties": {
                            "nodeRangeProperties": [
                                {"container": {"jobRoleArn": f"{role}/node-a"}},
                                {"container": {"jobRoleArn": f"{role}/node-b"}},
                            ]
                        },
                    },
                    {"jobDefinitionArn": f"{jd}/norole:1", "containerProperties": {}},
                ]
                if here
                else []
            }
        if (service, op) == ("ecs", "list-clusters"):
            return {"clusterArns": [f"arn:aws:ecs:{r}:{ACCT}:cluster/main"] if here else []}
        if (service, op) == ("ecs", "list-tasks"):
            return {"taskArns": [f"arn:aws:ecs:{r}:{ACCT}:task/main/t{i}" for i in range(120)]}
        if (service, op) == ("ecs", "describe-tasks"):
            tasks = args[args.index("--tasks") + 1 :]
            assert len(tasks) <= 100
            td = f"arn:aws:ecs:{r}:{ACCT}:task-definition/app:7"
            return {
                "tasks": [
                    {
                        "taskArn": t,
                        "taskDefinitionArn": td,
                        **({"overrides": {"taskRoleArn": f"{role}/override"}} if t.endswith("/t0") else {}),
                    }
                    for t in tasks
                ]
            }
        if (service, op) == ("ecs", "describe-task-definition"):
            self.task_definition_lookups = getattr(self, "task_definition_lookups", 0) + 1
            return {"taskDefinition": {"taskRoleArn": f"{role}/app-task"}}
        if (service, op) == ("ec2", "describe-launch-templates"):
            return {
                "LaunchTemplates": [{"LaunchTemplateId": "lt-arn"}, {"LaunchTemplateId": "lt-name"}] if here else []
            }
        if (service, op) == ("ec2", "describe-launch-template-versions"):
            assert args[args.index("--versions") + 1] == "$Default"
            tid = args[args.index("--launch-template-id") + 1]
            profile = (
                {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/web"} if tid == "lt-arn" else {"Name": "batch-hosts"}
            )
            return {"LaunchTemplateVersions": [{"LaunchTemplateData": {"IamInstanceProfile": profile}}]}
        ac = f"arn:aws:bedrock-agentcore:{r}"
        if (service, op) == ("bedrock-agentcore-control", "list-agent-runtimes"):
            return {
                "agentRuntimes": [{"agentRuntimeId": "rt1", "agentRuntimeArn": f"{ac}:{ACCT}:runtime/rt1"}]
                if here
                else []
            }
        if (service, op) == ("bedrock-agentcore-control", "get-agent-runtime"):
            return {"roleArn": f"{role}/agent"}
        if (service, op) == ("bedrock-agentcore-control", "list-code-interpreters"):
            return {
                "codeInterpreterSummaries": [
                    {
                        "codeInterpreterId": "aws.codeinterpreter.v1",
                        "codeInterpreterArn": f"{ac}:aws:code-interpreter/aws.codeinterpreter.v1",
                    },
                    {"codeInterpreterId": "ci1", "codeInterpreterArn": f"{ac}:{ACCT}:code-interpreter-custom/ci1"},
                ]
                if here
                else []
            }
        if (service, op) == ("bedrock-agentcore-control", "get-code-interpreter"):
            assert args[args.index("--code-interpreter-id") + 1] == "ci1"
            return {"executionRoleArn": f"{role}/interpreter"}
        if (service, op) == ("bedrock-agentcore-control", "list-browsers"):
            return {"browserSummaries": []}
        return None

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
        # Secrets, tables, topics and queues: one of each in us-east-1, none in other regions.
        here = region == "us-east-1"
        sm = f"arn:aws:secretsmanager:{region}:{ACCT}:secret"
        if (service, op) == ("secretsmanager", "list-secrets"):
            return {
                "SecretList": [{"ARN": f"{sm}:db-AbCdEf", "KmsKeyId": "k1"}, {"ARN": f"{sm}:plain-123456"}]
                if here
                else []
            }
        if (service, op) == ("secretsmanager", "get-resource-policy"):
            secret = args[args.index("--secret-id") + 1]
            return {
                "ARN": secret,
                **({"ResourcePolicy": '{"Version":"2012-10-17","Statement":[]}'} if "db-" in secret else {}),
            }
        if (service, op) == ("dynamodb", "list-tables"):
            return {"TableNames": ["orders", "cache"] if here else []}
        if (service, op) == ("dynamodb", "describe-table"):
            name = args[args.index("--table-name") + 1]
            table: dict[str, Any] = {"TableArn": f"arn:aws:dynamodb:{region}:{ACCT}:table/{name}"}
            if name == "orders":
                table["SSEDescription"] = {
                    "Status": "ENABLED",
                    "SSEType": "KMS",
                    "KMSMasterKeyArn": f"arn:aws:kms:{region}:{ACCT}:key/k1",
                }
            return {"Table": table}
        if (service, op) == ("dynamodb", "get-resource-policy"):
            if args[args.index("--resource-arn") + 1].endswith("/cache"):
                raise CollectError("An error occurred (PolicyNotFoundException) when calling GetResourcePolicy")
            return {"Policy": '{"Version":"2012-10-17","Statement":[]}', "RevisionId": "1"}
        if (service, op) == ("sns", "list-topics"):
            return {"Topics": [{"TopicArn": f"arn:aws:sns:{region}:{ACCT}:alerts"}] if here else []}
        if (service, op) == ("sns", "get-topic-attributes"):
            return {"Attributes": {"Policy": '{"Version":"2012-10-17","Statement":[]}', "KmsMasterKeyId": "aws1"}}
        if (service, op) == ("sqs", "list-queues"):
            return {"QueueUrls": [f"https://sqs.{region}.amazonaws.com/{ACCT}/jobs"] if here else []}
        if (service, op) == ("sqs", "get-queue-attributes"):
            return {
                "Attributes": {
                    "QueueArn": f"arn:aws:sqs:{region}:{ACCT}:jobs",
                    "KmsMasterKeyId": "alias/aws/sqs",
                    "SqsManagedSseEnabled": "false",
                }
            }
        if (service, op) == ("kms", "list-keys"):
            return {"Keys": [{"KeyId": "k1"}, {"KeyId": "aws1"}] if region == "us-east-1" else []}
        if (service, op) == ("kms", "describe-key"):
            key_id = args[args.index("--key-id") + 1]
            manager = "CUSTOMER" if key_id.rsplit("/", 1)[-1] == "k1" else "AWS"
            key_id = key_id.rsplit("/", 1)[-1]
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


def test_collects_batch_ecs_launch_templates_and_agentcore() -> None:
    aws = FakeAws()
    kinds = ["batch-job-definition", "ecs-task", "ec2-launch-template", "agentcore-resource"]
    inv = collect(aws, regions=["us-east-1"], kinds=kinds)
    assert inv["Collected"] == kinds and inv["Errors"] == []
    got = {(r["Arn"].split(":", 5)[5], r.get("Role", "").rsplit("/", 1)[-1]) for r in inv["Resources"]}
    # A job definition with several roles is listed once per role; one with none, without a role.
    assert ("job-definition/single:3", "batch-job") in got
    assert {("job-definition/multinode:1", "node-a"), ("job-definition/multinode:1", "node-b")} <= got
    assert ("job-definition/norole:1", "") in got
    # A task's own override wins over its task definition, which is looked up once.
    assert ("task/main/t0", "override") in got and ("task/main/t1", "app-task") in got
    assert sum(1 for a, _ in got if a.startswith("task/")) == 120
    assert aws.task_definition_lookups == 1
    # A launch template's profile, given by ARN or only by name.
    assert ("launch-template/lt-arn", "web") in got and ("launch-template/lt-name", "batch-hosts") in got
    # AgentCore: the account's runtime and custom interpreter; AWS's built-in one is skipped.
    assert ("runtime/rt1", "agent") in got and ("code-interpreter-custom/ci1", "interpreter") in got
    assert all("aws.codeinterpreter" not in a for a, _ in got)
    assert all(kind_of(r["Arn"]) for r in inv["Resources"])


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


def test_collects_secrets_tables_topics_and_queues() -> None:
    from iamtrace.escalate import Environment
    from iamtrace.inventory import load_inventory

    kinds = ["secretsmanager-secret", "dynamodb-table", "sns-topic", "sqs-queue"]
    aws = FakeAws()
    inv = collect(aws, regions=["us-east-1", "eu-west-1"], kinds=kinds)
    assert inv["Collected"] == kinds
    assert inv["Errors"] == []
    by_arn = {r["Arn"]: r for r in inv["Resources"]}
    key = f"arn:aws:kms:us-east-1:{ACCT}:key/k1"
    secret = by_arn[f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:db-AbCdEf"]
    assert secret["KmsKey"] == key and "Policy" in secret
    plain = by_arn[f"arn:aws:secretsmanager:us-east-1:{ACCT}:secret:plain-123456"]
    assert plain == {"Arn": plain["Arn"]}  # no key of its own: the AWS managed key; no policy
    orders = by_arn[f"arn:aws:dynamodb:us-east-1:{ACCT}:table/orders"]
    assert orders["KmsKey"] == key and "Policy" in orders
    assert set(by_arn[f"arn:aws:dynamodb:us-east-1:{ACCT}:table/cache"]) == {"Arn"}
    assert by_arn[f"arn:aws:sns:us-east-1:{ACCT}:alerts"]["KmsKey"] == "alias/aws/sns"  # an AWS managed key
    assert by_arn[f"arn:aws:sqs:us-east-1:{ACCT}:jobs"]["KmsKey"] == "alias/aws/sqs"
    # Each key is described once, however many resources use it.
    described = [c for c in aws.calls if c[:2] == ["kms", "describe-key"]]
    assert len(described) == len({tuple(c) for c in described})
    for call in aws.calls:
        assert call[1].split("-")[0] in ("list", "describe", "get"), call
    env = Environment.from_auth_details(
        {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    )
    loaded = load_inventory(inv, env)
    assert loaded.warnings == []
    assert {r.kind for r in loaded.resources} == set(kinds)


def test_queue_with_sqs_managed_encryption_has_no_key() -> None:
    from iamtrace.collect import _queues

    def run(args: list[str]) -> Any:
        if args[1] == "list-queues":
            return {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/1/q"]}
        return {"Attributes": {"QueueArn": f"arn:aws:sqs:us-east-1:{ACCT}:q", "SqsManagedSseEnabled": "true"}}

    assert _queues(run, "us-east-1", ACCT, "aws") == [{"Arn": f"arn:aws:sqs:us-east-1:{ACCT}:q"}]


def test_a_key_that_cannot_be_described_is_kept_as_given() -> None:
    from iamtrace.collect import _key_ref

    def run(args: list[str]) -> Any:
        raise CollectError("An error occurred (AccessDeniedException) when calling DescribeKey")

    other = "arn:aws:kms:us-east-1:444455556666:key/x"
    assert _key_ref(run, "us-east-1", other, "sqs", {}) == other
    assert _key_ref(run, "us-east-1", "alias/aws/sqs", "sqs", {}) == "alias/aws/sqs"
