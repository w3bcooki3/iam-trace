"""`iam-trace inventory collect`: list existing resources and their roles with the AWS CLI.

Read-only: every call is a List*, Describe*, Get* or BatchGet* call, which the AWS managed
policies ReadOnlyAccess and SecurityAudit allow. iam-trace itself never talks to AWS: it runs the
`aws` command you already have configured, with the profile you choose, so credentials stay
with the AWS CLI.

A kind is listed under "Collected" only if it was collected in every region without an error.
If a call fails (no permission, a service not offered in a region), the error is recorded and
the kind is left out, so the analysis keeps treating it as unknown instead of empty.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

Runner = Callable[[list[str]], Any]

_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")


class CollectError(RuntimeError):
    pass


def aws_cli(profile: str | None = None) -> Runner:
    """A runner that calls the AWS CLI and returns its parsed JSON output."""
    exe = shutil.which("aws")
    if exe is None:
        raise CollectError("the AWS CLI (aws) is not installed or not on PATH")

    def run(args: list[str]) -> Any:
        cmd = [exe, *args, "--output", "json", "--no-cli-pager"]
        if profile:
            cmd += ["--profile", profile]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            # The AWS CLI puts the useful part ("An error occurred (AccessDenied) ...") last.
            message = (proc.stderr or proc.stdout or "").strip().splitlines()
            raise CollectError(message[-1] if message else f"aws exited with {proc.returncode}")
        try:
            return json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            raise CollectError(f"aws returned something other than JSON: {e}") from e

    return run


# --- one function per kind: (runner, region, account, partition) -> [(arn, role)] ----------


def _lambda(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    out = run(["lambda", "list-functions", "--region", region])
    return [(f["FunctionArn"], f.get("Role")) for f in out.get("Functions", [])]


def _ec2(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    out = run(["ec2", "describe-instances", "--region", region])
    found = []
    for res in out.get("Reservations", []):
        owner = res.get("OwnerId", account)
        for i in res.get("Instances", []):
            if i.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                continue
            arn = f"arn:{partition}:ec2:{region}:{owner}:instance/{i['InstanceId']}"
            found.append((arn, (i.get("IamInstanceProfile") or {}).get("Arn")))
    return found


def _codebuild(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    names = run(["codebuild", "list-projects", "--region", region]).get("projects", [])
    found = []
    for i in range(0, len(names), 100):  # BatchGetProjects takes at most 100 names
        out = run(["codebuild", "batch-get-projects", "--region", region, "--names", *names[i : i + 100]])
        found += [(p["arn"], p.get("serviceRole")) for p in out.get("projects", [])]
    return found


def _cloudformation(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    out = run(["cloudformation", "describe-stacks", "--region", region])
    # A stack without RoleARN runs with the caller's own credentials: there is no role to gain.
    return [
        (s["StackId"], s.get("RoleARN")) for s in out.get("Stacks", []) if s.get("StackStatus") != "DELETE_COMPLETE"
    ]


def _glue(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    out = run(["glue", "get-dev-endpoints", "--region", region])
    return [
        (f"arn:{partition}:glue:{region}:{account}:devEndpoint/{e['EndpointName']}", e.get("RoleArn"))
        for e in out.get("DevEndpoints", [])
    ]


def _sagemaker(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    found = []
    for nb in run(["sagemaker", "list-notebook-instances", "--region", region]).get("NotebookInstances", []):
        d = run(
            [
                "sagemaker",
                "describe-notebook-instance",
                "--region",
                region,
                "--notebook-instance-name",
                nb["NotebookInstanceName"],
            ]
        )
        found.append((nb["NotebookInstanceArn"], d.get("RoleArn")))
    return found


def _states(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    found = []
    for sm in run(["stepfunctions", "list-state-machines", "--region", region]).get("stateMachines", []):
        d = run(
            [
                "stepfunctions",
                "describe-state-machine",
                "--region",
                region,
                "--state-machine-arn",
                sm["stateMachineArn"],
            ]
        )
        found.append((sm["stateMachineArn"], d.get("roleArn")))
    return found


def _apprunner(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    found = []
    for s in run(["apprunner", "list-services", "--region", region]).get("ServiceSummaryList", []):
        d = run(["apprunner", "describe-service", "--region", region, "--service-arn", s["ServiceArn"]])
        role = ((d.get("Service") or {}).get("InstanceConfiguration") or {}).get("InstanceRoleArn")
        found.append((s["ServiceArn"], role))
    return found


def _batch(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    """Active job definitions and the role each one's jobs run as (one entry per role)."""
    found: list[tuple[str, str | None]] = []
    out = run(["batch", "describe-job-definitions", "--status", "ACTIVE", "--region", region])
    for d in out.get("jobDefinitions", []):
        roles = [(d.get("containerProperties") or {}).get("jobRoleArn")]
        roles += [
            (n.get("container") or {}).get("jobRoleArn")
            for n in (d.get("nodeProperties") or {}).get("nodeRangeProperties") or []
        ]
        roles += [t.get("taskRoleArn") for t in (d.get("ecsProperties") or {}).get("taskProperties") or []]
        named = sorted({r for r in roles if r})
        found += [(d["jobDefinitionArn"], r) for r in named] or [(d["jobDefinitionArn"], None)]
    return found


def _ecs(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    """Running ECS tasks and their task role (a task's override, else its task definition's)."""
    found: list[tuple[str, str | None]] = []
    definitions: dict[str, str | None] = {}
    for cluster in run(["ecs", "list-clusters", "--region", region]).get("clusterArns", []):
        arns = run(["ecs", "list-tasks", "--region", region, "--cluster", cluster]).get("taskArns", [])
        for i in range(0, len(arns), 100):  # DescribeTasks takes at most 100 tasks
            out = run(
                ["ecs", "describe-tasks", "--region", region, "--cluster", cluster, "--tasks", *arns[i : i + 100]]
            )
            for t in out.get("tasks", []):
                role = (t.get("overrides") or {}).get("taskRoleArn")
                if not role and t.get("taskDefinitionArn"):
                    td = t["taskDefinitionArn"]
                    if td not in definitions:
                        d = run(["ecs", "describe-task-definition", "--region", region, "--task-definition", td])
                        definitions[td] = (d.get("taskDefinition") or {}).get("taskRoleArn")
                    role = definitions[td]
                found.append((t["taskArn"], role))
    return found


def _launch_templates(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    """Launch templates and the instance profile of each one's default version."""
    found: list[tuple[str, str | None]] = []
    for lt in run(["ec2", "describe-launch-templates", "--region", region]).get("LaunchTemplates", []):
        tid = lt["LaunchTemplateId"]
        out = run(
            [
                "ec2",
                "describe-launch-template-versions",
                "--region",
                region,
                "--launch-template-id",
                tid,
                "--versions",
                "$Default",
            ]
        )
        versions = out.get("LaunchTemplateVersions", [])
        profile = (versions[0].get("LaunchTemplateData") or {}).get("IamInstanceProfile") or {} if versions else {}
        role = profile.get("Arn")
        if not role and profile.get("Name"):
            role = f"arn:{partition}:iam::{account}:instance-profile/{profile['Name']}"
        found.append((f"arn:{partition}:ec2:{region}:{account}:launch-template/{tid}", role))
    return found


def _aws_owned(arn: str) -> bool:
    """AWS's own AgentCore resources have "aws" where the account ID would be."""
    parts = arn.split(":")
    return len(parts) > 4 and parts[4] == "aws"


def _agentcore(run: Runner, region: str, account: str, partition: str) -> list[tuple[str, str | None]]:
    """Bedrock AgentCore agent runtimes, and custom code interpreters and browsers, with their roles."""
    found: list[tuple[str, str | None]] = []
    ctl = "bedrock-agentcore-control"
    for r in run([ctl, "list-agent-runtimes", "--region", region]).get("agentRuntimes", []):
        d = run([ctl, "get-agent-runtime", "--region", region, "--agent-runtime-id", r["agentRuntimeId"]])
        found.append((r["agentRuntimeArn"], d.get("roleArn")))
    for c in run([ctl, "list-code-interpreters", "--region", region]).get("codeInterpreterSummaries", []):
        if _aws_owned(c["codeInterpreterArn"]):
            continue  # AWS's built-in interpreter: no role of the account's
        d = run([ctl, "get-code-interpreter", "--region", region, "--code-interpreter-id", c["codeInterpreterId"]])
        found.append((c["codeInterpreterArn"], d.get("executionRoleArn")))
    for b in run([ctl, "list-browsers", "--region", region]).get("browserSummaries", []):
        if _aws_owned(b["browserArn"]):
            continue
        d = run([ctl, "get-browser", "--region", region, "--browser-id", b["browserId"]])
        found.append((b["browserArn"], d.get("executionRoleArn")))
    return found


COLLECTORS: dict[str, Callable[[Runner, str, str, str], list[tuple[str, str | None]]]] = {
    "lambda-function": _lambda,
    "ec2-instance": _ec2,
    "codebuild-project": _codebuild,
    "cloudformation-stack": _cloudformation,
    "glue-dev-endpoint": _glue,
    "sagemaker-notebook": _sagemaker,
    "state-machine": _states,
    "apprunner-service": _apprunner,
    "batch-job-definition": _batch,
    "ecs-task": _ecs,
    "ec2-launch-template": _launch_templates,
    "agentcore-resource": _agentcore,
}


# --- data: buckets and keys, with their resource policies ---------------------------------------


def _missing(e: CollectError, *codes: str) -> bool:
    """An AWS error that means "there is none", such as NoSuchBucketPolicy."""
    return any(c in str(e) for c in codes)


def _buckets(run: Runner, account: str, partition: str) -> list[dict[str, Any]]:
    """Every bucket with its policy, default KMS key and Block Public Access (bucket and account)."""
    try:
        acct_pab = run(["s3control", "get-public-access-block", "--account-id", account]).get(
            "PublicAccessBlockConfiguration", {}
        )
    except CollectError as e:
        if not _missing(e, "NoSuchPublicAccessBlockConfiguration"):
            raise
        acct_pab = {}
    out = []
    for b in run(["s3api", "list-buckets"]).get("Buckets", []):
        name = b["Name"]
        item: dict[str, Any] = {"Arn": f"arn:{partition}:s3:::{name}"}
        try:
            item["Policy"] = run(["s3api", "get-bucket-policy", "--bucket", name])["Policy"]
        except CollectError as e:
            if not _missing(e, "NoSuchBucketPolicy"):
                raise
        try:
            rules = run(["s3api", "get-bucket-encryption", "--bucket", name])["ServerSideEncryptionConfiguration"][
                "Rules"
            ]
            for rule in rules:
                default = rule.get("ApplyServerSideEncryptionByDefault", {})
                if default.get("SSEAlgorithm", "").startswith("aws:kms") and default.get("KMSMasterKeyID"):
                    item["KmsKey"] = default["KMSMasterKeyID"]
        except CollectError as e:
            if not _missing(e, "ServerSideEncryptionConfigurationNotFoundError"):
                raise
        try:
            pab = run(["s3api", "get-public-access-block", "--bucket", name]).get("PublicAccessBlockConfiguration", {})
        except CollectError as e:
            if not _missing(e, "NoSuchPublicAccessBlockConfiguration"):
                raise
            pab = {}
        merged = {k: bool(pab.get(k)) or bool(acct_pab.get(k)) for k in set(pab) | set(acct_pab)}
        if merged:
            item["PublicAccessBlock"] = merged
        out.append(item)
    return out


def _keys(run: Runner, region: str) -> list[dict[str, Any]]:
    """Customer managed KMS keys in a region, with their key policy."""
    out = []
    for k in run(["kms", "list-keys", "--region", region]).get("Keys", []):
        meta = run(["kms", "describe-key", "--key-id", k["KeyId"], "--region", region])["KeyMetadata"]
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") == "PendingDeletion":
            continue
        pol = run(["kms", "get-key-policy", "--key-id", k["KeyId"], "--policy-name", "default", "--region", region])
        out.append({"Arn": meta["Arn"], "Policy": pol["Policy"]})
    return out


DATA_KINDS = ("s3-bucket", "kms-key")


def collect(
    run: Runner,
    regions: list[str] | None = None,
    kinds: list[str] | None = None,
    log: Callable[[str], None] = lambda _: None,
) -> dict[str, Any]:
    who = run(["sts", "get-caller-identity"])
    account = who["Account"]
    partition = who["Arn"].split(":")[1]
    if not regions:
        regions = sorted(
            r["RegionName"] for r in run(["ec2", "describe-regions", "--region", "us-east-1"]).get("Regions", [])
        )
    for r in regions:
        if not _REGION.match(r):
            raise CollectError(f"not a region name: {r!r}")
    wanted = kinds or [*COLLECTORS, *DATA_KINDS]
    for k in wanted:
        if k not in COLLECTORS and k not in DATA_KINDS:
            raise CollectError(f"unknown kind {k!r}; choose from {', '.join([*COLLECTORS, *DATA_KINDS])}")

    resources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    collected = []
    if "s3-bucket" in wanted:
        try:
            buckets = _buckets(run, account, partition)
            resources += buckets
            collected.append("s3-bucket")
            log(f"s3-bucket: {len(buckets)}")
        except (CollectError, KeyError, TypeError, ValueError) as e:
            errors.append({"kind": "s3-bucket", "region": "global", "error": str(e)[:300]})
            log(f"s3-bucket: {e}")
    if "kms-key" in wanted:
        ok = True
        for region in regions:
            try:
                keys = _keys(run, region)
            except (CollectError, KeyError, TypeError, ValueError) as e:
                ok = False
                errors.append({"kind": "kms-key", "region": region, "error": str(e)[:300]})
                log(f"kms-key in {region}: {e}")
                continue
            resources += keys
            log(f"kms-key in {region}: {len(keys)}")
        if ok:
            collected.append("kms-key")
    for kind in [k for k in wanted if k in COLLECTORS]:
        ok = True
        for region in regions:
            try:
                items = COLLECTORS[kind](run, region, account, partition)
            except (CollectError, KeyError, TypeError, ValueError) as e:
                ok = False
                errors.append({"kind": kind, "region": region, "error": str(e)[:300]})
                log(f"{kind} in {region}: {e}")
                continue
            for arn, role in items:
                resources.append({"Arn": arn, **({"Role": role} if role else {})})
            log(f"{kind} in {region}: {len(items)}")
        if ok:
            collected.append(kind)
    return {
        "Version": 1,
        "Account": account,
        "Regions": regions,
        "Collected": collected,
        "Resources": resources,
        "Errors": errors,
    }
