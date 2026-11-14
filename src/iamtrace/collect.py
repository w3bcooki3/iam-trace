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


COLLECTORS: dict[str, Callable[[Runner, str, str, str], list[tuple[str, str | None]]]] = {
    "lambda-function": _lambda,
    "ec2-instance": _ec2,
    "codebuild-project": _codebuild,
    "cloudformation-stack": _cloudformation,
    "glue-dev-endpoint": _glue,
    "sagemaker-notebook": _sagemaker,
    "state-machine": _states,
    "apprunner-service": _apprunner,
}


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
    wanted = kinds or list(COLLECTORS)
    for k in wanted:
        if k not in COLLECTORS:
            raise CollectError(f"unknown kind {k!r}; choose from {', '.join(COLLECTORS)}")

    resources: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    collected = []
    for kind in wanted:
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
