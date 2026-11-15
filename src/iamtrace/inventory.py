"""Resource inventory: existing compute resources and the role each one runs as.

The IAM export says nothing about which Lambda functions, EC2 instances, CodeBuild projects
and so on exist. Techniques that abuse an existing resource ("existing-passrole" in
pathfinding.cloud, such as editing an existing function's code to act as its role) are therefore
"possible" without an inventory. With one, each technique is checked against every resource of
the right kind, using the resource's own ARN, so resource-scoped Allows and Denies count:

- a resource the principal can act on, whose role is known, makes the finding confirmed and
  adds an edge to that role;
- if the kind was collected and no resource is reachable, the technique is ruled out;
- if the kind was not collected (or collection failed), the finding stays possible.

File format (written by `iam-trace inventory collect`, or by hand):

    {
      "Version": 1,
      "Collected": ["lambda-function", "ec2-instance"],
      "Resources": [
        {"Arn": "arn:aws:lambda:us-east-1:111122223333:function:billing",
         "Role": "arn:aws:iam::111122223333:role/billing"},
        {"Arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc",
         "Role": "arn:aws:iam::111122223333:instance-profile/web"}
      ]
    }

"Collected" lists the kinds that were collected completely; a kind missing from it is treated
as unknown, never as empty. "Role" may be an instance profile ARN; it is resolved to its role
through the account export.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from iamtrace.model import PolicyError

if TYPE_CHECKING:
    from iamtrace.escalate import Environment


@dataclass(frozen=True)
class Kind:
    service: str  # the ARN's service field
    prefix: str  # how the ARN's resource field starts
    label: str  # for people: "Lambda functions"


KINDS: dict[str, Kind] = {
    "lambda-function": Kind("lambda", "function:", "Lambda functions"),
    "ec2-instance": Kind("ec2", "instance/", "EC2 instances"),
    "codebuild-project": Kind("codebuild", "project/", "CodeBuild projects"),
    "cloudformation-stack": Kind("cloudformation", "stack/", "CloudFormation stacks"),
    "glue-dev-endpoint": Kind("glue", "devEndpoint/", "Glue development endpoints"),
    "sagemaker-notebook": Kind("sagemaker", "notebook-instance/", "SageMaker notebook instances"),
    "state-machine": Kind("states", "stateMachine:", "Step Functions state machines"),
    "apprunner-service": Kind("apprunner", "service/", "App Runner services"),
    # Data, for iamtrace.data: no role, but a resource policy (and for a bucket, its default
    # encryption key and Block Public Access settings).
    "s3-bucket": Kind("s3", "", "S3 buckets"),
    "kms-key": Kind("kms", "key/", "KMS keys"),
}
DATA_KINDS = ("s3-bucket", "kms-key")

# Existing-resource techniques that act on one resource of a known kind with all of their
# permissions. Techniques left out (launch templates, Batch, CodeDeploy, ECS tasks, Bedrock
# AgentCore) act on more than one resource or on short-lived ones, and stay "possible".
TECHNIQUE_KIND: dict[str, str] = {
    "lambda-003": "lambda-function",
    "lambda-004": "lambda-function",
    "lambda-005": "lambda-function",
    "ec2-002": "ec2-instance",
    "ssm-001": "ec2-instance",
    "ssm-002": "ec2-instance",
    "ec2instanceconnect-003": "ec2-instance",
    "codebuild-002": "codebuild-project",
    "codebuild-003": "codebuild-project",
    "cloudformation-002": "cloudformation-stack",
    "glue-002": "glue-dev-endpoint",
    "sagemaker-004": "sagemaker-notebook",
    "sagemaker-005": "sagemaker-notebook",
    "stepfunctions-002": "state-machine",
    "apprunner-002": "apprunner-service",
}


def kind_of(arn: str) -> str | None:
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    if parts[2] == "s3":
        return "s3-bucket" if parts[5] and "/" not in parts[5] else None
    for name, k in KINDS.items():
        if parts[2] == k.service and k.prefix and parts[5].startswith(k.prefix):
            return name
    return None


@dataclass(frozen=True)
class Resource:
    arn: str
    kind: str
    role: str | None  # role ARN after instance-profile resolution; None if it has none
    policy: dict[str, Any] | None = None  # resource policy document: bucket policy, key policy
    kms_key: str | None = None  # a bucket's default encryption key (SSE-KMS)
    public_access_block: dict[str, Any] | None = None  # a bucket's Block Public Access settings


@dataclass
class Inventory:
    collected: set[str]
    resources: list[Resource]
    warnings: list[str] = field(default_factory=list)

    def of_kind(self, kind: str) -> list[Resource]:
        return [r for r in self.resources if r.kind == kind]

    def find(self, arn: str) -> Resource | None:
        return next((r for r in self.resources if r.arn == arn), None)

    def summary(self) -> dict[str, int]:
        return {k: len(self.of_kind(k)) for k in sorted(self.collected)}


def _profiles(env: Environment) -> dict[str, str]:
    """Instance profile ARN -> role ARN, from the RoleDetailList of the account export."""
    out: dict[str, str] = {}
    for r in env.raw.get("RoleDetailList") or []:
        for ip in r.get("InstanceProfileList") or []:
            if isinstance(ip, dict) and ip.get("Arn"):
                out[ip["Arn"]] = r.get("Arn", "")
    return out


def load_inventory(data: Any, env: Environment) -> Inventory:
    if not isinstance(data, dict) or not isinstance(data.get("Resources", []), list):
        raise PolicyError('not a resource inventory: expected {"Collected": [...], "Resources": [...]}')
    warnings: list[str] = []
    collected: set[str] = set()
    for k in data.get("Collected") or []:
        if k in KINDS:
            collected.add(k)
        else:
            warnings.append(f"inventory: unknown kind {k!r} in Collected; ignored")
    profiles = _profiles(env)
    resources: list[Resource] = []
    for i, item in enumerate(data.get("Resources") or []):
        if not isinstance(item, dict) or not isinstance(item.get("Arn"), str):
            raise PolicyError(f"inventory: Resources[{i}] needs an Arn")
        arn = item["Arn"]
        kind = kind_of(arn)
        if kind is None:
            warnings.append(f"inventory: {arn} is not a kind iam-trace uses; ignored")
            continue
        role = item.get("Role")
        if role is not None and not isinstance(role, str):
            raise PolicyError(f"inventory: Resources[{i}] Role must be a string")
        if role and ":instance-profile/" in role:
            resolved = profiles.get(role)
            if resolved is None:
                warnings.append(f"inventory: {arn} uses {role}, which is not in the account export; ignored")
                continue
            role = resolved
        policy = item.get("Policy")
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError as e:
                raise PolicyError(f"inventory: {arn} Policy is not JSON") from e
        if policy is not None and not isinstance(policy, dict):
            raise PolicyError(f"inventory: Resources[{i}] Policy must be a policy document")
        key = item.get("KmsKey")
        pab = item.get("PublicAccessBlock")
        resources.append(
            Resource(
                arn,
                kind,
                role or None,
                policy=policy,
                kms_key=key if isinstance(key, str) and key else None,
                public_access_block=pab if isinstance(pab, dict) else None,
            )
        )
    return Inventory(collected, resources, warnings)
