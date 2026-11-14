"""Shared by the live runner and the offline fixture test: placeholder filling and the
iam-trace side of each differential case."""

from __future__ import annotations

import json
from typing import Any

from iamtrace import Decision, Policy, PolicySet, PolicyType, Principal, Request, evaluate

# Values used when replaying stored fixtures offline. The live runner uses the real account and
# caller instead; only equality between accounts matters to the evaluation.
OFFLINE = {
    "{ACCOUNT}": "111122223333",
    "{OTHER}": "999988887777",
    "{CALLER}": "arn:aws:iam::111122223333:user/iamtrace-differential",
    "{USERNAME}": "iamtrace-differential",
}

AWS_DECISIONS = {
    "allowed": Decision.ALLOW,
    "explicitDeny": Decision.EXPLICIT_DENY,
    "implicitDeny": Decision.IMPLICIT_DENY,
}


def fill(obj: Any, values: dict[str, str]) -> Any:
    """Replace placeholders everywhere in a case."""
    text = json.dumps(obj)
    for k, v in values.items():
        text = text.replace(k, v)
    return json.loads(text)


def context_values(case: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, entry in case["context"].items():
        values = entry["values"]
        out[key] = list(values) if entry["type"].endswith("List") else values[0]
    return out


def iamtrace_decision(case: dict[str, Any], caller_arn: str, account: str) -> Decision:
    """Evaluate a filled-in case the way the simulator sees it.

    The simulator treats the caller as the IAM user or role given in CallerArn. A role ARN here
    becomes a session of that role.
    """
    ident = [
        Policy.parse(d, policy_id=f"PolicyInputList.{i + 1}", policy_type=PolicyType.IDENTITY)
        for i, d in enumerate(case["identity"])
    ]
    boundary = (
        Policy.parse(
            case["boundary"], policy_id="PermissionsBoundaryPolicyInputList.1", policy_type=PolicyType.BOUNDARY
        )
        if case["boundary"]
        else None
    )
    resource = (
        [Policy.parse(case["resource_policy"], policy_id="ResourcePolicy", policy_type=PolicyType.RESOURCE)]
        if case["resource_policy"]
        else []
    )
    scps = None
    if case["scps"]:
        scps = [
            [Policy.parse(d, policy_id=f"scp.{i}.{j}", policy_type=PolicyType.SCP) for j, d in enumerate(level)]
            for i, level in enumerate(case["scps"])
        ]
    req = Request(
        principal=Principal.from_arn(caller_arn),
        action=case["action"],
        resource=case["resource"],
        resource_account=case["resource_owner"] or account,
        context=context_values(case),
    )
    return evaluate(req, PolicySet(identity=ident, boundary=boundary, resource=resource, scps=scps)).decision
