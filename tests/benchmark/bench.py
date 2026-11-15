"""Benchmark the escalation engine against every AWS path in pathfinding.cloud.

For each path the benchmark builds small accounts from upstream's own description of it (the
required permissions, and the services a passed role must trust), not from iam-trace's tables,
and runs the analysis:

- positive: an attacker (a user and a role) holds exactly the required permissions, and an admin
  role and an admin user exist. Existing-resource paths run twice: with no resource inventory,
  and with an inventory listing one resource that runs as the admin role.
- near misses, which must not be reported: each required permission removed in turn, each one
  explicitly denied, an SCP denying it, a permissions boundary that leaves it out, a target that
  is not admin, and (for passed roles) a role trusted by a different service.

    python3 tests/benchmark/bench.py            # print the table
    python3 tests/benchmark/bench.py --write    # also write docs/coverage.md

tests/unit/test_benchmark.py runs the same checks and fails on any regression against
tests/benchmark/expected.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from iamtrace.escalate import MODIFY_PERMISSIONS, Environment, analyze
from iamtrace.inventory import kind_of, load_inventory
from iamtrace.model import Policy, PolicyType

HERE = Path(__file__).resolve().parent
CASES = HERE / "pathfinding_cases.json"
A = "111122223333"
REGION = "us-east-1"
ATTACKER_USER = f"arn:aws:iam::{A}:user/attacker"
ATTACKER_ROLE = f"arn:aws:iam::{A}:role/attacker"
ADMIN_ROLE = f"arn:aws:iam::{A}:role/admin-role"
ADMIN_USER = f"arn:aws:iam::{A}:user/admin-user"
WEAK_ROLE = f"arn:aws:iam::{A}:role/weak-role"
ADMINS_GROUP = f"arn:aws:iam::{A}:group/admins"
DEVS_GROUP = f"arn:aws:iam::{A}:group/devs"
MANAGED = f"arn:aws:iam::{A}:policy/attacker-managed"
TARGET_MANAGED = f"arn:aws:iam::{A}:policy/target-managed"
BOUNDARY = f"arn:aws:iam::{A}:policy/boundary"
OTHER_SERVICE = "example.amazonaws.com"

# The service a role must trust when upstream's prerequisites name none (our judgement, used
# only for paths whose text does not say).
FALLBACK_TRUST = {
    "apprunner": "tasks.apprunner.amazonaws.com",
    "batch": "ecs-tasks.amazonaws.com",
    "bedrock": "bedrock-agentcore.amazonaws.com",
    "cloudformation": "cloudformation.amazonaws.com",
    "codebuild": "codebuild.amazonaws.com",
    "codedeploy": "ec2.amazonaws.com",
    "ec2": "ec2.amazonaws.com",
    "ec2instanceconnect": "ec2.amazonaws.com",
    "ecs": "ecs-tasks.amazonaws.com",
    "glue": "glue.amazonaws.com",
    "lambda": "lambda.amazonaws.com",
    "sagemaker": "sagemaker.amazonaws.com",
    "ssm": "ec2.amazonaws.com",
    "stepfunctions": "states.amazonaws.com",
}

# An existing resource that runs as a role, for each existing-resource path (real ARN formats).
EXISTING = {
    "apprunner-002": f"arn:aws:apprunner:{REGION}:{A}:service/web/0123456789abcdef",
    "batch-002": f"arn:aws:batch:{REGION}:{A}:job-definition/nightly:1",
    "bedrock-002": f"arn:aws:bedrock-agentcore:{REGION}:{A}:code-interpreter-custom/ci-0123456789",
    "bedrock-004": f"arn:aws:bedrock-agentcore:{REGION}:{A}:runtime/rt-0123456789",
    "bedrock-007": f"arn:aws:bedrock-agentcore:{REGION}:{A}:browser-custom/br-0123456789",
    "cloudformation-002": f"arn:aws:cloudformation:{REGION}:{A}:stack/app/0a1b2c3d-1111-2222-3333-444455556666",
    "cloudformation-005": f"arn:aws:cloudformation:{REGION}:{A}:stack/app/0a1b2c3d-1111-2222-3333-444455556666",
    "codebuild-002": f"arn:aws:codebuild:{REGION}:{A}:project/build",
    "codebuild-003": f"arn:aws:codebuild:{REGION}:{A}:project/build",
    "codedeploy-001": f"arn:aws:ec2:{REGION}:{A}:instance/i-0123456789abcdef0",
    "ec2-002": f"arn:aws:ec2:{REGION}:{A}:instance/i-0123456789abcdef0",
    "ec2-005": f"arn:aws:ec2:{REGION}:{A}:launch-template/lt-0123456789abcdef0",
    "ec2instanceconnect-003": f"arn:aws:ec2:{REGION}:{A}:instance/i-0123456789abcdef0",
    "ecs-006": f"arn:aws:ecs:{REGION}:{A}:task/main/0123456789abcdef",
    "glue-002": f"arn:aws:glue:{REGION}:{A}:devEndpoint/dev",
    "lambda-003": f"arn:aws:lambda:{REGION}:{A}:function:report",
    "lambda-004": f"arn:aws:lambda:{REGION}:{A}:function:report",
    "lambda-005": f"arn:aws:lambda:{REGION}:{A}:function:report",
    "sagemaker-004": f"arn:aws:sagemaker:{REGION}:{A}:notebook-instance/nb",
    "sagemaker-005": f"arn:aws:sagemaker:{REGION}:{A}:notebook-instance/nb",
    "ssm-001": f"arn:aws:ec2:{REGION}:{A}:instance/i-0123456789abcdef0",
    "ssm-002": f"arn:aws:ec2:{REGION}:{A}:instance/i-0123456789abcdef0",
    "stepfunctions-002": f"arn:aws:states:{REGION}:{A}:stateMachine:pipeline",
}

# Permissions that change what the target may do: with these, a target that is not admin can be made one.
MODIFY = MODIFY_PERMISSIONS | {"iam:createpolicyversion", "iam:setdefaultpolicyversion"}

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
WEAK_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


def load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads(CASES.read_text())["cases"]
    return cases


def _doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


# Services that assume a role as a web identity federation, not as a service principal.
FEDERATED = {"cognito-identity.amazonaws.com"}


def _trust(services: list[str], account: bool) -> dict[str, Any]:
    principal: dict[str, Any] = {}
    plain = [x for x in services if x not in FEDERATED]
    if plain:
        principal["Service"] = plain
    if account:
        principal["AWS"] = f"arn:aws:iam::{A}:root"
    statements = [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}] if principal else []
    statements += [
        {"Effect": "Allow", "Principal": {"Federated": x}, "Action": "sts:AssumeRoleWithWebIdentity"}
        for x in services
        if x in FEDERATED
    ]
    return _doc(*statements)


def trusts_for(case: dict[str, Any]) -> list[str]:
    if case["trusts"]:
        return list(case["trusts"])
    fallback = FALLBACK_TRUST.get(case["id"].rsplit("-", 1)[0])
    return [fallback] if fallback else []


def build(
    case: dict[str, Any],
    *,
    perms: list[str] | None = None,
    deny: str | None = None,
    boundary_without: str | None = None,
    weak_target: bool = False,
    wrong_trust: bool = False,
    inventory: bool = False,
    deny_on_resource: str | None = None,
    passrole: dict[str, Any] | None = None,
    weak_resource_role: bool = False,
) -> Environment:
    """The account for one case. Keyword arguments make the near misses."""
    perms = case["required"] if perms is None else perms
    if passrole is not None:
        others = [p for p in perms if p.lower() != "iam:passrole"]
        statements = [
            {"Effect": "Allow", "Action": others, "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", **passrole},
        ]
    else:
        statements = [{"Effect": "Allow", "Action": perms, "Resource": "*"}] if perms else []
    if deny:
        statements.append({"Effect": "Deny", "Action": deny, "Resource": "*"})
    if deny_on_resource:
        statements.append({"Effect": "Deny", "Action": deny_on_resource, "Resource": EXISTING[case["id"]]})
    attacker_policy = [{"PolicyName": "attacker", "PolicyDocument": _doc(*statements)}] if statements else []
    managed = [{"PolicyName": "attacker-managed", "PolicyArn": MANAGED}]
    # The targets also have a customer managed policy, as paths that edit one need.
    target_managed = [{"PolicyName": "target-managed", "PolicyArn": TARGET_MANAGED}]
    bound = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": BOUNDARY} if boundary_without else None
    target_doc = WEAK_DOC if weak_target else ADMIN_DOC
    services = [OTHER_SERVICE] if wrong_trust else trusts_for(case)

    def extra(entity: dict[str, Any]) -> dict[str, Any]:
        return {**entity, **({"PermissionsBoundary": bound} if bound else {})}

    users = [
        extra(
            {
                "UserName": "attacker",
                "Arn": ATTACKER_USER,
                "UserPolicyList": attacker_policy,
                "AttachedManagedPolicies": managed,
                "GroupList": ["devs"],
            }
        ),
        {
            "UserName": "admin-user",
            "Arn": ADMIN_USER,
            "UserPolicyList": [{"PolicyName": "admin", "PolicyDocument": target_doc}],
            "AttachedManagedPolicies": target_managed,
            "GroupList": [],
        },
    ]
    roles = [
        extra(
            {
                "RoleName": "attacker",
                "Arn": ATTACKER_ROLE,
                "AssumeRolePolicyDocument": _trust(["ec2.amazonaws.com"], False),
                "RolePolicyList": attacker_policy,
                "AttachedManagedPolicies": managed,
            }
        ),
        {
            "RoleName": "weak-role",
            "Arn": WEAK_ROLE,
            "AssumeRolePolicyDocument": _trust(services, True),
            "RolePolicyList": [{"PolicyName": "weak", "PolicyDocument": WEAK_DOC}],
            "AttachedManagedPolicies": [],
        },
        {
            "RoleName": "admin-role",
            "Arn": ADMIN_ROLE,
            "AssumeRolePolicyDocument": _trust(services, True),
            "RolePolicyList": [{"PolicyName": "admin", "PolicyDocument": target_doc}],
            "AttachedManagedPolicies": target_managed,
        },
    ]
    groups = [
        {"GroupName": "devs", "Arn": DEVS_GROUP, "GroupPolicyList": [], "AttachedManagedPolicies": []},
        {
            "GroupName": "admins",
            "Arn": ADMINS_GROUP,
            "GroupPolicyList": [{"PolicyName": "admin", "PolicyDocument": target_doc}],
            "AttachedManagedPolicies": [],
        },
    ]
    policies = [
        {
            "PolicyName": "attacker-managed",
            "Arn": MANAGED,
            "DefaultVersionId": "v1",
            "PolicyVersionList": [
                {
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "Document": _doc({"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}),
                }
            ],
        }
    ]
    policies.append(
        {
            "PolicyName": "target-managed",
            "Arn": TARGET_MANAGED,
            "DefaultVersionId": "v1",
            "PolicyVersionList": [
                {
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "Document": _doc({"Effect": "Allow", "Action": "sqs:ListQueues", "Resource": "*"}),
                }
            ],
        }
    )
    if boundary_without:
        policies.append(
            {
                "PolicyName": "boundary",
                "Arn": BOUNDARY,
                "DefaultVersionId": "v1",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "Document": _doc({"Effect": "Allow", "NotAction": boundary_without, "Resource": "*"}),
                    }
                ],
            }
        )
    env = Environment.from_auth_details(
        {"UserDetailList": users, "RoleDetailList": roles, "GroupDetailList": groups, "Policies": policies}
    )
    if inventory and case["id"] in EXISTING:
        arn = EXISTING[case["id"]]
        kind = kind_of(arn)
        env.resources = load_inventory(
            {
                "Collected": [kind] if kind else [],
                "Resources": [{"Arn": arn, "Role": WEAK_ROLE if weak_resource_role else ADMIN_ROLE}],
            },
            env,
        )
    return env


ADMIN_TARGETS = {ADMIN_ROLE, ADMIN_USER, ADMINS_GROUP}


def outcome(env: Environment, case_id: str, scps: list[list[Policy]] | None = None) -> str:
    """confirmed: the technique is reported as confirmed and leads to admin (the attacker makes
    itself admin with it, it grants admin, or a target is an admin principal); possible: it is
    reported, but not confirmed; missed: it is not reported."""
    best = "missed"
    for start in (ATTACKER_USER, ATTACKER_ROLE):
        r = analyze(env, start=start, scps=scps)
        me = r["principals"][0]
        if me["admin_equivalent"] and case_id in (me["admin_reason"] or ""):
            return "confirmed"
        for t in me["techniques"]:
            if t["id"] != case_id:
                continue
            if t["confidence"] == "confirmed" and (
                t["grants_admin"] or t["category"] == "self-escalation" or ADMIN_TARGETS & set(t["targets"])
            ):
                return "confirmed"
            best = "possible"
    return best


def reaches_admin(env: Environment) -> bool:
    for start in (ATTACKER_USER, ATTACKER_ROLE):
        r = analyze(env, start=start)
        if r["paths"] or r["principals"][0]["admin_equivalent"]:
            return True
    return False


def scp_denying(perm: str) -> list[list[Policy]]:
    full = Policy.parse(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        policy_id="FullAWSAccess",
        policy_type=PolicyType.SCP,
    )
    deny = Policy.parse(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": perm, "Resource": "*"}]},
        policy_id="deny",
        policy_type=PolicyType.SCP,
    )
    return [[full, deny]]


def run_case(case: dict[str, Any]) -> dict[str, Any]:
    cid = case["id"]
    req: list[str] = case["required"]
    result: dict[str, Any] = {"id": cid, "category": case["category"], "detect": outcome(build(case), cid)}
    if cid in EXISTING:
        result["detect_inventory"] = outcome(build(case, inventory=True), cid)
    false_alarms: list[str] = []
    for p in req:
        if outcome(build(case, perms=[x for x in req if x != p]), cid) != "missed":
            false_alarms.append(f"without {p}")
        if outcome(build(case, deny=p), cid) != "missed":
            false_alarms.append(f"Deny {p}")
        if outcome(build(case), cid, scps=scp_denying(p)) != "missed":
            false_alarms.append(f"SCP denies {p}")
        if outcome(build(case, boundary_without=p), cid) != "missed":
            false_alarms.append(f"boundary leaves out {p}")
    changes_target = any(p.lower() in MODIFY for p in req)
    if case["category"] != "self-escalation" and not changes_target and reaches_admin(build(case, weak_target=True)):
        false_alarms.append("target is not admin")
    if case["category"] == "new-passrole" and outcome(build(case, wrong_trust=True), cid) == "confirmed":
        false_alarms.append("role trusts a different service")
    if cid in EXISTING:
        for p in req:
            if outcome(build(case, inventory=True, deny_on_resource=p), cid) == "confirmed":
                false_alarms.append(f"Deny {p} on the resource")
        if reaches_admin(build(case, inventory=True, weak_resource_role=True)) and not changes_target:
            false_alarms.append("the resource's role is not admin")
    if any(p.lower() == "iam:passrole" for p in req):
        others = {"Resource": "*", "Condition": {"StringEquals": {"iam:PassedToService": OTHER_SERVICE}}}
        if outcome(build(case, passrole=others), cid) == "confirmed":
            false_alarms.append("PassRole only to another service")
        if outcome(build(case, passrole={"Resource": WEAK_ROLE}), cid) == "confirmed":
            false_alarms.append("PassRole only on another role")
    result["false_alarms"] = false_alarms
    return result


def run() -> list[dict[str, Any]]:
    return [run_case(c) for c in load_cases()]


def summary(results: list[dict[str, Any]]) -> dict[str, int]:
    out = {"paths": len(results), "confirmed": 0, "possible": 0, "missed": 0, "clean": 0}
    for r in results:
        best = r.get("detect_inventory") if r.get("detect_inventory") == "confirmed" else r["detect"]
        out[best] += 1
        out["clean"] += not r["false_alarms"]
    return out


def checks_per_case(case: dict[str, Any]) -> int:
    """How many near misses run_case tries for a case."""
    n = 4 * len(case["required"]) + 1
    if case["category"] == "new-passrole":
        n += 1
    if case["id"] in EXISTING:
        n += len(case["required"]) + 1
    if any(p.lower() == "iam:passrole" for p in case["required"]):
        n += 2
    return n


def coverage_markdown(results: list[dict[str, Any]]) -> str:
    cases = {c["id"]: c for c in load_cases()}
    meta = json.loads(CASES.read_text())
    s = summary(results)
    checks = sum(checks_per_case(cases[r["id"]]) for r in results)
    export_only = sum(1 for r in results if r["detect"] == "confirmed")
    label = {"confirmed": "Confirmed", "possible": "Possible", "missed": "Missed"}
    rows = []
    for r in results:
        c = cases[r["id"]]
        inv = label[r["detect_inventory"]] if "detect_inventory" in r else "not needed"
        fa = ", ".join(r["false_alarms"]) or "none"
        name = c["name"].replace("|", "\\|")
        link = f"[{r['id']}](https://pathfinding.cloud/paths/{r['id']})"
        rows.append(f"| {link} | {name} | {label[r['detect']]} | {inv} | {checks_per_case(c)} | {fa} |")
    return "\n".join(
        [
            "# Escalation coverage",
            "",
            "<!-- Written by tests/benchmark/bench.py --write. Do not edit by hand. -->",
            "",
            "iam-trace is benchmarked against every AWS path in",
            f"[pathfinding.cloud](https://pathfinding.cloud) (commit `{meta['commit'][:12]}`).",
            "For each path the benchmark builds small accounts from pathfinding.cloud's own description of",
            "it (the required permissions, and the service a passed role must trust), not from iam-trace's",
            "tables, and runs the analysis. `tests/unit/test_benchmark.py` runs it on every change.",
            "",
            f"- **{s['confirmed']} of {s['paths']}** paths are confirmed (reported as a path to admin):",
            f"  {export_only} from the IAM export alone, and {s['confirmed'] - export_only} that act on an"
            " existing resource",
            "  with a resource inventory. "
            + (f"{s['possible']} are reported only as possible. " if s["possible"] else "None is only possible. ")
            + (f"{s['missed']} are missed." if s["missed"] else "None is missed."),
            f"- **{s['clean']} of {s['paths']}** raise no false alarm in {checks} near misses: each required",
            "  permission removed, denied by the identity policy, denied by an SCP, or left out of a",
            "  permissions boundary; a target that is not admin; a passed role trusted by another",
            "  service; PassRole limited to another service or another role; and, for existing",
            "  resources, a Deny on that resource or a resource whose role is not admin.",
            "",
            '"Existing resource" paths (a Lambda function, an EC2 instance, a CodeBuild project that',
            "already runs as a role) are confirmed only with a resource inventory",
            "(`iam-trace inventory collect`). Without one they are reported as possible, with every role",
            "the service could be running as.",
            "",
            "## What the benchmark does not show",
            "",
            "- The accounts are small and each holds one path. Real accounts mix many; the engine's",
            "  search across them is covered by the unit tests, not by this table.",
            "- Paths that exist in AWS but not yet in pathfinding.cloud are not counted.",
            "- The benchmark checks iam-trace against a description of AWS, not against AWS itself.",
            "  A path that pathfinding.cloud describes wrongly would be scored wrongly too.",
            "- See [limitations](limitations.md) for what the engine does not model.",
            "",
            "## Every path",
            "",
            "| Path | Permissions | Without inventory | With inventory | Near misses | False alarms |",
            "|---|---|---|---|---|---|",
            *rows,
            "",
            "pathfinding.cloud is Apache-2.0, Copyright 2025-Present Datadog, Inc.",
            "",
        ]
    )


def table(results: list[dict[str, Any]]) -> str:
    lines = []
    for r in results:
        inv = f" / {r['detect_inventory']} with inventory" if "detect_inventory" in r else ""
        fa = "; ".join(r["false_alarms"]) or "none"
        lines.append(f"{r['id']:24} {r['category']:18} {r['detect']}{inv}   false alarms: {fa}")
    return "\n".join(lines)


if __name__ == "__main__":
    res = run()
    print(table(res))
    print(json.dumps(summary(res)))
    if "--write" in sys.argv:
        (HERE / "expected.json").write_text(json.dumps(res, indent=1) + "\n")
        (HERE.parents[1] / "docs" / "coverage.md").write_text(coverage_markdown(res))
        print("wrote tests/benchmark/expected.json and docs/coverage.md")
