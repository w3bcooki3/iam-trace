"""Live differential run: compare iam-trace with iam:SimulateCustomPolicy.

This is the only part of the project that calls AWS. It runs from the manual GitHub workflow
(.github/workflows/differential.yml) or locally:

    pip install -e '.[differential]'
    AWS_PROFILE=... python -m tests.differential.runner --out tests/differential/fixtures

Permissions needed (the simulator API is free of charge):
    iam:SimulateCustomPolicy
    sts:GetCallerIdentity (allowed for every principal; no policy needed)

Every case where the two sides disagree, or where AWS rejects the input, is written to the
output directory as a JSON fixture. The offline test (test_fixtures.py) replays them on every
push. A summary is printed and written to summary.json, which the README's pass count is
generated from.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from tests.differential.common import AWS_DECISIONS, fill, iamtrace_decision
from tests.differential.generator import generate


def _caller(sts: Any, override: str | None) -> tuple[str, str]:
    ident = sts.get_caller_identity()
    account = ident["Account"]
    if override:
        return override, account
    arn: str = ident["Arn"]
    if ":assumed-role/" in arn:
        # CallerArn cannot be an assumed-role session; use the role (path unknown, so prefer --caller-arn).
        role = arn.split(":assumed-role/")[1].split("/")[0]
        arn = f"arn:aws:iam::{account}:role/{role}"
    return arn, account


def _params(case: dict[str, Any], caller: str) -> dict[str, Any]:
    p: dict[str, Any] = {
        "PolicyInputList": [json.dumps(d) for d in case["identity"]],
        "ActionNames": [case["action"]],
        "ResourceArns": [case["resource"]],
        "CallerArn": caller,
    }
    if case["boundary"]:
        p["PermissionsBoundaryPolicyInputList"] = [json.dumps(case["boundary"])]
    if case["resource_policy"]:
        p["ResourcePolicy"] = json.dumps(case["resource_policy"])
    if case["resource_owner"]:
        p["ResourceOwner"] = f"arn:aws:iam::{case['resource_owner']}:root"
    if case["scps"]:
        p["OrderedOrganizationPolicyInputList"] = [
            {"ServiceControlPolicyInputList": [json.dumps(d) for d in level]} for level in case["scps"]
        ]
    if case["context"]:
        p["ContextEntries"] = [
            {"ContextKeyName": k, "ContextKeyType": v["type"], "ContextKeyValues": v["values"]}
            for k, v in case["context"].items()
        ]
    return p


def run(out_dir: Path, caller_override: str | None, other_account: str, only: str | None) -> int:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError

    cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    iam = boto3.client("iam", config=cfg)
    caller, account = _caller(boto3.client("sts", config=cfg), caller_override)
    username = caller.rsplit("/", 1)[1]
    values = {"{ACCOUNT}": account, "{OTHER}": other_account, "{CALLER}": caller, "{USERNAME}": username}

    out_dir.mkdir(parents=True, exist_ok=True)
    agree = disagree = errors = 0
    by_category: dict[str, dict[str, int]] = {}
    for raw in generate():
        if only and raw["category"] != only:
            continue
        case = fill(raw, values)
        stats = by_category.setdefault(raw["category"], {"agree": 0, "disagree": 0, "error": 0})
        fixture: dict[str, Any] = {"case": raw, "status": "open"}
        try:
            resp = iam.simulate_custom_policy(**_params(case, caller))
            aws = resp["EvaluationResults"][0]["EvalDecision"]
            fixture["aws_decision"] = aws
            fixture["aws_matched_statements"] = resp["EvaluationResults"][0].get("MatchedStatements", [])
        except ClientError as e:
            fixture["aws_error"] = str(e)
            aws = None
        ours = iamtrace_decision(case, caller, account)
        fixture["iamtrace_decision"] = ours.value
        if aws is None:
            errors += 1
            stats["error"] += 1
        elif AWS_DECISIONS[aws] is ours:
            agree += 1
            stats["agree"] += 1
            continue
        else:
            disagree += 1
            stats["disagree"] += 1
        (out_dir / f"{raw['id']}.json").write_text(json.dumps(fixture, indent=2) + "\n")
        time.sleep(0.05)  # stay well under the IAM API rate limit

    total = agree + disagree
    summary = {
        "agree": agree,
        "disagree": disagree,
        "aws_errors": errors,
        "compared": total,
        "by_category": by_category,
        "date": time.strftime("%Y-%m-%d"),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if disagree == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("tests/differential/fixtures"))
    parser.add_argument(
        "--caller-arn", help="IAM user or role ARN to simulate as (defaults to the credentials' identity)"
    )
    parser.add_argument("--other-account", default="999988887777", help="account ID used for cross-account cases")
    parser.add_argument("--category", help="only run one category")
    args = parser.parse_args()
    sys.exit(run(args.out, args.caller_arn, args.other_account, args.category))


if __name__ == "__main__":
    main()
