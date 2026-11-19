"""Command-line interface.

Exit codes:
  0  success (for `can`: the request is allowed)
  1  for `can`: the request is denied. For `check`/`diff`/`escalate` with --fail-on: a finding matched.
  2  usage error, unreadable file, or a policy AWS would reject
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from iamtrace import __version__, fields
from iamtrace.catalog import ACCESS_LEVELS, Catalog, CatalogMissing, user_cache_dir
from iamtrace.catalog.refresh import refresh
from iamtrace.check import check_auth_details, check_documents, check_sarif, check_text
from iamtrace.collect import CollectError, aws_cli, collect
from iamtrace.credentials import (
    CredentialError,
    CredentialReport,
    collect_credential_report,
    parse_credential_report,
)
from iamtrace.data import data_access, data_access_text, data_exposure, data_exposure_text
from iamtrace.diff import diff_markdown, diff_policies, diff_sarif, diff_text
from iamtrace.documents import decode, load_json
from iamtrace.entry import entry_points, entry_points_text
from iamtrace.escalate import Environment, analyze, escalate_sarif, escalate_text
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.expand import expand_patterns, expand_policies, expand_sarif, expand_text
from iamtrace.fixplan import fix_plan, fix_plan_text, public
from iamtrace.inventory import load_inventory
from iamtrace.loader import load_any_policy, load_levels, load_policies, load_policy, parse_context, read_file
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.output import can_sarif, can_text, to_json
from iamtrace.principals import Principal
from iamtrace.terraform import TerraformError, review_markdown, review_text
from iamtrace.terraform import review as terraform_review
from iamtrace.usage import STALE_DAYS, collect_usage, parse_usage, unused_access, unused_text
from iamtrace.whatif import what_if, what_if_text
from iamtrace.whocan import who_can, who_can_text

Handler = Callable[[argparse.Namespace], int]


def _add_format(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="output format")


def _read_json(path: str | Path) -> Any:
    """A JSON file: any Unicode encoding, strict JSON, a clear message naming the file."""
    return load_json(read_file(path), str(path)).value


def _read_text(path: str | Path) -> str:
    return decode(read_file(path), str(path))


# --- can --------------------------------------------------------------------------


def _principal(args: argparse.Namespace) -> Principal:
    spec: str = args.principal
    if spec != "anonymous":
        spec = fields.principal(spec)
    if spec.startswith("service:"):
        return Principal.service(spec.split(":", 1)[1])
    if spec == "anonymous":
        return Principal.anonymous()
    return Principal.from_arn(spec, role_arn=args.role_arn, federating_user_arn=args.federating_user)


def cmd_can(args: argparse.Namespace) -> int:
    principal = _principal(args)
    policies = PolicySet(
        identity=load_policies(args.identity, PolicyType.IDENTITY),
        resource=load_policies(args.resource_policy, PolicyType.RESOURCE),
        boundary=load_policy(args.boundary, PolicyType.BOUNDARY) if args.boundary else None,
        session=load_policies(args.session_policy, PolicyType.SESSION),
        scps=load_levels(args.scp, PolicyType.SCP),
        rcps=load_levels(args.rcp, PolicyType.RCP),
        scp_exempt=args.management_account_principal,
        rcp_exempt=args.management_account_resource,
        resource_is_aws_managed_key=args.aws_managed_key,
    )
    ctx = parse_context(args.context, args.context_json)
    fields.context(ctx)
    req = Request(
        principal=principal,
        action=fields.action(args.action),
        resource=fields.resource(args.resource or "*"),
        resource_account=fields.account_id(args.resource_account or "", "--resource-account"),
        context=ctx,
    )
    result = evaluate(req, policies)
    if args.what_if and args.format == "json":
        sys.stdout.write(to_json({**result.to_dict(), "what_if": what_if(req, policies, result)}))
    else:
        out = {"text": can_text, "json": lambda r: to_json(r.to_dict()), "sarif": can_sarif}[args.format](result)
        sys.stdout.write(out)
        if args.what_if and args.format == "text":
            sys.stdout.write(what_if_text(what_if(req, policies, result)))
    return 0 if result.allowed else 1


def _add_can(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "can",
        help="decide whether a principal can perform an action on a resource",
        description="Evaluate one request against the supplied policies and print the decision with a trace.",
    )
    p.add_argument(
        "--principal",
        required=True,
        help="caller ARN (IAM user, role, assumed-role session, federated user, or account root), "
        "'service:NAME' for a service principal, or 'anonymous'",
    )
    p.add_argument("--action", required=True, help="for example s3:GetObject")
    p.add_argument(
        "--what-if",
        action="store_true",
        help="also show what would change the answer: the smallest fixes if denied, what it depends on if allowed",
    )
    p.add_argument("--resource", default="*", help="resource ARN, or * for actions without a resource type")
    p.add_argument(
        "--resource-account", help="account that owns the resource (needed for S3 and other ARNs without one)"
    )
    p.add_argument("--role-arn", help="for a role session: the role ARN including its path")
    p.add_argument("--federating-user", help="for a federated user: ARN of the IAM user who federated")
    p.add_argument("--identity", action="append", metavar="FILE", help="identity-based policy (repeatable)")
    p.add_argument("--resource-policy", action="append", metavar="FILE", help="resource-based policy (repeatable)")
    p.add_argument("--boundary", metavar="FILE", help="permissions boundary")
    p.add_argument("--session-policy", action="append", metavar="FILE", help="session policy (repeatable)")
    p.add_argument(
        "--scp",
        action="append",
        metavar="FILES",
        help="SCPs for one organization level, comma-separated; repeat per level, root first",
    )
    p.add_argument("--rcp", action="append", metavar="FILES", help="RCPs for one level, like --scp")
    p.add_argument("--management-account-principal", action="store_true", help="principal is in the management account")
    p.add_argument("--management-account-resource", action="store_true", help="resource is in the management account")
    p.add_argument("--aws-managed-key", action="store_true", help="resource is an AWS managed KMS key")
    p.add_argument(
        "--context", action="append", metavar="KEY=VALUE", help="context key; repeat a key for several values"
    )
    p.add_argument("--context-json", metavar="FILE", help="context keys as a JSON object")
    _add_format(p)
    p.set_defaults(func=cmd_can)


# --- expand -------------------------------------------------------------------------


def _catalog(args: argparse.Namespace) -> Catalog:
    return Catalog.load(getattr(args, "catalog", None))


def cmd_expand(args: argparse.Namespace) -> int:
    cat = _catalog(args)
    if not args.patterns and not args.policy:
        raise PolicyError("give at least one action pattern or --policy FILE")
    if args.policy:
        report = expand_policies([load_any_policy(f) for f in args.policy], cat)
    else:
        report = expand_patterns(args.patterns, cat)
    out = {"text": expand_text, "json": to_json, "sarif": expand_sarif}[args.format](report)
    sys.stdout.write(out)
    return 0


def _add_catalog_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--catalog", metavar="DIR", help="catalog directory (default: packaged, then user cache)")


def _add_expand(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "expand",
        help="expand wildcard actions into concrete actions with access levels",
        description="List the concrete actions an Action pattern (or every statement of a policy) covers.",
    )
    p.add_argument("patterns", nargs="*", help="action patterns such as s3:Get* or iam:*Policy*")
    p.add_argument("--policy", action="append", metavar="FILE", help="expand every statement of a policy file")
    _add_catalog_arg(p)
    _add_format(p)
    p.set_defaults(func=cmd_expand)


# --- diff ----------------------------------------------------------------------------


def _load_optional(path: str) -> Policy | None:
    """A missing or empty file (or /dev/null) means "no policy": the file is new or deleted."""
    p = Path(path)
    if not p.exists() or not p.read_text(encoding="utf-8-sig").strip():
        return None
    return load_any_policy(p, policy_id=path)


def cmd_diff(args: argparse.Namespace) -> int:
    cat = _catalog(args)
    d = diff_policies(_load_optional(args.old), _load_optional(args.new), cat)
    if args.format == "text":
        out = diff_text(d)
    elif args.format == "json":
        out = to_json(d)
    elif args.format == "markdown":
        out = diff_markdown(d, args.title)
    else:
        out = diff_sarif(d, args.new)
    sys.stdout.write(out)
    if args.fail_on == "any" and not d["unchanged"]:
        return 1
    if args.fail_on == "new-allow" and d["changes"]["newly_allowed"]:
        return 1
    if args.fail_on == "highlighted" and d["highlighted"]:
        return 1
    return 0


def _add_diff(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "diff",
        help="show what a policy change grants or takes away",
        description="Semantic diff of two policy files: newly allowed or denied actions and resources, grouped by "
        "access level. Reordering, renaming Sids or splitting statements is not a change. Use /dev/null for a "
        "file that was added or deleted.",
    )
    p.add_argument("old")
    p.add_argument("new")
    p.add_argument("--title", help="heading for markdown output")
    p.add_argument(
        "--fail-on",
        choices=["never", "any", "new-allow", "highlighted"],
        default="never",
        help="exit 1 when: anything changed, anything is newly allowed, or a newly allowed action is "
        "permissions management or part of a known escalation path",
    )
    _add_catalog_arg(p)
    p.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    p.set_defaults(func=cmd_diff)


# --- escalate ------------------------------------------------------------------------


def cmd_escalate(args: argparse.Namespace) -> int:
    scps = load_levels(args.scp, PolicyType.SCP)
    cat = None
    if args.blast_radius:
        cat = _catalog(args)
    if args.auth_details:
        try:
            data = _read_json(args.auth_details)
        except (OSError, json.JSONDecodeError, RecursionError) as e:
            raise PolicyError(f"{args.auth_details}: cannot read: {e}") from e
        env = Environment.from_auth_details(data)
        if args.inventory:
            try:
                inv_data = _read_json(args.inventory)
            except (OSError, json.JSONDecodeError, RecursionError) as e:
                raise PolicyError(f"{args.inventory}: cannot read: {e}") from e
            env.resources = load_inventory(inv_data, env)
        report = analyze(env, start=args.principal, catalog=cat, scps=scps, conditions=not args.strict_context)
    elif args.policy:
        if args.inventory:
            raise PolicyError("--inventory needs --auth-details: roles are resolved through the account export")
        principal = args.principal or "arn:aws:iam::111122223333:role/policy-under-test"
        boundary = load_policy(args.boundary, PolicyType.BOUNDARY) if args.boundary else None
        env = Environment.single([load_policy(f, PolicyType.IDENTITY) for f in args.policy], principal, boundary)
        report = analyze(env, start=principal, catalog=cat, scps=scps, conditions=not args.strict_context)
        if args.baseline:
            base_env = Environment.single([load_policy(args.baseline, PolicyType.IDENTITY)], principal, boundary)
            base = analyze(base_env, start=principal, scps=scps)
            old_ids = {t["id"] for p in base["principals"] for t in p["techniques"]}
            report["new_findings"] = [
                t for p in report["principals"] for t in p["techniques"] if t["id"] not in old_ids
            ]
    else:
        raise PolicyError("give --auth-details FILE (an account export) or --policy FILE")

    out = {"text": escalate_text, "json": to_json, "sarif": escalate_sarif}[args.format](report)
    sys.stdout.write(out)
    any_finding = bool(report["paths"]) or any(p["techniques"] for p in report["principals"])
    admin = bool(report["paths"]) or any(
        p["admin_equivalent"] for p in report["principals"] if p["arn"] == report["start"]
    )
    if args.fail_on == "any" and any_finding:
        return 1
    if args.fail_on == "admin" and admin:
        return 1
    if args.fail_on == "new" and report.get("new_findings"):
        return 1
    return 0


def _add_escalate(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "escalate",
        help="find privilege-escalation techniques, multi-principal paths and blast radius",
        description="Analyse an account export (aws iam get-account-authorization-details) or a single policy "
        "for known privilege-escalation techniques (pathfinding.cloud) and paths to admin-equivalent principals.",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--auth-details", metavar="FILE", help="output of aws iam get-account-authorization-details")
    src.add_argument(
        "--policy", action="append", metavar="FILE", help="identity policy file(s) of one hypothetical principal"
    )
    p.add_argument("--principal", metavar="ARN", help="start from this principal (default: analyse every principal)")
    p.add_argument(
        "--inventory",
        metavar="FILE",
        help="with --auth-details: existing resources and their roles (from `iam-trace inventory collect`), "
        "to confirm or rule out techniques that abuse existing resources",
    )
    p.add_argument("--boundary", metavar="FILE", help="with --policy: a permissions boundary")
    p.add_argument(
        "--baseline", metavar="FILE", help="with --policy: the previous version, to report only new findings"
    )
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument("--blast-radius", action="store_true", help="count every action the reachable principals allow")
    p.add_argument(
        "--strict-context",
        action="store_true",
        help="evaluate every check with no request context, instead of trying the values conditions name "
        "(MFA, source IP, region, ...); gated paths are then not found",
    )
    p.add_argument(
        "--fail-on",
        choices=["never", "any", "admin", "new"],
        default="never",
        help="exit 1 on any finding, on a path to (or start at) an admin-equivalent principal, "
        "or on findings that are new compared with --baseline",
    )
    _add_catalog_arg(p)
    _add_format(p)
    p.set_defaults(func=cmd_escalate)


# --- check ----------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    cat = _catalog(args)
    if args.auth_details and args.files:
        raise PolicyError("give policy files or --auth-details, not both")
    if args.auth_details:
        try:
            data = _read_json(args.auth_details)
        except (OSError, json.JSONDecodeError, RecursionError) as e:
            raise PolicyError(f"{args.auth_details}: cannot read: {e}") from e
        report = check_auth_details(data, cat, include_aws_managed=args.include_aws_managed)
    elif args.files:
        docs = []
        for f in args.files:
            try:
                docs.append((f, _read_text(f)))
            except OSError as e:
                raise PolicyError(f"{f}: cannot read: {e.strerror}") from e
        report = check_documents(docs, cat)
    else:
        raise PolicyError("give one or more policy files, or --auth-details FILE (an account export)")
    out = {"text": check_text, "json": to_json, "sarif": check_sarif}[args.format](report)
    sys.stdout.write(out)
    if args.fail_on == "never":
        return 0
    levels = ["high", "medium", "low"]
    worst = levels[: levels.index(args.fail_on) + 1]
    return 1 if any(f["severity"] in worst for f in report["findings"]) else 0


def _add_check(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "check",
        help="flag risky patterns in policies, with a reason and a fix for each",
        description="Check policy files (identity, resource or trust policies; the type is inferred) or every "
        "policy in an account export for risky patterns such as full admin access, iam:PassRole on any role, "
        "public principals and actions that match nothing.",
    )
    p.add_argument("files", nargs="*", metavar="FILE", help="policy JSON files")
    p.add_argument("--auth-details", metavar="FILE", help="output of aws iam get-account-authorization-details")
    p.add_argument(
        "--include-aws-managed",
        action="store_true",
        help="with --auth-details: also check AWS managed policies (skipped by default; they are broad by design)",
    )
    p.add_argument(
        "--fail-on",
        choices=["never", "high", "medium", "low"],
        default="never",
        help="exit 1 if there is a finding at this severity or higher",
    )
    _add_catalog_arg(p)
    _add_format(p)
    p.set_defaults(func=cmd_check)


# --- who can --------------------------------------------------------------------------


def cmd_who_can(args: argparse.Namespace) -> int:
    try:
        data = _read_json(args.auth_details)
    except (OSError, json.JSONDecodeError, RecursionError) as e:
        raise PolicyError(f"{args.auth_details}: cannot read: {e}") from e
    env = Environment.from_auth_details(data)
    if args.inventory:
        env.resources = load_inventory(_read_json(args.inventory), env)
    res_policy = load_policy(args.resource_policy, PolicyType.RESOURCE) if args.resource_policy else None
    report = who_can(
        env,
        fields.action(args.action),
        fields.resource(args.resource or "*"),
        scps=load_levels(args.scp, PolicyType.SCP),
        resource_policy=res_policy,
        context=parse_context(args.context, None),
    )
    out = who_can_text(report) if args.format == "text" else to_json(report)
    sys.stdout.write(out)
    return 0


def _add_who_can(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "who-can",
        help="list every principal that can perform an action on a resource, directly or through escalation",
        description="Evaluates the action for every user and role in an account export, then follows confirmed "
        "escalation paths to find principals that can reach someone who can.",
    )
    p.add_argument(
        "--auth-details", required=True, metavar="FILE", help="aws iam get-account-authorization-details output"
    )
    p.add_argument("--action", required=True, help="for example s3:GetObject")
    p.add_argument("--resource", default="*", help="resource ARN, or * for actions without a resource type")
    p.add_argument("--resource-policy", metavar="FILE", help="the resource's own policy (bucket, key, queue...)")
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument("--context", action="append", metavar="KEY=VALUE", help="request context (repeatable)")
    p.add_argument("--inventory", metavar="FILE", help="resource inventory, to confirm more escalation paths")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_who_can)


# --- entry points -----------------------------------------------------------------------


def _load_account(path: str, inventory: str | None) -> Environment:
    try:
        data = _read_json(path)
    except (OSError, json.JSONDecodeError, RecursionError) as e:
        raise PolicyError(f"{path}: cannot read: {e}") from e
    env = Environment.from_auth_details(data)
    if inventory:
        try:
            inv_data = _read_json(inventory)
        except (OSError, json.JSONDecodeError, RecursionError) as e:
            raise PolicyError(f"{inventory}: cannot read: {e}") from e
        env.resources = load_inventory(inv_data, env)
    return env


def _load_credentials(path: str | None) -> CredentialReport | None:
    if not path:
        return None
    try:
        return parse_credential_report(_read_text(path))
    except OSError as e:
        raise PolicyError(f"{path}: cannot read: {e}") from e
    except CredentialError as e:
        raise PolicyError(f"{path}: {e}") from e


def cmd_entry_points(args: argparse.Namespace) -> int:
    env = _load_account(args.auth_details, args.inventory)
    report = entry_points(
        env, scps=load_levels(args.scp, PolicyType.SCP), credentials=_load_credentials(args.credential_report)
    )
    sys.stdout.write(entry_points_text(report) if args.format == "text" else to_json(report))
    order = ["low", "medium", "high", "critical"]
    if args.fail_on != "never":
        worst = [e["rating"].lower() for e in report["entries"]]
        if any(order.index(w) >= order.index(args.fail_on) for w in worst):
            return 1
    return 0


def _add_entry_points(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "entry-points",
        help="who outside the account could become each principal, ranked by what it reaches",
        description="Asks each role's trust policy whether a GitHub workflow in another repository, any identity "
        "of an OIDC or SAML provider, an unrelated AWS account or a named account without ExternalId can assume "
        "it, and combines that with the escalation analysis. IAM users count as entry points too.",
    )
    p.add_argument(
        "--auth-details", required=True, metavar="FILE", help="aws iam get-account-authorization-details output"
    )
    p.add_argument("--inventory", metavar="FILE", help="resource inventory, to confirm more escalation paths")
    p.add_argument(
        "--credential-report",
        metavar="FILE",
        help="IAM credential report (from `iam-trace credentials collect` or aws iam get-credential-report): "
        "which users really have keys, passwords and MFA",
    )
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="exit 1 if any entry point is rated at least this",
    )
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_entry_points)


# --- data -------------------------------------------------------------------------------


def cmd_data(args: argparse.Namespace) -> int:
    env = _load_account(args.auth_details, args.inventory)
    scps = load_levels(args.scp, PolicyType.SCP)
    if args.resource:
        try:
            r = data_access(env, args.resource, args.access, scps=scps)
        except ValueError as e:
            raise PolicyError(str(e)) from e
        sys.stdout.write(data_access_text(r) if args.format == "text" else to_json(r))
        bad = r["public"] or bool(r["outside"])
        return 1 if args.fail_on != "never" and bad else 0
    x = data_exposure(env, scps=scps)
    sys.stdout.write(data_exposure_text(x) if args.format == "text" else to_json(x))
    order = ["low", "medium", "high", "critical"]
    if args.fail_on != "never" and any(
        order.index(r["rating"].lower()) >= order.index(args.fail_on) for r in x["resources"]
    ):
        return 1
    return 0


def _add_data(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "data",
        help="who can read, write or delete the data in buckets, secrets, tables, topics and queues, by any route",
        description="Without --resource, rates every data resource in the inventory (S3 buckets, KMS keys, "
        "Secrets Manager secrets, DynamoDB tables, SNS topics, SQS queues), worst first. With it, lists who can "
        "read (write, delete) that resource: directly, through escalation, and from outside the account. "
        "Encrypted data needs the service's KMS permissions on its key too (kms:Decrypt to read an SSE-KMS "
        "bucket, for example). Collect them with `iam-trace inventory collect`.",
    )
    p.add_argument(
        "--auth-details", required=True, metavar="FILE", help="aws iam get-account-authorization-details output"
    )
    p.add_argument("--inventory", metavar="FILE", help="resource inventory (iam-trace inventory collect)")
    p.add_argument(
        "--resource", metavar="ARN", help="one bucket (arn:aws:s3:::name), key, secret, table, topic or queue ARN"
    )
    p.add_argument("--access", choices=["read", "write", "delete"], default="read")
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="exit 1 if a resource is rated at least this (with --resource: if it is public or shared outside)",
    )
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_data)


# --- terraform --------------------------------------------------------------------------


def cmd_terraform(args: argparse.Namespace) -> int:
    try:
        plan = _read_json(args.plan)
    except (OSError, json.JSONDecodeError, RecursionError) as e:
        raise PolicyError(f"{args.plan}: cannot read: {e}") from e
    export = None
    if args.auth_details:
        try:
            export = _read_json(args.auth_details)
        except (OSError, json.JSONDecodeError, RecursionError) as e:
            raise PolicyError(f"{args.auth_details}: cannot read: {e}") from e
    try:
        r = terraform_review(plan, Catalog.load(args.catalog), export=export)
    except TerraformError as e:
        raise PolicyError(f"{args.plan}: {e}") from e
    if args.format == "text":
        sys.stdout.write(review_text(r))
    elif args.format == "markdown":
        sys.stdout.write(review_markdown(r))
    else:
        sys.stdout.write(to_json(r))
    s = r["summary"]
    fail = {
        "never": False,
        "new-path": s["new_paths"] > 0 or s["new_admins"] > 0,
        "new-entry-point": s["new_entry_points"] > 0,
        "escalation": s["new_escalations"] > 0 or s["new_paths"] > 0,
        "check-high": s["high_checks"] > 0,
        "any": s["new_paths"] + s["new_admins"] + s["new_entry_points"] + s["new_escalations"] + s["new_checks"] > 0,
    }[args.fail_on]
    return 1 if fail else 0


def _add_terraform(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "terraform",
        help="review the IAM changes in a Terraform plan (terraform show -json)",
        description="Extracts every IAM policy, trust policy, bucket policy and key policy the plan changes, and "
        "reports new escalation techniques and risky patterns. With --auth-details, applies the plan to the "
        "account export and reports new paths to admin, new admins and new entry points.",
    )
    p.add_argument("plan", metavar="PLAN_JSON", help="output of terraform show -json plan.out")
    p.add_argument("--auth-details", metavar="FILE", help="the current account export, to see what the plan changes")
    p.add_argument("--catalog", metavar="DIR", help="action catalog directory")
    p.add_argument(
        "--fail-on",
        choices=["never", "new-path", "new-entry-point", "escalation", "check-high", "any"],
        default="never",
        help="exit 1 if the plan does this",
    )
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.set_defaults(func=cmd_terraform)


# --- fix --------------------------------------------------------------------------------


def cmd_fix(args: argparse.Namespace) -> int:
    env = _load_account(args.auth_details, args.inventory)
    try:
        try:
            cat: Catalog | None = Catalog.load()
        except CatalogMissing:
            cat = None  # wildcards then cannot be listed out; such changes keep their Deny
        plan = fix_plan(
            env,
            start=args.principal,
            scps=load_levels(args.scp, PolicyType.SCP),
            include_gated=args.include_gated,
            catalog=cat,
        )
    except ValueError as e:
        raise PolicyError(str(e)) from e
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for principal, policy in plan["policies"].items():
            name = principal.split(":", 5)[-1].replace("/", "-")
            (out / f"{name}.iam-trace-fix.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
        narrowed = plan.get("narrowed") or {}
        for edit in narrowed.get("edits", []):
            if edit.get("document") is None:
                continue
            name = edit["policy"].split(":", 5)[-1].replace("/", "-").replace(" ", "-")
            text = json.dumps(edit["document"], indent=2) + "\n"
            (out / f"{name}.narrowed.json").write_text(text, encoding="utf-8")
        if plan.get("scp"):
            (out / "iam-trace-fix.scp.json").write_text(
                json.dumps(plan["scp"]["policy"], indent=2) + "\n", encoding="utf-8"
            )
    sys.stdout.write(fix_plan_text(plan) if args.format == "text" else to_json(public(plan)))
    return 0 if plan["verified"] else 1


def _add_fix(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser(
        "fix",
        help="the smallest verified set of policy changes that removes every path to admin",
        description="Finds the cheapest set of Deny statements (targeted ones first) that cuts every confirmed path "
        "to an admin-equivalent principal, applies them to a copy of the account and runs the analysis again "
        "to prove it. Exits 1 if the plan could not be verified.",
    )
    p.add_argument(
        "--auth-details", required=True, metavar="FILE", help="aws iam get-account-authorization-details output"
    )
    p.add_argument("--principal", metavar="ARN", help="fix the paths from this principal (default: every principal)")
    p.add_argument("--inventory", metavar="FILE", help="resource inventory, to confirm more escalation paths")
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument("--out-dir", metavar="DIR", help="also write each principal's Deny policy as a JSON file here")
    p.add_argument(
        "--include-gated",
        action="store_true",
        help="also cut paths that need MFA, a network location or a time window (often intended access)",
    )
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_fix)


# --- inventory ------------------------------------------------------------------------


def cmd_inventory_collect(args: argparse.Namespace) -> int:
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()] if args.kinds else None
    inv = collect(aws_cli(args.profile), regions, kinds, log=lambda m: print(m, file=sys.stderr))
    text = to_json(inv)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    print(
        f"{len(inv['Resources'])} resources; collected: {', '.join(inv['Collected']) or 'nothing'}",
        file=sys.stderr,
    )
    if inv["Errors"]:
        print(
            f"{len(inv['Errors'])} call(s) failed; those kinds stay unknown in the analysis (see Errors in the file)",
            file=sys.stderr,
        )
    return 0


def cmd_credentials_collect(args: argparse.Namespace) -> int:
    text = collect_credential_report(aws_cli(args.profile))
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        report = parse_credential_report(text)
        print(f"{len(report.users)} users in the credential report", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _add_credentials(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("credentials", help="the IAM credential report, for entry-points --credential-report")
    csub = p.add_subparsers(dest="credentials_command", required=True)
    c = csub.add_parser(
        "collect",
        help="get a fresh credential report with the AWS CLI (read-only)",
        description="Runs aws iam generate-credential-report until the report is ready, then "
        "aws iam get-credential-report. Needs iam:GenerateCredentialReport and iam:GetCredentialReport "
        "(both in the SecurityAudit managed policy). The report lists every user's password, MFA and access key "
        "status and dates; it contains no secrets.",
    )
    c.add_argument("--out", metavar="FILE", help="write the report here (default: stdout)")
    c.add_argument("--profile", metavar="NAME", help="AWS CLI profile")
    c.set_defaults(func=cmd_credentials_collect)


def _add_inventory(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("inventory", help="list existing resources and their roles, for escalate --inventory")
    isub = p.add_subparsers(dest="inventory_command", required=True)
    c = isub.add_parser(
        "collect",
        help="collect with the AWS CLI (read-only list and describe calls)",
        description="Runs read-only AWS CLI calls (list, describe, get) to find Lambda functions, EC2 instances, "
        "CodeBuild projects, CloudFormation stacks, Glue dev endpoints, SageMaker notebooks, Step Functions state "
        "machines and App Runner services, with the role each runs as. Needs the AWS CLI configured; the "
        "ReadOnlyAccess or SecurityAudit managed policy is enough.",
    )
    c.add_argument("--regions", metavar="LIST", help="comma-separated regions (default: every enabled region)")
    c.add_argument("--kinds", metavar="LIST", help="comma-separated kinds to collect (default: all)")
    c.add_argument("--profile", metavar="NAME", help="AWS CLI profile to use")
    c.add_argument("--out", metavar="FILE", help="write here instead of standard output")
    c.set_defaults(func=cmd_inventory_collect)


# --- catalog --------------------------------------------------------------------------


def cmd_catalog_refresh(args: argparse.Namespace) -> int:
    out = Path(args.out) if args.out else user_cache_dir()
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        refresh(out, log=lambda m: print(m, file=sys.stderr))
    except (RuntimeError, OSError) as e:
        print(f"iamtrace: error: catalog refresh failed: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_catalog_info(args: argparse.Namespace) -> int:
    cat = _catalog(args)
    levels: dict[str, int] = {}
    for a in cat.all_actions():
        levels[a.access_level] = levels.get(a.access_level, 0) + 1
    print(f"catalog: {cat.meta.get('path')}")
    print(f"services: {len(cat.services)}")
    print(f"actions: {len(cat)}")
    for level in ACCESS_LEVELS:
        if level in levels:
            print(f"  {level}: {levels[level]}")
    return 0


def _add_catalog(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("catalog", help="download or inspect the action catalog")
    csub = p.add_subparsers(dest="catalog_command", required=True)
    r = csub.add_parser("refresh", help="download the Service Authorization Reference from AWS")
    r.add_argument("--out", metavar="DIR", help=f"where to write it (default: {user_cache_dir()})")
    r.set_defaults(func=cmd_catalog_refresh)
    i = csub.add_parser("info", help="show what the current catalog contains")
    _add_catalog_arg(i)
    i.set_defaults(func=cmd_catalog_info)


# --- entry point ------------------------------------------------------------------

# --- unused access ---------------------------------------------------------------------


def cmd_usage_collect(args: argparse.Namespace) -> int:
    env = _load_account(args.auth_details, None)
    arns = sorted(a for a, n in env.nodes.items() if n.kind in ("user", "role"))
    print(f"asking IAM for last accessed data for {len(arns)} users and roles", file=sys.stderr)
    text = collect_usage(aws_cli(args.profile), arns)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_unused(args: argparse.Namespace) -> int:
    env = _load_account(args.auth_details, args.inventory)
    try:
        usage = parse_usage(_read_text(args.usage))
    except OSError as e:
        raise PolicyError(f"{args.usage}: cannot read: {e}") from e
    result = unused_access(env, usage, days=args.days, scps=load_levels(args.scp, PolicyType.SCP))
    if args.out_dir:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        for edit in result["edits"]:
            if edit["document"] is None:
                continue
            name = edit["policy"].split(":", 5)[-1].replace("/", "-").replace(" ", "-")
            (out / f"{name}.trimmed.json").write_text(json.dumps(edit["document"], indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(unused_text(result) if args.format == "text" else to_json(result))
    return 0


def _add_usage(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("usage", help="IAM last accessed data, for unused --usage")
    usub = p.add_subparsers(dest="usage_command", required=True)
    c = usub.add_parser(
        "collect",
        help="get last accessed data for every user and role with the AWS CLI (read-only)",
        description="For each user and role in the export, runs aws iam generate-service-last-accessed-details "
        "(action level), then aws iam get-service-last-accessed-details until the report is ready. Needs "
        "iam:GenerateServiceLastAccessedDetails and iam:GetServiceLastAccessedDetails (both Read-level actions). "
        "Reports cover the last 400 days.",
    )
    c.add_argument("--auth-details", required=True, metavar="FILE", help="the account export, for the principals")
    c.add_argument("--out", metavar="FILE", help="write the reports here (default: stdout)")
    c.add_argument("--profile", metavar="NAME", help="AWS CLI profile")
    c.set_defaults(func=cmd_usage_collect)

    p = sub.add_parser(
        "unused",
        help="services each policy allows that nobody who has it used, and the policies without them",
        description="Reads IAM last accessed data (from `iam-trace usage collect`). A service is removed from a "
        "policy only if every user and role that has the policy has not used it for --days days. Edits only take "
        "access away, and iam:PassRole is kept (AWS does not track it). The trimmed account is analysed again to "
        "show which paths to admin the cleanup closes.",
    )
    p.add_argument("--auth-details", required=True, metavar="FILE", help="aws iam get-account-authorization-details")
    p.add_argument("--usage", required=True, metavar="FILE", help="from `iam-trace usage collect`")
    p.add_argument("--days", type=int, default=STALE_DAYS, help=f"unused for this many days (default {STALE_DAYS})")
    p.add_argument("--inventory", metavar="FILE", help="resource inventory, to confirm more escalation paths")
    p.add_argument("--scp", action="append", metavar="FILES", help="SCPs for one level (root first), like `can`")
    p.add_argument("--out-dir", metavar="DIR", help="also write each trimmed policy as a JSON file here")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_unused)


SUBCOMMANDS: list[Callable[[argparse._SubParsersAction[argparse.ArgumentParser]], None]] = [
    _add_can,
    _add_check,
    _add_expand,
    _add_diff,
    _add_escalate,
    _add_who_can,
    _add_entry_points,
    _add_data,
    _add_terraform,
    _add_fix,
    _add_credentials,
    _add_usage,
    _add_inventory,
    _add_catalog,
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-trace", description="Explain what AWS IAM policies allow.")
    parser.add_argument("--version", action="version", version=f"iam-trace {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for add in SUBCOMMANDS:
        add(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Handler = args.func
    try:
        return handler(args)
    except (PolicyError, ValueError, CatalogMissing, CollectError) as e:
        print(f"iamtrace: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
