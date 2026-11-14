"""`iam-trace check`: flag risky patterns in policies, one finding per problem, each with a
plain reason and a fix.

Unlike `can` and `escalate`, this looks at each policy on its own. It does not know what else is
attached to the same principal or what exists in the account, so findings describe what a
policy *grants*, not what an attacker can definitely do. `escalate` answers that question.

Every rule is listed in RULES with its default severity. A statement with a Condition that the
rule does not specifically look for is reported one level lower, because the condition may
narrow it; the finding says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

from iamtrace.catalog import Catalog
from iamtrace.escalate import _document
from iamtrace.loader import parse_any_policy
from iamtrace.model import Policy, PolicyError, PolicyType, Statement
from iamtrace.output import sarif_location, sarif_log
from iamtrace.wildcard import glob_match

SEVERITIES = ("high", "medium", "low")
_LOWER = {"high": "medium", "medium": "low", "low": "low"}
_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    why: str
    fix: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "invalid-policy",
            "high",
            "Policy cannot be read",
            "AWS would reject this document, or iam-trace cannot interpret it, so nothing else in it was checked.",
            "Fix the error shown. The IAM console's policy editor reports the same problems.",
        ),
        Rule(
            "full-admin",
            "high",
            "Full administrator access",
            'Allows every action on every resource ("Action": "*" with "Resource": "*"). Anyone with '
            "this policy can do anything in the account, including granting themselves more access "
            "and deleting audit logs.",
            "Grant only the services and actions this principal uses. IAM Access Analyzer can "
            "generate a policy from CloudTrail activity. Keep full access for a small number of "
            "break-glass roles that require MFA.",
        ),
        Rule(
            "allow-not-action",
            "high",
            "Allow with NotAction",
            "Allows every action except the ones listed, including actions AWS adds in future. On "
            '"Resource": "*" this is close to full administrator access.',
            "List the actions to allow with Action instead. If the aim is to block a few actions, "
            "keep the Allow narrow and add a separate Deny statement.",
        ),
        Rule(
            "passrole-any-role",
            "high",
            "iam:PassRole on any role",
            "Lets the principal hand any role, including an administrator role, to a service such as "
            "Lambda or EC2, then use that service to act as the role. This is the most common step in "
            "privilege-escalation paths.",
            "Limit Resource to the role ARNs this principal needs to pass, and add an "
            "iam:PassedToService condition naming the service.",
        ),
        Rule(
            "privilege-escalation",
            "high",
            "Grants a known privilege-escalation technique",
            "The policy allows every permission a published technique needs (pathfinding.cloud). "
            "Self-escalation techniques work on their own; the others depend on which roles and "
            "resources exist in the account.",
            "Remove or scope the listed permissions to specific resources. To see whether a path "
            "really exists, run `iam-trace escalate` on an account export.",
        ),
        Rule(
            "permissions-management",
            "medium",
            "Can change permissions on any resource",
            "Allows actions AWS classes as permissions management (changing policies, grants or "
            'credentials) on "Resource": "*". These actions control who else gets access.',
            "Scope Resource to the specific resources this principal manages, or move these "
            "actions to a separate administrative role.",
        ),
        Rule(
            "public-principal",
            "high",
            "Open to any AWS principal",
            'An Allow with "Principal": "*" (or a wildcard account) and no condition that limits who '
            "the caller is. Anyone with an AWS account, or anonymous users for some services, can "
            "make these requests.",
            "Name the principals that need access, or add a condition such as aws:PrincipalOrgID, "
            "aws:PrincipalAccount or aws:SourceVpce.",
        ),
        Rule(
            "allow-not-resource",
            "medium",
            "Allow with NotResource",
            "Allows the actions on every resource except the ones listed, including resources "
            "created later and resources in other accounts.",
            "List the resources to allow with Resource instead.",
        ),
        Rule(
            "unknown-action",
            "low",
            "Action matches nothing",
            "The action is not in the AWS Service Authorization Reference. It is usually a typo. "
            "In an Allow it grants nothing; in a Deny it protects nothing, which is worse because "
            "the policy looks safer than it is.",
            "Check the spelling against the AWS documentation for the service. If the action is "
            "new, run `iam-trace catalog refresh`.",
        ),
        Rule(
            "for-all-values-allow",
            "medium",
            "ForAllValues in an Allow",
            "ForAllValues is true when the request has no value for the key, so the Allow applies "
            "to requests that do not send the key at all.",
            'Add a Null condition for the same key with "false", or use ForAnyValue if any one '
            "matching value should be enough.",
        ),
        Rule(
            "service-no-source",
            "low",
            "Service principal without a source condition",
            "Allows an AWS service to act here without saying on whose behalf. Another account's "
            'resources can use the same service to make the request (the "confused deputy" problem).',
            "Add aws:SourceAccount or aws:SourceArn naming your resource, if the service sends them.",
        ),
        Rule(
            "trust-whole-account",
            "low",
            "Trusts an entire account",
            "Any user or role in that account whose own policies allow sts:AssumeRole can assume "
            "this role. For a third party, anyone at that company who can assume roles can use it.",
            "Name the specific role ARNs that may assume it. For third parties, also require sts:ExternalId.",
        ),
        Rule(
            "duplicate-key",
            "medium",
            "Duplicate key",
            "The same key appears twice in one object. AWS keeps only the last one, so part of "
            "what you wrote is silently ignored.",
            "Merge the values into one key.",
        ),
        Rule(
            "missing-version",
            "low",
            "No Version element",
            'Without "Version": "2012-10-17", policy variables such as ${aws:username} are treated as literal text.',
            'Add "Version": "2012-10-17" at the top of the policy.',
        ),
    ]
}

# Condition keys that narrow *who* the caller is, which is what makes a public principal safe.
_IDENTITY_KEYS = {
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "aws:userid",
    "aws:username",
    "aws:principalservicename",
    "kms:calleraccount",
    "kms:viaservice",
}
_SOURCE_KEYS = {"aws:sourceaccount", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths"}
_TRUST_KEYS = {"sts:externalid", "aws:principalarn", "aws:principalorgid", "aws:multifactorauthpresent"}


@cache
def _techniques() -> list[dict[str, Any]]:
    data = json.loads(resources.files("iamtrace").joinpath("data/escalation_paths.json").read_text())
    return list(data["paths"])


# --- statement helpers -------------------------------------------------------------------


def _keys(st: Statement) -> set[str]:
    return {k.lower() for keys in st.condition.values() for k in keys}


def _covers(st: Statement, action: str) -> bool:
    """True if the statement's Action/NotAction element covers a concrete action name."""
    if st.actions is not None:
        return any(glob_match(p, action, ignore_case=True) for p in st.actions)
    assert st.not_actions is not None
    return not any(glob_match(p, action, ignore_case=True) for p in st.not_actions)


def _all_resources(st: Statement) -> bool:
    """Resource "*", or no Resource element at all (resource policies apply to their own resource)."""
    if st.not_resources is not None:
        return True
    return st.resources is None or "*" in st.resources


def _is_full_admin(st: Statement) -> bool:
    return (
        st.effect == "Allow"
        and st.actions is not None
        and any(a in ("*", "*:*") for a in st.actions)
        and (st.resources is not None and "*" in st.resources)
    )


def _principal_values(st: Statement, kind: str) -> list[str]:
    p = st.principal
    if p is None:
        return []
    if p == "*":
        return ["*"] if kind == "AWS" else []
    return list(p.get(kind, ()))


def _is_public(st: Statement) -> bool:
    if st.principal == "*":
        return True
    for v in _principal_values(st, "AWS"):
        if v == "*" or (v.startswith("arn:") and len(v.split(":")) > 4 and "*" in v.split(":")[4]):
            return True
    return False


def _whole_accounts(st: Statement) -> list[str]:
    out = []
    for v in _principal_values(st, "AWS"):
        if v.isdigit() and len(v) == 12:
            out.append(v)
        elif v.startswith("arn:") and v.endswith(":root"):
            out.append(v.split(":")[4])
    return out


# --- the checker --------------------------------------------------------------------------


class _Checker:
    def __init__(self, catalog: Catalog) -> None:
        self.cat = catalog
        self.findings: list[dict[str, Any]] = []

    def add(
        self,
        rule_id: str,
        policy: str,
        statement: str,
        detail: str,
        *,
        conditional: bool = False,
        severity: str | None = None,
        **extra: Any,
    ) -> None:
        rule = RULES[rule_id]
        sev = severity or rule.severity
        if conditional:
            sev = _LOWER[sev]
            detail += " The statement has a condition that may narrow this; check what it requires."
        self.findings.append(
            {
                "rule": rule.id,
                "severity": sev,
                "title": rule.title,
                "policy": policy,
                "statement": statement,
                "detail": detail,
                "why": rule.why,
                "fix": rule.fix,
                **extra,
            }
        )

    # -- per policy -----------------------------------------------------------------------

    def policy(self, pol: Policy, **extra: Any) -> None:
        for w in pol.warnings:
            if w.startswith("duplicate key"):
                self.add("duplicate-key", pol.id, "", w[:1].upper() + w[1:] + ".", **extra)
            elif w.startswith("no Version"):
                self.add("missing-version", pol.id, "", "The policy has no Version element.", **extra)
        admin_unconditional = False
        for st in pol.statements:
            if _is_full_admin(st):
                cond = bool(st.condition)
                admin_unconditional |= not cond
                self.add(
                    "full-admin",
                    pol.id,
                    st.label,
                    f"{st.label} allows every action on every resource.",
                    conditional=cond,
                    **extra,
                )
                continue
            self.statement(pol, st, **extra)
        if pol.type in (PolicyType.IDENTITY, PolicyType.BOUNDARY, PolicyType.SESSION) and not admin_unconditional:
            self.escalation(pol, **extra)

    def statement(self, pol: Policy, st: Statement, **extra: Any) -> None:
        self.unknown_actions(pol, st, **extra)
        if st.effect != "Allow":
            return
        keys = _keys(st)
        cond = bool(st.condition)
        if any(op.lower().startswith("forallvalues:") for op in st.condition):
            null_keys = {k.lower() for op, ks in st.condition.items() if op.lower() == "null" for k in ks}
            fav = {k.lower() for op, ks in st.condition.items() if op.lower().startswith("forallvalues:") for k in ks}
            missing = sorted(fav - null_keys)
            if missing:
                self.add(
                    "for-all-values-allow",
                    pol.id,
                    st.label,
                    f"{st.label} uses ForAllValues on {', '.join(missing)} with no Null check.",
                    **extra,
                )
        if st.not_actions is not None:
            sev = "high" if _all_resources(st) and st.resources is not None and "*" in st.resources else "medium"
            self.add(
                "allow-not-action",
                pol.id,
                st.label,
                f"{st.label} allows everything except {', '.join(st.not_actions)}.",
                conditional=cond,
                severity=sev,
                **extra,
            )
        if st.not_resources is not None:
            self.add(
                "allow-not-resource",
                pol.id,
                st.label,
                f"{st.label} applies to every resource except {', '.join(st.not_resources)}.",
                conditional=cond,
                **extra,
            )
        if pol.type is PolicyType.RESOURCE:
            self.principals(pol, st, keys, **extra)
            return
        if _covers(st, "iam:PassRole") and "iam:passedtoservice" not in keys:
            broad = st.resources is None or any(
                r == "*" or r.endswith(":role/*") or r.endswith(":role*") for r in st.resources
            )
            if broad or st.not_resources is not None:
                self.add(
                    "passrole-any-role",
                    pol.id,
                    st.label,
                    f"{st.label} allows iam:PassRole on {', '.join(st.resources or st.not_resources or ['*'])}.",
                    conditional=cond,
                    **extra,
                )
        if st.resources is not None and "*" in st.resources and st.not_actions is None:
            pm = sorted(
                {
                    a.full_name
                    for p in st.actions or ()
                    for a in self.cat.expand(p)
                    if a.access_level == "Permissions management" and a.full_name != "iam:PassRole"
                }
            )
            if pm:
                shown = ", ".join(pm[:8]) + (f" and {len(pm) - 8} more" if len(pm) > 8 else "")
                self.add(
                    "permissions-management",
                    pol.id,
                    st.label,
                    f"{st.label} allows {len(pm)} permissions-management action{'' if len(pm) == 1 else 's'} "
                    f"on every resource: {shown}.",
                    conditional=cond,
                    actions=pm,
                    **extra,
                )

    def principals(self, pol: Policy, st: Statement, keys: set[str], **extra: Any) -> None:
        if _is_public(st) and not keys & _IDENTITY_KEYS:
            self.add(
                "public-principal",
                pol.id,
                st.label,
                f"{st.label} allows any principal to {', '.join(st.actions or st.not_actions or ())}.",
                **extra,
            )
        services = _principal_values(st, "Service")
        # Role trust policies are left out: services such as EC2 do not send a source account when
        # they assume a role, so the advice would break working roles.
        assumes = st.actions is not None and all(a.lower().startswith("sts:assumerole") for a in st.actions)
        if services and not assumes and not keys & _SOURCE_KEYS:
            self.add(
                "service-no-source",
                pol.id,
                st.label,
                f"{st.label} allows {', '.join(services)} with no aws:SourceAccount or aws:SourceArn condition.",
                **extra,
            )
        accounts = _whole_accounts(st)
        if accounts and _covers(st, "sts:AssumeRole") and not keys & _TRUST_KEYS:
            self.add(
                "trust-whole-account",
                pol.id,
                st.label,
                f"{st.label} lets any principal in account {', '.join(accounts)} assume this role.",
                **extra,
            )

    def unknown_actions(self, pol: Policy, st: Statement, **extra: Any) -> None:
        patterns = st.actions if st.actions is not None else st.not_actions
        bad = [p for p in patterns or () if p not in ("*", "*:*") and not self.cat.expand(p)]
        if not bad:
            return
        if st.effect == "Deny" and st.actions is not None:
            detail = f"{st.label} denies {', '.join(bad)}, which matches no known action, so it protects nothing."
            self.add("unknown-action", pol.id, st.label, detail, severity="medium", **extra)
        else:
            detail = f"{st.label} names {', '.join(bad)}, which matches no known action."
            self.add("unknown-action", pol.id, st.label, detail, **extra)

    def escalation(self, pol: Policy, **extra: Any) -> None:
        """Techniques whose every permission is allowed, unconditionally, on all resources."""
        allows = [st for st in pol.statements if st.effect == "Allow" and not st.condition and _all_resources(st)]
        denies = [st for st in pol.statements if st.effect == "Deny" and not st.condition and _all_resources(st)]

        def granted(action: str) -> bool:
            return any(_covers(s, action) for s in allows) and not any(_covers(s, action) for s in denies)

        hits = [t for t in _techniques() if all(granted(p) for p in t["permissions"])]
        if not hits:
            return
        self_esc = [t for t in hits if t["category"] == "self-escalation"]
        names = [f"{t['id']}: {t['name']}" for t in hits]
        count = "1 published technique needs" if len(hits) == 1 else f"{len(hits)} published techniques need"
        extra_note = f" {len(self_esc)} of them work on their own (self-escalation)." if self_esc else ""
        self.add(
            "privilege-escalation",
            pol.id,
            "",
            f"The policy grants every permission that {count}.{extra_note}",
            severity="high" if self_esc else "medium",
            techniques=names,
            links=[t["pathfinding_url"] for t in hits],
            **extra,
        )

    # -- result ---------------------------------------------------------------------------

    def report(self, policies: int, **summary: Any) -> dict[str, Any]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        self.findings.sort(key=lambda f: (order[f["severity"]], f["policy"], f["statement"], f["rule"]))
        counts = {s: sum(1 for f in self.findings if f["severity"] == s) for s in SEVERITIES}
        return {
            "summary": {"policies": policies, **counts, **summary},
            "findings": self.findings,
            "catalog": {k: v for k, v in self.cat.meta.items() if k != "path"},
        }


# --- entry points ------------------------------------------------------------------------


def check_documents(documents: list[tuple[str, str]], catalog: Catalog) -> dict[str, Any]:
    """Check policy files given as (name, JSON text). The type of each is inferred: a policy that
    names principals is resource-based (including trust policies); otherwise identity-based."""
    c = _Checker(catalog)
    for name, text in documents:
        try:
            pol = parse_any_policy(text.lstrip("﻿"), name)
        except PolicyError as e:
            c.add("invalid-policy", name, "", str(e), file=name)
            continue
        c.policy(pol, file=name)
    return c.report(len(documents))


def check_auth_details(data: Any, catalog: Catalog, *, include_aws_managed: bool = False) -> dict[str, Any]:
    """Check every policy in `aws iam get-account-authorization-details` output once: customer
    managed policies (with the users, groups and roles they are attached to), inline policies,
    and role trust policies. AWS managed policies are skipped unless asked for."""
    if not isinstance(data, dict) or not any(
        k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
    ):
        raise PolicyError("not an account export: expected the output of aws iam get-account-authorization-details")
    c = _Checker(catalog)
    attached: dict[str, list[str]] = {}
    for key in ("UserDetailList", "GroupDetailList", "RoleDetailList"):
        for entity in data.get(key) or []:
            for a in entity.get("AttachedManagedPolicies") or []:
                attached.setdefault(a.get("PolicyArn", ""), []).append(entity.get("Arn", "?"))
    checked = skipped = 0

    def parse(doc: Any, pid: str, ptype: PolicyType, **extra: Any) -> None:
        nonlocal checked
        checked += 1
        try:
            pol = Policy.parse(_document(doc, pid), policy_id=pid, policy_type=ptype)
        except PolicyError as e:
            c.add("invalid-policy", pid, "", str(e), **extra)
            return
        c.policy(pol, **extra)

    for p in data.get("Policies") or []:
        arn = p.get("Arn", "?")
        if arn.startswith("arn:aws:iam::aws:policy/") and not include_aws_managed:
            skipped += 1
            continue
        default = next((v for v in p.get("PolicyVersionList") or [] if v.get("IsDefaultVersion")), None)
        if default is None:
            continue
        parse(default.get("Document"), arn, PolicyType.IDENTITY, attached_to=sorted(attached.get(arn, [])))
    for key, inline_key in (
        ("UserDetailList", "UserPolicyList"),
        ("GroupDetailList", "GroupPolicyList"),
        ("RoleDetailList", "RolePolicyList"),
    ):
        for entity in data.get(key) or []:
            arn = entity.get("Arn", "?")
            for i in entity.get(inline_key) or []:
                pid = f"{arn} inline {i.get('PolicyName', '?')}"
                parse(i.get("PolicyDocument"), pid, PolicyType.IDENTITY, attached_to=[arn])
            if key == "RoleDetailList" and entity.get("AssumeRolePolicyDocument"):
                parse(entity["AssumeRolePolicyDocument"], f"{arn} trust policy", PolicyType.RESOURCE, attached_to=[arn])
    return c.report(checked, skipped_aws_managed=skipped)


# --- output ------------------------------------------------------------------------------


def check_text(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"Checked {s['policies']} polic{'y' if s['policies'] == 1 else 'ies'}: "
        f"{s['high']} high, {s['medium']} medium, {s['low']} low."
    ]
    if s.get("skipped_aws_managed"):
        lines.append(f"Skipped {s['skipped_aws_managed']} AWS managed policies (use --include-aws-managed).")
    if not report["findings"]:
        lines += ["", "No risky patterns found. This does not mean the policies are least-privilege;"]
        lines.append("run `iam-trace escalate` on an account export to look for escalation paths.")
        return "\n".join(lines) + "\n"
    for f in report["findings"]:
        where = f"{f['policy']} {f['statement']}".strip()
        lines += ["", f"[{f['severity'].upper()}] {f['rule']}: {f['title']}", f"  Where: {where}"]
        if f.get("attached_to") and f["attached_to"] != [f["policy"].split(" ")[0]]:
            lines.append(f"  Attached to: {', '.join(f['attached_to'])}")
        lines.append(f"  {f['detail']}")
        lines += [f"    - {name}" for name in f.get("techniques", [])]
        lines += [f"  Why: {f['why']}", f"  Fix: {f['fix']}"]
    return "\n".join(lines) + "\n"


def check_sarif(report: dict[str, Any]) -> str:
    used = sorted({f["rule"] for f in report["findings"]})
    rules = [
        {
            "id": f"check/{r}",
            "shortDescription": {"text": RULES[r].title},
            "fullDescription": {"text": RULES[r].why},
            "help": {"text": RULES[r].fix},
            "defaultConfiguration": {"level": _SARIF_LEVEL[RULES[r].severity]},
        }
        for r in used
    ]
    results = [
        {
            "ruleId": f"check/{f['rule']}",
            "level": _SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['detail']} Fix: {f['fix']}"},
            "locations": sarif_location(f.get("file")),
            "properties": {"policy": f["policy"], "statement": f["statement"], "severity": f["severity"]},
        }
        for f in report["findings"]
    ]
    return sarif_log(rules, results)
