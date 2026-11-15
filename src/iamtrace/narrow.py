"""Alternatives to a fix plan's Deny statements: narrowed Allow statements, and one SCP.

A Deny is easy to add and easy to verify, but it leaves the over-broad Allow in place, and a
policy full of exceptions is hard to read. Usually the better change is to the statement that
grants the permission. For each change in a fix plan (principal, action, resources):

- If the action is denied on every resource, it is removed from the granting statement's Action
  list. A wildcard such as "iam:Put*Policy" is replaced by the actions it covers, minus this one,
  when that is a short list (MAX_EXPANSION); a broader wildcard ("iam:*") cannot be narrowed
  readably, and the Deny is kept for that change.
- If it is denied on specific resources, the statement is split: one copy keeps every other
  action as it was, the other grants only this action on the resources that remain. Exact ARNs
  are simply removed. A wildcard becomes the list of resources that exist today (from the export
  and inventory), minus the targets and minus anything admin-equivalent, when the list is short;
  "*" otherwise becomes NotResource naming the targets.
- A grant that comes only from a role's trust policy (it names the principal) gets a condition
  excluding the principal.

The edited documents are put back into a copy of the export, the account is rebuilt and analysed
again: the narrowed plan is verified the same way as the Deny plan. The old and new documents are
also compared on probe requests (every action they mention against every known resource of the
right kind, and a resource created later), so anything else the edit removes is named.

The SCP version is one policy with a Deny per change, limited to the principal with
aws:PrincipalArn. It is verified by adding it as an SCP level (next to FullAWSAccess).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from iamtrace.arn import resource_matches
from iamtrace.catalog import Catalog
from iamtrace.context import Context
from iamtrace.escalate import PERMISSION_TARGET, Environment, _document, analyze
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.matching import action_matches
from iamtrace.model import Policy, PolicyType
from iamtrace.principals import Principal

MAX_EXPANSION = 25  # a wildcard is listed out only if it covers at most this many actions
MAX_LISTED = 30  # a wildcard resource is listed out only if this many resources would remain
SCP_LIMIT = 5120  # characters AWS allows in one SCP
_NO_CONTEXT = Context()

FULL_ACCESS = Policy.parse(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    policy_id="FullAWSAccess",
    policy_type=PolicyType.SCP,
)


class NarrowError(ValueError):
    """This statement cannot be narrowed in a way a person would accept."""


def _as_list(v: Any) -> list[Any]:
    return [v] if isinstance(v, str) else list(v or [])


def _one_or_list(v: list[Any]) -> Any:
    return v[0] if len(v) == 1 else v


# --- where a policy lives in the export ---------------------------------------------------------


@dataclass
class Located:
    kind: str  # inline, group, managed, trust
    path: tuple[Any, ...]  # keys into the export to the document
    document: dict[str, Any]
    affects: list[str]


def locate(env: Environment, policy_id: str) -> Located | None:
    raw = env.raw or {}
    if policy_id.endswith(" trust policy"):
        owner = policy_id.removesuffix(" trust policy")
        for i, r in enumerate(raw.get("RoleDetailList", [])):
            if r["Arn"] == owner:
                doc = _document(r["AssumeRolePolicyDocument"], owner)
                return Located("trust", ("RoleDetailList", i, "AssumeRolePolicyDocument"), doc, [owner])
        return None
    if " inline " in policy_id:
        owner, name = policy_id.split(" inline ", 1)
        for list_key, pol_key in (
            ("UserDetailList", "UserPolicyList"),
            ("RoleDetailList", "RolePolicyList"),
            ("GroupDetailList", "GroupPolicyList"),
        ):
            for i, e in enumerate(raw.get(list_key, [])):
                if e["Arn"] != owner:
                    continue
                for j, p in enumerate(e.get(pol_key) or []):
                    if p["PolicyName"] == name:
                        doc = _document(p["PolicyDocument"], policy_id)
                        if list_key == "GroupDetailList":
                            members = sorted(n.arn for n in env.nodes.values() if owner in n.groups)
                            return Located("group", (list_key, i, pol_key, j, "PolicyDocument"), doc, members)
                        return Located("inline", (list_key, i, pol_key, j, "PolicyDocument"), doc, [owner])
        return None
    for i, p in enumerate(raw.get("Policies", [])):
        if p["Arn"] != policy_id:
            continue
        for j, v in enumerate(p.get("PolicyVersionList") or []):
            if v.get("IsDefaultVersion"):
                doc = _document(v["Document"], policy_id)
                users = sorted(n.arn for n in env.nodes.values() if policy_id in n.attached)
                return Located("managed", ("Policies", i, "PolicyVersionList", j, "Document"), doc, users)
    return None


def _set_path(raw: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    node: Any = raw
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


# --- narrowing one statement ------------------------------------------------------------------


def _remove_action(actions: list[str], action: str, catalog: Catalog | None) -> list[str]:
    out: list[str] = []
    for pattern in actions:
        if not action_matches(pattern, action):
            out.append(pattern)
            continue
        if pattern.lower() == action.lower():
            continue
        if catalog is None:
            raise NarrowError(f'"{pattern}" is a wildcard and the action catalog is not available to list it')
        covered = [a.full_name for a in catalog.expand(pattern) if a.full_name.lower() != action.lower()]
        if len(covered) > MAX_EXPANSION:
            raise NarrowError(
                f'"{pattern}" covers {len(covered) + 1} actions; listing all of them but {action} would make '
                "the policy hard to read and maintain"
            )
        out += covered
    return out


def _known_resources(env: Environment, action: str, exclude: set[str]) -> list[str] | None:
    """Resources of the kind the action targets that exist today, or None if unknown."""
    kind = PERMISSION_TARGET.get(action.lower())
    if kind in ("role", "user"):
        return sorted(a for a, n in env.nodes.items() if n.kind == kind and a not in exclude)
    if kind == "policy":
        return sorted(p["Arn"] for p in (env.raw or {}).get("Policies", []) if p["Arn"] not in exclude)
    return None


def _narrow_resources(
    st: dict[str, Any], action: str, targets: list[str], env: Environment, admins: set[str]
) -> tuple[dict[str, Any] | None, list[str]]:
    """The statement granting only `action`, on its resources minus `targets`; and what else it
    gives up. None if nothing remains."""
    if "NotResource" in st:
        raise NarrowError("the statement uses NotResource; add the targets to it, or keep the Deny")
    resources = _as_list(st.get("Resource"))
    keep = [r for r in resources if r not in targets]
    wild = [r for r in keep if "*" in r or "?" in r]
    also: list[str] = []
    new = {k: v for k, v in st.items() if k not in ("Sid", "Action", "NotAction", "Resource")}
    if st.get("Sid"):
        new["Sid"] = f"{st['Sid']}Narrowed"
    new["Action"] = action
    if not wild:
        if not keep:
            return None, also
        new["Resource"] = _one_or_list(keep)
        return new, also
    exact = [r for r in keep if r not in wild]
    known = _known_resources(env, action, set(targets) | admins)
    if known is not None:
        listed = sorted(
            {r for r in known if any(resource_matches(w, r, _NO_CONTEXT, False) for w in wild)} | set(exact)
        )
        if len(listed) <= MAX_LISTED:
            kind = PERMISSION_TARGET.get(action.lower()) or "resource"
            also.append(f"{action} on {kind}s created later (only today's are listed)")
            dropped = sorted(
                a for a in admins if a not in targets and any(resource_matches(w, a, _NO_CONTEXT, False) for w in wild)
            )
            if dropped:
                also.append(f"{action} on other admin-equivalent {kind}s: " + ", ".join(_short(a) for a in dropped))
            if not listed:
                return None, also
            new["Resource"] = _one_or_list(listed)
            return new, also
    if resources == ["*"]:
        new.pop("Resource", None)
        new["NotResource"] = _one_or_list(sorted(set(targets)))
        return new, also
    raise NarrowError(
        f"{action} is granted on {', '.join(wild)}; too many resources match to list them and NotResource "
        "cannot be combined with a narrower Resource"
    )


def narrow_statements(
    statements: list[dict[str, Any]],
    action: str,
    targets: list[str],
    env: Environment,
    catalog: Catalog | None,
    admins: set[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply one removal (action on targets, or everywhere if targets is ["*"]) to every Allow
    statement in the list that grants it."""
    out: list[dict[str, Any]] = []
    also: list[str] = []
    for st in statements:
        acts = _as_list(st.get("Action"))
        grants = st.get("Effect") == "Allow" and any(action_matches(a, action) for a in acts)
        if st.get("Effect") == "Allow" and "NotAction" in st:
            raise NarrowError("the statement grants by NotAction; add the action to NotAction, or keep the Deny")
        if not grants:
            out.append(st)
            continue
        if targets != ["*"]:
            resources = _as_list(st.get("Resource"))
            if "NotResource" not in st and not any(
                resource_matches(r, t, _NO_CONTEXT, False) for r in resources for t in targets
            ):
                out.append(st)  # grants the action, but not on these targets
                continue
        rest = _remove_action(acts, action, catalog)
        if rest:
            out.append({**st, "Action": _one_or_list(rest)})
        if targets == ["*"]:
            continue
        piece, more = _narrow_resources(st, action, targets, env, admins)
        also += more
        if piece is not None:
            out.append(piece)
    return out, also


def _exclude_principal(statements: list[dict[str, Any]], principal: str) -> list[dict[str, Any]]:
    """A trust policy: add a condition so the principal no longer matches."""
    out = []
    for st in statements:
        if st.get("Effect") != "Allow":
            out.append(st)
            continue
        cond = copy.deepcopy(st.get("Condition") or {})
        block = cond.setdefault("ArnNotEquals", {})
        prev = _as_list(block.get("aws:PrincipalArn"))
        block["aws:PrincipalArn"] = _one_or_list(sorted({*prev, principal}))
        out.append({**st, "Condition": cond})
    return out


# --- comparing old and new -----------------------------------------------------------------------


def _probe_diff(
    old: dict[str, Any],
    new: dict[str, Any],
    principal: str,
    env: Environment,
    catalog: Catalog | None,
    expected: set[tuple[str, str]],
) -> list[str]:
    """Requests the old document allowed and the new one does not, beyond the intended ones."""
    try:
        before = Policy.parse(old, policy_id="before", policy_type=PolicyType.IDENTITY)
        after = Policy.parse(new, policy_id="after", policy_type=PolicyType.IDENTITY)
    except Exception:  # noqa: BLE001 - a document we cannot parse is reported elsewhere
        return []
    actions: set[str] = set()
    for st in before.statements:
        for pattern in st.actions or ():
            if "*" in pattern or "?" in pattern:
                if catalog is not None:
                    actions |= {a.full_name for a in catalog.expand(pattern)[:300]}
            else:
                actions.add(pattern)
    resources = sorted(env.nodes) + [p["Arn"] for p in (env.raw or {}).get("Policies", [])]
    account = next(iter(env.nodes.values())).account if env.nodes else "111122223333"
    resources += [f"arn:aws:iam::{account}:role/iam-trace-new-role", "arn:aws:s3:::iam-trace-probe/object"]
    caller = (
        Principal.from_arn(principal)
        if principal.startswith("arn:")
        else Principal.from_arn(f"arn:aws:iam::{account}:user/probe")
    )
    lost: dict[str, list[str]] = {}
    for action in sorted(actions)[:400]:
        kind = PERMISSION_TARGET.get(action.lower())
        for res in resources:
            if (action.lower(), res) in expected:
                continue
            if kind in ("role", "user", "policy") and f":{kind}/" not in res:
                continue  # e.g. iam:PassRole "on" a user: not a request anyone makes
            req = Request(caller, action, res, resource_account=account)
            if (
                evaluate(req, PolicySet(identity=[before])).allowed
                and not evaluate(req, PolicySet(identity=[after])).allowed
            ):
                lost.setdefault(action, []).append(res)
    out = []
    for action, res in lost.items():
        if all("iam-trace-new" in r for r in res):
            continue  # reported as "created later" by the narrowing itself
        shown = [_short(r) for r in res if "iam-trace" not in r][:5]
        if shown:
            out.append(f"{action} on {', '.join(shown)}" + (" and more" if len(res) > 5 else ""))
    return out


# --- plans -------------------------------------------------------------------------------------


def narrowed_plan(
    env: Environment,
    changes: list[dict[str, Any]],
    *,
    roots: list[str],
    scps: list[list[Policy]] | None,
    catalog: Catalog | None,
    include_gated: bool,
    everyone: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Edit the granting statements instead of adding Denies, and verify by analysing again."""
    if everyone is None:
        everyone = analyze(env, scps=scps)
    admins = {p["arn"] for p in everyone["principals"] if p["admin_equivalent"] and not p.get("admin_requires")}
    raw = copy.deepcopy(env.raw or {})
    docs: dict[str, tuple[Located, dict[str, Any]]] = {}
    problems: list[str] = []
    also: dict[str, list[str]] = {}
    expected: dict[str, set[tuple[str, str]]] = {}
    for c in changes:
        action, targets, principal = c["actions"][0], c["resources"], c["principal"]
        identity = [g for g in c["granted_by"] if not g["policy"].endswith(" trust policy")]
        sources = identity or c["granted_by"]
        if not sources:
            problems.append(f"Change for {_short(principal)}: no statement grants {action}; keep the Deny.")
            continue
        for g in sources:
            loc = locate(env, g["policy"])
            if loc is None:
                problems.append(f"{g['policy']}: not found in the export; keep the Deny.")
                continue
            current = docs.get(g["policy"], (loc, copy.deepcopy(loc.document)))[1]
            sts = _as_list(current.get("Statement"))
            try:
                if loc.kind == "trust":
                    new_sts = _exclude_principal(sts, principal)
                    more: list[str] = []
                else:
                    new_sts, more = narrow_statements(sts, action, targets, env, catalog, admins)
            except NarrowError as e:
                problems.append(f"{_short(g['policy'])}, {g['statement']}: {e}. Keep the Deny for this change.")
                continue
            docs[g["policy"]] = (loc, {**current, "Statement": new_sts})
            also.setdefault(g["policy"], [])
            also[g["policy"]] += [m for m in more if m not in also[g["policy"]]]
            exp = expected.setdefault(g["policy"], set())
            exp |= {(action.lower(), t) for t in targets} if targets != ["*"] else set()
            exp |= {(action.lower(), a) for a in admins}  # reported by the narrowing itself
    edits = []
    deletions: list[tuple[Any, ...]] = []
    for pid, (loc, new_doc) in docs.items():
        empty = not _as_list(new_doc.get("Statement"))
        if empty and loc.kind in ("inline", "group"):
            deletions.append(loc.path[:-1])  # the whole inline policy entry
        elif empty and loc.kind == "managed":
            # Detaching it everywhere is the edit; for the analysis, an unusable default version.
            _set_path(raw, (*loc.path[:-1], "IsDefaultVersion"), False)
        else:
            _set_path(raw, loc.path, new_doc)
        removed = list(also.get(pid, []))
        if empty:
            edits.append(
                {
                    "policy": pid,
                    "kind": loc.kind,
                    "affects": loc.affects,
                    "document": None,
                    "delete": True,
                    "before": loc.document,
                    "also_removes": removed,
                }
            )
            continue
        if loc.kind != "trust":
            removed += _probe_diff(
                loc.document, new_doc, loc.affects[0] if loc.affects else "", env, catalog, expected.get(pid, set())
            )
        edits.append(
            {
                "policy": pid,
                "kind": loc.kind,
                "affects": loc.affects,
                "document": new_doc,
                "before": loc.document,
                "also_removes": removed,
            }
        )
    # Delete from the end, so earlier positions stay valid.
    for path in sorted(deletions, reverse=True):
        container: Any = raw
        for key in path[:-1]:
            container = container[key]
        del container[path[-1]]
    fixed = Environment.from_auth_details(raw)
    fixed.resources = env.resources
    after = analyze(fixed, scps=scps)
    left = [p for p in after["paths"] if p["start"] in roots and (include_gated or p.get("open", True))]
    complete = not problems
    return {
        "complete": complete,
        "verified": complete and not left,
        "paths_after": len(left),
        "edits": edits,
        "problems": problems,
        "_fixed_env": fixed,
    }


def scp_plan(
    env: Environment,
    changes: list[dict[str, Any]],
    *,
    roots: list[str],
    scps: list[list[Policy]] | None,
    include_gated: bool,
) -> dict[str, Any]:
    """The plan's Denies as one SCP, each limited to its principal with aws:PrincipalArn."""
    grouped: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for c in changes:
        grouped.setdefault((c["actions"][0], tuple(c["resources"])), []).append(c["principal"])
    statements = []
    for i, ((action, res), principals) in enumerate(sorted(grouped.items()), 1):
        statements.append(
            {
                "Sid": f"IamTraceFix{i}",
                "Effect": "Deny",
                "Action": action,
                "Resource": _one_or_list(list(res)),
                "Condition": {"ArnEquals": {"aws:PrincipalArn": _one_or_list(sorted(set(principals)))}},
            }
        )
    doc = {"Version": "2012-10-17", "Statement": statements}
    pol = Policy.parse(doc, policy_id="iam-trace fix SCP", policy_type=PolicyType.SCP)
    after = analyze(env, scps=[*(scps or []), [FULL_ACCESS, pol]])
    left = [p for p in after["paths"] if p["start"] in roots and (include_gated or p.get("open", True))]
    size = len(json.dumps(doc, separators=(",", ":")))
    notes = [
        "Attach it to the account or its OU next to FullAWSAccess (or your allow-list SCP): an SCP level "
        "with only Deny statements would allow nothing.",
        "SCPs do not apply to the organisation's management account or to service-linked roles.",
    ]
    if size > SCP_LIMIT:
        notes.append(f"It is {size} characters; AWS allows {SCP_LIMIT}. Split it, or use the Deny statements.")
    return {"policy": doc, "verified": not left, "paths_after": len(left), "size": size, "notes": notes}


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def text(plan: dict[str, Any]) -> list[str]:
    """Lines for fix_plan_text."""
    lines: list[str] = []
    n = plan.get("narrowed")
    if n:
        lines.append("")
        state = "verified" if n["verified"] else ("NOT verified" if n["complete"] else "partial")
        lines.append(f"Instead of the Deny statements, narrow the Allow statements ({state}):")
        for e in n["edits"]:
            who = ", ".join(_short(a) for a in e["affects"]) or "nobody"
            if e.get("delete"):
                verb = "Detach and delete" if e["kind"] == "managed" else "Delete"
                lines.append(f"  {verb} {_short(e['policy'])} ({e['kind']}, affects {who}): it grants nothing else.")
                continue
            lines.append(f"  {_short(e['policy'])} ({e['kind']}, affects {who}):")
            lines += ["    " + x for x in json.dumps(e["document"], indent=2).splitlines()]
            for x in e["also_removes"]:
                lines.append(f"    Also no longer allows: {x}")
        for p in n["problems"]:
            lines.append(f"  {p}")
    s = plan.get("scp")
    if s:
        lines.append("")
        lines.append(f"As one SCP ({'verified' if s['verified'] else 'NOT verified'}, {s['size']} characters):")
        lines += ["  " + x for x in json.dumps(s["policy"], indent=2).splitlines()]
        lines += [f"  Note: {x}" for x in s["notes"]]
    return lines
