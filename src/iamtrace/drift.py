"""Drift: what changed in an account between two exports of it.

Input is two outputs of `aws iam get-account-authorization-details`, an older one and a newer one.
The question it answers is the one a security team has every week: did anything get worse?

- Paths to admin, admin-equivalent principals and entry points: both exports are analysed in full
  and compared (the same comparison the Terraform review makes, iamtrace.terraform).
- Users and roles added or removed.
- For every user and role in both, what it can now do that it could not before: all of its
  identity policies (inline, managed, through groups) are taken together and compared with the
  semantic diff (iamtrace.diff), so moving a statement from one policy to another is no change,
  and only real new access is reported. Its permission boundary and, for roles, who can assume it
  are compared the same way.

A principal whose policies, boundary and trust policy are all unchanged is not diffed at all, so a
large account with a few changes is quick.
"""

from __future__ import annotations

import dataclasses
from typing import Any

from iamtrace.catalog import Catalog
from iamtrace.diff import diff_policies, md_code
from iamtrace.escalate import Environment, Node
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyType
from iamtrace.terraform import _account_diff

# Biggest problems first in every listing.
_SEVERITY = {"new_admin": 0, "new_path": 1, "entry_point": 2, "grew": 3}


def _combined(node: Node) -> Policy:
    """All identity policies of a principal as one document, for a semantic diff of what it can do."""
    statements = tuple(st for p in node.policies for st in p.statements)
    statements = tuple(dataclasses.replace(st, index=i) for i, st in enumerate(statements))
    return Policy(
        id=f"{node.arn} identity policies", type=PolicyType.IDENTITY, version="2012-10-17", statements=statements
    )


def _same(a: Policy | None, b: Policy | None) -> bool:
    if a is None or b is None:
        return a is b
    return a.statements == b.statements


def _changed_entries(old: Policy | None, new: Policy | None, cat: Catalog) -> dict[str, Any] | None:
    if _same(old, new):
        return None
    d = diff_policies(old, new, cat)
    return None if d["unchanged"] else d


def _boundary_blocks(boundary: Policy | None, action: str) -> bool:
    """True only when the permission boundary has no Allow statement that could cover the action,
    so the new grant cannot take effect. Resources and conditions are not looked at: a boundary
    that allows the action anywhere, under any condition, counts as not blocking (never hides a
    real change)."""
    if boundary is None:
        return False
    for st in boundary.statements:
        if st.effect != "Allow":
            continue
        if st.actions is not None and any_action_matches(st.actions, action):
            return False
        if st.not_actions is not None and not any_action_matches(st.not_actions, action):
            return False
    return True


def _principal_change(before: Node, after: Node, cat: Catalog) -> dict[str, Any] | None:
    old_all, new_all = _combined(before), _combined(after)
    identity = None if _same(old_all, new_all) else _changed_entries(old_all, new_all, cat)
    boundary = _changed_entries(before.boundary, after.boundary, cat)
    trust = _changed_entries(before.trust, after.trust, cat)
    attached = sorted(set(after.attached) - set(before.attached))
    detached = sorted(set(before.attached) - set(after.attached))
    joined = sorted(set(after.groups) - set(before.groups))
    left = sorted(set(before.groups) - set(after.groups))
    if not (identity or boundary or trust or attached or detached or joined or left):
        return None
    grew = []
    for e in identity["changes"]["newly_allowed"] if identity else []:
        e = dict(e, blocked_by_boundary=_boundary_blocks(after.boundary, e["action"]))
        grew.append(e)
    # What can actually be used first, the most sensitive of it first.
    grew.sort(key=lambda e: (e["blocked_by_boundary"], not e["highlight"]))
    return {
        "principal": after.arn,
        "kind": after.kind,
        "newly_allowed": grew,
        "no_longer_allowed": identity["changes"]["no_longer_allowed"] if identity else [],
        "newly_denied": identity["changes"]["newly_denied"] if identity else [],
        "deny_removed": identity["changes"]["deny_removed"] if identity else [],
        "sensitive": sum(1 for e in grew if e["highlight"] and not e["blocked_by_boundary"]),
        "blocked_by_boundary": sum(1 for e in grew if e["blocked_by_boundary"]),
        "boundary": boundary,
        "boundary_removed": before.boundary is not None and after.boundary is None,
        "trust": trust,
        "attached": attached,
        "detached": detached,
        "joined_groups": joined,
        "left_groups": left,
    }


def drift(before_raw: dict[str, Any], after_raw: dict[str, Any], catalog: Catalog) -> dict[str, Any]:
    """Compare two account exports (validated here: PolicyError names what is wrong)."""
    env_b = Environment.from_auth_details(before_raw)
    env_a = Environment.from_auth_details(after_raw)
    account = _account_diff(before_raw, after_raw)
    added = sorted(set(env_a.nodes) - set(env_b.nodes))
    removed = sorted(set(env_b.nodes) - set(env_a.nodes))
    changed = []
    for arn in sorted(set(env_a.nodes) & set(env_b.nodes)):
        c = _principal_change(env_b.nodes[arn], env_a.nodes[arn], catalog)
        if c:
            changed.append(c)
    # Most new sensitive access first, then most new access.
    changed.sort(key=lambda c: (-c["sensitive"], -len(c["newly_allowed"]), c["principal"]))
    accounts_b = {n.account for n in env_b.nodes.values()}
    accounts_a = {n.account for n in env_a.nodes.values()}
    notes = []
    if accounts_b and accounts_a and accounts_b != accounts_a:
        notes.append(
            f"the exports are of different accounts ({', '.join(sorted(accounts_b))} and "
            f"{', '.join(sorted(accounts_a))}): everything shows as added and removed"
        )
    notes += [f"older export: {w}" for w in env_b.warnings] + [f"newer export: {w}" for w in env_a.warnings]
    summary = {
        "new_paths": len(account["new_paths"]),
        "removed_paths": len(account["removed_paths"]),
        "new_admins": len(account["new_admins"]),
        "removed_admins": len(account["removed_admins"]),
        "new_entry_points": len(account["new_entry_points"]),
        "principals_added": len(added),
        "principals_removed": len(removed),
        "principals_changed": len(changed),
        "principals_grew": sum(
            1 for c in changed if len(c["newly_allowed"]) > c["blocked_by_boundary"] or c["boundary_removed"]
        ),
        "sensitive_grants": sum(c["sensitive"] for c in changed),
        "trust_changed": sum(1 for c in changed if c["trust"]),
    }
    worse = summary["new_paths"] + summary["new_admins"] + summary["new_entry_points"] > 0
    return {
        "verdict": "worse" if worse else ("changed" if added or removed or changed else "unchanged"),
        "summary": summary,
        "account": account,
        "principals_added": added,
        "principals_removed": removed,
        "changed": changed,
        "notes": notes,
    }


# --- rendering ----------------------------------------------------------------------------------


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def _chain(p: dict[str, Any]) -> str:
    out = " -> ".join([_short(p["start"])] + [f"[{s['technique']}] {_short(s['to'])}" for s in p["steps"]])
    return out + ("" if p.get("open", True) else "  (needs " + ", ".join(r["kind"] for r in p["requires"]) + ")")


def _grant(e: dict[str, Any], trust: bool = False) -> str:
    if trust:  # a trust policy names who, not what
        who = ", ".join(x.split(":", 1)[-1] for x in e["principals"]) or "anyone"
        return f"{who} ({e['action']}{', with conditions' if e['conditions'] else ''})"
    res = ", ".join(e["resources"][:3]) + (f" (+{len(e['resources']) - 3})" if len(e["resources"]) > 3 else "")
    who = f" from {', '.join(e['principals'])}" if e["principals"] else ""
    when = " (with conditions)" if e["conditions"] else ""
    return f"{e['action']} on {res}{who}{when}"


def _by_service(entries: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for e in entries:
        svc = e["action"].split(":", 1)[0]
        counts[svc] = counts.get(svc, 0) + 1
    return ", ".join(f"{svc} {n}" for svc, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


_HEADLINE = {
    "worse": "WORSE: someone can now reach admin, or a new way in opened.",
    "changed": "Changed, but no new path to admin and no new entry point.",
    "unchanged": "No change in what anyone can do.",
}


def drift_text(r: dict[str, Any], limit: int = 15) -> str:
    s, acct = r["summary"], r["account"]
    lines = [
        f"iam-trace drift: {_HEADLINE[r['verdict']]}",
        f"  paths to admin: +{s['new_paths']} -{s['removed_paths']}   admins: +{s['new_admins']} "
        f"-{s['removed_admins']}   entry points new or worse: {s['new_entry_points']}",
        f"  users and roles: +{s['principals_added']} -{s['principals_removed']}, {s['principals_changed']} changed "
        f"({s['principals_grew']} gained access, {s['sensitive_grants']} sensitive grant(s))",
    ]
    if acct["new_admins"]:
        lines += ["", "New admin-equivalent principals"] + [f"  {_short(a)}" for a in acct["new_admins"]]
    if acct["new_paths"]:
        lines += ["", "New paths to admin"] + [f"  {_chain(p)}" for p in acct["new_paths"][:limit]]
        if len(acct["new_paths"]) > limit:
            lines.append(f"  ... and {len(acct['new_paths']) - limit} more (--format json for all)")
    if acct["new_entry_points"]:
        lines += ["", "New or worse entry points"]
        lines += [f"  {e['rating']:<8} {_short(e['principal'])}: {e['why']}" for e in acct["new_entry_points"]]
    if r["principals_added"]:
        lines += ["", "Added"] + [f"  {_short(a)}" for a in r["principals_added"]]
    if r["principals_removed"]:
        lines += ["", "Removed"] + [f"  {_short(a)}" for a in r["principals_removed"]]
    for c in r["changed"]:
        lines += ["", f"{_short(c['principal'])} ({c['kind']})"]
        for g in c["joined_groups"]:
            lines.append(f"  joined group {_short(g)}")
        for g in c["left_groups"]:
            lines.append(f"  left group {_short(g)}")
        for a in c["attached"]:
            lines.append(f"  policy attached: {_short(a)}")
        for a in c["detached"]:
            lines.append(f"  policy detached: {_short(a)}")
        if c["boundary_removed"]:
            lines.append("  ! permission boundary removed")
        elif c["boundary"]:
            lines.append("  permission boundary changed")
        if c["trust"]:
            for e in c["trust"]["changes"]["newly_allowed"]:
                lines.append(f"  ! can now be assumed by {_grant(e, trust=True)}")
            for e in c["trust"]["changes"]["no_longer_allowed"]:
                lines.append(f"  can no longer be assumed by {_grant(e, trust=True)}")
        usable = [e for e in c["newly_allowed"] if not e["blocked_by_boundary"]]
        for e in usable[:limit]:
            lines.append(f"  {'!' if e['highlight'] else '+'} {_grant(e)}")
        if len(usable) > limit:
            lines.append(f"  + ... and {len(usable) - limit} more: {_by_service(usable[limit:])}")
        if c["blocked_by_boundary"]:
            blocked = [e for e in c["newly_allowed"] if e["blocked_by_boundary"]]
            lines.append(
                f"  ~ {len(blocked)} new permission(s) with no effect, the permission boundary does not allow "
                f"them: {_by_service(blocked)}"
            )
        if c["no_longer_allowed"]:
            lines.append(f"  - {len(c['no_longer_allowed'])} permission(s) taken away")
        if c["newly_denied"]:
            lines.append(
                f"  - {len(c['newly_denied'])} new Deny: " + ", ".join(e["action"] for e in c["newly_denied"][:5])
            )
        if c["deny_removed"]:
            lines.append(f"  ! {len(c['deny_removed'])} Deny statement(s) removed")
    if acct["removed_paths"]:
        lines += ["", "Paths to admin closed"] + [f"  {_chain(p)}" for p in acct["removed_paths"][:limit]]
    for n in r["notes"]:
        lines.append(f"Note: {n}")
    lines.append("")
    lines.append("! marks access used in known privilege-escalation paths or permissions management.")
    return "\n".join(lines) + "\n"


def drift_markdown(r: dict[str, Any], limit: int = 15) -> str:
    s, acct = r["summary"], r["account"]
    lines = [
        "### iam-trace drift",
        "",
        f"**{_HEADLINE[r['verdict']]}**",
        "",
        "| | added | removed |",
        "|---|---:|---:|",
        f"| Paths to admin | {s['new_paths']} | {s['removed_paths']} |",
        f"| Admin-equivalent principals | {s['new_admins']} | {s['removed_admins']} |",
        f"| Users and roles | {s['principals_added']} | {s['principals_removed']} |",
        "",
        f"{s['principals_changed']} principal(s) changed, {s['principals_grew']} gained access, "
        f"{s['sensitive_grants']} sensitive grant(s), {s['new_entry_points']} new or worse entry point(s).",
    ]
    if acct["new_admins"]:
        lines += ["", "**New admin-equivalent principals**", ""] + [
            f"- {md_code(_short(a))}" for a in acct["new_admins"]
        ]
    if acct["new_paths"]:
        lines += ["", "**New paths to admin**", ""] + [f"- {md_code(_chain(p))}" for p in acct["new_paths"][:limit]]
    if acct["new_entry_points"]:
        lines += ["", "**New or worse entry points**", ""]
        lines += [f"- {e['rating']}: {md_code(_short(e['principal']))}" for e in acct["new_entry_points"]]
    grew = [
        c
        for c in r["changed"]
        if len(c["newly_allowed"]) > c["blocked_by_boundary"] or c["trust"] or c["boundary_removed"]
    ]
    if grew:
        lines += ["", "**Gained access**", ""]
        for c in grew[:limit]:
            usable = len(c["newly_allowed"]) - c["blocked_by_boundary"]
            bits = [f"{usable} new permission(s)"] if usable else []
            if c["sensitive"]:
                bits.append(f"{c['sensitive']} sensitive")
            if c["trust"] and c["trust"]["changes"]["newly_allowed"]:
                bits.append("can be assumed by more")
            if c["boundary_removed"]:
                bits.append("boundary removed")
            lines.append(f"- {md_code(_short(c['principal']))}: {', '.join(bits)}")
    for n in r["notes"]:
        lines += ["", f"_Note: {n}_"]
    return "\n".join(lines) + "\n"
