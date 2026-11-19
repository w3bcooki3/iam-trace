"""Who can: every principal in an account that can perform one action on one resource.

Three answers, from most to least direct:

- direct: the principal's own policies (with SCPs, the permissions boundary and the resource
  policy, if given) allow the request. Each comes with the statements that granted it.
- via escalation: the principal cannot do it itself, but has a confirmed path (from `escalate`) to
  a principal that can. The shortest such path is shown.
- outside the export: principals a resource policy names that are not in the account export
  (other accounts, services, "*"). Their own policies are unknown, so they are listed, not judged.

A principal is evaluated with the same engine as `can`; nothing is approximated.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from typing import Any

from iamtrace.escalate import Environment, analyze
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy


def account_of(resource: str, default: str | None) -> str | None:
    parts = resource.split(":", 5)
    return parts[4] if len(parts) > 4 and parts[0] == "arn" and parts[4] else default


def outside_principals(env: Environment, policy: Policy | None, action: str) -> list[dict[str, Any]]:
    """Principals named by Allow statements of the resource policy that the export does not have."""
    if policy is None:
        return []
    out = []
    seen = set()
    for st in policy.statements:
        if st.effect != "Allow" or (st.actions is not None and not any_action_matches(st.actions, action)):
            continue
        p = st.principal
        values: list[tuple[str, str]] = []
        if p == "*":
            values.append(("AWS", "*"))
        elif isinstance(p, dict):
            for kind, items in p.items():
                values += [(kind, v) for v in items]
        for kind, v in values:
            if v in env.nodes or (kind, v) in seen:
                continue
            seen.add((kind, v))
            what = {
                "AWS": "anyone (public)" if v == "*" else "an AWS principal outside this export",
                "Service": "an AWS service",
                "Federated": "a federated identity provider",
            }.get(kind, kind)
            out.append(
                {"principal": v, "kind": kind, "what": what, "statement": st.label, "conditional": bool(st.condition)}
            )
    return out


def escalation_routes(env: Environment, report: dict[str, Any], direct: set[str]) -> list[dict[str, Any]]:
    """For every principal outside `direct`, the shortest confirmed escalation route to one inside
    it: open steps first, then steps that need MFA, a network location or a time window."""
    # A step can need MFA, a network location or a time window ("requires", from the analysis).
    edges: dict[str, list[tuple[str, str, str, list[dict[str, str]]]]] = {}
    for p in report["principals"]:
        for t in p["techniques"]:
            if t["confidence"] != "confirmed":
                continue
            for target in t["targets"]:
                if target in env.nodes and target != p["arn"]:
                    gate = t.get("requires") or t.get("gated_targets", {}).get(target) or []
                    edges.setdefault(p["arn"], []).append((target, t["id"], t["name"], gate))

    via: list[dict[str, Any]] = []
    for arn, node in env.nodes.items():
        if arn in direct:
            continue
        # Breadth-first, over open steps first: the first principal with direct access ends the
        # shortest path. Only if there is none, steps that need MFA or a network are allowed too.
        for open_only in (True, False):
            prev: dict[str, tuple[str, str, str, list[dict[str, str]]]] = {}
            queue = deque([arn])
            seen = {arn}
            end = None
            while queue and end is None:
                cur = queue.popleft()
                for nxt, tid, name, gate in edges.get(cur, []):
                    if nxt in seen or (open_only and gate):
                        continue
                    seen.add(nxt)
                    prev[nxt] = (cur, tid, name, gate)
                    if nxt in direct:
                        end = nxt
                        break
                    queue.append(nxt)
            if end is not None:
                break
        if end is None:
            continue
        steps = []
        cur = end
        requires: list[dict[str, str]] = []
        while cur != arn:
            frm, tid, name, gate = prev[cur]
            steps.append(
                {"from": frm, "to": cur, "technique": tid, "name": name, **({"requires": gate} if gate else {})}
            )
            requires += [r for r in gate if r not in requires]
            cur = frm
        steps.reverse()
        via.append(
            {
                "principal": arn,
                "kind": node.kind,
                "through": end,
                "steps": steps,
                "open": not requires,
                **({"requires": requires} if requires else {}),
            }
        )
    via.sort(key=lambda v: (not v["open"], len(v["steps"]), v["principal"]))
    return via


def allowed_principals(
    env: Environment,
    action: str,
    resource: str,
    *,
    scps: list[list[Policy]] | None = None,
    resource_policy: Policy | None = None,
    context: dict[str, Any] | None = None,
    context_for: Callable[[str], Mapping[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Every principal in the export whose own policies (with SCPs, its boundary and the resource
    policy) allow the request, with the statements that granted it.

    `context_for`, given a caller's account ID, adds context keys that depend on the caller (such
    as kms:CallerAccount); `context` is the same for every caller."""
    direct: dict[str, dict[str, Any]] = {}
    for arn, node in env.nodes.items():
        ctx = {**(context or {}), **(context_for(node.account) if context_for else {})}
        req = Request(node.caller(), action, resource, resource_account=account_of(resource, node.account), context=ctx)
        ps = PolicySet(
            identity=node.policies,
            boundary=node.boundary,
            scps=scps,
            resource=[resource_policy] if resource_policy else [],
        )
        r = evaluate(req, ps)
        if r.allowed:
            grants = [
                f"{m.policy_id} / {m.statement}"
                for t in r.trace
                if t.outcome in ("allow", "pass")
                for m in t.matches
                if m.effect == "Allow" and m.policy_type in ("identity", "resource")
            ]
            direct[arn] = {"principal": arn, "kind": node.kind, "granted_by": sorted(set(grants))}
    return direct


def who_can(
    env: Environment,
    action: str,
    resource: str,
    *,
    scps: list[list[Policy]] | None = None,
    resource_policy: Policy | None = None,
    context: dict[str, Any] | None = None,
    context_for: Callable[[str], Mapping[str, Any]] | None = None,
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    direct = allowed_principals(
        env, action, resource, scps=scps, resource_policy=resource_policy, context=context, context_for=context_for
    )
    report = report or analyze(env, scps=scps)
    via = escalation_routes(env, report, set(direct))

    outside = outside_principals(env, resource_policy, action)
    total = len(env.nodes)
    return {
        "action": action,
        "resource": resource,
        "checked": total,
        "direct": sorted(direct.values(), key=lambda d: d["principal"]),
        "via": via,
        "outside": outside,
        "cannot": total - len(direct) - len(via),
        "warnings": report.get("warnings", []),
    }


def who_can_text(r: dict[str, Any]) -> str:
    lines = [
        f"Who can {r['action']} on {r['resource']}",
        f"Checked {r['checked']} principals: {len(r['direct'])} directly, {len(r['via'])} through escalation, "
        f"{r['cannot']} cannot.",
        "",
        "Directly:" if r["direct"] else "Directly: nobody",
    ]
    for d in r["direct"]:
        lines.append(f"  {d['principal']}")
        for g in d["granted_by"]:
            lines.append(f"    granted by {g}")
    if r["via"]:
        lines += ["", "Through escalation (shortest path to someone who can):"]
        for v in r["via"]:
            chain = " -> ".join([v["principal"]] + [f"[{s['technique']}] {s['to']}" for s in v["steps"]])
            if v.get("requires"):
                chain += "  (only when " + "; ".join(r["text"] for r in v["requires"]) + ")"
            lines.append(f"  {chain}")
    if r["outside"]:
        lines += ["", "Named by the resource policy but not in the export (their own policies are unknown):"]
        for o in r["outside"]:
            cond = ", with a condition" if o["conditional"] else ""
            lines.append(f"  {o['principal']} ({o['what']}, {o['statement']}{cond})")
    return "\n".join(lines) + "\n"
