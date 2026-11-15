"""Fix plan: the smallest set of policy changes that removes every path to admin, proven.

The escalation analysis gives a graph. Its nodes are principals plus one "admin" sink; its edges
are confirmed techniques (A can become B), plus an edge to the sink for every technique that
grants admin by itself (self-escalation, or changing another principal's permissions). Principals
that are admin-equivalent on their own (Action "*") connect to the sink by an edge that cannot be
cut: they are the admins, and the plan is about who can reach them.

A technique needs all of its permissions, so denying any one of them breaks the edge. A denial is
a *unit*: (principal, action, resources). Where the permission applies to the edge's target (the
role passed, the role assumed, the user whose keys are created), the unit is scoped to that
target. Otherwise (ec2:RunInstances, lambda:CreateFunction) it is denied on every resource, which
breaks more of what the principal legitimately does, so it costs more. One unit can break several
edges: denying iam:PassRole on one role breaks every technique that passes it.

Choosing the cheapest set of units that leaves no route from the starting principal(s) to the sink
is a weighted minimum hitting set over routes. There can be many routes, so they are added lazily:
find a surviving route, require the solution to hit it, solve again exactly (branch and bound),
repeat until no route survives. Then the plan is applied for real, as Deny statements added to a
copy of the account, and the full analysis runs again. Only if that finds no path is the plan
called verified; if it finds one, that route is added and the plan is solved again.

Equal-cost plans are broken in favour of cuts that also remove other principals' paths, so the
fix for one starting principal does as much good as it can for the rest of the account.
"""

from __future__ import annotations

import dataclasses
import json
from collections import deque
from collections.abc import Iterable
from typing import Any

from iamtrace.arn import resource_matches
from iamtrace.context import Context
from iamtrace.escalate import FULL_ADMIN, PERMISSION_TARGET, Environment, analyze
from iamtrace.inventory import TECHNIQUE_KIND
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyType

SINK = "#admin"
TARGETED_COST = 1.0
EVERYWHERE_COST = 3.0
TIE_BREAK = 0.001  # per other edge a unit also breaks; small enough never to outweigh a whole unit
MAX_ROUNDS = 400
_NO_CONTEXT = Context()

Unit = tuple[str, str, tuple[str, ...]]  # (principal, action, resources)


@dataclasses.dataclass(frozen=True)
class _Edge:
    source: str
    target: str  # a principal ARN or SINK
    technique: str
    name: str
    units: frozenset[Unit]


# --- the solver --------------------------------------------------------------------------------


def min_hitting_set(sets: list[frozenset[Any]], cost: dict[Any, float], budget: int = 200_000) -> tuple[set[Any], bool]:
    """The cheapest set of elements that has at least one element of every set.

    Exact branch and bound: take the unhit set with the fewest options, try each option, prune
    any branch whose cost reaches the best found. Returns (choice, optimal); if the search runs
    out of budget, the best found so far is returned with optimal False (the greedy start
    guarantees there is one). Raises ValueError if a set is empty, as nothing can hit it.
    """
    if any(not s for s in sets):
        raise ValueError("a route has no permission that can be denied")
    uniq = sorted(set(sets), key=len)
    # Greedy start: a good first bound makes the exact search prune early.
    best: set[Any] = set()
    left = list(uniq)
    while left:
        counts: dict[Any, int] = {}
        for s in left:
            for x in s:
                counts[x] = counts.get(x, 0) + 1
        pick = min(counts, key=lambda x: (cost.get(x, 1.0) / counts[x], str(x)))
        best.add(pick)
        left = [s for s in left if pick not in s]
    best_cost = sum(cost.get(x, 1.0) for x in best)
    steps = 0
    exhausted = False

    def search(chosen: frozenset[Any], spent: float) -> None:
        nonlocal best, best_cost, steps, exhausted
        steps += 1
        if steps > budget:
            exhausted = True
            return
        unhit = [s for s in uniq if not (s & chosen)]
        if not unhit:
            if spent < best_cost - 1e-12:
                best, best_cost = set(chosen), spent
            return
        # Lower bound: the cheapest option of the unhit set that is hardest to hit.
        target = min(unhit, key=len)
        floor = max(min(cost.get(x, 1.0) for x in s) for s in unhit)
        if spent + floor >= best_cost - 1e-12:
            return
        for x in sorted(target, key=lambda x: (cost.get(x, 1.0), str(x))):
            search(chosen | {x}, spent + cost.get(x, 1.0))
            if exhausted:
                return

    search(frozenset(), 0.0)
    return best, not exhausted


# --- the graph ---------------------------------------------------------------------------------


def _units_for(env: Environment, src: str, perm: str, target: str | None, technique: dict[str, Any]) -> Unit:
    """The denial of one permission that breaks this technique towards this target."""
    p = perm.lower()
    ptype = PERMISSION_TARGET.get(p)
    tnode = env.nodes.get(target) if target else None
    if ptype in ("user", "role") and tnode is not None:
        return (src, perm, (tnode.arn,))
    if ptype == "policy" and tnode is not None:
        customer = tuple(sorted(a for a in tnode.attached if ":iam::aws:policy/" not in a))
        if customer:
            return (src, perm, customer)
    if technique["category"] == "existing-passrole" and tnode is not None and env.resources is not None:
        kind = TECHNIQUE_KIND.get(technique["id"])
        via = set(technique.get("via") or [])
        arns = tuple(sorted(r.arn for r in env.resources.of_kind(kind or "") if r.role == tnode.arn and r.arn in via))
        if arns:
            return (src, perm, arns)
    return (src, perm, ("*",))


def _edges(env: Environment, report: dict[str, Any], gated: bool = False) -> tuple[list[_Edge], set[str]]:
    """Every confirmed edge of an analysis, and the principals that are admins on their own.
    Without `gated`, steps and admin access that need MFA, a network location or a time window
    are left out: the plan is about what anyone holding the credentials can do."""
    edges: list[_Edge] = []
    admins: set[str] = set()
    for p in report["principals"]:
        src = p["arn"]
        if p["admin_reason"] == FULL_ADMIN and (gated or not p.get("admin_requires")):
            admins.add(src)
        for t in p["techniques"]:
            if t["confidence"] != "confirmed" or (t.get("requires") and not gated):
                continue
            if t["category"] == "self-escalation":
                main = t["permissions"][0]
                own: set[Unit] = {(src, main, tuple(sorted(t["targets"])))}
                own |= {(src, x, ("*",)) for x in t["permissions"][1:]}
                edges.append(_Edge(src, SINK, t["id"], t["name"], frozenset(own)))
                continue
            for target in t["targets"]:
                if target not in env.nodes or (not gated and target in t.get("gated_targets", {})):
                    continue
                units = frozenset(_units_for(env, src, perm, target, t) for perm in t["permissions"])
                edges.append(_Edge(src, target, t["id"], t["name"], units))
                if t["grants_admin"]:
                    edges.append(_Edge(src, SINK, t["id"], t["name"], units))
    return edges, admins


def _route(roots: Iterable[str], edges: list[_Edge], admins: set[str], cut: set[Unit]) -> list[_Edge] | None:
    """A shortest surviving route from any root to admin, or None."""
    out: dict[str, list[_Edge]] = {}
    for e in edges:
        if not (e.units & cut):
            out.setdefault(e.source, []).append(e)
    for root in sorted(roots):
        if root in admins:
            continue
        prev: dict[str, _Edge | None] = {root: None}
        q = deque([root])
        while q:
            cur = q.popleft()
            for e in out.get(cur, []):
                if e.target in prev:
                    continue
                prev[e.target] = e
                if e.target == SINK or e.target in admins:
                    route = []
                    node = e.target
                    while prev[node] is not None:
                        edge = prev[node]
                        assert edge is not None
                        route.append(edge)
                        node = edge.source
                    return route[::-1]
                q.append(e.target)
    return None


# --- applying a plan ---------------------------------------------------------------------------


def _statements(units: Iterable[Unit]) -> dict[str, list[dict[str, Any]]]:
    """Deny statements per principal; units with the same resources share a statement."""
    grouped: dict[tuple[str, tuple[str, ...]], set[str]] = {}
    for principal, action, res in units:
        grouped.setdefault((principal, res), set()).add(action)
    out: dict[str, list[dict[str, Any]]] = {}
    for (principal, res), actions in sorted(grouped.items()):
        acts = sorted(actions, key=str.lower)
        out.setdefault(principal, []).append(
            {
                "Sid": f"IamTraceFix{len(out.get(principal, [])) + 1}",
                "Effect": "Deny",
                "Action": acts[0] if len(acts) == 1 else acts,
                "Resource": res[0] if len(res) == 1 else list(res),
            }
        )
    return out


def _apply(env: Environment, units: Iterable[Unit]) -> tuple[Environment, dict[str, dict[str, Any]]]:
    policies = {principal: {"Version": "2012-10-17", "Statement": sts} for principal, sts in _statements(units).items()}
    nodes = dict(env.nodes)
    for principal, doc in policies.items():
        node = nodes[principal]
        fix = Policy.parse(doc, policy_id=f"{principal} inline iam-trace-fix", policy_type=PolicyType.IDENTITY)
        nodes[principal] = dataclasses.replace(node, policies=[*node.policies, fix])
    fixed = Environment(nodes, env.groups, env.warnings, raw=env.raw, inventory=env.inventory)
    fixed.resources = env.resources
    return fixed, policies


def _granted_by(env: Environment, unit: Unit) -> list[dict[str, str]]:
    """The Allow statements that grant the permission a unit denies: where to narrow it instead."""
    principal, action, res = unit
    node = env.nodes[principal]
    found: list[dict[str, str]] = []
    for pol in node.policies:
        for st in pol.statements:
            if st.effect != "Allow":
                continue
            if st.actions is not None:
                if not any_action_matches(st.actions, action):
                    continue
            elif any_action_matches(st.not_actions or (), action):
                continue
            if res != ("*",) and st.resources is not None:
                if not any(resource_matches(pat, r, _NO_CONTEXT, False) for pat in st.resources for r in res):
                    continue
            found.append({"policy": pol.id, "statement": st.label})
    if action.lower() == "sts:assumerole":
        for r in res:
            target = env.nodes.get(r)
            if target is None or target.trust is None:
                continue
            for st in target.trust.statements:
                who = json.dumps(st.principal)
                if st.effect == "Allow" and (principal in who or f":{node.account}:root" in who or '"*"' in who):
                    found.append({"policy": target.trust.id, "statement": st.label})
    return found


# --- the plan ----------------------------------------------------------------------------------


def fix_plan(
    env: Environment,
    start: str | None = None,
    *,
    scps: list[list[Policy]] | None = None,
    everyone: dict[str, Any] | None = None,
    include_gated: bool = False,
) -> dict[str, Any]:
    """The cheapest verified set of denials that removes every path to admin from `start`, or
    from every principal when `start` is None. Keys starting with "_" are Python objects for
    callers that want them (the fixed environment); everything else is JSON.

    `everyone` is `analyze(env, scps=scps)` if the caller already has it. The whole account is
    analysed once before and once after the change: one starting principal's view is part of it.

    By default only open paths are cut: those anyone holding the credentials can follow. Paths that
    need MFA, a network location or a time window are often intended (break-glass admin access with
    MFA), so they are counted in `gated_left` instead; `include_gated` cuts them too.
    """
    if start is not None and start not in env.nodes:
        raise ValueError(f"{start} is not in the account export")
    if everyone is None:
        everyone = analyze(env, scps=scps)
    all_edges, admins = _edges(env, everyone, include_gated)
    edges = all_edges
    all_roots = {p["arn"] for p in everyone["principals"]} - admins
    roots = [start] if start else sorted(all_roots)
    report = everyone

    def counted(p: dict[str, Any]) -> bool:
        return p["start"] in roots and (include_gated or p.get("open", True))

    def counted_any(p: dict[str, Any]) -> bool:
        return include_gated or p.get("open", True)

    paths_before = sum(1 for p in everyone["paths"] if counted(p))
    base: dict[str, Any] = {
        "start": start,
        "changes": [],
        "policies": {},
        "paths_before": paths_before,
        "paths_after": paths_before,
        "also_fixed": [],
        "still_at_risk": [],
        "techniques_removed": [],
        "not_covered": _not_covered(report, _reachable(roots, all_edges)),
        "optimal": True,
        "verified": False,
        "include_gated": include_gated,
        "gated_left": 0
        if include_gated
        else sum(1 for p in everyone["paths"] if p["start"] in roots and not p.get("open", True)),
    }

    if start is not None and start in admins:
        return {**base, "status": "start-is-admin", "verified": True, "_fixed_env": env}
    if _route(roots, edges, admins, set()) is None:
        return {**base, "status": "nothing-to-fix", "paths_after": 0, "verified": True, "_fixed_env": env}

    # Unit costs: targeted denials are cheap; a tiny bonus for every other edge in the account
    # a unit breaks steers ties toward cuts that help other principals too.
    # The bonus counts, for each edge a unit breaks, how many principals can reach that edge:
    # cutting near admin helps everyone upstream, cutting next to the start helps only the start.
    reach = _reached_by(all_roots, all_edges)
    help_count: dict[Unit, int] = {}
    for e in all_edges:
        for u in e.units:
            help_count[u] = help_count.get(u, 0) + len(reach.get(e.source, ()))
    most = max(help_count.values(), default=1) or 1
    unit_cost: dict[Unit, float] = {}
    for e in [*edges, *all_edges]:
        for u in e.units:
            base_cost = EVERYWHERE_COST if u[2] == ("*",) else TARGETED_COST
            unit_cost[u] = base_cost - TIE_BREAK * help_count.get(u, 0) / most

    constraints: list[frozenset[Unit]] = []
    cut: set[Unit] = set()
    optimal = True
    fixed_env = env
    policies: dict[str, dict[str, Any]] = {}
    after_report: dict[str, Any] = report
    for _attempt in range(5):
        for _round in range(MAX_ROUNDS):
            route = _route(roots, edges, admins, cut)
            if route is None:
                break
            constraints.append(frozenset(u for e in route for u in e.units))
            cut, exact = min_hitting_set(constraints, unit_cost)
            optimal = optimal and exact
        else:
            optimal = False
        fixed_env, policies = _apply(env, cut)
        after_report = analyze(fixed_env, scps=scps)
        after_edges, after_admins = _edges(fixed_env, after_report, include_gated)
        leftover = _route(roots, after_edges, after_admins, set())
        if leftover is None and not any(counted(p) for p in after_report["paths"]):
            break
        if leftover is None:
            break  # the analysis reports a path the edge model cannot see: stop, unverified
        # The model missed something the real analysis found: require this route too.
        edges = edges + [e for e in after_edges if e not in edges]
        constraints.append(frozenset(u for e in leftover for u in e.units))
        cut, exact = min_hitting_set(constraints, unit_cost)
        optimal = optimal and exact

    verified = not any(counted(p) for p in after_report["paths"]) and not any(
        p["admin_equivalent"] and (include_gated or not p.get("admin_requires"))
        for p in after_report["principals"]
        if p["arn"] in roots
    )
    everyone_after = after_report
    starts_before = {p["start"] for p in everyone["paths"] if counted_any(p)}
    starts_after = {p["start"] for p in everyone_after["paths"] if counted_any(p)}
    removed = _technique_diff(everyone, everyone_after)

    changes = []
    for u in sorted(cut, key=lambda u: (u[0], u[1].lower(), u[2])):
        principal, action, res = u
        broken = [e for e in all_edges if u in e.units] or [e for e in edges if u in e.units]
        changes.append(
            {
                "principal": principal,
                "effect": "Deny",
                "actions": [action],
                "resources": list(res),
                "scope": "everywhere" if res == ("*",) else "targeted",
                "breaks": [
                    {
                        "from": e.source,
                        "to": "admin" if e.target == SINK else e.target,
                        "technique": e.technique,
                        "name": e.name,
                    }
                    for e in sorted(set(broken), key=lambda e: (e.source, e.technique, e.target))
                ],
                "granted_by": _granted_by(env, u),
                "consequence": _consequence(principal, action, res),
            }
        )
    return {
        **base,
        "status": "fixed" if verified else "not-verified",
        "changes": changes,
        "policies": policies,
        "paths_after": sum(1 for p in after_report["paths"] if counted(p)),
        "gated_left": 0
        if include_gated
        else sum(1 for p in after_report["paths"] if p["start"] in roots and not p.get("open", True)),
        "also_fixed": sorted((starts_before - starts_after) - set(roots)),
        "still_at_risk": sorted(starts_after - set(roots)),
        "techniques_removed": removed,
        "optimal": optimal,
        "verified": verified,
        "_fixed_env": fixed_env,
    }


def _reached_by(roots: Iterable[str], edges: list[_Edge]) -> dict[str, set[str]]:
    """For each principal, the roots that can reach it (itself included)."""
    out: dict[str, list[str]] = {}
    for e in edges:
        if e.target != SINK:
            out.setdefault(e.source, []).append(e.target)
    reached: dict[str, set[str]] = {}
    for root in roots:
        seen = {root}
        q = deque([root])
        while q:
            cur = q.popleft()
            reached.setdefault(cur, set()).add(root)
            for nxt in out.get(cur, []):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
    return reached


def _reachable(roots: Iterable[str], edges: list[_Edge]) -> set[str]:
    return set(_reached_by(roots, edges))


def _not_covered(report: dict[str, Any], reachable: set[str]) -> int:
    """Possible techniques of the principals the attacker can reach: they are not part of any
    path, so a plan cannot be checked against them."""
    return sum(
        1
        for p in report["principals"]
        if p["arn"] in reachable and not (p["admin_equivalent"] and not p.get("admin_requires"))
        for t in p["techniques"]
        if t["confidence"] == "possible"
    )


def _technique_diff(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, str]]:
    def keys(r: dict[str, Any]) -> set[tuple[str, str, str]]:
        return {
            (p["arn"], t["id"], target)
            for p in r["principals"]
            for t in p["techniques"]
            if t["confidence"] == "confirmed"
            for target in t["targets"]
        }

    gone = keys(before) - keys(after)
    return [{"principal": a, "technique": t, "target": x} for a, t, x in sorted(gone)]


def _consequence(principal: str, action: str, res: tuple[str, ...]) -> str:
    who = _short(principal)
    if res == ("*",):
        return f"{who} can no longer call {action} on any resource."
    names = ", ".join(_short(r) for r in res)
    return f"{who} can no longer call {action} on {names}. Everything else it is allowed stays allowed."


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def public(plan: dict[str, Any]) -> dict[str, Any]:
    """The plan without its Python-only keys, ready for JSON."""
    return {k: v for k, v in plan.items() if not k.startswith("_")}


def fix_plan_text(plan: dict[str, Any]) -> str:
    who = _short(plan["start"]) if plan["start"] else "every principal"
    status = plan["status"]
    if status == "start-is-admin":
        return f"{who} is already admin-equivalent on its own. There is no path to cut.\n"
    if status == "nothing-to-fix":
        gated = plan.get("gated_left", 0)
        if gated:
            return (
                f"No open path to admin from {who}. {gated} path{'s' if gated != 1 else ''} need MFA, a network "
                "location or a time window; use --include-gated to cut them too.\n"
            )
        return f"No confirmed path to admin from {who}. Nothing to fix.\n"
    lines = []
    n = len(plan["changes"])
    head = "Verified" if plan["verified"] else "NOT verified"
    lines.append(
        f"{head}: {n} change{'s' if n != 1 else ''} remove{'' if n != 1 else 's'} every path to admin from {who} "
        f"({plan['paths_before']} before, {plan['paths_after']} after, checked by analysing the changed account again)."
    )
    if plan.get("gated_left"):
        lines.append(
            f"{plan['gated_left']} path{'s' if plan['gated_left'] != 1 else ''} that need MFA, a network location or a "
            "time window are left as they are (use --include-gated to cut them too)."
        )
    if not plan["optimal"]:
        lines.append("The search stopped early: this plan works but may not be the smallest.")
    if plan["also_fixed"]:
        lines.append("Also removes the paths of: " + ", ".join(_short(x) for x in plan["also_fixed"]) + ".")
    if plan["still_at_risk"]:
        lines.append(
            "Other principals that still reach admin: " + ", ".join(_short(x) for x in plan["still_at_risk"]) + "."
        )
    for i, c in enumerate(plan["changes"], 1):
        lines.append("")
        lines.append(
            f"{i}. Deny {', '.join(c['actions'])} for {_short(c['principal'])} "
            f"on {', '.join(_short(r) for r in c['resources'])}"
        )
        lines.append(f"   {c['consequence']}")
        lines.append(
            "   Breaks: "
            + "; ".join(f"{_short(b['from'])} -> {_short(b['to'])} ({b['technique']})" for b in c["breaks"])
        )
        if c["granted_by"]:
            lines.append(
                "   Or narrow where it is granted: "
                + "; ".join(f"{_short(g['policy'])} {g['statement']}" for g in c["granted_by"])
            )
    for principal, policy in plan["policies"].items():
        lines.append("")
        lines.append(f"Inline policy for {_short(principal)}:")
        lines.append(json.dumps(policy, indent=2))
    if plan["not_covered"]:
        lines.append("")
        lines.append(
            f"{plan['not_covered']} possible technique{'s' if plan['not_covered'] != 1 else ''} depend on "
            "resources the export does not describe and are not covered by this check. "
            "Add a resource inventory to confirm them."
        )
    return "\n".join(lines) + "\n"
