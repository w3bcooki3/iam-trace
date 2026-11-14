"""What would change the answer: counterfactual explanations for one request.

`evaluate` says whether a request is allowed and why. This module answers the next question a
person asks, by changing one thing at a time and evaluating again with the same engine:

- Denied: the smallest set of changes that would allow it. Remove or narrow the Deny that applies,
  send a context value that stops it applying, or add the missing Allow to each layer that refused
  (identity, permissions boundary, session policy, SCPs, RCPs, resource policy), in AWS's order.
- Allowed: what the decision depends on. Statements without which it would be denied, context
  keys whose absence or other value would deny it, and Deny statements that would start to apply.
- Near misses: Allow statements that name the action but fail on the resource, the principal or a
  condition, with the reason. These are usually the typo or the wrong ARN.

Every suggestion is verified by re-running `evaluate`; nothing is reported from reasoning about the
policy text alone. Suggestions are minimal (the exact action and resource, the exact principal),
not least-privilege advice for the whole policy.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import replace
from typing import Any

from iamtrace.arn import resource_matches
from iamtrace.conditions import evaluate_condition_block
from iamtrace.evaluate import Decision, PolicySet, Request, Result, _build_context, evaluate
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyType, Statement

# Keys AWS sets on every request. A person cannot choose them, so they are never suggested.
_AUTOMATIC = {"aws:principalarn", "aws:principalaccount", "aws:principaltype", "aws:username", "aws:resourceaccount"}

_LAYER = {
    "identity_policy": "the identity-based policies",
    "permissions_boundary": "the permissions boundary",
    "session_policy": "the session policy",
    "resource_policy": "the resource-based policy",
    "scp": "the service control policies",
    "rcp": "the resource control policies",
}


# --- changing a policy set --------------------------------------------------------------


def _policies(ps: PolicySet) -> list[Policy]:
    return list(ps.all_policies())


def _without(ps: PolicySet, policy_id: str, index: int) -> PolicySet:
    """A copy of the policy set with one statement removed."""

    def strip(p: Policy) -> Policy:
        if p.id != policy_id:
            return p
        return replace(p, statements=tuple(s for s in p.statements if s.index != index))

    return replace(
        ps,
        identity=[strip(p) for p in ps.identity],
        resource=[strip(p) for p in ps.resource],
        boundary=strip(ps.boundary) if ps.boundary else None,
        session=[strip(p) for p in ps.session],
        scps=[[strip(p) for p in level] for level in ps.scps] if ps.scps is not None else None,
        rcps=[[strip(p) for p in level] for level in ps.rcps] if ps.rcps is not None else None,
    )


def _statement_policy(doc: dict[str, Any], ptype: PolicyType, layer: str) -> Policy:
    return Policy.parse(
        {"Version": "2012-10-17", "Statement": [doc]}, policy_id=f"suggested {layer} statement", policy_type=ptype
    )


def _merge(p: Policy, extra: Policy) -> Policy:
    start = len(p.statements)
    added = tuple(replace(s, index=start + i) for i, s in enumerate(extra.statements))
    return replace(p, statements=p.statements + added)


def _principal_element(req: Request) -> dict[str, Any]:
    p = req.principal
    if p.kind == "service" and p.service_name:
        return {"Service": p.service_name}
    arn = p.role_arn or p.principal_arn or p.arn
    return {"AWS": arn or (f"arn:aws:iam::{p.account}:root" if p.account else "*")}


def _add(ps: PolicySet, req: Request, step: str) -> tuple[PolicySet, dict[str, Any]] | None:
    """Add the smallest Allow that satisfies `step`. Returns the new set and the statement added."""
    stmt: dict[str, Any] = {"Effect": "Allow", "Action": req.action, "Resource": req.resource or "*"}
    if step == "identity_policy":
        return replace(ps, identity=[*ps.identity, _statement_policy(stmt, PolicyType.IDENTITY, "identity")]), stmt
    if step == "permissions_boundary":
        extra = _statement_policy(stmt, PolicyType.BOUNDARY, "boundary")
        return replace(ps, boundary=_merge(ps.boundary, extra) if ps.boundary else extra), stmt
    if step == "session_policy":
        extra = _statement_policy(stmt, PolicyType.SESSION, "session")
        return replace(ps, session=[_merge(p, extra) for p in ps.session] or [extra]), stmt
    if step in ("scp", "rcp"):
        levels = ps.scps if step == "scp" else ps.rcps
        if levels is None:
            return None
        ptype = PolicyType.SCP if step == "scp" else PolicyType.RCP
        if step == "rcp":
            stmt = {"Effect": "Allow", "Principal": "*", "Action": req.action, "Resource": req.resource or "*"}
        extra = _statement_policy(stmt, ptype, step.upper())
        new = [[*level, extra] for level in levels]
        return (replace(ps, scps=new) if step == "scp" else replace(ps, rcps=new)), stmt
    if step == "resource_policy":
        stmt = {"Effect": "Allow", "Principal": _principal_element(req), "Action": req.action}
        if req.resource and req.resource != "*":
            stmt["Resource"] = req.resource
        return replace(ps, resource=[*ps.resource, _statement_policy(stmt, PolicyType.RESOURCE, "resource")]), stmt
    return None


def _with_context(req: Request, key: str, value: str | None) -> Request:
    ctx = {k: v for k, v in req.context.items() if k.lower() != key.lower()}
    if value is not None:
        ctx[key] = value
    return replace(req, context=ctx)


# --- condition values worth trying ------------------------------------------------------


def _candidates(op: str, values: tuple[str, ...], current: tuple[str, ...] | None) -> list[str | None]:
    """Values for one condition key that might change the outcome: the policy's own values made
    concrete, the opposite boolean, and the key being absent."""
    out: list[str | None] = []
    base = op.split(":")[-1].removesuffix("IfExists").lower()
    for v in values:
        if "${" in v:
            continue
        if base in ("bool",):
            out += [v.lower(), "false" if v.lower() == "true" else "true"]
        elif base in ("ipaddress", "notipaddress"):
            try:
                net = ipaddress.ip_network(v, strict=False)
                inside = str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address)
                out += [
                    inside,
                    "203.0.113.10" if not net.overlaps(ipaddress.ip_network("203.0.113.0/24")) else "198.51.100.10",
                ]
            except ValueError:
                continue
        elif base.startswith(("date",)):
            continue
        elif base.startswith("numeric"):
            try:
                n = float(v)
            except ValueError:
                continue
            out += [
                v,
                str(int(n) + 1) if n.is_integer() else str(n + 1),
                str(int(n) - 1) if n.is_integer() else str(n - 1),
            ]
        else:
            # Strings and ARNs: make wildcards concrete so a Like operator matches.
            out.append(v.replace("*", "example").replace("?", "x"))
    if current:
        out.append(None)  # the key not sent at all
    unique: list[str | None] = []
    for cand in out:
        if cand not in unique and (current is None or cand is None or (cand,) != current):
            unique.append(cand)
    return unique


def _current(req: Request, key: str) -> tuple[str, ...] | None:
    for k, v in req.context.items():
        if k.lower() == key.lower():
            return tuple(str(x) for x in v) if isinstance(v, list | tuple) else (str(v),)
    return None


def _show(value: str | None) -> str:
    return "not sent" if value is None else value


# --- near misses ------------------------------------------------------------------------


def _near_misses(req: Request, ps: PolicySet) -> list[dict[str, Any]]:
    """Allow statements that name the action but do not apply, with the first reason found."""
    ctx = _build_context(req, req.resource_account or req.principal.account)
    out = []
    for pol in _policies(ps):
        for s in pol.statements:
            if s.effect != "Allow":
                continue
            if s.actions is not None and not any_action_matches(s.actions, req.action):
                continue
            if s.not_actions is not None and any_action_matches(s.not_actions, req.action):
                continue
            reason = _miss_reason(s, pol, req, ctx)
            if reason:
                out.append({"policy": pol.id, "policy_type": pol.type.value, "statement": s.label, "reason": reason})
    return out


def _miss_reason(s: Statement, pol: Policy, req: Request, ctx: Any) -> str | None:
    v = pol.variables_enabled
    if s.resources is not None and not any(resource_matches(r, req.resource, ctx, v) for r in s.resources):
        return f"it allows the action only on {', '.join(s.resources)}, not on {req.resource}"
    if s.not_resources is not None and any(resource_matches(r, req.resource, ctx, v) for r in s.not_resources):
        return f"it excludes {req.resource} with NotResource"
    cond = evaluate_condition_block(s.condition, ctx, v)
    if not cond.matched:
        # The evaluator stops at the first failing key, so the last detail is the reason.
        return "its condition is not met: " + (cond.details[-1] if cond.details else "a condition key does not match")
    return None  # it applies; any reason it does not count is in the trace (principal, other layers)


# --- the analysis -------------------------------------------------------------------------


def _deny_matches(r: Result) -> list[tuple[str, int, str]]:
    for t in r.trace:
        if t.step == "explicit_deny" and t.outcome == "deny":
            return [(m.policy_id, m.index, m.statement) for m in t.matches]
    return []


def _allow_matches(r: Result) -> list[tuple[str, int, str, str]]:
    seen = set()
    out = []
    for t in r.trace:
        if t.outcome in ("allow", "pass"):
            for m in t.matches:
                if m.effect == "Allow" and (m.policy_id, m.index) not in seen:
                    seen.add((m.policy_id, m.index))
                    out.append((m.policy_id, m.index, m.statement, t.step))
    return out


def _refusing_step(r: Result) -> str | None:
    for t in reversed(r.trace):
        if t.outcome == "deny":
            return t.step
    return None


def _find_statement(ps: PolicySet, policy_id: str, index: int) -> Statement | None:
    for p in _policies(ps):
        if p.id == policy_id:
            for s in p.statements:
                if s.index == index:
                    return s
    return None


def _complete_allows(req: Request, ps: PolicySet, limit: int = 6) -> tuple[list[dict[str, Any]], PolicySet, Result]:
    """Add Allows, layer by layer, until the request is allowed (or nothing more can be added)."""
    added: list[dict[str, Any]] = []
    r = evaluate(req, ps)
    while not r.allowed and r.decision is Decision.IMPLICIT_DENY and len(added) < limit:
        step = _refusing_step(r)
        made = _add(ps, req, step) if step else None
        if made is None:
            break
        ps, stmt = made
        added.append({"layer": step, "where": _LAYER.get(step or "", step), "statement": stmt})
        r = evaluate(req, ps)
    return added, ps, r


def what_if(req: Request, ps: PolicySet, result: Result | None = None) -> dict[str, Any]:
    result = result or evaluate(req, ps)
    out: dict[str, Any] = {"decision": result.decision.value, "fixes": [], "depends_on": [], "near_misses": []}
    if result.allowed:
        _explain_allowed(req, ps, result, out)
    else:
        _explain_denied(req, ps, result, out)
        out["near_misses"] = _near_misses(req, ps)
    out["summary"] = _summary(result, out)
    return out


def _explain_denied(req: Request, ps: PolicySet, result: Result, out: dict[str, Any]) -> None:
    denies = _deny_matches(result)
    if denies:
        # 1. A context value that stops every applicable Deny, if the rest already allows.
        for pid, idx, label in denies:
            st = _find_statement(ps, pid, idx)
            if st is None:
                continue
            for op, keys in st.condition.items():
                for key, values in keys.items():
                    if key.lower() in _AUTOMATIC:
                        continue
                    for val in _candidates(op, values, _current(req, key)):
                        alt = _with_context(req, key, val)
                        r = evaluate(alt, ps)
                        if (pid, idx, label) not in _deny_matches(r) and r.allowed:
                            out["fixes"].append(
                                {
                                    "kind": "context",
                                    "title": f"Send {key} = {_show(val)}",
                                    "detail": f"The Deny {pid} / {label} applies only while {key} is "
                                    f"{_show(now[0] if (now := _current(req, key)) else None)}. "
                                    "With this value the request is allowed.",
                                    "context": {key: val},
                                    "verified": True,
                                }
                            )
                            break
        # 2. Remove or narrow the Deny statements (and add whatever Allow is still missing).
        without = ps
        for pid, idx, _ in denies:
            without = _without(without, pid, idx)
        added, _, r = _complete_allows(req, without)
        names = ", ".join(f"{pid} / {label}" for pid, _, label in denies)
        detail = f"{names} applies to this request. An explicit Deny overrides every Allow."
        if added:
            detail += " With it gone, these Allows are still needed:"
        out["fixes"].append(
            {
                "kind": "remove_deny",
                "title": f"Remove or narrow the Deny ({len(denies)} statement{'s' if len(denies) > 1 else ''})",
                "detail": detail,
                "statements": [{"policy": pid, "statement": label} for pid, _, label in denies],
                "add": added,
                "verified": r.allowed,
            }
        )
        return
    # Implicit deny: the missing Allows, layer by layer.
    added, _, r = _complete_allows(req, ps)
    if added:
        out["fixes"].append(
            {
                "kind": "add_allow",
                "title": "Add the missing Allow"
                + (f"s in {len(added)} places" if len(added) > 1 else f" to {added[0]['where']}"),
                "detail": "Nothing allows this request in "
                + " and ".join(a["where"] for a in added)
                + ". These statements are the smallest that allow it.",
                "add": added,
                "verified": r.allowed,
            }
        )
    # A context value that would make an existing Allow apply.
    for miss in _near_misses(req, ps):
        st = next(
            (s for p in _policies(ps) if p.id == miss["policy"] for s in p.statements if s.label == miss["statement"]),
            None,
        )
        if st is None or not st.condition or "condition" not in miss["reason"]:
            continue
        for op, keys in st.condition.items():
            for key, values in keys.items():
                if key.lower() in _AUTOMATIC:
                    continue
                for val in _candidates(op, values, _current(req, key)):
                    if evaluate(_with_context(req, key, val), ps).allowed:
                        out["fixes"].append(
                            {
                                "kind": "context",
                                "title": f"Send {key} = {_show(val)}",
                                "detail": f"{miss['policy']} / {miss['statement']} allows this request when "
                                f"{key} is {_show(val)}.",
                                "context": {key: val},
                                "verified": True,
                            }
                        )
                        break


def _explain_allowed(req: Request, ps: PolicySet, result: Result, out: dict[str, Any]) -> None:
    allows = _allow_matches(result)
    needed = []
    for pid, idx, label, step in allows:
        if not evaluate(req, _without(ps, pid, idx)).allowed:
            needed.append((pid, label, step))
    for pid, label, step in needed:
        out["depends_on"].append(
            {
                "kind": "statement",
                "title": f"{pid} / {label}",
                "detail": f"The only statement in {_LAYER.get(step, step)} that allows this. "
                "Without it, the request is denied.",
            }
        )
    redundant = [(pid, label) for pid, _, label, _ in allows if (pid, label) not in {(n[0], n[1]) for n in needed}]
    if redundant and not needed:
        out["depends_on"].append(
            {
                "kind": "redundant",
                "title": f"{len(redundant)} statements allow this",
                "detail": "Removing any one of them keeps the request allowed: "
                + ", ".join(f"{p} / {s}" for p, s in redundant)
                + ".",
            }
        )
    # Context keys named in the conditions of statements that matter.
    tried: set[str] = set()
    for pol in _policies(ps):
        for s in pol.statements:
            for op, keys in s.condition.items():
                for key, values in keys.items():
                    lk = key.lower()
                    if lk in _AUTOMATIC or lk in tried:
                        continue
                    tried.add(lk)
                    current = _current(req, key)
                    for val in _candidates(op, values, current):
                        r = evaluate(_with_context(req, key, val), ps)
                        if r.allowed:
                            continue
                        why = (
                            f"a Deny would apply ({', '.join(f'{p} / {lbl}' for p, _, lbl in _deny_matches(r))})"
                            if r.decision is Decision.EXPLICIT_DENY
                            else "no Allow would apply"
                        )
                        out["depends_on"].append(
                            {
                                "kind": "context",
                                "title": f"{key} = {_show(current[0] if current else None)}",
                                "detail": f"If {key} were {_show(val)}, the request would be denied: {why}.",
                            }
                        )
                        break


def _summary(result: Result, out: dict[str, Any]) -> str:
    if result.allowed:
        n = sum(1 for d in out["depends_on"] if d["kind"] in ("statement", "context"))
        if not n:
            return "Allowed, and no single statement or context value is critical: several grants allow it."
        return f"Allowed. The decision depends on {n} thing{'s' if n > 1 else ''}: change any one and it is denied."
    fixes = [f for f in out["fixes"] if f["verified"]]
    if not fixes:
        return "Denied, and no small change found that allows it."
    return f"Denied. {len(fixes)} way{'s' if len(fixes) > 1 else ''} to allow it, each checked by evaluating again."


def what_if_text(report: dict[str, Any]) -> str:
    lines = ["", "What would change this", "  " + report["summary"]]
    for i, f in enumerate(report["fixes"], 1):
        lines.append(f"  {i}. {f['title']}{'' if f['verified'] else ' (not enough on its own)'}")
        lines.append(f"     {f['detail']}")
        for a in f.get("add", []):
            lines.append(f"     In {a['where']}: {json.dumps(a['statement'])}")
    for d in report["depends_on"]:
        lines.append(f"  - {d['title']}: {d['detail']}")
    if report["near_misses"]:
        lines.append("  Near misses (Allow statements that name the action):")
        for m in report["near_misses"]:
            lines.append(f"  - {m['policy']} / {m['statement']}: {m['reason']}")
    return "\n".join(lines) + "\n"
