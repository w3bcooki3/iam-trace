"""Unused access: what principals are allowed but have not used, and the policies without it.

The input is IAM's service last accessed data (iam generate-service-last-accessed-details, then
get-service-last-accessed-details) for each user and role. For each service a principal's
policies allow, it says when the principal last tried to use it, within a 400-day tracking period.
`collect_usage` gathers it with read-only calls; `unused_access` turns it into edits:

- A service is removed from a policy only if every principal that has the policy (directly or
  through a group) has the service in its report and has not used it within `days`. If anyone
  sharing the policy has no report, the policy is left alone.
- Edits only take away. "svc:*" and narrower patterns for an unused service are dropped; a
  statement that allows "*" (or uses NotAction) gets the unused services added to its NotAction,
  so services the report does not cover are never removed.
- iam:PassRole is kept: AWS does not track it, so it never looks used.
- Action-level data (some EC2, IAM, Lambda and S3 actions) is shown, not acted on: it covers
  management actions only, and a policy needs more than the actions it tracks.

The edited account is analysed again, to show which paths to admin the cleanup closes.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from iamtrace.escalate import Environment, analyze
from iamtrace.model import Policy
from iamtrace.narrow import locate

STALE_DAYS = 90
NEVER_TRACKED = ("iam:PassRole",)  # "The iam:PassRole action is not tracked" (IAM User Guide)


class UsageError(ValueError):
    pass


@dataclass
class ServiceUse:
    namespace: str
    name: str
    last: datetime | None
    region: str | None
    actions: dict[str, datetime | None] = field(default_factory=dict)  # tracked actions only


@dataclass
class PrincipalUsage:
    arn: str
    generated: datetime
    services: dict[str, ServiceUse]

    def idle_days(self, ns: str) -> int | None:
        """Days since the service was last used, or None if never in the tracking period."""
        s = self.services.get(ns)
        if s is None or s.last is None:
            return None
        return max(0, (self.generated - s.last).days)

    def unused(self, ns: str, days: int) -> bool:
        """Listed in the report and not used within `days`."""
        if ns not in self.services:
            return False
        idle = self.idle_days(ns)
        return idle is None or idle >= days


def _time(value: Any) -> datetime | None:
    if not value:
        return None
    t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def parse_usage(text: str) -> dict[str, PrincipalUsage]:
    """Read the file `iam-trace usage collect` writes: {"Reports": {principal ARN: the JSON of
    get-service-last-accessed-details}}."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise UsageError(f"not valid JSON: {e}") from e
    reports = data.get("Reports") if isinstance(data, dict) else None
    if not isinstance(reports, dict):
        raise UsageError('expected {"Reports": {principal ARN: get-service-last-accessed-details output}}')
    out: dict[str, PrincipalUsage] = {}
    for arn, r in reports.items():
        if not isinstance(r, dict) or "ServicesLastAccessed" not in r:
            raise UsageError(f"{arn}: not the output of get-service-last-accessed-details")
        if r.get("JobStatus", "COMPLETED") != "COMPLETED":
            raise UsageError(f"{arn}: the report's job is {r.get('JobStatus')}, not COMPLETED")
        generated = _time(r.get("JobCompletionDate")) or _time(r.get("JobCreationDate"))
        if generated is None:
            raise UsageError(f"{arn}: the report has no JobCompletionDate")
        services: dict[str, ServiceUse] = {}
        for s in r["ServicesLastAccessed"]:
            ns = str(s.get("ServiceNamespace", "")).lower()
            if not ns:
                continue
            actions = {
                f"{ns}:{a['ActionName']}": _time(a.get("LastAccessedTime"))
                for a in s.get("TrackedActionsLastAccessed") or []
                if a.get("ActionName")
            }
            services[ns] = ServiceUse(
                ns,
                str(s.get("ServiceName", ns)),
                _time(s.get("LastAuthenticated")),
                s.get("LastAuthenticatedRegion"),
                actions,
            )
        out[arn] = PrincipalUsage(arn, generated, services)
    return out


def collect_usage(run: Any, arns: list[str], *, sleep: Any = None, tries: int = 30) -> str:
    """Ask IAM for last accessed data for each principal and return the file parse_usage reads.

    Read-only calls: generate-service-last-accessed-details (it starts a report job) for every
    principal first, then get-service-last-accessed-details until each job is COMPLETED.
    """
    import time

    from iamtrace.collect import CollectError

    wait = sleep or time.sleep
    jobs = {}
    for arn in arns:
        out = run(["iam", "generate-service-last-accessed-details", "--arn", arn, "--granularity", "ACTION_LEVEL"])
        jobs[arn] = (out or {})["JobId"]
    reports: dict[str, Any] = {}
    for i in range(tries):
        for arn, job in jobs.items():
            if arn in reports:
                continue
            first = run(["iam", "get-service-last-accessed-details", "--job-id", job])
            status = first.get("JobStatus")
            if status == "FAILED":
                raise CollectError(f"{arn}: {((first.get('Error') or {}).get('Message')) or 'the report job failed'}")
            if status != "COMPLETED":
                continue
            page = first
            while page.get("IsTruncated"):
                page = run(["iam", "get-service-last-accessed-details", "--job-id", job, "--marker", page["Marker"]])
                first["ServicesLastAccessed"] += page.get("ServicesLastAccessed", [])
            first.pop("IsTruncated", None)
            first.pop("Marker", None)
            reports[arn] = first
        if len(reports) == len(jobs):
            break
        wait(min(2 * (i + 1), 10))
    else:
        missing = sorted(set(jobs) - set(reports))
        raise CollectError(f"{len(missing)} reports were not ready in time; try again in a minute")
    return json.dumps({"Reports": reports}, indent=2) + "\n"


# --- editing statements ------------------------------------------------------------------------


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v] if v is not None else []


def _one_or_list(v: list[str]) -> Any:
    return v[0] if len(v) == 1 else v


def _service(pattern: str) -> str | None:
    """The service of an action pattern, or None if the pattern does not name one ("*", "s*:Get")."""
    svc, sep, _ = pattern.partition(":")
    if not sep or any(c in svc for c in "*?"):
        return None
    return svc.lower()


def _covers_passrole(pattern: str) -> bool:
    from iamtrace.matching import action_matches

    return any(action_matches(pattern, a) for a in NEVER_TRACKED)


def trim_statement(st: dict[str, Any], unused: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """The statement without the unused services, and the services actually removed.

    Returns [] when nothing is left. Never adds access: patterns are only dropped, and NotAction
    only grows."""
    if st.get("Effect") != "Allow":
        return [st], []
    removed: set[str] = set()
    extra: list[dict[str, Any]] = []
    if "Action" in st:
        acts = [str(a) for a in _as_list(st["Action"])]
        broad = [a for a in acts if _service(a) is None]
        untracked = {x.lower() for x in NEVER_TRACKED}
        keep = [a for a in acts if _service(a) is None or _service(a) not in unused or a.lower() in untracked]
        dropped = [a for a in acts if a not in keep]
        removed |= {s for a in dropped if (s := _service(a)) in unused}
        if any(_covers_passrole(a) for a in dropped) and not any(a.lower() in untracked for a in keep):
            keep.append("iam:PassRole")  # never tracked, so never looks used: keep it
        if broad:
            # "*" or a pattern without a fixed service: allow it except the unused services.
            others = [a for a in keep if a not in broad]
            new: list[dict[str, Any]] = []
            if others:
                new.append({**st, "Action": _one_or_list(others)})
            for b in broad:
                svcs = sorted(unused)
                body = {k: v for k, v in st.items() if k != "Action"}
                if b == "*":
                    new.append({**body, "NotAction": _one_or_list([f"{s}:*" for s in svcs])})
                    removed |= set(svcs)
                    if "iam" in unused:
                        extra.append({**body, "Action": "iam:PassRole"})
                else:
                    new.append({**body, "Action": b})  # cannot express "this pattern except": keep it
            return new + extra, sorted(removed)
        if not keep:
            return [], sorted(removed)
        return [{**st, "Action": _one_or_list(keep)}], sorted(removed)
    # NotAction: allowed is everything but these; adding the unused services takes them away.
    nots = [str(a) for a in _as_list(st.get("NotAction"))]
    if "*" in nots:
        return [st], []  # allows nothing already
    # Only a whole-service pattern already excludes a service ("lambda:*", not "lambda:Create*").
    already = {s for a in nots if (s := _service(a)) and a.partition(":")[2] == "*"}
    add = sorted(s for s in unused if s not in already)
    if not add:
        return [st], []
    out = [{**st, "NotAction": _one_or_list(nots + [f"{s}:*" for s in add])}]
    if "iam" in add and not any(_covers_passrole(a) for a in nots):
        out.append({k: v for k, v in st.items() if k != "NotAction"} | {"Action": "iam:PassRole"})
    return out, add


# --- the analysis --------------------------------------------------------------------------------


def _policy_ids(env: Environment) -> list[str]:
    ids: list[str] = []
    for n in env.nodes.values():
        for p in n.policies:
            if p.id not in ids and not p.id.endswith(" trust policy"):
                ids.append(p.id)
    return ids


def _granted_services(doc: dict[str, Any]) -> set[str] | None:
    """Services the policy's Allow statements name; None if one allows "*"-like or uses NotAction."""
    out: set[str] = set()
    for st in _as_list(doc.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            return None
        for a in _as_list(st.get("Action")):
            s = _service(str(a))
            if s is None:
                return None
            out.add(s)
    return out


def unused_access(
    env: Environment,
    usage: dict[str, PrincipalUsage],
    *,
    days: int = STALE_DAYS,
    scps: list[list[Policy]] | None = None,
    everyone: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Policy edits that remove unused services, and what they change in the analysis."""
    principals = []
    for arn, n in sorted(env.nodes.items()):
        if n.kind not in ("user", "role"):
            continue
        u = usage.get(arn)
        if u is None:
            principals.append({"arn": arn, "kind": n.kind, "report": False})
            continue
        unused = sorted(ns for ns in u.services if u.unused(ns, days))
        last = max((s.last for s in u.services.values() if s.last), default=None)
        principals.append(
            {
                "arn": arn,
                "kind": n.kind,
                "report": True,
                "generated": u.generated.isoformat(),
                "allowed": len(u.services),
                "unused": unused,
                "used": sorted(set(u.services) - set(unused)),
                "last_used": last.isoformat() if last else None,
                "idle": not (set(u.services) - set(unused)),
                "unused_actions": sorted(
                    a
                    for s in u.services.values()
                    for a, t in s.actions.items()
                    if t is None or (u.generated - t).days >= days
                ),
            }
        )

    raw = copy.deepcopy(env.raw or {})
    edits: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    deletions: list[tuple[Any, ...]] = []
    for pid in _policy_ids(env):
        loc = locate(env, pid)
        if loc is None:
            continue
        affects = [a for a in loc.affects if env.nodes[a].kind in ("user", "role")]
        if not affects:
            continue
        missing = [a for a in affects if a not in usage]
        if missing:
            skipped.append({"policy": pid, "reason": "no last accessed report for " + ", ".join(missing)})
            continue
        listed = set.intersection(*(set(usage[a].services) for a in affects))
        drop = {ns for ns in listed if all(usage[a].unused(ns, days) for a in affects)}
        granted = _granted_services(loc.document)
        if granted is not None:
            drop &= granted
        if not drop:
            continue
        new_sts: list[dict[str, Any]] = []
        removed: set[str] = set()
        for st in _as_list(loc.document.get("Statement")):
            if not isinstance(st, dict):
                new_sts.append(st)
                continue
            out, gone = trim_statement(st, drop)
            new_sts += out
            removed |= set(gone)
        if not removed:
            continue
        doc = {**loc.document, "Statement": new_sts}
        aws_managed = ":iam::aws:policy/" in pid
        edit: dict[str, Any] = {
            "policy": pid,
            "kind": "aws-managed" if aws_managed else loc.kind,
            "affects": affects,
            "removes": sorted(removed),
            "idle_days": {
                ns: min((d for a in affects if (d := usage[a].idle_days(ns)) is not None), default=None)
                for ns in sorted(removed)
            },
            "before": loc.document,
            "document": doc if new_sts else None,
            "delete": not new_sts,
            "keeps_passrole": any(
                _covers_passrole(str(a)) for st in new_sts if isinstance(st, dict) for a in _as_list(st.get("Action"))
            )
            and "iam" in drop,
        }
        edits.append(edit)
        if not new_sts and loc.kind in ("inline", "group"):
            deletions.append(loc.path[:-1])
        elif not new_sts:
            node: Any = raw
            for key in loc.path[:-2]:
                node = node[key]
            node[loc.path[-2]]["IsDefaultVersion"] = False
        else:
            node = raw
            for key in loc.path[:-1]:
                node = node[key]
            node[loc.path[-1]] = doc
    for path in sorted(deletions, reverse=True):
        container: Any = raw
        for key in path[:-1]:
            container = container[key]
        del container[path[-1]]

    before = everyone if everyone is not None else analyze(env, scps=scps)
    trimmed = Environment.from_auth_details(raw)
    trimmed.resources = env.resources
    after = analyze(trimmed, scps=scps) if edits else before
    return {
        "days": days,
        "principals": principals,
        "edits": edits,
        "skipped": skipped,
        "impact": _impact(before, after),
    }


def _impact(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    def admins(r: dict[str, Any]) -> set[str]:
        return {p["arn"] for p in r["principals"] if p["admin_equivalent"] and not p.get("admin_requires")}

    def reach(r: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {p["start"]: p for p in r["paths"] if p.get("open", True)}

    b, a = reach(before), reach(after)
    return {
        "paths_before": len(b),
        "paths_after": len(a),
        "closed": [b[s] for s in sorted(set(b) - set(a))],
        "admins_before": len(admins(before)),
        "admins_after": len(admins(after)),
        "no_longer_admin": sorted(admins(before) - admins(after)),
    }


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def unused_text(result: dict[str, Any]) -> str:
    lines = [f"Unused access: services not used in {result['days']} days or more"]
    with_report = [p for p in result["principals"] if p["report"]]
    lines.append(f"{len(with_report)} of {len(result['principals'])} users and roles have a last accessed report.")
    idle = [p for p in with_report if p["idle"] and p["allowed"]]
    if idle:
        lines.append("")
        lines.append("Used nothing in the period. Unless kept for emergencies, consider removing them:")
        lines += [f"  {_short(p['arn'])}" for p in idle]
    lines.append("")
    lines.append("Review each edit before applying it: the reports cover the tracking period only.")
    if not result["edits"]:
        lines.append("No policy can lose a service: everything allowed is in use, or the reports are missing.")
    for e in result["edits"]:
        verb = "delete it (nothing left)" if e["delete"] else "remove"
        lines.append(
            f"{_short(e['policy'])} ({e['kind']}, {len(e['affects'])} principal(s)): {verb} {', '.join(e['removes'])}"
        )
        if e["kind"] == "aws-managed":
            lines.append("  AWS managed: attach a customer managed copy with the edit instead.")
        if e["keeps_passrole"]:
            lines.append("  iam:PassRole kept: AWS does not track it.")
    for s in result["skipped"]:
        lines.append(f"{_short(s['policy'])}: left alone, {s['reason']}")
    imp = result["impact"]
    lines.append("")
    lines.append(
        f"Paths to admin: {imp['paths_before']} before, {imp['paths_after']} after. "
        f"Admin principals: {imp['admins_before']} before, {imp['admins_after']} after."
    )
    for p in imp["closed"]:
        lines.append(f"  closes: {_short(p['start'])} -> {_short(p['end'])}")
    return "\n".join(lines) + "\n"
