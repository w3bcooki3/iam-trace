"""Semantic diff of two policy documents.

Each policy is reduced to a set of grants, one per (effect, concrete action, resource pattern,
principal, conditions). Wildcard actions are expanded with the catalog, so "s3:Get*" and the
list it stands for compare equal. Sids, statement order, value order, and splitting or merging
statements do not change the set, so reorder-only edits produce no change.

A grant counts as added only if no grant on the other side already covers it. Covering means:
same effect, action and principal; a resource pattern that matches everything the new pattern
matches; and either no conditions or the same conditions. So widening Resource or dropping a
condition shows up as "newly allowed", and narrowing shows up as "no longer allowed".

Two simplifications, both listed in docs/limitations.md:
- Conditions are compared by equality. A change from one condition to a different one is
  reported as one grant removed and one added, even when the new condition is looser.
- Resource coverage treats the narrower pattern's wildcards as literal text. That is exact for
  the common cases (a/* covers a/b/*) and conservative otherwise: it never claims coverage that
  doesn't hold.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

from iamtrace.catalog import ACCESS_LEVELS, Catalog
from iamtrace.model import Policy, Statement
from iamtrace.output import sarif_location, sarif_log
from iamtrace.wildcard import glob_match

CHANGE_KINDS = ("newly_allowed", "no_longer_allowed", "newly_denied", "deny_removed")
TITLES = {
    "newly_allowed": "Newly allowed",
    "no_longer_allowed": "No longer allowed",
    "newly_denied": "Newly denied",
    "deny_removed": "Deny removed (now possible if something else allows it)",
}


@cache
def escalation_actions() -> frozenset[str]:
    """Every action that appears in a known privilege-escalation path (pathfinding.cloud)."""
    data = json.loads(resources.files("iamtrace").joinpath("data/escalation_paths.json").read_text())
    return frozenset(perm.lower() for path in data["paths"] for perm in path["permissions"])


@dataclass(frozen=True)
class Grant:
    effect: str
    action: str  # concrete action as named in the catalog, or the pattern if unknown
    resource: str  # a pattern, or "NOT <patterns>" for NotResource
    principal: str  # "" for policies without principals, "*" or "AWS:<value>" etc.
    conditions: str  # canonical JSON, "{}" when none


def _canonical_conditions(st: Statement) -> str:
    canon: dict[str, dict[str, list[str]]] = {}
    for op, keys in st.condition.items():
        canon[op] = {k.lower(): sorted(v) for k, v in keys.items()}
    return json.dumps(canon, sort_keys=True)


def _principals(st: Statement) -> list[str]:
    if st.principal is not None:
        if st.principal == "*":
            return ["*"]
        return sorted(f"{t}:{v}" for t, vals in st.principal.items() for v in vals)
    if st.not_principal is not None:
        if st.not_principal == "*":
            return ["NOT *"]
        return ["NOT " + ", ".join(sorted(f"{t}:{v}" for t, vals in st.not_principal.items() for v in vals))]
    return [""]


def _resources(st: Statement) -> list[str]:
    if st.resources is not None:
        return sorted(set(st.resources))
    if st.not_resources is not None:
        return ["NOT " + ", ".join(sorted(set(st.not_resources)))]
    return ["*"]


def _actions(st: Statement, cat: Catalog) -> list[str]:
    if st.actions is not None:
        names: set[str] = set()
        for p in st.actions:
            found = cat.expand(p)
            names.update(a.full_name for a in found) if found else names.add(p)
        return sorted(names)
    assert st.not_actions is not None
    return [a.full_name for a in cat.expand_not(st.not_actions)]


def grants(policy: Policy, cat: Catalog) -> set[Grant]:
    out: set[Grant] = set()
    for st in policy.statements:
        cond = _canonical_conditions(st)
        for action in _actions(st, cat):
            for res in _resources(st):
                for pr in _principals(st):
                    out.add(Grant(st.effect, action, res, pr, cond))
    return out


def resource_subsumes(broad: str, narrow: str) -> bool:
    if broad == narrow or broad == "*":
        return True
    if broad.startswith("NOT ") or narrow.startswith("NOT ") or narrow == "*":
        return False
    return glob_match(broad, narrow)


def _covered(g: Grant, others: set[Grant], index: dict[tuple[str, str, str], list[Grant]]) -> bool:
    if g in others:
        return True
    for o in index.get((g.effect, g.action.lower(), g.principal), []):
        if (o.conditions == "{}" or o.conditions == g.conditions) and resource_subsumes(o.resource, g.resource):
            return True
    return False


def _index(gs: set[Grant]) -> dict[tuple[str, str, str], list[Grant]]:
    idx: dict[tuple[str, str, str], list[Grant]] = {}
    for g in gs:
        idx.setdefault((g.effect, g.action.lower(), g.principal), []).append(g)
    return idx


def _entries(gs: list[Grant], cat: Catalog) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[Grant]] = {}
    for g in gs:
        grouped.setdefault((g.action, g.conditions, g.principal), []).append(g)
    sensitive = escalation_actions()
    entries = []
    for (action, cond, principal), items in grouped.items():
        info = cat.get(action)
        level = info.access_level if info else "Unknown"
        reasons = []
        if level == "Permissions management":
            reasons.append("permissions management")
        if action.lower() in sensitive:
            reasons.append("used in known privilege-escalation paths")
        entries.append(
            {
                "action": info.full_name if info else action,
                "access_level": level,
                "resources": sorted({g.resource for g in items}),
                "principals": [principal] if principal else [],
                "conditions": json.loads(cond),
                "highlight": bool(reasons),
                "highlight_reason": "; ".join(reasons),
            }
        )
    order = {lvl: i for i, lvl in enumerate(ACCESS_LEVELS)}
    entries.sort(key=lambda e: (order.get(e["access_level"], 99), e["action"], e["principals"]))
    return entries


def diff_policies(old: Policy | None, new: Policy | None, cat: Catalog) -> dict[str, Any]:
    og = grants(old, cat) if old else set()
    ng = grants(new, cat) if new else set()
    oi, ni = _index(og), _index(ng)
    raw: dict[str, list[Grant]] = {k: [] for k in CHANGE_KINDS}
    for g in ng - og:
        if not _covered(g, og, oi):
            raw["newly_allowed" if g.effect == "Allow" else "newly_denied"].append(g)
    for g in og - ng:
        if not _covered(g, ng, ni):
            raw["no_longer_allowed" if g.effect == "Allow" else "deny_removed"].append(g)
    changes = {k: _entries(v, cat) for k, v in raw.items()}
    return {
        "old": old.id if old else None,
        "new": new.id if new else None,
        "unchanged": not any(changes.values()),
        "changes": changes,
        "summary": {k: len(v) for k, v in changes.items()},
        "highlighted": sum(1 for e in changes["newly_allowed"] if e["highlight"]),
    }


# --- rendering ----------------------------------------------------------------------


def _cond_text(c: dict[str, Any]) -> str:
    if not c:
        return ""
    parts = [f"{op} {k}={v}" for op, keys in c.items() for k, v in keys.items()]
    return "  when " + "; ".join(parts)


def diff_text(d: dict[str, Any]) -> str:
    lines = [f"iam-trace diff {d['old'] or '(none)'} -> {d['new'] or '(none)'}"]
    if d["unchanged"]:
        return "\n".join(lines + ["No change in what the policy allows or denies."]) + "\n"
    for kind in CHANGE_KINDS:
        entries = d["changes"][kind]
        if not entries:
            continue
        lines += ["", f"{TITLES[kind]} ({len(entries)})"]
        current = None
        for e in entries:
            if e["access_level"] != current:
                current = e["access_level"]
                lines.append(f"  {current}")
            mark = "!" if e["highlight"] and kind == "newly_allowed" else " "
            who = f"  for {', '.join(e['principals'])}" if e["principals"] else ""
            lines.append(
                f"   {mark} {e['action']:<40} on {', '.join(e['resources'])}{who}{_cond_text(e['conditions'])}"
            )
    if d["highlighted"]:
        lines += ["", "! = permissions management, or used in a known privilege-escalation path"]
    return "\n".join(lines) + "\n"


def md_code(value: object, limit: int = 300) -> str:
    """Render text from a policy (attacker-controlled in a pull request) as inert inline code.

    HTML-escaped inside <code>, so it cannot become a link, image, @mention, heading or table cell
    break, whatever it contains. Long values are cut.
    """
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[:limit] + "\u2026"
    return "<code>" + html.escape(text, quote=True).replace("|", "&#124;").replace("@", "&#64;") + "</code>"


def md_text(value: object, limit: int = 300) -> str:
    """Escape plain text (for example an error message quoting a policy) so Markdown renders it as
    text: HTML is escaped and every Markdown control character is backslash-escaped."""
    text = " ".join(str(value).split())[:limit]
    # Markdown escapes first, then HTML: the other way round, "#" in "&#x27;" would be escaped too.
    text = "".join("\\" + ch if ch in "\\`*_[]()#!~" else ch for ch in text)
    return html.escape(text, quote=False).replace("@", "&#64;").replace("|", "&#124;")


def diff_markdown(d: dict[str, Any], title: str | None = None) -> str:
    lines = [f"#### {title or md_code(d['new'] or d['old'])}"]
    if d["unchanged"]:
        return "\n".join(lines + ["", "No change in what the policy allows or denies."]) + "\n"
    for kind in CHANGE_KINDS:
        entries = d["changes"][kind]
        if not entries:
            continue
        lines += [
            "",
            f"**{TITLES[kind]}** ({len(entries)})",
            "",
            "| | Action | Access level | Resources | Principals | Conditions |",
            "|---|---|---|---|---|---|",
        ]
        for e in entries:
            mark = "!" if e["highlight"] and kind == "newly_allowed" else ""
            cond = _cond_text(e["conditions"]).replace("  when ", "")
            res = ", ".join(md_code(r) for r in e["resources"][:20])
            if len(e["resources"]) > 20:
                res += f" and {len(e['resources']) - 20} more"
            who = ", ".join(md_code(p) for p in e["principals"])
            cond_cell = md_code(cond) if cond else ""
            lines.append(f"| {mark} | {md_code(e['action'])} | {e['access_level']} | {res} | {who} | {cond_cell} |")
    return "\n".join(lines) + "\n"


def diff_sarif(d: dict[str, Any], new_path: str | None = None) -> str:
    results = []
    for kind in ("newly_allowed", "deny_removed"):
        for e in d["changes"][kind]:
            level = "warning" if e["highlight"] else "note"
            results.append(
                {
                    "ruleId": f"diff/{kind.replace('_', '-')}",
                    "level": level,
                    "message": {
                        "text": f"{e['action']} {TITLES[kind].lower()} on {', '.join(e['resources'])}"
                        + (f" ({e['highlight_reason']})" if e["highlight"] else "")
                    },
                    "locations": sarif_location(new_path),
                }
            )
    rules = [
        {
            "id": "diff/newly-allowed",
            "shortDescription": {"text": "The change allows an action it did not allow before"},
        },
        {"id": "diff/deny-removed", "shortDescription": {"text": "The change removes a Deny"}},
    ]
    return sarif_log(rules, results)
