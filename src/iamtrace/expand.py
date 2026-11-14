"""`iam-trace expand`: wildcard actions to concrete actions with access levels."""

from __future__ import annotations

from typing import Any

from iamtrace.catalog import ACCESS_LEVELS, ActionInfo, Catalog
from iamtrace.model import Policy
from iamtrace.output import sarif_log


def _actions(infos: list[ActionInfo]) -> list[dict[str, Any]]:
    return [a.to_dict() for a in infos]


def expand_patterns(patterns: list[str], cat: Catalog) -> dict[str, Any]:
    return {
        "catalog": cat.meta.get("path"),
        "patterns": [{"pattern": p, "actions": _actions(cat.expand(p))} for p in patterns],
    }


def expand_policies(policies: list[Policy], cat: Catalog) -> dict[str, Any]:
    statements = []
    for pol in policies:
        for s in pol.statements:
            if s.actions is not None:
                seen: dict[str, ActionInfo] = {}
                for p in s.actions:
                    for a in cat.expand(p):
                        seen[a.full_name] = a
                infos = sorted(seen.values(), key=lambda a: a.full_name)
                unmatched = [p for p in s.actions if not cat.expand(p)]
                patterns = list(s.actions)
                not_action = False
            else:
                assert s.not_actions is not None
                infos = cat.expand_not(s.not_actions)
                unmatched = [p for p in s.not_actions if not cat.expand(p)]
                patterns = list(s.not_actions)
                not_action = True
            statements.append(
                {
                    "policy": pol.id,
                    "statement": s.label,
                    "effect": s.effect,
                    "not_action": not_action,
                    "patterns": patterns,
                    "unmatched_patterns": unmatched,
                    "actions": _actions(infos),
                }
            )
    return {"catalog": cat.meta.get("path"), "statements": statements}


def _group(actions: list[dict[str, Any]]) -> list[str]:
    lines = []
    by_level: dict[str, list[str]] = {}
    for a in actions:
        by_level.setdefault(a["access_level"], []).append(a["action"])
    for level in ACCESS_LEVELS:
        names = by_level.get(level)
        if names:
            lines.append(f"    {level} ({len(names)})")
            lines += [f"      {n}" for n in names]
    return lines


def expand_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    for entry in report.get("patterns", []):
        acts = entry["actions"]
        lines.append(f"{entry['pattern']}: {len(acts)} action(s)")
        if not acts:
            lines.append("    matches no known action (check the spelling, or refresh the catalog)")
        lines += _group(acts)
    for st in report.get("statements", []):
        kind = "NotAction" if st["not_action"] else "Action"
        lines.append(
            f"{st['policy']} {st['statement']} ({st['effect']}, {kind} {', '.join(st['patterns'])}): "
            f"{len(st['actions'])} action(s)"
        )
        if st["not_action"]:
            lines.append("    NotAction: every catalog action except the ones listed")
        for p in st["unmatched_patterns"]:
            lines.append(f"    warning: {p} matches no known action")
        lines += _group(st["actions"])
    return "\n".join(lines) + "\n"


def expand_sarif(report: dict[str, Any]) -> str:
    """One result per permissions-management action an Allow covers; that is what reviewers want flagged."""
    results = []
    for st in report.get("statements", []):
        if st["effect"] != "Allow":
            continue
        for a in st["actions"]:
            if a["access_level"] == "Permissions management":
                results.append(
                    {
                        "ruleId": "expand/permissions-management",
                        "level": "warning",
                        "message": {
                            "text": f"{st['policy']} {st['statement']} allows {a['action']} (Permissions management)"
                        },
                    }
                )
    for entry in report.get("patterns", []):
        for a in entry["actions"]:
            if a["access_level"] == "Permissions management":
                results.append(
                    {
                        "ruleId": "expand/permissions-management",
                        "level": "note",
                        "message": {"text": f"{entry['pattern']} covers {a['action']} (Permissions management)"},
                    }
                )
    rules = [
        {
            "id": "expand/permissions-management",
            "shortDescription": {"text": "Allows an action that can change permissions or credentials"},
        }
    ]
    return sarif_log(rules, results)
