"""Rendering results as text, JSON and SARIF 2.1.0.

SARIF reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from iamtrace import __version__
from iamtrace.evaluate import Result

TOOL_URI = "https://github.com/w3bcooki3/iam-trace"


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False) + "\n"


# --- can --------------------------------------------------------------------------


def can_text(r: Result) -> str:
    req = r.request
    lines = [
        f"Decision: {r.decision.value}  (stopped at: {r.deciding_step})",
        f"Request:  {req.principal.describe()}",
        f"          {req.action} on {req.resource}",
        "",
        "Trace:",
    ]
    for i, step in enumerate(r.trace, 1):
        lines.append(f"  {i}. {step.step:<21} {step.outcome:<15} {step.detail}")
        for m in step.matches:
            grant = f", grant: {m.grant}" if m.grant else ""
            lines.append(f"       - {m.policy_id} ({m.policy_type}): {m.statement} [{m.effect}{grant}]")
            for c in m.conditions:
                lines.append(f"           condition: {c}")
    if r.warnings:
        lines += ["", "Warnings:"] + [f"  - {w}" for w in r.warnings]
    return "\n".join(lines) + "\n"


def can_sarif(r: Result) -> str:
    level = "note" if r.allowed else "warning"
    rule = f"can/{r.decision.value}"
    result = {
        "ruleId": rule,
        "level": level,
        "message": {
            "text": f"{r.request.principal.describe()} {r.request.action} on {r.request.resource}: "
            f"{r.decision.value} (stopped at {r.deciding_step})"
        },
        "properties": r.to_dict(),
    }
    return sarif_log([{"id": rule, "shortDescription": {"text": f"Request decision: {r.decision.value}"}}], [result])


# --- SARIF ------------------------------------------------------------------------


def sarif_log(rules: list[dict[str, Any]], results: list[dict[str, Any]]) -> str:
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iamtrace",
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return to_json(log)


def sarif_location(path: str | None) -> list[dict[str, Any]]:
    if not path:
        return []
    return [{"physicalLocation": {"artifactLocation": {"uri": path}}}]
