"""Reading policy files and building requests from command-line style inputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from iamtrace.model import Policy, PolicyError, PolicyType


def load_policy(path: str | Path, policy_type: PolicyType, policy_id: str | None = None) -> Policy:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise PolicyError(f"{p}: cannot read: {e.strerror}") from e
    return Policy.from_json(text, policy_id=policy_id or p.name, policy_type=policy_type)


def load_policies(paths: list[str] | None, policy_type: PolicyType) -> list[Policy]:
    return [load_policy(p, policy_type) for p in (paths or [])]


def load_levels(specs: list[str] | None, policy_type: PolicyType) -> list[list[Policy]] | None:
    """Each spec is one organization level, root first; files in a level are comma-separated."""
    if not specs:
        return None
    return [[load_policy(f.strip(), policy_type) for f in spec.split(",") if f.strip()] for spec in specs]


def parse_context(pairs: list[str] | None, json_file: str | None) -> dict[str, Any]:
    """KEY=VALUE pairs; repeat a key to make it multivalued. KEY=[] sets an empty set."""
    ctx: dict[str, Any] = {}
    if json_file:
        try:
            data = json.loads(Path(json_file).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as e:
            raise PolicyError(f"{json_file}: cannot read context: {e}") from e
        if not isinstance(data, dict):
            raise PolicyError(f"{json_file}: context must be a JSON object")
        ctx.update(data)
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise PolicyError(f"context must be KEY=VALUE, got {pair!r}")
        if value == "[]":
            ctx[key] = []
        elif key in ctx:
            prev = ctx[key]
            ctx[key] = (prev if isinstance(prev, list) else [prev]) + [value]
        else:
            ctx[key] = value
    return ctx


def load_any_policy(path: str | Path, policy_id: str | None = None) -> Policy:
    """Load a policy whose type is not known: resource-based if it names principals, otherwise
    identity-based, falling back to SCP rules (which allow statements without Resource)."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as e:
        raise PolicyError(f"{p}: cannot read: {e.strerror}") from e
    return parse_any_policy(text, policy_id or p.name)


def parse_any_policy(text: str, policy_id: str) -> Policy:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise PolicyError(f"{policy_id}: invalid JSON: {e}") from e
    except RecursionError as e:
        raise PolicyError(f"{policy_id}: JSON is nested too deeply") from e
    statements = doc.get("Statement", []) if isinstance(doc, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    names_principal = any(isinstance(s, dict) and ("Principal" in s or "NotPrincipal" in s) for s in statements)
    if names_principal:
        return Policy.from_json(text, policy_id=policy_id, policy_type=PolicyType.RESOURCE)
    try:
        return Policy.from_json(text, policy_id=policy_id, policy_type=PolicyType.IDENTITY)
    except PolicyError:
        return Policy.from_json(text, policy_id=policy_id, policy_type=PolicyType.SCP)
