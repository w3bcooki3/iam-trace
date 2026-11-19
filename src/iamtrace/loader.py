"""Reading policy files and building requests from command-line style inputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from iamtrace.documents import load_json, unwrap_policy
from iamtrace.model import Policy, PolicyError, PolicyType


def read_file(path: str | Path) -> bytes:
    p = Path(path)
    try:
        return p.read_bytes()
    except OSError as e:
        raise PolicyError(f"{p}: cannot read: {e.strerror}") from e


def policy_from_text(text: str | bytes, policy_type: PolicyType, policy_id: str) -> Policy:
    """A policy from JSON text: a policy document, or AWS CLI output that holds one."""
    parsed = load_json(text, policy_id)
    found = unwrap_policy(parsed.value, policy_id)
    policy = Policy.parse(found.document, policy_id=policy_id, policy_type=policy_type)
    warnings = [f"duplicate key {k!r}: the last value is used" for k in parsed.duplicates]
    if found.source:
        warnings.append(f"read the policy from the output of {found.source}")
    if warnings:
        policy = Policy(policy.id, policy.type, policy.version, policy.statements, policy.warnings + tuple(warnings))
    return policy


def load_policy(path: str | Path, policy_type: PolicyType, policy_id: str | None = None) -> Policy:
    p = Path(path)
    return policy_from_text(read_file(p), policy_type, policy_id or p.name)


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
        data = load_json(read_file(json_file), json_file).value
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
    return parse_any_policy(read_file(p), policy_id or p.name)


def parse_any_policy(text: str | bytes, policy_id: str) -> Policy:
    found = unwrap_policy(load_json(text, policy_id).value, policy_id)
    doc = found.document
    if found.kind == "scp":
        return policy_from_text(text, PolicyType.SCP, policy_id)
    statements = doc.get("Statement", []) if isinstance(doc, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        statements = []
    names_principal = any(isinstance(s, dict) and ("Principal" in s or "NotPrincipal" in s) for s in statements)
    if names_principal:
        return policy_from_text(text, PolicyType.RESOURCE, policy_id)
    try:
        return policy_from_text(text, PolicyType.IDENTITY, policy_id)
    except PolicyError:
        return policy_from_text(text, PolicyType.SCP, policy_id)
