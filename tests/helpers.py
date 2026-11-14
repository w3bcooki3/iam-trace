"""Small builders that keep the evaluation tests readable."""

from __future__ import annotations

import itertools
from typing import Any

from iamtrace import Policy, PolicySet, PolicyType, Principal, Request, Result, evaluate

_ids = itertools.count(1)

A = "111122223333"  # the "home" account in most tests
B = "444455556666"  # a second account for cross-account tests


def stmt(effect: str, action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    s: dict[str, Any] = {"Effect": effect}
    if isinstance(action, dict):  # {"NotAction": ...}
        s.update(action)
    else:
        s["Action"] = action
    if isinstance(resource, dict):  # {"NotResource": ...}
        s.update(resource)
    elif resource is not None:
        s["Resource"] = resource
    s.update(extra)
    return s


def allow(action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    return stmt("Allow", action, resource, **extra)


def deny(action: Any, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    return stmt("Deny", action, resource, **extra)


def pol(
    policy_type: PolicyType,
    *statements: dict[str, Any],
    version: str | None = "2012-10-17",
    policy_id: str | None = None,
) -> Policy:
    doc: dict[str, Any] = {"Statement": list(statements)}
    if version:
        doc["Version"] = version
    return Policy.parse(doc, policy_id=policy_id or f"{policy_type.value}-{next(_ids)}", policy_type=policy_type)


def identity(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.IDENTITY, *s, **kw)


def resource(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.RESOURCE, *s, **kw)


def boundary(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.BOUNDARY, *s, **kw)


def session(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.SESSION, *s, **kw)


def scp(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.SCP, *s, **kw)


def rcp(*s: dict[str, Any], **kw: Any) -> Policy:
    return pol(PolicyType.RCP, *s, **kw)


def user(name: str = "alice", account: str = A) -> Principal:
    return Principal.from_arn(f"arn:aws:iam::{account}:user/{name}")


def role_session(role: str = "app", session_name: str = "s1", account: str = A) -> Principal:
    return Principal.from_arn(f"arn:aws:sts::{account}:assumed-role/{role}/{session_name}")


def run(
    principal: Principal,
    action: str,
    res: str,
    *,
    resource_account: str | None = None,
    context: dict[str, Any] | None = None,
    **policies: Any,
) -> Result:
    req = Request(
        principal=principal, action=action, resource=res, resource_account=resource_account, context=context or {}
    )
    return evaluate(req, PolicySet(**policies))
