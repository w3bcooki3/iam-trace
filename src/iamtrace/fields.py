"""Checking the small values people type: principals, actions, resources, account IDs, request
context, numbers. The web app and the command line use the same checks, so a value that one
refuses the other refuses too, with the same message.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from iamtrace.conditions import parse_date
from iamtrace.model import PolicyError


class FieldError(PolicyError):
    """A typed value that is not valid, with a message saying what is expected."""


ACCOUNT = re.compile(r"^\d{12}$")
ACTION = re.compile(r"^[a-z0-9][a-z0-9-]*:[A-Za-z0-9][A-Za-z0-9-_.]*$", re.IGNORECASE)
SERVICE_PRINCIPAL = re.compile(r"^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(\.cn)?$|^[a-z0-9][a-z0-9.-]*\.amazon\.com$")

# Global condition keys whose values have a type, and how to check them.
_DATE_KEYS = {"aws:currenttime", "aws:tokenissuetime", "aws:epochtime"}
_BOOL_KEYS = {"aws:multifactorauthpresent", "aws:securetransport", "aws:viaawsservice", "aws:principalisawsservice"}
_NUMBER_KEYS = {"aws:multifactorauthage"}
_IP_KEYS = {"aws:sourceip", "aws:vpcsourceip"}


def account_id(value: str, label: str = "the account ID") -> str | None:
    v = value.strip()
    if not v:
        return None
    if not ACCOUNT.match(v):
        raise FieldError(f"{label} must be 12 digits, got {v!r}")
    return v


def action(value: str, label: str = "the action") -> str:
    """One action, as a request names it: service:Action, no wildcards."""
    v = value.strip()
    if not v:
        raise FieldError(f"enter {label}, for example s3:GetObject")
    if "*" in v or "?" in v:
        raise FieldError(f"{label} must be one action, like s3:GetObject: {v!r} is a pattern")
    if not ACTION.match(v):
        raise FieldError(f"{label} must look like service:Action (for example s3:GetObject), got {v!r}")
    return v


def resource(value: str, label: str = "the resource") -> str:
    """An ARN, or * for actions that take no resource."""
    v = value.strip() or "*"
    if v == "*":
        return v
    parts = v.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn" or not parts[1] or not parts[2]:
        raise FieldError(f"{label} must be an ARN (arn:partition:service:region:account:resource) or *, got {v!r}")
    return v


def principal(value: str) -> str:
    """A principal ARN (user, role, assumed-role session, root, federated user), or
    service:NAME for an AWS service principal."""
    v = value.strip()
    if not v:
        raise FieldError("enter the principal making the request")
    if v.startswith("service:"):
        name = v[len("service:") :].strip()
        if not SERVICE_PRINCIPAL.match(name):
            raise FieldError(f"service:{name} is not a service principal (for example service:lambda.amazonaws.com)")
        return f"service:{name}"
    parts = v.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn" or parts[2] not in ("iam", "sts"):
        raise FieldError(f"the principal must be an IAM or STS ARN, or service:NAME, got {v!r}")
    if not ACCOUNT.match(parts[4]):
        raise FieldError(f"the principal's account must be 12 digits, got {parts[4]!r}")
    return v


def context(ctx: dict[str, Any]) -> list[str]:
    """Check values of global condition keys that have a type. Returns warnings (a value that
    would never match is worth knowing about, but not a reason to refuse the request)."""
    warnings: list[str] = []
    for key, raw in ctx.items():
        k = key.lower()
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            text = str(value)
            if k in _DATE_KEYS and parse_date(text) is None:
                raise FieldError(f"{key}: {text!r} is not a date (use 2026-11-19T10:00:00Z or epoch seconds)")
            if k in _BOOL_KEYS and text.lower() not in ("true", "false"):
                raise FieldError(f"{key}: {text!r} must be true or false")
            if k in _NUMBER_KEYS:
                try:
                    float(text)
                except ValueError:
                    raise FieldError(f"{key}: {text!r} must be a number") from None
            if k in _IP_KEYS:
                try:
                    ipaddress.ip_address(text)
                except ValueError:
                    raise FieldError(f"{key}: {text!r} is not an IP address") from None
        if not key.strip() or any(c.isspace() for c in key):
            raise FieldError(f"context key {key!r} must not be empty or contain spaces")
    return warnings


def whole_number(value: Any, label: str, lo: int, hi: int) -> int:
    try:
        n = int(str(value).strip())
    except ValueError:
        raise FieldError(f"{label} must be a whole number, got {value!r}") from None
    if not lo <= n <= hi:
        raise FieldError(f"{label} must be between {lo} and {hi}, got {n}")
    return n
