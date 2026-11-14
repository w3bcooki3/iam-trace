"""Condition element evaluation.

Sources:
- Operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- Set operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html

Combination rules:
- All operators in a Condition block must be true (AND).
- Within an operator, all keys must be true (AND).
- Within a key, any one policy value may match (OR).

Missing keys:
- Positive operators: false.
- Negated operators (StringNotEquals, ArnNotLike, NotIpAddress, ...): true.
- ...IfExists: true.
- Null tests presence directly.
- ForAllValues: true when the key is missing or its value set is empty.
- ForAnyValue: false when the key is missing or empty.

One case is not documented: a single-value operator (no set qualifier) applied to a key that has
several values in the request. iam-trace treats it as "any value matches" for positive operators
and as the negation of that for negated operators. docs/limitations.md lists it as a case for the
differential test.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from iamtrace.context import Context
from iamtrace.model import ConditionBlock, PolicyError
from iamtrace.variables import as_text, substitute
from iamtrace.wildcard import Segment, glob_match

# --- value comparisons --------------------------------------------------------
# Each comparison takes (request_value, policy_value_segments) and returns True on a match.
# Policy values arrive as segments so that variables substituted into them stay literal.

Compare = Callable[[str, tuple[Segment, ...]], bool]


def _string_equals(r: str, p: tuple[Segment, ...]) -> bool:
    return r == as_text(p)


def _string_equals_ic(r: str, p: tuple[Segment, ...]) -> bool:
    return r.casefold() == as_text(p).casefold()


def _string_like(r: str, p: tuple[Segment, ...]) -> bool:
    return glob_match(p, r)


def _num(v: str) -> Decimal | None:
    try:
        d = Decimal(v.strip())
    except (InvalidOperation, AttributeError):
        return None
    return d if d.is_finite() else None


def _numeric(op: Callable[[Decimal, Decimal], bool]) -> Compare:
    def cmp(r: str, p: tuple[Segment, ...]) -> bool:
        a, b = _num(r), _num(as_text(p))
        return a is not None and b is not None and op(a, b)

    return cmp


def parse_date(v: str) -> datetime | None:
    """ISO 8601 (W3C profile) or epoch seconds. Naive times are taken as UTC."""
    v = v.strip()
    if v.lstrip("-").isdigit():
        try:
            return datetime.fromtimestamp(int(v), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def _date(op: Callable[[datetime, datetime], bool]) -> Compare:
    def cmp(r: str, p: tuple[Segment, ...]) -> bool:
        a, b = parse_date(r), parse_date(as_text(p))
        return a is not None and b is not None and op(a, b)

    return cmp


def _bool(r: str, p: tuple[Segment, ...]) -> bool:
    a, b = r.strip().lower(), as_text(p).strip().lower()
    return a in ("true", "false") and a == b


def _binary(r: str, p: tuple[Segment, ...]) -> bool:
    try:
        return base64.b64decode(r, validate=True) == base64.b64decode(as_text(p), validate=True)
    except (binascii.Error, ValueError):
        return r == as_text(p)


def _ip(r: str, p: tuple[Segment, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(r.strip())
        # "If you specify an IP address without the associated routing prefix, IAM uses the
        # default prefix value of /32." ip_network does the same (/128 for IPv6).
        net = ipaddress.ip_network(as_text(p).strip(), strict=False)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def split_arn_text(text: str) -> list[str]:
    """Split an ARN (or ARN pattern) into at most six components on ':'.

    Colons inside ${...} do not split, so "${aws:username}" stays whole.
    """
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "$" and text.startswith("${", i):
            depth += 1
            buf.append("${")
            i += 2
            continue
        if ch == "}" and depth:
            depth -= 1
        if ch == ":" and not depth and len(parts) < 5:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def arn_like(r: str, pattern_parts: list[tuple[Segment, ...]]) -> bool:
    """ArnEquals/ArnLike: "Each of the six colon-delimited components of the ARN is checked
    separately and each can include multi-character match wildcards (*) or single-character
    match wildcards (?)."
    """
    rparts = r.split(":", 5)
    if len(rparts) != 6 or len(pattern_parts) != 6:
        return False
    return all(glob_match(pp, rp) for pp, rp in zip(pattern_parts, rparts, strict=True))


# --- operator table -----------------------------------------------------------


@dataclass(frozen=True)
class OperatorSpec:
    compare: Compare | None  # None for ARN (handled specially) and Null
    negated: bool = False
    variables: bool = False  # whether policy variables are substituted in values
    kind: str = "plain"  # "plain" | "arn" | "null"


def _ge(a: Any, b: Any) -> bool:
    return bool(a >= b)


OPERATORS: dict[str, OperatorSpec] = {
    "StringEquals": OperatorSpec(_string_equals, variables=True),
    "StringNotEquals": OperatorSpec(_string_equals, negated=True, variables=True),
    "StringEqualsIgnoreCase": OperatorSpec(_string_equals_ic, variables=True),
    "StringNotEqualsIgnoreCase": OperatorSpec(_string_equals_ic, negated=True, variables=True),
    "StringLike": OperatorSpec(_string_like, variables=True),
    "StringNotLike": OperatorSpec(_string_like, negated=True, variables=True),
    "NumericEquals": OperatorSpec(_numeric(lambda a, b: a == b)),
    "NumericNotEquals": OperatorSpec(_numeric(lambda a, b: a == b), negated=True),
    "NumericLessThan": OperatorSpec(_numeric(lambda a, b: a < b)),
    "NumericLessThanEquals": OperatorSpec(_numeric(lambda a, b: a <= b)),
    "NumericGreaterThan": OperatorSpec(_numeric(lambda a, b: a > b)),
    "NumericGreaterThanEquals": OperatorSpec(_numeric(_ge)),
    "DateEquals": OperatorSpec(_date(lambda a, b: a == b)),
    "DateNotEquals": OperatorSpec(_date(lambda a, b: a == b), negated=True),
    "DateLessThan": OperatorSpec(_date(lambda a, b: a < b)),
    "DateLessThanEquals": OperatorSpec(_date(lambda a, b: a <= b)),
    "DateGreaterThan": OperatorSpec(_date(lambda a, b: a > b)),
    "DateGreaterThanEquals": OperatorSpec(_date(_ge)),
    "Bool": OperatorSpec(_bool, variables=True),
    "BinaryEquals": OperatorSpec(_binary),
    "IpAddress": OperatorSpec(_ip),
    "NotIpAddress": OperatorSpec(_ip, negated=True),
    "ArnEquals": OperatorSpec(None, variables=True, kind="arn"),
    "ArnLike": OperatorSpec(None, variables=True, kind="arn"),
    "ArnNotEquals": OperatorSpec(None, negated=True, variables=True, kind="arn"),
    "ArnNotLike": OperatorSpec(None, negated=True, variables=True, kind="arn"),
    "Null": OperatorSpec(None, kind="null"),
}


@dataclass(frozen=True)
class ParsedOperator:
    name: str  # as written in the policy
    base: str
    spec: OperatorSpec
    set_op: str | None  # "ForAllValues" | "ForAnyValue" | None
    if_exists: bool


def parse_operator(name: str) -> ParsedOperator:
    set_op = None
    rest = name
    for q in ("ForAllValues:", "ForAnyValue:"):
        if name.startswith(q):
            set_op, rest = q[:-1], name[len(q) :]
            break
    if_exists = rest.endswith("IfExists")
    base = rest[: -len("IfExists")] if if_exists else rest
    spec = OPERATORS.get(base)
    if spec is None:
        raise PolicyError(f"unknown condition operator {name!r}")
    if base == "Null" and (if_exists or set_op):
        raise PolicyError(f"{name!r}: Null cannot be combined with IfExists or a set operator")
    return ParsedOperator(name, base, spec, set_op, if_exists)


def _value_strings(v: Any, where: str) -> tuple[str, ...]:
    def one(x: Any) -> str:
        if isinstance(x, bool):
            return "true" if x else "false"
        if isinstance(x, (str, int, float)):
            return str(x)
        raise PolicyError(f"{where}: condition values must be strings, numbers or booleans")

    if isinstance(v, list):
        return tuple(one(x) for x in v)
    return (one(v),)


def normalize_condition(raw: Mapping[str, Any]) -> dict[str, dict[str, tuple[str, ...]]]:
    out: dict[str, dict[str, tuple[str, ...]]] = {}
    for op, keys in raw.items():
        parse_operator(op)  # validates
        if not isinstance(keys, Mapping) or not keys:
            raise PolicyError(f"condition operator {op!r} must map to an object of keys")
        out[op] = {k: _value_strings(v, f"{op}/{k}") for k, v in keys.items()}
    return out


# --- evaluation ---------------------------------------------------------------


@dataclass(frozen=True)
class ConditionResult:
    matched: bool
    details: tuple[str, ...] = ()


def _policy_values(op: ParsedOperator, values: tuple[str, ...], ctx: Context, variables: bool) -> list[Any]:
    """Pre-process policy values: substitute variables; split ARNs. Unresolvable -> None."""
    use_vars = variables and op.spec.variables
    out: list[Any] = []
    for v in values:
        if op.spec.kind == "arn":
            parts = [substitute(p, ctx, use_vars) for p in split_arn_text(v)]
            out.append(None if any(p is None for p in parts) else parts)
        else:
            out.append(substitute(v, ctx, use_vars))
    return out


def _positive(op: ParsedOperator, r: str, pvals: list[Any]) -> bool:
    for pv in pvals:
        if pv is None:  # unresolved variable: compares as null, never equal
            continue
        if op.spec.kind == "arn":
            if arn_like(r, pv):
                return True
        else:
            assert op.spec.compare is not None
            if op.spec.compare(r, pv):
                return True
    return False


def _single(op: ParsedOperator, r: str, pvals: list[Any]) -> bool:
    pos = _positive(op, r, pvals)
    return not pos if op.spec.negated else pos


def evaluate_key(
    op: ParsedOperator, key: str, values: tuple[str, ...], ctx: Context, variables: bool
) -> tuple[bool, str]:
    present = key in ctx
    req = ctx[key] if present else ()
    empty = present and len(req) == 0

    if op.spec.kind == "null":
        is_null = not present or empty
        wanted = {v.strip().lower() for v in values}
        ok = ("true" in wanted and is_null) or ("false" in wanted and not is_null)
        return ok, f"{key} is {'absent' if is_null else 'present'}"

    if op.set_op == "ForAllValues":
        if not present or empty:
            # Also true for IfExists; the qualifier changes nothing here.
            return True, f"{key} has no values; ForAllValues is true for an empty set"
        pvals = _policy_values(op, values, ctx, variables)
        ok = all(_single(op, r, pvals) for r in req)
        return ok, f"{key}={list(req)}: {'every' if ok else 'not every'} value matched"

    if op.set_op == "ForAnyValue":
        if not present or empty:
            return op.if_exists, f"{key} has no values; ForAnyValue is {'true (IfExists)' if op.if_exists else 'false'}"
        pvals = _policy_values(op, values, ctx, variables)
        ok = any(_single(op, r, pvals) for r in req)
        return ok, f"{key}={list(req)}: {'a' if ok else 'no'} value matched"

    if not present or empty:
        if op.if_exists:
            return True, f"{key} is absent; IfExists makes the condition true"
        if op.spec.negated:
            return True, f"{key} is absent; a negated operator is true for a missing key"
        return False, f"{key} is absent"
    pvals = _policy_values(op, values, ctx, variables)
    pos = any(_positive(op, r, pvals) for r in req)
    ok = not pos if op.spec.negated else pos
    shown = req[0] if len(req) == 1 else list(req)
    return ok, f"{key}={shown!r} {'matched' if ok else 'did not match'} {list(values)}"


def evaluate_condition_block(block: ConditionBlock, ctx: Context, variables: bool) -> ConditionResult:
    if not block:
        return ConditionResult(True)
    details: list[str] = []
    for op_name, keys in block.items():
        op = parse_operator(op_name)
        for key, values in keys.items():
            ok, why = evaluate_key(op, key, values, ctx, variables)
            details.append(f"{op_name} {why}")
            if not ok:
                return ConditionResult(False, tuple(details))
    return ConditionResult(True, tuple(details))
