"""Policy variables: ${key}, ${key, 'default'}, and the escapes ${*}, ${?}, ${$}.

Source: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html

- Variables only work when the policy Version is 2012-10-17; otherwise the text is literal.
- A key with no value (and no default) makes the variable unresolvable. Callers decide what that
  means: in Resource it matches nothing, in a condition the value compares as null.
- Only single-valued keys can be variables; a multivalued key is treated as unresolvable.
"""

from __future__ import annotations

import re

from iamtrace.context import Context
from iamtrace.wildcard import Segment

_VAR = re.compile(r"\$\{([^}]*)\}")
_DEFAULT = re.compile(r"^\s*([^,]+?)\s*,\s*'([^']*)'\s*$")
_ESCAPES = {"*": "*", "?": "?", "$": "$"}


def substitute(text: str, ctx: Context, enabled: bool) -> tuple[Segment, ...] | None:
    """Split text into wildcard-pattern and literal segments, resolving variables.

    Returns None when a variable cannot be resolved.
    """
    if not enabled or "${" not in text:
        return ((text, False),)
    segments: list[Segment] = []
    pos = 0
    for m in _VAR.finditer(text):
        if m.start() > pos:
            segments.append((text[pos : m.start()], False))
        value = resolve(m.group(1), ctx)
        if value is None:
            return None
        segments.append((value, True))
        pos = m.end()
    if pos < len(text):
        segments.append((text[pos:], False))
    return tuple(segments)


def resolve(expr: str, ctx: Context) -> str | None:
    expr = expr.strip()
    if expr in _ESCAPES:
        return _ESCAPES[expr]
    default = None
    m = _DEFAULT.match(expr)
    if m:
        expr, default = m.group(1), m.group(2)
    if expr in ctx and not ctx.is_multivalued(expr):
        return ctx[expr][0]
    return default


def as_text(segments: tuple[Segment, ...]) -> str:
    return "".join(t for t, _ in segments)
