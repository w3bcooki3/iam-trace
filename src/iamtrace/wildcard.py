"""Wildcard (* and ?) matching shared by actions, resources and string/ARN conditions.

A pattern is a sequence of segments. Policy text is a *pattern* segment, where * matches any
run of characters (including none) and ? matches exactly one. Text that came from a policy
variable is a *literal* segment: its characters never act as wildcards. That is how IAM keeps
${aws:username} = "*" from matching every user.

Matching does not use regular expressions. A regex built from a pattern such as "*a*a*a*a*b"
backtracks exponentially, so one hostile policy could stall CI or freeze the web page. The
matcher below is the classic single-backtrack-point algorithm: worst case O(len(pattern) *
len(value)), never exponential.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

# (text, is_literal)
Segment = tuple[str, bool]

STAR = object()
ONE = object()


@lru_cache(maxsize=8192)
def _tokens(segments: tuple[Segment, ...], ignore_case: bool) -> tuple[object, ...]:
    out: list[object] = []
    for text, literal in segments:
        if ignore_case:
            text = text.casefold()
        for ch in text:
            if literal:
                out.append(ch)
            elif ch == "*":
                if not out or out[-1] is not STAR:  # collapse runs of *
                    out.append(STAR)
            elif ch == "?":
                out.append(ONE)
            else:
                out.append(ch)
    return tuple(out)


def _match(tokens: tuple[object, ...], value: str) -> bool:
    t = v = 0
    star_t = -1  # position after the last * seen in the pattern
    star_v = 0  # value position that * is currently covering up to
    nt, nv = len(tokens), len(value)
    while v < nv:
        if t < nt and tokens[t] is not STAR and (tokens[t] is ONE or tokens[t] == value[v]):
            t += 1
            v += 1
        elif t < nt and tokens[t] is STAR:
            star_t = t + 1
            star_v = v
            t += 1
        elif star_t != -1:
            # Let the last * absorb one more character and retry from there.
            star_v += 1
            v = star_v
            t = star_t
        else:
            return False
    while t < nt and tokens[t] is STAR:
        t += 1
    return t == nt


def glob_match(pattern: str | Sequence[Segment], value: str, *, ignore_case: bool = False) -> bool:
    segs: tuple[Segment, ...] = ((pattern, False),) if isinstance(pattern, str) else tuple(pattern)
    tokens = _tokens(segs, ignore_case)
    return _match(tokens, value.casefold() if ignore_case else value)


def has_wildcard(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern
