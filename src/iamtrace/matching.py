"""Action/NotAction matching.

Action names are case-insensitive ("s3:getobject" equals "s3:GetObject"). Wildcards are allowed
in the action part. The service prefix must match exactly (case-insensitively) unless the whole
pattern is "*".
"""

from __future__ import annotations

from functools import lru_cache

from iamtrace.wildcard import glob_match


@lru_cache(maxsize=131072)
def action_matches(pattern: str, action: str) -> bool:
    """Cached: policies repeat the same few patterns, and the analysis asks about the same actions."""
    if pattern == "*":
        return True
    p_service, sep, p_name = pattern.partition(":")
    a_service, _, a_name = action.partition(":")
    if not sep:
        return False
    return glob_match(p_service, a_service, ignore_case=True) and glob_match(p_name, a_name, ignore_case=True)


def any_action_matches(patterns: tuple[str, ...], action: str) -> bool:
    return any(action_matches(p, action) for p in patterns)
