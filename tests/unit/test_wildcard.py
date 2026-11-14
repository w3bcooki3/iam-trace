"""Wildcard matching: semantics, and protection against pathological patterns."""

from __future__ import annotations

import re
import time

import pytest

from iamtrace.wildcard import glob_match


@pytest.mark.parametrize(
    "pattern,value,expected",
    [
        ("*", "", True),
        ("*", "anything", True),
        ("", "", True),
        ("", "a", False),
        ("a*", "a", True),
        ("a*", "ab/c:d", True),
        ("*b", "ab", True),
        ("*b", "ba", False),
        ("a?c", "abc", True),
        ("a?c", "ac", False),
        ("a**b", "ab", True),
        ("*a*b*", "xxaxxbxx", True),
        ("*a*b*", "xxbxxaxx", False),
        ("arn:aws:s3:::*log*", "arn:aws:s3:::my-logs/file", True),
        ("a.c", "abc", False),  # regex metacharacters are literal
        ("a[bc]", "ab", False),
        ("a+", "aa", False),
    ],
)
def test_semantics(pattern: str, value: str, expected: bool) -> None:
    assert glob_match(pattern, value) is expected


def test_matches_regex_reference_on_random_inputs() -> None:
    import random

    rng = random.Random(7)
    alphabet = "ab/:*?"
    for _ in range(3000):
        p = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        v = "".join(rng.choice("ab/:") for _ in range(rng.randint(0, 10)))
        ref = re.fullmatch("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in p), v, re.DOTALL)
        assert glob_match(p, v) is (ref is not None), (p, v)


def test_literal_segments_are_not_wildcards() -> None:
    assert glob_match((("home/", False), ("*", True)), "home/*")
    assert not glob_match((("home/", False), ("*", True)), "home/x")


def test_ignore_case() -> None:
    assert glob_match("S3:Get*", "s3:getobject", ignore_case=True)
    assert not glob_match("S3:Get*", "s3:getobject")


def test_pathological_pattern_is_fast() -> None:
    # With a backtracking regex this takes minutes; it must stay well under a second.
    start = time.perf_counter()
    assert not glob_match("*a" * 40 + "b", "a" * 5000)
    assert time.perf_counter() - start < 1.0
