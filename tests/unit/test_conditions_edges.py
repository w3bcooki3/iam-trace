"""Condition edge cases that mutation testing showed no other test pinned down.

Each case is something AWS documents, where a plausible bug (">" for ">=", a dropped time zone,
ForAnyValue treated as a plain operator) would otherwise go unnoticed.
"""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.conditions import evaluate_condition_block, normalize_condition, parse_date
from iamtrace.context import Context


def check(block: dict[str, Any], ctx: dict[str, Any], variables: bool = True) -> bool:
    return evaluate_condition_block(normalize_condition(block), Context(ctx), variables).matched


# --- "...Equals" includes equality ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("NumericGreaterThanEquals", "5"),
        ("NumericLessThanEquals", "5"),
        ("DateGreaterThanEquals", "2024-06-01T00:00:00Z"),
        ("DateLessThanEquals", "2024-06-01T00:00:00Z"),
    ],
)
def test_or_equals_operators_accept_the_same_value(op: str, value: str) -> None:
    assert check({op: {"k": value}}, {"k": value})


@pytest.mark.parametrize("op", ["NumericGreaterThan", "NumericLessThan"])
def test_strict_operators_reject_the_same_value(op: str) -> None:
    assert not check({op: {"k": "5"}}, {"k": "5"})


# --- dates ---------------------------------------------------------------------------------------


def test_a_time_zone_offset_is_kept() -> None:
    # 05:00 at +05:00 is midnight UTC.
    assert check(
        {"DateEquals": {"aws:CurrentTime": "2024-01-01T00:00:00Z"}}, {"aws:CurrentTime": "2024-01-01T05:00:00+05:00"}
    )
    assert parse_date("2024-01-01T05:00:00+05:00") == parse_date("2024-01-01T00:00:00Z")


def test_negative_epoch_seconds() -> None:
    assert parse_date("-60") == parse_date("1969-12-31T23:59:00Z")
    assert check({"DateLessThan": {"k": "1970-01-01T00:00:00Z"}}, {"k": "-1"})


def test_lower_case_z_is_utc() -> None:
    assert parse_date("2024-01-01T00:00:00z") == parse_date("2024-01-01T00:00:00Z")


# --- binary and IP -------------------------------------------------------------------------------


def test_binary_equals_does_not_ignore_invalid_characters() -> None:
    assert check({"BinaryEquals": {"k": "QUJD"}}, {"k": "QUJD"})
    assert not check({"BinaryEquals": {"k": "QUJD"}}, {"k": "QUJD!"})


def test_ip_range_with_host_bits_set() -> None:
    # Written as 10.0.0.1/24, which is the range 10.0.0.0/24; IAM accepts it.
    assert check({"IpAddress": {"aws:SourceIp": "10.0.0.1/24"}}, {"aws:SourceIp": "10.0.0.200"})


def test_an_invalid_ip_never_matches() -> None:
    assert not check({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "not-an-ip"})
    assert not check({"IpAddress": {"aws:SourceIp": "not-a-range"}}, {"aws:SourceIp": "10.0.0.1"})


# --- ARNs ----------------------------------------------------------------------------------------


def test_arn_like_with_colons_in_the_resource_part() -> None:
    # An SNS subscription ARN has a seventh colon-separated part; the sixth component is
    # everything after the fifth colon.
    sub = "arn:aws:sns:us-east-1:111122223333:alerts:6f1b4f52-0000-4000-8000-000000000000"
    assert check({"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:alerts:*"}}, {"aws:SourceArn": sub})
    assert not check(
        {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:other:*"}}, {"aws:SourceArn": sub}
    )


def test_arn_like_substitutes_policy_variables() -> None:
    block = {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::111122223333:user/${aws:username}"}}
    ctx = {"aws:PrincipalArn": "arn:aws:iam::111122223333:user/ana", "aws:username": "ana"}
    assert check(block, ctx)
    assert not check(block, {**ctx, "aws:username": "bo"})


def test_arn_like_with_an_unresolved_variable_never_matches() -> None:
    block = {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::111122223333:user/${aws:username}"}}
    assert not check(block, {"aws:PrincipalArn": "arn:aws:iam::111122223333:user/ana"})


def test_an_unresolved_value_does_not_hide_the_next_value() -> None:
    # The first value has a variable the request lacks; the second still counts.
    assert check({"StringEquals": {"k": ["${aws:nothing}", "x"]}}, {"k": "x"})
    assert check({"ArnEquals": {"k": ["arn:aws:s3:::${aws:nothing}", "arn:aws:s3:::b"]}}, {"k": "arn:aws:s3:::b"})


# --- set operators -------------------------------------------------------------------------------


def test_for_any_value_with_a_negated_operator() -> None:
    # True if any request value is not in the list: "c" is not.
    block = {"ForAnyValue:StringNotEquals": {"aws:TagKeys": ["a", "b"]}}
    assert check(block, {"aws:TagKeys": ["a", "c"]})
    assert not check(block, {"aws:TagKeys": ["a", "b"]})


def test_for_any_value_with_a_missing_key_is_false_even_when_negated() -> None:
    assert not check({"ForAnyValue:StringNotEquals": {"aws:TagKeys": ["a"]}}, {})
    # A plain negated operator is true for a missing key.
    assert check({"StringNotEquals": {"aws:TagKeys": ["a"]}}, {})


def test_for_any_value_if_exists_with_a_missing_key_is_true() -> None:
    assert check({"ForAnyValue:StringEqualsIfExists": {"aws:TagKeys": ["a"]}}, {})
    assert not check({"ForAnyValue:StringEquals": {"aws:TagKeys": ["a"]}}, {"aws:TagKeys": []})


def test_details_say_why() -> None:
    r = evaluate_condition_block(normalize_condition({"Null": {"aws:TokenIssueTime": "true"}}), Context({}), True)
    assert r.matched and "absent" in r.details[0]
    r = evaluate_condition_block(
        normalize_condition({"ForAllValues:StringEquals": {"aws:TagKeys": ["a"]}}),
        Context({"aws:TagKeys": ["a", "b"]}),
        True,
    )
    assert not r.matched and "not every value matched" in r.details[0]
