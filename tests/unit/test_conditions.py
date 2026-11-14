"""Condition operator semantics.

Each test cites the AWS documentation it encodes. Main sources:
- Condition operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- Set operators: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
- Condition element: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
"""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.conditions import evaluate_condition_block, normalize_condition
from iamtrace.context import Context


def check(block: dict[str, Any], ctx: dict[str, Any], variables: bool = True) -> bool:
    return evaluate_condition_block(normalize_condition(block), Context(ctx), variables).matched


# --- String operators -------------------------------------------------------


def test_string_equals_is_case_sensitive() -> None:
    assert check({"StringEquals": {"aws:username": "john"}}, {"aws:username": "john"})
    assert not check({"StringEquals": {"aws:username": "john"}}, {"aws:username": "John"})


def test_string_equals_ignore_case() -> None:
    assert check({"StringEqualsIgnoreCase": {"aws:username": "john"}}, {"aws:username": "JOHN"})


def test_string_like_wildcards() -> None:
    block = {"StringLike": {"s3:prefix": ["home/*", "a?c"]}}
    assert check(block, {"s3:prefix": "home/x/y"})
    assert check(block, {"s3:prefix": "abc"})
    assert not check(block, {"s3:prefix": "abbc"})


def test_string_equals_treats_asterisk_literally() -> None:
    assert not check({"StringEquals": {"k": "a*"}}, {"k": "abc"})
    assert check({"StringEquals": {"k": "a*"}}, {"k": "a*"})


def test_values_within_a_key_are_ored() -> None:
    assert check({"StringEquals": {"k": ["a", "b"]}}, {"k": "b"})


def test_keys_and_operators_are_anded() -> None:
    block = {"StringEquals": {"a": "1", "b": "2"}, "Bool": {"c": "true"}}
    assert check(block, {"a": "1", "b": "2", "c": "true"})
    assert not check(block, {"a": "1", "b": "2", "c": "false"})
    assert not check(block, {"a": "1", "b": "x", "c": "true"})


def test_condition_key_names_are_case_insensitive() -> None:
    # "Context key names are not case-sensitive."
    assert check({"IpAddress": {"aws:SourceIP": "10.0.0.0/8"}}, {"AWS:SourceIp": "10.1.2.3"})


# --- Missing keys -----------------------------------------------------------


def test_missing_key_positive_operator_is_false() -> None:
    assert not check({"StringEquals": {"k": "v"}}, {})


@pytest.mark.parametrize(
    "op",
    ["StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "ArnNotEquals", "ArnNotLike"],
)
def test_missing_key_negated_operator_is_true(op: str) -> None:
    # "If the policy condition requires that the key is not matched, such as StringNotLike
    # or ArnNotLike, and the right key is not present, the condition is true."
    assert check({op: {"k": "v"}}, {})


def test_if_exists_missing_key_is_true() -> None:
    assert check({"StringLikeIfExists": {"ec2:InstanceType": ["t2.*"]}}, {})


def test_if_exists_present_key_uses_base_operator() -> None:
    block = {"StringLikeIfExists": {"ec2:InstanceType": ["t2.*"]}}
    assert check(block, {"ec2:InstanceType": "t2.micro"})
    assert not check(block, {"ec2:InstanceType": "m5.large"})


def test_negated_if_exists_missing_key_is_true() -> None:
    # Docs: a Deny with StringNotEqualsIfExists still denies when the key is absent,
    # i.e. the condition evaluates to true.
    assert check({"StringNotEqualsIfExists": {"k": "v"}}, {})


# --- Null ------------------------------------------------------------------


def test_null_true_means_absent() -> None:
    assert check({"Null": {"aws:TokenIssueTime": "true"}}, {})
    assert not check({"Null": {"aws:TokenIssueTime": "true"}}, {"aws:TokenIssueTime": "2024-01-01T00:00:00Z"})


def test_null_false_means_present() -> None:
    assert check({"Null": {"aws:TokenIssueTime": "false"}}, {"aws:TokenIssueTime": "2024-01-01T00:00:00Z"})
    assert not check({"Null": {"aws:TokenIssueTime": "false"}}, {})


def test_null_treats_empty_multivalue_as_absent() -> None:
    assert check({"Null": {"aws:TagKeys": "true"}}, {"aws:TagKeys": []})


# --- Numeric, Date, Bool, Binary -------------------------------------------


def test_numeric_operators() -> None:
    assert check({"NumericLessThanEquals": {"s3:max-keys": "10"}}, {"s3:max-keys": "10"})
    assert not check({"NumericLessThan": {"s3:max-keys": "10"}}, {"s3:max-keys": "10"})
    assert check({"NumericGreaterThan": {"n": "1.5"}}, {"n": "2"})
    assert check({"NumericNotEquals": {"n": "1"}}, {"n": "2"})


def test_numeric_unparseable_request_value_does_not_match() -> None:
    assert not check({"NumericEquals": {"n": "1"}}, {"n": "one"})


def test_date_iso8601_and_epoch() -> None:
    # "You must specify date/time values with one of the W3C implementations of the
    # ISO 8601 date formats or in epoch (UNIX) time."
    ctx = {"aws:CurrentTime": "2024-06-01T12:00:00Z"}
    assert check({"DateGreaterThan": {"aws:CurrentTime": "2024-01-01T00:00:00Z"}}, ctx)
    assert check({"DateLessThan": {"aws:CurrentTime": "1735689600"}}, ctx)  # 2025-01-01
    assert check({"DateEquals": {"aws:CurrentTime": "2024-06-01T12:00:00+00:00"}}, ctx)
    assert check({"DateGreaterThanEquals": {"aws:CurrentTime": "2024-06-01"}}, ctx)


def test_bool_operator() -> None:
    assert check({"Bool": {"aws:SecureTransport": "false"}}, {"aws:SecureTransport": False})
    assert not check({"Bool": {"aws:SecureTransport": "false"}}, {"aws:SecureTransport": "true"})
    # Missing key: no match.
    assert not check({"Bool": {"aws:SecureTransport": "false"}}, {})


def test_bool_accepts_json_boolean_in_policy() -> None:
    assert check({"Bool": {"aws:MultiFactorAuthPresent": True}}, {"aws:MultiFactorAuthPresent": "true"})


def test_binary_equals_compares_base64_bytes() -> None:
    assert check({"BinaryEquals": {"k": "QmluYXJ5"}}, {"k": "QmluYXJ5"})
    assert not check({"BinaryEquals": {"k": "QmluYXJ5"}}, {"k": "QmluYXJ6"})


# --- IP address -------------------------------------------------------------


def test_ip_address_cidr_v4_and_v6() -> None:
    block = {"IpAddress": {"aws:SourceIp": ["203.0.113.0/24", "2001:DB8:1234:5678::/64"]}}
    assert check(block, {"aws:SourceIp": "203.0.113.7"})
    assert check(block, {"aws:SourceIp": "2001:db8:1234:5678::1"})
    assert not check(block, {"aws:SourceIp": "198.51.100.1"})


def test_ip_address_without_prefix_is_slash_32() -> None:
    assert check({"IpAddress": {"aws:SourceIp": "203.0.113.7"}}, {"aws:SourceIp": "203.0.113.7"})
    assert not check({"IpAddress": {"aws:SourceIp": "203.0.113.7"}}, {"aws:SourceIp": "203.0.113.8"})


def test_not_ip_address() -> None:
    assert check({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "192.0.2.1"})
    assert not check({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "10.0.0.1"})


# --- ARN --------------------------------------------------------------------


def test_arn_like_matches_per_component() -> None:
    block = {"ArnLike": {"aws:SourceArn": "arn:aws:sns:*:123456789012:*"}}
    assert check(block, {"aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:topic"})
    assert not check(block, {"aws:SourceArn": "arn:aws:sns:us-east-1:999999999999:topic"})


def test_arn_wildcard_does_not_span_components() -> None:
    # "Each of the six colon-delimited components of the ARN is checked separately."
    block = {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-*"}}
    # The pattern has only four components, so it cannot match a six-component ARN.
    assert not check(block, {"aws:SourceArn": "arn:aws:sns:us-east-1:123456789012:topic"})


def test_arn_equals_and_like_are_identical() -> None:
    ctx = {"aws:SourceArn": "arn:aws:s3:::bucket"}
    assert check({"ArnEquals": {"aws:SourceArn": "arn:aws:s3:::b*"}}, ctx)
    assert check({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::b*"}}, ctx)


# --- Set operators ----------------------------------------------------------


def test_for_all_values_true_on_missing_key() -> None:
    # "It also returns true if there are no context keys in the request."
    assert check({"ForAllValues:StringEquals": {"aws:TagKeys": ["a", "b"]}}, {})


def test_for_all_values_true_on_empty_set() -> None:
    assert check({"ForAllValues:StringEquals": {"aws:TagKeys": ["a", "b"]}}, {"aws:TagKeys": []})


def test_for_all_values_every_member_must_match() -> None:
    block = {"ForAllValues:StringEquals": {"aws:TagKeys": ["a", "b"]}}
    assert check(block, {"aws:TagKeys": ["a"]})
    assert check(block, {"aws:TagKeys": ["a", "b"]})
    assert not check(block, {"aws:TagKeys": ["a", "c"]})


def test_for_all_values_with_null_guard() -> None:
    block = {
        "ForAllValues:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]},
        "Null": {"aws:TagKeys": "false"},
    }
    assert not check(block, {})
    assert check(block, {"aws:TagKeys": ["environment"]})


def test_for_any_value_false_on_missing_key() -> None:
    # "For no matching context key or if the key does not exist, the condition returns false."
    assert not check({"ForAnyValue:StringEquals": {"aws:TagKeys": ["a"]}}, {})
    assert not check({"ForAnyValue:StringEquals": {"aws:TagKeys": ["a"]}}, {"aws:TagKeys": []})


def test_for_any_value_one_member_suffices() -> None:
    assert check({"ForAnyValue:StringEquals": {"aws:TagKeys": ["a"]}}, {"aws:TagKeys": ["x", "a"]})


def test_for_all_values_negated_operator() -> None:
    # Every request value must differ from every policy value.
    block = {"ForAllValues:StringNotEquals": {"aws:TagKeys": ["secret"]}}
    assert check(block, {"aws:TagKeys": ["a", "b"]})
    assert not check(block, {"aws:TagKeys": ["a", "secret"]})


def test_for_any_value_string_like() -> None:
    assert check({"ForAnyValue:StringLike": {"k": "dev-*"}}, {"k": ["prod-1", "dev-2"]})


# --- Policy variables in conditions -----------------------------------------


def test_variable_in_string_condition() -> None:
    block = {"StringLike": {"s3:prefix": ["home/${aws:username}/*"]}}
    assert check(block, {"s3:prefix": "home/alice/x", "aws:username": "alice"})
    assert not check(block, {"s3:prefix": "home/bob/x", "aws:username": "alice"})


def test_variable_value_is_literal_not_wildcard() -> None:
    block = {"StringLike": {"k": "${aws:username}"}}
    assert not check(block, {"k": "anything", "aws:username": "*"})
    assert check(block, {"k": "*", "aws:username": "*"})


def test_variable_with_missing_key_positive_no_match_negated_match() -> None:
    # Missing variable: positive operators don't match, negative operators do.
    assert not check({"StringEquals": {"k": "${aws:PrincipalTag/team}"}}, {"k": "x"})
    assert check({"StringNotEquals": {"k": "${aws:PrincipalTag/team}"}}, {"k": "x"})


def test_variable_default_value() -> None:
    block = {"StringEquals": {"k": "${aws:PrincipalTag/team, 'company-wide'}"}}
    assert check(block, {"k": "company-wide"})
    assert check(block, {"k": "yellow", "aws:PrincipalTag/team": "yellow"})


def test_variables_disabled_are_literal() -> None:
    # Without Version 2012-10-17 variables "are treated as literal strings".
    block = {"StringEquals": {"k": "${aws:username}"}}
    assert check(block, {"k": "${aws:username}", "aws:username": "a"}, variables=False)
    assert not check(block, {"k": "a", "aws:username": "a"}, variables=False)


def test_unknown_operator_rejected() -> None:
    from iamtrace.model import PolicyError

    with pytest.raises(PolicyError):
        normalize_condition({"StringEqualz": {"k": "v"}})
