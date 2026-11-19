from __future__ import annotations

import pytest

from iamtrace import fields
from iamtrace.fields import FieldError


@pytest.mark.parametrize(
    "v", ["s3:GetObject", "ec2:RunInstances", "IAM:passrole", "execute-api:Invoke", "s3:Get-Object_2"]
)
def test_actions(v: str) -> None:
    assert fields.action(v) == v


@pytest.mark.parametrize(
    "v, message",
    [
        ("", "enter"),
        ("GetObject", "service:Action"),
        ("s3:*", "pattern"),
        ("s3:Get?", "pattern"),
        ("s3:Get Object", "service:Action"),
        ("s3:", "service:Action"),
    ],
)
def test_bad_actions(v: str, message: str) -> None:
    with pytest.raises(FieldError, match=message):
        fields.action(v)


@pytest.mark.parametrize(
    "v", ["*", "", "arn:aws:s3:::bucket/key", "arn:aws-cn:iam::111122223333:role/r", "arn:aws:s3:::b/${x}/é"]
)
def test_resources(v: str) -> None:
    assert fields.resource(v) == (v or "*")


@pytest.mark.parametrize("v", ["bucket", "arn:aws:s3", "s3://bucket/key", "arn::s3:::b"])
def test_bad_resources(v: str) -> None:
    with pytest.raises(FieldError, match="must be an ARN"):
        fields.resource(v)


@pytest.mark.parametrize(
    "v",
    [
        "arn:aws:iam::111122223333:user/dev",
        "arn:aws:iam::111122223333:role/path/r",
        "arn:aws:sts::111122223333:assumed-role/r/session",
        "arn:aws:iam::111122223333:root",
        "service:lambda.amazonaws.com",
        "service:ec2.amazonaws.com.cn",
    ],
)
def test_principals(v: str) -> None:
    assert fields.principal(v) == v


@pytest.mark.parametrize(
    "v, message",
    [
        ("", "enter"),
        ("dev", "IAM or STS ARN"),
        ("arn:aws:s3:::bucket", "IAM or STS ARN"),
        ("arn:aws:iam::12:user/dev", "12 digits"),
        ("service:", "not a service principal"),
        ("service:lambda", "not a service principal"),
    ],
)
def test_bad_principals(v: str, message: str) -> None:
    with pytest.raises(FieldError, match=message):
        fields.principal(v)


def test_account_ids() -> None:
    assert fields.account_id("") is None
    assert fields.account_id(" 111122223333 ") == "111122223333"
    for bad in ("12", "abcdefghijkl", "1111222233334"):
        with pytest.raises(FieldError, match="12 digits"):
            fields.account_id(bad)


@pytest.mark.parametrize(
    "ctx, message",
    [
        ({"aws:CurrentTime": "yesterday"}, "not a date"),
        ({"aws:SourceIp": "10.0.0"}, "not an IP"),
        ({"aws:MultiFactorAuthPresent": "yes"}, "true or false"),
        ({"aws:MultiFactorAuthAge": "ten"}, "number"),
        ({"bad key": "x"}, "spaces"),
    ],
)
def test_bad_context_values(ctx: dict, message: str) -> None:
    with pytest.raises(FieldError, match=message):
        fields.context(ctx)


def test_good_context_values() -> None:
    ok = {
        "aws:CurrentTime": "2026-11-19T10:00:00Z",
        "aws:EpochTime": "1763546400",
        "aws:SourceIp": ["10.0.0.1", "2001:db8::1"],
        "aws:SecureTransport": "TRUE",
        "aws:MultiFactorAuthAge": "3600",
        "aws:PrincipalTag/team": "anything goes",
    }
    assert fields.context(ok) == []


def test_whole_numbers() -> None:
    assert fields.whole_number(" 90 ", "days", 1, 400) == 90
    for bad, message in (("abc", "whole number"), (0, "between"), (401, "between"), ("1.5", "whole number")):
        with pytest.raises(FieldError, match=message):
            fields.whole_number(bad, "days", 1, 400)
