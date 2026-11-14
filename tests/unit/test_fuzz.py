"""Randomised robustness tests. The engine must never crash on any input: it either evaluates or
raises PolicyError (which the CLI reports as exit code 2). Seeds are fixed so failures reproduce."""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from iamtrace import Decision, Policy, PolicyError, PolicySet, PolicyType, Principal, Request, evaluate
from iamtrace.loader import parse_any_policy

ACTIONS = ["s3:GetObject", "s3:*", "*", "iam:Pass?ole", "ec2:Run*", "sts:AssumeRole", "kms:Decrypt", "S3:getobject"]
RESOURCES = [
    "*",
    "arn:aws:s3:::b/*",
    "arn:aws:s3:::b",
    "arn:aws:iam::111122223333:role/*",
    "arn:aws:kms:us-east-1:111122223333:key/k",
    "arn:aws:s3:::${aws:username}/*",
    "not-an-arn",
    "arn:aws:*",
]
OPERATORS = [
    "StringEquals",
    "StringNotLike",
    "ForAllValues:StringLike",
    "ForAnyValue:StringNotEquals",
    "Bool",
    "NumericLessThan",
    "DateGreaterThanIfExists",
    "IpAddress",
    "NotIpAddress",
    "ArnLike",
    "Null",
    "BinaryEquals",
    "StringEqualsIgnoreCaseIfExists",
    "ArnNotEqualsIfExists",
]
KEYS = ["aws:SourceIp", "aws:PrincipalTag/team", "aws:TagKeys", "aws:CurrentTime", "aws:SecureTransport", "s3:prefix"]
VALUES = [
    "10.0.0.0/8",
    "true",
    "2024-01-01T00:00:00Z",
    "1700000000",
    "${aws:username}",
    "*",
    "",
    "not-an-ip",
    "QmluYXJ5",
    "arn:aws:iam::*:role/x",
    "x" * 300,
    "${aws:PrincipalTag/team, 'd'}",
    "${",
    "}",
]
PRINCIPALS = [
    "*",
    {"AWS": "111122223333"},
    {"AWS": "arn:aws:iam::111122223333:user/alice"},
    {"AWS": ["arn:aws:iam::111122223333:role/app", "444455556666"]},
    {"Service": "lambda.amazonaws.com"},
]


def rand_statement(rng: random.Random, resource_policy: bool) -> dict[str, Any]:
    s: dict[str, Any] = {"Effect": rng.choice(["Allow", "Deny"])}
    s["NotAction" if rng.random() < 0.15 else "Action"] = rng.sample(ACTIONS, rng.randint(1, 3))
    if rng.random() < 0.9:
        s["NotResource" if rng.random() < 0.15 else "Resource"] = rng.sample(RESOURCES, rng.randint(1, 3))
    if resource_policy:
        if s["Effect"] == "Deny" and rng.random() < 0.2:
            s["NotPrincipal"] = {"AWS": "arn:aws:iam::111122223333:root"}
        else:
            s["Principal"] = rng.choice(PRINCIPALS)
    if rng.random() < 0.6:
        s["Condition"] = {
            rng.choice(OPERATORS): {rng.choice(KEYS): rng.sample(VALUES, rng.randint(1, 3))}
            for _ in range(rng.randint(1, 2))
        }
    return s


def rand_policy(rng: random.Random, t: PolicyType) -> Policy:
    doc = {
        "Version": rng.choice(["2012-10-17", "2008-10-17"]),
        "Statement": [rand_statement(rng, t is PolicyType.RESOURCE) for _ in range(rng.randint(1, 4))],
    }
    return Policy.parse(doc, policy_id=f"{t.value}", policy_type=t)


@pytest.mark.parametrize("seed", range(40))
def test_random_evaluations_never_crash(seed: int) -> None:
    rng = random.Random(seed)
    principals = [
        Principal.from_arn("arn:aws:iam::111122223333:user/alice"),
        Principal.from_arn("arn:aws:sts::111122223333:assumed-role/app/s"),
        Principal.from_arn("arn:aws:iam::111122223333:root"),
        Principal.service("lambda.amazonaws.com"),
        Principal.anonymous(),
    ]
    for _ in range(50):
        try:
            ps = PolicySet(
                identity=[rand_policy(rng, PolicyType.IDENTITY)],
                resource=[rand_policy(rng, PolicyType.RESOURCE)] if rng.random() < 0.6 else [],
                boundary=rand_policy(rng, PolicyType.BOUNDARY) if rng.random() < 0.3 else None,
                session=[rand_policy(rng, PolicyType.SESSION)] if rng.random() < 0.3 else [],
                scps=[[rand_policy(rng, PolicyType.SCP)]] if rng.random() < 0.3 else None,
            )
        except PolicyError:
            continue
        ctx = {
            k: rng.choice([v, [v, "x"], []]) for k, v in zip(rng.sample(KEYS, 3), rng.sample(VALUES, 3), strict=True)
        }
        req = Request(
            rng.choice(principals),
            rng.choice(["s3:GetObject", "kms:Decrypt", "sts:AssumeRole", "ec2:RunInstances"]),
            rng.choice(RESOURCES[:5]),
            resource_account=rng.choice([None, "111122223333", "444455556666"]),
            context=ctx,
        )
        result = evaluate(req, ps)
        assert result.decision in Decision
        assert result.trace and result.trace[-1].step == result.deciding_step
        json.dumps(result.to_dict())  # always serialisable


@pytest.mark.parametrize(
    "text",
    [
        "",
        "null",
        "[]",
        "{}",
        '{"Statement": null}',
        '{"Statement": [null]}',
        '{"Statement": [{}]}',
        '{"Statement": {"Effect": "Allow", "Action": [], "Resource": "*"}}',
        '{"Statement": {"Effect": "Allow", "Action": 5, "Resource": "*"}}',
        '{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"StringEquals": "x"}}}',
        '{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*",'
        ' "Condition": {"StringEquals": {"k": {"a": 1}}}}}',
        '{"Statement": {"Effect": "Allow", "Principal": {"Bogus": "x"}, "Action": "*"}}',
        '{"Version": "2099-01-01", "Statement": []}',
        '{"Statement": ' + "[" * 2000 + "]" * 2000 + "}",
        "﻿{}",
        '{"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}',
    ],
)
def test_malformed_documents_raise_policy_error(text: str) -> None:
    with pytest.raises(PolicyError):
        parse_any_policy(text, "fuzz")
