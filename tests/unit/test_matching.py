"""Action, resource and principal matching, and policy parsing."""

from __future__ import annotations

import pytest

from iamtrace.arn import resource_matches
from iamtrace.context import Context
from iamtrace.matching import action_matches
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.principals import GrantKind, Principal, match_principal_element, not_principal_excludes

# --- Actions ----------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern,action,expected",
    [
        ("s3:GetObject", "s3:GetObject", True),
        ("s3:getobject", "s3:GetObject", True),  # action names are case-insensitive
        ("S3:GetObject", "s3:GetObject", True),
        ("s3:Get*", "s3:GetObject", True),
        ("s3:*Object", "s3:PutObject", True),
        ("s3:Get?bject", "s3:GetObject", True),
        ("s3:Get*", "s3:PutObject", False),
        ("*", "ec2:RunInstances", True),
        ("s3:*", "s3express:CreateSession", False),
        ("iam:PassRole", "iam:PassRoles", False),
    ],
)
def test_action_matching(pattern: str, action: str, expected: bool) -> None:
    assert action_matches(pattern, action) is expected


# --- Resources --------------------------------------------------------------


def rm(pattern: str, resource: str, ctx: dict[str, str] | None = None, variables: bool = True) -> bool:
    return resource_matches(pattern, resource, Context(ctx or {}), variables)


def test_resource_star_matches_anything() -> None:
    assert rm("*", "arn:aws:s3:::bucket")
    assert rm("*", "*")


def test_resource_arn_requires_concrete_resource() -> None:
    # Actions without a resource type are requested against "*"; only "*" matches them.
    assert not rm("arn:aws:s3:::*", "*")


def test_resource_wildcards_in_resource_part() -> None:
    assert rm("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c")
    assert rm("arn:aws:s3:::*log*", "arn:aws:s3:::my-logs-bucket")
    assert not rm("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket")


def test_resource_part_may_contain_colons() -> None:
    pattern = "arn:aws:logs:us-east-1:123456789012:log-group:/app/*"
    assert rm(pattern, "arn:aws:logs:us-east-1:123456789012:log-group:/app/web:log-stream:x")


def test_resource_matching_is_case_sensitive() -> None:
    assert not rm("arn:aws:s3:::Bucket", "arn:aws:s3:::bucket")


def test_resource_wildcard_in_region_and_account() -> None:
    assert rm("arn:aws:sqs:*:*:queue", "arn:aws:sqs:eu-west-1:111122223333:queue")
    assert rm("arn:aws:sqs:us-*:111122223333:q?", "arn:aws:sqs:us-east-2:111122223333:q1")


def test_resource_variable_substitution() -> None:
    pattern = "arn:aws:s3:::bucket/home/${aws:username}/*"
    assert rm(pattern, "arn:aws:s3:::bucket/home/alice/f", {"aws:username": "alice"})
    assert not rm(pattern, "arn:aws:s3:::bucket/home/bob/f", {"aws:username": "alice"})


def test_resource_variable_missing_matches_nothing() -> None:
    # "A resource containing a variable with no value matches no resource."
    assert not rm("arn:aws:s3:::bucket/${aws:PrincipalTag/team}/*", "arn:aws:s3:::bucket/x/y")


def test_resource_variable_value_is_literal() -> None:
    pattern = "arn:aws:s3:::bucket/${aws:username}"
    assert not rm(pattern, "arn:aws:s3:::bucket/alice", {"aws:username": "*"})


def test_resource_variable_special_characters() -> None:
    assert rm("arn:aws:s3:::bucket/${*}", "arn:aws:s3:::bucket/*")
    assert not rm("arn:aws:s3:::bucket/${*}", "arn:aws:s3:::bucket/x")


def test_resource_variables_disabled_are_literal() -> None:
    pattern = "arn:aws:s3:::bucket/${aws:username}"
    assert rm(pattern, "arn:aws:s3:::bucket/${aws:username}", {"aws:username": "a"}, variables=False)


# --- Principals -------------------------------------------------------------

ACCOUNT = "111122223333"
USER = Principal.from_arn(f"arn:aws:iam::{ACCOUNT}:user/alice")
SESSION = Principal.from_arn(f"arn:aws:sts::{ACCOUNT}:assumed-role/app/s1")


def test_principal_from_session_arn() -> None:
    assert SESSION.kind == "role_session"
    assert SESSION.role_arn == f"arn:aws:iam::{ACCOUNT}:role/app"
    assert SESSION.account == ACCOUNT


def test_principal_role_arn_with_path() -> None:
    p = Principal.from_arn(
        f"arn:aws:sts::{ACCOUNT}:assumed-role/app/s1", role_arn=f"arn:aws:iam::{ACCOUNT}:role/team/app"
    )
    assert p.role_arn == f"arn:aws:iam::{ACCOUNT}:role/team/app"


def test_grant_kinds() -> None:
    assert match_principal_element({"AWS": f"arn:aws:iam::{ACCOUNT}:user/alice"}, USER) is GrantKind.DIRECT
    assert match_principal_element({"AWS": ACCOUNT}, USER) is GrantKind.ACCOUNT
    assert match_principal_element({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, USER) is GrantKind.ACCOUNT
    assert match_principal_element("*", USER) is GrantKind.DIRECT
    assert match_principal_element({"AWS": "*"}, USER) is GrantKind.DIRECT
    assert match_principal_element({"AWS": f"arn:aws:iam::{ACCOUNT}:role/app"}, SESSION) is GrantKind.ROLE
    assert match_principal_element({"AWS": f"arn:aws:sts::{ACCOUNT}:assumed-role/app/s1"}, SESSION) is GrantKind.DIRECT
    assert match_principal_element({"AWS": f"arn:aws:iam::{ACCOUNT}:user/bob"}, USER) is None


def test_service_principal() -> None:
    svc = Principal.service("lambda.amazonaws.com")
    assert match_principal_element({"Service": "lambda.amazonaws.com"}, svc) is GrantKind.DIRECT
    assert match_principal_element({"Service": "ec2.amazonaws.com"}, svc) is None
    assert match_principal_element({"AWS": ACCOUNT}, svc) is None


def test_not_principal_requires_account_and_principal() -> None:
    # Docs: when you use NotPrincipal you must also specify the account ARN of the
    # not-denied principal, otherwise the deny may apply to the whole account.
    only_user = {"AWS": [f"arn:aws:iam::{ACCOUNT}:user/alice"]}
    both = {"AWS": [f"arn:aws:iam::{ACCOUNT}:user/alice", f"arn:aws:iam::{ACCOUNT}:root"]}
    assert not not_principal_excludes(only_user, USER, has_boundary=False)
    assert not_principal_excludes(both, USER, has_boundary=False)


def test_not_principal_never_excludes_principal_with_boundary() -> None:
    both = {"AWS": [f"arn:aws:iam::{ACCOUNT}:user/alice", f"arn:aws:iam::{ACCOUNT}:root"]}
    assert not not_principal_excludes(both, USER, has_boundary=True)


# --- Parsing ----------------------------------------------------------------


def test_parse_single_statement_object_and_string_values() -> None:
    p = Policy.parse(
        {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
        policy_id="p",
        policy_type=PolicyType.IDENTITY,
    )
    assert len(p.statements) == 1
    assert p.statements[0].actions == ("s3:GetObject",)
    assert p.variables_enabled


def test_parse_rejects_bad_effect() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]},
            policy_id="p",
            policy_type=PolicyType.IDENTITY,
        )


def test_parse_rejects_action_and_not_action() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "Action": "*", "NotAction": "s3:*", "Resource": "*"}]},
            policy_id="p",
            policy_type=PolicyType.IDENTITY,
        )


def test_parse_identity_policy_requires_resource() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "Action": "*"}]}, policy_id="p", policy_type=PolicyType.IDENTITY
        )


def test_parse_identity_policy_rejects_principal() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]},
            policy_id="p",
            policy_type=PolicyType.IDENTITY,
        )


def test_parse_resource_policy_requires_principal() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            policy_id="p",
            policy_type=PolicyType.RESOURCE,
        )


def test_parse_version_controls_variables() -> None:
    p = Policy.parse(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        policy_id="p",
        policy_type=PolicyType.IDENTITY,
    )
    assert not p.variables_enabled
    p = Policy.parse(
        {"Version": "2008-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        policy_id="p",
        policy_type=PolicyType.IDENTITY,
    )
    assert not p.variables_enabled


def test_parse_rejects_not_principal_with_allow() -> None:
    with pytest.raises(PolicyError):
        Policy.parse(
            {"Statement": [{"Effect": "Allow", "NotPrincipal": {"AWS": ACCOUNT}, "Action": "*", "Resource": "*"}]},
            policy_id="p",
            policy_type=PolicyType.RESOURCE,
        )


def test_parse_reports_duplicate_keys() -> None:
    p = Policy.from_json(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
        '"Action":"s3:PutObject","Resource":"*"}]}',
        policy_id="p",
        policy_type=PolicyType.IDENTITY,
    )
    assert any("duplicate" in w.lower() for w in p.warnings)
