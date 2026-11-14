"""Cases the AWS policy simulator cannot model, so they cannot be differential-tested.

Every test quotes or paraphrases the AWS documentation it encodes. If AWS changes the docs,
these tests are the place to update. See docs/limitations.md for the list of gaps.

Sources:
[EVAL]  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
[BOUND] https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
[RCP]   https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
[NOTP]  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
"""

from __future__ import annotations

from iamtrace import Decision, Principal
from tests.helpers import (
    A,
    B,
    allow,
    boundary,
    deny,
    identity,
    rcp,
    resource,
    role_session,
    run,
    scp,
    session,
    user,
)

SECRET = f"arn:aws:secretsmanager:us-east-1:{A}:secret:db-AbCdEf"
ROLE_ARN = f"arn:aws:iam::{A}:role/app"
SESSION_ARN = f"arn:aws:sts::{A}:assumed-role/app/s1"


# --- Resource-policy grants by principal type [EVAL] [BOUND] -----------------


def test_role_arn_grant_limited_by_boundary() -> None:
    # "Resource-based policies that grant permissions to an IAM role ARN are limited by an
    # implicit deny in a permissions boundary or session policy."
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": ROLE_ARN}))
    r = run(role_session(), "secretsmanager:GetSecretValue", SECRET, resource=[res], boundary=boundary(allow("s3:*")))
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "permissions_boundary"


def test_role_arn_grant_limited_by_session_policy() -> None:
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": ROLE_ARN}))
    r = run(role_session(), "secretsmanager:GetSecretValue", SECRET, resource=[res], session=[session(allow("s3:*"))])
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "session_policy"


def test_role_arn_grant_does_not_need_identity_policy() -> None:
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": ROLE_ARN}))
    assert run(role_session(), "secretsmanager:GetSecretValue", SECRET, resource=[res]).allowed


def test_role_session_arn_grant_not_limited() -> None:
    # "Permissions granted directly to a session are not limited by an implicit deny in an
    # identity-based policy, a permissions boundary, or session policy."
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": SESSION_ARN}))
    r = run(
        role_session(),
        "secretsmanager:GetSecretValue",
        SECRET,
        resource=[res],
        boundary=boundary(allow("s3:*")),
        session=[session(allow("s3:*"))],
    )
    assert r.allowed
    assert r.deciding_step == "resource_policy"


def test_user_arn_grant_not_limited_by_boundary() -> None:
    # The Nikhil example in [BOUND]: "implicit denies in permissions boundaries do not limit
    # resource-based policies".
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    r = run(user(), "secretsmanager:GetSecretValue", SECRET, resource=[res], boundary=boundary(allow("s3:*")))
    assert r.allowed


def test_explicit_deny_in_boundary_still_blocks_resource_grant() -> None:
    res = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    r = run(
        user(),
        "secretsmanager:GetSecretValue",
        SECRET,
        resource=[res],
        boundary=boundary(allow("*"), deny("secretsmanager:*")),
    )
    assert r.decision is Decision.EXPLICIT_DENY


def test_wildcard_principal_with_principal_arn_not_limited() -> None:
    # "Permissions boundaries and session policies do not limit permissions granted using the
    # aws:PrincipalArn condition key with a wildcard(*) in the Principal element, unless the
    # identity-based policies contain an explicit deny."
    res = resource(
        allow(
            "secretsmanager:GetSecretValue",
            SECRET,
            Principal="*",
            Condition={"ArnEquals": {"aws:PrincipalArn": ROLE_ARN}},
        )
    )
    r = run(
        role_session(),
        "secretsmanager:GetSecretValue",
        SECRET,
        resource=[res],
        boundary=boundary(allow("s3:*")),
        session=[session(allow("s3:*"))],
    )
    assert r.allowed


def test_federated_user_grant_and_federating_user_grant() -> None:
    fed = Principal.from_arn(f"arn:aws:sts::{A}:federated-user/bob", federating_user_arn=f"arn:aws:iam::{A}:user/bob")
    direct = resource(
        allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": f"arn:aws:sts::{A}:federated-user/bob"})
    )
    via_user = resource(allow("secretsmanager:GetSecretValue", SECRET, Principal={"AWS": f"arn:aws:iam::{A}:user/bob"}))
    limit = [session(allow("s3:*"))]
    # Granted to the federated user ARN: not limited by the session policy.
    assert run(fed, "secretsmanager:GetSecretValue", SECRET, resource=[direct], session=limit).allowed
    # Granted to the IAM user who federated: limited by the session policy.
    assert not run(fed, "secretsmanager:GetSecretValue", SECRET, resource=[via_user], session=limit).allowed
    assert run(fed, "secretsmanager:GetSecretValue", SECRET, resource=[via_user]).allowed


# --- Resource policies that must explicitly allow [EVAL] ---------------------


def test_role_trust_policy_must_allow_assume_role() -> None:
    # "IAM role trust policies and KMS key policies are exceptions to this logic, because they
    # must explicitly allow access for principals."
    target = f"arn:aws:iam::{A}:role/target"
    ident = [identity(allow("sts:AssumeRole", target))]
    r = run(user(), "sts:AssumeRole", target, identity=ident)
    assert not r.allowed
    trust = resource(allow("sts:AssumeRole", None, Principal={"AWS": f"arn:aws:iam::{A}:root"}))
    assert run(user(), "sts:AssumeRole", target, identity=ident, resource=[trust]).allowed


def test_kms_key_policy_must_allow() -> None:
    key = f"arn:aws:kms:us-east-1:{A}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    ident = [identity(allow("kms:Decrypt", key))]
    assert not run(user(), "kms:Decrypt", key, identity=ident).allowed
    key_policy = resource(allow("kms:*", "*", Principal={"AWS": f"arn:aws:iam::{A}:root"}))
    assert run(user(), "kms:Decrypt", key, identity=ident, resource=[key_policy]).allowed


def test_trust_policy_naming_user_directly_needs_no_identity_policy() -> None:
    target = f"arn:aws:iam::{A}:role/target"
    trust = resource(allow("sts:AssumeRole", None, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    assert run(user(), "sts:AssumeRole", target, resource=[trust]).allowed


# --- RCPs [RCP] (the simulator "does not support resource control policies") --


def test_rcp_deny_applies_to_cross_org_principal() -> None:
    # "RCPs impact the effective permissions of principals trying to access resources in a member
    # account with an applicable RCP, regardless of whether the principals belong to the same
    # organizations or not."
    obj = "arn:aws:s3:::bucket/key"
    res = resource(allow("s3:GetObject", obj, Principal="*"))
    r = run(
        user(account=B),
        "s3:GetObject",
        obj,
        resource_account=A,
        resource=[res],
        identity=[identity(allow("s3:*"))],
        rcps=[
            [
                rcp(
                    allow("*", Principal="*"),
                    deny("s3:*", Principal="*", Condition={"StringNotEquals": {"aws:PrincipalAccount": A}}),
                )
            ]
        ],
    )
    assert r.decision is Decision.EXPLICIT_DENY


def test_rcp_never_grants() -> None:
    # "A user or role without any IAM permission policies has no access, even if an applicable
    # RCP allows all services, all actions, and all resources."
    r = run(
        user(), "s3:GetObject", "arn:aws:s3:::bucket/key", resource_account=A, rcps=[[rcp(allow("*", Principal="*"))]]
    )
    assert not r.allowed


def test_rcp_does_not_apply_to_service_linked_role() -> None:
    # "The permissions of service-linked roles can't be restricted by RCPs."
    slr = Principal.from_arn(
        f"arn:aws:sts::{A}:assumed-role/AWSServiceRoleForX/s",
        role_arn=f"arn:aws:iam::{A}:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX",
    )
    assert slr.is_service_linked_role
    r = run(
        slr,
        "s3:GetObject",
        "arn:aws:s3:::bucket/key",
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        rcps=[[rcp(deny("*", Principal="*"))]],
    )
    assert r.allowed


def test_rcp_does_not_apply_to_kms_retire_grant() -> None:
    key = f"arn:aws:kms:us-east-1:{A}:key/k"
    key_policy = resource(allow("kms:*", "*", Principal={"AWS": f"arn:aws:iam::{A}:root"}))
    r = run(
        user(),
        "kms:RetireGrant",
        key,
        identity=[identity(allow("kms:*"))],
        resource=[key_policy],
        rcps=[[rcp(deny("*", Principal="*"))]],
    )
    assert r.allowed


def test_rcp_exempt_management_account_resources() -> None:
    r = run(
        user(),
        "s3:GetObject",
        "arn:aws:s3:::bucket/key",
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        rcps=[[rcp(deny("*", Principal="*"))]],
        rcp_exempt=True,
    )
    assert r.allowed


# --- SCPs ---------------------------------------------------------------------


def test_scp_does_not_apply_to_service_linked_role() -> None:
    slr = Principal.from_arn(
        f"arn:aws:sts::{A}:assumed-role/AWSServiceRoleForX/s",
        role_arn=f"arn:aws:iam::{A}:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX",
    )
    r = run(
        slr,
        "s3:GetObject",
        "arn:aws:s3:::b/k",
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        scps=[[scp(deny("*"))]],
    )
    assert r.allowed


# --- Root user [EVAL] --------------------------------------------------------


def test_root_user_needs_no_identity_policy() -> None:
    # "By default, all requests are implicitly denied with the exception of the AWS account root
    # user, which has full access."
    root = Principal.from_arn(f"arn:aws:iam::{A}:root")
    assert run(root, "s3:GetObject", "arn:aws:s3:::b/k", resource_account=A).allowed


def test_root_user_still_subject_to_scp_and_explicit_deny() -> None:
    root = Principal.from_arn(f"arn:aws:iam::{A}:root")
    assert not run(
        root, "s3:GetObject", "arn:aws:s3:::b/k", resource_account=A, scps=[[scp(deny("s3:*"), allow("*"))]]
    ).allowed
    assert not run(
        root,
        "s3:GetObject",
        "arn:aws:s3:::b/k",
        resource_account=A,
        resource=[resource(deny("s3:*", "*", Principal="*"))],
    ).allowed


# --- NotPrincipal [NOTP] --------------------------------------------------------


def test_not_principal_deny_spares_listed_principal() -> None:
    obj = "arn:aws:s3:::b/k"
    res = resource(
        allow("s3:*", "*", Principal={"AWS": A}),
        deny("s3:*", "*", NotPrincipal={"AWS": [f"arn:aws:iam::{A}:user/alice", f"arn:aws:iam::{A}:root"]}),
    )
    ident = [identity(allow("s3:*"))]
    assert run(user("alice"), "s3:GetObject", obj, resource_account=A, resource=[res], identity=ident).allowed
    assert not run(user("bob"), "s3:GetObject", obj, resource_account=A, resource=[res], identity=ident).allowed


def test_not_principal_deny_always_hits_principal_with_boundary() -> None:
    # "The NotPrincipal element with a Deny effect will always deny any IAM principal that has a
    # permissions boundary policy attached, regardless of the values specified in NotPrincipal."
    obj = "arn:aws:s3:::b/k"
    res = resource(deny("s3:*", "*", NotPrincipal={"AWS": [f"arn:aws:iam::{A}:user/alice", f"arn:aws:iam::{A}:root"]}))
    r = run(
        user("alice"),
        "s3:GetObject",
        obj,
        resource_account=A,
        resource=[res],
        identity=[identity(allow("s3:*"))],
        boundary=boundary(allow("*")),
    )
    assert r.decision is Decision.EXPLICIT_DENY


def test_session_policy_without_session_principal_role_check() -> None:
    # Step 7 of [EVAL]: with a session policy that allows, a role session is allowed.
    r = run(
        role_session(),
        "s3:GetObject",
        "arn:aws:s3:::b/k",
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        session=[session(allow("s3:GetObject"))],
    )
    assert r.allowed
