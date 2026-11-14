"""Core evaluation flow.

Source for the ordering: "How AWS enforcement code logic evaluates requests to allow or deny
access", https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
"""

from __future__ import annotations

from iamtrace import Decision
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

BUCKET = "arn:aws:s3:::bucket"
OBJ = "arn:aws:s3:::bucket/key"


def test_implicit_deny_by_default() -> None:
    r = run(user(), "s3:GetObject", OBJ, resource_account=A)
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "identity_policy"


def test_identity_allow() -> None:
    r = run(user(), "s3:GetObject", OBJ, resource_account=A, identity=[identity(allow("s3:GetObject", OBJ))])
    assert r.decision is Decision.ALLOW


def test_explicit_deny_wins_over_allow() -> None:
    r = run(
        user(), "s3:GetObject", OBJ, resource_account=A, identity=[identity(allow("s3:*"), deny("s3:GetObject", OBJ))]
    )
    assert r.decision is Decision.EXPLICIT_DENY
    assert r.deciding_step == "explicit_deny"
    assert r.trace[0].matches[0].effect == "Deny"


def test_explicit_deny_in_resource_policy_wins() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        resource=[resource(deny("s3:*", OBJ, Principal="*"))],
    )
    assert r.decision is Decision.EXPLICIT_DENY


def test_not_action_with_deny() -> None:
    # Deny everything except IAM reads: s3 is denied, iam:GetUser is not.
    ident = identity(allow("*"), deny({"NotAction": ["iam:Get*", "iam:List*"]}))
    assert run(user(), "s3:GetObject", OBJ, resource_account=A, identity=[ident]).decision is Decision.EXPLICIT_DENY
    assert run(user(), "iam:GetUser", "*", resource_account=A, identity=[ident]).decision is Decision.ALLOW


def test_not_resource() -> None:
    ident = identity(allow("s3:*", {"NotResource": "arn:aws:s3:::secret/*"}))
    assert run(user(), "s3:GetObject", OBJ, resource_account=A, identity=[ident]).allowed
    assert not run(user(), "s3:GetObject", "arn:aws:s3:::secret/x", resource_account=A, identity=[ident]).allowed


def test_condition_failure_means_statement_does_not_apply() -> None:
    ident = identity(allow("s3:*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
    assert not run(user(), "s3:GetObject", OBJ, resource_account=A, identity=[ident]).allowed
    assert run(
        user(), "s3:GetObject", OBJ, resource_account=A, identity=[ident], context={"aws:MultiFactorAuthPresent": True}
    ).allowed


def test_scp_must_allow() -> None:
    r = run(
        user(), "s3:GetObject", OBJ, resource_account=A, identity=[identity(allow("*"))], scps=[[scp(allow("ec2:*"))]]
    )
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "scp"


def test_scp_every_level_must_allow() -> None:
    # Root allows everything, the OU only allows ec2: s3 is denied.
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("*"))],
        scps=[[scp(allow("*"))], [scp(allow("ec2:*"))]],
    )
    assert r.decision is Decision.IMPLICIT_DENY


def test_scp_deny() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("*"))],
        scps=[[scp(allow("*"), deny("s3:*"))]],
    )
    assert r.decision is Decision.EXPLICIT_DENY


def test_scp_exempt_for_management_account() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("*"))],
        scps=[[scp(deny("s3:*"))]],
        scp_exempt=True,
    )
    assert r.allowed


def test_rcp_must_allow() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("*"))],
        rcps=[[rcp(allow("sqs:*", Principal="*"))]],
    )
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "rcp"


def test_rcp_ignored_for_unsupported_service() -> None:
    # RCPs apply only to the services AWS lists; iam is not one of them.
    r = run(
        user(),
        "iam:GetUser",
        "*",
        resource_account=A,
        identity=[identity(allow("*"))],
        rcps=[[rcp(deny("*", Principal="*"))]],
    )
    assert r.allowed


def test_boundary_intersects_identity() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        boundary=boundary(allow("ec2:*")),
    )
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "permissions_boundary"
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        boundary=boundary(allow("s3:Get*")),
    )
    assert r.allowed


def test_boundary_alone_grants_nothing() -> None:
    r = run(user(), "s3:GetObject", OBJ, resource_account=A, boundary=boundary(allow("*")))
    assert not r.allowed


def test_session_policy_intersects_identity() -> None:
    r = run(
        role_session(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        session=[session(allow("ec2:*"))],
    )
    assert r.decision is Decision.IMPLICIT_DENY
    assert r.deciding_step == "session_policy"


def test_session_policy_ignored_for_iam_user() -> None:
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        identity=[identity(allow("s3:*"))],
        session=[session(allow("ec2:*"))],
    )
    assert r.allowed
    assert any("session" in w for w in r.warnings)


def test_same_account_resource_policy_grants_on_its_own() -> None:
    # "If an action is allowed by an identity-based policy, a resource-based policy, or both,
    # then AWS allows the action."
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=A,
        resource=[resource(allow("s3:GetObject", OBJ, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))],
    )
    assert r.allowed
    assert r.deciding_step == "resource_policy"


def test_same_account_account_principal_delegates_to_identity() -> None:
    res = resource(allow("s3:GetObject", OBJ, Principal={"AWS": f"arn:aws:iam::{A}:root"}))
    assert not run(user(), "s3:GetObject", OBJ, resource_account=A, resource=[res]).allowed
    assert run(
        user(), "s3:GetObject", OBJ, resource_account=A, resource=[res], identity=[identity(allow("s3:GetObject"))]
    ).allowed


def test_cross_account_needs_both_sides() -> None:
    res = resource(allow("s3:GetObject", OBJ, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    # Resource side only.
    assert not run(user(), "s3:GetObject", OBJ, resource_account=B, resource=[res]).allowed
    # Identity side only.
    assert not run(user(), "s3:GetObject", OBJ, resource_account=B, identity=[identity(allow("s3:*"))]).allowed
    # Both.
    r = run(user(), "s3:GetObject", OBJ, resource_account=B, resource=[res], identity=[identity(allow("s3:*"))])
    assert r.allowed


def test_cross_account_account_principal_counts_for_resource_side() -> None:
    res = resource(allow("s3:GetObject", OBJ, Principal={"AWS": A}))
    r = run(user(), "s3:GetObject", OBJ, resource_account=B, resource=[res], identity=[identity(allow("s3:*"))])
    assert r.allowed


def test_cross_account_boundary_still_applies() -> None:
    res = resource(allow("s3:GetObject", OBJ, Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    r = run(
        user(),
        "s3:GetObject",
        OBJ,
        resource_account=B,
        resource=[res],
        identity=[identity(allow("s3:*"))],
        boundary=boundary(allow("ec2:*")),
    )
    assert not r.allowed


def test_every_decision_has_a_trace() -> None:
    r = run(user(), "s3:GetObject", OBJ, resource_account=A, identity=[identity(allow("s3:*"))])
    steps = [t.step for t in r.trace]
    assert steps[0] == "explicit_deny"
    assert "identity_policy" in steps
    assert r.trace[-1].step == r.deciding_step


def test_unknown_resource_account_assumed_same_with_warning() -> None:
    r = run(user(), "s3:GetObject", OBJ, identity=[identity(allow("s3:*"))])
    assert r.allowed
    assert any("resource account" in w for w in r.warnings)


def test_resource_account_from_arn() -> None:
    res = resource(allow("sqs:SendMessage", "*", Principal={"AWS": f"arn:aws:iam::{A}:user/alice"}))
    q = f"arn:aws:sqs:us-east-1:{B}:q"
    # Account comes from the ARN, so this is cross-account and needs identity too.
    assert not run(user(), "sqs:SendMessage", q, resource=[res]).allowed
