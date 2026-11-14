"""What would change the answer: every suggestion must be the smallest change, and verified."""

from __future__ import annotations

import json
from typing import Any

from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.model import Policy, PolicyType
from iamtrace.principals import Principal
from iamtrace.whatif import what_if, what_if_text

ALICE = "arn:aws:iam::111122223333:user/alice"
OBJ = "arn:aws:s3:::reports/q3.csv"


def pol(statements: list[dict[str, Any]], ptype: PolicyType = PolicyType.IDENTITY, pid: str = "p") -> Policy:
    return Policy.from_json(
        json.dumps({"Version": "2012-10-17", "Statement": statements}), policy_id=pid, policy_type=ptype
    )


def req(action: str = "s3:GetObject", resource: str = OBJ, context: dict[str, Any] | None = None, **kw: Any) -> Request:
    return Request(Principal.from_arn(ALICE), action, resource, context=context or {}, **kw)


ALLOW_GET = {"Sid": "Read", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}


def fixes(report: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [f for f in report["fixes"] if f["kind"] == kind]


# --- denied: the missing Allows ---------------------------------------------------------


def test_missing_identity_allow_is_added_and_verified() -> None:
    r = what_if(req(), PolicySet(identity=[pol([{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}])]))
    (fix,) = fixes(r, "add_allow")
    assert fix["verified"]
    assert fix["add"] == [
        {
            "layer": "identity_policy",
            "where": "the identity-based policies",
            "statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJ},
        }
    ]


def test_every_refusing_layer_gets_an_allow_in_order() -> None:
    boundary = pol([{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}], PolicyType.BOUNDARY, "boundary")
    scp = pol([{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}], PolicyType.SCP, "scp")
    r = what_if(req(), PolicySet(boundary=boundary, scps=[[scp]]))
    (fix,) = fixes(r, "add_allow")
    assert [a["layer"] for a in fix["add"]] == ["scp", "identity_policy", "permissions_boundary"]
    assert fix["verified"]


def test_cross_account_needs_a_resource_policy_naming_the_caller() -> None:
    r = what_if(req(resource_account="444455556666"), PolicySet(identity=[pol([ALLOW_GET])]))
    (fix,) = fixes(r, "add_allow")
    assert fix["verified"]
    assert fix["add"][0]["layer"] == "resource_policy"
    assert fix["add"][0]["statement"]["Principal"] == {"AWS": ALICE}


def test_role_session_is_named_by_its_role() -> None:
    session = Principal.from_arn(
        "arn:aws:sts::111122223333:assumed-role/app/i-123", role_arn="arn:aws:iam::111122223333:role/app"
    )
    request = Request(session, "s3:GetObject", OBJ, resource_account="444455556666")
    r = what_if(request, PolicySet(identity=[pol([ALLOW_GET])]))
    (fix,) = fixes(r, "add_allow")
    assert fix["add"][0]["statement"]["Principal"] == {"AWS": "arn:aws:iam::111122223333:role/app"}


# --- denied: an explicit Deny ------------------------------------------------------------


def test_conditional_deny_suggests_the_context_value_and_removing_it() -> None:
    deny = {
        "Sid": "TLS",
        "Effect": "Deny",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    r = what_if(req(context={"aws:SecureTransport": "false"}), PolicySet(identity=[pol([ALLOW_GET, deny])]))
    (ctx,) = fixes(r, "context")
    assert ctx["context"] == {"aws:SecureTransport": "true"} and ctx["verified"]
    (rm,) = fixes(r, "remove_deny")
    assert rm["verified"] and rm["statements"] == [{"policy": "p", "statement": "TLS"}] and rm["add"] == []


def test_deny_that_hides_a_missing_allow_says_both() -> None:
    deny = {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
    r = what_if(req(), PolicySet(identity=[pol([deny])]))
    (rm,) = fixes(r, "remove_deny")
    assert rm["verified"]
    assert [a["layer"] for a in rm["add"]] == ["identity_policy"]
    assert fixes(r, "context") == []


# --- denied: near misses ------------------------------------------------------------------


def test_near_miss_on_resource() -> None:
    near = {"Sid": "Other", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::archive/*"}
    r = what_if(req(), PolicySet(identity=[pol([near])]))
    (miss,) = r["near_misses"]
    assert miss["statement"] == "Other" and "arn:aws:s3:::archive/*" in miss["reason"]


def test_near_miss_on_condition_suggests_a_value_inside_the_range() -> None:
    near = {**ALLOW_GET, "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
    r = what_if(req(context={"aws:SourceIp": "203.0.113.5"}), PolicySet(identity=[pol([near])]))
    assert "aws:SourceIp" in r["near_misses"][0]["reason"]
    (ctx,) = fixes(r, "context")
    assert ctx["context"] == {"aws:SourceIp": "10.0.0.1"} and ctx["verified"]


# --- allowed: what it depends on -----------------------------------------------------------


def test_single_grant_is_critical() -> None:
    r = what_if(req(), PolicySet(identity=[pol([ALLOW_GET])]))
    assert r["decision"] == "Allow"
    assert [d["title"] for d in r["depends_on"] if d["kind"] == "statement"] == ["p / Read"]


def test_two_grants_are_redundant() -> None:
    other = {"Sid": "All", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}
    r = what_if(req(), PolicySet(identity=[pol([ALLOW_GET, other])]))
    kinds = [d["kind"] for d in r["depends_on"]]
    assert kinds == ["redundant"]
    assert "Removing any one" in r["depends_on"][0]["detail"]


def test_allow_depends_on_a_context_key() -> None:
    allow = {**ALLOW_GET, "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    r = what_if(req(context={"aws:MultiFactorAuthPresent": "true"}), PolicySet(identity=[pol([allow])]))
    ctx = [d for d in r["depends_on"] if d["kind"] == "context"]
    assert ctx[0]["title"] == "aws:MultiFactorAuthPresent = true"
    assert "no Allow would apply" in ctx[0]["detail"]


def test_guardrail_deny_that_would_start_to_apply() -> None:
    deny = {
        "Sid": "TLS",
        "Effect": "Deny",
        "Action": "s3:*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }
    r = what_if(req(context={"aws:SecureTransport": "true"}), PolicySet(identity=[pol([ALLOW_GET, deny])]))
    ctx = [d for d in r["depends_on"] if d["kind"] == "context"]
    assert ctx and "a Deny would apply (p / TLS)" in ctx[0]["detail"]


def test_keys_aws_sets_itself_are_never_suggested() -> None:
    allow = {**ALLOW_GET, "Condition": {"StringEquals": {"aws:PrincipalAccount": "111122223333"}}}
    r = what_if(req(), PolicySet(identity=[pol([allow])]))
    assert not [d for d in r["depends_on"] if d["kind"] == "context"]


# --- every suggestion really works ---------------------------------------------------------


def test_suggested_statements_allow_the_request_when_applied() -> None:
    """Apply the suggestion by hand, the way a person would, and evaluate again."""
    request = req(resource_account="444455556666")
    ps = PolicySet(identity=[pol([{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}])])
    (fix,) = fixes(what_if(request, ps), "add_allow")
    identity = list(ps.identity)
    resource = []
    for a in fix["add"]:
        if a["layer"] == "identity_policy":
            identity.append(pol([a["statement"]], pid="added"))
        elif a["layer"] == "resource_policy":
            resource.append(pol([a["statement"]], PolicyType.RESOURCE, "bucket"))
    assert evaluate(request, PolicySet(identity=identity, resource=resource)).allowed


def test_text_rendering() -> None:
    r = what_if(req(), PolicySet())
    text = what_if_text(r)
    assert "What would change this" in text and '"Action": "s3:GetObject"' in text
