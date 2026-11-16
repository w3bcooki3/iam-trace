"""Trimming unused services never adds access and never takes away what it should keep."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.model import Policy, PolicyType
from iamtrace.principals import Principal
from iamtrace.usage import trim_statement
from tests.property.strategies import REQUEST_ACTIONS, REQUEST_RESOURCES, document, requests_ctx, statements

SERVICES = sorted({a.split(":")[0] for a in REQUEST_ACTIONS})
USER = Principal.from_arn("arn:aws:iam::111122223333:user/u0")


def allowed(sts: list[dict[str, Any]], action: str, resource: str, ctx: dict[str, Any]) -> bool:
    if not sts:
        return False
    pol = Policy.parse(document(sts), policy_id="p", policy_type=PolicyType.IDENTITY)
    req = Request(USER, action, resource, resource_account="111122223333", context=ctx)
    return evaluate(req, PolicySet(identity=[pol])).allowed


@given(
    st.lists(statements(), min_size=1, max_size=3),
    st.sets(st.sampled_from(SERVICES), min_size=1),
    st.sampled_from(REQUEST_ACTIONS),
    st.sampled_from(REQUEST_RESOURCES),
    requests_ctx(),
)
def test_trimming_only_takes_away_unused_services(
    sts: list[dict[str, Any]], unused: set[str], action: str, resource: str, ctx: dict[str, Any]
) -> None:
    trimmed = [out for s in sts for out in trim_statement(s, unused)[0]]
    before, after = allowed(sts, action, resource, ctx), allowed(trimmed, action, resource, ctx)
    assert not after or before, "trimming allowed something new"
    service = action.split(":")[0].lower()
    if service not in unused or action.lower() == "iam:passrole":
        assert after == before, "trimming took away a service in use (or iam:PassRole)"
    else:
        assert not after, "an unused service is still allowed"
