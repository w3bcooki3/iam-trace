"""Rules the evaluator must follow for every policy, found or not by hand-written tests.

Each test states a rule of AWS's policy evaluation logic and checks it on random policies and
requests (see strategies.py). The rules come from AWS's documentation of the evaluation logic:
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

from __future__ import annotations

import random
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.model import Policy, PolicyType
from iamtrace.principals import Principal
from iamtrace.servicerules import resource_policy_required
from tests.property.strategies import (
    PRINCIPAL_ARNS,
    REQUEST_ACTIONS,
    REQUEST_RESOURCES,
    document,
    policies,
    requests_ctx,
    statements,
)

FULL = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def identity(doc: dict[str, Any], i: int = 0) -> Policy:
    return Policy.parse(doc, policy_id=f"identity{i}", policy_type=PolicyType.IDENTITY)


def boundary(doc: dict[str, Any]) -> Policy:
    return Policy.parse(doc, policy_id="boundary", policy_type=PolicyType.BOUNDARY)


def scp(doc: dict[str, Any], i: int = 0) -> Policy:
    return Policy.parse(doc, policy_id=f"scp{i}", policy_type=PolicyType.SCP)


@st.composite
def request(draw: st.DrawFn) -> Request:
    who = draw(st.sampled_from(PRINCIPAL_ARNS))
    principal = Principal.from_arn(who)
    tags = {"aws:PrincipalTag/team": "ops"} if draw(st.booleans()) else {}
    return Request(
        principal,
        draw(st.sampled_from(REQUEST_ACTIONS)),
        draw(st.sampled_from(REQUEST_RESOURCES)),
        resource_account=principal.account,
        context={**draw(requests_ctx()), **tags},
    )


def allowed(req: Request, ids: list[dict[str, Any]], **kw: Any) -> bool:
    return evaluate(req, PolicySet(identity=[identity(d, i) for i, d in enumerate(ids)], **kw)).allowed


@given(request(), st.lists(policies(), max_size=3))
def test_an_explicit_deny_of_the_action_always_wins(req: Request, ids: list[dict[str, Any]]) -> None:
    deny = document([{"Effect": "Deny", "Action": req.action, "Resource": "*"}])
    assert not allowed(req, [*ids, deny])


@given(request(), st.lists(policies(), max_size=3), statements(effect="Allow"))
def test_adding_an_allow_never_takes_access_away(
    req: Request, ids: list[dict[str, Any]], extra: dict[str, Any]
) -> None:
    if allowed(req, ids):
        assert allowed(req, [*ids, document([extra])])


@given(request(), st.lists(policies(), max_size=3), statements(effect="Deny"))
def test_adding_a_deny_never_grants_access(req: Request, ids: list[dict[str, Any]], extra: dict[str, Any]) -> None:
    if not allowed(req, ids):
        assert not allowed(req, [*ids, document([extra])])


@given(request(), st.lists(policies(), min_size=1, max_size=3), policies())
def test_a_permissions_boundary_only_restricts(req: Request, ids: list[dict[str, Any]], b: dict[str, Any]) -> None:
    if allowed(req, ids, boundary=boundary(b)):
        assert allowed(req, ids)


@given(request(), st.lists(policies(), min_size=1, max_size=3), st.lists(policies(), min_size=1, max_size=2))
def test_scps_only_restrict(req: Request, ids: list[dict[str, Any]], levels: list[dict[str, Any]]) -> None:
    scps = [[scp(FULL, 100 + i), scp(d, i)] for i, d in enumerate(levels)]
    if allowed(req, ids, scps=scps):
        assert allowed(req, ids)


@given(request(), st.lists(policies(), max_size=3))
def test_a_full_access_scp_and_boundary_change_nothing(req: Request, ids: list[dict[str, Any]]) -> None:
    plain = allowed(req, ids)
    assert allowed(req, ids, scps=[[scp(FULL)]]) == plain
    assert allowed(req, ids, boundary=boundary(FULL)) == plain


@given(request(), st.lists(policies(), min_size=1, max_size=3), st.randoms(use_true_random=False))
def test_statement_order_and_policy_grouping_do_not_matter(
    req: Request, ids: list[dict[str, Any]], rnd: random.Random
) -> None:
    before = allowed(req, ids)
    flat = [s for d in ids for s in d["Statement"]]
    rnd.shuffle(flat)
    assert allowed(req, [document(flat)]) == before  # one policy, shuffled
    assert allowed(req, [document([s]) for s in flat]) == before  # one policy per statement


@given(request(), st.lists(policies(), max_size=3))
def test_action_names_are_case_insensitive(req: Request, ids: list[dict[str, Any]]) -> None:
    before = allowed(req, ids)
    for variant in (req.action.upper(), req.action.lower()):
        r = Request(req.principal, variant, req.resource, resource_account=req.resource_account, context=req.context)
        assert allowed(r, ids) == before


@given(request())
def test_allow_everything_allows_everything_but_trust_and_key_policies(req: Request) -> None:
    # Role trust policies and KMS key policies must allow the principal too (AWS's
    # evaluation logic names them as the exceptions), so with no resource policy those deny.
    needs = resource_policy_required(req.action, req.resource)
    assert allowed(req, [FULL]) == (needs is None)


@given(request(), st.lists(policies(), max_size=2))
def test_a_trust_or_key_policy_allowing_the_principal_is_needed_and_enough(
    req: Request, ids: list[dict[str, Any]]
) -> None:
    if resource_policy_required(req.action, req.resource) is None:
        return
    who = req.principal.principal_arn
    rp = Policy.parse(
        document([{"Effect": "Allow", "Principal": {"AWS": who}, "Action": req.action, "Resource": "*"}]),
        policy_id="resource",
        policy_type=PolicyType.RESOURCE,
    )
    # Never without it, whatever the identity policies say.
    assert not allowed(req, [*ids, FULL])
    # With it and an identity Allow, allowed unless an identity Deny or a condition gets in the way.
    with_rp = evaluate(req, PolicySet(identity=[identity(FULL)], resource=[rp])).allowed
    assert with_rp


@given(request())
def test_no_policy_denies(req: Request) -> None:
    assert not allowed(req, [])


@given(request(), st.lists(policies(), max_size=3))
def test_the_trace_agrees_with_the_decision(req: Request, ids: list[dict[str, Any]]) -> None:
    r = evaluate(req, PolicySet(identity=[identity(d, i) for i, d in enumerate(ids)]))
    assert r.allowed == evaluate(req, PolicySet(identity=[identity(d, i) for i, d in enumerate(ids)])).allowed
    steps = {t.step: t.outcome for t in r.trace}
    if r.allowed:
        assert "deny" not in steps.values()
    explicit = [m for t in r.trace for m in t.matches if m.effect == "Deny"]
    if explicit:
        assert not r.allowed
