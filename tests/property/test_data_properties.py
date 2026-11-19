"""Properties of data paths over random roles, resource policies and keys.

Whatever the policies say:

- a principal listed as having access is allowed every permission the access needs, checked one by
  one with the evaluator (so the merge across alternatives and key permissions is right);
- a principal that is allowed every permission is listed (nothing is lost);
- nobody is both listed and blocked by the key, and the blocked ones are allowed the first
  permission;
- the account itself is never "outside", and "public" means the first outside entry is "*".
"""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from iamtrace.data import SERVICES, data_access, requirements
from iamtrace.escalate import Environment
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.inventory import load_inventory

from .strategies import examples

A = "111122223333"
OTHER = "444455556666"
R = "eu-west-1"
KEY = f"arn:aws:kms:{R}:{A}:key/k"
RESOURCES = {
    "s3-bucket": "arn:aws:s3:::data",
    "secretsmanager-secret": f"arn:aws:secretsmanager:{R}:{A}:secret:s-AbCdEf",
    "dynamodb-table": f"arn:aws:dynamodb:{R}:{A}:table/t",
    "sns-topic": f"arn:aws:sns:{R}:{A}:topic",
    "sqs-queue": f"arn:aws:sqs:{R}:{A}:queue",
}
ACTIONS = sorted({a for s in SERVICES.values() for acts, keys in s.access.values() for a in (*acts, *keys)})
PATTERNS = [*ACTIONS, "*", "kms:*", "s3:*", "sqs:*", "secretsmanager:Get*", "dynamodb:*Item"]
ROLES = ["r0", "r1", "r2", "r3"]


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{A}:role/{name}"


statement = st.fixed_dictionaries(
    {
        "Effect": st.sampled_from(["Allow", "Allow", "Deny"]),
        "Action": st.lists(st.sampled_from(PATTERNS), min_size=1, max_size=3),
        "Resource": st.sampled_from(["*", KEY, *RESOURCES.values(), "arn:aws:s3:::data/*"]),
    }
)
principal = st.sampled_from(["*", f"arn:aws:iam::{A}:root", f"arn:aws:iam::{OTHER}:root", *map(role_arn, ROLES)])
resource_statement = st.fixed_dictionaries(
    {
        "Effect": st.sampled_from(["Allow", "Allow", "Deny"]),
        "Principal": principal.map(lambda p: p if p == "*" else {"AWS": p}),
        "Action": st.lists(st.sampled_from(PATTERNS), min_size=1, max_size=3),
        "Resource": st.just("*"),
    }
)


def doc(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


@st.composite
def setups(draw: Any) -> tuple[Environment, str, str]:
    kind = draw(st.sampled_from(sorted(RESOURCES)))
    arn = RESOURCES[kind]
    roles = [
        {
            "RoleName": name,
            "Arn": role_arn(name),
            "AssumeRolePolicyDocument": doc([]),
            "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(draw(st.lists(statement, max_size=3)))}],
            "AttachedManagedPolicies": [],
        }
        for name in ROLES
    ]
    res: dict[str, Any] = {"Arn": arn}
    if draw(st.booleans()):
        res["Policy"] = doc(draw(st.lists(resource_statement, min_size=1, max_size=3)))
    key = draw(st.sampled_from([None, KEY, f"alias/aws/{SERVICES[kind].name}"]))
    resources = [res]
    if key:
        res["KmsKey"] = key
    if key == KEY:
        resources.append({"Arn": KEY, "Policy": doc(draw(st.lists(resource_statement, min_size=1, max_size=3)))})
    env = Environment.from_auth_details(
        {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )
    env.resources = load_inventory({"Version": 1, "Collected": [kind, "kms-key"], "Resources": resources}, env)
    return env, arn, draw(st.sampled_from(["read", "write", "delete"]))


def allowed(env: Environment, who: str, need: Any) -> bool:
    node = env.nodes[who]
    ps = PolicySet(identity=node.policies, resource=[need.policy] if need.policy else [])
    acct = need.resource.split(":")[4] or A
    return any(
        evaluate(Request(node.caller(), a, need.resource, resource_account=acct, context=need.context(A)), ps).allowed
        for a in need.actions
    )


@examples(60, 600)
@given(setups())
def test_listed_exactly_when_every_permission_is_allowed(setup: tuple[Environment, str, str]) -> None:
    env, arn, access = setup
    r = data_access(env, arn, access)
    needs = requirements(env, arn, access).needs
    direct = {d["principal"] for d in r["direct"]}
    blocked = {d["principal"] for d in r["blocked_by_key"]}
    for who in env.nodes:
        each = [allowed(env, who, n) for n in needs]
        assert (who in direct) == all(each), (who, each)
        assert (who in blocked) == (each[0] and not all(each)), (who, each)
    assert not direct & blocked
    for o in r["outside"]:
        assert A not in o["principal"]
    if r["public"]:
        assert r["outside"][0]["principal"] == "*"
