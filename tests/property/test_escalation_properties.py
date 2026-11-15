"""Rules the escalation analysis and fix plans must follow on every account.

Random small accounts (strategies.accounts) are analysed and changed, and the results compared:

- denying a principal everything leaves it no technique and no path;
- adding an Allow never removes a path to admin, and adding a Deny never adds one;
- the order of users, roles, policies and statements in the export changes nothing;
- a fix plan that says "verified" really leaves no open path when it is applied to the export
  here, independently of the code that made it: as Deny statements, as narrowed Allow
  statements, and as one SCP.
"""

from __future__ import annotations

import copy
import random
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from iamtrace.escalate import Environment, analyze
from iamtrace.fixplan import fix_plan
from iamtrace.model import Policy, PolicyType
from tests.property.strategies import PRINCIPAL_ARNS, accounts, document, examples, statements

FULL = document([{"Effect": "Allow", "Action": "*", "Resource": "*"}])


def env_of(export: dict[str, Any]) -> Environment:
    return Environment.from_auth_details(copy.deepcopy(export))


def reach(report: dict[str, Any]) -> set[str]:
    """Principals that are admin, or have an open path to admin (no MFA, network or time needed)."""
    out = {p["arn"] for p in report["principals"] if p["admin_equivalent"] and not p.get("admin_requires")}
    return out | {p["start"] for p in report["paths"] if p["open"]}


def paths_of(report: dict[str, Any]) -> set[tuple[Any, ...]]:
    return {(p["start"], p["end"], p["open"], tuple(s["technique"] for s in p["steps"])) for p in report["paths"]}


def entity(export: dict[str, Any], arn: str) -> dict[str, Any]:
    for key in ("UserDetailList", "RoleDetailList", "GroupDetailList"):
        for e in export[key]:
            if e["Arn"] == arn:
                return e
    raise KeyError(arn)


def add_inline(export: dict[str, Any], arn: str, doc: dict[str, Any], name: str = "added") -> dict[str, Any]:
    out = copy.deepcopy(export)
    e = entity(out, arn)
    key = {"user": "UserPolicyList", "role": "RolePolicyList", "group": "GroupPolicyList"}[
        arn.split(":")[5].split("/")[0]
    ]
    e[key] = [*(e.get(key) or []), {"PolicyName": name, "PolicyDocument": doc}]
    return out


# --- the rules ------------------------------------------------------------------------------


@examples(80, 1000)
@given(accounts(), st.sampled_from(PRINCIPAL_ARNS))
def test_a_principal_denied_everything_has_no_technique_and_no_path(export: dict[str, Any], who: str) -> None:
    denied = add_inline(export, who, document([{"Effect": "Deny", "Action": "*", "Resource": "*"}]))
    r = analyze(env_of(denied), start=who)
    me = r["principals"][0]
    assert not me["admin_equivalent"]
    assert me["techniques"] == []
    assert r["paths"] == []


@examples(40, 600)
@given(accounts(), st.sampled_from(PRINCIPAL_ARNS), statements(effect="Allow"))
def test_adding_an_allow_never_removes_a_path(export: dict[str, Any], who: str, extra: dict[str, Any]) -> None:
    before = reach(analyze(env_of(export)))
    after = reach(analyze(env_of(add_inline(export, who, document([extra])))))
    assert before <= after, f"lost: {sorted(before - after)}"


@examples(40, 600)
@given(accounts(), st.sampled_from(PRINCIPAL_ARNS), statements(effect="Deny"))
def test_adding_a_deny_never_adds_a_path(export: dict[str, Any], who: str, extra: dict[str, Any]) -> None:
    before = reach(analyze(env_of(export)))
    after = reach(analyze(env_of(add_inline(export, who, document([extra])))))
    assert after <= before, f"gained: {sorted(after - before)}"


@examples(40, 600)
@given(accounts(), st.randoms(use_true_random=False))
def test_the_order_of_the_export_changes_nothing(export: dict[str, Any], rnd: random.Random) -> None:
    shuffled = copy.deepcopy(export)
    for key in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies"):
        rnd.shuffle(shuffled[key])
    for e in shuffled["UserDetailList"] + shuffled["RoleDetailList"] + shuffled["GroupDetailList"]:
        for key in ("UserPolicyList", "RolePolicyList", "GroupPolicyList"):
            for p in e.get(key) or []:
                rnd.shuffle(p["PolicyDocument"]["Statement"])
    a, b = analyze(env_of(export)), analyze(env_of(shuffled))
    assert reach(a) == reach(b)
    assert {p["arn"]: p["admin_equivalent"] for p in a["principals"]} == {
        p["arn"]: p["admin_equivalent"] for p in b["principals"]
    }
    # The same principals reach the same admins; which equally short route is shown may differ.
    assert {(p[0], p[1], p[2], len(p[3])) for p in paths_of(a)} == {(p[0], p[1], p[2], len(p[3])) for p in paths_of(b)}


# --- fix plans, applied independently ---------------------------------------------------------


def apply_denies(export: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    out = export
    for i, (arn, doc) in enumerate(sorted(plan["policies"].items())):
        out = add_inline(out, arn, doc, name=f"iam-trace-fix-{i}")
    return out


def apply_narrowed(export: dict[str, Any], edits: list[dict[str, Any]]) -> dict[str, Any]:
    out = copy.deepcopy(export)
    for e in edits:
        pid, doc = e["policy"], e.get("document")
        if pid.endswith(" trust policy"):
            entity(out, pid.removesuffix(" trust policy"))["AssumeRolePolicyDocument"] = doc
        elif " inline " in pid:
            owner, name = pid.split(" inline ", 1)
            ent = entity(out, owner)
            key = next(k for k in ("UserPolicyList", "RolePolicyList", "GroupPolicyList") if k in ent)
            if e.get("delete"):
                ent[key] = [p for p in ent[key] if p["PolicyName"] != name]
            else:
                next(p for p in ent[key] if p["PolicyName"] == name)["PolicyDocument"] = doc
        else:  # a customer managed policy: deleting it detaches it everywhere
            if e.get("delete"):
                out["Policies"] = [p for p in out["Policies"] if p["Arn"] != pid]
                for ent in out["UserDetailList"] + out["RoleDetailList"] + out["GroupDetailList"]:
                    ent["AttachedManagedPolicies"] = [
                        a for a in ent["AttachedManagedPolicies"] if a["PolicyArn"] != pid
                    ]
            else:
                pol = next(p for p in out["Policies"] if p["Arn"] == pid)
                next(v for v in pol["PolicyVersionList"] if v["IsDefaultVersion"])["Document"] = doc
    return out


def open_paths(report: dict[str, Any], roots: set[str]) -> list[dict[str, Any]]:
    return [p for p in report["paths"] if p["open"] and p["start"] in roots]


@examples(20, 300)
@given(accounts())
def test_a_verified_fix_plan_leaves_no_open_path(export: dict[str, Any]) -> None:
    env = env_of(export)
    everyone = analyze(env)
    plan = fix_plan(env, everyone=everyone)
    if plan["status"] != "fixed":
        return
    assert plan["verified"]
    roots = {p["start"] for p in everyone["paths"] if p["open"]}

    after = analyze(env_of(apply_denies(export, plan)))
    assert open_paths(after, roots) == [], "Deny statements"

    narrowed = plan.get("narrowed") or {}
    if narrowed.get("verified"):
        after = analyze(env_of(apply_narrowed(export, narrowed["edits"])))
        assert open_paths(after, roots) == [], "narrowed Allow statements"

    scp_plan = plan.get("scp") or {}
    if scp_plan.get("verified"):
        full = Policy.parse(FULL, policy_id="FullAWSAccess", policy_type=PolicyType.SCP)
        fix = Policy.parse(scp_plan["policy"], policy_id="iam-trace-fix", policy_type=PolicyType.SCP)
        after = analyze(env_of(export), scps=[[full, fix]])
        assert open_paths(after, roots) == [], "SCP"


@examples(15, 200)
@given(accounts())
def test_a_fix_plan_only_denies_what_it_names(export: dict[str, Any]) -> None:
    """Principals the plan does not change keep every permission they had."""
    env = env_of(export)
    plan = fix_plan(env)
    if plan["status"] != "fixed":
        return
    changed = set(plan["policies"])
    before = analyze(env)
    after = analyze(env_of(apply_denies(export, plan)))
    for b, a in zip(before["principals"], after["principals"], strict=True):
        if b["arn"] not in changed and not any(c in changed for c in entity(export, b["arn"]).get("GroupList", [])):
            # Untouched principals keep their own techniques (targets may shrink: a target's own
            # permissions can change, not the principal's).
            assert {t["id"] for t in a["techniques"]} <= {t["id"] for t in b["techniques"]}
