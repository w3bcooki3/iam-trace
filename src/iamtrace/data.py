"""Data paths: who can read, write or delete the data in an S3 bucket, or use a KMS key.

Escalation analysis asks who can become admin. For data, the question is narrower and often the
one that matters: who can read the customer bucket, by any route?

Reading an object takes every permission involved, from every policy involved:

- s3:GetObject on the object, allowed by the principal's policies and not denied by the bucket
  policy (or allowed by the bucket policy alone, for a principal in the same account);
- if the bucket encrypts with a customer managed KMS key, kms:Decrypt on that key, which the
  key policy has to allow (directly, or by trusting the account so IAM policies can grant it).

So a role with s3:GetObject but no use of the key can fetch the objects and still not read them;
it is listed as blocked by the key. A bucket policy that is public with objects encrypted under a
key outsiders cannot use is not public in practice, and S3 Block Public Access
(RestrictPublicBuckets) stops a public bucket policy altogether. Both are reported.

Each principal is checked with the same evaluator as `can`; principals that can reach one with
access through a confirmed escalation route are listed with the route (iamtrace.whocan). Outside
principals are probed as `entry` does: a principal in an unrelated account with allow-all
identity policies (its account controls those), and each account the bucket policy names.

Resources come from the inventory (iamtrace.inventory: `iam-trace inventory collect` records
buckets with their policy, default encryption key and Block Public Access, and keys with their
key policy). A bucket or key that is not in the inventory is analysed without a resource policy.
"""

from __future__ import annotations

from typing import Any

from iamtrace.escalate import Environment, analyze
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.inventory import DATA_KINDS, Resource, kind_of
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.principals import Principal
from iamtrace.whocan import escalation_routes, who_can

# access -> (action on an S3 object, action on the bucket's KMS key, action on a KMS key itself)
ACCESS: dict[str, tuple[str, str | None, str]] = {
    "read": ("s3:GetObject", "kms:Decrypt", "kms:Decrypt"),
    "write": ("s3:PutObject", "kms:GenerateDataKey", "kms:Encrypt"),
    "delete": ("s3:DeleteObject", None, "kms:ScheduleKeyDeletion"),
}
PROBE_OBJECT = "iam-trace-probe-object"
STRANGER = "arn:aws:iam::999999999999:role/iam-trace-probe"

_ALLOW_ALL = Policy.parse(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    policy_id="probe identity",
    policy_type=PolicyType.IDENTITY,
)


def _resource_policy(res: Resource | None) -> Policy | None:
    if res is None or res.policy is None:
        return None
    try:
        return Policy.parse(res.policy, policy_id=f"{res.arn} resource policy", policy_type=PolicyType.RESOURCE)
    except PolicyError:
        return None


def _account(env: Environment) -> str:
    return next(iter(env.nodes.values())).account if env.nodes else "111122223333"


def requirements(env: Environment, arn: str, access: str) -> tuple[list[tuple[str, str, Policy | None]], list[str]]:
    """The (action, resource, resource policy) checks one access needs, and notes."""
    if access not in ACCESS:
        raise ValueError(f"access must be one of {', '.join(ACCESS)}")
    s3_action, key_action, own_action = ACCESS[access]
    kind = kind_of(arn)
    inv = env.resources
    res = inv.find(arn) if inv is not None else None
    notes: list[str] = []
    if kind not in DATA_KINDS:
        raise ValueError("data paths cover S3 buckets (arn:aws:s3:::name) and KMS keys (arn:aws:kms:...:key/id)")
    if res is None:
        notes.append(
            "The resource is not in the inventory, so its resource policy is unknown and only identity "
            "policies were checked."
        )
    if kind == "kms-key":
        return [(own_action, arn, _resource_policy(res))], notes
    reqs: list[tuple[str, str, Policy | None]] = [(s3_action, f"{arn}/{PROBE_OBJECT}", _resource_policy(res))]
    if res is not None and res.kms_key and key_action:
        key = res.kms_key
        key_res = inv.find(key) if inv is not None else None
        if not key.startswith("arn:"):
            notes.append(
                f"The bucket encrypts with {key}, which is not a key ARN (an alias or the AWS managed key); "
                "its key policy is not checked."
            )
        else:
            if key_res is None:
                notes.append(f"The bucket's KMS key {key} is not in the inventory; its key policy is unknown.")
            reqs.append((key_action, key, _resource_policy(key_res)))
    return reqs, notes


def _probe(env: Environment, caller: str, reqs: list[tuple[str, str, Policy | None]]) -> list[bool]:
    who = Principal.from_arn(caller)
    out = []
    for action, resource, pol in reqs:
        req = Request(who, action, resource, resource_account=_account(env))
        out.append(evaluate(req, PolicySet(identity=[_ALLOW_ALL], resource=[pol] if pol else [])).allowed)
    return out


def data_access(
    env: Environment,
    arn: str,
    access: str = "read",
    *,
    scps: list[list[Policy]] | None = None,
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Who can read (write, delete) the data in a bucket or use a key: directly, through
    escalation, and from outside the account."""
    reqs, notes = requirements(env, arn, access)
    report = report or analyze(env, scps=scps)
    per = [
        who_can(env, action, resource, scps=scps, resource_policy=pol, report=report) for action, resource, pol in reqs
    ]
    sets = [{d["principal"]: d for d in r["direct"]} for r in per]
    common = set(sets[0]).intersection(*sets[1:]) if sets else set()
    direct = [
        {**sets[0][a], "granted_by": sorted({g for s in sets for g in s[a]["granted_by"]})} for a in sorted(common)
    ]
    blocked = [sets[0][a] for a in sorted(set(sets[0]) - common)] if len(sets) > 1 else []
    via = escalation_routes(env, report, common)
    admins = {p["arn"] for p in report["principals"] if p["admin_equivalent"] and not p.get("admin_requires")}

    # Outside the account: anyone, and each account the resource policy names.
    stranger = _probe(env, STRANGER, reqs)
    res = env.resources.find(arn) if env.resources is not None else None
    pab = (res.public_access_block or {}) if res is not None else {}
    outside: list[dict[str, Any]] = []
    public = all(stranger)
    if stranger[0] and pab.get("RestrictPublicBuckets"):
        notes.append(
            "The bucket policy grants public access, but S3 Block Public Access (RestrictPublicBuckets) "
            "limits it to AWS services and principals in this account."
        )
        public = False
    elif stranger[0] and not public:
        notes.append(
            "The bucket policy grants public access, but the objects are encrypted with a KMS key that "
            "principals outside the account cannot use. Objects stored without that key would still be public."
        )
    if public:
        outside.append(
            {
                "principal": "*",
                "what": "anyone: the resource policy allows principals in any AWS account",
                "statement": next((o["statement"] for o in per[0]["outside"] if o["principal"] == "*"), ""),
            }
        )
    restricted = bool(pab.get("RestrictPublicBuckets")) and stranger[0]
    own = _account(env)
    for o in per[0]["outside"]:
        if o["kind"] != "AWS" or o["principal"] == "*" or restricted:
            continue
        acct = o["principal"].split(":")[4] if o["principal"].startswith("arn:") else o["principal"]
        if acct == own:
            continue  # the account itself (its root delegates to IAM policies): checked above, not outside
        caller = (
            o["principal"]
            if ":root" not in o["principal"] and o["principal"].startswith("arn:")
            else (f"arn:aws:iam::{acct}:role/iam-trace-probe")
        )
        if all(_probe(env, caller, reqs)):
            outside.append({"principal": o["principal"], "what": o["what"], "statement": o["statement"]})
    services = [
        {"principal": o["principal"], "statement": o["statement"]} for o in per[0]["outside"] if o["kind"] == "Service"
    ]
    return {
        "resource": arn,
        "kind": kind_of(arn),
        "access": access,
        "requires": [a for a, _, _ in reqs],
        "direct": direct,
        "direct_admins": sum(1 for d in direct if d["principal"] in admins),
        "via": via,
        "blocked_by_key": blocked,
        "outside": outside,
        "services": services,
        "public": public,
        "checked": len(env.nodes),
        "notes": notes,
    }


def _rating(read: dict[str, Any], write: dict[str, Any]) -> str:
    if read["public"] or write["public"]:
        return "Critical"
    if read["outside"] or write["outside"]:
        return "High"
    if any(v["open"] for v in read["via"]) or any(v["open"] for v in write["via"]):
        return "Medium"
    return "Low"


def data_exposure(
    env: Environment, *, scps: list[list[Policy]] | None = None, report: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Every bucket and key in the inventory: who can read and write it, worst first."""
    inv = env.resources
    if inv is None:
        return {"resources": [], "collected": [], "notes": ["No inventory: run iam-trace inventory collect."]}
    report = report or analyze(env, scps=scps)
    rows = []
    for res in [r for r in inv.resources if r.kind in DATA_KINDS]:
        read = data_access(env, res.arn, "read", scps=scps, report=report)
        write = data_access(env, res.arn, "write", scps=scps, report=report)

        def counts(r: dict[str, Any]) -> dict[str, Any]:
            return {
                "direct": len(r["direct"]),
                "admins": r["direct_admins"],
                "via": len(r["via"]),
                "via_open": sum(1 for v in r["via"] if v["open"]),
                "outside": [o["principal"] for o in r["outside"]],
                "public": r["public"],
                "blocked_by_key": len(r["blocked_by_key"]),
            }

        rows.append(
            {
                "resource": res.arn,
                "kind": res.kind,
                "encrypted_with": res.kms_key,
                "has_policy": res.policy is not None,
                "read": counts(read),
                "write": counts(write),
                "rating": _rating(read, write),
                "notes": sorted(set(read["notes"] + write["notes"])),
            }
        )
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    def rank(r: dict[str, Any]) -> tuple[int, int, str]:
        return (order[str(r["rating"])], -(int(r["read"]["direct"]) + int(r["read"]["via"])), str(r["resource"]))

    rows.sort(key=rank)
    collected = sorted(k for k in inv.collected if k in DATA_KINDS)
    notes = [] if collected else ["The inventory has no S3 buckets or KMS keys: collect them with inventory collect."]
    return {"resources": rows, "collected": collected, "notes": notes}


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def data_access_text(r: dict[str, Any]) -> str:
    lines = [
        f"Who can {r['access']} {r['resource']}",
        f"Needs: {' and '.join(r['requires'])}. Checked {r['checked']} principals: {len(r['direct'])} directly"
        f" ({r['direct_admins']} admin-equivalent), {len(r['via'])} through escalation.",
    ]
    if r["public"]:
        lines.append("PUBLIC: principals in any AWS account can do this.")
    for n in r["notes"]:
        lines.append(f"Note: {n}")
    if r["direct"]:
        lines.append("")
        lines.append("Directly")
        for d in r["direct"]:
            lines.append(f"  {_short(d['principal'])}")
    if r["via"]:
        lines.append("")
        lines.append("Through escalation")
        for v in r["via"]:
            chain = " -> ".join(
                [_short(v["principal"])] + [f"[{s['technique']}] {_short(s['to'])}" for s in v["steps"]]
            )
            if v.get("requires"):
                chain += "  (only when " + "; ".join(x["text"] for x in v["requires"]) + ")"
            lines.append(f"  {chain}")
    if r["blocked_by_key"]:
        lines.append("")
        lines.append(f"Allowed {r['requires'][0]} but not {r['requires'][1]} on the bucket's KMS key")
        for d in r["blocked_by_key"]:
            lines.append(f"  {_short(d['principal'])}")
    if r["outside"]:
        lines.append("")
        lines.append("Outside the account")
        for o in r["outside"]:
            lines.append(f"  {o['principal']}: {o['what']} ({o['statement']})")
    return "\n".join(lines) + "\n"


def data_exposure_text(x: dict[str, Any]) -> str:
    rows = x["resources"]
    if not rows:
        return "\n".join(x["notes"] or ["No S3 buckets or KMS keys in the inventory."]) + "\n"
    lines = [f"{len(rows)} data resource{'s' if len(rows) != 1 else ''}, worst first.", ""]
    for r in rows:
        rd, wr = r["read"], r["write"]
        who = f"read: {rd['direct']} directly, {rd['via']} through escalation; write: {wr['direct']} + {wr['via']}"
        out = rd["outside"] or wr["outside"]
        lines.append(f"{r['rating']:<8} {_short(r['resource'])}")
        lines.append(f"         {who}" + (f"; outside: {', '.join(out)}" if out else ""))
        if r["encrypted_with"]:
            lines.append(f"         encrypted with {r['encrypted_with']}")
        for n in r["notes"]:
            lines.append(f"         {n}")
    return "\n".join(lines) + "\n"
