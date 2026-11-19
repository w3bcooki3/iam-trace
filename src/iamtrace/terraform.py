"""Terraform plans: review IAM changes before they are applied.

Input is the JSON that `terraform show -json plan.out` writes. Every IAM-relevant document the
plan creates, updates, replaces or deletes is extracted:

- aws_iam_policy (managed), aws_iam_role (trust policy and inline_policy blocks),
  aws_iam_role_policy, aws_iam_user_policy, aws_iam_group_policy (inline),
- aws_s3_bucket_policy and aws_kms_key (resource policies).

Each one is reviewed like a changed policy file in a pull request (iamtrace.pr_review): a
semantic diff, the escalation techniques the new version allows that the old one did not, and
the Policy check findings it introduces. A document Terraform will only know at apply time
(after_unknown) is reported as such, never guessed.

With the account export (`--auth-details`), the plan is also applied to a copy of it: roles,
users and groups created or deleted, inline policies, managed policies and their attachments
(including a policy created in the same plan, found through the configuration's references),
group membership. Both versions of the account are analysed, and the review says what the change
does to the account: new and removed paths to admin, new admin-equivalent principals, new and
removed entry points. That is the question a reviewer actually has: does this pull request let
anyone become admin who could not before?
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from iamtrace.catalog import Catalog
from iamtrace.diff import md_code, md_text
from iamtrace.entry import entry_points
from iamtrace.escalate import Environment, analyze
from iamtrace.pr_review import review_file

MARKER = "<!-- iam-trace-terraform -->"
ACTIONS: dict[tuple[str, ...], str] = {("create",): "create", ("update",): "update", ("delete",): "delete"}

# type -> (kind, document attribute, owner attribute)
DOCS: dict[str, tuple[str, str, str | None]] = {
    "aws_iam_policy": ("managed", "policy", None),
    "aws_iam_role_policy": ("inline", "policy", "role"),
    "aws_iam_user_policy": ("inline", "policy", "user"),
    "aws_iam_group_policy": ("inline", "policy", "group"),
    "aws_s3_bucket_policy": ("resource", "policy", "bucket"),
    "aws_kms_key": ("resource", "policy", None),
}


class TerraformError(ValueError):
    """Not a Terraform plan in JSON."""


@dataclass
class Doc:
    address: str
    type: str
    kind: str  # managed, inline, trust, resource
    action: str  # create, update, delete, replace
    owner: str | None  # role, user or group name for inline policies; bucket for a bucket policy
    name: str | None
    before: str | None
    after: str | None
    unknown: bool = False


def _action(actions: list[str]) -> str | None:
    if "create" in actions and "delete" in actions:
        return "replace"
    return ACTIONS.get(tuple(actions))


def _text(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return v if isinstance(v, str) else json.dumps(v)


class _AllUnknown(dict):  # type: ignore[type-arg]
    """after_unknown given as true: every attribute is unknown until apply."""

    def get(self, key: Any, default: Any = None) -> Any:
        return True


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _clean_change(c: Any) -> dict[str, Any] | None:
    """One resource change with every field of the type the code expects, or None if unusable.
    Plans are machine-written, but a hand-edited or truncated one must not crash the review."""
    if not isinstance(c, dict) or not isinstance(c.get("address"), str) or not isinstance(c.get("type"), str):
        return None
    ch = _dict(c.get("change"))
    actions = ch.get("actions")
    unknown = ch.get("after_unknown")
    sides: dict[str, dict[str, Any]] = {}
    for side in ("before", "after"):
        values = _dict(ch.get(side))
        inl = values.get("inline_policy")
        if inl is not None:
            keep = [x for x in inl if isinstance(x, dict)] if isinstance(inl, list) else []
            values = {**values, "inline_policy": keep}
        sides[side] = values
    clean: dict[str, Any] = {
        "actions": [a for a in actions if isinstance(a, str)] if isinstance(actions, list) else [],
        "before": sides["before"],
        "after": sides["after"],
        "after_unknown": _AllUnknown() if unknown is True else _dict(unknown),
    }
    return {**c, "change": clean}


def _changes(plan: Any) -> list[dict[str, Any]]:
    if not isinstance(plan, dict) or "resource_changes" not in plan and "format_version" not in plan:
        raise TerraformError("not a Terraform plan: expected the JSON from terraform show -json plan.out")
    raw = plan.get("resource_changes") or []
    if not isinstance(raw, list):
        raise TerraformError("resource_changes must be a list")
    return [x for x in (_clean_change(c) for c in raw) if x is not None]


def extract(plan: Any) -> list[Doc]:
    """Every IAM-relevant document the plan changes."""
    out: list[Doc] = []
    for c in _changes(plan):
        ch = c.get("change") or {}
        action = _action(ch.get("actions") or [])
        if action is None:
            continue
        before, after = ch.get("before") or {}, ch.get("after") or {}
        unknown = ch.get("after_unknown") or {}
        t = c.get("type", "")
        if t in DOCS:
            kind, attr, owner_attr = DOCS[t]
            out.append(
                Doc(
                    c["address"],
                    t,
                    kind,
                    action,
                    (after or before).get(owner_attr) if owner_attr else None,
                    (after or before).get("name"),
                    _text(before.get(attr)),
                    _text(after.get(attr)),
                    unknown=bool(unknown.get(attr)),
                )
            )
        elif t == "aws_iam_role":
            name = (after or before).get("name")
            b, a = _text(before.get("assume_role_policy")), _text(after.get("assume_role_policy"))
            if b != a or action != "update":
                out.append(
                    Doc(c["address"], t, "trust", action, name, name, b, a, bool(unknown.get("assume_role_policy")))
                )
            old = {p.get("name"): _text(p.get("policy")) for p in before.get("inline_policy") or [] if p.get("name")}
            new = {p.get("name"): _text(p.get("policy")) for p in after.get("inline_policy") or [] if p.get("name")}
            for pname in sorted(set(old) | set(new)):
                if old.get(pname) == new.get(pname):
                    continue
                act = "create" if pname not in old else "delete" if pname not in new else "update"
                out.append(Doc(c["address"], t, "inline", act, name, pname, old.get(pname), new.get(pname)))
    return out


# --- applying the plan to an account export ------------------------------------------------------


def _config_resources(module: Any, prefix: str = "", depth: int = 0) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(module, dict) or depth > 20:
        return out
    resources = module.get("resources")
    for r in resources if isinstance(resources, list) else []:
        if isinstance(r, dict) and isinstance(r.get("address"), str):
            out[f"{prefix}{r['address']}"] = r
    for name, call in _dict(module.get("module_calls")).items():
        out.update(_config_resources(_dict(call).get("module"), f"{prefix}module.{name}.", depth + 1))
    return out


class _Applier:
    def __init__(self, plan: dict[str, Any], export: dict[str, Any]) -> None:
        self.raw = copy.deepcopy(export)
        self.notes: list[str] = []
        self.account = self._account()
        self.planned = {c["address"]: c for c in _changes(plan)}
        self.config = _config_resources(_dict(plan.get("configuration")).get("root_module"))

    def _account(self) -> str:
        for lst in ("RoleDetailList", "UserDetailList", "GroupDetailList"):
            for e in self.raw.get(lst) or []:
                parts = str(e.get("Arn", "") if isinstance(e, dict) else "").split(":")
                if len(parts) > 4 and parts[4]:
                    return parts[4]
        return "111122223333"

    # -- values, resolving references to resources created in the same plan
    def value(self, c: dict[str, Any], attr: str) -> Any:
        after = (c.get("change") or {}).get("after") or {}
        if after.get(attr) not in (None, ""):
            return after[attr]
        expr = _dict(_dict(_dict(self.config.get(c["address"])).get("expressions")).get(attr))
        if "constant_value" in expr:
            return expr["constant_value"]
        refs = expr.get("references")
        for ref in [r for r in refs if isinstance(r, str)] if isinstance(refs, list) else []:
            parts = ref.split(".")
            target = ".".join(parts[:2]) if not ref.startswith("module.") else ".".join(parts[:4])
            planned = self.planned.get(target)
            if planned is None:
                continue
            pa = (planned.get("change") or {}).get("after") or {}
            if planned["type"] == "aws_iam_policy":
                return pa.get("arn") or self._policy_arn(pa)
            if planned["type"] in ("aws_iam_role", "aws_iam_user", "aws_iam_group"):
                return pa.get("name")
            if planned["type"] == "aws_s3_bucket":
                return pa.get("bucket")
        return None

    def _policy_arn(self, after: dict[str, Any]) -> str:
        path = after.get("path") or "/"
        return f"arn:aws:iam::{self.account}:policy{path}{after.get('name')}"

    def _entity(self, lst: str, key: str, name: Any) -> dict[str, Any] | None:
        return next((e for e in self.raw.setdefault(lst, []) if e.get(key) == name), None)

    # -- the changes
    def apply(self) -> dict[str, Any]:
        order = {"aws_iam_policy": 0, "aws_iam_role": 1, "aws_iam_user": 1, "aws_iam_group": 1}
        for c in sorted(self.planned.values(), key=lambda c: order.get(c.get("type", ""), 2)):
            action = _action((c.get("change") or {}).get("actions") or [])
            if action is None:
                continue
            handler = getattr(self, f"_{c['type']}", None)
            if handler is not None:
                handler(c, action)
        return self.raw

    def _doc(self, c: dict[str, Any], attr: str) -> Any:
        ch = c.get("change") or {}
        if (ch.get("after_unknown") or {}).get(attr):
            self.notes.append(f"{c['address']}: {attr} is not known until apply; the account is analysed without it.")
            return None
        v = (ch.get("after") or {}).get(attr)
        try:
            return json.loads(v) if isinstance(v, str) else v
        except json.JSONDecodeError:
            self.notes.append(f"{c['address']}: {attr} is not valid JSON; ignored.")
            return None

    def _aws_iam_policy(self, c: dict[str, Any], action: str) -> None:
        before = (c.get("change") or {}).get("before") or {}
        after = (c.get("change") or {}).get("after") or {}
        pols = self.raw.setdefault("Policies", [])
        arn = after.get("arn") or before.get("arn") or self._policy_arn(after or before)
        pols[:] = [p for p in pols if p["Arn"] != arn]
        if action == "delete":
            return
        document = self._doc(c, "policy")
        if document is None:
            return
        pols.append(
            {
                "PolicyName": after.get("name"),
                "Arn": arn,
                "DefaultVersionId": "v1",
                "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True, "Document": document}],
            }
        )

    def _principal(self, c: dict[str, Any], action: str, lst: str, key: str, kind: str) -> None:
        before = (c.get("change") or {}).get("before") or {}
        after = (c.get("change") or {}).get("after") or {}
        name = after.get("name") or before.get("name")
        existing = self._entity(lst, key, name)
        if action == "delete":
            if existing is not None:
                self.raw[lst].remove(existing)
            return
        if existing is None:
            path = after.get("path") or "/"
            existing = {key: name, "Arn": f"arn:aws:iam::{self.account}:{kind}{path}{name}", "Path": path}
            for k in {
                "role": ("RolePolicyList", "AttachedManagedPolicies"),
                "user": ("UserPolicyList", "AttachedManagedPolicies", "GroupList"),
                "group": ("GroupPolicyList", "AttachedManagedPolicies"),
            }[kind]:
                existing[k] = []
            self.raw[lst].append(existing)
        if kind == "role":
            trust = self._doc(c, "assume_role_policy")
            if trust is not None:
                existing["AssumeRolePolicyDocument"] = trust
            elif "AssumeRolePolicyDocument" not in existing:
                existing["AssumeRolePolicyDocument"] = {"Version": "2012-10-17", "Statement": []}
            inline = after.get("inline_policy")
            if inline:
                existing["RolePolicyList"] = [
                    {"PolicyName": p["name"], "PolicyDocument": json.loads(p["policy"])}
                    for p in inline
                    if p.get("name") and p.get("policy")
                ]
            arns = after.get("managed_policy_arns")
            if arns:
                existing["AttachedManagedPolicies"] = [
                    {"PolicyName": a.rsplit("/", 1)[-1], "PolicyArn": a} for a in sorted(arns)
                ]
        tags = after.get("tags")
        if isinstance(tags, dict):
            existing["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]

    def _aws_iam_role(self, c: dict[str, Any], action: str) -> None:
        self._principal(c, action, "RoleDetailList", "RoleName", "role")

    def _aws_iam_user(self, c: dict[str, Any], action: str) -> None:
        self._principal(c, action, "UserDetailList", "UserName", "user")

    def _aws_iam_group(self, c: dict[str, Any], action: str) -> None:
        self._principal(c, action, "GroupDetailList", "GroupName", "group")

    def _inline(self, c: dict[str, Any], action: str, lst: str, key: str, owner_attr: str, pol_list: str) -> None:
        before = (c.get("change") or {}).get("before") or {}
        owner = self.value(c, owner_attr) or before.get(owner_attr)
        name = (c.get("change") or {}).get("after", {}) and self.value(c, "name") or before.get("name")
        entity = self._entity(lst, key, owner) if owner else None
        if entity is None:
            self.notes.append(f"{c['address']}: {owner_attr} {owner!r} is not in the export; ignored.")
            return
        entity[pol_list] = [p for p in entity.get(pol_list) or [] if p.get("PolicyName") != name]
        if action == "delete":
            return
        document = self._doc(c, "policy")
        if document is not None:
            entity[pol_list].append({"PolicyName": name, "PolicyDocument": document})

    def _aws_iam_role_policy(self, c: dict[str, Any], action: str) -> None:
        self._inline(c, action, "RoleDetailList", "RoleName", "role", "RolePolicyList")

    def _aws_iam_user_policy(self, c: dict[str, Any], action: str) -> None:
        self._inline(c, action, "UserDetailList", "UserName", "user", "UserPolicyList")

    def _aws_iam_group_policy(self, c: dict[str, Any], action: str) -> None:
        self._inline(c, action, "GroupDetailList", "GroupName", "group", "GroupPolicyList")

    def _attach(self, c: dict[str, Any], action: str, lst: str, key: str, owner_attr: str) -> None:
        before = (c.get("change") or {}).get("before") or {}
        owner = self.value(c, owner_attr) or before.get(owner_attr)
        arn = self.value(c, "policy_arn") or before.get("policy_arn")
        entity = self._entity(lst, key, owner) if owner else None
        if entity is None or not arn:
            self.notes.append(f"{c['address']}: could not tell which policy is attached to what; ignored.")
            return
        attached = [a for a in entity.get("AttachedManagedPolicies") or [] if a.get("PolicyArn") != arn]
        if action != "delete":
            attached.append({"PolicyName": arn.rsplit("/", 1)[-1], "PolicyArn": arn})
        entity["AttachedManagedPolicies"] = attached

    def _aws_iam_role_policy_attachment(self, c: dict[str, Any], action: str) -> None:
        self._attach(c, action, "RoleDetailList", "RoleName", "role")

    def _aws_iam_user_policy_attachment(self, c: dict[str, Any], action: str) -> None:
        self._attach(c, action, "UserDetailList", "UserName", "user")

    def _aws_iam_group_policy_attachment(self, c: dict[str, Any], action: str) -> None:
        self._attach(c, action, "GroupDetailList", "GroupName", "group")

    def _aws_iam_user_group_membership(self, c: dict[str, Any], action: str) -> None:
        before = (c.get("change") or {}).get("before") or {}
        after = (c.get("change") or {}).get("after") or {}
        user = self._entity("UserDetailList", "UserName", self.value(c, "user") or before.get("user"))
        if user is None:
            return
        groups = set(user.get("GroupList") or []) - set(before.get("groups") or [])
        if action != "delete":
            groups |= set(after.get("groups") or [])
        user["GroupList"] = sorted(groups)


def _path_key(p: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    return (p["start"], p["end"], tuple(s["technique"] for s in p["steps"]))


def _account_diff(before_raw: dict[str, Any], after_raw: dict[str, Any]) -> dict[str, Any]:
    env_b, env_a = Environment.from_auth_details(before_raw), Environment.from_auth_details(after_raw)
    b, a = analyze(env_b), analyze(env_a)
    pb, pa = {_path_key(p): p for p in b["paths"]}, {_path_key(p): p for p in a["paths"]}
    admins_b = {p["arn"] for p in b["principals"] if p["admin_equivalent"]}
    admins_a = {p["arn"] for p in a["principals"] if p["admin_equivalent"]}
    eb = {e["principal"]: e for e in entry_points(env_b, everyone=b)["entries"]}
    ea = {e["principal"]: e for e in entry_points(env_a, everyone=a)["entries"]}
    rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    new_entries = [e for k, e in ea.items() if k not in eb or rank[e["rating"]] > rank[eb[k]["rating"]]]
    return {
        "new_paths": [pa[k] for k in sorted(set(pa) - set(pb))],
        "removed_paths": [pb[k] for k in sorted(set(pb) - set(pa))],
        "new_admins": sorted(admins_a - admins_b),
        "removed_admins": sorted(admins_b - admins_a),
        "new_entry_points": sorted(new_entries, key=lambda e: -e["score"]),
        "removed_entry_points": [eb[k] for k in sorted(set(eb) - set(ea))],
        "principals_before": len(env_b.nodes),
        "principals_after": len(env_a.nodes),
    }


# --- the review ----------------------------------------------------------------------------------


def review(plan: Any, catalog: Catalog, export: dict[str, Any] | None = None) -> dict[str, Any]:
    if export is not None and not (
        isinstance(export, dict) and any(k in export for k in ("UserDetailList", "RoleDetailList", "GroupDetailList"))
    ):
        raise TerraformError("the account export is not the output of aws iam get-account-authorization-details")
    docs = extract(plan)
    notes: list[str] = []
    documents: list[dict[str, Any]] = []
    for d in docs:
        label = f"{d.address}" + (f" ({d.kind} {d.name})" if d.kind == "inline" and d.type == "aws_iam_role" else "")
        if d.unknown:
            notes.append(f"{d.address}: the policy is not known until apply, so it was not reviewed.")
            continue
        status = {"create": "added", "delete": "deleted"}.get(d.action, "modified")
        rep = review_file(label, status, d.before, d.after, catalog)
        if rep is None:
            continue
        documents.append(
            {
                "address": d.address,
                "type": d.type,
                "kind": d.kind,
                "action": d.action,
                "owner": d.owner,
                "name": d.name,
                "diff": rep.diff,
                "new_escalations": rep.new_escalations,
                "new_checks": rep.new_checks,
                "error": rep.error,
            }
        )
    account = None
    if export is not None:
        from iamtrace.escalate import Environment, clean_export

        Environment.from_auth_details(export)  # a clear error for an export that is not usable
        export = clean_export(export)
        applier = _Applier(plan, export)
        after = applier.apply()
        notes += applier.notes
        account = _account_diff(export, after)
    summary = {
        "documents": len(documents),
        "new_escalations": sum(len(d["new_escalations"]) for d in documents),
        "new_checks": sum(len(d["new_checks"]) for d in documents),
        "high_checks": sum(1 for d in documents for f in d["new_checks"] if f["severity"] == "high"),
        "new_paths": len(account["new_paths"]) if account else 0,
        "new_admins": len(account["new_admins"]) if account else 0,
        "new_entry_points": len(account["new_entry_points"]) if account else 0,
    }
    return {"documents": documents, "account": account, "notes": notes, "summary": summary}


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def _chain(p: dict[str, Any]) -> str:
    out = " -> ".join([_short(p["start"])] + [f"[{s['technique']}] {_short(s['to'])}" for s in p["steps"]])
    return out + ("" if p.get("open", True) else "  (needs " + ", ".join(r["kind"] for r in p["requires"]) + ")")


def review_text(r: dict[str, Any]) -> str:
    s = r["summary"]
    lines = [
        f"Terraform plan: {s['documents']} IAM document change(s), {s['new_escalations']} new escalation "
        f"technique(s), {s['new_checks']} new risky pattern(s)."
    ]
    acct = r["account"]
    if acct is not None:
        lines.append(
            f"Account after the plan: {len(acct['new_paths'])} new path(s) to admin, "
            f"{len(acct['removed_paths'])} removed; {len(acct['new_admins'])} new admin-equivalent principal(s); "
            f"{len(acct['new_entry_points'])} new or worse entry point(s)."
        )
        for p in acct["new_paths"]:
            lines.append(f"  NEW PATH {_chain(p)}")
        for a in acct["new_admins"]:
            lines.append(f"  NEW ADMIN {_short(a)}")
        for e in acct["new_entry_points"]:
            lines.append(f"  ENTRY {e['rating']} {_short(e['principal'])}: {e['why']}")
        for p in acct["removed_paths"]:
            lines.append(f"  removed path {_chain(p)}")
    for d in r["documents"]:
        lines += ["", f"{d['address']} ({d['kind']}, {d['action']})"]
        if d["error"]:
            lines.append(f"  could not analyse: {d['error']}")
            continue
        if d["diff"] and not d["diff"]["unchanged"]:
            for kind, entries in d["diff"]["changes"].items():
                for e in entries[:20]:
                    mark = "!" if e["highlight"] and kind == "newly_allowed" else " "
                    who = f" for {', '.join(e['principals'])}" if e["principals"] else ""
                    lines.append(
                        f"  {mark} {kind.replace('_', ' ')}: {e['action']} on {', '.join(e['resources'])}{who}"
                    )
        for t in d["new_escalations"]:
            lines.append(f"  new escalation technique {t['id']}: {t['name']}")
        for f in d["new_checks"]:
            lines.append(f"  {f['severity']} {f['rule']}: {f['detail']}")
    for n in r["notes"]:
        lines.append(f"Note: {n}")
    return "\n".join(lines) + "\n"


def review_markdown(r: dict[str, Any]) -> str:
    s = r["summary"]
    lines = [MARKER, "### iam-trace: IAM changes in this Terraform plan", ""]
    acct = r["account"]
    if acct is not None:
        verdict = (
            "**This plan opens a path to admin.**"
            if acct["new_paths"] or acct["new_admins"]
            else "No new path to admin."
        )
        lines.append(
            f"{verdict} New paths: **{len(acct['new_paths'])}**, removed: {len(acct['removed_paths'])}. "
            f"New admin-equivalent principals: **{len(acct['new_admins'])}**. "
            f"New or worse entry points: **{len(acct['new_entry_points'])}**."
        )
        if acct["new_paths"]:
            lines += ["", "**New paths to admin**", ""]
            lines += [f"- {md_code(_chain(p), 400)}" for p in acct["new_paths"][:20]]
        if acct["new_admins"]:
            lines += ["", "**New admin-equivalent principals**", ""]
            lines += [f"- {md_code(_short(a))}" for a in acct["new_admins"]]
        if acct["new_entry_points"]:
            lines += ["", "**New entry points**", ""]
            lines += [
                f"- **{e['rating']}** {md_code(_short(e['principal']))}: {md_text(e['why'], 300)}"
                for e in acct["new_entry_points"][:20]
            ]
        if acct["removed_paths"]:
            lines += ["", f"Removed paths: {len(acct['removed_paths'])}."]
        lines.append("")
    lines.append(
        f"{s['documents']} IAM document(s) changed. New escalation techniques: **{s['new_escalations']}**. "
        f"New risky patterns: **{s['new_checks']}**."
    )
    for d in r["documents"]:
        if not d["new_escalations"] and not d["new_checks"] and not d["error"]:
            continue
        lines += ["", f"#### {md_code(d['address'])} ({d['kind']}, {d['action']})", ""]
        if d["error"]:
            lines.append(f"Could not analyse: {md_text(d['error'])}")
        for t in d["new_escalations"]:
            lines.append(f"- New escalation technique [{t['id']}]({t['source']['pathfinding']}) {md_code(t['name'])}")
        for f in d["new_checks"]:
            lines.append(f"- **{f['severity'].capitalize()}** {md_code(f['rule'])}: {md_text(f['detail'], 400)}")
    if r["notes"]:
        lines += ["", *[f"> {md_text(n, 400)}" for n in r["notes"]]]
    lines += ["", "<sub>Generated by iam-trace from terraform show -json.</sub>"]
    return "\n".join(lines) + "\n"
