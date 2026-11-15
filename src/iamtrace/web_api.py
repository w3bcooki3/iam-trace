"""Entry points for the static web page (web/app.js calls these inside Pyodide).

Every function takes and returns JSON-compatible values and never raises: errors come back as
{"error": "..."} so the page can show them. Nothing here does I/O except reading the catalog
from the in-browser file system.
"""

from __future__ import annotations

import hashlib
import json
from functools import cache
from typing import Any

from iamtrace.catalog import Catalog, CatalogMissing
from iamtrace.check import check_auth_details, check_documents, check_sarif, check_text
from iamtrace.credentials import CredentialError, parse_credential_report
from iamtrace.data import data_access, data_exposure
from iamtrace.diff import diff_policies, diff_text
from iamtrace.entry import entry_points
from iamtrace.escalate import Environment, analyze, escalate_sarif, escalate_text
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.fixplan import fix_plan, public
from iamtrace.inventory import load_inventory
from iamtrace.loader import parse_any_policy, parse_context
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.output import can_text
from iamtrace.principals import Principal
from iamtrace.terraform import review as terraform_review
from iamtrace.terraform import review_markdown
from iamtrace.whatif import what_if, what_if_text
from iamtrace.whocan import who_can, who_can_text

CATALOG_DIR = "/home/pyodide/catalog"


@cache
def _catalog() -> Catalog | None:
    try:
        return Catalog.load(CATALOG_DIR)
    except CatalogMissing:
        return None


def _policies(texts: list[str], t: PolicyType, label: str) -> list[Policy]:
    return [Policy.from_json(x, policy_id=f"{label} {i + 1}", policy_type=t) for i, x in enumerate(texts) if x.strip()]


def _safe(fn: Any) -> Any:
    def wrapper(*args: Any) -> str:
        try:
            return json.dumps(fn(*args))
        except (PolicyError, ValueError, KeyError) as e:
            return json.dumps({"error": str(e)})

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


@_safe
def can(request_json: str) -> dict[str, Any]:
    """request: {principal, action, resource, resource_account, context: "k=v\\n...",
    identity: [text], resource_policy: text, boundary: text, session: [text], scp: [text], rcp: [text]}"""
    r = json.loads(request_json)
    principal = r["principal"].strip()
    p = Principal.service(principal[8:]) if principal.startswith("service:") else Principal.from_arn(principal)
    boundary = _policies([r.get("boundary", "")], PolicyType.BOUNDARY, "boundary")
    scps = _policies(r.get("scp", []), PolicyType.SCP, "SCP")
    rcps = _policies(r.get("rcp", []), PolicyType.RCP, "RCP")
    ps = PolicySet(
        identity=_policies(r.get("identity", []), PolicyType.IDENTITY, "identity policy"),
        resource=_policies([r.get("resource_policy", "")], PolicyType.RESOURCE, "resource policy"),
        boundary=boundary[0] if boundary else None,
        session=_policies(r.get("session", []), PolicyType.SESSION, "session policy"),
        # The page has one box per policy type; each SCP/RCP box is one organization level.
        scps=[[x] for x in scps] or None,
        rcps=[[x] for x in rcps] or None,
    )
    pairs = [line.strip() for line in r.get("context", "").splitlines() if line.strip()]
    req = Request(
        p,
        r["action"].strip(),
        r.get("resource", "*").strip() or "*",
        resource_account=(r.get("resource_account") or "").strip() or None,
        context=parse_context(pairs, None),
    )
    result = evaluate(req, ps)
    report = what_if(req, ps, result)
    return {
        "decision": result.decision.value,
        "text": can_text(result) + what_if_text(report),
        "result": result.to_dict(),
        "what_if": report,
    }


@_safe
def diff(old_text: str, new_text: str) -> dict[str, Any]:
    cat = _catalog()
    if cat is None:
        return {"error": "the action catalog is not available on this page"}
    old = parse_any_policy(old_text, "old") if old_text.strip() else None
    new = parse_any_policy(new_text, "new") if new_text.strip() else None
    d = diff_policies(old, new, cat)
    return {"text": diff_text(d), "result": d}


@_safe
def check(documents_json: str, include_aws_managed: bool = False) -> dict[str, Any]:
    """documents: [{name, text}]. A document that is an account export is checked policy by
    policy; anything else is one policy. Returns the report with text and SARIF renderings."""
    cat = _catalog()
    if cat is None:
        return {"error": "the action catalog is not available on this page"}
    docs = [d for d in json.loads(documents_json) if str(d.get("text", "")).strip()]
    if not docs:
        return {"error": "paste a policy or drop a file to check"}
    reports = []
    singles: list[tuple[str, str]] = []
    for d in docs:
        text = str(d["text"]).lstrip("\ufeff")
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            data = None
        if isinstance(data, dict) and any(k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList")):
            reports.append(check_auth_details(data, cat, include_aws_managed=include_aws_managed))
        else:
            singles.append((str(d.get("name") or f"policy {len(singles) + 1}"), text))
    if singles:
        reports.append(check_documents(singles, cat))
    report = reports[0] if len(reports) == 1 else _merge(reports)
    return {"result": report, "text": check_text(report), "sarif": check_sarif(report)}


def _merge(reports: list[dict[str, Any]]) -> dict[str, Any]:
    order = {"high": 0, "medium": 1, "low": 2}
    findings = sorted(
        (f for r in reports for f in r["findings"]),
        key=lambda f: (order[f["severity"]], f["policy"], f["statement"], f["rule"]),
    )
    summary: dict[str, int] = {}
    for r in reports:
        for k, v in r["summary"].items():
            summary[k] = summary.get(k, 0) + v
    return {"summary": summary, "findings": findings, "catalog": reports[0]["catalog"]}


@_safe
def who_can_query(
    auth_details_text: str,
    action: str,
    resource: str,
    resource_policy_text: str = "",
    scp_text: str = "",
    inventory_text: str = "",
    context_text: str = "",
) -> dict[str, Any]:
    """Every principal in the export that can perform `action` on `resource`."""
    if not action.strip():
        return {"error": "enter the action to check, for example s3:GetObject"}
    data = json.loads(auth_details_text)
    env = Environment.from_auth_details(data)
    if inventory_text.strip():
        env.resources = load_inventory(json.loads(inventory_text), env)
    res_policy = (
        Policy.from_json(resource_policy_text, policy_id="resource policy", policy_type=PolicyType.RESOURCE)
        if resource_policy_text.strip()
        else None
    )
    pairs = [line.strip() for line in context_text.splitlines() if line.strip()]
    report = who_can(
        env,
        action.strip(),
        resource.strip() or "*",
        scps=_scp_level(scp_text),
        resource_policy=res_policy,
        context=dict(parse_context(pairs, None)),
    )
    return {"result": report, "text": who_can_text(report)}


@_safe
def escalate(policy_text: str) -> dict[str, Any]:
    pol = Policy.from_json(policy_text, policy_id="policy", policy_type=PolicyType.IDENTITY)
    arn = "arn:aws:iam::111122223333:role/policy-under-test"
    report = analyze(Environment.single([pol], arn), start=arn)
    return {"text": escalate_text(report), "result": report, "graph": escalation_graph(report)}


@_safe
def escalate_account(auth_details_text: str, principal: str) -> dict[str, Any]:
    """Analyse an `aws iam get-account-authorization-details` export from one principal."""
    data = json.loads(auth_details_text)
    env = Environment.from_auth_details(data)
    start = principal.strip() or None
    if start is None:
        return {"error": "choose the principal to start from"}
    report = analyze(env, start=start)
    principals = sorted(env.nodes)
    return {
        "text": escalate_text(report),
        "result": report,
        "graph": escalation_graph(report),
        "principals": principals,
    }


def _scp_level(scp_text: str) -> list[list[Policy]] | None:
    """One organization level of SCPs from a policy document or a JSON array of them."""
    if not scp_text.strip():
        return None
    doc = json.loads(scp_text)
    docs = doc if isinstance(doc, list) else [doc]
    level = [
        Policy.from_json(json.dumps(d), policy_id=f"SCP {i + 1}", policy_type=PolicyType.SCP)
        for i, d in enumerate(docs)
    ]
    return [level] if level else None


def _inventory(data: dict[str, Any]) -> dict[str, int]:
    """How much the export contains, for the page's summary."""

    def items(key: str) -> list[Any]:
        value = data.get(key)
        return value if isinstance(value, list) else []

    inline = sum(len(x.get("UserPolicyList") or []) for x in items("UserDetailList") if isinstance(x, dict))
    inline += sum(len(x.get("GroupPolicyList") or []) for x in items("GroupDetailList") if isinstance(x, dict))
    inline += sum(len(x.get("RolePolicyList") or []) for x in items("RoleDetailList") if isinstance(x, dict))
    return {
        "users": len(items("UserDetailList")),
        "groups": len(items("GroupDetailList")),
        "roles": len(items("RoleDetailList")),
        "managed_policies": len(items("Policies")),
        "inline_policies": inline,
    }


@_safe
def analyze_account(
    auth_details_text: str,
    principal: str,
    scp_text: str = "",
    blast_radius: bool = False,
    inventory_text: str = "",
    credential_text: str = "",
) -> dict[str, Any]:
    """Everything the web app's attack-path screens show, in one call.

    `result` and `graph` are the analysis from the chosen starting principal (as escalate_account).
    `account` summarises every principal in the export: its techniques and its shortest path to an
    admin-equivalent principal, if any. `scp_text` is one level of SCPs that apply to the account.
    `inventory_text` is an optional resource inventory (iamtrace.inventory). `credential_text` is an
    optional IAM credential report (iamtrace.credentials), used for entry points.
    """
    data = json.loads(auth_details_text)
    if not isinstance(data, dict):
        raise ValueError("expected the JSON object that get-account-authorization-details prints")
    env = Environment.from_auth_details(data)
    start = principal.strip()
    if not start:
        return {"error": "choose the principal the attacker starts as"}
    if inventory_text.strip():
        try:
            inv_data = json.loads(inventory_text)
        except json.JSONDecodeError as e:
            raise ValueError(f"the resource inventory is not valid JSON: {e}") from e
        env.resources = load_inventory(inv_data, env)
    credentials = None
    if credential_text.strip():
        try:
            credentials = parse_credential_report(credential_text)
        except CredentialError as e:
            raise ValueError(f"the credential report: {e}") from e
    scps = _scp_level(scp_text)
    report = analyze(env, start=start, catalog=_catalog() if blast_radius else None, scps=scps)
    everyone = analyze(env, scps=scps)
    _LAST.clear()
    _LAST.update(key=_key(auth_details_text, scp_text, inventory_text), env=env, everyone=everyone, scps=scps)
    shortest: dict[str, dict[str, Any]] = {}
    for path in everyone["paths"]:
        best = shortest.get(path["start"])
        # An open path beats a gated one (MFA, network, time); then the shorter one.
        if best is None or (not path.get("open", True), len(path["steps"])) < (
            not best.get("open", True),
            len(best["steps"]),
        ):
            shortest[path["start"]] = path
    principals = []
    for p in everyone["principals"]:
        node = env.nodes[p["arn"]]
        principals.append(
            {
                "arn": p["arn"],
                "kind": p["kind"],
                "admin_equivalent": p["admin_equivalent"],
                "admin_reason": p["admin_reason"],
                "confirmed": sum(1 for t in p["techniques"] if t["confidence"] == "confirmed"),
                "possible": sum(1 for t in p["techniques"] if t["confidence"] == "possible"),
                "policies": len(node.policies),
                "groups": node.groups,
                "path": shortest.get(p["arn"]),
                "techniques": p["techniques"],
            }
        )
    return {
        "result": report,
        "graph": escalation_graph(report),
        "account": {"principals": principals, "paths": everyone["paths"]},
        "entry_points": entry_points(env, everyone=everyone, scps=scps, credentials=credentials),
        "data": data_exposure(env, scps=scps, report=everyone),
        "inventory": _inventory(data),
        "scps": sum(len(level) for level in scps) if scps else 0,
        "resources": env.resources.summary() if env.resources else None,
        "text": escalate_text(report),
        "sarif": escalate_sarif(report),
    }


# The last account analysed, so a fix plan for the same input reuses its analysis instead of
# running it again. One entry: the page works on one account at a time.
_LAST: dict[str, Any] = {}


def _key(*texts: str) -> str:
    return hashlib.sha256("\x00".join(texts).encode()).hexdigest()


@_safe
def fix_plan_query(
    auth_details_text: str, principal: str, scp_text: str = "", inventory_text: str = "", include_gated: bool = False
) -> dict[str, Any]:
    """The verified fix plan (iamtrace.fixplan) from `principal`, or from every principal when
    `principal` is empty."""
    key = _key(auth_details_text, scp_text, inventory_text)
    if _LAST.get("key") == key:
        env, everyone, scps = _LAST["env"], _LAST["everyone"], _LAST["scps"]
    else:
        data = json.loads(auth_details_text)
        if not isinstance(data, dict):
            raise ValueError("expected the JSON object that get-account-authorization-details prints")
        env = Environment.from_auth_details(data)
        if inventory_text.strip():
            env.resources = load_inventory(json.loads(inventory_text), env)
        scps = _scp_level(scp_text)
        everyone = None
    plan = fix_plan(
        env,
        start=principal.strip() or None,
        scps=scps,
        everyone=everyone,
        include_gated=include_gated,
        catalog=_catalog(),
    )
    out: dict[str, Any] = public(plan)
    return out


@_safe
def data_query(
    auth_details_text: str, resource: str, access: str, scp_text: str = "", inventory_text: str = ""
) -> dict[str, Any]:
    """Who can read (write, delete) one bucket or key (iamtrace.data), reusing the last analysis."""
    key = _key(auth_details_text, scp_text, inventory_text)
    if _LAST.get("key") == key:
        env, everyone, scps = _LAST["env"], _LAST["everyone"], _LAST["scps"]
    else:
        env = Environment.from_auth_details(json.loads(auth_details_text))
        if inventory_text.strip():
            env.resources = load_inventory(json.loads(inventory_text), env)
        scps = _scp_level(scp_text)
        everyone = analyze(env, scps=scps)
    return data_access(env, resource.strip(), access, scps=scps, report=everyone)


@_safe
def terraform_query(plan_text: str, auth_details_text: str = "") -> dict[str, Any]:
    """Review a Terraform plan (iamtrace.terraform), against the account export if one is given."""
    cat = _catalog()
    if cat is None:
        raise ValueError("the action catalog is not available")
    try:
        plan = json.loads(plan_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"the plan is not valid JSON: {e}") from e
    export = json.loads(auth_details_text) if auth_details_text.strip() else None
    out = terraform_review(plan, cat, export=export)
    out["markdown"] = review_markdown(out)
    return out


def account_principals(auth_details_text: str) -> str:
    """List the users and roles in an export, for the page's principal picker."""
    try:
        env = Environment.from_auth_details(json.loads(auth_details_text))
    except (PolicyError, ValueError, KeyError) as e:
        return json.dumps({"error": str(e)})
    return json.dumps({"principals": sorted(env.nodes)})


ADMIN_NODE = "admin"
MAX_POSSIBLE_TARGETS = 6


def escalation_graph(report: dict[str, Any]) -> dict[str, Any]:
    """Turn an escalation report into nodes and edges for the attack-path canvas.

    Principals are nodes. A technique that hands over another principal is an edge labelled with
    the technique ID. Admin-equivalent principals, and techniques that grant any permission, lead
    to a single "full control" node. Only the start principal's "possible" techniques are drawn
    (dashed), grouped by target, so the graph stays readable.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    start = report.get("start")
    by_arn = {p["arn"]: p for p in report["principals"]}

    def principal_node(arn: str) -> None:
        if arn in nodes:
            return
        info = by_arn.get(arn)
        kind = "user" if ":user/" in arn else "role" if ":role/" in arn else "resource"
        nodes[arn] = {
            "id": arn,
            "label": arn.rsplit("/", 1)[-1] if arn.startswith("arn:") else arn,
            "subtitle": arn.split(":", 5)[-1] if arn.startswith("arn:") else "",
            "kind": kind,
            "start": arn == start,
            "admin": bool(info and info["admin_equivalent"]),
            "admin_reason": info["admin_reason"] if info else None,
            "techniques": len(info["techniques"]) if info else 0,
        }

    def admin_node() -> None:
        nodes.setdefault(
            ADMIN_NODE,
            {
                "id": ADMIN_NODE,
                "label": "Full control",
                "subtitle": "every action on every resource",
                "kind": "admin",
                "start": False,
                "admin": True,
                "admin_reason": None,
                "techniques": 0,
            },
        )

    def edge(
        src: str, dst: str, label: str, name: str, confidence: str, requires: list[dict[str, str]] | None = None
    ) -> None:
        if any(e["from"] == src and e["to"] == dst and e["label"] == label for e in edges):
            return
        e: dict[str, Any] = {"from": src, "to": dst, "label": label, "name": name, "confidence": confidence}
        if requires:
            e["requires"] = requires  # a gated step: only with MFA, a network location, ...
        edges.append(e)

    if start:
        principal_node(start)
    for path in report["paths"]:
        principal_node(path["start"])
        for step in path["steps"]:
            principal_node(step["from"])
            principal_node(step["to"])
            edge(step["from"], step["to"], step["technique"], step["name"], "confirmed", step.get("requires"))

    for p in report["principals"]:
        if p["arn"] not in nodes:
            continue
        if p["admin_equivalent"]:
            admin_node()
            reason = p["admin_reason"] or ""
            label = "admin" if reason.startswith("allowed every") else reason.split("(")[-1].rstrip(")") or "self"
            edge(p["arn"], ADMIN_NODE, label, reason, "confirmed", p.get("admin_requires"))
        if p["arn"] != start or p["admin_equivalent"]:
            continue
        # The start principal's remaining techniques, grouped by where they lead.
        groups: dict[str, list[dict[str, Any]]] = {}
        for t in p["techniques"]:
            if t["category"] == "self-escalation":
                continue
            for target in t["targets"]:
                groups.setdefault(target, []).append(t)
        for i, (target, techniques) in enumerate(sorted(groups.items())):
            if i >= MAX_POSSIBLE_TARGETS:
                break
            confirmed = any(t["confidence"] == "confirmed" for t in techniques)
            if target not in nodes:
                is_arn = target.startswith("arn:")
                kind = (
                    "role"
                    if ":role/" in target or (not is_arn and " role" in target)
                    else "user"
                    if ":user/" in target or (not is_arn and " user" in target)
                    else "resource"
                )
                nodes[target] = {
                    "id": target,
                    "label": target.rsplit("/", 1)[-1] if is_arn else target[0].upper() + target[1:],
                    "subtitle": target.split(":", 5)[-1] if is_arn else "not a specific principal",
                    "kind": kind,
                    "start": False,
                    "admin": False,
                    "admin_reason": None,
                    "techniques": 0,
                }
            ids = [t["id"] for t in techniques]
            label = ids[0] if len(ids) == 1 else f"{ids[0]} +{len(ids) - 1}"
            conf = [t for t in techniques if t["confidence"] == "confirmed"]
            gated = bool(conf) and all(t.get("requires") or target in t.get("gated_targets", {}) for t in conf)
            requires = (conf[0].get("requires") or conf[0]["gated_targets"][target]) if gated else None
            edge(start, target, label, ", ".join(ids), "confirmed" if confirmed else "possible", requires)
            if any(t["grants_admin"] for t in techniques):
                admin_node()
                edge(
                    target,
                    ADMIN_NODE,
                    "modify",
                    "the technique lets the attacker change its permissions",
                    "confirmed" if confirmed else "possible",
                )
    return {"nodes": list(nodes.values()), "edges": edges}


def catalog_available() -> bool:
    return _catalog() is not None


def catalog_summary() -> str:
    """{"services": n, "actions": n} for the page's status bar, or null without a catalog."""
    cat = _catalog()
    return json.dumps({"services": len(cat.services), "actions": len(cat)} if cat else None)
