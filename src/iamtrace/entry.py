"""Entry points: who outside the account could become each principal, ranked by what it reaches.

An attack starts somewhere. In an account export that is either an IAM user (its access keys or
password can leak) or a role whose trust policy lets someone outside the account assume it: a
GitHub Actions workflow, any identity of an OIDC or SAML provider, another AWS account, or anyone.

Trust policies are not read by pattern-matching their text. Each one is asked concrete questions
through the same evaluator that answers `can`:

- Can a GitHub workflow in a repository we do not own assume it? In another repository of the
  organisation it names? On another branch or in a pull request of the repository it names?
- Can any identity of this OIDC provider assume it, whatever its subject?
- Can an unauthenticated Cognito identity assume it?
- Can a principal in an unrelated AWS account assume it? One in the account it names, without
  sts:ExternalId?

So StringLike wildcards, Deny statements, negated operators and missing condition keys are all
judged the way AWS judges them, and "condition on aud but not on sub" is caught as what it is:
open to every GitHub repository.

Each exposure is then combined with the escalation analysis: an exposed principal that is
admin-equivalent, or has a short path to one, is what an attacker would use first.
"""

from __future__ import annotations

import json
import re
from typing import Any

from iamtrace.credentials import CredentialReport, describe_user
from iamtrace.escalate import Environment, Node, analyze
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.model import Policy, PolicyType
from iamtrace.principals import Principal

GITHUB = "token.actions.githubusercontent.com"
COGNITO = "cognito-identity.amazonaws.com"
# Identity providers anyone on the internet can get an identity from.
PUBLIC_IDPS = ("accounts.google.com", "graph.facebook.com", "www.amazon.com", "appleid.apple.com", COGNITO)
PROBE_ACCOUNT = "999999999999"
PROBE_OWNER = "iam-trace-probe"

# How much each kind of exposure counts, and how it is described. "public": anyone can do it;
# "broad": anyone in a large group (a GitHub organisation, every pod of a cluster); "branch": any
# branch or pull request of one repository; "external": another AWS account, no ExternalId;
# "external-id": another account that must present an ExternalId; "org": any principal in the AWS
# organisation; "user": an IAM user, whose keys or password can leak; "federated": a narrowly
# scoped identity provider trust (a branch of one repository, a SAML IdP).
LEVELS: dict[str, tuple[int, str]] = {
    "public": (100, "Anyone"),
    "broad": (70, "A large group"),
    "branch": (55, "Any branch or pull request"),
    "external": (50, "Another AWS account"),
    "root": (100, "The root user's credentials"),
    "user-stale": (60, "Stale IAM user credentials"),
    "user": (50, "IAM user credentials"),
    "external-id": (30, "Another AWS account, with ExternalId"),
    "org": (25, "The AWS organisation"),
    "federated": (20, "A scoped identity provider"),
}

_ALLOW_ALL = Policy.parse(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    policy_id="probe identity",
    policy_type=PolicyType.IDENTITY,
)


def _assume(role: Node, caller: Principal, action: str, context: dict[str, Any]) -> bool:
    """Does the role's trust policy let this caller assume it? A caller in another account is given
    allow-all identity policies: its own account controls those, so assume the worst."""
    assert role.trust is not None
    req = Request(caller, action, role.arn, resource_account=role.account, context=context)
    identity = [_ALLOW_ALL] if caller.kind in ("user", "role_session") else []
    return evaluate(req, PolicySet(identity=identity, resource=[role.trust])).allowed


def _allow_statements(role: Node) -> list[Any]:
    assert role.trust is not None
    return [st for st in role.trust.statements if st.effect == "Allow" and st.principal is not None]


def _principal_values(st: Any, kind: str) -> list[str]:
    p = st.principal
    if p == "*":
        return ["*"] if kind == "AWS" else []
    if not isinstance(p, dict):
        return []
    v = p.get(kind)
    if v is None:
        return []
    return [v] if isinstance(v, str) else [x for x in v if isinstance(x, str)]


def _condition_strings(st: Any, key_suffix: str) -> list[str]:
    """Every string value given for condition keys ending with key_suffix (case-insensitive)."""
    out: list[str] = []
    for _op, block in (st.condition or {}).items():
        for key, values in block.items():
            if key.lower().endswith(key_suffix.lower()):
                out += [values] if isinstance(values, str) else [x for x in values if isinstance(x, str)]
    return out


def trust_exposures(role: Node) -> list[dict[str, Any]]:
    """Who outside the account the role's trust policy lets in, one entry per kind of exposure."""
    if role.trust is None:
        return []
    found: list[dict[str, Any]] = []

    def adder(source: str) -> Any:
        def add(level: str, who: str, st: Any, fix: str, detail: str = "") -> None:
            found.append(
                {
                    "level": level,
                    "who": who,
                    "source": source,
                    "statement": f"{role.trust.id if role.trust else ''} {st.label}".strip(),
                    "statement_label": st.label,
                    "fix": fix,
                    "detail": detail,
                }
            )

        return add

    for st in _allow_statements(role):
        for provider in _principal_values(st, "Federated"):
            _federated(role, st, provider, adder("federated"))
        for value in _principal_values(st, "AWS"):
            _aws(role, st, value, adder("aws"))
    # Keep one exposure per level and description.
    seen: set[tuple[str, str]] = set()
    uniq = []
    for f in found:
        k = (f["level"], f["who"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def _federated(role: Node, st: Any, provider: str, add: Any) -> None:
    host = provider.split("oidc-provider/", 1)[-1] if "oidc-provider/" in provider else provider
    caller = Principal.web_identity(provider)
    if ":saml-provider/" in provider:
        name = provider.rsplit("/", 1)[-1]
        ctx = {"SAML:aud": "https://signin.aws.amazon.com/saml"}
        if _assume(role, caller, "sts:AssumeRoleWithSAML", ctx):
            add("federated", f"users of the SAML identity provider {name}", st, "Map the role to a specific IdP group.")
        return
    action = "sts:AssumeRoleWithWebIdentity"
    if host == GITHUB:
        _github(role, st, caller, add)
        return
    if host == COGNITO:
        pools = _condition_strings(st, ":aud") or ["probe-pool"]
        for pool in pools:
            unauth = {f"{COGNITO}:aud": pool, f"{COGNITO}:amr": ["unauthenticated"]}
            if _assume(role, caller, action, unauth):
                add(
                    "public",
                    f"unauthenticated (guest) identities of Cognito identity pool {pool}, if the pool allows them",
                    st,
                    'Require "cognito-identity.amazonaws.com:amr": "authenticated", or turn off guest access.',
                )
                return
            authed = {f"{COGNITO}:aud": pool, f"{COGNITO}:amr": ["authenticated"]}
            if _assume(role, caller, action, authed):
                add("broad", f"any signed-in user of Cognito identity pool {pool}", st, "Check who can sign up.")
                return
        return
    probe = {f"{host}:sub": PROBE_OWNER, f"{host}:aud": PROBE_OWNER, f"{host}:oaud": PROBE_OWNER}
    if _assume(role, caller, action, probe):
        public = host in PUBLIC_IDPS
        add(
            "public" if public else "broad",
            f"any identity of {host}" + (" (anyone can get one)" if public else ""),
            st,
            f'Add a StringEquals condition on "{host}:sub" (and "{host}:aud") naming the identity that should '
            "assume the role.",
        )
        return
    subs = _condition_strings(st, ":sub")
    add("federated", f"identities of {host} matching {', '.join(subs) or 'its conditions'}", st, "")


_REPO = re.compile(r"^repo:([^/:*?]+)/([^:*?]+)")
_ORG = re.compile(r"^repo:([^/:*?]+)/")


def _github(role: Node, st: Any, caller: Principal, add: Any) -> None:
    action = "sts:AssumeRoleWithWebIdentity"

    def ok(owner: str, repo: str, sub: str) -> bool:
        ctx = {
            f"{GITHUB}:sub": sub,
            f"{GITHUB}:aud": "sts.amazonaws.com",
            f"{GITHUB}:repository": f"{owner}/{repo}",
            f"{GITHUB}:repository_owner": owner,
            f"{GITHUB}:ref": "refs/heads/iam-trace-probe",
        }
        return _assume(role, caller, action, ctx)

    fix_repo = (
        f'Add a StringEquals condition on "{GITHUB}:sub" naming one repository and branch, for example '
        '"repo:ORG/REPO:ref:refs/heads/main", and on ":aud" with "sts.amazonaws.com".'
    )
    if ok(PROBE_OWNER, "not-yours", f"repo:{PROBE_OWNER}/not-yours:ref:refs/heads/main"):
        add(
            "public",
            "any GitHub repository (a workflow anyone writes)",
            st,
            fix_repo,
            "The trust policy does not limit the token's subject (sub) to your repositories.",
        )
        return
    subs = _condition_strings(st, ":sub") + _condition_strings(st, ":repository")
    orgs = sorted({m.group(1) for s in subs for m in [_ORG.match(s if s.startswith("repo:") else f"repo:{s}")] if m})
    for org in orgs:
        if ok(org, "iam-trace-probe", f"repo:{org}/iam-trace-probe:ref:refs/heads/main"):
            add(
                "broad",
                f"any repository in the GitHub organisation {org}",
                st,
                fix_repo.replace("ORG", org),
                "Anyone who can create or push to a repository in the organisation can assume the role.",
            )
            return
    repos = sorted({(m.group(1), m.group(2)) for s in subs for m in [_REPO.match(s)] if m})
    for owner, repo in repos:
        if ok(owner, repo, f"repo:{owner}/{repo}:ref:refs/heads/iam-trace-probe") or ok(
            owner, repo, f"repo:{owner}/{repo}:pull_request"
        ):
            add(
                "branch",
                f"any branch or pull request of {owner}/{repo}",
                st,
                f'Pin the branch or environment: "repo:{owner}/{repo}:ref:refs/heads/main" or '
                f'"repo:{owner}/{repo}:environment:production".',
                "Anyone who can push a branch or open a pull request that runs workflows can assume the role.",
            )
            return
    if subs:
        add("federated", f"GitHub Actions in {', '.join(sorted(set(subs)))}", st, "")


def _aws(role: Node, st: Any, value: str, add: Any) -> None:
    stranger = Principal.from_arn(f"arn:aws:iam::{PROBE_ACCOUNT}:role/{PROBE_OWNER}")
    if value == "*" or value == f"arn:aws:iam::{PROBE_ACCOUNT}:root":
        if _assume(role, stranger, "sts:AssumeRole", {}):
            add(
                "public",
                "any AWS account: any principal in the world",
                st,
                'Name the accounts or roles that should assume it, or add a condition on "aws:PrincipalOrgID".',
            )
            return
        orgs = _condition_strings(st, "aws:PrincipalOrgID")
        for org in orgs:
            if _assume(role, stranger, "sts:AssumeRole", {"aws:PrincipalOrgID": org}):
                add("org", f"any principal in the AWS organisation {org}", st, "Name the accounts that need it.")
                return
        # Open, but behind a condition we did not satisfy: check the deny side too.
        if not orgs and role.trust is not None:
            for d in role.trust.statements:
                for org in _condition_strings(d, "aws:PrincipalOrgID"):
                    if _assume(role, stranger, "sts:AssumeRole", {"aws:PrincipalOrgID": org}):
                        add(
                            "org", f"any principal in the AWS organisation {org}", st, "Name the accounts that need it."
                        )
                        return
        return
    m = re.match(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)", value)
    if not m:
        return
    acct = m.group(1)
    if acct == role.account:
        return  # the account itself: not an entry from outside
    caller = (
        Principal.from_arn(f"arn:aws:iam::{acct}:role/{PROBE_OWNER}")
        if value.endswith(":root") or value == acct
        else Principal.from_arn(value)
    )
    if _assume(role, caller, "sts:AssumeRole", {}):
        add(
            "external",
            f"AWS account {acct}"
            + ("" if value.endswith(":root") or value == acct else f" ({value.split(':', 5)[-1]})"),
            st,
            'If this is a third party, require "sts:ExternalId" so it cannot be tricked into using the role for '
            "someone else (the confused deputy problem).",
        )
        return
    if _assume(
        role, caller, "sts:AssumeRole", {"sts:ExternalId": next(iter(_condition_strings(st, "sts:ExternalId")), "x")}
    ):
        add("external-id", f"AWS account {acct}, which must present an ExternalId", st, "")


# --- ranking -----------------------------------------------------------------------------------


def _impact(p: dict[str, Any], path: dict[str, Any] | None) -> tuple[float, dict[str, Any]]:
    confirmed = sum(1 for t in p["techniques"] if t["confidence"] == "confirmed")
    possible = sum(1 for t in p["techniques"] if t["confidence"] == "possible")
    info = {
        "admin": bool(p["admin_equivalent"]),
        "admin_reason": p["admin_reason"],
        "steps": len(path["steps"]) if path else None,
        "path": path,
        "confirmed": confirmed,
        "possible": possible,
    }
    if p["admin_equivalent"]:
        return 1.0, info
    if path:
        reach = max(0.55, 0.95 - 0.08 * (len(path["steps"]) - 1))
        # A path that needs MFA or a network location is harder to use with stolen credentials.
        return (reach if path.get("open", True) else reach * 0.6), info
    if confirmed:
        return 0.4, info
    return (0.3 if possible else 0.25), info


def _rating(score: int) -> str:
    return "Critical" if score >= 70 else "High" if score >= 40 else "Medium" if score >= 20 else "Low"


def _why(e: dict[str, Any]) -> str:
    imp = e["impact"]
    who = e["exposure"]["who"]
    if imp["admin"]:
        reach = "is admin-equivalent itself"
    elif imp["steps"]:
        reach = f"reaches admin in {imp['steps']} step{'s' if imp['steps'] != 1 else ''}"
        if imp["path"] and not imp["path"].get("open", True):
            reach += " if it also has " + " and ".join(
                sorted(
                    {
                        {"mfa": "MFA", "network": "the right network", "time": "the right time"}[r["kind"]]
                        for r in imp["path"]["requires"]
                    }
                )
            )
    elif imp["confirmed"]:
        reach = (
            f"has {imp['confirmed']} escalation technique{'s' if imp['confirmed'] != 1 else ''} but no path to admin"
        )
    else:
        reach = "has no known escalation technique; check what it can do directly"
    return f"Reachable by {who}, and {reach}."


def entry_points(
    env: Environment,
    *,
    everyone: dict[str, Any] | None = None,
    scps: list[list[Policy]] | None = None,
    credentials: CredentialReport | None = None,
) -> dict[str, Any]:
    """Every principal someone outside the account could start as, worst first.

    With a credential report, users with no password and no active access key are left out (they
    cannot be used from outside), stale or unused keys and passwords without MFA rank higher, and
    root user access keys are reported. Without one, every user is listed."""
    if everyone is None:
        everyone = analyze(env, scps=scps)
    shortest: dict[str, dict[str, Any]] = {}
    for path in everyone["paths"]:
        best = shortest.get(path["start"])
        # An open path beats a gated one (MFA, network, time); then the shorter one.
        if best is None or (not path.get("open", True), len(path["steps"])) < (
            not best.get("open", True),
            len(best["steps"]),
        ):
            shortest[path["start"]] = path
    by_arn = {p["arn"]: p for p in everyone["principals"]}
    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    no_credentials = 0
    for arn in sorted(env.nodes):
        node = env.nodes[arn]
        if node.kind == "user":
            creds = credentials.users.get(arn) if credentials else None
            if credentials is not None and creds is not None and not creds.usable:
                no_credentials += 1
                continue
            exposures = [_user_exposure(creds, credentials is not None)]
        else:
            exposures = trust_exposures(node)
        if not exposures:
            continue
        p = by_arn.get(arn) or {"admin_equivalent": False, "admin_reason": None, "techniques": []}
        impact, info = _impact(p, shortest.get(arn))
        exposures.sort(key=lambda x: -LEVELS[x["level"]][0])
        worst = exposures[0]
        score = round(LEVELS[worst["level"]][0] * impact)
        entry: dict[str, Any] = {
            "principal": arn,
            "kind": node.kind,
            "exposure": worst,
            "other_exposures": exposures[1:],
            "impact": info,
            "score": score,
            "rating": _rating(score),
        }
        entry["why"] = _why(entry)
        entries.append(entry)
    if credentials is not None:
        if credentials.root is not None:
            root = _root_entry(credentials.root, env)
            if root is not None:
                entries.append(root)
        missing = sorted(set(credentials.users) - set(env.nodes))
        if missing:
            warnings.append(
                f"{len(missing)} user{'s' if len(missing) != 1 else ''} in the credential report "
                f"{'are' if len(missing) != 1 else 'is'} not in the account export: "
                + ", ".join(_short(a) for a in missing[:10])
                + (" and more" if len(missing) > 10 else "")
                + ". Export and report may be from different times or accounts."
            )
    entries.sort(key=lambda e: (-e["score"], e["principal"]))
    summary = {r.lower(): sum(1 for e in entries if e["rating"] == r) for r in ("Critical", "High", "Medium", "Low")}
    summary["external"] = sum(1 for e in entries if e["kind"] == "role")
    summary["users"] = sum(1 for e in entries if e["kind"] == "user")
    summary["no_credentials"] = no_credentials
    return {
        "entries": entries,
        "summary": summary,
        "warnings": warnings,
        "credential_report": None
        if credentials is None
        else {"generated": credentials.generated, "users": len(credentials.users)},
    }


def _user_exposure(creds: Any, have_report: bool) -> dict[str, Any]:
    if creds is None:
        return {
            "level": "user",
            "who": "anyone holding its access keys or console password",
            "source": "user",
            "statement": "",
            "statement_label": "",
            "fix": "Prefer roles with short-lived credentials (for example IAM Identity Center); "
            "remove unused access keys and require MFA.",
            "detail": "The credential report does not list this user."
            if have_report
            else "The account export does not say whether the user has keys or a password. "
            "Add a credential report to know.",
        }
    who, detail, fix = describe_user(creds)
    stale = bool(creds.stale_keys()) or (creds.password and not creds.mfa)
    return {
        "level": "user-stale" if stale else "user",
        "who": who,
        "source": "user",
        "statement": "",
        "statement_label": "",
        "fix": fix,
        "detail": detail,
    }


def _root_entry(root: Any, env: Environment) -> dict[str, Any] | None:
    """The root user is admin of everything; its access keys, or a password without MFA, are critical."""
    problems = []
    fixes = []
    if root.active_keys:
        ages = [k.age_days for k in root.active_keys if k.age_days is not None]
        problems.append(
            f"{len(root.active_keys)} active access key{'s' if len(root.active_keys) != 1 else ''}"
            + (f", the oldest {max(ages)} days old" if ages else "")
        )
        fixes.append("Delete the root user's access keys; use IAM roles instead.")
    if root.password and not root.mfa:
        problems.append("a console password without MFA")
        fixes.append("Turn on MFA for the root user.")
    if not problems:
        return None
    account = next(iter(env.nodes.values())).account if env.nodes else ""
    score = 100 if root.active_keys else 90
    entry: dict[str, Any] = {
        "principal": root.arn or f"arn:aws:iam::{account}:root",
        "kind": "root",
        "exposure": {
            "level": "root",
            "who": "anyone holding the root user's " + " and ".join(problems),
            "source": "user",
            "statement": "",
            "statement_label": "",
            "fix": " ".join(fixes),
            "detail": "The root user can do anything in the account, and policies and SCPs do not limit it.",
        },
        "other_exposures": [],
        "impact": {
            "admin": True,
            "admin_reason": "the root user",
            "steps": None,
            "path": None,
            "confirmed": 0,
            "possible": 0,
        },
        "score": score,
        "rating": _rating(score),
    }
    entry["why"] = f"The root user has {' and '.join(problems)}, and it is the account's root: full control."
    return entry


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def entry_points_text(report: dict[str, Any]) -> str:
    entries = report["entries"]
    if not entries:
        return "No entry points: no IAM users, and no role trusts anyone outside the account.\n"
    s = report["summary"]
    lines = [
        f"{len(entries)} entry point{'s' if len(entries) != 1 else ''}: {s['critical']} critical, {s['high']} high, "
        f"{s['medium']} medium, {s['low']} low. Worst first.",
    ]
    if s.get("no_credentials"):
        n = s["no_credentials"]
        lines.append(f"{n} user{'s' if n != 1 else ''} with no password and no active access key left out.")
    for w in report.get("warnings", []):
        lines.append(f"Warning: {w}")
    for e in entries:
        lines.append("")
        lines.append(f"{e['rating']:<8} {e['score']:>3}  {_short(e['principal'])}")
        lines.append(f"              {e['why']}")
        if e["exposure"]["detail"]:
            lines.append(f"              {e['exposure']['detail']}")
        if e["impact"]["path"]:
            steps = e["impact"]["path"]["steps"]
            chain = " -> ".join([_short(steps[0]["from"])] + [f"[{x['technique']}] {_short(x['to'])}" for x in steps])
            lines.append(f"              Path: {chain}")
        if e["exposure"]["statement"]:
            lines.append(f"              Granted by: {_short(e['exposure']['statement'])}")
        if e["exposure"]["fix"]:
            lines.append(f"              Fix: {e['exposure']['fix']}")
    return "\n".join(lines) + "\n"


def entry_points_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2) + "\n"
