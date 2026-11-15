"""Entry points: who outside the account could become each principal, ranked by what they reach."""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.entry import entry_points, entry_points_text
from iamtrace.escalate import Environment

A = "111122223333"
GH = f"arn:aws:iam::{A}:oidc-provider/token.actions.githubusercontent.com"
H = "token.actions.githubusercontent.com"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action: str | list[str], resource: str | list[str] = "*") -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def gh_trust(condition: dict[str, Any] | None) -> dict[str, Any]:
    st: dict[str, Any] = {"Effect": "Allow", "Principal": {"Federated": GH}, "Action": "sts:AssumeRoleWithWebIdentity"}
    if condition:
        st["Condition"] = condition
    return doc(st)


def aws_trust(principal: Any, condition: dict[str, Any] | None = None) -> dict[str, Any]:
    st: dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}
    if condition:
        st["Condition"] = condition
    return doc(st)


def role(name: str, trust: dict[str, Any], *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": arn("role", name),
        "AssumeRolePolicyDocument": trust,
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
    }


def user(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
        "GroupList": [],
    }


def account(roles: list[dict[str, Any]], users: list[dict[str, Any]] | None = None) -> Environment:
    return Environment.from_auth_details(
        {"UserDetailList": users or [], "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )


def only(env: Environment, name: str) -> dict[str, Any]:
    entries = [e for e in entry_points(env)["entries"] if e["principal"] == arn("role", name)]
    assert len(entries) == 1, entries
    return entries[0]


# --- GitHub Actions ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "condition",
    [None, {"StringEquals": {f"{H}:aud": "sts.amazonaws.com"}}],
    ids=["no condition", "audience only"],
)
def test_github_role_open_to_every_repository(condition: dict[str, Any] | None) -> None:
    e = only(account([role("gh", gh_trust(condition), allow("*"))]), "gh")
    assert e["exposure"]["level"] == "public"
    assert "any GitHub repository" in e["exposure"]["who"]
    assert e["rating"] == "Critical"
    assert e["impact"]["admin"] is True
    assert "sub" in e["exposure"]["fix"]


def test_github_role_open_to_a_whole_organisation() -> None:
    e = only(account([role("gh", gh_trust({"StringLike": {f"{H}:sub": "repo:acme/*"}}))]), "gh")
    assert e["exposure"]["level"] == "broad"
    assert "acme" in e["exposure"]["who"]


def test_github_role_open_to_any_branch_of_one_repository() -> None:
    e = only(account([role("gh", gh_trust({"StringLike": {f"{H}:sub": "repo:acme/app:*"}}))]), "gh")
    assert e["exposure"]["level"] == "branch"
    assert "acme/app" in e["exposure"]["who"]


def test_github_role_pinned_to_a_branch_is_low() -> None:
    cond = {"StringEquals": {f"{H}:sub": "repo:acme/app:ref:refs/heads/main", f"{H}:aud": "sts.amazonaws.com"}}
    e = only(account([role("gh", gh_trust(cond))]), "gh")
    assert e["exposure"]["level"] == "federated"
    assert e["rating"] in ("Low", "Medium")


# --- other identity providers ----------------------------------------------------------------


def test_other_oidc_without_sub_is_broad() -> None:
    eks = f"arn:aws:iam::{A}:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC"
    trust = doc({"Effect": "Allow", "Principal": {"Federated": eks}, "Action": "sts:AssumeRoleWithWebIdentity"})
    e = only(account([role("pods", trust)]), "pods")
    assert e["exposure"]["level"] == "broad"
    assert "oidc.eks.eu-west-1.amazonaws.com/id/ABC" in e["exposure"]["who"]


def test_cognito_unauthenticated_identities_are_public() -> None:
    trust = doc(
        {
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": "eu-west-1:pool-id"},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
            },
        }
    )
    e = only(account([role("guest", trust)]), "guest")
    assert e["exposure"]["level"] == "public"
    assert "unauthenticated" in e["exposure"]["who"]


def test_saml_is_federated() -> None:
    trust = doc(
        {
            "Effect": "Allow",
            "Principal": {"Federated": f"arn:aws:iam::{A}:saml-provider/Okta"},
            "Action": "sts:AssumeRoleWithSAML",
            "Condition": {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
        }
    )
    e = only(account([role("sso", trust)]), "sso")
    assert e["exposure"]["level"] == "federated"
    assert "Okta" in e["exposure"]["who"]


# --- AWS principals ----------------------------------------------------------------------------


def test_any_aws_account() -> None:
    e = only(account([role("open", aws_trust("*"))]), "open")
    assert e["exposure"]["level"] == "public"
    assert "any AWS account" in e["exposure"]["who"]


def test_any_principal_in_the_organization() -> None:
    e = only(account([role("org", aws_trust("*", {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}))]), "org")
    assert e["exposure"]["level"] == "org"
    assert "o-abc123" in e["exposure"]["who"]


def test_external_account_without_external_id() -> None:
    e = only(account([role("vendor", aws_trust({"AWS": "arn:aws:iam::999988887777:root"}))]), "vendor")
    assert e["exposure"]["level"] == "external"
    assert "999988887777" in e["exposure"]["who"]
    assert "ExternalId" in e["exposure"]["fix"]


def test_external_account_with_external_id() -> None:
    trust = aws_trust({"AWS": "arn:aws:iam::999988887777:root"}, {"StringEquals": {"sts:ExternalId": "x1"}})
    e = only(account([role("vendor", trust)]), "vendor")
    assert e["exposure"]["level"] == "external-id"


def test_a_deny_closes_an_open_trust() -> None:
    trust = doc(
        {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "sts:AssumeRole",
            "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}},
        },
    )
    e = only(account([role("guarded", trust)]), "guarded")
    assert e["exposure"]["level"] == "org"


@pytest.mark.parametrize(
    "trust",
    [
        aws_trust({"AWS": f"arn:aws:iam::{A}:root"}),
        aws_trust({"Service": "ec2.amazonaws.com"}),
    ],
    ids=["same account", "service"],
)
def test_not_an_entry_point(trust: dict[str, Any]) -> None:
    out = entry_points(account([role("inside", trust)]))
    assert out["entries"] == []


# --- users and ranking ---------------------------------------------------------------------------


def test_users_are_entry_points() -> None:
    out = entry_points(account([], [user("alice", allow("s3:GetObject"))]))
    assert [e["exposure"]["level"] for e in out["entries"]] == ["user"]


def test_ranking_puts_reach_first() -> None:
    env = account(
        [
            role("gh-admin", gh_trust(None), allow("*")),
            role("gh-reader", gh_trust(None), allow("s3:GetObject")),
            role("admin", aws_trust({"AWS": f"arn:aws:iam::{A}:root"}), allow("*")),
        ],
        [user("dev", allow("sts:AssumeRole", arn("role", "admin")))],
    )
    out = entry_points(env)
    order = [e["principal"].split("/")[-1] for e in out["entries"]]
    assert order[0] == "gh-admin"
    assert order.index("dev") < order.index("gh-reader")
    dev = next(e for e in out["entries"] if e["principal"].endswith("/dev"))
    assert dev["impact"]["steps"] == 1
    assert dev["rating"] == "High"
    assert out["summary"]["critical"] == 1


def test_text_output() -> None:
    text = entry_points_text(entry_points(account([role("gh", gh_trust(None), allow("*"))])))
    assert "Critical" in text and "role/gh" in text and "any GitHub repository" in text


# --- command line and web ----------------------------------------------------------------------


def test_cli_entry_points(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    from iamtrace.cli import main

    data = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [role("gh", gh_trust(None), allow("*"))],
        "Policies": [],
    }
    f = tmp_path / "auth.json"
    f.write_text(json.dumps(data))
    assert main(["entry-points", "--auth-details", str(f)]) == 0
    assert "Critical" in capsys.readouterr().out
    assert main(["entry-points", "--auth-details", str(f), "--fail-on", "high"]) == 1
    capsys.readouterr()
    assert main(["entry-points", "--auth-details", str(f), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["critical"] == 1


def test_web_analysis_includes_entry_points() -> None:
    import json
    from pathlib import Path

    from iamtrace import web_api

    text = (Path(__file__).resolve().parents[2] / "examples/account/auth-details.json").read_text()
    out = json.loads(web_api.analyze_account(text, "arn:aws:iam::111122223333:user/dev"))
    entries = out["entry_points"]["entries"]
    assert entries and entries[0]["rating"] in ("Critical", "High")
