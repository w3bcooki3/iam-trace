"""`iam-trace check`: risky patterns in single policies, each with a reason and a fix."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iamtrace.catalog import default_catalog
from iamtrace.check import RULES, check_auth_details, check_documents, check_sarif, check_text

CAT = default_catalog()


def run(*statements: dict[str, Any], version: str | None = "2012-10-17", name: str = "p.json") -> list[dict[str, Any]]:
    doc: dict[str, Any] = {"Statement": list(statements)}
    if version:
        doc["Version"] = version
    return check_documents([(name, json.dumps(doc))], CAT)["findings"]


def rules(findings: list[dict[str, Any]]) -> list[str]:
    return sorted(f["rule"] for f in findings)


def one(findings: list[dict[str, Any]], rule: str) -> dict[str, Any]:
    hits = [f for f in findings if f["rule"] == rule]
    assert len(hits) == 1, rules(findings)
    return hits[0]


# --- every rule has the text the UI needs -------------------------------------------------


def test_every_rule_is_documented() -> None:
    for rule_id, rule in RULES.items():
        assert rule.id == rule_id
        assert rule.title and rule.why and rule.fix, rule_id
        assert rule.severity in ("high", "medium", "low"), rule_id


# --- identity policies ---------------------------------------------------------------------


def test_full_admin() -> None:
    f = one(run({"Effect": "Allow", "Action": "*", "Resource": "*"}), "full-admin")
    assert f["severity"] == "high"
    assert f["statement"] == "Statement[0]"


def test_full_admin_with_condition_is_downgraded() -> None:
    f = one(
        run(
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ),
        "full-admin",
    )
    assert f["severity"] == "medium"
    assert "condition" in f["detail"].lower()


def test_full_admin_suppresses_overlapping_rules() -> None:
    # One clear finding is better than five that say the same thing.
    assert rules(run({"Effect": "Allow", "Action": "*", "Resource": "*"})) == ["full-admin"]


def test_passrole_on_any_role() -> None:
    f = one(run({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}), "passrole-any-role")
    assert f["severity"] == "high"
    f = one(
        run({"Effect": "Allow", "Action": "iam:Pass*", "Resource": "arn:aws:iam::111122223333:role/*"}),
        "passrole-any-role",
    )
    assert f["severity"] == "high"


def test_passrole_limited_by_service_is_fine() -> None:
    found = run(
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        }
    )
    assert "passrole-any-role" not in rules(found)


def test_passrole_on_named_role_is_fine() -> None:
    found = run({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::111122223333:role/app"})
    assert "passrole-any-role" not in rules(found)


def test_privilege_escalation_needs_every_permission_of_a_technique() -> None:
    found = run({"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"})
    f = one(found, "privilege-escalation")
    assert any("iam:CreatePolicyVersion" in t for t in f["techniques"])
    # lambda:CreateFunction on its own completes no technique (it also needs iam:PassRole).
    assert "privilege-escalation" not in rules(
        run({"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"})
    )


def test_privilege_escalation_across_statements() -> None:
    found = run(
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        {"Effect": "Allow", "Action": "lambda:CreateFunction", "Resource": "*"},
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"},
    )
    f = one(found, "privilege-escalation")
    assert f["statement"] == ""  # policy-level finding
    assert any("lambda:CreateFunction" in t for t in f["techniques"])


def test_permissions_management_on_all_resources() -> None:
    f = one(run({"Effect": "Allow", "Action": "s3:PutBucketPolicy", "Resource": "*"}), "permissions-management")
    assert f["severity"] == "medium"
    assert "s3:PutBucketPolicy" in f["actions"]


def test_read_only_wildcard_is_quiet() -> None:
    assert run({"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}) == []


def test_allow_with_not_action() -> None:
    f = one(run({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}), "allow-not-action")
    assert f["severity"] == "high"
    f = one(
        run({"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::bucket/*"}),
        "allow-not-action",
    )
    assert f["severity"] == "medium"


def test_allow_with_not_resource() -> None:
    f = one(
        run({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"}),
        "allow-not-resource",
    )
    assert f["severity"] == "medium"


def test_unknown_action_in_allow_and_deny() -> None:
    found = run(
        {"Effect": "Allow", "Action": "s3:GetObjects", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteBuckets", "Resource": "*"},
    )
    hits = sorted((f for f in found if f["rule"] == "unknown-action"), key=lambda f: f["statement"])
    assert [h["severity"] for h in hits] == ["low", "medium"]
    assert "s3:GetObjects" in hits[0]["detail"] and "protects nothing" in hits[1]["detail"]


def test_for_all_values_in_allow() -> None:
    f = one(
        run(
            {
                "Effect": "Allow",
                "Action": "dynamodb:GetItem",
                "Resource": "*",
                "Condition": {"ForAllValues:StringEquals": {"dynamodb:Attributes": ["id", "name"]}},
            }
        ),
        "for-all-values-allow",
    )
    assert f["severity"] == "medium"


def test_for_all_values_with_null_check_is_fine() -> None:
    found = run(
        {
            "Effect": "Allow",
            "Action": "dynamodb:GetItem",
            "Resource": "*",
            "Condition": {
                "ForAllValues:StringEquals": {"dynamodb:Attributes": ["id"]},
                "Null": {"dynamodb:Attributes": "false"},
            },
        }
    )
    assert "for-all-values-allow" not in rules(found)


def test_missing_version_and_duplicate_keys() -> None:
    assert rules(run({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, version=None)) == [
        "missing-version"
    ]
    text = (
        '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Action":"s3:*","Resource":"*"}}'
    )
    found = check_documents([("d.json", text)], CAT)["findings"]
    assert "duplicate-key" in rules(found)


def test_invalid_policy_is_a_finding_not_a_crash() -> None:
    report = check_documents([("bad.json", "{not json"), ("ok.json", '{"Statement":[]}')], CAT)
    assert [f["rule"] for f in report["findings"]] == ["invalid-policy", "invalid-policy"]
    assert report["findings"][0]["severity"] == "high"


# --- resource and trust policies -----------------------------------------------------------


def test_public_principal() -> None:
    f = one(
        run({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}),
        "public-principal",
    )
    assert f["severity"] == "high"
    found = run({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
    assert "public-principal" in rules(found)
    found = run({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::*:root"}, "Action": "sts:AssumeRole"})
    assert "public-principal" in rules(found)


def test_public_principal_limited_to_org_is_fine() -> None:
    found = run(
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
        }
    )
    assert "public-principal" not in rules(found)


def test_public_principal_with_unrelated_condition_is_still_flagged() -> None:
    f = one(
        run(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        ),
        "public-principal",
    )
    assert f["severity"] == "high"


def test_public_deny_is_fine() -> None:
    found = run(
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::b/*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    )
    assert found == []


def test_service_principal_without_source_condition() -> None:
    f = one(
        run(
            {
                "Effect": "Allow",
                "Principal": {"Service": "sns.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": "*",
            }
        ),
        "service-no-source",
    )
    assert f["severity"] == "low"
    found = run(
        {
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": "*",
            "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:topic"}},
        }
    )
    assert "service-no-source" not in rules(found)


def test_service_trust_policy_is_not_flagged() -> None:
    found = run({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
    assert found == []


def test_trust_whole_account() -> None:
    f = one(
        run({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::444455556666:root"}, "Action": "sts:AssumeRole"}),
        "trust-whole-account",
    )
    assert f["severity"] == "low"
    found = run({"Effect": "Allow", "Principal": {"AWS": "444455556666"}, "Action": "sts:AssumeRole"})
    assert "trust-whole-account" in rules(found)
    found = run(
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "abc"}},
        }
    )
    assert "trust-whole-account" not in rules(found)


# --- account exports -----------------------------------------------------------------------


def _export() -> dict[str, Any]:
    admin = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
    }
    return {
        "UserDetailList": [
            {
                "UserName": "alice",
                "Arn": "arn:aws:iam::111122223333:user/alice",
                "UserPolicyList": [
                    {
                        "PolicyName": "pass",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
                        },
                    }
                ],
                "AttachedManagedPolicies": [
                    {"PolicyName": "Custom", "PolicyArn": "arn:aws:iam::111122223333:policy/Custom"},
                    {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
                ],
                "GroupList": [],
            }
        ],
        "GroupDetailList": [],
        "RoleDetailList": [
            {
                "RoleName": "open",
                "Arn": "arn:aws:iam::111122223333:role/open",
                "AssumeRolePolicyDocument": trust,
                "RolePolicyList": [],
                "AttachedManagedPolicies": [
                    {"PolicyName": "Custom", "PolicyArn": "arn:aws:iam::111122223333:policy/Custom"}
                ],
            }
        ],
        "Policies": [
            {
                "PolicyName": "Custom",
                "Arn": "arn:aws:iam::111122223333:policy/Custom",
                "PolicyVersionList": [{"Document": admin, "IsDefaultVersion": True, "VersionId": "v1"}],
            },
            {
                "PolicyName": "AdministratorAccess",
                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "PolicyVersionList": [{"Document": admin, "IsDefaultVersion": True, "VersionId": "v1"}],
            },
        ],
    }


def test_account_export_checks_each_policy_once() -> None:
    report = check_auth_details(_export(), CAT)
    by_rule = {f["rule"]: f for f in report["findings"]}
    assert set(by_rule) == {"full-admin", "passrole-any-role", "public-principal"}
    admin = by_rule["full-admin"]
    assert admin["policy"] == "arn:aws:iam::111122223333:policy/Custom"
    assert admin["attached_to"] == ["arn:aws:iam::111122223333:role/open", "arn:aws:iam::111122223333:user/alice"]
    assert by_rule["public-principal"]["policy"] == "arn:aws:iam::111122223333:role/open trust policy"
    assert report["summary"]["skipped_aws_managed"] == 1


def test_account_export_can_include_aws_managed() -> None:
    report = check_auth_details(_export(), CAT, include_aws_managed=True)
    admins = [f for f in report["findings"] if f["rule"] == "full-admin"]
    assert len(admins) == 2


def test_account_export_rejects_other_json() -> None:
    from iamtrace.model import PolicyError

    with pytest.raises(PolicyError):
        check_auth_details({"Version": "2012-10-17"}, CAT)


# --- output --------------------------------------------------------------------------------


def test_findings_are_sorted_by_severity() -> None:
    found = run(
        {"Effect": "Allow", "Action": "s3:GetObjects", "Resource": "*"},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    )
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[f["severity"]] for f in found] == sorted(order[f["severity"]] for f in found)


def test_text_and_sarif() -> None:
    report = check_documents(
        [
            (
                "p.json",
                json.dumps({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}),
            )
        ],
        CAT,
    )
    text = check_text(report)
    assert "full-admin" in text and "Fix:" in text and "1 high" in text
    sarif = json.loads(check_sarif(report))
    run0 = sarif["runs"][0]
    assert run0["results"][0]["ruleId"] == "check/full-admin"
    assert run0["results"][0]["level"] == "error"
    assert run0["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "p.json"
    assert {r["id"] for r in run0["tool"]["driver"]["rules"]} >= {"check/full-admin"}


def test_text_when_clean() -> None:
    report = check_documents(
        [("p.json", '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}')],
        CAT,
    )
    assert "No risky patterns found" in check_text(report)


GH_PROVIDER = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"


def gh_statement(condition: dict[str, Any] | None) -> dict[str, Any]:
    st: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": {"Federated": GH_PROVIDER},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition:
        st["Condition"] = condition
    return st


def test_github_trust_with_audience_only_is_open() -> None:
    aud_only = {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
    f = one(run(gh_statement(aud_only)), "open-federated-trust")
    assert f["severity"] == "high"
    assert "any GitHub repository" in f["detail"]


def test_github_trust_for_a_whole_organisation_is_medium() -> None:
    org = {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}
    f = one(run(gh_statement(org)), "open-federated-trust")
    assert f["severity"] == "medium"
    assert "acme" in f["detail"]


def test_github_trust_pinned_to_a_branch_is_not_flagged() -> None:
    pinned = {
        "StringEquals": {
            "token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main",
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        }
    }
    assert "open-federated-trust" not in rules(run(gh_statement(pinned)))


def test_example_account_github_role_is_flagged() -> None:
    from pathlib import Path

    data = json.loads((Path(__file__).resolve().parents[2] / "examples/account/auth-details.json").read_text())
    report = check_auth_details(data, CAT)
    hits = [f for f in report["findings"] if f["rule"] == "open-federated-trust"]
    assert [f["policy"] for f in hits] == ["arn:aws:iam::111122223333:role/github-deploy trust policy"]
