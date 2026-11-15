"""Data paths: who can read, write or delete the data in a bucket, or use a KMS key."""

from __future__ import annotations

from typing import Any

from iamtrace.data import data_access, data_access_text, data_exposure, data_exposure_text
from iamtrace.escalate import Environment
from iamtrace.inventory import load_inventory

A = "111122223333"
BUCKET = "arn:aws:s3:::reports"
KEY = f"arn:aws:kms:eu-west-1:{A}:key/1111-2222"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


TRUST = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"})


def user(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "UserName": name,
        "Arn": arn("user", name),
        "UserPolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
        "GroupList": [],
    }


def role(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": arn("role", name),
        "AssumeRolePolicyDocument": TRUST,
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
    }


def allow(action: str | list[str], resource: str | list[str] = "*") -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


def env_with(users: list[dict[str, Any]], roles: list[dict[str, Any]], resources: list[dict[str, Any]]) -> Environment:
    env = Environment.from_auth_details(
        {"UserDetailList": users, "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )
    env.resources = load_inventory({"Version": 1, "Collected": ["s3-bucket", "kms-key"], "Resources": resources}, env)
    return env


def bucket(policy: dict[str, Any] | None = None, key: str | None = None, restrict: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"Arn": BUCKET}
    if policy:
        out["Policy"] = policy
    if key:
        out["KmsKey"] = key
    if restrict:
        out["PublicAccessBlock"] = {"BlockPublicPolicy": True, "RestrictPublicBuckets": True}
    return out


def key_policy(*principals: str) -> dict[str, Any]:
    return doc(
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"},
        *({"Effect": "Allow", "Principal": {"AWS": p}, "Action": "kms:Decrypt", "Resource": "*"} for p in principals),
    )


def names(entries: list[dict[str, Any]]) -> list[str]:
    return sorted(e["principal"].rsplit("/", 1)[-1] for e in entries)


# --- one resource ------------------------------------------------------------------------------


def test_direct_and_through_escalation() -> None:
    env = env_with(
        [user("dev", allow("sts:AssumeRole", arn("role", "reader")))],
        [role("reader", allow("s3:GetObject", f"{BUCKET}/*"))],
        [bucket()],
    )
    r = data_access(env, BUCKET, "read")
    assert names(r["direct"]) == ["reader"]
    assert names(r["via"]) == ["dev"]
    assert r["requires"] == ["s3:GetObject"]


def test_kms_encryption_needs_decrypt_too() -> None:
    env = env_with(
        [],
        [
            role("both", allow("s3:GetObject", f"{BUCKET}/*"), allow("kms:Decrypt", KEY)),
            role("s3only", allow("s3:GetObject", f"{BUCKET}/*")),
        ],
        [bucket(key=KEY), {"Arn": KEY, "Policy": key_policy()}],
    )
    r = data_access(env, BUCKET, "read")
    assert r["requires"] == ["s3:GetObject", "kms:Decrypt"]
    assert names(r["direct"]) == ["both"]
    assert names(r["blocked_by_key"]) == ["s3only"]


def test_key_policy_without_the_account_blocks_identity_grants() -> None:
    # A key policy that does not trust the account: IAM policies alone cannot grant kms:Decrypt.
    strict = doc({"Effect": "Allow", "Principal": {"AWS": arn("role", "both")}, "Action": "kms:*", "Resource": "*"})
    env = env_with(
        [],
        [
            role("both", allow("s3:GetObject", f"{BUCKET}/*"), allow("kms:Decrypt", KEY)),
            role("other", allow("s3:GetObject", f"{BUCKET}/*"), allow("kms:Decrypt", KEY)),
        ],
        [bucket(key=KEY), {"Arn": KEY, "Policy": strict}],
    )
    r = data_access(env, BUCKET, "read")
    assert names(r["direct"]) == ["both"]
    assert names(r["blocked_by_key"]) == ["other"]


def test_public_bucket_policy() -> None:
    public = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"})
    r = data_access(env_with([], [], [bucket(public)]), BUCKET, "read")
    assert r["public"] is True
    assert r["outside"][0]["principal"] == "*"


def test_block_public_access_stops_a_public_policy() -> None:
    public = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"})
    r = data_access(env_with([], [], [bucket(public, restrict=True)]), BUCKET, "read")
    assert r["public"] is False
    assert r["outside"] == []
    assert any("Block Public Access" in n for n in r["notes"])


def test_public_policy_but_objects_need_a_key_outsiders_cannot_use() -> None:
    public = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"})
    env = env_with([], [], [bucket(public, key=KEY), {"Arn": KEY, "Policy": key_policy()}])
    r = data_access(env, BUCKET, "read")
    assert r["public"] is False
    assert any("KMS key" in n for n in r["notes"])


def test_another_account_named_in_the_bucket_policy() -> None:
    other = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": f"{BUCKET}/*",
        }
    )
    r = data_access(env_with([], [], [bucket(other)]), BUCKET, "write")
    assert r["requires"] == ["s3:PutObject"]
    assert [o["principal"] for o in r["outside"]] == ["arn:aws:iam::999988887777:root"]


def test_deny_in_the_bucket_policy_wins() -> None:
    deny = doc(
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": f"{BUCKET}/*",
            "Condition": {"StringNotEquals": {"aws:PrincipalArn": arn("role", "app")}},
        }
    )
    env = env_with([], [role("app", allow("s3:*")), role("ops", allow("s3:*"))], [bucket(deny)])
    r = data_access(env, BUCKET, "delete")
    assert names(r["direct"]) == ["app"]


def test_kms_key_itself() -> None:
    env = env_with([], [role("app", allow("kms:Decrypt", KEY))], [{"Arn": KEY, "Policy": key_policy()}])
    r = data_access(env, KEY, "read")
    assert r["requires"] == ["kms:Decrypt"]
    assert names(r["direct"]) == ["app"]


def test_unknown_bucket_is_analysed_without_a_policy() -> None:
    env = env_with([], [role("app", allow("s3:GetObject"))], [])
    r = data_access(env, "arn:aws:s3:::elsewhere", "read")
    assert names(r["direct"]) == ["app"]
    assert any("not in the inventory" in n for n in r["notes"])


def test_text() -> None:
    env = env_with([], [role("reader", allow("s3:GetObject", f"{BUCKET}/*"))], [bucket()])
    text = data_access_text(data_access(env, BUCKET, "read"))
    assert "Who can read" in text and "role/reader" in text


# --- the whole account ----------------------------------------------------------------------------


def test_exposure_ranks_public_first() -> None:
    public = doc({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::open/*"})
    env = env_with(
        [user("dev", allow("sts:AssumeRole", arn("role", "reader")))],
        [role("reader", allow("s3:GetObject", "*"))],
        [bucket(), {"Arn": "arn:aws:s3:::open", "Policy": public}],
    )
    rows = data_exposure(env)["resources"]
    assert rows[0]["resource"] == "arn:aws:s3:::open"
    assert rows[0]["rating"] == "Critical"
    priv = next(r for r in rows if r["resource"] == BUCKET)
    assert priv["read"]["direct"] == 1 and priv["read"]["via"] == 1
    assert "open" in data_exposure_text(data_exposure(env))


def test_the_account_itself_is_not_outside() -> None:
    env = env_with([], [role("app", allow("kms:Decrypt", KEY))], [{"Arn": KEY, "Policy": key_policy()}])
    assert data_access(env, KEY, "read")["outside"] == []


def test_cli_data(capsys: Any) -> None:
    from pathlib import Path

    from iamtrace.cli import main

    root = Path(__file__).resolve().parents[2] / "examples/account"
    args = ["data", "--auth-details", str(root / "auth-details.json"), "--inventory", str(root / "inventory.json")]
    assert main(args) == 0
    out = capsys.readouterr().out
    assert out.index("example-public-assets") < out.index("example-reports")
    assert main([*args, "--fail-on", "critical"]) == 1
    capsys.readouterr()
    assert main([*args, "--resource", "arn:aws:s3:::example-reports"]) == 0
    out = capsys.readouterr().out
    assert "kms:Decrypt" in out and "role/report-runner" in out
