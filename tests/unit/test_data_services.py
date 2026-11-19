"""Data paths for Secrets Manager secrets, DynamoDB tables, SNS topics and SQS queues.

Each service has its own actions for reading and writing, and its own rules for which KMS
permissions the caller needs when the data is encrypted with a KMS key:

- Secrets Manager: GetSecretValue needs kms:Decrypt; writing needs kms:GenerateDataKey. A secret
  without a key of its own uses the AWS managed key aws/secretsmanager, which only principals in
  the account can use, so another account can never read it.
- DynamoDB: a table encrypted with a customer managed key needs kms:Decrypt for reads and writes.
- SNS: publishing needs kms:GenerateDataKey and kms:Decrypt; subscribing needs neither.
- SQS: receiving needs kms:Decrypt; sending needs kms:GenerateDataKey and kms:Decrypt.

KMS calls made by a service on the caller's behalf carry kms:ViaService and kms:CallerAccount,
which key policies often require.
"""

from __future__ import annotations

from typing import Any

import pytest

from iamtrace.data import data_access, data_access_text, data_exposure
from iamtrace.escalate import Environment
from iamtrace.inventory import kind_of, load_inventory

A = "111122223333"
OTHER = "999988887777"
R = "eu-west-1"
SECRET = f"arn:aws:secretsmanager:{R}:{A}:secret:db-password-AbCdEf"
TABLE = f"arn:aws:dynamodb:{R}:{A}:table/orders"
TOPIC = f"arn:aws:sns:{R}:{A}:alerts"
QUEUE = f"arn:aws:sqs:{R}:{A}:jobs"
KEY = f"arn:aws:kms:{R}:{A}:key/1111-2222"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{A}:{kind}/{name}"


def doc(*statements: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def role(name: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {
        "RoleName": name,
        "Arn": arn("role", name),
        "AssumeRolePolicyDocument": doc(
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "sts:AssumeRole"}
        ),
        "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": doc(*statements)}] if statements else [],
        "AttachedManagedPolicies": [],
    }


def allow(action: str | list[str], resource: str | list[str] = "*") -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource}


KINDS = ["s3-bucket", "kms-key", "secretsmanager-secret", "dynamodb-table", "sns-topic", "sqs-queue"]


def env_with(roles: list[dict[str, Any]], resources: list[dict[str, Any]]) -> Environment:
    env = Environment.from_auth_details(
        {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": roles, "Policies": []}
    )
    env.resources = load_inventory({"Version": 1, "Collected": KINDS, "Resources": resources}, env)
    return env


def names(entries: list[dict[str, Any]]) -> list[str]:
    return sorted(e["principal"].rsplit("/", 1)[-1] for e in entries)


def trusting_key() -> dict[str, Any]:
    return {
        "Arn": KEY,
        "Policy": doc(
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"}
        ),
    }


def to_other(action: str | list[str], resource: str) -> dict[str, Any]:
    return doc(
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"}, "Action": action, "Resource": resource}
    )


def public(action: str, resource: str) -> dict[str, Any]:
    return doc({"Effect": "Allow", "Principal": "*", "Action": action, "Resource": resource})


# --- recognising the resources --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        (SECRET, "secretsmanager-secret"),
        (TABLE, "dynamodb-table"),
        (f"{TABLE}/index/by-date", None),
        (f"{TABLE}/stream/2024-01-01T00:00:00.000", None),
        (TOPIC, "sns-topic"),
        (f"{TOPIC}:6f1b4f52-0000-4000-8000-000000000000", None),  # a subscription
        (QUEUE, "sqs-queue"),
        (f"arn:aws:sqs:{R}:{A}:jobs.fifo", "sqs-queue"),
        (f"arn:aws:sns:{R}:{A}:alerts.fifo", "sns-topic"),
        (f"arn:aws:secretsmanager:{R}:{A}:other", None),
    ],
)
def test_kind_of(value: str, kind: str | None) -> None:
    assert kind_of(value) == kind


# --- Secrets Manager -----------------------------------------------------------------------------


def test_secret_with_the_aws_managed_key_is_readable_by_identity_policy() -> None:
    env = env_with(
        [role("app", allow("secretsmanager:GetSecretValue", SECRET)), role("ops", allow("s3:*"))],
        [{"Arn": SECRET}],
    )
    r = data_access(env, SECRET, "read")
    assert names(r["direct"]) == ["app"]
    assert r["requires"] == ["secretsmanager:GetSecretValue", "kms:Decrypt"]
    assert r["blocked_by_key"] == []


def test_secret_aws_managed_key_blocks_another_account() -> None:
    env = env_with([], [{"Arn": SECRET, "Policy": to_other("secretsmanager:GetSecretValue", "*")}])
    r = data_access(env, SECRET, "read")
    assert r["outside"] == []
    assert any("aws/secretsmanager" in n and "another account" in n for n in r["notes"])


def test_secret_with_a_customer_key_can_be_shared_with_another_account() -> None:
    key = {
        "Arn": KEY,
        "Policy": doc(
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{A}:root"}, "Action": "kms:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"},
                "Action": "kms:Decrypt",
                "Resource": "*",
            },
        ),
    }
    env = env_with([], [{"Arn": SECRET, "KmsKey": KEY, "Policy": to_other("secretsmanager:GetSecretValue", "*")}, key])
    r = data_access(env, SECRET, "read")
    assert [o["principal"] for o in r["outside"]] == [f"arn:aws:iam::{OTHER}:root"]


def test_secret_customer_key_needs_decrypt() -> None:
    env = env_with(
        [
            role("both", allow("secretsmanager:GetSecretValue", SECRET), allow("kms:Decrypt", KEY)),
            role("secret_only", allow("secretsmanager:GetSecretValue", SECRET)),
        ],
        [{"Arn": SECRET, "KmsKey": KEY}, trusting_key()],
    )
    r = data_access(env, SECRET, "read")
    assert names(r["direct"]) == ["both"]
    assert names(r["blocked_by_key"]) == ["secret_only"]
    assert r["blocked_by_key"][0]["missing"] == ["kms:Decrypt"]


def test_secret_write_is_put_or_update() -> None:
    env = env_with(
        [
            role("putter", allow("secretsmanager:PutSecretValue", SECRET)),
            role("updater", allow("secretsmanager:UpdateSecret", SECRET)),
        ],
        [{"Arn": SECRET}],
    )
    r = data_access(env, SECRET, "write")
    assert names(r["direct"]) == ["putter", "updater"]
    assert r["requires"][0] == "secretsmanager:PutSecretValue or secretsmanager:UpdateSecret"


def test_key_policy_with_via_service_condition_is_met() -> None:
    # A common key policy shape: the key can be used only through Secrets Manager, by this account.
    key = {
        "Arn": KEY,
        "Policy": doc(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"kms:ViaService": f"secretsmanager.{R}.amazonaws.com", "kms:CallerAccount": A}
                },
            }
        ),
    }
    env = env_with([role("app", allow("secretsmanager:GetSecretValue", SECRET))], [{"Arn": SECRET, "KmsKey": KEY}, key])
    r = data_access(env, SECRET, "read")
    assert names(r["direct"]) == ["app"]


def test_via_service_for_another_service_does_not_count() -> None:
    key = {
        "Arn": KEY,
        "Policy": doc(
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {"StringEquals": {"kms:ViaService": f"s3.{R}.amazonaws.com"}},
            }
        ),
    }
    env = env_with([role("app", allow("secretsmanager:GetSecretValue", SECRET))], [{"Arn": SECRET, "KmsKey": KEY}, key])
    r = data_access(env, SECRET, "read")
    assert r["direct"] == []
    assert names(r["blocked_by_key"]) == ["app"]


def test_secret_delete_needs_no_key() -> None:
    env = env_with(
        [role("admin", allow("secretsmanager:DeleteSecret", SECRET))], [{"Arn": SECRET, "KmsKey": KEY}, trusting_key()]
    )
    r = data_access(env, SECRET, "delete")
    assert r["requires"] == ["secretsmanager:DeleteSecret"]
    assert names(r["direct"]) == ["admin"]


def test_identity_deny_on_kms_blocks_an_aws_managed_key() -> None:
    env = env_with(
        [
            role(
                "app",
                allow("secretsmanager:GetSecretValue", SECRET),
                {"Effect": "Deny", "Action": "kms:*", "Resource": "*"},
            )
        ],
        [{"Arn": SECRET}],
    )
    r = data_access(env, SECRET, "read")
    assert r["direct"] == []
    assert names(r["blocked_by_key"]) == ["app"]


# --- DynamoDB ------------------------------------------------------------------------------------


def test_table_read_is_any_read_action() -> None:
    env = env_with(
        [
            role("getter", allow("dynamodb:GetItem", TABLE)),
            role("scanner", allow("dynamodb:Scan", TABLE)),
            role("describer", allow("dynamodb:DescribeTable", TABLE)),
        ],
        [{"Arn": TABLE}],
    )
    r = data_access(env, TABLE, "read")
    assert names(r["direct"]) == ["getter", "scanner"]


def test_table_with_customer_key_needs_decrypt_for_writes_too() -> None:
    env = env_with(
        [
            role("writer", allow("dynamodb:PutItem", TABLE), allow("kms:Decrypt", KEY)),
            role("nokey", allow("dynamodb:PutItem", TABLE)),
        ],
        [{"Arn": TABLE, "KmsKey": KEY}, trusting_key()],
    )
    r = data_access(env, TABLE, "write")
    assert r["requires"][-1] == "kms:Decrypt"
    assert names(r["direct"]) == ["writer"]
    assert names(r["blocked_by_key"]) == ["nokey"]


def test_table_without_a_key_needs_no_kms() -> None:
    env = env_with([role("app", allow("dynamodb:Query", TABLE))], [{"Arn": TABLE}])
    r = data_access(env, TABLE, "read")
    assert len(r["requires"]) == 1 and names(r["direct"]) == ["app"]


def test_table_resource_policy_shared_with_another_account() -> None:
    env = env_with([], [{"Arn": TABLE, "Policy": to_other(["dynamodb:GetItem", "dynamodb:Query"], TABLE)}])
    r = data_access(env, TABLE, "read")
    assert [o["principal"] for o in r["outside"]] == [f"arn:aws:iam::{OTHER}:root"]


def test_table_with_aws_managed_key_cannot_be_read_from_another_account() -> None:
    env = env_with([], [{"Arn": TABLE, "KmsKey": "alias/aws/dynamodb", "Policy": to_other("dynamodb:GetItem", TABLE)}])
    r = data_access(env, TABLE, "read")
    assert r["outside"] == []


# --- SNS -----------------------------------------------------------------------------------------


def test_public_topic_publish() -> None:
    env = env_with([], [{"Arn": TOPIC, "Policy": public("sns:Publish", TOPIC)}])
    r = data_access(env, TOPIC, "write")
    assert r["public"] is True
    assert r["requires"] == ["sns:Publish"]


def test_topic_conditioned_on_source_is_not_public() -> None:
    pol = doc(
        {
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sns:Publish",
            "Resource": TOPIC,
        },
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sns:Publish",
            "Resource": TOPIC,
            "Condition": {"StringEquals": {"aws:SourceOwner": A}},
        },
    )
    r = data_access(env_with([], [{"Arn": TOPIC, "Policy": pol}]), TOPIC, "write")
    assert r["public"] is False
    assert [s["principal"] for s in r["services"]] == ["events.amazonaws.com"]


def test_encrypted_topic_publish_needs_generate_and_decrypt() -> None:
    env = env_with(
        [
            role("both", allow("sns:Publish", TOPIC), allow(["kms:GenerateDataKey", "kms:Decrypt"], KEY)),
            role("half", allow("sns:Publish", TOPIC), allow("kms:GenerateDataKey", KEY)),
        ],
        [{"Arn": TOPIC, "KmsKey": KEY}, trusting_key()],
    )
    r = data_access(env, TOPIC, "write")
    assert r["requires"] == ["sns:Publish", "kms:GenerateDataKey", "kms:Decrypt"]
    assert names(r["direct"]) == ["both"]
    assert r["blocked_by_key"][0]["missing"] == ["kms:Decrypt"]


def test_subscribe_needs_no_key() -> None:
    env = env_with([role("sub", allow("sns:Subscribe", TOPIC))], [{"Arn": TOPIC, "KmsKey": KEY}, trusting_key()])
    r = data_access(env, TOPIC, "read")
    assert r["requires"] == ["sns:Subscribe"]
    assert names(r["direct"]) == ["sub"]


# --- SQS -----------------------------------------------------------------------------------------


def test_queue_receive_with_key() -> None:
    env = env_with(
        [
            role("consumer", allow("sqs:ReceiveMessage", QUEUE), allow("kms:Decrypt", KEY)),
            role("nokey", allow("sqs:ReceiveMessage", QUEUE)),
        ],
        [{"Arn": QUEUE, "KmsKey": KEY}, trusting_key()],
    )
    r = data_access(env, QUEUE, "read")
    assert r["requires"] == ["sqs:ReceiveMessage", "kms:Decrypt"]
    assert names(r["direct"]) == ["consumer"]


def test_queue_send_needs_both_key_actions() -> None:
    env = env_with([], [{"Arn": QUEUE, "KmsKey": KEY}, trusting_key()])
    assert data_access(env, QUEUE, "write")["requires"] == ["sqs:SendMessage", "kms:GenerateDataKey", "kms:Decrypt"]


def test_public_queue_with_aws_managed_key_is_not_public() -> None:
    env = env_with([], [{"Arn": QUEUE, "KmsKey": "alias/aws/sqs", "Policy": public("sqs:SendMessage", QUEUE)}])
    r = data_access(env, QUEUE, "write")
    assert r["public"] is False
    assert any("KMS key" in n for n in r["notes"])


def test_public_queue_without_key_is_public() -> None:
    env = env_with([], [{"Arn": QUEUE, "Policy": public("sqs:ReceiveMessage", QUEUE)}])
    r = data_access(env, QUEUE, "read")
    assert r["public"] is True


def test_queue_delete_is_any_delete_action() -> None:
    env = env_with([role("purger", allow("sqs:PurgeQueue", QUEUE))], [{"Arn": QUEUE}])
    assert names(data_access(env, QUEUE, "delete")["direct"]) == ["purger"]


# --- across the account --------------------------------------------------------------------------


def test_exposure_covers_every_kind_and_text_names_them() -> None:
    env = env_with(
        [role("app", allow("*"))],
        [
            {"Arn": SECRET},
            {"Arn": TABLE},
            {"Arn": TOPIC, "Policy": public("sns:Publish", TOPIC)},
            {"Arn": QUEUE},
        ],
    )
    rows = data_exposure(env)["resources"]
    assert {r["kind"] for r in rows} == {"secretsmanager-secret", "dynamodb-table", "sns-topic", "sqs-queue"}
    assert rows[0]["resource"] == TOPIC and rows[0]["rating"] == "Critical"
    text = data_access_text(data_access(env, TOPIC, "write"))
    assert "PUBLIC" in text


def test_unknown_kind_is_refused() -> None:
    env = env_with([], [])
    with pytest.raises(ValueError, match="Secrets Manager"):
        data_access(env, f"arn:aws:lambda:{R}:{A}:function:f", "read")
