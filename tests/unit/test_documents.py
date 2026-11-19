from __future__ import annotations

import codecs
import gzip
import json
import urllib.parse
from pathlib import Path

import pytest

from iamtrace.documents import DocumentError, decode, detect, document, load_json, unwrap_policy, wrong_kind
from iamtrace.escalate import Environment
from iamtrace.loader import parse_any_policy, policy_from_text
from iamtrace.model import PolicyError, PolicyType

EX = Path(__file__).resolve().parents[2] / "examples"
POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
TEXT = json.dumps(POLICY)


# --- text ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        TEXT.encode(),
        codecs.BOM_UTF8 + TEXT.encode(),
        codecs.BOM_UTF16_LE + TEXT.encode("utf-16-le"),
        codecs.BOM_UTF16_BE + TEXT.encode("utf-16-be"),
        TEXT.encode("utf-16-le"),  # Windows tools write this without a byte order mark
        TEXT.encode("utf-16-be"),
        codecs.BOM_UTF32_LE + TEXT.encode("utf-32-le"),
        "﻿" + TEXT,
    ],
    ids=["utf8", "utf8-bom", "utf16le-bom", "utf16be-bom", "utf16le", "utf16be", "utf32le-bom", "str-bom"],
)
def test_every_unicode_encoding_reads_the_same(data: bytes | str) -> None:
    assert decode(data, "f") == TEXT


@pytest.mark.parametrize(
    "data, message",
    [
        ("é".encode("latin-1") + b"{}", "not a text file"),
        (b"\x00\x00\x00\x00", "NUL"),
        (gzip.compress(b"{}"), "not a text file"),
    ],
)
def test_binary_is_refused_clearly(data: bytes, message: str) -> None:
    with pytest.raises(DocumentError, match=message):
        decode(data, "f")


# --- JSON ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, hint",
    [
        ("", "empty"),
        ("   \n", "empty"),
        ('{"a": 1,}', "comma before"),
        ("{'Version': '2012-10-17'}", "single quotes"),
        ("Version: 2012-10-17\nStatement: []", "YAML"),
        ("<!DOCTYPE html><html></html>", "HTML"),
        ("user,arn,user_creation_time,password_enabled\n", "CSV"),
        ('{"a": 1} // note', "comments"),
    ],
)
def test_json_errors_say_what_the_text_looks_like(text: str, hint: str) -> None:
    with pytest.raises(DocumentError, match=hint):
        load_json(text, "f")


def test_json_errors_point_at_the_line_and_column() -> None:
    with pytest.raises(DocumentError) as e:
        load_json('{\n  "Version": "2012-10-17",\n  "Statement": [}\n}', "policy.json")
    msg = str(e.value)
    assert "line 3, column 17" in msg
    assert '"Statement": [}' in msg and "^" in msg


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nan_and_infinity_are_not_json(constant: str) -> None:
    with pytest.raises(DocumentError, match="not valid JSON"):
        load_json(f'{{"a": {constant}}}', "f")


def test_duplicate_keys_are_recorded() -> None:
    parsed = load_json('{"Effect": "Allow", "Effect": "Deny", "x": {"y": 1, "y": 2}}', "f")
    assert parsed.value["Effect"] == "Deny"
    assert parsed.duplicates == ["Effect", "y"]


def test_deep_nesting_is_refused() -> None:
    with pytest.raises(DocumentError, match="nested"):
        load_json("[" * 100 + "]" * 100, "f")
    with pytest.raises(DocumentError, match="nested"):
        load_json("[" * 100000 + "]" * 100000, "f")


# --- policy documents ----------------------------------------------------------------------------------


def test_documents_as_objects_strings_and_url_encoded_strings() -> None:
    assert document(POLICY, "d") == POLICY
    assert document(TEXT, "d") == POLICY
    assert document(urllib.parse.quote(TEXT), "d") == POLICY


def test_a_plain_document_with_a_percent_sign_is_not_url_decoded() -> None:
    # Found while hardening: every text document used to be URL-decoded, which corrupted
    # values like "100%" or "a%20b".
    doc = {
        **POLICY,
        "Statement": [{**POLICY["Statement"][0], "Condition": {"StringEquals": {"aws:UserAgent": "a%20b 100%"}}}],
    }
    assert document(json.dumps(doc), "d") == doc


WRAPPERS = [
    ({"PolicyVersion": {"Document": POLICY, "VersionId": "v1"}}, "get-policy-version", None),
    ({"RoleName": "r", "PolicyName": "p", "PolicyDocument": POLICY}, "get-role-policy", None),
    ({"Role": {"RoleName": "r", "AssumeRolePolicyDocument": urllib.parse.quote(TEXT)}}, "get-role", "resource"),
    ({"Policy": {"PolicySummary": {"Id": "p-1"}, "Content": TEXT}}, "describe-policy", "scp"),
    ({"Policy": TEXT}, "get-bucket-policy", "resource"),
    ({"Attributes": {"Policy": TEXT, "QueueArn": "x"}}, "get-queue-attributes", "resource"),
    ({"registryId": "1", "repositoryName": "r", "policyText": TEXT}, "get-repository-policy", "resource"),
    ({"ARN": "x", "Name": "s", "ResourcePolicy": TEXT}, "get-resource-policy", "resource"),
]


@pytest.mark.parametrize("wrapped, source, kind", WRAPPERS, ids=[w[1] for w in WRAPPERS])
def test_policies_inside_aws_cli_output_are_found(wrapped: dict, source: str, kind: str | None) -> None:
    found = unwrap_policy(wrapped, "w")
    assert found.document == POLICY
    assert source in str(found.source)
    assert found.kind == kind


def test_a_wrapped_policy_loads_with_a_note() -> None:
    p = policy_from_text(json.dumps(WRAPPERS[0][0]), PolicyType.IDENTITY, "p")
    assert len(p.statements) == 1
    assert any("get-policy-version" in w for w in p.warnings)
    # An Organizations policy is an SCP whatever it looks like.
    scp = parse_any_policy(json.dumps(WRAPPERS[3][0]), "p")
    assert scp.type is PolicyType.SCP


# --- what kind of file ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path, kind",
    [
        ("account/auth-details.json", "account"),
        ("account/inventory.json", "inventory"),
        ("account/last-accessed.json", "usage"),
        ("terraform/plan.json", "terraform"),
    ],
)
def test_detects_each_kind_of_input(path: str, kind: str) -> None:
    assert detect(json.loads((EX / path).read_text())) == kind


def test_detects_policies_and_credential_report_json() -> None:
    assert detect(POLICY) == "policy"
    assert detect([POLICY, POLICY]) == "policies"
    assert (
        detect({"Content": "dXNlcg==", "ReportFormat": "text/csv", "GeneratedTime": "2026-01-01T00:00:00Z"})
        == "credentials"
    )
    assert detect({"something": "else"}) == "unknown"


def test_the_wrong_file_in_a_box_is_named() -> None:
    export = json.loads((EX / "account/auth-details.json").read_text())
    err = wrong_kind(export, "policy", "the policy")
    assert err is not None and "account export" in str(err)
    assert wrong_kind(POLICY, "policy", "the policy") is None
    assert wrong_kind({"x": 1}, "policy", "the policy") is None  # unknown: let the parser explain


# --- account exports ----------------------------------------------------------------------------------------


def _export() -> dict:
    return json.loads((EX / "account/auth-details.json").read_text())


def test_an_unreadable_policy_is_left_out_not_fatal() -> None:
    data = _export()
    data["RoleDetailList"][0]["RolePolicyList"][0]["PolicyDocument"] = {"Statement": [{"Effect": "allow"}]}
    env = Environment.from_auth_details(data)
    assert len(env.unreadable) == 1
    assert any("could not be read and is left out" in w and "case-sensitive" in w for w in env.warnings)
    assert len(env.nodes) == 6


def test_a_truncated_export_and_duplicates_are_flagged() -> None:
    data = _export()
    data["IsTruncated"] = True
    data["RoleDetailList"].append(dict(data["RoleDetailList"][0]))
    env = Environment.from_auth_details(data)
    assert any("only the first page" in w for w in env.warnings)
    assert any("appears more than once" in w for w in env.warnings)


@pytest.mark.parametrize(
    "change, message",
    [
        (lambda d: d["RoleDetailList"][0].update(Arn=["x"]), "Arn must be text"),
        (lambda d: d["RoleDetailList"][0].update(Arn="arn:aws:iam::111122223333:user/ops"), "not an IAM role ARN"),
        (lambda d: d["RoleDetailList"][0].pop("AssumeRolePolicyDocument"), "missing AssumeRolePolicyDocument"),
        (lambda d: d.update(UserDetailList="x"), "UserDetailList must be a list"),
        (lambda d: d["UserDetailList"].append(5), r"UserDetailList\[1\] must be an object"),
    ],
)
def test_a_broken_export_names_the_entry(change, message: str) -> None:  # type: ignore[no-untyped-def]
    data = _export()
    change(data)
    with pytest.raises(PolicyError, match=message):
        Environment.from_auth_details(data)


def test_odd_entries_inside_lists_are_skipped_with_a_warning() -> None:
    data = _export()
    data["UserDetailList"][0]["UserPolicyList"].append(None)
    data["UserDetailList"][0]["GroupList"].append(["not", "a", "name"])
    env = Environment.from_auth_details(data)
    assert any("not objects; ignored" in w for w in env.warnings)
    assert any("is not in the export" in w for w in env.warnings)


def test_something_else_given_as_the_export_is_named() -> None:
    with pytest.raises(PolicyError, match="this is a policy document"):
        Environment.from_auth_details(POLICY)  # type: ignore[arg-type]
