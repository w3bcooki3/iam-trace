"""Reading what people give iam-trace: bytes or text, JSON, and the many shapes AWS wraps a policy in.

Every input goes through here, so the same rules apply everywhere (command line, web app, files):

- Text: UTF-8, UTF-16 and UTF-32, with or without a byte order mark; a binary file is refused
  with a clear message instead of being read as garbage.
- JSON: strict, as AWS is. NaN and Infinity are refused, duplicate keys are recorded (JSON parsers
  silently keep the last one), deep nesting is refused, and an error names the line and column and
  shows the line. Common mix-ups (YAML, CSV, an HTML page, a Python dict) are named.
- Policies: a policy document, or the output of the AWS CLI command that returns one: get-policy-
  version, get-role-policy (and the user and group versions), get-role, get-bucket-policy,
  get-key-policy, Lambda get-policy, SQS and SNS get-*-attributes, ECR get-repository-policy,
  Secrets Manager get-resource-policy, Organizations describe-policy. Documents may be objects,
  JSON strings, or URL-encoded JSON strings (the raw IAM API returns those).
"""

from __future__ import annotations

import codecs
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from iamtrace.model import PolicyError

MAX_DEPTH = 64  # policies are a few levels deep; an export about 8


class DocumentError(PolicyError):
    """The input is not readable text or JSON, or not the shape expected."""


# --- text ------------------------------------------------------------------------------------

_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


def decode(data: bytes | str, where: str) -> str:
    """Text from a file's bytes (or text already decoded), without a byte order mark."""
    if isinstance(data, str):
        return data[1:] if data.startswith("﻿") else data
    for bom, enc in _BOMS:
        if data.startswith(bom):
            try:
                return data[len(bom) :].decode(enc)
            except UnicodeDecodeError as e:
                raise DocumentError(f"{where}: starts like {enc.upper()} text but isn't: {e.reason}") from e
    if len(data) >= 4 and data[1] == 0 and data[3] == 0 and data[0] != 0:
        enc = "utf-16-le"  # UTF-16 without a byte order mark, as Windows tools write it
    elif len(data) >= 4 and data[0] == 0 and data[2] == 0 and data[1] != 0:
        enc = "utf-16-be"
    else:
        enc = "utf-8"
    try:
        text = data.decode(enc)
    except UnicodeDecodeError as e:
        raise DocumentError(
            f"{where}: not a text file (byte {e.start} is not {enc.upper()}). "
            "Export the data as JSON or CSV text and try again."
        ) from e
    if "\x00" in text:
        raise DocumentError(f"{where}: not a text file (it contains NUL bytes)")
    return text


# --- JSON ----------------------------------------------------------------------------------------


@dataclass
class Parsed:
    value: Any
    duplicates: list[str] = field(default_factory=list)  # keys that appeared twice in one object


def _hint(text: str) -> str:
    """A guess at what the text is, when it is not JSON."""
    t = text.lstrip()
    head = t[:200].lower()
    if not t:
        return " The input is empty."
    if head.startswith(("<!doctype", "<html", "<?xml", "<")):
        return " It looks like HTML or XML, not JSON (a web page saved instead of the file?)."
    if re.match(r"^[\w-]+:\s", t) or t.startswith("---"):
        return " It looks like YAML. iam-trace reads JSON; convert it first (for example: yq -o=json)."
    first = t.splitlines()[0]
    if first.count(",") >= 3 and not first.startswith(("{", "[")):
        return " It looks like CSV. Is this a credential report? Load it under Credential report."
    if t.startswith("{") and re.search(r"'\w+'\s*:", t[:500]):
        return " It uses single quotes, like a Python dict. JSON needs double quotes."
    if re.search(r",\s*[}\]]", t):
        return " JSON does not allow a comma before } or ]."
    if re.search(r"(^|\s)//|/\*", t):
        return " JSON does not allow comments."
    return ""


def _excerpt(text: str, line: int, col: int) -> str:
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return ""
    src = lines[line - 1]
    start = max(0, col - 40)
    snippet = src[start : start + 80]
    return f"\n  {snippet}\n  {' ' * (col - 1 - start)}^"


def _depth_ok(value: Any) -> bool:
    stack = [(value, 1)]
    while stack:
        v, d = stack.pop()
        if d > MAX_DEPTH:
            return False
        if isinstance(v, dict):
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, d + 1) for x in v)
    return True


def load_json(data: bytes | str, where: str) -> Parsed:
    """Strict JSON, with duplicate keys recorded. Raises DocumentError with a useful message."""
    text = decode(data, where)
    dupes: list[str] = []

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                dupes.append(k)
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise DocumentError(f"{where}: {name} is not valid JSON (use a number or a string)")

    if not text.strip():
        raise DocumentError(f"{where}: the input is empty")
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except json.JSONDecodeError as e:
        raise DocumentError(
            f"{where}: invalid JSON at line {e.lineno}, column {e.colno}: {e.msg}.{_hint(text)}"
            + _excerpt(text, e.lineno, e.colno)
        ) from e
    except RecursionError as e:
        raise DocumentError(f"{where}: JSON is nested too deeply") from e
    if not _depth_ok(value):
        raise DocumentError(f"{where}: JSON is nested more than {MAX_DEPTH} levels deep")
    return Parsed(value, sorted(set(dupes)))


# --- policy documents --------------------------------------------------------------------------------


def document(value: Any, where: str) -> Any:
    """A policy document from an object, a JSON string, or a URL-encoded JSON string."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    try:
        return load_json(text, where).value
    except DocumentError:
        # The raw IAM API returns policy documents URL-encoded ("%7B%22Version%22..."). Only
        # decode when the text looks like that, so a plain document with "%" in it stays intact.
        if "%" in text and not text.startswith(("{", "[")):
            return load_json(urllib.parse.unquote(text), where).value
        raise


# AWS CLI outputs that carry a policy: (path of keys to the document, what it came from, policy type).
_WRAPPERS: tuple[tuple[tuple[str, ...], str, str | None], ...] = (
    (("PolicyVersion", "Document"), "aws iam get-policy-version", None),
    (("PolicyDocument",), "aws iam get-role-policy / get-user-policy / get-group-policy", None),
    (("Role", "AssumeRolePolicyDocument"), "aws iam get-role (the trust policy)", "resource"),
    (("AssumeRolePolicyDocument",), "a role's trust policy", "resource"),
    (("Policy", "Content"), "aws organizations describe-policy", "scp"),
    (("Content",), "an Organizations policy", "scp"),
    (("Policy",), "get-bucket-policy, get-key-policy or Lambda get-policy", "resource"),
    (("Attributes", "Policy"), "SQS get-queue-attributes or SNS get-topic-attributes", "resource"),
    (("policyText",), "aws ecr get-repository-policy", "resource"),
    (("ResourcePolicy",), "aws secretsmanager get-resource-policy", "resource"),
)


@dataclass
class Unwrapped:
    document: Any
    source: str | None = None  # the AWS command the document came from, when it was wrapped
    kind: str | None = None  # "resource" or "scp" when the wrapper says what the policy is


def looks_like_policy(value: Any) -> bool:
    return isinstance(value, dict) and "Statement" in value


def unwrap_policy(value: Any, where: str) -> Unwrapped:
    """Find the policy document in a value that is one, or that an AWS command wrapped it in."""
    value = document(value, where)
    if looks_like_policy(value) or not isinstance(value, dict):
        return Unwrapped(value)
    for path, source, kind in _WRAPPERS:
        node: Any = value
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            continue
        inner = document(node, where)
        if looks_like_policy(inner):
            return Unwrapped(inner, source, kind)
    return Unwrapped(value)


# --- what is this file? ------------------------------------------------------------------------------

KIND_LABELS = {
    "account": "an account export (aws iam get-account-authorization-details)",
    "policy": "a policy document",
    "policies": "a list of policy documents",
    "inventory": "a resource inventory (iam-trace inventory collect)",
    "usage": "last accessed data (iam-trace usage collect)",
    "credentials": "a credential report",
    "terraform": "a Terraform plan (terraform show -json)",
    "unknown": "something iam-trace does not recognise",
}


def detect(value: Any) -> str:
    """Which kind of input a parsed JSON value is (see KIND_LABELS)."""
    if isinstance(value, dict):
        if any(k in value for k in ("UserDetailList", "RoleDetailList", "GroupDetailList")):
            return "account"
        if "Reports" in value and isinstance(value["Reports"], dict):
            return "usage"
        if "Resources" in value and ("Collected" in value or isinstance(value.get("Resources"), list)):
            return "inventory"
        if "resource_changes" in value or "planned_values" in value or "terraform_version" in value:
            return "terraform"
        if "Content" in value and "GeneratedTime" in value:
            return "credentials"
        try:
            if looks_like_policy(unwrap_policy(value, "input").document):
                return "policy"
        except DocumentError:
            return "unknown"
        return "unknown"
    if isinstance(value, list) and value and all(isinstance(x, dict) and "Statement" in x for x in value):
        return "policies"
    return "unknown"


def wrong_kind(value: Any, expected: str, where: str) -> DocumentError | None:
    """An error naming what was given, if it is not what was expected."""
    got = detect(value)
    if got == expected or got == "unknown":
        return None
    if expected == "policy" and got == "policies":
        return None
    return DocumentError(f"{where}: this is {KIND_LABELS[got]}, not {KIND_LABELS[expected]}")
