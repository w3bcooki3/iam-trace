"""Hostile and broken input never crashes iam-trace.

Every function the web page calls, and every command-line command, is given random JSON and
randomly damaged copies of the example files (a value of the wrong type, a missing key, odd text
deep inside). Each must answer with a result or a clear error message, never an unexpected
exception ("This is a bug" from web_api, a traceback from the command line).
"""

from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from iamtrace import web_api
from iamtrace.cli import main
from tests.property.strategies import examples

ROOT = Path(__file__).resolve().parents[2]
EX = ROOT / "examples"
FILES = {
    "account": json.loads((EX / "account/auth-details.json").read_text()),
    "inventory": json.loads((EX / "account/inventory.json").read_text()),
    "usage": json.loads((EX / "account/last-accessed.json").read_text()),
    "plan": json.loads((EX / "terraform/plan.json").read_text()),
    "policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
}
CREDENTIALS = (EX / "account/credential-report.csv").read_text()
DEV = "arn:aws:iam::111122223333:user/dev"

ODD_TEXT = [
    "",
    " ",
    "﻿",
    "\x00",
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "${aws:username}",
    "${",
    "%7B%22",
    "*",
    "?",
    "arn:aws:iam::*:*",
    "arn:aws:iam::111122223333:role/",
    "‮​",
    "😀",
    "a" * 3000,
    "../../etc/passwd",
    "NaN",
]

json_leaves = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**70), 2**70),
    st.floats(allow_nan=False, allow_infinity=False),
    st.sampled_from(ODD_TEXT),
    st.text(max_size=20),
)
json_values = st.recursive(
    json_leaves,
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(
            st.text(max_size=12)
            | st.sampled_from(
                [
                    "Statement",
                    "Effect",
                    "Action",
                    "Resource",
                    "Condition",
                    "Principal",
                    "Arn",
                    "UserDetailList",
                    "RoleDetailList",
                    "Reports",
                    "Resources",
                    "resource_changes",
                    "PolicyVersionList",
                    "Document",
                ]
            ),
            inner,
            max_size=4,
        )
    ),
    max_leaves=12,
)


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    out = [prefix]
    if isinstance(value, dict):
        for k, v in value.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out += _paths(v, (*prefix, i))
    return out


@st.composite
def damaged(draw: st.DrawFn, name: str) -> str:
    """The example file with one to three random changes deep inside."""
    doc = copy.deepcopy(FILES[name])
    for _ in range(draw(st.integers(1, 3))):
        paths = _paths(doc)
        path = draw(st.sampled_from(paths))
        if not path:
            doc = draw(json_values)
            continue
        parent: Any = doc
        for key in path[:-1]:
            parent = parent[key]
        how = draw(st.sampled_from(["replace", "delete", "odd"]))
        if how == "delete":
            del parent[path[-1]]
        elif how == "odd":
            parent[path[-1]] = draw(st.sampled_from(ODD_TEXT))
        else:
            parent[path[-1]] = draw(json_values)
    return json.dumps(doc)


def _answer(fn: Any, *args: Any) -> dict[str, Any]:
    out = fn(*args)
    value = json.loads(out)
    assert isinstance(value, dict)
    assert "This is a bug" not in str(value.get("error", "")), value["error"]
    return value


# --- the web page's functions ---------------------------------------------------------------------

INPUT_OF = {
    "auth_details_text": "account",
    "inventory_text": "inventory",
    "usage_text": "usage",
    "plan_text": "plan",
    "policy_text": "policy",
    "old_text": "policy",
    "new_text": "policy",
    "scp_text": "policy",
    "resource_policy_text": "policy",
}
DEFAULTS: dict[str, Any] = {
    "principal": DEV,
    "action": "s3:GetObject",
    "resource": "*",
    "access": "read",
    "days": 90,
    "blast_radius": False,
    "include_gated": False,
    "include_aws_managed": False,
    "context_text": "aws:SourceIp=10.1.2.3",
    "credential_text": CREDENTIALS,
}
FUNCTIONS = [
    "can",
    "diff",
    "check",
    "who_can_query",
    "escalate",
    "escalate_account",
    "analyze_account",
    "fix_plan_query",
    "data_query",
    "unused_query",
    "terraform_query",
]


def _call_with(name: str, damaged_param: str | None, value: Any) -> dict[str, Any]:
    fn = getattr(web_api, name)
    args = []
    for p in inspect.signature(fn).parameters:
        if p == damaged_param:
            args.append(value)
        elif p in INPUT_OF:
            args.append(json.dumps(FILES[INPUT_OF[p]]))
        elif p == "request_json":
            args.append(
                json.dumps({"principal": DEV, "action": "s3:GetObject", "identity": [json.dumps(FILES["policy"])]})
            )
        elif p == "documents_json":
            args.append(json.dumps([{"name": "p", "text": json.dumps(FILES["policy"])}]))
        else:
            args.append(DEFAULTS.get(p, ""))
    return _answer(fn, *args)


def _text_params(name: str) -> list[str]:
    return [
        p
        for p in inspect.signature(getattr(web_api, name)).parameters
        if p in INPUT_OF or p.endswith(("_json", "_text"))
    ]


@pytest.mark.parametrize("name", FUNCTIONS)
@examples(25, 300)
@given(data=st.data())
def test_random_json_in_any_box_gets_an_answer(name: str, data: st.DataObject) -> None:
    param = data.draw(st.sampled_from(_text_params(name)))
    _call_with(name, param, json.dumps(data.draw(json_values)))


@pytest.mark.parametrize("name", FUNCTIONS)
@examples(25, 300)
@given(data=st.data())
def test_a_damaged_file_in_any_box_gets_an_answer(name: str, data: st.DataObject) -> None:
    param = data.draw(st.sampled_from(_text_params(name)))
    source = INPUT_OF.get(param, "policy")
    _call_with(name, param, data.draw(damaged(source)))


@examples(25, 300)
@given(
    st.sampled_from(["principal", "action", "resource", "access", "context_text", "credential_text"]),
    st.sampled_from(ODD_TEXT) | st.text(max_size=40),
)
def test_odd_text_in_the_small_fields_gets_an_answer(field: str, text: str) -> None:
    for name in ("analyze_account", "who_can_query", "data_query"):
        if field in inspect.signature(getattr(web_api, name)).parameters:
            _call_with(name, field, text)


# --- the command line ---------------------------------------------------------------------------------


COMMANDS = {
    "account": lambda f: ["escalate", "--auth-details", f, "--principal", DEV],
    "inventory": lambda f: [
        "escalate",
        "--auth-details",
        str(EX / "account/auth-details.json"),
        "--inventory",
        f,
        "--all",
    ],
    "usage": lambda f: ["unused", "--auth-details", str(EX / "account/auth-details.json"), "--usage", f],
    "plan": lambda f: ["terraform", f],
    "policy": lambda f: ["check", f],
}


@pytest.mark.parametrize("kind", sorted(COMMANDS))
@examples(15, 200)
@given(data=st.data())
def test_the_command_line_never_shows_a_traceback(
    kind: str, data: st.DataObject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    path = tmp_path_factory.mktemp("in") / "input.json"
    text = data.draw(damaged(kind) | json_values.map(json.dumps) | st.sampled_from(ODD_TEXT))
    path.write_text(text, encoding="utf-8")
    try:
        code = main(COMMANDS[kind](str(path)))
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
    assert code in (0, 1, 2)
