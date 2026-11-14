"""Offline replay of stored differential fixtures.

A fixture is written whenever iam-trace and the AWS simulator disagreed. Each one asserts the
AWS answer. A fixture whose status is "open" is expected to fail until the engine is fixed (or
the case is explained in docs/limitations.md and its status set to "explained"); then set its
status to "fixed" and the test enforces it from then on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.differential.common import AWS_DECISIONS, OFFLINE, fill, iamtrace_decision
from tests.differential.generator import generate

FIXTURES = sorted(p for p in (Path(__file__).parent / "fixtures").glob("*.json") if p.name != "summary.json")


@pytest.mark.parametrize("path", FIXTURES, ids=[p.stem for p in FIXTURES])
def test_fixture(path: Path) -> None:
    fixture = json.loads(path.read_text())
    if "aws_decision" not in fixture:
        pytest.skip(f"AWS rejected this input: {fixture.get('aws_error')}")
    status = fixture.get("status", "open")
    if status == "explained":
        pytest.skip("difference documented in docs/limitations.md")
    case = fill(fixture["case"], OFFLINE)
    ours = iamtrace_decision(case, OFFLINE["{CALLER}"], OFFLINE["{ACCOUNT}"])
    expected = AWS_DECISIONS[fixture["aws_decision"]]
    if status == "open" and ours is not expected:
        pytest.xfail(f"open disagreement: AWS says {expected.value}, iam-trace says {ours.value}")
    assert ours is expected


@pytest.mark.parametrize("case", generate(), ids=lambda c: c["id"])
def test_generated_case_evaluates(case: dict) -> None:
    """Every generated case must at least parse and evaluate offline."""
    filled = fill(case, OFFLINE)
    iamtrace_decision(filled, OFFLINE["{CALLER}"], OFFLINE["{ACCOUNT}"])
