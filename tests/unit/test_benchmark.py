"""The pathfinding.cloud benchmark (tests/benchmark/bench.py): no path may get worse.

Each AWS path in pathfinding.cloud must be detected as well as tests/benchmark/expected.json
records, and must raise no false alarm in its near misses. After improving the engine, or after
updating the cases from upstream, run `python3 tests/benchmark/bench.py --write` and commit the
new expected.json and docs/coverage.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from iamtrace.escalate import technique_catalog

BENCH = Path(__file__).resolve().parents[1] / "benchmark"
sys.path.insert(0, str(BENCH))
import bench  # noqa: E402

EXPECTED = {r["id"]: r for r in json.loads((BENCH / "expected.json").read_text())}
RANK = {"missed": 0, "possible": 1, "confirmed": 2}


@pytest.fixture(scope="module")
def results() -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in bench.run()}


@pytest.mark.parametrize("case_id", sorted(EXPECTED))
def test_path_is_detected_as_before(results: dict[str, dict[str, Any]], case_id: str) -> None:
    got, want = results[case_id], EXPECTED[case_id]
    assert RANK[got["detect"]] >= RANK[want["detect"]], f"{case_id}: {got['detect']}, was {want['detect']}"
    if "detect_inventory" in want:
        assert RANK[got["detect_inventory"]] >= RANK[want["detect_inventory"]]


@pytest.mark.parametrize("case_id", sorted(EXPECTED))
def test_near_misses_stay_clean(results: dict[str, dict[str, Any]], case_id: str) -> None:
    assert results[case_id]["false_alarms"] == []


def test_every_case_is_in_the_catalog_and_the_other_way_round() -> None:
    cases = {c["id"]: c for c in bench.load_cases()}
    catalog = {t["id"]: t for t in technique_catalog()}
    assert set(cases) == set(catalog) == set(EXPECTED)
    for cid, case in cases.items():
        assert sorted(p.lower() for p in case["required"]) == sorted(p.lower() for p in catalog[cid]["permissions"])


def test_coverage_page_is_up_to_date(results: dict[str, dict[str, Any]]) -> None:
    ordered = [results[c["id"]] for c in bench.load_cases()]
    page = (BENCH.parents[1] / "docs" / "coverage.md").read_text()
    assert page == bench.coverage_markdown(ordered), "run python3 tests/benchmark/bench.py --write"
