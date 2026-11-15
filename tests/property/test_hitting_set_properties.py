"""The fix plan's solver against brute force: always a cheapest hitting set, never a wrong one."""

from __future__ import annotations

from itertools import combinations
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from iamtrace.fixplan import min_hitting_set

ELEMENTS = list("abcdefgh")


@st.composite
def instances(draw: st.DrawFn) -> tuple[list[frozenset[str]], dict[str, float]]:
    sets = draw(st.lists(st.frozensets(st.sampled_from(ELEMENTS), min_size=1, max_size=4), min_size=1, max_size=10))
    cost = {x: float(draw(st.integers(1, 4))) for x in ELEMENTS}
    return sets, cost


def brute_force(sets: list[frozenset[str]], cost: dict[str, float]) -> float:
    pool = sorted(set().union(*sets))
    best = float("inf")
    for k in range(len(pool) + 1):
        for combo in combinations(pool, k):
            if all(s & set(combo) for s in sets):
                best = min(best, sum(cost[x] for x in combo))
    return best


@given(instances())
def test_the_solver_finds_a_cheapest_hitting_set(inst: tuple[list[frozenset[str]], dict[str, Any]]) -> None:
    sets, cost = inst
    choice, optimal = min_hitting_set(sets, cost)
    assert optimal
    assert all(s & choice for s in sets), "every set is hit"
    assert sum(cost[x] for x in choice) == brute_force(sets, cost)


@given(instances())
def test_a_tiny_budget_still_returns_a_valid_cover(inst: tuple[list[frozenset[str]], dict[str, Any]]) -> None:
    sets, cost = inst
    choice, _ = min_hitting_set(sets, cost, budget=1)
    assert all(s & choice for s in sets)
