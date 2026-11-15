"""Hypothesis settings for the property tests.

By default the examples come from a fixed seed, so CI and the README test counts are stable.
Run many more, with fresh random examples, to look for bugs:

    HYPOTHESIS_PROFILE=deep pytest tests/property
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "default", max_examples=150, derandomize=True, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile(
    "deep", max_examples=3000, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large]
)
PROFILE = os.environ.get("HYPOTHESIS_PROFILE", "default")
settings.load_profile(PROFILE)
