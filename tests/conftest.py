"""Shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from iamtrace.catalog import Catalog
from iamtrace.catalog.refresh import refresh
from tests.fixtures.servicereference import fake_fetch


@pytest.fixture(scope="session")
def catalog_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A catalog built by the real refresh code from synthetic service reference data."""
    out = tmp_path_factory.mktemp("catalog") / "catalog"
    refresh(out, fetch=fake_fetch, workers=2, log=lambda _: None)
    return out


@pytest.fixture(scope="session")
def catalog(catalog_dir: Path) -> Catalog:
    return Catalog.load(catalog_dir)
