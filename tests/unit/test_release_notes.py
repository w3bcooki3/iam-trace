"""scripts/release_notes.py extracts one version's notes and refuses undated releases."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "release_notes", Path(__file__).parents[2] / "scripts" / "release_notes.py"
)
assert _spec and _spec.loader
release_notes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release_notes)

CHANGELOG = """# Changelog

## [0.3.0] - 2026-12-01

### Added

- New thing.

## [0.2.0] - unreleased

- Old thing.
"""


def test_extracts_only_that_version() -> None:
    rest, body = release_notes.section(CHANGELOG, "0.3.0")
    assert rest == "- 2026-12-01"
    assert "New thing" in body and "Old thing" not in body


def test_missing_version() -> None:
    with pytest.raises(KeyError):
        release_notes.section(CHANGELOG, "9.9.9")


def test_real_changelog_has_current_version() -> None:
    from iamtrace import __version__

    text = (Path(__file__).parents[2] / "CHANGELOG.md").read_text(encoding="utf-8")
    _, body = release_notes.section(text, __version__)
    assert body.strip()
