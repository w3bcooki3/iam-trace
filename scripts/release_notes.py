"""Print the CHANGELOG.md section for one version, for the GitHub release notes.

    python scripts/release_notes.py 0.2.0 > notes.md

Fails (exit 1) when the version has no section, or when its heading still says "unreleased":
a release must have a date, written as `## [0.2.0] - 2026-11-20`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?P<rest>.*)$")


def section(changelog: str, version: str) -> tuple[str, str]:
    """Return (heading suffix, body) for `version`; raise KeyError if it is missing."""
    lines = changelog.splitlines()
    for i, line in enumerate(lines):
        m = HEADING.match(line)
        if m and m.group("version") == version:
            body = []
            for nxt in lines[i + 1 :]:
                if HEADING.match(nxt):
                    break
                body.append(nxt)
            return m.group("rest").strip(), "\n".join(body).strip() + "\n"
    raise KeyError(version)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    text = (Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        rest, body = section(text, version)
    except KeyError:
        print(f"CHANGELOG.md has no section for {version}", file=sys.stderr)
        return 1
    if "unreleased" in rest.lower() or not re.search(r"\d{4}-\d{2}-\d{2}", rest):
        print(f"CHANGELOG.md section for {version} has no release date: '## [{version}] {rest}'", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
