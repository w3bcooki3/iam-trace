"""Compare iam-trace's derived access levels with the HTML Service Authorization Reference.

The JSON reference has no access-level field (see src/iamtrace/catalog/__init__.py), so iam-trace
derives it from annotation flags. This script reads the HTML pages, where AWS shows the access
level in a column, and lists every action where the two disagree.

    python scripts/check_access_levels.py --catalog src/iamtrace/catalog/data [--services s3,iam] [--out report.md]

Exit code 0 when everything matches, 1 when there are mismatches, 2 on fetch/parse failure.

The HTML parser expects the documented layout: a table whose header row contains "Actions" and
"Access level"; rows with the full number of cells start a new action, rows with fewer cells
continue the previous action (extra resource types). The page states the service prefix as
"(service prefix: xyz)". If AWS changes the layout the script fails loudly instead of reporting
false matches.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iamtrace.catalog import Catalog  # noqa: E402

BASE = "https://docs.aws.amazon.com/service-authorization/latest/reference/"
INDEX = BASE + "reference_policies_actions-resources-contextkeys.html"
PREFIX = re.compile(r"\(service prefix:\s*([a-z0-9-]+)\s*\)", re.IGNORECASE)


class _Tables(HTMLParser):
    """Collect every table as rows of cell texts, plus all page text and links."""

    def __init__(self) -> None:
        super().__init__()
        self.tables: list[list[list[str]]] = []
        self.links: list[str] = []
        self.text: list[str] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            self.tables.append([])
            self._depth += 1
        elif tag == "tr" and self._depth:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.tables[-1].append(self._row)
            self._row = None
        elif tag == "table":
            self._depth -= 1

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self._cell is not None:
            self._cell.append(data)


def parse_page(html: str) -> tuple[str | None, dict[str, str]]:
    """Return (service prefix, {action name: access level}) for one service page."""
    p = _Tables()
    p.feed(html)
    m = PREFIX.search(" ".join(p.text))
    prefix = m.group(1).lower() if m else None
    levels: dict[str, str] = {}
    for table in p.tables:
        if not table:
            continue
        header = [h.lower() for h in table[0]]
        if "access level" not in header or not header[0].startswith("action"):
            continue
        col = header.index("access level")
        width = len(header)
        for row in table[1:]:
            if len(row) != width:
                continue  # continuation row for an extra resource type
            name = row[0].replace("[permission only]", "").strip()
            if name:
                levels[name] = row[col]
        break
    return prefix, levels


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "iamtrace-access-level-check"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        data: bytes = resp.read()
    return data.decode("utf-8", errors="replace")


def compare(cat: Catalog, pages: dict[str, dict[str, str]]) -> list[tuple[str, str, str]]:
    mismatches = []
    for prefix, levels in sorted(pages.items()):
        for name, html_level in sorted(levels.items()):
            info = cat.get(f"{prefix}:{name}")
            # The HTML can list several levels for one action ("Tagging, Write"); iam-trace derives
            # one. It matches when its level is among the listed ones.
            listed = {level.strip() for level in html_level.split(",")}
            if info is None:
                mismatches.append((f"{prefix}:{name}", html_level, "(not in JSON)"))
            elif info.access_level not in listed:
                mismatches.append((info.full_name, html_level, info.access_level))
    return mismatches


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--services", help="comma-separated prefixes to check (default: all)")
    ap.add_argument("--out", help="write a Markdown report here")
    args = ap.parse_args()
    cat = Catalog.load(args.catalog)
    wanted = set(args.services.split(",")) if args.services else None

    index = _Tables()
    index.feed(fetch(INDEX))
    urls = sorted({BASE + h.split("#")[0].lstrip("./") for h in index.links if h.lstrip("./").startswith("list_")})
    if not urls:
        print("no service pages found on the index page; the layout may have changed", file=sys.stderr)
        return 2

    pages: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for prefix, levels in pool.map(lambda u: parse_page(fetch(u)), urls):
            if prefix and (wanted is None or prefix in wanted):
                pages.setdefault(prefix, {}).update(levels)
    if not pages or not any(pages.values()):
        print("parsed no access levels; the page layout may have changed", file=sys.stderr)
        return 2

    mismatches = compare(cat, pages)
    checked = sum(len(v) for v in pages.values())
    lines = [f"Checked {checked} actions in {len(pages)} services: {len(mismatches)} mismatches.", ""]
    if mismatches:
        lines += ["| Action | HTML access level | iam-trace (from JSON flags) |", "|---|---|---|"]
        lines += [f"| `{a}` | {h} | {j} |" for a, h, j in mismatches]
    report = "\n".join(lines) + "\n"
    print(report)
    if args.out:
        Path(args.out).write_text(report)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
