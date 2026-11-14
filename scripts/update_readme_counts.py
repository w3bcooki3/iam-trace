"""Write the real test counts into README.md between the counts markers.

    python scripts/update_readme_counts.py          # rewrite README.md
    python scripts/update_readme_counts.py --check  # exit 1 if README.md is out of date (CI)

Offline counts come from running pytest. Differential counts come from
tests/differential/fixtures/summary.json, written by the last live run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SUMMARY = ROOT / "tests" / "differential" / "fixtures" / "summary.json"
START, END = "<!-- counts:start -->", "<!-- counts:end -->"


def offline_counts() -> dict[str, int]:
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    ).stdout
    last = out.strip().splitlines()[-1] if out.strip() else ""
    counts = {k: 0 for k in ("passed", "failed", "skipped", "xfailed")}
    for n, word in re.findall(r"(\d+) (passed|failed|skipped|xfailed)", last):
        counts[word] = int(n)
    return counts


def render() -> str:
    c = offline_counts()
    lines = [
        START,
        f"Offline tests: **{c['passed']} passed**, {c['failed']} failed, {c['xfailed']} expected failures "
        f"(open differential disagreements), {c['skipped']} skipped.",
        "",
    ]
    if SUMMARY.exists():
        s = json.loads(SUMMARY.read_text())
        lines.append(
            f"Last live differential run ({s['date']}): iam-trace agreed with `iam:SimulateCustomPolicy` on "
            f"**{s['agree']} of {s['compared']}** cases; {s['disagree']} disagreements are stored as fixtures; "
            f"AWS rejected {s['aws_errors']} inputs."
        )
    else:
        lines.append('Live differential run: **not run yet**. See "Differential testing" below.')
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = README.read_text()
    pattern = re.compile(re.escape(START) + ".*?" + re.escape(END), re.DOTALL)
    if not pattern.search(text):
        print("README.md has no counts markers", file=sys.stderr)
        return 1
    new = pattern.sub(lambda _: render(), text)
    if args.check:
        if new != text:
            print("README.md test counts are out of date; run scripts/update_readme_counts.py", file=sys.stderr)
            return 1
        return 0
    README.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
