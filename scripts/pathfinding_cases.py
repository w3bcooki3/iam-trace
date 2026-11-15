"""Write tests/benchmark/pathfinding_cases.json from a checkout of pathfinding.cloud.

    git clone https://github.com/DataDog/pathfinding.cloud /tmp/pathfinding.cloud
    python3 scripts/pathfinding_cases.py /tmp/pathfinding.cloud

The cases keep what the benchmark needs from each AWS path, in upstream's words: the required
permissions, the category, the service principals the prerequisites say a role must trust, and
the prerequisites themselves. pathfinding.cloud is Apache-2.0, Copyright 2025-Present Datadog, Inc.
Requires PyYAML (a development tool only, not a dependency of iam-trace).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parents[1] / "tests" / "benchmark" / "pathfinding_cases.json"
SERVICE = re.compile(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.amazonaws\.com\b")


def prerequisites(p: dict) -> list[str]:
    pre = p.get("prerequisites") or {}
    if isinstance(pre, dict):
        return [str(x) for v in pre.values() for x in (v if isinstance(v, list) else [v])]
    return [str(x) for x in (pre if isinstance(pre, list) else [pre])]


def main(repo: str) -> None:
    root = Path(repo)
    commit = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    cases = []
    for f in sorted((root / "data" / "paths" / "aws").rglob("*.yaml")):
        p = yaml.safe_load(f.read_text())
        pre = prerequisites(p)
        cases.append(
            {
                "id": p["id"],
                "name": p["name"],
                "category": p["category"],
                "required": [x["permission"] for x in p["permissions"]["required"]],
                "trusts": sorted({m for line in pre for m in SERVICE.findall(line)}),
                "prerequisites": pre,
            }
        )
    data = {
        "source": "https://github.com/DataDog/pathfinding.cloud",
        "commit": commit,
        "license": "Apache-2.0, Copyright 2025-Present Datadog, Inc.",
        "cases": cases,
    }
    OUT.write_text(json.dumps(data, indent=1) + "\n")
    print(f"wrote {len(cases)} cases to {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
