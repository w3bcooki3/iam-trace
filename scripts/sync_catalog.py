"""Rewrite src/iamtrace/data/escalation_paths.json from a checkout of pathfinding.cloud.

    git clone https://github.com/DataDog/pathfinding.cloud /tmp/pathfinding.cloud
    python3 scripts/sync_catalog.py /tmp/pathfinding.cloud

Keeps the AWS paths only, with their required permissions, category and first documentation.
Paths removed or renamed upstream are dropped. Run tests/benchmark/bench.py afterwards: a new
path or a changed permission list may need engine work before it is detected.
pathfinding.cloud is Apache-2.0, Copyright 2025-Present Datadog, Inc. Requires PyYAML.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

OUT = Path(__file__).resolve().parents[1] / "src" / "iamtrace" / "data" / "escalation_paths.json"


def main(repo: str) -> None:
    paths = []
    for f in sorted((Path(repo) / "data" / "paths" / "aws").rglob("*.yaml")):
        p = yaml.safe_load(f.read_text())
        first = (p.get("discoveryAttribution") or {}).get("firstDocumented") or {}
        paths.append(
            {
                "category": p["category"],
                "first_documented": {k: first[k] for k in ("author", "link", "organization") if first.get(k)}
                or ({"author": first["source"]} if first.get("source") else {}),
                "id": p["id"],
                "name": p["name"],
                "pathfinding_url": f"https://pathfinding.cloud/paths/{p['id']}",
                "permissions": [x["permission"] for x in p["permissions"]["required"]],
            }
        )
    old = {p["id"] for p in json.loads(OUT.read_text())["paths"]}
    new = {p["id"] for p in paths}
    data = {"license": "Apache-2.0", "paths": paths, "source": "https://github.com/DataDog/pathfinding.cloud"}
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    print(f"{len(paths)} paths; added {sorted(new - old)}; removed {sorted(old - new)}")


if __name__ == "__main__":
    main(sys.argv[1])
