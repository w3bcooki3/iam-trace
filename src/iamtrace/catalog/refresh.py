"""Download the Service Authorization Reference JSON and store a compact copy.

Endpoints (https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html):
    https://servicereference.us-east-1.amazonaws.com/              index: [{"service", "url"}]
    https://servicereference.us-east-1.amazonaws.com/v1/<s>/<s>.json  one service

Stored layout (deterministic, so the weekly PR diff is readable):

    <dir>/meta.json                {"source", "service_count", "action_count"}
    <dir>/services/<prefix>.json   {"prefix", "name", "actions": {Name: {...}}, "resources": {...},
                                    "condition_keys": {...}}

Each action keeps: access_level (derived, see catalog/__init__.py), the raw annotation flags,
resource_types, condition_keys and data_plane. Fields AWS omits are stored as empty lists.

The output directory is replaced as a whole, so keep nothing else in it.

This is the only network code in the package. It is never used at evaluation time.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from iamtrace.catalog import access_level

INDEX_URL = "https://servicereference.us-east-1.amazonaws.com/"
SERVICE_URL = re.compile(r"^https://servicereference\.us-east-1\.amazonaws\.com/v1/[a-z0-9-]+/[a-z0-9-]+\.json$")
PREFIX = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
USER_AGENT = "iamtrace-catalog-refresh (+https://github.com/w3bcooki3/iam-trace)"

Fetch = Callable[[str], Any]


def http_get_json(url: str, attempts: int = 4) -> Any:
    delay = 1.0
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https URL)
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")


def compact_service(raw: dict[str, Any]) -> dict[str, Any]:
    """Reduce one service reference file to what iam-trace uses."""
    if not isinstance(raw, dict) or not isinstance(raw.get("Name"), str) or not PREFIX.match(raw["Name"]):
        # The prefix becomes a file name, so anything unexpected is rejected rather than written.
        raise RuntimeError(f"unexpected service name in the service reference: {str(raw.get('Name'))[:80]!r}")
    actions: dict[str, Any] = {}
    for a in raw.get("Actions") or []:
        props = (a.get("Annotations") or {}).get("Properties")
        actions[a["Name"]] = {
            "access_level": access_level(props),
            "flags": {k: bool(v) for k, v in sorted((props or {}).items())},
            "resource_types": sorted(r["Name"] for r in a.get("Resources") or []),
            "condition_keys": sorted(a.get("ActionConditionKeys") or []),
            "data_plane": (props or {}).get("IsDataPlane"),
        }
    resources = {r["Name"]: sorted(r.get("ARNFormats") or []) for r in raw.get("Resources") or []}
    keys = {k["Name"]: sorted(k.get("Types") or []) for k in raw.get("ConditionKeys") or []}
    return {
        "prefix": raw["Name"],
        "name": raw.get("ServiceName", raw["Name"]),
        "actions": dict(sorted(actions.items())),
        "resources": dict(sorted(resources.items())),
        "condition_keys": dict(sorted(keys.items())),
    }


def refresh(
    out_dir: Path, fetch: Fetch = http_get_json, workers: int = 8, log: Callable[[str], None] = print
) -> dict[str, Any]:
    index = fetch(INDEX_URL)
    if not isinstance(index, list) or not index:
        raise RuntimeError("unexpected service reference index format")
    entries = sorted(index, key=lambda e: e["service"])
    log(f"fetching {len(entries)} services")

    def one(entry: dict[str, str]) -> dict[str, Any]:
        url = entry.get("url", "")
        if not SERVICE_URL.match(url):
            raise RuntimeError(f"unexpected URL in the service reference index: {url[:120]!r}")
        return compact_service(fetch(url))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        services = list(pool.map(one, entries))

    check_replaceable(out_dir)
    # Write to a temporary directory first so a failed run never leaves a half catalog.
    tmp = out_dir.with_name(out_dir.name + ".tmp")
    if tmp.exists():
        _rmtree(tmp)
    (tmp / "services").mkdir(parents=True)
    actions = 0
    for s in services:
        actions += len(s["actions"])
        (tmp / "services" / f"{s['prefix']}.json").write_text(json.dumps(s, indent=1, sort_keys=False) + "\n")
    meta = {"source": INDEX_URL, "service_count": len(services), "action_count": actions}
    (tmp / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    if out_dir.exists():
        _rmtree(out_dir)
    tmp.rename(out_dir)
    log(f"wrote {len(services)} services, {actions} actions to {out_dir}")
    return meta


def check_replaceable(out_dir: Path) -> None:
    """Refuse to replace a directory that is not a catalog: the refresh deletes the old one."""
    if not out_dir.exists():
        return
    if not out_dir.is_dir():
        raise RuntimeError(f"{out_dir} exists and is not a directory")
    entries = {p.name for p in out_dir.iterdir()}
    if entries and not entries <= {"meta.json", "services"}:
        raise RuntimeError(
            f"{out_dir} contains files that are not an iam-trace catalog ({', '.join(sorted(entries)[:5])}); "
            "choose an empty or new directory"
        )
    if (out_dir / "services").is_dir() and any(p.suffix != ".json" for p in (out_dir / "services").iterdir()):
        raise RuntimeError(f"{out_dir}/services contains files that are not catalog files; refusing to replace it")


def _rmtree(path: Path) -> None:
    for child in sorted(path.rglob("*"), reverse=True):
        child.rmdir() if child.is_dir() else child.unlink()
    path.rmdir()


if __name__ == "__main__":
    refresh(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src/iamtrace/catalog/data"))
