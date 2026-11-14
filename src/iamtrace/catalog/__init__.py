"""The action catalog: every IAM action, with its access level, resource types and condition keys.

Source: AWS's machine-readable Service Authorization Reference
(https://docs.aws.amazon.com/service-authorization/latest/reference/service-reference.html).
`iam-trace catalog refresh` downloads it; refresh.py documents the format we store.

Access levels. The JSON has no access-level field. It has five boolean annotations instead
(IsDataPlane, IsList, IsPermissionManagement, IsTaggingOnly, IsWrite). iam-trace maps them to the
five access levels of the HTML reference in this order of precedence:

    IsPermissionManagement -> "Permissions management"
    IsTaggingOnly          -> "Tagging"
    IsWrite                -> "Write"
    IsList                 -> "List"
    none of the above      -> "Read"
    no annotations at all  -> "Unknown"

scripts/check_access_levels.py compares this mapping with the HTML pages and reports every
mismatch.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from iamtrace.wildcard import glob_match

ACCESS_LEVELS = ("Permissions management", "Write", "Tagging", "Read", "List", "Unknown")

PACKAGED = Path(__file__).parent / "data"


class CatalogMissing(RuntimeError):
    pass


def access_level(properties: dict[str, Any] | None) -> str:
    if not properties:
        return "Unknown"
    if properties.get("IsPermissionManagement"):
        return "Permissions management"
    if properties.get("IsTaggingOnly"):
        return "Tagging"
    if properties.get("IsWrite"):
        return "Write"
    if properties.get("IsList"):
        return "List"
    return "Read"


@dataclass(frozen=True)
class ActionInfo:
    service: str
    name: str
    access_level: str
    resource_types: tuple[str, ...]
    condition_keys: tuple[str, ...]
    data_plane: bool | None

    @property
    def full_name(self) -> str:
        return f"{self.service}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.full_name,
            "access_level": self.access_level,
            "resource_types": list(self.resource_types),
            "condition_keys": list(self.condition_keys),
        }


class Catalog:
    def __init__(self, services: dict[str, dict[str, ActionInfo]], meta: dict[str, Any]) -> None:
        self._services = services  # lowercase prefix -> lowercase action name -> info
        self.meta = meta

    # -- loading --------------------------------------------------------------

    @classmethod
    def load(cls, directory: str | Path | None = None) -> Catalog:
        path = _locate(directory)
        services: dict[str, dict[str, ActionInfo]] = {}
        for f in sorted((path / "services").glob("*.json")):
            data = json.loads(f.read_text(encoding="utf-8"))
            prefix = data["prefix"]
            actions = services.setdefault(prefix.lower(), {})
            for name, a in data["actions"].items():
                actions[name.lower()] = ActionInfo(
                    service=prefix,
                    name=name,
                    access_level=a["access_level"],
                    resource_types=tuple(a.get("resource_types", ())),
                    condition_keys=tuple(a.get("condition_keys", ())),
                    data_plane=a.get("data_plane"),
                )
        meta_file = path / "meta.json"
        meta = json.loads(meta_file.read_text()) if meta_file.exists() else {}
        meta["path"] = str(path)
        return cls(services, meta)

    # -- queries --------------------------------------------------------------

    @property
    def services(self) -> list[str]:
        return sorted(self._services)

    def get(self, action: str) -> ActionInfo | None:
        service, _, name = action.partition(":")
        return self._services.get(service.lower(), {}).get(name.lower())

    def all_actions(self) -> list[ActionInfo]:
        return [a for s in sorted(self._services) for _, a in sorted(self._services[s].items())]

    def expand(self, pattern: str) -> list[ActionInfo]:
        """Concrete actions matching an Action pattern (case-insensitive, * and ?)."""
        if pattern == "*":
            return self.all_actions()
        p_service, sep, p_name = pattern.partition(":")
        if not sep:
            return []
        out = []
        for service in sorted(self._services):
            if not glob_match(p_service, service, ignore_case=True):
                continue
            for _, a in sorted(self._services[service].items()):
                if glob_match(p_name, a.name, ignore_case=True):
                    out.append(a)
        return out

    def expand_not(self, patterns: tuple[str, ...] | list[str]) -> list[ActionInfo]:
        """Concrete actions NOT matched by any pattern (what NotAction covers)."""
        excluded = {a.full_name for p in patterns for a in self.expand(p)}
        return [a for a in self.all_actions() if a.full_name not in excluded]

    def __len__(self) -> int:
        return sum(len(v) for v in self._services.values())


def _locate(directory: str | Path | None) -> Path:
    candidates: list[Path] = []
    if directory:
        candidates.append(Path(directory))
    if os.environ.get("IAMTRACE_CATALOG"):
        candidates.append(Path(os.environ["IAMTRACE_CATALOG"]))
    candidates += [PACKAGED, user_cache_dir()]
    for c in candidates:
        if (c / "services").is_dir() and any((c / "services").glob("*.json")):
            return c
    raise CatalogMissing(
        "no action catalog found. Run `iam-trace catalog refresh` to download it from AWS "
        "(about 10 MB), or pass --catalog DIR."
    )


def user_cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "iamtrace" / "catalog"


@cache
def default_catalog() -> Catalog:
    return Catalog.load()
