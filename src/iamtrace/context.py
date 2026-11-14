"""The request context: the condition keys and values a request carries.

"Context key names are not case-sensitive" (Condition element docs), so lookups fold case while
keeping the original spelling for display.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any


def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


class Context(Mapping[str, tuple[str, ...]]):
    """Case-insensitive mapping of context key -> values.

    Every value is stored as a tuple of strings. A key given as a list is multivalued (for
    example aws:TagKeys); a key given as a scalar is single-valued. An empty list is kept: it is
    present but empty, which matters for ForAllValues and Null.
    """

    def __init__(self, values: Mapping[str, Any] | None = None) -> None:
        self._data: dict[str, tuple[str, tuple[str, ...], bool]] = {}
        for k, v in (values or {}).items():
            self.set(k, v)

    def set(self, key: str, value: Any) -> None:
        if isinstance(value, (list, tuple, set, frozenset)):
            self._data[key.lower()] = (key, tuple(_to_str(x) for x in value), True)
        else:
            self._data[key.lower()] = (key, (_to_str(value),), False)

    def setdefault_value(self, key: str, value: Any) -> None:
        if key.lower() not in self._data:
            self.set(key, value)

    def is_multivalued(self, key: str) -> bool:
        entry = self._data.get(key.lower())
        return bool(entry and entry[2])

    def copy(self) -> Context:
        c = Context()
        c._data = dict(self._data)
        return c

    def __getitem__(self, key: str) -> tuple[str, ...]:
        return self._data[key.lower()][1]

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key.lower() in self._data

    def __iter__(self) -> Iterator[str]:
        return (orig for orig, _, _ in self._data.values())

    def __len__(self) -> int:
        return len(self._data)

    def as_dict(self) -> dict[str, Any]:
        return {orig: (list(vals) if multi else vals[0]) for orig, vals, multi in self._data.values()}
