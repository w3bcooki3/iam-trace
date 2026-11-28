"""A small YAML reader for CloudFormation templates.

iam-trace has no runtime dependencies (it runs offline and in Pyodide), so it cannot use PyYAML. This reads
the part of YAML that CloudFormation templates use: block mappings and sequences, plain, quoted and block
scalars (| and >, with chomping), flow collections ([a, b], {k: v}), comments, and CloudFormation's short
tags (!Ref, !Sub, !GetAtt, ...), which become their long JSON forms ({"Ref": ...}, {"Fn::Sub": ...}).

Scalars are typed the way CloudFormation reads them: true/false, null, integers and floats; everything else,
dates included ("2012-10-17"), stays text. Anchors, aliases, merge keys and other tags are refused with a
clear message instead of being half-read. Input size and nesting depth are capped.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_TEXT = 5_000_000
MAX_DEPTH = 100

# Short tags -> the long form. GetAtt's scalar form "A.B" becomes ["A", "B"].
TAGS = {
    "Ref": "Ref",
    "Condition": "Condition",
    **{
        t: f"Fn::{t}"
        for t in (
            "Sub",
            "GetAtt",
            "Join",
            "If",
            "Select",
            "Split",
            "FindInMap",
            "ImportValue",
            "Base64",
            "Equals",
            "Not",
            "And",
            "Or",
            "GetAZs",
            "Cidr",
            "Transform",
            "Length",
            "ToJsonString",
        )
    },
}


class YamlError(ValueError):
    """Not a template this reader can read."""


def _scalar(s: str) -> Any:
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"[-+]?(0|[1-9][0-9]*)", s):
        return int(s)
    if re.fullmatch(r"[-+]?([0-9]+\.[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?", s):
        return float(s)
    return s


def _tagged(tag: str, value: Any, line: int) -> Any:
    if tag not in TAGS:
        raise YamlError(f"line {line}: the tag !{tag} is not one CloudFormation uses")
    if tag == "GetAtt" and isinstance(value, str):
        a, _, b = value.partition(".")
        value = [a, b]
    return {TAGS[tag]: value}


class _Reader:
    def __init__(self, text: str) -> None:
        if len(text) > MAX_TEXT:
            raise YamlError("the template is larger than 5 MB")
        self.lines: list[tuple[int, int, str]] = []  # (line number, indent, content without comment)
        for n, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
            if "\t" in raw[: len(raw) - len(raw.lstrip())]:
                raise YamlError(f"line {n}: tabs cannot indent YAML")
            body = raw.rstrip()
            stripped = body.lstrip(" ")
            if stripped in ("---", "...") or stripped.startswith("%"):
                continue
            self.lines.append((n, len(body) - len(stripped), body))
        self.i = 0
        self._cache: dict[int, tuple[tuple[int, int, str], str]] = {}

    # -- lines
    def _content(self, idx: int) -> str:
        """The line without a trailing comment, outside quotes (worked out once per line)."""
        got = self._cache.get(idx)
        if got is not None and got[0] is self.lines[idx]:
            return got[1]
        text = self._strip(self.lines[idx][2])
        self._cache[idx] = (self.lines[idx], text)
        return text

    @staticmethod
    def _strip(s: str) -> str:
        q, k = "", 0
        while k < len(s):
            ch = s[k]
            if q:
                if q == '"' and ch == "\\":
                    k += 2
                    continue
                if ch == q:
                    if q == "'" and s[k + 1 : k + 2] == "'":
                        k += 2
                        continue
                    q = ""
            elif ch in "'\"" and (k == 0 or s[k - 1] in " [{,:-!"):
                q = ch
            elif ch == "#" and (k == 0 or s[k - 1] == " "):
                return s[:k].rstrip()
            k += 1
        return s.rstrip()

    def _skip_blank(self) -> None:
        while self.i < len(self.lines) and not self._content(self.i).strip():
            self.i += 1

    def _peek(self) -> tuple[int, int, str] | None:
        self._skip_blank()
        if self.i >= len(self.lines):
            return None
        n, ind, _ = self.lines[self.i]
        return n, ind, self._content(self.i).strip()

    # -- nodes
    def document(self) -> Any:
        p = self._peek()
        if p is None:
            return None
        v = self.block(p[1], 0)
        if self._peek() is not None:
            n = self._peek()[0]  # type: ignore[index]
            raise YamlError(f"line {n}: unexpected text after the end of the document (check the indentation)")
        return v

    def block(self, indent: int, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise YamlError("the template is nested too deeply")
        p = self._peek()
        if p is None:
            return None
        n, ind, s = p
        if ind < indent:
            return None
        if s == "-" or s.startswith("- "):
            return self.sequence(ind, depth)
        if self._key(s) is not None:
            return self.mapping(ind, depth)
        # a scalar or flow node on its own line(s)
        self.i += 1
        return self.inline(s, n, ind, depth)

    def sequence(self, indent: int, depth: int) -> list[Any]:
        out: list[Any] = []
        while True:
            p = self._peek()
            if p is None or p[1] != indent or not (p[2] == "-" or p[2].startswith("- ")):
                if p is not None and p[1] > indent:
                    raise YamlError(f"line {p[0]}: bad indentation in a list")
                return out
            n, _, s = p
            rest = s[1:].lstrip()
            if not rest:
                self.i += 1
                out.append(self.block(indent + 1, depth + 1))
                continue
            col = indent + (len(s) - len(rest))
            if rest == "-" or rest.startswith("- "):
                # "- - x": a list inside a list, indented to where the inner dash is
                self.lines[self.i] = (n, col, " " * col + rest)
                out.append(self.sequence(col, depth + 1))
                continue
            if self._key(rest) is not None:
                # "- key: value" opens a mapping indented to where "key" starts
                self.lines[self.i] = (n, col, " " * col + rest)
                out.append(self.mapping(col, depth + 1))
                continue
            self.i += 1
            out.append(self.inline(rest, n, indent, depth + 1))

    def _key(self, s: str) -> tuple[str, str] | None:
        """(key, rest) when s is "key: value" or "key:", else None."""
        if s.startswith(('"', "'")):
            q = s[0]
            k = 1
            while k < len(s):
                if s[k] == q:
                    if q == "'" and k + 1 < len(s) and s[k + 1] == "'":
                        k += 2
                        continue
                    break
                if q == '"' and s[k] == "\\":
                    k += 1
                k += 1
            if k < len(s) and s[k + 1 : k + 2] == ":" and (k + 2 == len(s) or s[k + 2] == " "):
                return _unquote(s[: k + 1], 0), s[k + 2 :].strip()
            return None
        if s.startswith(("[", "{", "!", "|", ">", "&", "*", "?")):
            return None
        m = re.match(r"([^#:\s][^:]*?|[^#:\s]):(?:\s+(.*))?$", s)
        if not m:
            return None
        return m.group(1).rstrip(), (m.group(2) or "").strip()

    def mapping(self, indent: int, depth: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        while True:
            p = self._peek()
            if p is None or p[1] != indent:
                if p is not None and p[1] > indent:
                    raise YamlError(f"line {p[0]}: bad indentation")
                return out
            n, _, s = p
            kv = self._key(s)
            if kv is None:
                if s.startswith("- "):
                    return out
                raise YamlError(f'line {n}: expected "key: value"')
            key, rest = kv
            if key == "<<":
                raise YamlError(f"line {n}: merge keys (<<) are not supported in templates here")
            if key in out:
                raise YamlError(f"line {n}: the key {key!r} appears twice")
            self.i += 1
            if not rest:
                nxt = self._peek()
                if nxt is not None and (
                    nxt[1] > indent or (nxt[1] == indent and (nxt[2] == "-" or nxt[2].startswith("- ")))
                ):
                    out[key] = self.block(nxt[1], depth + 1)
                else:
                    out[key] = None
            else:
                out[key] = self.inline(rest, n, indent, depth + 1)

    def inline(self, s: str, n: int, indent: int, depth: int) -> Any:
        """A value that starts on a line: tag, block scalar, flow collection, quoted or plain scalar."""
        if s.startswith(("&", "*")):
            raise YamlError(f"line {n}: anchors and aliases are not supported in templates here")
        if s.startswith("!"):
            m = re.match(r"!([A-Za-z]+)(?:\s+(.*))?$", s)
            if not m:
                raise YamlError(f"line {n}: cannot read the tag in {s[:40]!r}")
            tag, rest = m.group(1), (m.group(2) or "").strip()
            if not rest:
                nxt = self._peek()
                value = self.block(nxt[1], depth + 1) if nxt is not None and nxt[1] > indent else ""
            else:
                value = self.inline(rest, n, indent, depth + 1)
            return _tagged(tag, value, n)
        if s[0] in "|>":
            return self.block_scalar(s, n, indent)
        if s[0] in "[{":
            text = s
            while not _balanced(text):
                if self.i >= len(self.lines):
                    raise YamlError(f"line {n}: a [ or {{ is never closed")
                text += " " + self._content(self.i).strip()
                self.i += 1
            v, end = _Flow(text, n).value(0, depth)
            if text[end:].strip():
                raise YamlError(f"line {n}: unexpected text after a closing bracket")
            return v
        if s[0] in "\"'":
            text = s
            while not _closed_quote(text):
                if self.i >= len(self.lines):
                    raise YamlError(f"line {n}: a quote is never closed")
                text += "\n" + self.lines[self.i][2].strip()
                self.i += 1
            v = _unquote(text, n)
            return v
        # plain scalar, possibly continued on more-indented lines
        parts = [s]
        while True:
            p = self._peek()
            if p is None or p[1] <= indent or self._key(p[2]) is not None or p[2].startswith("- "):
                break
            parts.append(p[2])
            self.i += 1
        if len(parts) == 1:
            return _scalar(s)
        return " ".join(parts)

    def block_scalar(self, head: str, n: int, indent: int) -> str:
        m = re.fullmatch(r"([|>])([-+]?)([1-9]?)([-+]?)", head)
        if not m:
            raise YamlError(f"line {n}: cannot read the block scalar header {head!r}")
        style, chomp = m.group(1), m.group(2) or m.group(4)
        body: list[str] = []
        block_indent = indent + int(m.group(3)) if m.group(3) else None
        while self.i < len(self.lines):
            _, ind, raw = self.lines[self.i]
            if raw.strip() == "":
                body.append("")
                self.i += 1
                continue
            if block_indent is None:
                if ind <= indent:
                    break
                block_indent = ind
            if ind < block_indent:
                break
            body.append(raw[block_indent:])
            self.i += 1
        while body and body[-1] == "" and chomp != "+":
            body.pop()
        if style == "|":
            text = "\n".join(body)
        else:
            text, prev_blank = "", True
            for line in body:
                if line == "":
                    text += "\n"
                    prev_blank = True
                elif line.startswith(" "):
                    text += ("\n" if text and not text.endswith("\n") else "") + line + "\n"
                    prev_blank = True
                else:
                    text += ("" if prev_blank else " ") + line
                    prev_blank = False
            text = text.rstrip("\n") if chomp != "+" else text
        return text if chomp == "-" else text + "\n" if chomp == "" else text + "\n"


def _balanced(s: str) -> bool:
    """Every [ and { is closed (in the right order); a wrong closing bracket ends the scan as balanced, and the
    flow reader then reports it."""
    stack: list[str] = []
    q, k = "", 0
    while k < len(s):
        ch = s[k]
        if q:
            if q == '"' and ch == "\\":
                k += 2
                continue
            if ch == q and not (q == "'" and s[k + 1 : k + 2] == "'"):
                q = ""
            elif ch == q:
                k += 1
        elif ch in "\"'":
            q = ch
        elif ch in "[{":
            stack.append("]" if ch == "[" else "}")
        elif ch in "]}":
            if not stack or stack.pop() != ch:
                return True
        k += 1
    return not stack


def _closed_quote(s: str) -> bool:
    q, k = s[0], 1
    while k < len(s):
        if s[k] == "\\" and q == '"':
            k += 2
            continue
        if s[k] == q:
            if q == "'" and s[k + 1 : k + 2] == "'":
                k += 2
                continue
            return True
        k += 1
    return False


def _unquote(s: str, n: int) -> str:
    q = s[0]
    end = len(s) - 1
    while end > 0 and s[end] != q:
        end -= 1
    if s[end + 1 :].strip():
        raise YamlError(f"line {n}: unexpected text after a quoted value")
    inner = s[1:end]
    if q == "'":
        return re.sub(r"\s*\n\s*", " ", inner).replace("''", "'")
    inner = re.sub(r"\s*\n\s*", " ", inner)
    try:
        return str(json.loads('"' + inner.replace("\\'", "'").replace("\\/", "/") + '"'))
    except json.JSONDecodeError as e:
        raise YamlError(f"line {n}: cannot read the quoted text ({e.msg})") from None


class _Flow:
    """[a, b, {k: v}] on one logical line."""

    def __init__(self, s: str, n: int) -> None:
        self.s, self.n = s, n

    def _ws(self, k: int) -> int:
        while k < len(self.s) and self.s[k] == " ":
            k += 1
        return k

    def value(self, k: int, depth: int) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise YamlError("the template is nested too deeply")
        k = self._ws(k)
        s = self.s
        if k >= len(s):
            return None, k
        ch = s[k]
        if ch == "[":
            out: list[Any] = []
            k = self._ws(k + 1)
            while k < len(s) and s[k] != "]":
                if s[k] in "}:":
                    raise YamlError(f"line {self.n}: a [ is closed with {s[k]!r}")
                v, k2 = self.value(k, depth + 1)
                if k2 <= k:
                    raise YamlError(f"line {self.n}: cannot read the list at {s[k : k + 20]!r}")
                out.append(v)
                k = self._ws(k2)
                if k < len(s) and s[k] == ",":
                    k = self._ws(k + 1)
                elif k < len(s) and s[k] != "]":
                    raise YamlError(f"line {self.n}: expected , or ] at {s[k : k + 20]!r}")
            if k >= len(s):
                raise YamlError(f"line {self.n}: a [ is never closed")
            return out, k + 1
        if ch == "{":
            obj: dict[str, Any] = {}
            k = self._ws(k + 1)
            while k < len(s) and s[k] != "}":
                if s[k] in "]:,":
                    raise YamlError(f"line {self.n}: unexpected {s[k]!r} in a {{ }} mapping")
                key, k2 = self.value(k, depth + 1)
                if k2 <= k:
                    raise YamlError(f"line {self.n}: cannot read the mapping at {s[k : k + 20]!r}")
                k = self._ws(k2)
                if k < len(s) and s[k] == ":":
                    v, k = self.value(k + 1, depth + 1)
                else:
                    v = None
                obj[str(key)] = v
                k = self._ws(k)
                if k < len(s) and s[k] == ",":
                    k = self._ws(k + 1)
                elif k < len(s) and s[k] != "}":
                    raise YamlError(f"line {self.n}: expected , or }} at {s[k : k + 20]!r}")
            if k >= len(s):
                raise YamlError(f"line {self.n}: a {{ is never closed")
            return obj, k + 1
        if ch == "!":
            m = re.match(r"!([A-Za-z]+)\s*", s[k:])
            if not m:
                raise YamlError(f"line {self.n}: cannot read a tag")
            v, k2 = self.value(k + m.end(), depth + 1)
            return _tagged(m.group(1), v, self.n), k2
        if ch in "\"'":
            e = k + 1
            while e < len(s):
                if ch == '"' and s[e] == "\\":
                    e += 2
                    continue
                if s[e] == ch:
                    if ch == "'" and s[e + 1 : e + 2] == "'":
                        e += 2
                        continue
                    break
                e += 1
            return _unquote(s[k : e + 1], self.n), e + 1
        m = re.match(r"[^,\[\]{}]*?(?=\s*(?:,|\]|\}|:\s|:$))|[^,\[\]{}]+", s[k:])
        text = m.group(0) if m else ""
        return _scalar(text.strip()), k + len(text)


def loads(text: str) -> Any:
    """Read a CloudFormation template written in YAML (or JSON, which is YAML too)."""
    stripped = text.lstrip("﻿ \n\r\t")
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as e:
            raise YamlError(f"line {e.lineno}: {e.msg}") from None
        except RecursionError:
            raise YamlError("the template is nested too deeply") from None
    return _Reader(text.lstrip("﻿")).document()
