"""tinyyaml — a dependency-free parser for the YAML subset used by
LiteLLM proxy configuration files.

Supported syntax:
  * comments (``#`` outside of quoted strings)
  * nested mappings via indentation
  * block lists (``- `` items), including lists of mappings
  * scalars: raw strings, quoted strings, ints, floats, booleans, null
  * inline empty maps/lists (``key: {}`` / ``key: []``)
  * simple inline lists (``key: [a, b, c]``)

Not supported (will not raise, values are kept best-effort):
  * anchors and aliases, multi-document streams, flow nesting

This is deliberately not a general YAML parser; it exists so litaudit can
run anywhere with zero dependencies. Garbage input still maps to data we
can reason about rather than crashing the audit.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple


class YamlError(ValueError):
    """Raised only for structurally impossible documents."""


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            out.append(ch)
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _scalar(tok: str) -> Any:
    tok = tok.strip()
    if tok == "" or tok == "~" or tok.lower() == "null":
        return None
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    low = tok.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"-?\d+", tok):
        try:
            return int(tok)
        except ValueError:
            return tok
    if re.fullmatch(r"-?\d+\.\d+", tok):
        try:
            return float(tok)
        except ValueError:
            return tok
    return tok




def _split_inline(inner: str) -> List[str]:
    parts: List[str] = []
    buf: List[str] = []
    quote = None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf or parts:
        parts.append("".join(buf))
    return parts


def _inline_list(tok: str) -> List[Any]:
    inner = tok.strip()[1:-1].strip()
    if not inner:
        return []
    return [_scalar(p) for p in _split_inline(inner)]


class _Parser:
    def __init__(self, text: str) -> None:
        self.lines: List[Tuple[int, str]] = []
        for lineno, raw in enumerate(text.splitlines(), 1):
            content = _strip_comment(raw)
            if not content.strip():
                continue
            indent = len(content) - len(content.lstrip(" "))
            self.lines.append((indent, content.strip()))
        self.i = 0

    def peek(self) -> Optional[Tuple[int, str]]:
        return self.lines[self.i] if self.i < len(self.lines) else None

    def _empty_value(self, tok: str, indent: int) -> Any:
        tok = tok.strip()
        if tok == "{}" or tok.endswith("{}"):
            return {}
        if tok.startswith("[") and tok.endswith("]"):
            return _inline_list(tok)
        return None

    def parse_block(self, indent: int) -> Any:
        """Parse a block whose first line is at exactly ``indent``."""
        first = self.peek()
        assert first is not None
        if first[1].startswith("- ") or first[1] == "-":
            return self.parse_list(indent)
        return self.parse_map(indent)

    def parse_map(self, indent: int) -> dict:
        result: dict = {}
        while True:
            cur = self.peek()
            if cur is None or cur[0] < indent or cur[1].startswith("- "):
                break
            if cur[0] > indent:
                # over-indented garbage inside a scalar context; absorb it
                # into an empty key so we never crash the audit.
                result.setdefault("_overindented_", []).append(cur[1])
                self.i += 1
                continue
            line = cur[1]
            self.i += 1
            key, sep, value = line.partition(":")
            key = key.strip().strip("'\"")
            value = value.strip()
            if not sep:
                continue
            if value == "":
                nxt = self.peek()
                if nxt is not None and nxt[0] > indent and not nxt[1].startswith("- "):
                    result[key] = self.parse_map(nxt[0])
                elif nxt is not None and nxt[0] > indent and nxt[1].startswith("- "):
                    result[key] = self.parse_list(nxt[0])
                elif nxt is not None and nxt[0] == indent and nxt[1].startswith("- "):
                    # list written at same indent as its key (common style)
                    result[key] = self.parse_list(nxt[0])
                else:
                    result[key] = None
            else:
                result[key] = self.parse_value_inline(value)
        return result

    def parse_list(self, indent: int) -> List[Any]:
        items: List[Any] = []
        # indent of the dash line
        dash_indent = indent
        while True:
            cur = self.peek()
            if cur is None or cur[0] != dash_indent or not cur[1].startswith("-"):
                break
            if cur[0] < dash_indent:
                break
            line = cur[1]
            self.i += 1
            rest = line[1:].strip()
            if not rest:
                nxt = self.peek()
                if nxt is not None and nxt[0] > dash_indent:
                    items.append(self.parse_block(nxt[0]))
                else:
                    items.append(None)
                continue
            key, sep, value = rest.partition(":")
            if not sep:
                items.append(self.parse_value_inline(rest))
                continue
            # "- key: value" — mapping item; child keys sit at dash_indent + 2
            child_indent = dash_indent + (len(line) - len(line[1:].lstrip())) - len(line) + 2
            # normalize: compute effective column of content after dash
            content_col = (len(cur[0] * " ") if False else 0)
            item: dict = {}
            k = key.strip().strip("'\"")
            value_s = value.strip()
            if value_s == "":
                nxt = self.peek()
                if nxt is not None and nxt[0] > dash_indent and not nxt[1].startswith("- "):
                    item[k] = self.parse_map(nxt[0])
                elif nxt is not None and nxt[0] > dash_indent and nxt[1].startswith("- "):
                    item[k] = self.parse_list(nxt[0])
                else:
                    item[k] = None
            else:
                item[k] = self.parse_value_inline(value_s)
            # continuation keys of this mapping item
            while True:
                nxt = self.peek()
                if nxt is None or nxt[0] <= dash_indent:
                    break
                nline = nxt[1]
                nkey, nsep, nvalue = nline.partition(":")
                if not nsep or nline.startswith("- "):
                    # nested list/value deeper inside — best effort scalar list
                    item.setdefault(nkey.strip().strip("'\"") or "_raw_", None)
                    self.i += 1
                    continue
                self.i += 1
                nk = nkey.strip().strip("'\"")
                nv = nvalue.strip()
                if nv == "":
                    after = self.peek()
                    if after is not None and after[0] > nxt[0] and not after[1].startswith("- "):
                        item[nk] = self.parse_map(after[0])
                    elif after is not None and after[0] > nxt[0] and after[1].startswith("- "):
                        item[nk] = self.parse_list(after[0])
                    else:
                        item[nk] = None
                else:
                    item[nk] = self.parse_value_inline(nv)
            items.append(item)
        return items

    def parse_value_inline(self, tok: str) -> Any:
        tok = tok.strip()
        if tok.startswith("[") and tok.endswith("]"):
            return _inline_list(tok)
        if tok == "{}":
            return {}
        return _scalar(tok)


def parse(text: str) -> dict:
    """Parse a YAML-subset document into a Python dict."""
    if text.lstrip().startswith("- "):
        raise YamlError("top-level sequences are not valid config documents")
    p = _Parser(text)
    if not p.lines:
        return {}
    p.prev_indent = p.lines[0][0]
    return p.parse_map(p.lines[0][0])
