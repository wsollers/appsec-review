"""Line and function attribution over the reviewed snapshot.

Function boundaries come only from accepted Tree-sitter node records; this module never parses
source itself.  Lines are attributed to the change that last touched them through ``git blame`` at the
snapshot commit, so function-level change sets contain only changes with surviving lines.  That is
an under-approximation, recorded as the ``surviving-line`` attribution method.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from pathlib import Path
import re
from typing import Any


ATTRIBUTION_IDENTITY = "appsec-review/change-context-attribution/1"
# Grammar node types that delimit a named callable body, by Tree-sitter grammar.
FUNCTION_TYPES = frozenset({
    "function_definition", "function_declaration", "method_declaration", "method_definition",
    "constructor_declaration", "function_item", "generator_function_declaration", "local_function_statement",
})
_NAME_TYPES = frozenset({"identifier", "field_identifier", "qualified_identifier", "property_identifier",
                         "name", "destructor_name", "operator_name", "type_identifier"})
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_:.~<>$-]")
_BLAME_HEADER = re.compile(rb"([0-9a-f]{40}|[0-9a-f]{64}) (\d+) (\d+)(?: \d+)?")
_HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def parse_blame_lines(data: bytes) -> list[tuple[str, str]]:
    """Return ``(commit, author_email)`` for every final line of ``blame --porcelain`` output."""
    authors: dict[str, str] = {}
    lines: list[tuple[str, str]] = []
    current: str | None = None
    for raw in data.split(b"\n"):
        if raw.startswith(b"\t"):
            if current is None:
                raise ValueError("blame line precedes its header")
            lines.append((current, authors.get(current, "")))
            continue
        header = _BLAME_HEADER.fullmatch(raw)
        if header is not None:
            current = header.group(1).decode()
        elif raw.startswith(b"author-mail ") and current is not None:
            authors[current] = raw.split(b" ", 1)[1].strip().strip(b"<>").decode("utf-8", "replace").lower()
    return lines


def parse_blame_commits(data: bytes) -> list[str]:
    """Return the originating commit of each blamed line (any order) for range blames."""
    return [commit for commit, _ in parse_blame_lines(data)]


def parse_old_hunks(data: bytes) -> list[tuple[int, int]]:
    """Return pre-image ``(start, count)`` ranges with at least one removed or modified line."""
    ranges = []
    for raw in data.split(b"\n"):
        match = _HUNK.match(raw)
        if match is None:
            continue
        start, count = int(match.group(1)), int(match.group(2)) if match.group(2) is not None else 1
        if count > 0 and start > 0:
            ranges.append((start, count))
    return ranges


def _function_name(nodes: Mapping[tuple[int, ...], Mapping[str, Any]], ordinal: tuple[int, ...], data: bytes) -> str | None:
    children = sorted((key for key in nodes if len(key) == len(ordinal) + 1 and key[:len(ordinal)] == ordinal))
    named = [key for key in children if nodes[key].get("field") == "name"]
    candidate = named[0] if named else None
    if candidate is None:
        # C and C++ nest the name in declarator fields: function_declarator -> identifier.
        cursor = next((key for key in children if nodes[key].get("field") == "declarator"), None)
        for _ in range(4):
            if cursor is None:
                break
            if nodes[cursor]["grammar_native_type"] in _NAME_TYPES:
                candidate = cursor
                break
            cursor = next((key for key in sorted(nodes) if len(key) == len(cursor) + 1 and key[:len(cursor)] == cursor
                           and nodes[key].get("field") == "declarator"), None)
    if candidate is None:
        return None
    location = nodes[candidate]["location"]
    text = data[int(location["start_byte"]):int(location["end_byte"])][:512].decode("utf-8", "replace")
    return _SAFE_NAME.sub("", text)[:256] or None


def function_spans(records: Iterable[bytes], wanted: Mapping[str, str], target_root: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    """Extract callable spans for ``wanted`` paths (path -> accepted sha256) from Tree-sitter JSONL.

    Returns spans per path and a per-path reason for files whose mapping is unreliable.
    """
    by_path: dict[str, dict[tuple[int, ...], dict[str, Any]]] = {}
    for line in records:
        if not line.strip():
            continue
        record = json.loads(line)
        path = record.get("path")
        if path not in wanted:
            continue
        if record.get("file_sha256") != wanted[path]:
            raise ValueError("Tree-sitter node hash does not match the accepted file")
        ordinal = tuple(int(item) for item in record["location"]["producer_location"]["ordinal_path"])
        by_path.setdefault(path, {})[ordinal] = record
    spans: dict[str, list[dict[str, Any]]] = {}
    unreliable: dict[str, str] = {}
    root = target_root.resolve()
    for path in sorted(wanted):
        nodes = by_path.get(path)
        if not nodes or () not in nodes:
            unreliable[path] = "function_spans_unavailable"
            continue
        if nodes[()].get("has_error") or any(node.get("error") or node.get("missing") for node in nodes.values()):
            unreliable[path] = "function_parse_diagnostics"
            continue
        data = (root / path).read_bytes()
        values = []
        for ordinal in sorted(nodes):
            node = nodes[ordinal]
            if node["grammar_native_type"] not in FUNCTION_TYPES:
                continue
            location = node["location"]
            values.append({"identity": node["identity"], "type": node["grammar_native_type"],
                           "name": _function_name(nodes, ordinal, data), "ordinal_path": list(ordinal),
                           "start_line": int(location["start_line"]), "end_line": int(location["end_line"]),
                           "location": location, "language": node.get("language")})
        spans[path] = values
    return spans, unreliable


def innermost_function(spans: list[Mapping[str, Any]], line: int) -> Mapping[str, Any] | None:
    best = None
    for span in spans:
        if span["start_line"] <= line <= span["end_line"]:
            if best is None or (span["end_line"] - span["start_line"]) < (best["end_line"] - best["start_line"]):
                best = span
    return best
