"""Rebuild per-file concrete syntax trees from accepted Tree-sitter AST shards.

The accepted shard rows carry grammar-native node types, fields, flags, byte spans, points, and
ordinal paths, but no source text.  Text is read from the hash-verified target bytes on demand.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any


COMMENT_TYPES = frozenset({"comment", "line_comment", "block_comment"})
MAX_TEXT_BYTES = 4096


@dataclass(slots=True, eq=False)
class Node:
    type: str
    field: str | None
    named: bool
    error: bool
    start: int
    end: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    children: list["Node"] = field(default_factory=list)
    parent: "Node | None" = None

    def child(self, name: str) -> "Node | None":
        return next((item for item in self.children if item.field == name), None)

    def fields(self, name: str) -> list["Node"]:
        return [item for item in self.children if item.field == name]

    def named_children(self) -> list["Node"]:
        return [item for item in self.children if item.named and item.type not in COMMENT_TYPES]

    def walk(self) -> Iterator["Node"]:
        stack = [self]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node.children))

    def operator(self) -> str | None:
        """Return the anonymous operator token of a binary or assignment node, if any."""
        for item in self.children:
            if item.field == "operator" and not item.named:
                return item.type
        return None


@dataclass(slots=True)
class SourceFile:
    path: str
    sha256: str
    grammar: str
    language: str
    data: bytes
    root: Node
    error_count: int

    def text(self, node: Node, limit: int = MAX_TEXT_BYTES) -> str:
        return self.data[node.start:min(node.end, node.start + limit)].decode("utf-8", "replace")

    def line_count(self) -> int:
        return self.data.count(b"\n") + (0 if self.data.endswith(b"\n") or not self.data else 1)


def build_tree(rows: Iterable[Mapping[str, Any]]) -> tuple[Node, int]:
    """Assemble one file's rows into a tree using the producer ordinal paths."""
    nodes: dict[tuple[int, ...], Node] = {}
    errors = 0
    for row in rows:
        location = row["location"]
        ordinal = tuple(int(value) for value in location["producer_location"]["ordinal_path"])
        if ordinal in nodes:
            raise ValueError("duplicate Tree-sitter ordinal path")
        broken = bool(row.get("error")) or bool(row.get("missing"))
        errors += broken
        nodes[ordinal] = Node(str(row["grammar_native_type"]), row.get("field"), bool(row.get("named")), broken,
                              int(location["start_byte"]), int(location["end_byte"]),
                              int(location["start_line"]), int(location["end_line"]),
                              int(location["start_column"]), int(location["end_column"]))
    if () not in nodes:
        raise ValueError("Tree-sitter rows omit the root node")
    for ordinal in sorted(nodes):
        if not ordinal:
            continue
        parent = nodes.get(ordinal[:-1])
        if parent is None:
            raise ValueError("Tree-sitter rows omit a parent node")
        node = nodes[ordinal]
        node.parent = parent
        parent.children.append(node)
    return nodes[()], errors


def code_lines(node: Node) -> set[int]:
    """Physical lines touched by non-comment leaf tokens (source lines of code)."""
    lines: set[int] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in COMMENT_TYPES:
            continue
        if not current.children:
            if current.end > current.start:
                lines.update(range(current.start_line, current.end_line + 1))
            continue
        stack.extend(current.children)
    return lines
