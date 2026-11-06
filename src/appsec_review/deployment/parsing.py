"""Bounded YAML syntax with resolving spans; never expand aliases or custom tags."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import re

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .model import Limits, Outcome


@dataclass
class ParseError(ValueError):
    code: str
    message: str
    outcome: Outcome = "malformed"

    def __str__(self) -> str:
        return self.message


def yaml_documents(text: str, limits: Limits) -> list[Node]:
    # The same event-before-compose discipline as indexing.document_interfaces; that
    # parser's public API is specific to API operations and supports only one document.
    depth = 0
    try:
        for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader), 1):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ParseError("yaml_alias", "YAML anchors and aliases are not expanded", "unsupported")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > limits.max_depth or count > limits.max_nodes:
                raise ParseError("syntax_limit", "YAML syntax bound exceeded", "partial")
        roots = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        raise ParseError("invalid_yaml", f"invalid YAML/JSON ({type(exc).__name__})") from exc
    pending = list(roots)
    while pending:
        node = pending.pop()
        if node.tag not in {
            "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq", "tag:yaml.org,2002:str",
            "tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:null", "tag:yaml.org,2002:timestamp",
        }:
            raise ParseError("yaml_tag", "custom YAML tags are not supported", "unsupported")
        if isinstance(node, MappingNode):
            pending.extend(mapping(node).values())
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)
    return roots


def mapping(node: Node) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise ParseError("expected_mapping", "expected an object")
    result = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
            raise ParseError("invalid_key", "mapping keys must be strings")
        if key.value in result:
            raise ParseError("duplicate_key", "duplicate mapping field")
        result[key.value] = value
    return result


def sequence(node: Node) -> list[Node]:
    if not isinstance(node, SequenceNode):
        raise ParseError("expected_sequence", "expected an array")
    result: list[Node] = []
    for item in node.value:
        if not isinstance(item, Node):
            raise ParseError("invalid_node", "sequence contains an invalid node")
        result.append(item)
    return result


def scalar(node: Node, *, numeric: bool = False) -> str:
    tags = {"tag:yaml.org,2002:str"}
    if numeric:
        tags.add("tag:yaml.org,2002:int")
    if not isinstance(node, ScalarNode) or node.tag not in tags:
        raise ParseError("expected_scalar", "expected a string" + (" or integer" if numeric else ""))
    if not isinstance(node.value, str):
        raise ParseError("invalid_node", "scalar contains an invalid value")
    if len(node.value) > 4096:
        raise ParseError("scalar_limit", "literal value exceeds supported bound", "partial")
    return node.value


def boolean(node: Node) -> bool:
    if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:bool":
        raise ParseError("expected_boolean", "expected a boolean")
    return node.value.lower() in {"true", "yes", "on"}


def port(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ParseError("invalid_port", "port must be an integer between 1 and 65535")
    return int(value)


def dynamic(value: str) -> bool:
    return "$" in value or "{{" in value or "}}" in value


def node_lines(node: Node) -> tuple[int, int]:
    start = node.start_mark.line + 1
    end = node.end_mark.line + bool(node.end_mark.column)
    return start, max(start, end)


def bounded_lines(text: str, limits: Limits) -> Iterator[tuple[int, str]]:
    lines = text.splitlines()
    if len(lines) > limits.max_nodes:
        raise ParseError("syntax_limit", "configuration line bound exceeded", "partial")
    yield from enumerate(lines, 1)
