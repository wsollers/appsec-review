"""Bounded declaration parsing; specifications are data, never implementation proof."""

from __future__ import annotations

import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class DocumentParseError(ValueError):
    """An unsupported, malformed, or bounded specification leaves an explicit gap."""


def _mapping(node: Node | None) -> dict[str, tuple[ScalarNode, Node]]:
    if node is None:
        return {}
    if not isinstance(node, MappingNode):
        raise DocumentParseError("expected a specification mapping")
    result = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.value in result:
            raise DocumentParseError("non-scalar or duplicate specification key")
        result[key.value] = (key, value)
    return result


def _child(node: Node | None, key: str) -> Node | None:
    value = _mapping(node).get(key)
    return value[1] if value is not None else None


def _scalar(node: Node | None) -> str:
    if node is None:
        return ""
    if not isinstance(node, ScalarNode):
        raise DocumentParseError("expected a specification scalar")
    return node.value


def _compose(text: str, max_depth: int, max_nodes: int) -> Node | None:
    depth = count = 0
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            count += 1
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise DocumentParseError("YAML anchors and aliases are not supported")
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > max_depth or count > max_nodes:
                raise DocumentParseError("specification parsing bound reached")
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise DocumentParseError(f"invalid YAML/JSON: {type(exc).__name__}") from exc
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, MappingNode):
            pending.extend(value for _, value in _mapping(node).values())
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)
        elif node is not None and not isinstance(node, ScalarNode):
            raise DocumentParseError("unsupported specification node")
        if node is not None and node.tag not in {
            "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq", "tag:yaml.org,2002:str",
            "tag:yaml.org,2002:bool", "tag:yaml.org,2002:int", "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:null", "tag:yaml.org,2002:timestamp",
        }:
            raise DocumentParseError("custom YAML tags are not supported")
    return root


def _span(key: Node, value: Node) -> tuple[int, int]:
    start = key.start_mark.line + 1
    mark = value.end_mark
    buffer = mark.buffer or ""
    line_start = buffer.rfind("\n", 0, mark.pointer) + 1
    end = mark.line + bool(buffer[line_start:mark.pointer].strip())
    return start, max(start, end)


def _operation(protocol: str, method: str, route: str, start: int, end: int,
               **fields: Any) -> dict[str, Any]:
    return {"protocol": protocol, "method": method, "route": route,
            "start_line": start, "end_line": end, **fields}


def _security(node: Node | None) -> tuple[str, list[str]]:
    if node is None:
        return "unspecified", []
    if not isinstance(node, SequenceNode):
        raise DocumentParseError("security requirements must be a sequence")
    alternatives = [_mapping(value) for value in node.value]
    names = sorted({name for value in alternatives for name in value})
    if not alternatives or not names:
        return "none", names
    return ("optional" if any(not value for value in alternatives) else "required"), names


def structured_operations(text: str, kind: str, *, max_depth: int, max_nodes: int
                          ) -> tuple[list[dict[str, Any]], list[str]]:
    root = _compose(text, max_depth, max_nodes)
    top = _mapping(root)
    operations = []
    gaps = []
    # References are not fetched or silently treated as complete interface coverage.
    pending = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, MappingNode):
            values = _mapping(node)
            if "$ref" in values:
                gaps.append(f"unresolved specification reference: {_scalar(values['$ref'][1])[:200]}")
            pending.extend(value for _, value in values.values())
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)
    if kind == "openapi":
        version = _scalar(_child(root, "openapi") or _child(root, "swagger"))
        if not (version.startswith("3.") or version == "2.0") or "paths" not in top:
            raise DocumentParseError("expected OpenAPI 3 or Swagger 2 paths")
        for route, (_, path) in _mapping(_child(root, "paths")).items():
            for method, (key, value) in _mapping(path).items():
                if method.lower() not in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                    continue
                fields = _mapping(value)
                security = fields["security"][1] if "security" in fields else _child(root, "security")
                state, schemes = _security(security)
                parameters = _child(value, "parameters")
                if parameters is not None and not isinstance(parameters, SequenceNode):
                    raise DocumentParseError("operation parameters must be a sequence")
                operations.append(_operation(
                    "http", method.upper(), route, *_span(key, value),
                    operation_id=_scalar(_child(value, "operationId")),
                    responses=sorted(_mapping(_child(value, "responses"))),
                    request_body="requestBody" in fields, security_state=state,
                    security_schemes=schemes,
                ))
    else:
        version = _scalar(_child(root, "asyncapi"))
        if not version.startswith(("2.", "3.")):
            raise DocumentParseError("expected AsyncAPI 2 or 3")
        channels = _mapping(_child(root, "channels"))
        if version.startswith("2."):
            for route, (_, channel) in channels.items():
                for action, (key, value) in _mapping(channel).items():
                    if action in {"publish", "subscribe"}:
                        operations.append(_operation("async", action.upper(), route, *_span(key, value)))
        else:
            for name, (key, value) in _mapping(_child(root, "operations")).items():
                reference = _scalar(_child(_child(value, "channel"), "$ref"))
                channel_name = reference.removeprefix("#/channels/").replace("~1", "/").replace("~0", "~")
                action = _scalar(_child(value, "action"))
                if not reference.startswith("#/channels/") or channel_name not in channels:
                    gaps.append(f"unresolved AsyncAPI channel for {name}")
                    continue
                if action not in {"send", "receive"}:
                    raise DocumentParseError("invalid AsyncAPI action")
                route = _scalar(_child(channels[channel_name][1], "address"))
                if not route:
                    gaps.append(f"missing AsyncAPI channel address for {name}")
                    continue
                operations.append(_operation("async", action.upper(), route, *_span(key, value),
                                             operation_id=name))
    return operations, sorted(set(gaps))


_TOKEN = re.compile(
    r'"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|'
    r"/\*[\s\S]*?\*/|//[^\r\n]*|\#[^\r\n]*|"
    r"[A-Za-z_][A-Za-z_0-9.]*|\s+|.", re.DOTALL,
)


def _tokens(text: str, max_nodes: int) -> list[tuple[str, int]]:
    result = []
    line = 1
    for match in _TOKEN.finditer(text):
        value = match.group()
        if value == '"' or value == "/" and text.startswith("/*", match.start()):
            raise DocumentParseError("unterminated interface string or comment")
        if not (value.isspace() or value.startswith(('"', "/*", "//", "#"))):
            result.append((value, line))
            if len(result) > max_nodes:
                raise DocumentParseError("interface token bound reached")
        line += value.count("\n")
    return result


def _message_type(values: list[str]) -> tuple[bool, str]:
    streaming = bool(values and values[0] == "stream")
    name = values[1:] if streaming else values
    if len(name) == 2 and name[0] == ".":
        name = ["".join(name)]
    if len(name) != 1 or not re.fullmatch(r"\.?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", name[0]):
        raise DocumentParseError("malformed RPC message type")
    return streaming, name[0]


def idl_operations(text: str, kind: str, *, max_depth: int, max_nodes: int
                   ) -> tuple[list[dict[str, Any]], list[str]]:
    tokens = _tokens(text, max_nodes)
    values = [value for value, _ in tokens]
    matching = {}
    stack = []
    for index, value in enumerate(values):
        if value in {"{", "(", "["}:
            stack.append((value, index))
            if len(stack) > max_depth:
                raise DocumentParseError("interface nesting bound reached")
        elif value in {"}", ")", "]"}:
            if not stack or stack[-1][0] != {"}": "{", ")": "(", "]": "["}[value]:
                raise DocumentParseError("unbalanced interface declaration")
            _, start = stack.pop()
            matching[start] = index
    if stack:
        raise DocumentParseError("unterminated interface declaration")
    roots = {"Query": "QUERY", "Mutation": "MUTATION", "Subscription": "SUBSCRIPTION"}
    if kind == "graphql":
        for index in range(len(values) - 2):
            if values[index:index + 2] == ["schema", "@"]:
                raise DocumentParseError("GraphQL schema directives are not supported")
            if values[index:index + 2] == ["schema", "{"]:
                roots = {}
                for cursor in range(index + 2, matching[index + 1] - 2):
                    if values[cursor] in {"query", "mutation", "subscription"} and values[cursor + 1] == ":":
                        roots[values[cursor + 2]] = values[cursor].upper()
    package = ""
    operations = []
    cursor = 0
    while cursor < len(values):
        if values[cursor] in {"{", "(", "["}:
            cursor = matching[cursor] + 1
            continue
        if kind == "protobuf" and values[cursor] == "package" and cursor + 1 < len(values):
            package = values[cursor + 1]
        declaration = "service" if kind == "protobuf" else "type"
        if values[cursor] != declaration or cursor + 2 >= len(values):
            cursor += 1
            continue
        name = values[cursor + 1]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name):
            raise DocumentParseError("invalid interface name")
        start = cursor + 2
        if kind == "protobuf" and values[start] != "{":
            raise DocumentParseError("missing service body")
        while start < len(values) and values[start] != "{":
            start += 1
        if start == len(values):
            raise DocumentParseError("missing interface body")
        end = matching[start]
        if kind == "graphql" and name not in roots:
            cursor = end + 1
            continue
        position = start + 1
        while position < end:
            first = position
            if kind == "protobuf":
                if values[position] != "rpc":
                    position = matching.get(position, position) + 1
                    continue
                header_end = position + 2
                if header_end not in matching or values[header_end] != "(":
                    raise DocumentParseError("malformed RPC request")
                request_end = matching[header_end]
                response_start = request_end + 2
                if (request_end + 1 >= end or values[request_end + 1] != "returns"
                        or response_start not in matching or values[response_start] != "("):
                    raise DocumentParseError("malformed RPC response")
                response_end = matching[response_start]
                request = values[header_end + 1:request_end]
                response = values[response_start + 1:response_end]
                client_streaming, request_type = _message_type(request)
                server_streaming, response_type = _message_type(response)
                position = response_end + 1
                if position >= end or values[position] not in {"{", ";"}:
                    raise DocumentParseError("unterminated RPC")
                position = matching.get(position, position) + 1
                operations.append(_operation(
                    "grpc", "RPC", f"/{package + '.' if package else ''}{name}/{values[first + 1]}",
                    tokens[first][1], tokens[position - 1][1],
                    request_type=request_type, response_type=response_type,
                    client_streaming=client_streaming, server_streaming=server_streaming,
                ))
            else:
                field = values[position]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", field):
                    raise DocumentParseError("invalid GraphQL field name")
                position += 1
                if position < end and values[position] == "(":
                    position = matching[position] + 1
                if position >= end or values[position] != ":":
                    raise DocumentParseError("malformed GraphQL field")
                position += 1
                if position >= end:
                    raise DocumentParseError("missing GraphQL return type")
                position = matching.get(position, position) + 1
                if position < end and values[position] == "!":
                    position += 1
                while position < end and values[position] == "@":
                    position += 2
                    if position < end and values[position] == "(":
                        position = matching[position] + 1
                operations.append(_operation("graphql", roots[name], f"{name}.{field}",
                                             tokens[first][1], tokens[position - 1][1]))
        cursor = end + 1
    gaps = [] if operations else ["no supported interface operation"]
    return operations, gaps
