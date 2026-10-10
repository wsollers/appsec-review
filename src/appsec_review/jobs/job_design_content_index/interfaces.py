"""Deterministic extraction of declared interface operations from specifications and IDL.

Nothing is executed or fetched: YAML/JSON is composed with PyYAML's safe composer after rejecting
anchors and aliases, external `$ref`s are never followed, and protobuf/GraphQL use bounded
tokenizers. Every operation keeps the inclusive line span of the text that declared it.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


EXTRACTOR_IDENTITY = "design-interface-extractor/1"
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_MAX_DEPTH = 64
_MAX_NODES = 200_000
_MAX_LIST = 64


class SpecificationError(ValueError):
    """A specification could not be safely composed; reported as a named gap."""


def _line_span(node: Node, key: Node | None = None) -> tuple[int, int]:
    """Inclusive 1-based lines; a block value's end mark sits on the next key's indentation."""
    start = (key or node).start_mark.line + 1
    end_mark = node.end_mark
    buffer = end_mark.buffer or ""
    line_start = buffer.rfind("\n", 0, end_mark.pointer) + 1
    only_indent = not buffer[line_start:end_mark.pointer].strip()
    end = end_mark.line if only_indent else end_mark.line + 1
    return start, max(start, end)


def compose(text: str) -> Node | None:
    """Compose one YAML/JSON document without constructing objects or expanding aliases."""
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise SpecificationError("YAML anchors and aliases are not accepted in specifications")
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        raise SpecificationError(f"specification is not well-formed YAML/JSON ({type(exc).__name__})") from exc


def to_value(node: Node | None, depth: int = 0, budget: list[int] | None = None) -> Any:
    budget = budget if budget is not None else [_MAX_NODES]
    budget[0] -= 1
    if budget[0] < 0 or depth > _MAX_DEPTH:
        raise SpecificationError("specification exceeds the composition bound")
    if node is None:
        return None
    if isinstance(node, ScalarNode):
        return node.value
    if isinstance(node, SequenceNode):
        return [to_value(item, depth + 1, budget) for item in node.value]
    if isinstance(node, MappingNode):
        return {str(to_value(key, depth + 1, budget)): to_value(value, depth + 1, budget)
                for key, value in node.value}
    return None


def _items(node: Node | None) -> list[tuple[str, Node, Node]]:
    if not isinstance(node, MappingNode):
        return []
    return [(str(key.value), key, value) for key, value in node.value if isinstance(key, ScalarNode)]


def _child(node: Node | None, name: str) -> Node | None:
    return next((value for key, _, value in _items(node) if key == name), None)


def _local_ref(root: Node, value: Any) -> Any:
    """Resolve one same-document JSON pointer; external references are never fetched."""
    if not isinstance(value, Mapping) or "$ref" not in value:
        return value
    reference = str(value["$ref"])
    if not reference.startswith("#/"):
        return {"unresolved_ref": "external"}
    node: Node | None = root
    for part in reference[2:].split("/"):
        node = _child(node, part.replace("~1", "/").replace("~0", "~"))
        if node is None:
            return {"unresolved_ref": "missing"}
    resolved = to_value(node)
    return resolved if not (isinstance(resolved, Mapping) and "$ref" in resolved) else {"unresolved_ref": "nested"}


def _security_state(requirements: Any) -> tuple[str, list[str]]:
    if requirements is None:
        return "unspecified", []
    if not isinstance(requirements, list):
        return "invalid", []
    if not requirements:
        return "none", []
    schemes = sorted({str(name) for item in requirements if isinstance(item, Mapping) for name in item})
    if all(isinstance(item, Mapping) and not item for item in requirements):
        return "none", []
    if any(isinstance(item, Mapping) and not item for item in requirements):
        return "optional", schemes
    return ("required", schemes) if schemes else ("invalid", [])


def _bounded(values: list[Any]) -> list[Any]:
    return values[:_MAX_LIST]


def openapi_operations(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = compose(text)
    if not isinstance(root, MappingNode):
        raise SpecificationError("specification root is not a mapping")
    top = {key: value for key, _, value in _items(root)}
    version_node = top.get("openapi") or top.get("swagger")
    version = str(version_node.value) if isinstance(version_node, ScalarNode) else ""
    swagger = "swagger" in top
    schemes_node = _child(_child(root, "components"), "securitySchemes") if not swagger else \
        _child(root, "securityDefinitions")
    scheme_types: dict[str, str] = {}
    for name, _, value in _items(schemes_node):
        definition = _local_ref(root, to_value(value))
        if isinstance(definition, Mapping):
            kind = str(definition.get("type", "unknown"))
            if kind == "http" and definition.get("scheme"):
                kind = f"http:{str(definition['scheme']).lower()}"
            scheme_types[name] = kind
    root_security = to_value(top["security"]) if "security" in top else None
    servers = [str(item.get("url")) for item in (to_value(top.get("servers")) or []) if isinstance(item, Mapping)]
    transports = [str(item).lower() for item in (to_value(top.get("schemes")) or [])] if swagger else \
        sorted({url.split(":", 1)[0].lower() for url in servers if "://" in url})
    root_consumes = to_value(top.get("consumes")) if swagger else None
    operations: list[dict[str, Any]] = []
    for route, route_key, path_item in _items(top.get("paths")):
        item_value = _local_ref(root, to_value(path_item))
        path_parameters = item_value.get("parameters", []) if isinstance(item_value, Mapping) else []
        for method, method_key, operation_node in _items(path_item):
            if method.lower() not in HTTP_METHODS:
                continue
            operation = to_value(operation_node)
            if not isinstance(operation, Mapping):
                continue
            parameters: dict[tuple[str, str], dict[str, Any]] = {}
            for raw in [*path_parameters, *operation.get("parameters", [])]:
                parameter = _local_ref(root, raw)
                if isinstance(parameter, Mapping) and "name" in parameter:
                    parameters[(str(parameter["name"]), str(parameter.get("in", "")))] = {
                        "name": str(parameter["name"])[:128], "in": str(parameter.get("in", ""))[:32],
                        "required": str(parameter.get("required", "false")).lower() == "true"}
            state, schemes = _security_state(operation["security"] if "security" in operation else root_security)
            body = _local_ref(root, operation.get("requestBody"))
            media = sorted(body.get("content", {})) if isinstance(body, Mapping) and isinstance(
                body.get("content"), Mapping) else sorted(operation.get("consumes") or root_consumes or [])
            operation_servers = [str(item.get("url")) for item in operation.get("servers", [])
                                 if isinstance(item, Mapping)]
            start, end = _line_span(operation_node, method_key)
            operations.append({
                "protocol": "http", "method": method.upper(), "route": route[:1024],
                "operation_id": str(operation.get("operationId", ""))[:256] or None,
                "name": f"{method.upper()} {route}"[:1100], "security_state": state,
                "security_schemes": _bounded(schemes),
                "security_scheme_types": _bounded(sorted({scheme_types.get(name, "undeclared") for name in schemes})),
                "parameters": _bounded(sorted(parameters.values(), key=lambda item: (item["in"], item["name"]))),
                "request_media_types": _bounded([str(item)[:128] for item in media]),
                "response_codes": _bounded(sorted(str(code) for code in (operation.get("responses") or {}))),
                "deprecated": str(operation.get("deprecated", "false")).lower() == "true",
                "insecure_transport": "http" in transports or any(url.lower().startswith("http://")
                                                                  for url in operation_servers),
                "client_streaming": False, "server_streaming": False,
                "start_line": start, "end_line": end,
                "route_start_line": route_key.start_mark.line + 1,
            })
    facts = {"specification": "swagger" if swagger else "openapi", "version": version[:32],
             "security_schemes": dict(sorted(scheme_types.items())), "transports": transports,
             "operation_count": len(operations)}
    return operations, facts


def asyncapi_operations(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = compose(text)
    if not isinstance(root, MappingNode):
        raise SpecificationError("specification root is not a mapping")
    version_node = _child(root, "asyncapi")
    version = str(version_node.value) if isinstance(version_node, ScalarNode) else ""
    operations: list[dict[str, Any]] = []
    channels = {name: (key, value) for name, key, value in _items(_child(root, "channels"))}
    if version.startswith("2"):
        for name, (_, channel) in channels.items():
            for action, action_key, node in _items(channel):
                if action not in {"publish", "subscribe"}:
                    continue
                value = to_value(node)
                state, schemes = _security_state(value.get("security") if isinstance(value, Mapping) else None)
                start, end = _line_span(node, action_key)
                operations.append(_async(action, name, value, state, schemes, start, end))
    else:
        for operation_id, key, node in _items(_child(root, "operations")):
            value = to_value(node)
            if not isinstance(value, Mapping):
                continue
            reference = str((value.get("channel") or {}).get("$ref", "")) if isinstance(value.get("channel"), Mapping) else ""
            channel_name = reference.rsplit("/", 1)[-1] if reference.startswith("#/channels/") else ""
            channel = to_value(channels[channel_name][1]) if channel_name in channels else {}
            address = str(channel.get("address") or channel_name) if isinstance(channel, Mapping) else channel_name
            state, schemes = _security_state(value.get("security"))
            start, end = _line_span(node, key)
            operations.append(_async(str(value.get("action", "")), address, value, state, schemes, start, end,
                                     operation_id))
    return operations, {"specification": "asyncapi", "version": version[:32], "operation_count": len(operations)}


def _async(action: str, address: str, value: Any, state: str, schemes: list[str], start: int, end: int,
           operation_id: str | None = None) -> dict[str, Any]:
    identifier = operation_id or (value.get("operationId") if isinstance(value, Mapping) else None)
    return {"protocol": "async", "method": action.upper()[:32], "route": address[:1024],
            "operation_id": str(identifier)[:256] if identifier else None,
            "name": f"{action.upper()} {address}"[:1100], "security_state": state,
            "security_schemes": _bounded(schemes), "security_scheme_types": [], "parameters": [],
            "request_media_types": [], "response_codes": [], "deprecated": False,
            "insecure_transport": False, "client_streaming": False, "server_streaming": False,
            "start_line": start, "end_line": end}


_PROTO_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][\w.]*|[{}();=:\[\],<>]|\S')
_HTTP_RULE = re.compile(r"\b(get|put|post|delete|patch)\s*:\s*\"([^\"]{1,1024})\"")


def _tokens(text: str, comment_markers: tuple[str, ...]) -> list[tuple[str, int]]:
    tokens: list[tuple[str, int]] = []
    in_block = False
    for number, line in enumerate(text.splitlines(), 1):
        index = 0
        while index < len(line):
            if in_block:
                close = line.find("*/", index)
                if close < 0:
                    break
                in_block, index = False, close + 2
                continue
            if "/*" in comment_markers and line.startswith("/*", index):
                in_block, index = True, index + 2
                continue
            if any(line.startswith(marker, index) for marker in comment_markers if marker != "/*"):
                break
            match = _PROTO_TOKEN.match(line, index)
            if match is None:
                index += 1
                continue
            if not match.group().isspace():
                tokens.append((match.group(), number))
            index = match.end()
            while index < len(line) and line[index].isspace():
                index += 1
    return tokens


def protobuf_operations(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    tokens = _tokens(text, ("//", "/*"))
    package = ""
    services: list[str] = []
    operations: list[dict[str, Any]] = []
    index = 0
    depth = 0
    service: str | None = None
    service_depth = 0
    while index < len(tokens):
        token, line = tokens[index]
        if token == "package" and depth == 0 and index + 1 < len(tokens):
            package = tokens[index + 1][0][:256]
        elif token == "service" and index + 1 < len(tokens) and depth == 0:
            service, service_depth = tokens[index + 1][0][:256], depth + 1
            services.append(service)
        elif token == "rpc" and service is not None and depth == service_depth:
            parsed = _proto_rpc(tokens, index)
            if parsed is not None:
                rpc, index = parsed
                full = f"{package + '.' if package else ''}{service}/{rpc['method_name']}"
                operations.append({
                    "protocol": "grpc", "method": "RPC", "route": f"/{full}"[:1024], "operation_id": full[:512],
                    "name": full[:1100], "service": service, "package": package or None,
                    "request_type": rpc["request"], "response_type": rpc["response"],
                    "client_streaming": rpc["client_streaming"], "server_streaming": rpc["server_streaming"],
                    "http_rules": rpc["http_rules"], "security_state": "unspecified", "security_schemes": [],
                    "security_scheme_types": [], "parameters": [], "request_media_types": [],
                    "response_codes": [], "deprecated": rpc["deprecated"], "insecure_transport": False,
                    "start_line": line, "end_line": rpc["end_line"]})
                continue
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
            if service is not None and depth < service_depth:
                service = None
        index += 1
    return operations, {"specification": "protobuf", "package": package or None,
                        "services": services[:_MAX_LIST], "operation_count": len(operations)}


def _proto_rpc(tokens: list[tuple[str, int]], index: int) -> tuple[dict[str, Any], int] | None:
    values = [token for token, _ in tokens[index:index + 16]]
    try:
        name = values[1]
        cursor = 2
        if values[cursor] != "(":
            return None
        client = values[cursor + 1] == "stream"
        request = values[cursor + 2 if client else cursor + 1]
        cursor = values.index("returns", cursor) + 1
        if values[cursor] != "(":
            return None
        server = values[cursor + 1] == "stream"
        response = values[cursor + 2 if server else cursor + 1]
        cursor = values.index(")", cursor) + 1
    except (IndexError, ValueError):
        return None
    position = index + cursor
    http_rules: list[dict[str, str]] = []
    deprecated = False
    end_line = tokens[min(position, len(tokens) - 1)][1]
    if position < len(tokens) and tokens[position][0] == "{":
        depth = 0
        body: list[str] = []
        while position < len(tokens):
            token, end_line = tokens[position]
            depth += token == "{"
            depth -= token == "}"
            body.append(token)
            position += 1
            if depth == 0:
                break
        joined = " ".join(body)
        http_rules = [{"method": method.upper(), "path": path} for method, path in _HTTP_RULE.findall(joined)]
        deprecated = "deprecated = true" in joined
    elif position < len(tokens) and tokens[position][0] == ";":
        end_line = tokens[position][1]
        position += 1
    return ({"method_name": name[:256], "request": request[:256], "response": response[:256],
             "client_streaming": client, "server_streaming": server, "http_rules": http_rules[:8],
             "deprecated": deprecated, "end_line": end_line}, position)


def graphql_operations(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # Block strings and descriptions are blanked first so their content cannot look like fields.
    blanked = re.sub(r'"""[\s\S]*?"""', lambda match: re.sub(r"[^\n]", " ", match.group()), text)
    tokens = _tokens(blanked, ("#",))
    roots = {"query": "Query", "mutation": "Mutation", "subscription": "Subscription"}
    for index, (token, _) in enumerate(tokens):
        if token == "schema" and index + 1 < len(tokens) and tokens[index + 1][0] == "{":
            cursor = index + 2
            while cursor + 2 < len(tokens) and tokens[cursor][0] != "}":
                if tokens[cursor][0] in roots and tokens[cursor + 1][0] == ":":
                    roots[tokens[cursor][0]] = tokens[cursor + 2][0]
                cursor += 1
    by_type = {name: kind for kind, name in roots.items()}
    operations: list[dict[str, Any]] = []
    index = 0
    while index < len(tokens):
        token, _ = tokens[index]
        if token == "type" and index + 1 < len(tokens) and tokens[index + 1][0] in by_type:
            type_name = tokens[index + 1][0]
            cursor = index + 2
            while cursor < len(tokens) and tokens[cursor][0] != "{":
                cursor += 1
            depth, cursor = 1, cursor + 1
            while cursor < len(tokens) and depth > 0:
                value, line = tokens[cursor]
                if value in "{([":
                    depth += 1
                elif value in "})]":
                    depth -= 1
                elif depth == 1 and re.fullmatch(r"[A-Za-z_]\w*", value) and cursor + 1 < len(tokens) \
                        and tokens[cursor + 1][0] in {":", "("}:
                    end_line = line
                    probe, inner = cursor + 1, 0
                    while probe < len(tokens):
                        if tokens[probe][0] in "([":
                            inner += 1
                        elif tokens[probe][0] in ")]":
                            inner -= 1
                        elif inner == 0 and tokens[probe][0] == ":":
                            end_line = tokens[min(probe + 1, len(tokens) - 1)][1]
                            break
                        probe += 1
                    kind = by_type[type_name]
                    operations.append({
                        "protocol": "graphql", "method": kind.upper(), "route": f"{type_name}.{value}"[:1024],
                        "operation_id": value[:256], "name": f"{type_name}.{value}"[:1100],
                        "security_state": "unspecified", "security_schemes": [], "security_scheme_types": [],
                        "parameters": [], "request_media_types": [], "response_codes": [], "deprecated": False,
                        "insecure_transport": False, "client_streaming": False,
                        "server_streaming": kind == "subscription", "start_line": line, "end_line": end_line})
                    cursor = probe
                cursor += 1
            index = cursor
            continue
        index += 1
    return operations, {"specification": "graphql", "roots": roots, "operation_count": len(operations)}


EXTRACTORS = {"openapi": openapi_operations, "swagger": openapi_operations, "asyncapi": asyncapi_operations,
              "protobuf": protobuf_operations, "graphql_schema": graphql_operations}
