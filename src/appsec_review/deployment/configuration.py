"""Conservative configuration declarations for three supported product syntaxes."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
from urllib.parse import urlsplit

from .builder import Builder
from .model import Service
from .parsing import ParseError, bounded_lines, dynamic, port


def _service(builder: Builder, rule: str) -> Service:
    if not builder.lines:
        raise ParseError("empty_configuration", "configuration is empty")
    ev = builder.evidence((1, len(builder.lines)), rule)
    key = builder.document.service or f"configuration:{builder.document.path}"
    name = key.split(":")[-1] if builder.document.service else builder.document.path
    service = builder.service(key, name, "configuration", ev)
    builder.fact(service, f"{builder.document.format}-compatible configuration; product identity is unverified", ev)
    return service


def _endpoint(value: str) -> tuple[str | None, int | None]:
    if dynamic(value):
        return None, None
    if value.isdecimal():
        return None, port(value)
    match = re.fullmatch(r"\[([^\]]+)\]:(\d+)|([^:\s]+):(\d+)", value)
    if match:
        return match[1] or match[3], port(match[2] or match[4])
    if ":" not in value and re.fullmatch(r"[\w.*-]+", value):
        return value, None
    raise ParseError("unsupported_endpoint", "endpoint syntax is unresolved", "unsupported")


@dataclass(frozen=True)
class Directive:
    name: str
    args: tuple[str, ...]
    children: tuple[Directive, ...] | None
    start: int
    end: int


_NGINX_TOKEN = re.compile(r'''\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};'"#]+''')


def _nginx_tree(text: str, builder: Builder) -> tuple[Directive, ...]:
    tokens: list[tuple[str, int, int]] = []
    position = 0
    line = 1
    for match in _NGINX_TOKEN.finditer(text):
        if match.start() != position:
            raise ParseError("invalid_nginx", "unterminated or unsupported Nginx token")
        value = match[0]
        end = line + value.count("\n")
        if not value.isspace() and not value.startswith("#"):
            if value.startswith(("'", '"')):
                try:
                    value = shlex.split(value)[0]
                except (ValueError, IndexError) as exc:
                    raise ParseError("invalid_nginx", "invalid Nginx quoted token") from exc
            tokens.append((value, line, end))
            if len(value) > 1024:
                raise ParseError("scalar_limit", "Nginx literal exceeds supported bound", "partial")
        if len(tokens) > builder.limits.max_nodes:
            raise ParseError("syntax_limit", "Nginx token bound exceeded", "partial")
        line = end
        position = match.end()
    if position != len(text):
        raise ParseError("invalid_nginx", "unterminated Nginx string")

    def parse(index: int, depth: int) -> tuple[tuple[Directive, ...], int]:
        if depth > builder.limits.max_depth:
            raise ParseError("syntax_limit", "Nginx nesting bound exceeded", "partial")
        result: list[Directive] = []
        while index < len(tokens):
            if tokens[index][0] == "}":
                if depth == 0:
                    raise ParseError("invalid_nginx", "unexpected closing brace")
                return tuple(result), index + 1
            start = tokens[index][1]
            words = []
            while index < len(tokens) and tokens[index][0] not in {"{", "}", ";"}:
                words.append(tokens[index][0])
                index += 1
            if not words or index == len(tokens) or tokens[index][0] == "}":
                raise ParseError("invalid_nginx", "directive requires a terminator")
            terminator, _, end = tokens[index]
            index += 1
            children = None
            if terminator == "{":
                children, index = parse(index, depth + 1)
                end = tokens[index - 1][2]
            result.append(Directive(words[0], tuple(words[1:]), children, start, end))
        if depth:
            raise ParseError("invalid_nginx", "unclosed configuration block")
        return tuple(result), index

    return parse(0, 0)[0]


def nginx(builder: Builder, text: str) -> None:
    directives = _nginx_tree(text, builder)
    service = _service(builder, "nginx.configuration.v1")
    upstreams: dict[str, list[tuple[str, int | None, str]]] = {}
    ambiguous_upstreams: set[str] = set()

    def evidence(node: Directive, rule: str) -> str:
        return builder.evidence((node.start, node.end), rule)

    def collect(nodes: tuple[Directive, ...], context: str = "main") -> None:
        for node in nodes:
            if node.name == "upstream" and node.children is not None and context == "http":
                if len(node.args) != 1 or dynamic(node.args[0]):
                    builder.gap("dynamic_upstream", "upstream identity is unresolved", service=service,
                                evidence=evidence(node, "nginx.upstream.v1"))
                    continue
                name = node.args[0]
                if name in upstreams:
                    ambiguous_upstreams.add(name)
                    builder.gap("duplicate_upstream", "upstream has conflicting declarations", service=service,
                                evidence=evidence(node, "nginx.upstream.v1"))
                upstreams.setdefault(name, [])
                for child in node.children:
                    if child.name == "server" and child.args and child.children is None:
                        ev = evidence(child, "nginx.upstream-server.v1")
                        if dynamic(child.args[0]) or child.args[0].startswith("unix:"):
                            builder.gap("dynamic_backend", "backend address is unresolved", service=service, evidence=ev)
                            continue
                        address, number = _endpoint(child.args[0])
                        if address is not None:
                            upstreams[name].append((address, number, ev))
                        if len(child.args) > 1:
                            builder.gap("upstream_options", "upstream options are not interpreted",
                                        service=service, evidence=ev)
                    else:
                        builder.gap("unsupported_directive", "upstream directive is not interpreted",
                                    service=service, evidence=evidence(child, "nginx.coverage.v1"))
            elif node.children is not None and node.name == "http" and context == "main":
                collect(node.children, "http")

    collect(directives)

    def walk(nodes: tuple[Directive, ...], context: str = "main", route: str | None = None) -> None:
        for node in nodes:
            ev = evidence(node, f"nginx.{node.name if node.name in {'listen', 'proxy_pass', 'user'} else 'coverage'}.v1")
            if node.name == "upstream" and context == "http":
                continue
            if node.children is not None:
                valid_context = {
                    "http": {"main"}, "events": {"main"}, "server": {"http"}, "location": {"server", "location"},
                }
                if context not in valid_context.get(node.name, set()):
                    builder.gap("unsupported_block", "Nginx block is not interpreted", service=service, evidence=ev)
                    continue
                if node.name == "location":
                    if len(node.args) != 1 or dynamic(node.args[0]):
                        builder.gap("location_unknown", "nonliteral location matching is unresolved",
                                    service=service, evidence=ev)
                        continue
                    walk(node.children, "location", node.args[0])
                else:
                    walk(node.children, node.name, route)
                continue
            if node.name == "listen" and context == "server" and node.args:
                if dynamic(node.args[0]) or node.args[0].startswith("unix:"):
                    builder.gap("listener_unknown", "listener address is unresolved", service=service, evidence=ev)
                    continue
                address, number = _endpoint(node.args[0])
                unknown_options = set(node.args[1:]) - {"ssl", "default_server"}
                if unknown_options:
                    builder.gap("listen_options", "Nginx listen options are not interpreted",
                                service=service, evidence=ev)
                builder.listener(service, address, number, ev, tls=True if "ssl" in node.args[1:] else None)
            elif node.name == "proxy_pass" and context in {"server", "location"} and len(node.args) == 1:
                if dynamic(node.args[0]):
                    builder.gap("dynamic_proxy", "proxy target interpolation is unresolved", service=service, evidence=ev)
                    continue
                try:
                    url = urlsplit(node.args[0])
                    hostname, number = url.hostname, url.port
                except ValueError as exc:
                    raise ParseError("invalid_proxy", "invalid proxy target") from exc
                if url.scheme not in {"http", "https"} or not hostname or url.username or url.password:
                    builder.gap("unsupported_proxy", "proxy URL scheme or authority is unsupported",
                                service=service, evidence=ev)
                    continue
                if number is not None:
                    port(str(number))
                if hostname in ambiguous_upstreams:
                    builder.edge(service, hostname, number, ev, route=route)
                    builder.graph.relationships[-1].resolution = "ambiguous"
                elif hostname in upstreams:
                    for address, backend_port, upstream_ev in upstreams[hostname]:
                        builder.edge(service, address, backend_port, ev, route=route)
                        builder.graph.relationships[-1].evidence.append(upstream_ev)
                    if not upstreams[hostname]:
                        builder.gap("upstream_empty", "upstream has no resolved backends", service=service, evidence=ev)
                else:
                    builder.edge(service, hostname, number, ev, route=route)
            elif node.name == "user" and context == "main" and 1 <= len(node.args) <= 2:
                if dynamic(" ".join(node.args)):
                    builder.gap("dynamic_identity", "Nginx user is unresolved", service=service, evidence=ev)
                else:
                    builder.claim(service, "configuration.worker_user", ":".join(node.args), ev)
                    builder.fact(service, f"Nginx worker identity: {':'.join(node.args)}; container identity is separate", ev,
                                 "deployment_declaration")
            else:
                builder.gap("unsupported_directive", "Nginx directive or context is not interpreted",
                            service=service, evidence=ev)

    walk(directives)


def simple_configuration(builder: Builder, text: str) -> None:
    service = _service(builder, f"{builder.document.format}.configuration.v1")
    postgres = builder.document.format == "postgresql"
    supported = ({"listen_addresses", "port", "ssl", "password_encryption"} if postgres else
                 {"bind", "port", "tls-port", "requirepass", "aclfile", "protected-mode"})
    values: dict[str, list[tuple[list[str], str]]] = {}
    for line, raw in bounded_lines(text, builder.limits):
        try:
            if postgres:
                lexer = shlex.shlex(raw, posix=True, punctuation_chars="=")
                lexer.whitespace_split = True
                tokens = list(lexer)
                if not tokens:
                    continue
                name = tokens[0]
                if re.fullmatch(r"[a-z_]+", name) is None:
                    raise ParseError("invalid_configuration", "invalid PostgreSQL setting")
                args = tokens[2:] if len(tokens) > 1 and tokens[1] == "=" else tokens[1:]
            else:
                tokens = shlex.split(raw, comments=True)
                if not tokens:
                    continue
                name, *args = tokens
        except ValueError as exc:
            raise ParseError("invalid_configuration", "unterminated configuration string") from exc
        ev = builder.evidence((line, line), f"{builder.document.format}.{name if name in supported else 'coverage'}.v1")
        if name not in supported:
            builder.gap("unsupported_directive", "configuration directive is not interpreted",
                        service=service, evidence=ev)
            continue
        if not args:
            raise ParseError("missing_value", "configuration setting requires a value")
        if len(" ".join(args)) > 4096:
            raise ParseError("scalar_limit", "configuration literal exceeds supported bound", "partial")
        if dynamic(" ".join(args)):
            builder.gap("dynamic_configuration", "configuration value is unresolved", service=service, evidence=ev)
            continue
        values.setdefault(name, []).append((args, ev))
        # Never copy secret values into facts, conflict summaries or error messages.
        if name in {"requirepass", "aclfile", "password_encryption", "protected-mode"}:
            builder.fact(service, f"{name} directive present; policy enforcement is unverified", ev,
                         "deployment_declaration")
        elif name in {"port", "tls-port", "bind", "listen_addresses", "ssl"}:
            builder.claim(service, f"configuration.{name}", " ".join(args), ev)
    address_key = "listen_addresses" if postgres else "bind"
    bindings = values.get(address_key, [])
    addresses: list[tuple[str | None, str | None]] = [(None, None)]
    if bindings:
        addresses = []
        for args, ev in bindings:
            if postgres and len(args) != 1:
                raise ParseError("invalid_address", "listen_addresses requires one quoted value")
            for address in (args[0].split(",") if postgres else args):
                address = address.strip()
                if not address:
                    continue
                if address.startswith("-"):
                    builder.gap("optional_bind", "optional bind success is unknown", service=service, evidence=ev)
                    address = address[1:]
                addresses.append((address, ev))
    tls = None
    if postgres and "ssl" in values:
        choices = {tuple(args) for args, _ in values["ssl"]}
        if any(args not in {("on",), ("off",)} for args in choices):
            raise ParseError("invalid_ssl", "supported ssl declarations are on and off")
        if len(choices) == 1:
            tls = next(iter(choices)) == ("on",)
    for name in ("port", "tls-port"):
        for args, ev in values.get(name, []):
            if len(args) != 1:
                raise ParseError("invalid_port", "port setting requires one integer")
            if not postgres and args[0] == "0":
                builder.fact(service, f"{name} explicitly disabled in configuration", ev, "deployment_declaration")
                continue
            number = port(args[0])
            for bind_address, bind_ev in addresses:
                evidence: tuple[str, ...] = (ev, bind_ev) if bind_ev is not None else (ev,)
                if postgres and "ssl" in values:
                    evidence += tuple(item[1] for item in values["ssl"])
                builder.listener(service, bind_address, number, evidence,
                                 tls=tls if postgres else name == "tls-port")
    if not any(name in values for name in ("port", "tls-port")):
        builder.gap("port_unknown", "no literal port supplied; product defaults are not assumed",
                    service=service)
