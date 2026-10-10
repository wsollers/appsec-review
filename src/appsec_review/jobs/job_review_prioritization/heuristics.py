"""Tree-sitter boundary, privilege, wrapper, mutation, parsing, and suppression signals."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import re
from typing import Any

from .complexity import own_nodes
from .languages import BITWISE, LanguageSpec
from .rules import (
    ANNOTATIONS, CALL_RULES, COMMENT_SUPPRESSIONS, CSHARP_INGRESS_PROPERTIES, GO_INGRESS_FIELDS,
    GO_INGRESS_OBJECTS, HEURISTIC, JAVA_COMPILER_KEYS, JS_INGRESS_OBJECTS, JS_INGRESS_PROPERTIES,
    JS_ROUTE_RECEIVERS, OBSERVED, PHP_SUPERGLOBALS, ROUTE_VERBS, RULES_IDENTITY, RUST_INGRESS_EXTRACTORS,
    RUST_ROUTE_ATTRIBUTES, RUST_SCHEMA_DERIVES, SECURITY_MARKERS, CallRule,
)
from .syntax import COMMENT_TYPES, Node, SourceFile


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RECEIVER_FIELDS = {
    "member_expression": ("object", "property"), "selector_expression": ("operand", "field"),
    "field_expression": ("value", "field"), "member_access_expression": ("expression", "name"),
    "scoped_identifier": ("path", "name"), "qualified_identifier": ("scope", "name"),
    "qualified_name": ("prefix", "name"), "generic_function": ("function", None),
}
_CALL_RECEIVERS = {"method_invocation": "object", "member_call_expression": "object",
                   "nullsafe_member_call_expression": "object", "scoped_call_expression": "scope"}
_CREATION = frozenset({"object_creation_expression", "new_expression"})
_STRINGS = frozenset({"string", "string_literal", "interpreted_string_literal", "raw_string_literal",
                      "encapsed_string", "template_string", "verbatim_string_literal"})
_SLICING = frozenset({"subscript_expression", "index_expression", "slice_expression", "element_access_expression",
                      "array_access"})
_CPP_STREAM = re.compile(r"(?i)(^|::|\.)(std::)?(cout|cerr|clog|wcout|\w*stream\w*|os|out|ss|log\w*)$")
_ANNOTATION_TYPES = frozenset({"marker_annotation", "annotation", "attribute", "decorator"})
_RUST_ATTRIBUTES = frozenset({"attribute_item", "inner_attribute_item"})
_PUBLIC_RUST_ITEMS = frozenset({"function_item", "struct_item", "enum_item", "trait_item", "type_item"})
_TRANSPARENT_SIBLINGS = COMMENT_TYPES | _RUST_ATTRIBUTES | frozenset({"decorator", "attribute_list"})
_INSECURE_CALLBACKS = frozenset({"ServerCertificateCustomValidationCallback", "ServerCertificateValidationCallback",
                                 "RemoteCertificateValidationCallback"})


@dataclass(frozen=True, slots=True)
class CallFact:
    node: Node
    simple: str
    receiver: str
    segments: tuple[str, ...]
    arguments: tuple[Node, ...]


def _strip(text: str) -> str:
    value = text.strip()
    for prefix in ("@\"", "r\"", "b\""):
        if value.startswith(prefix):
            value = value[len(prefix) - 1:]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return value[1:-1]
    return value


def _arguments(node: Node) -> tuple[Node, ...]:
    holder = node.child("arguments")
    if holder is None:
        return ()
    values = []
    for item in holder.named_children():
        while item.type == "argument" and len(item.named_children()) == 1:
            item = item.named_children()[0]
        values.append(item)
    return tuple(values)


def call_fact(source: SourceFile, node: Node, spec: LanguageSpec) -> CallFact | None:
    field = spec.calls.get(node.type)
    if field is None:
        return None
    target = node.child(field)
    if target is None:
        return None
    receiver = ""
    if node.type in _CREATION:
        words = _WORD.findall(source.text(target, 256))
        simple = words[-1] if words else ""
    elif node.type in _CALL_RECEIVERS:
        simple = source.text(target, 128).strip()
        holder = node.child(_CALL_RECEIVERS[node.type])
        receiver = source.text(holder, 256) if holder is not None else ""
    elif target.type in _RECEIVER_FIELDS:
        left, right = _RECEIVER_FIELDS[target.type]
        holder, name = target.child(left), target.child(right) if right else None
        if name is None:
            words = _WORD.findall(source.text(target, 256))
            simple, receiver = (words[-1] if words else ""), " ".join(words[:-1])
        else:
            simple = source.text(name, 128).strip()
            receiver = source.text(holder, 256) if holder is not None else ""
    else:
        words = _WORD.findall(source.text(target, 256))
        simple = words[-1] if words else ""
        receiver = " ".join(words[:-1]) if len(words) > 1 else ""
    simple = simple.lstrip("$")
    return CallFact(node, simple, receiver, tuple(_WORD.findall(receiver)), _arguments(node))


def _qualified(rule: CallRule, segments: tuple[str, ...]) -> bool:
    if "*" in rule.qualifiers:
        return True
    for qualifier in rule.qualifiers:
        if qualifier.startswith("*"):
            if any(segment.endswith(qualifier[1:]) for segment in segments):
                return True
        elif qualifier in segments:
            return True
    return False


def rule_matches(rule: CallRule, fact: CallFact, grammar: str, imports: frozenset[str]) -> bool:
    if grammar not in rule.grammars:
        return False
    if fact.simple not in rule.names and not any(fact.simple.startswith(prefix) for prefix in rule.prefixes):
        return False
    if fact.segments:
        return bool(rule.qualifiers) and _qualified(rule, fact.segments)
    if not rule.allow_bare:
        return False
    return not rule.bare_imports or bool(imports & rule.bare_imports)


class UnitIndex:
    """Map syntax nodes to their innermost functional unit."""

    def __init__(self, units: list[Mapping[str, Any]]):
        self.units = sorted(units, key=lambda item: (item["start_byte"], -item["end_byte"]))

    def containing(self, start: int, end: int) -> str | None:
        best = None
        for unit in self.units:
            if unit["start_byte"] > start:
                break
            if unit["end_byte"] >= end and (best is None or unit["start_byte"] >= best["start_byte"]):
                best = unit
        return best["function_id"] if best else None

    def starting_at(self, node: Node) -> str | None:
        for unit in self.units:
            if unit["start_byte"] == node.start and unit["end_byte"] == node.end:
                return unit["function_id"]
        return None


def _next_unit(node: Node, spec: LanguageSpec, units: UnitIndex) -> str | None:
    """The unit a leading annotation, attribute, or comment documents (next declaration sibling)."""
    current = node
    while current.parent is not None and current.parent.type in {"attribute_item", "attribute_list", "modifiers",
                                                                  "attribute_group"} | _RUST_ATTRIBUTES:
        current = current.parent
    parent = current.parent
    if parent is None:
        return None
    siblings = parent.children
    index = next((position for position, item in enumerate(siblings) if item is current), None)
    if index is None:
        return None
    for item in siblings[index + 1:]:
        if item.type in _TRANSPARENT_SIBLINGS or not item.named:
            continue
        if item.start_line - node.end_line > 2:
            return None
        if item.type == "export_statement":
            item = item.child("declaration") or item
        return units.starting_at(item) if item.type in spec.units else None
    return None


class Extractor:
    """Collect every signal for one parsed file."""

    def __init__(self, source: SourceFile, spec: LanguageSpec, units: list[Mapping[str, Any]],
                 imports: Iterable[str], settings: Mapping[str, Any]):
        self.source = source
        self.spec = spec
        self.units = UnitIndex(units)
        self.unit_by_id = {unit["function_id"]: unit for unit in units}
        self.imports = frozenset(imports)
        self.settings = settings
        self.signals: list[dict[str, Any]] = []
        self.suppressions: list[dict[str, Any]] = []
        self.unit_counters: dict[str, Counter[str]] = defaultdict(Counter)
        self.unit_mutations: dict[str, Counter[str]] = defaultdict(Counter)

    # -- recording -------------------------------------------------------------------------------
    def _location(self, node: Node) -> dict[str, int]:
        return {"start_byte": node.start, "end_byte": node.end, "start_line": node.start_line,
                "end_line": node.end_line, "start_column": node.start_column, "end_column": node.end_column}

    def signal(self, node: Node, rule_id: str, category: str, surface: str, basis: str, *,
               function_id: str | None | bool = False, detail: Mapping[str, Any] | None = None) -> None:
        owner = self.units.containing(node.start, node.end) if function_id is False else function_id
        self.signals.append({
            "rule_id": rule_id, "rules": RULES_IDENTITY, "producer": "tree-sitter", "basis": basis,
            "category": category, "surface": surface, "path": self.source.path, "file_sha256": self.source.sha256,
            "function_id": owner, **self._location(node), "detail": dict(detail or {}),
        })

    # -- passes ----------------------------------------------------------------------------------
    def run(self) -> None:
        self.foreign_functions = frozenset(
            self.source.text(name, 128) for node in self.source.root.walk() if node.type == "foreign_mod_item"
            for item in node.walk() if item.type == "function_signature_item"
            for name in [item.child("name")] if name is not None) if self.spec.grammar == "rust" else frozenset()
        for node in self.source.root.walk():
            kind = node.type
            if kind in COMMENT_TYPES:
                self._comment(node)
                continue
            if kind in self.spec.calls:
                fact = call_fact(self.source, node, self.spec)
                if fact is not None:
                    self._call(fact)
            if kind in _ANNOTATION_TYPES or kind in _RUST_ATTRIBUTES:
                self._annotation(node)
            self._syntax(node)
        self._unit_heuristics()

    def _call(self, fact: CallFact) -> None:
        grammar = self.spec.grammar
        owner = self.units.containing(fact.node.start, fact.node.end)
        for rule in CALL_RULES:
            if not rule_matches(rule, fact, grammar, self.imports):
                continue
            detail = {"callee": fact.simple, "receiver": fact.receiver[:128]}
            if rule.category == "state_mutation":
                if owner is not None:
                    self.unit_mutations[owner][rule.surface] += 1
                continue
            if rule.category == "custom_parsing":
                if owner is not None:
                    self.unit_counters[owner]["manual_serialization"] += 1
                continue
            if rule.surface == "regex":
                detail["pattern_literal"] = bool(fact.arguments) and fact.arguments[0].type in _STRINGS | {"regex"}
            self.signal(fact.node, rule.rule_id, rule.category, rule.surface, HEURISTIC, function_id=owner,
                        detail=detail)
        if fact.simple in self.foreign_functions and not fact.segments:
            self.signal(fact.node, "wrapper.ffi.extern-call", "sensitive_wrapper", "ffi", OBSERVED, function_id=owner,
                        detail={"callee": fact.simple})
        self._route(fact, owner)
        self._insecure_call(fact)
        if grammar in {"javascript", "typescript", "tsx"} and fact.simple == "object" and set(fact.segments) & {
                "z", "Joi", "yup"}:
            self.signal(fact.node, "schema.validation-object", "public_api", "schema", OBSERVED, function_id=owner)
        if fact.node.type in _CREATION and fact.simple == "Schema":
            self.signal(fact.node, "schema.model", "public_api", "schema", OBSERVED, function_id=owner)

    def _route(self, fact: CallFact, owner: str | None) -> None:
        verbs = ROUTE_VERBS.get(self.spec.grammar)
        if not verbs or fact.simple not in verbs or not fact.segments or not fact.arguments:
            return
        if self.spec.grammar in {"javascript", "typescript", "tsx"} and not set(fact.segments) & JS_ROUTE_RECEIVERS:
            return
        first = fact.arguments[0]
        if first.type not in _STRINGS or not _strip(self.source.text(first, 512)).startswith("/"):
            return
        route = _strip(self.source.text(first, 512))[:256]
        self.signal(fact.node, "route.registration", "public_api", "route", OBSERVED, function_id=owner,
                    detail={"route": route, "verb": fact.simple})
        handlers = [item for item in fact.arguments[1:] if item.named and item.type in self.spec.units]
        for handler in handlers:
            self.signal(handler, "route.handler", "ingress", "route_handler", OBSERVED,
                        function_id=self.units.starting_at(handler), detail={"route": route, "verb": fact.simple})
        if not handlers:
            self.signal(fact.node, "route.handler-reference", "ingress", "route_handler", HEURISTIC, function_id=owner,
                        detail={"route": route, "verb": fact.simple})

    def _insecure_call(self, fact: CallFact) -> None:
        texts = [self.source.text(item, 256).strip() for item in fact.arguments]
        name = fact.simple
        insecure = None
        if name in {"curl_setopt", "curl_easy_setopt"} and len(texts) >= 3 and texts[1] in {
                "CURLOPT_SSL_VERIFYPEER", "CURLOPT_SSL_VERIFYHOST"} and texts[2] in {"false", "FALSE", "0", "0L"}:
            insecure = "tls_peer_verification_disabled"
        elif name in {"SSL_CTX_set_verify", "SSL_set_verify"} and any("SSL_VERIFY_NONE" in text for text in texts):
            insecure = "tls_peer_verification_disabled"
        elif name in {"danger_accept_invalid_certs", "danger_accept_invalid_hostnames"} and texts[:1] == ["true"]:
            insecure = "tls_peer_verification_disabled"
        elif name in {"setHostnameVerifier", "setDefaultHostnameVerifier"} and fact.arguments and (
                any(marker in texts[0] for marker in ("NoopHostnameVerifier", "ALLOW_ALL")) or
                self._returns_true(fact.arguments[0])):
            insecure = "hostname_verification_disabled"
        if insecure:
            self.signal(fact.node, f"privilege.insecure_verification.{name}", "privilege_shift",
                        "insecure_verification", OBSERVED, detail={"setting": insecure, "callee": name})

    def _returns_true(self, node: Node) -> bool:
        if node.type not in self.spec.anonymous:
            return False
        body = node.child("body")
        if body is None:
            return False
        if self.source.text(body, 16).strip() == "true":
            return True
        statements = body.named_children()
        return (len(statements) == 1 and statements[0].type == "return_statement" and
                self.source.text(statements[0], 64).replace(" ", "").rstrip(";") == "returntrue")

    def _annotation(self, node: Node) -> None:
        grammar = self.spec.grammar
        if node.type in _RUST_ATTRIBUTES:
            attribute = next((item for item in node.named_children() if item.type == "attribute"), None)
            if attribute is None:
                return
            words = _WORD.findall(self.source.text(attribute, 512))
            name = words[0] if words else ""
            arguments = self.source.text(attribute, 1024)
            owner = None if node.type == "inner_attribute_item" else _next_unit(node, self.spec, self.units)
            if name in {"allow", "expect"}:
                self._suppression_attribute(node, arguments, owner, "file" if owner is None and
                                            node.type == "inner_attribute_item" else "declaration")
            elif name in RUST_ROUTE_ATTRIBUTES and owner is not None:
                self.signal(node, "annotation.route", "ingress", "route_handler", OBSERVED, function_id=owner)
                self.signal(node, "annotation.route-api", "public_api", "route", OBSERVED, function_id=owner)
            elif name == "derive" and RUST_SCHEMA_DERIVES.search(arguments):
                self.signal(node, "annotation.schema", "public_api", "schema", OBSERVED, function_id=owner)
            return
        target = node.child("name")
        if node.type == "decorator":
            target = next((item for item in node.named_children()), None)
            if target is not None and target.type == "call_expression":
                target = target.child("function")
        if target is None:
            return
        words = _WORD.findall(self.source.text(target, 256))
        if not words:
            return
        name = words[-1]
        if grammar == "csharp" and name.endswith("Attribute") and name != "Attribute":
            name = name[:-len("Attribute")]
        holder = node.child("arguments") or next(
            (item for item in node.children if item.type in {"attribute_argument_list", "annotation_argument_list",
                                                             "arguments"}), None)
        arguments = self.source.text(holder, 1024) if holder is not None else ""
        owner = self.units.containing(node.start, node.end) or _next_unit(node, self.spec, self.units)
        if name in {"SuppressWarnings", "SuppressFBWarnings", "SuppressMessage", "SuppressLint"}:
            self._suppression_attribute(node, f"{name}{arguments}", owner, "declaration", annotation=name)
            return
        if grammar == "java" and name == "native":
            return
        for rule_id, category, surface in ANNOTATIONS.get(name, ()):
            self.signal(node, rule_id, category, surface, OBSERVED, function_id=owner, detail={"annotation": name})

    def _syntax(self, node: Node) -> None:
        grammar = self.spec.grammar
        kind = node.type
        text = self.source.text
        if grammar == "go" and kind == "keyed_element":
            key, value = node.child("key"), node.child("value")
            if key is not None and value is not None and text(key, 64).strip() == "InsecureSkipVerify" and \
                    text(value, 16).strip() == "true":
                self.signal(node, "privilege.insecure_verification.InsecureSkipVerify", "privilege_shift",
                            "insecure_verification", OBSERVED, detail={"setting": "InsecureSkipVerify"})
        elif grammar in {"javascript", "typescript", "tsx"} and kind == "pair":
            key, value = node.child("key"), node.child("value")
            if key is not None and value is not None and _strip(text(key, 64)) in {"rejectUnauthorized", "strictSSL"} \
                    and text(value, 16).strip() == "false":
                self.signal(node, "privilege.insecure_verification.rejectUnauthorized", "privilege_shift",
                            "insecure_verification", OBSERVED, detail={"setting": _strip(text(key, 64))})
        elif kind == "assignment_expression":
            left, right = node.child("left"), node.child("right")
            if left is None or right is None:
                return
            words = _WORD.findall(text(left, 256))
            last = words[-1] if words else ""
            if grammar == "csharp" and last in _INSECURE_CALLBACKS and (
                    self._returns_true(right) or "DangerousAcceptAnyServerCertificateValidator" in text(right, 256)):
                self.signal(node, "privilege.insecure_verification.certificate-callback", "privilege_shift",
                            "insecure_verification", OBSERVED, detail={"setting": last})
            elif last == "NODE_TLS_REJECT_UNAUTHORIZED" and _strip(text(right, 16)) == "0":
                self.signal(node, "privilege.insecure_verification.node-tls", "privilege_shift",
                            "insecure_verification", OBSERVED, detail={"setting": last})
            elif grammar in {"javascript", "typescript", "tsx"} and last in {"innerHTML", "outerHTML"}:
                self.signal(node, "sink.html.inner-html", "sink", "html_output", HEURISTIC, detail={"property": last})
            elif grammar in {"javascript", "typescript", "tsx"} and text(left, 32).startswith(("module.exports",
                                                                                                 "exports.")):
                self.signal(node, "api.commonjs-export", "public_api", "export", OBSERVED,
                            function_id=self.units.containing(node.start, node.end))
        elif grammar in {"javascript", "typescript", "tsx"} and kind == "export_statement":
            declaration = node.child("declaration")
            surface = "exported_interface" if declaration is not None and declaration.type in {
                "interface_declaration", "type_alias_declaration"} else "export"
            self.signal(node, "api.esm-export", "public_api", surface, OBSERVED,
                        function_id=self.units.starting_at(declaration) if declaration is not None else None)
        elif grammar in {"javascript", "typescript", "tsx"} and kind == "member_expression":
            target, prop = node.child("object"), node.child("property")
            if target is not None and prop is not None and text(target, 32).split(".")[-1] in JS_INGRESS_OBJECTS \
                    and text(prop, 32) in JS_INGRESS_PROPERTIES:
                self.signal(node, "ingress.request-property", "ingress", "untrusted_input", HEURISTIC,
                            detail={"property": text(prop, 32)})
        elif grammar in {"javascript", "typescript", "tsx"} and kind == "jsx_attribute":
            if text(node, 64).startswith("dangerouslySetInnerHTML"):
                self.signal(node, "sink.html.dangerously-set", "sink", "html_output", OBSERVED)
        elif grammar == "go" and kind == "selector_expression":
            operand, field = node.child("operand"), node.child("field")
            if operand is not None and field is not None and text(operand, 16) in GO_INGRESS_OBJECTS and \
                    text(field, 32) in GO_INGRESS_FIELDS and (node.parent is None or node.parent.type != "call_expression"
                                                               or node.field != "function"):
                self.signal(node, "ingress.request-field", "ingress", "untrusted_input", HEURISTIC,
                            detail={"field": text(field, 32)})
        elif grammar == "go" and kind in {"function_declaration", "method_declaration"}:
            self._go_declaration(node)
        elif grammar == "go" and kind == "import_spec" and _strip(text(node.child("path") or node, 64)) == "C":
            self.signal(node, "wrapper.ffi.cgo", "sensitive_wrapper", "ffi", OBSERVED, function_id=None)
        elif grammar == "go" and kind == "type_spec":
            name = node.child("name")
            body = node.child("type")
            if body is not None and body.type == "struct_type" and any(
                    item.type == "field_declaration" and item.child("tag") is not None and
                    re.search(r"\b(json|xml|yaml):\"", text(item.child("tag"), 512)) for item in body.walk()):
                self.signal(node, "schema.go-struct-tags", "public_api", "schema", OBSERVED, function_id=None,
                            detail={"type": text(name, 64) if name is not None else ""})
        elif grammar == "php" and kind == "variable_name" and text(node, 32).lstrip("$") in PHP_SUPERGLOBALS:
            self.signal(node, "ingress.superglobal", "ingress", "untrusted_input", OBSERVED,
                        detail={"superglobal": text(node, 32)})
        elif grammar == "php" and kind == "error_suppression_expression":
            self._suppression(node, "suppression.php-error-control", "php", "compiler", "expression", "@")
        elif grammar == "php" and kind in {"method_declaration", "function_definition"}:
            self._php_declaration(node)
        elif grammar == "csharp" and kind == "member_access_expression":
            expression, name = node.child("expression"), node.child("name")
            if expression is not None and name is not None and text(expression, 32).split(".")[-1] == "Request" and \
                    text(name, 32) in CSHARP_INGRESS_PROPERTIES:
                self.signal(node, "ingress.request-property", "ingress", "untrusted_input", HEURISTIC,
                            detail={"property": text(name, 32)})
        elif grammar == "csharp" and kind == "preproc_pragma":
            body = text(node, 512)
            if re.search(r"\bwarning\s+disable\b", body):
                self._suppression_codes(node, body, "csharp-pragma")
            elif "nullable" in body and "disable" in body:
                self._suppression(node, "suppression.csharp-nullable", "csharp", "type", "block_start", body.strip())
        elif grammar == "csharp" and kind == "nullable_directive" and "disable" in text(node, 64):
            self._suppression(node, "suppression.csharp-nullable", "csharp", "type", "block_start", text(node, 64))
        elif grammar in {"csharp", "java"} and kind in {"method_declaration", "interface_declaration"}:
            self._modifier_declaration(node)
        elif grammar in {"c", "cpp"} and kind in {"preproc_call", "preproc_pragma"}:
            body = text(node, 512)
            if re.search(r"#\s*pragma\s+(warning\s*\(\s*disable|(GCC|clang)\s+diagnostic\s+ignored|diag_suppress)",
                         body):
                self._suppression_codes(node, body, "c-pragma")
        elif grammar in {"c", "cpp"} and kind == "declaration" and self.source.path.endswith((".h", ".hpp", ".hh")) \
                and node.parent is not None and node.parent.type == "translation_unit" and \
                any(item.type == "function_declarator" for item in node.walk()):
            self.signal(node, "api.header-declaration", "public_api", "header_declaration", OBSERVED, function_id=None)
        elif grammar == "rust" and kind == "unsafe_block":
            self._suppression(node, "suppression.rust-unsafe", "rustc", "compiler", "expression", "unsafe")
        elif grammar == "rust" and kind == "foreign_mod_item":
            self.signal(node, "wrapper.ffi.extern-block", "sensitive_wrapper", "ffi", OBSERVED, function_id=None)
        elif grammar == "rust" and kind in _PUBLIC_RUST_ITEMS:
            visibility = next((item for item in node.children if item.type == "visibility_modifier"), None)
            if visibility is not None and text(visibility, 16).strip() == "pub":
                self.signal(node, "api.rust-pub", "public_api", "pub_item", OBSERVED,
                            function_id=self.units.starting_at(node))
            if kind == "function_item":
                parameters = node.child("parameters")
                if parameters is not None and any(
                        RUST_INGRESS_EXTRACTORS.match(text(item.child("type"), 64).strip())
                        for item in parameters.named_children() if item.child("type") is not None):
                    self.signal(node, "ingress.rust-extractor", "ingress", "request_binding", OBSERVED,
                                function_id=self.units.starting_at(node))
        elif grammar in {"typescript", "tsx"} and kind == "as_expression":
            named = node.named_children()
            if named and text(named[-1], 16).strip() == "any":
                self._suppression(node, "suppression.ts-as-any", "typescript", "type", "expression", "as any")
        elif grammar == "java" and kind == "modifiers" and re.search(r"\bnative\b", text(node, 256)):
            owner = self.units.containing(node.start, node.end)
            parent = node.parent
            if parent is not None and parent.type == "method_declaration":
                self.signal(parent, "wrapper.ffi.java-native", "sensitive_wrapper", "ffi", OBSERVED, function_id=owner)

    def _go_declaration(self, node: Node) -> None:
        package = next((item for item in self.source.root.children if item.type == "package_clause"), None)
        package_name = _WORD.findall(self.source.text(package, 64))[-1] if package is not None else ""
        name = node.child("name")
        if package_name != "main" and name is not None and self.source.text(name, 64)[:1].isupper():
            self.signal(node, "api.go-exported", "public_api", "exported_function", OBSERVED,
                        function_id=self.units.starting_at(node))
        parameters = node.child("parameters")
        result = node.child("result")
        if parameters is not None and result is not None and "http.Handler" in self.source.text(parameters, 256) and \
                self.source.text(result, 64).strip() == "http.Handler":
            self.signal(node, "middleware.go-handler-wrapper", "middleware", "request_pipeline", OBSERVED,
                        function_id=self.units.starting_at(node))

    def _php_declaration(self, node: Node) -> None:
        visibility = next((item for item in node.children if item.type == "visibility_modifier"), None)
        if node.type == "function_definition" or visibility is None or self.source.text(visibility, 16) == "public":
            self.signal(node, "api.php-public", "public_api", "public_method", OBSERVED,
                        function_id=self.units.starting_at(node))

    def _modifier_declaration(self, node: Node) -> None:
        modifiers = [item for item in node.children if item.type in {"modifiers", "modifier"}]
        if any(re.search(r"\bpublic\b", self.source.text(item, 256)) for item in modifiers):
            surface = "public_interface" if node.type == "interface_declaration" else "public_method"
            self.signal(node, "api.public-modifier", "public_api", surface, OBSERVED,
                        function_id=self.units.starting_at(node) if node.type == "method_declaration" else None)

    # -- suppressions ----------------------------------------------------------------------------
    def _suppression(self, node: Node, rule_id: str, tool: str, category: str, scope: str, directive: str, *,
                     owner: str | None | bool = False) -> None:
        if owner is False:
            owner = self.units.containing(node.start, node.end)
            if owner is None and scope in {"next_line", "declaration", "line"}:
                owner = _next_unit(node, self.spec, self.units)
        self.suppressions.append({
            "rule_id": rule_id, "rules": RULES_IDENTITY, "producer": "tree-sitter", "basis": OBSERVED,
            "category": category, "tool": tool, "scope": scope, "directive": directive[:256],
            "path": self.source.path, "file_sha256": self.source.sha256, "function_id": owner, **self._location(node),
        })

    def _comment(self, node: Node) -> None:
        body = self.source.text(node, 4096)
        for rule in COMMENT_SUPPRESSIONS:
            match = rule.pattern.search(body)
            if match is None:
                continue
            tail = body[match.start():match.start() + 256]
            category = "security" if rule.category != "security" and SECURITY_MARKERS.search(tail) else rule.category
            self._suppression(node, rule.rule_id, rule.tool, category, rule.scope, tail.splitlines()[0].strip())
            return

    def _suppression_codes(self, node: Node, body: str, tool: str) -> None:
        if tool == "csharp-pragma":
            codes = re.findall(r"\b[A-Z]{2,4}\d{3,5}\b", body)
            category = ("security" if SECURITY_MARKERS.search(body) else
                        "compiler" if codes and all(code.startswith("CS") for code in codes) else "lint")
        else:
            category = "security" if SECURITY_MARKERS.search(body) else "compiler"
        self._suppression(node, f"suppression.{tool}", tool, category, "block_start", body.strip().splitlines()[0])

    def _suppression_attribute(self, node: Node, text: str, owner: str | None, scope: str, *,
                               annotation: str | None = None) -> None:
        if annotation == "SuppressWarnings":
            keys = re.findall(r"\"([^\"]{1,128})\"", text)
            category = ("security" if SECURITY_MARKERS.search(text) else
                        "compiler" if keys and all(key in JAVA_COMPILER_KEYS for key in keys) else "lint")
            tool = "javac" if category == "compiler" else "java-lint"
        elif annotation == "SuppressMessage":
            category = "security" if SECURITY_MARKERS.search(text) else "lint"
            tool = "dotnet-analyzers"
        elif annotation in {"SuppressFBWarnings", "SuppressLint"}:
            category = "security" if SECURITY_MARKERS.search(text) else "lint"
            tool = "spotbugs" if annotation == "SuppressFBWarnings" else "android-lint"
        else:
            category = ("security" if SECURITY_MARKERS.search(text) else
                        "lint" if "clippy::" in text else "compiler")
            tool = "clippy" if "clippy::" in text else "rustc"
        self._suppression(node, f"suppression.attribute.{annotation or 'rust-allow'}", tool, category, scope,
                          text.strip()[:256], owner=owner)

    # -- per-unit heuristics -----------------------------------------------------------------------
    def _unit_heuristics(self) -> None:
        settings = self.settings
        for function_id, unit in self.unit_by_id.items():
            node = unit["_node"]
            counters = self.unit_counters[function_id]
            for item in own_nodes(node, self.spec):
                if item.type in _SLICING:
                    counters["slicing"] += 1
                operator = item.operator()
                if operator in BITWISE and item.type not in {"unary_expression", "reference_expression",
                                                             "pointer_expression"}:
                    if operator in {"<<", ">>"} and self.spec.grammar == "cpp" and self._stream_shift(item):
                        continue
                    counters["bitwise"] += 1
                elif operator == "~" and item.type == "unary_expression":
                    counters["bitwise"] += 1
            total = sum(counters.values())
            sloc = max(1, int(unit["sloc"]))
            density = round(total / sloc, 6)
            unit["custom_parsing"] = {**dict(sorted(counters.items())), "total": total, "density": density}
            if total >= int(settings["custom_parsing_min_operations"]) and \
                    density >= float(settings["custom_parsing_min_density"]):
                self.signal(node, "parsing.dense-manual-decoding", "custom_parsing", "manual_decoding", HEURISTIC,
                            function_id=function_id, detail=unit["custom_parsing"])
            mutations = self.unit_mutations[function_id]
            kinds = {key for key in ("transaction", "db_write", "fs_write") if mutations.get(key)}
            operations = sum(mutations.values())
            unit["state_mutation"] = {**dict(sorted(mutations.items())), "total": operations}
            if operations >= int(settings["state_mutation_min_operations"]) and (
                    len(kinds) >= 2 or mutations.get("transaction", 0) >= 2):
                self.signal(node, "state.multi-mutation", "state_mutation", "multiple_state_mutations", HEURISTIC,
                            function_id=function_id, detail=unit["state_mutation"])
            surfaces = sorted({item["surface"] for item in self.signals
                               if item["function_id"] == function_id and item["category"] == "sensitive_wrapper"})
            unit["wrapper_surfaces"] = surfaces

    def _stream_shift(self, node: Node) -> bool:
        left, right = node.child("left"), node.child("right")
        for side in (left, right):
            if side is None:
                continue
            if side.type in _STRINGS or side.type == "concatenated_string":
                return True
            leftmost = side
            while leftmost.child("left") is not None:
                leftmost = leftmost.child("left")  # type: ignore[assignment]
            if _CPP_STREAM.search(self.source.text(leftmost, 64).strip()):
                return True
        return False
