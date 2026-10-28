"""Source-resolved syntax navigation over accepted parser nodes; never semantic call resolution."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from appsec_review.retrieval.syntax_contract import MAX_NAME_BYTES, SCHEMA
DEFINITIONS = {
    "c": {"function_definition", "struct_specifier", "enum_specifier"},
    "cpp": {"function_definition", "class_specifier", "struct_specifier", "namespace_definition"},
    "csharp": {"method_declaration", "constructor_declaration", "local_function_statement",
               "class_declaration", "interface_declaration", "struct_declaration", "namespace_declaration"},
    "go": {"function_declaration", "method_declaration", "type_spec"},
    "java": {"method_declaration", "constructor_declaration", "class_declaration",
             "interface_declaration", "enum_declaration", "record_declaration"},
    "javascript": {"function_declaration", "function_expression", "method_definition", "class_declaration"},
    "typescript": {"function_declaration", "function_expression", "method_definition", "class_declaration",
                   "interface_declaration", "type_alias_declaration"},
    "tsx": {"function_declaration", "function_expression", "method_definition", "class_declaration",
            "interface_declaration", "type_alias_declaration"},
    "kotlin": {"function_declaration", "class_declaration", "object_declaration"},
    "python": {"function_definition", "class_definition"},
    "ruby": {"method", "singleton_method", "class", "module"},
    "rust": {"function_item", "struct_item", "enum_item", "trait_item", "mod_item", "type_item"},
    "php": {"function_definition", "method_declaration", "class_declaration", "interface_declaration"},
}
CALLS = {
    "c": {"call_expression"}, "cpp": {"call_expression", "new_expression"},
    "csharp": {"invocation_expression", "object_creation_expression"},
    "go": {"call_expression"}, "java": {"method_invocation", "object_creation_expression"},
    "javascript": {"call_expression", "new_expression"},
    "typescript": {"call_expression", "new_expression"}, "tsx": {"call_expression", "new_expression"},
    "kotlin": {"call_expression"}, "python": {"call"},
    "ruby": {"call"}, "rust": {"call_expression"},
    "php": {"function_call_expression", "member_call_expression", "scoped_call_expression"},
}
IMPORTS = {
    "c": {"preproc_include"}, "cpp": {"preproc_include"},
    "csharp": {"using_directive"}, "go": {"import_spec"},
    "java": {"import_declaration"}, "javascript": {"import_statement", "export_statement"},
    "typescript": {"import_statement", "export_statement"}, "tsx": {"import_statement", "export_statement"},
    "kotlin": {"import_header"}, "python": {"import_statement", "import_from_statement"},
    "ruby": set(), "rust": {"use_declaration", "extern_crate_declaration"},
    "php": {"namespace_use_declaration", "include_expression", "require_expression"},
}
IDENTIFIERS = frozenset({"identifier", "simple_identifier", "type_identifier", "field_identifier",
                         "property_identifier", "constant", "name"})
_INDIRECT_IMPORTS = frozenset({"require", "require_relative", "load", "__import__", "import"})


def project(nodes: Sequence[Mapping[str, Any]], data: bytes, *, grammar: str,
            source_identity: str, identities: Mapping[tuple[int, ...], str],
            limitations: set[str] | None = None) -> dict[tuple[int, ...], dict[str, Any]]:
    """Project bounded written names onto canonical AST nodes without resolving their meanings."""
    if grammar not in DEFINITIONS:
        return {}
    limitations = set() if limitations is None else limitations
    by_ordinal = {tuple(node["ordinal_path"]): node for node in nodes}
    children: dict[tuple[int, ...], list[Mapping[str, Any]]] = {}
    for ordinal, node in by_ordinal.items():
        if ordinal:
            children.setdefault(ordinal[:-1], []).append(node)
    for values in children.values():
        values.sort(key=lambda node: tuple(node["ordinal_path"]))

    def text(node: Mapping[str, Any]) -> str | None:
        start, end = int(node["start_byte"]), int(node["end_byte"])
        if not 0 <= start <= end <= len(data):
            raise ValueError("syntax projection span exceeds accepted source bytes")
        if end - start > MAX_NAME_BYTES:
            limitations.add("written names exceeding 512 bytes omitted")
            return None
        try:
            return data[start:end].decode("utf-8")
        except UnicodeDecodeError:
            limitations.add("non-UTF-8 written names omitted")
            return None

    def named(node: Mapping[str, Any], fields: tuple[str, ...]) -> Mapping[str, Any] | None:
        # C/C++ declarators nest the identifier behind bounded parameter/pointer wrappers.
        for _ in range(64):
            values = children.get(tuple(node["ordinal_path"]), ())
            match = next(((field, child) for field in fields for child in values if child.get("field") == field), None)
            if match is None:
                return next((child for child in values if child["type"] in IDENTIFIERS), None)
            field, found = match
            if field != "declarator" or found["type"] in IDENTIFIERS:
                return found
            node, fields = found, ("declarator", "name")
        limitations.add("declarator navigation depth bound reached")
        return None

    result: dict[tuple[int, ...], dict[str, Any]] = {}
    contexts: dict[tuple[int, ...], tuple[str | None, list[str]]] = {}
    for ordinal, node in sorted(by_ordinal.items()):
        enclosing, qualifiers = contexts.get(ordinal[:-1], (None, [])) if ordinal else (None, [])
        contexts[ordinal] = (enclosing, qualifiers)
        kind = str(node["type"])
        if kind in DEFINITIONS.get(grammar, ()):
            category, anchor = "definition", named(node, ("name", "declarator"))
        elif kind in CALLS.get(grammar, ()):
            category, anchor = "call_expression", named(node, ("function", "name", "method", "constructor", "type"))
            if anchor is None and grammar == "kotlin":
                anchor = next((child for child in children.get(ordinal, ()) if child.get("named")
                               and child["type"] not in {"value_arguments", "type_arguments", "call_suffix"}), None)
        elif kind in IMPORTS.get(grammar, ()):
            category, anchor = "import", named(node, ("source", "path", "module_name", "name"))
            if kind == "export_statement" and not any(child.get("field") == "source"
                                                      for child in children.get(ordinal, ())):
                continue
            anchor = node if anchor is None else anchor
        elif kind in IDENTIFIERS:
            category, anchor = "reference", node
        else:
            continue
        if anchor is None or anchor.get("error") or anchor.get("missing"):
            continue
        written = text(anchor)
        if not written:
            continue
        projection = {
            "schema": SCHEMA, "source_identity": source_identity, "category": category,
            "written_name": written, "enclosing_definition": enclosing,
            "syntactic_qualifiers": qualifiers,
            "name_span": {key: anchor[key] for key in ("start_byte", "end_byte", "start_point", "end_point")},
            "resolution": "unresolved", "syntax_only": True,
        }
        # These remain written import expressions; even a literal is not a resolved module edge.
        if category == "import" or category == "call_expression" and written in _INDIRECT_IMPORTS:
            projection["import_expression"] = True
            projection["import_form"] = "call_expression" if category == "call_expression" else "syntax_declaration"
        result[ordinal] = projection
        if category == "definition":
            contexts[ordinal] = (identities[ordinal], [*qualifiers, written][-16:])
    return result
