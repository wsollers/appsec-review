"""Function spans and complexity from source-resolved Tree-sitter concrete syntax trees.

The pinned ``tool-tree-sitter`` container returns every node with byte and point spans.  This
module turns those nodes into innermost function symbols and measures two distinct complexities
per function with a versioned, per-language node-type table:

- **Cyclomatic** (McCabe): ``1 +`` decision points.  Decision points are branch statements, loop
  heads, non-default case labels, catch clauses, conditional expressions, and short-circuit
  boolean operator tokens.
- **Cognitive** (after SonarSource's definition): ``+1`` plus the current nesting depth for each
  nesting control structure, ``+1`` for each ``else``/``elif``/``else if`` and ``goto``, and ``+1``
  for each run of the same boolean operator.  Recursion and labelled jumps are not detected.

Nested functions and lambdas are their own symbols and are excluded from their parents.  File
totals add every function and the decision points outside any function.  Syntax errors, node-limit
truncation, and C/C++ preprocessor conditionals inside a span are named gaps, because the counts
under them are incomplete.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from typing import Any


SYMBOL_IDENTITY = "appsec-review/history-symbols/1"
COMPLEXITY_IDENTITY = "appsec-review/complexity-rules/1"
_ELSE = frozenset({"else_clause", "else"})


@dataclass(frozen=True, slots=True)
class LanguageRules:
    functions: frozenset[str]
    containers: frozenset[str]
    ifs: frozenset[str]
    decisions: frozenset[str]
    cases: frozenset[str]
    nesting: frozenset[str]
    flat: frozenset[str]
    boolean_tokens: frozenset[str]
    preprocessor: frozenset[str] = frozenset()


def _rules(functions, containers, ifs, decisions, cases, nesting, flat, tokens, preprocessor=()) -> LanguageRules:
    return LanguageRules(frozenset(functions), frozenset(containers), frozenset(ifs), frozenset(decisions) | frozenset(ifs),
                         frozenset(cases), frozenset(nesting) | frozenset(ifs), frozenset(flat), frozenset(tokens),
                         frozenset(preprocessor))


_C_FAMILY_TOKENS = ("&&", "||")
_JAVASCRIPT = _rules(
    ("function_declaration", "function_expression", "function", "arrow_function", "method_definition",
     "generator_function_declaration", "generator_function"),
    ("class_declaration", "class", "abstract_class_declaration"),
    ("if_statement",),
    ("for_statement", "for_in_statement", "while_statement", "do_statement", "switch_case", "catch_clause",
     "ternary_expression"),
    (),
    ("for_statement", "for_in_statement", "while_statement", "do_statement", "switch_statement", "catch_clause",
     "ternary_expression"),
    ("else_clause",), ("&&", "||", "??"))
_C = _rules(
    ("function_definition", "lambda_expression"),
    ("class_specifier", "struct_specifier", "namespace_definition"),
    ("if_statement",),
    ("for_statement", "for_range_loop", "while_statement", "do_statement", "case_statement", "catch_clause",
     "conditional_expression"),
    ("case_statement",),
    ("for_statement", "for_range_loop", "while_statement", "do_statement", "switch_statement", "catch_clause",
     "conditional_expression"),
    ("else_clause", "goto_statement"), _C_FAMILY_TOKENS,
    ("preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else", "preproc_elifdef"))
RULES: Mapping[str, LanguageRules] = {
    "Python": _rules(
        ("function_definition", "lambda"), ("class_definition",), ("if_statement",),
        ("elif_clause", "for_statement", "while_statement", "except_clause", "conditional_expression", "case_clause",
         "for_in_clause", "if_clause"),
        (), ("for_statement", "while_statement", "except_clause", "conditional_expression", "match_statement"),
        ("elif_clause", "else_clause"), ("and", "or")),
    "JavaScript": _JAVASCRIPT, "TypeScript": _JAVASCRIPT, "TSX": _JAVASCRIPT,
    "Java": _rules(
        ("method_declaration", "constructor_declaration", "compact_constructor_declaration", "lambda_expression"),
        ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"),
        ("if_statement",),
        ("for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_label", "catch_clause",
         "ternary_expression"),
        ("switch_label",),
        ("for_statement", "enhanced_for_statement", "while_statement", "do_statement", "switch_expression",
         "switch_statement", "catch_clause", "ternary_expression"),
        (), _C_FAMILY_TOKENS),
    "C": _C, "C++": _C, "C/C++": _C,
    "C#": _rules(
        ("method_declaration", "constructor_declaration", "destructor_declaration", "operator_declaration",
         "local_function_statement", "lambda_expression", "anonymous_method_expression", "accessor_declaration"),
        ("class_declaration", "struct_declaration", "interface_declaration", "record_declaration",
         "namespace_declaration"),
        ("if_statement",),
        ("for_statement", "foreach_statement", "while_statement", "do_statement", "case_switch_label",
         "case_pattern_switch_label", "switch_expression_arm", "catch_clause", "conditional_expression"),
        (),
        ("for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement",
         "switch_expression", "catch_clause", "conditional_expression"),
        ("goto_statement",), ("&&", "||", "??"),
        ("if_directive", "elif_directive", "else_directive")),
    "Go": _rules(
        ("function_declaration", "method_declaration", "func_literal"), (), ("if_statement",),
        ("for_statement", "expression_case", "type_case", "communication_case"), (),
        ("for_statement", "expression_switch_statement", "type_switch_statement", "select_statement"),
        ("goto_statement",), _C_FAMILY_TOKENS),
    "Rust": _rules(
        ("function_item", "closure_expression"), ("impl_item", "trait_item", "mod_item"), ("if_expression",),
        ("while_expression", "for_expression", "match_arm"), (),
        ("while_expression", "for_expression", "loop_expression", "match_expression"),
        ("else_clause",), _C_FAMILY_TOKENS),
    "PHP": _rules(
        ("function_definition", "method_declaration", "anonymous_function_creation_expression", "anonymous_function",
         "arrow_function"),
        ("class_declaration", "interface_declaration", "trait_declaration", "namespace_definition"),
        ("if_statement",),
        ("else_if_clause", "for_statement", "foreach_statement", "while_statement", "do_statement", "case_statement",
         "catch_clause", "conditional_expression", "match_conditional_expression"),
        (),
        ("for_statement", "foreach_statement", "while_statement", "do_statement", "switch_statement", "catch_clause",
         "conditional_expression", "match_expression"),
        ("else_if_clause", "else_clause"), ("&&", "||", "??", "and", "or")),
}
_NAME_TYPES = frozenset({"identifier", "field_identifier", "qualified_identifier", "destructor_name", "operator_name",
                         "scoped_identifier", "property_identifier", "name", "type_identifier"})
_UNSAFE = re.compile(r"[^\w.:<>~$@#\-\[\]]+", re.UNICODE)


def tree_sitter_language(language: str | None, path: str) -> str | None:
    """Route a catalog language to its locked Tree-sitter grammar, or ``None`` when unsupported."""
    if language is None:
        return None
    if path.lower().endswith(".tsx"):
        return "TSX"
    return language if language in RULES else None


class _Tree:
    def __init__(self, nodes: Sequence[Mapping[str, Any]]):
        self.nodes = {tuple(int(value) for value in node["ordinal_path"]): node for node in nodes}
        self.children: dict[tuple[int, ...], list[tuple[int, ...]]] = {}
        for ordinal in sorted(self.nodes):
            if ordinal:
                self.children.setdefault(ordinal[:-1], []).append(ordinal)

    def parent(self, ordinal: tuple[int, ...]) -> tuple[int, ...] | None:
        return ordinal[:-1] if ordinal and ordinal[:-1] in self.nodes else None

    def type(self, ordinal: tuple[int, ...] | None) -> str | None:
        return None if ordinal is None else str(self.nodes[ordinal]["type"])

    def field_child(self, ordinal: tuple[int, ...], field: str) -> tuple[int, ...] | None:
        return next((child for child in self.children.get(ordinal, ()) if self.nodes[child].get("field") == field), None)

    def anonymous(self, ordinal: tuple[int, ...], types: frozenset[str]) -> str | None:
        return next((str(self.nodes[child]["type"]) for child in self.children.get(ordinal, ())
                     if not self.nodes[child].get("named") and str(self.nodes[child]["type"]) in types), None)


def _text(source: bytes, node: Mapping[str, Any]) -> str:
    raw = source[int(node["start_byte"]):int(node["end_byte"])][:256].decode("utf-8", "replace")
    return _UNSAFE.sub("_", raw).strip("_")[:128]


def _name(tree: _Tree, source: bytes, ordinal: tuple[int, ...]) -> str | None:
    current: tuple[int, ...] | None = ordinal
    for _ in range(16):
        if current is None:
            return None
        named = tree.field_child(current, "name")
        if named is not None:
            return _text(source, tree.nodes[named]) or None
        declarator = tree.field_child(current, "declarator")
        if declarator is None:
            break
        if tree.type(declarator) in _NAME_TYPES:
            return _text(source, tree.nodes[declarator]) or None
        current = declarator
    parent = tree.parent(ordinal)
    if parent is not None:
        for field in ("name", "key", "left"):
            child = tree.field_child(parent, field)
            if child is not None and child != ordinal and tree.type(child) in _NAME_TYPES:
                return _text(source, tree.nodes[child]) or None
    return None


def _is_else_if(tree: _Tree, ordinal: tuple[int, ...], rules: LanguageRules) -> bool:
    parent = tree.parent(ordinal)
    if tree.type(ordinal) not in rules.ifs or parent is None:
        return False
    return tree.type(parent) in _ELSE or (tree.nodes[ordinal].get("field") == "alternative" and
                                          tree.type(parent) in rules.ifs)


def _operator(tree: _Tree, ordinal: tuple[int, ...] | None, rules: LanguageRules) -> str | None:
    return None if ordinal is None else tree.anonymous(ordinal, rules.boolean_tokens)


def _measure(tree: _Tree, root: tuple[int, ...], rules: LanguageRules) -> dict[str, Any]:
    """Count decisions and cognitive increments under ``root``, stopping at nested functions."""
    decisions = cognitive = 0
    gaps: set[str] = set()
    nested: list[tuple[int, ...]] = []
    stack: list[tuple[tuple[int, ...], int]] = [(child, 0) for child in reversed(tree.children.get(root, ()))]
    while stack:
        ordinal, nesting = stack.pop()
        node = tree.nodes[ordinal]
        kind = str(node["type"])
        if kind in rules.functions:
            nested.append(ordinal)
            continue
        if node.get("error") or node.get("missing"):
            gaps.add("parse_errors_in_span")
        if kind in rules.preprocessor:
            gaps.add("preprocessor_branches_not_counted")
        child_nesting = nesting
        if not node.get("named") and kind in rules.boolean_tokens:
            decisions += 1
            expression = tree.parent(ordinal)
            outer = tree.parent(expression) if expression is not None else None
            while outer is not None and tree.type(outer) == "parenthesized_expression":
                outer = tree.parent(outer)
            if _operator(tree, outer, rules) != kind:
                cognitive += 1
        elif kind in rules.decisions and not (kind in rules.cases and tree.anonymous(ordinal, frozenset({"default"}))):
            decisions += 1
        if _is_else_if(tree, ordinal, rules):
            # ``else if`` scores +1 once: on the else node when the grammar has one, otherwise here.
            cognitive += 0 if tree.type(tree.parent(ordinal)) in _ELSE else 1
        elif kind in rules.nesting:
            cognitive += 1 + nesting
            child_nesting = nesting + 1
        elif kind in rules.flat:
            cognitive += 1
        if kind in rules.ifs:
            alternative = tree.field_child(ordinal, "alternative")
            if alternative is not None and tree.type(alternative) not in _ELSE | rules.ifs | rules.flat:
                cognitive += 1
        stack.extend((child, child_nesting) for child in reversed(tree.children.get(ordinal, ())))
    return {"decisions": decisions, "cognitive": cognitive, "gaps": sorted(gaps), "nested": nested}


def _nonblank(lines: Sequence[bytes], start: int, end: int) -> int:
    return sum(1 for line in lines[start - 1:end] if line.strip())


def extract(record: Mapping[str, Any], source: bytes, language: str, path: str) -> dict[str, Any]:
    """Return innermost function symbols, their own lines, spans, and complexities for one file."""
    rules = RULES[language]
    tree = _Tree(record.get("nodes", ()))
    gaps: set[str] = set()
    if record.get("truncated") or record.get("status") == "PARTIAL":
        gaps.add("node_limit_reached")
    if record.get("root_has_error"):
        gaps.add("parse_errors_present")
    roots = [ordinal for ordinal in tree.nodes if not ordinal]
    if not roots:
        return {"status": "unavailable", "language": language, "symbols": [], "gaps": sorted(gaps | {"no_syntax_tree"}),
                "file_complexity": None}
    lines = source.split(b"\n")
    module = _measure(tree, (), rules)
    pending = list(module["nested"])
    symbols: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    while pending:
        ordinal = pending.pop(0)
        node = tree.nodes[ordinal]
        measured = _measure(tree, ordinal, rules)
        pending.extend(measured["nested"])
        qualifiers = []
        ancestor = tree.parent(ordinal)
        while ancestor is not None:
            if tree.type(ancestor) in rules.containers or tree.type(ancestor) in rules.functions:
                qualifiers.append(_name(tree, source, ancestor) or f"<anonymous:{int(tree.nodes[ancestor]['start_point'][0]) + 1}>")
            ancestor = tree.parent(ancestor)
        start_line, end_line = int(node["start_point"][0]) + 1, int(node["end_point"][0]) + 1
        name = _name(tree, source, ordinal) or f"<anonymous:{start_line}>"
        qualified = ".".join([*reversed(qualifiers), name])
        base = f"{path}::{qualified}"
        seen[base] = seen.get(base, 0) + 1
        symbol_id = base if seen[base] == 1 else f"{base}#{seen[base]}"
        own: list[tuple[int, int]] = []
        cursor = start_line
        for child in sorted(measured["nested"], key=lambda item: int(tree.nodes[item]["start_byte"])):
            child_start = int(tree.nodes[child]["start_point"][0]) + 1
            child_end = int(tree.nodes[child]["end_point"][0]) + 1
            if child_start > cursor:
                own.append((cursor, child_start - 1))
            cursor = max(cursor, child_end + 1)
        if cursor <= end_line:
            own.append((cursor, end_line))
        symbols.append({
            "symbol_id": symbol_id, "qualified_name": qualified, "name": name, "kind": str(node["type"]),
            "language": language, "start_line": start_line, "end_line": end_line,
            "start_column": int(node["start_point"][1]) + 1, "end_column": int(node["end_point"][1]) + 1,
            "start_byte": int(node["start_byte"]), "end_byte": int(node["end_byte"]),
            "own_lines": own or [(start_line, start_line)], "nonblank_lines": _nonblank(lines, start_line, end_line),
            "cyclomatic_complexity": 1 + measured["decisions"], "cognitive_complexity": measured["cognitive"],
            "complexity_gaps": measured["gaps"],
        })
        gaps.update(measured["gaps"])
    symbols.sort(key=lambda item: (item["start_byte"], item["symbol_id"]))
    file_complexity = {
        "cyclomatic": module["decisions"] + sum(item["cyclomatic_complexity"] for item in symbols),
        "cognitive": module["cognitive"] + sum(item["cognitive_complexity"] for item in symbols),
        "function_count": len(symbols), "gaps": sorted(set(module["gaps"]) | {gap for item in symbols for gap in item["complexity_gaps"]}),
    }
    return {"status": "partial" if gaps else "complete", "language": language, "symbols": symbols,
            "gaps": sorted(gaps), "file_complexity": file_complexity}
