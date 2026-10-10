"""Function-level structural complexity over Tree-sitter syntax.

Cyclomatic complexity (``appsec-review/cyclomatic-complexity/1``) is McCabe's decision count: one
plus each conditional branch, loop, non-default case clause, exhaustive multiway arm beyond the
first, guard, catch clause, conditional expression, and short-circuit boolean or null-coalescing
operator inside the unit.  Rust ``?`` and Go ``if err != nil { return ... }`` checks are explicit
error-propagation branches; both are counted (or both excluded) under one configuration switch
so that Go and Rust stay comparable, and the alternate value is always published.

Cognitive complexity (``appsec-review/cognitive-complexity-approx/1``) approximates the rules of
SonarSource's Cognitive Complexity white paper.  It is not SonarSource's implementation; the
documented deviations are listed in ``COGNITIVE_DEVIATIONS``.

Every lambda, closure, and function literal is its own unit.  Its decisions are excluded from the
enclosing unit, so nothing is counted twice.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import Any

from .languages import (
    CONDITION_FIELDS, NULL_COALESCING, SHORT_CIRCUIT, SHORT_CIRCUIT_ASSIGNMENT, LanguageSpec,
)
from .syntax import COMMENT_TYPES, Node, SourceFile, code_lines


CYCLOMATIC_IDENTITY = "appsec-review/cyclomatic-complexity/1"
COGNITIVE_IDENTITY = "appsec-review/cognitive-complexity-approx/1"
COGNITIVE_DEVIATIONS = (
    "nested lambdas and closures are scored as their own units starting at nesting 0 instead of "
    "adding to the enclosing method with a nesting increment",
    "recursion is detected only for direct calls whose callee name equals the unit name; indirect "
    "cycles and overload resolution are not analyzed",
    "boolean operator sequences are flattened through parentheses; negation does not split a sequence",
    "preprocessor conditionals and macro bodies are not scored and are reported as unsupported constructs",
)
_NAME_TYPES = frozenset({"identifier", "field_identifier", "qualified_identifier", "destructor_name",
                         "operator_name", "type_identifier", "name", "property_identifier"})
_LABEL_TYPES = frozenset({"identifier", "label_name", "statement_identifier", "label"})
_MACRO_FLOW_TOKENS = frozenset({"if", "match", "for", "while", "loop", "&&", "||", "?", "return"})
_ANONYMOUS_BINDINGS = {
    "variable_declarator": ("name",), "init_declarator": ("declarator",), "let_declaration": ("pattern",),
    "assignment_expression": ("left",), "pair": ("key",), "keyed_element": ("key",),
    "public_field_definition": ("name",), "field_definition": ("property", "name"),
    "short_var_declaration": ("left",), "property_declaration": ("name",),
}


def own_nodes(unit: Node, spec: LanguageSpec) -> Iterator[Node]:
    """Yield the unit's nodes without descending into nested functional units."""
    stack = list(reversed(unit.children))
    while stack:
        node = stack.pop()
        if node.named and node.type in spec.units:
            continue
        yield node
        stack.extend(reversed(node.children))


def is_unit(node: Node, spec: LanguageSpec) -> bool:
    if not node.named or node.type not in spec.units:
        return False
    if node.type in spec.anonymous:
        return True
    return node.child("body") is not None


def _last_name(source: SourceFile, node: Node | None) -> str | None:
    if node is None:
        return None
    current = node
    while True:
        nested = current.child("declarator") or current.child("name")
        if nested is None or nested is current:
            break
        current = nested
    if current.type in _NAME_TYPES or not current.children:
        text = source.text(current, 256).strip()
        return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1] if current.type == "qualified_identifier" else text
    names = [item for item in current.walk() if item.type in _NAME_TYPES]
    return source.text(names[-1], 256).strip() if names else None


def unit_name(source: SourceFile, node: Node, spec: LanguageSpec) -> tuple[str, bool]:
    if node.type not in spec.anonymous:
        if spec.grammar in {"c", "cpp"} and node.type == "function_definition":
            name = _last_name(source, node.child("declarator"))
        else:
            target = node.child("name")
            name = source.text(target, 256).strip() if target is not None else None
        return (name or "<unnamed>"), False
    parent = node.parent
    while parent is not None and parent.type in {"parenthesized_expression", "argument", "expression_list",
                                                 "literal_element"}:
        parent = parent.parent
    if parent is not None and parent.type in _ANONYMOUS_BINDINGS:
        for field in _ANONYMOUS_BINDINGS[parent.type]:
            target = parent.child(field)
            if target is not None and target.end <= node.start:
                name = _last_name(source, target)
                if name:
                    return name, True
    if parent is not None and parent.type in {"arguments", "argument_list"} and parent.parent is not None:
        call = parent.parent
        callee = call.child(spec.calls.get(call.type, "function")) if call.type in spec.calls else None
        if callee is not None:
            text = " ".join(source.text(callee, 96).split())[:64]
            return f"<callback:{text}>", True
    return "<anonymous>", True


def _qualifiers(source: SourceFile, node: Node, spec: LanguageSpec, names: dict[int, str]) -> list[str]:
    parts: list[str] = []
    current = node.parent
    while current is not None:
        if id(current) in names:
            parts.append(names[id(current)])
        elif current.type in spec.containers:
            target = current.child(spec.containers[current.type])
            if target is not None:
                parts.append(source.text(target, 256).strip())
        current = current.parent
    if spec.grammar == "go" and node.type == "method_declaration":
        receiver = node.child("receiver")
        types = [item for item in receiver.walk() if item.type == "type_identifier"] if receiver else []
        if types:
            parts.append(source.text(types[-1], 128))
    return list(reversed(parts))


def _case_count(node: Node, spec: LanguageSpec) -> int:
    if spec.grammar in {"c", "cpp"}:
        return 1 if node.child("value") is not None else 0
    if spec.grammar == "java":
        return 1 if any(item.type == "case" and not item.named for item in node.children) else 0
    if spec.grammar == "csharp":
        return sum(1 for item in node.children if item.type == "case" and not item.named)
    return 1


def _arm_count(node: Node, arms: frozenset[str]) -> int:
    count = sum(1 for item in node.children if item.type in arms)
    for item in node.children:
        if item.field == "body" or item.type == "match_block":
            count += sum(1 for child in item.children if child.type in arms)
    return count


def _go_error_check(source: SourceFile, node: Node, spec: LanguageSpec) -> bool:
    condition = node.child("condition")
    if condition is None or condition.type != "binary_expression" or condition.operator() != "!=":
        return False
    sides = [condition.child("left"), condition.child("right")]
    if not all(sides) or not any(side.type == "nil" for side in sides):  # type: ignore[union-attr]
        return False
    other = next(side for side in sides if side.type != "nil")  # type: ignore[union-attr]
    if other.type != "identifier":
        return False
    name = source.text(other, 64)
    if not (name == "err" or name.endswith("Err") or name.endswith("err")):
        return False
    consequence = node.child("consequence")
    return consequence is not None and any(item.type == "return_statement" for item in own_nodes(consequence, spec))


def _boolean_top(node: Node) -> bool:
    if node.operator() not in SHORT_CIRCUIT:
        return False
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    return parent is None or parent.operator() not in SHORT_CIRCUIT


def _boolean_runs(node: Node) -> int:
    """Count runs of like short-circuit operators in token order across one boolean expression."""
    tokens: list[tuple[int, str]] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "parenthesized_expression" or current.operator() in SHORT_CIRCUIT:
            for item in current.children:
                if item.field == "operator" and item.type in SHORT_CIRCUIT:
                    tokens.append((item.start, item.type))
            stack.extend(item for item in current.children if item.named)
    ordered = [value for _start, value in sorted(tokens)]
    return sum(1 for index, value in enumerate(ordered) if index == 0 or ordered[index - 1] != value)


def callee_name(source: SourceFile, node: Node, spec: LanguageSpec) -> str | None:
    field = spec.calls.get(node.type)
    if field is None:
        return None
    target = node.child(field)
    if target is None:
        return None
    if target.type in _NAME_TYPES or not target.children:
        return source.text(target, 256).strip()
    for name_field in ("name", "field", "property", "member"):
        candidate = target.child(name_field)
        if candidate is not None:
            return source.text(candidate, 256).strip()
    names = [item for item in target.walk() if item.type in _NAME_TYPES]
    return source.text(names[-1], 256).strip() if names else None


def _cognitive(source: SourceFile, unit: Node, spec: LanguageSpec, simple_name: str) -> dict[str, Any]:
    increments: Counter[str] = Counter()
    total = 0
    max_nesting = 0
    recursive = False
    stack: list[tuple[Node, int, bool]] = [(item, 0, False) for item in reversed(unit.children)]

    def push_children(node: Node, nesting: int, *, nested_except: frozenset[str] = CONDITION_FIELDS) -> None:
        for item in reversed(node.children):
            stack.append((item, nesting if item.field in nested_except else nesting + 1, False))

    while stack:
        node, nesting, else_if = stack.pop()
        if node.named and node.type in spec.units:
            continue
        max_nesting = max(max_nesting, nesting)
        kind = node.type
        if kind in spec.if_types or kind in spec.else_if_types:
            amount = 1 if else_if else 1 + nesting
            total += amount
            increments["else_if" if else_if else "if"] += amount
            for item in reversed(node.children):
                if item.field != "alternative":
                    stack.append((item, nesting if item.field in CONDITION_FIELDS else nesting + 1, False))
                    continue
                if item.type in spec.else_if_types or item.type in spec.if_types:
                    stack.append((item, nesting, True))
                    continue
                inner = item.named_children() if item.type in spec.else_wrappers else []
                if len(inner) == 1 and inner[0].type in spec.if_types:
                    stack.append((inner[0], nesting, True))
                    continue
                total += 1
                increments["else"] += 1
                if item.type in spec.else_wrappers:
                    stack.extend((child, nesting + 1, False) for child in reversed(item.children))
                else:
                    stack.append((item, nesting + 1, False))
            continue
        if kind in spec.loops or kind in spec.switches or kind in spec.catches or kind in spec.ternaries:
            total += 1 + nesting
            label = ("loop" if kind in spec.loops else "switch" if kind in spec.switches else
                     "catch" if kind in spec.catches else "ternary")
            increments[label] += 1 + nesting
            push_children(node, nesting)
            continue
        if kind == "let_declaration" and node.child("alternative") is not None:
            total += 1 + nesting
            increments["let_else"] += 1 + nesting
            push_children(node, nesting, nested_except=frozenset({"pattern", "value", "type"}))
            continue
        if kind in spec.gotos:
            total += 1
            increments["jump"] += 1
        elif kind in spec.labeled_jumps and any(item.type in _LABEL_TYPES for item in node.children):
            total += 1
            increments["jump"] += 1
        if _boolean_top(node):
            runs = _boolean_runs(node)
            total += runs
            increments["boolean_sequence"] += runs
        if kind in spec.calls and not recursive and callee_name(source, node, spec) == simple_name:
            recursive = True
        stack.extend((item, nesting, False) for item in reversed(node.children))
    if recursive:
        total += 1
        increments["recursion"] += 1
    return {"cognitive": total, "increments": dict(sorted(increments.items())), "max_nesting": max_nesting,
            "recursive": recursive}


def _cyclomatic(source: SourceFile, unit: Node, spec: LanguageSpec, count_error_propagation: bool) -> dict[str, Any]:
    decisions: Counter[str] = Counter()
    rust_try = go_checks = 0
    unsupported: Counter[str] = Counter()
    parse_error = unit.error
    for node in own_nodes(unit, spec):
        kind = node.type
        parse_error = parse_error or node.error
        if kind in spec.if_types or kind in spec.else_if_types:
            decisions["if"] += 1
            if spec.grammar == "go" and _go_error_check(source, node, spec):
                go_checks += 1
        elif kind in spec.loops:
            decisions["loop"] += 1
        elif kind in spec.cases:
            decisions["case"] += _case_count(node, spec)
        elif kind in spec.multiway:
            decisions["multiway_arm"] += max(0, _arm_count(node, spec.multiway[kind]) - 1)
        elif kind in spec.guards or (kind == "match_pattern" and node.child("condition") is not None):
            decisions["guard"] += 1
        elif kind in spec.catches:
            decisions["catch"] += 1
        elif kind in spec.ternaries:
            decisions["ternary"] += 1
        elif kind == "let_declaration" and node.child("alternative") is not None:
            decisions["let_else"] += 1
        elif kind == "try_expression":
            rust_try += 1
        operator = node.operator()
        if operator in SHORT_CIRCUIT:
            decisions["boolean"] += 1
        elif operator in NULL_COALESCING or operator in SHORT_CIRCUIT_ASSIGNMENT:
            decisions["null_coalescing"] += 1
        if kind in spec.unsupported:
            if kind == "macro_invocation":
                if any(not item.named and item.type in _MACRO_FLOW_TOKENS for item in node.walk()):
                    unsupported["macro_control_flow_not_analyzed"] += 1
            else:
                unsupported["preprocessor_conditional_not_analyzed"] += 1
    base = 1 + sum(decisions.values())
    standard = base + rust_try
    without = base - go_checks
    return {"cyclomatic": standard if count_error_propagation else without,
            "cyclomatic_with_error_propagation": standard,
            "cyclomatic_without_error_propagation": without,
            "error_propagation": {"rust_try_operator": rust_try, "go_error_check": go_checks},
            "decisions": dict(sorted(decisions.items())), "unsupported_constructs": dict(sorted(unsupported.items())),
            "parse_error": bool(parse_error)}


def function_units(source: SourceFile, spec: LanguageSpec, *, count_error_propagation: bool,
                   limit: int) -> tuple[list[dict[str, Any]], bool]:
    """Return every functional unit in the file with its complexity facts, and a truncation flag.

    Each unit carries its syntax node under ``_node`` for the heuristic pass; callers drop it before
    serializing.
    """
    nodes = [node for node in source.root.walk() if is_unit(node, spec)]
    truncated = len(nodes) > limit
    names: dict[int, str] = {}
    identities: dict[int, str] = {}
    units: list[dict[str, Any]] = []
    for node in nodes[:limit]:
        name, anonymous = unit_name(source, node, spec)
        names[id(node)] = name
        qualified = ".".join([*_qualifiers(source, node, spec, names), name])
        function_id = f"{source.path}#{qualified}@{node.start_line}:{node.start_column}"
        identities[id(node)] = function_id
        parent = node.parent
        while parent is not None and id(parent) not in identities:
            parent = parent.parent
        lines = code_lines(node)
        cyclomatic = _cyclomatic(source, node, spec, count_error_propagation)
        cognitive = _cognitive(source, node, spec, name if not anonymous else "\x00")
        units.append({
            "function_id": function_id, "path": source.path, "language": spec.language, "grammar": spec.grammar,
            "name": name, "qualified_name": qualified, "anonymous": anonymous, "node_type": node.type,
            "parent_function": identities.get(id(parent)) if parent is not None else None,
            "start_byte": node.start, "end_byte": node.end, "start_line": node.start_line,
            "end_line": node.end_line, "start_column": node.start_column, "end_column": node.end_column,
            "sloc": len(lines), **cyclomatic, **cognitive,
            "complexity_density": round(cyclomatic["cyclomatic"] / len(lines), 6) if lines else None,
            "_node": node,
        })
    return units, truncated


def file_summary(units: list[dict[str, Any]], sloc: int, thresholds: list[int]) -> dict[str, Any]:
    values = [int(unit["cyclomatic"]) for unit in units]
    total = sum(values)
    summary: dict[str, Any] = {
        "function_count": len(values), "sloc": sloc, "cyclomatic_total": total,
        "cyclomatic_max": max(values) if values else None,
        "cyclomatic_average": round(total / len(values), 6) if values else None,
        "cognitive_total": sum(int(unit["cognitive"]) for unit in units),
        "cognitive_max": max((int(unit["cognitive"]) for unit in units), default=None),
        "complexity_density": round(total / sloc, 6) if sloc else None,
        "functions_above_threshold": {str(limit): sum(1 for value in values if value > limit) for limit in thresholds},
        "share_above_threshold": {str(limit): (round(sum(1 for value in values if value > limit) / len(values), 6)
                                               if values else None) for limit in thresholds},
    }
    return summary


def comment_nodes(root: Node) -> Iterator[Node]:
    for node in root.walk():
        if node.type in COMMENT_TYPES:
            yield node
