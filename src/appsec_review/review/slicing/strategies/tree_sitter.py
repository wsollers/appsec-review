"""Syntax-precision slice strategy over the accepted tree-sitter syntax projection.

Strategy ``tree_sitter_references`` (precision ``syntax``) relates a dataflow path's anchor lines to other
lines of the same function by written identifier names, following LLMxCPG (arXiv:2507.16585):

1. **Interacters** - every non-anchor line of a function span that references an identifier written on
   one of that span's anchor lines (``Reason.INTERACTER``).
2. **Backward definitions** - for each identifier on an anchor or interacter line, the in-span lines
   before that use where the identifier is a syntactic binding target (assignment left side, declarator,
   parameter, loop/with/except target) (``Reason.BACKWARD_DEF``). Identifiers on a found definition line
   seed the next round; at most ``MAX_ROUNDS`` rounds run and a ``slice_truncated`` gap is recorded when
   the cap leaves work pending.

Input (``SliceSources.syntax_rows(path)``): the accepted ``ast_node`` rows of the ``analysis`` index for
``path``, i.e. ALL nodes of the file (not only projected ones; parents are needed to classify binding
targets), each shaped as ``RetrievalCore._entity`` returns them for rows that
``jobs.job_tree_sitter_ast.normalize.normalize_scope`` wrote. Consumed fields (anything else is ignored):

- ``native_id``: ``"/"``-joined tree-sitter ordinal path of the node (``"root"`` for the root); gives
  the parent node.
- ``payload.schema``: ``"appsec-review/tree-sitter-normalizer/1"`` (rows of other producers, e.g. clang
  ``ast_node`` rows, are ignored).
- ``payload.grammar_native_type``: tree-sitter node type (e.g. ``identifier``, ``assignment``).
- ``payload.field``: the node's field name in its parent (e.g. ``left``, ``name``) or ``None``.
- ``payload.syntax`` (present only on projected nodes, schema ``appsec-review/syntax-projection/1``):
  ``schema``, ``category`` (``reference``/``definition``/``call_expression``/``import``),
  ``written_name``, and ``name_span.start_byte``/``name_span.end_byte``.
- ``location``: ``path``, ``file_sha256``, ``start_line`` (1-based), ``start_byte``, ``end_byte``.

Identifier occurrences are the projected ``reference`` rows (one per identifier node; the projection has
no other identifier-level category). The callee name of a ``call_expression`` row (its ``name_span``) is
not an occurrence, and the receiver names ``self``/``cls``/``this`` are ignored because they appear on
most method lines.

Missing data: ``None`` for every span file -> ``not_applicable``; ``None`` (or rows without a syntax
projection for the span's file hash) for some span files -> ``partial`` with a per-file gap; rows
without ``native_id`` -> ``partial`` (interacters only). An empty sequence is an available, empty file.

Limitations: names are unresolved written text (no scopes, imports, shadowing or aliasing); lines are
matched by name within one function span only; reaching definitions use line order without control
flow (every earlier binding is kept, loop back edges are ignored); attribute/subscript targets
(``obj.x = v``, ``buf[i] = v``) do not define the base name. The binding-target table targets Python
and covers common C/C++, Java, JavaScript/TypeScript, Go and Rust forms best-effort.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from appsec_review.retrieval.syntax_contract import SCHEMA as SYNTAX_SCHEMA
from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_TRUNCATED, FunctionSpan, LineKey, Precision, Reason, SliceContribution, SliceLine,
    SliceRequest, StrategyState,
)

NAME = "tree_sitter_references"
# Matches jobs.job_tree_sitter_ast.normalize.NORMALIZER_SCHEMA (not imported: review must not load jobs).
NORMALIZER_SCHEMA = "appsec-review/tree-sitter-normalizer/1"
MAX_ROUNDS = 6
MAX_TARGET_DEPTH = 4
RECEIVER_NAMES = frozenset({"self", "cls", "this"})

# (parent node type, field of the child) pairs whose child subtree is a binding target.
BINDING_EDGES = frozenset({
    # Python
    ("assignment", "left"), ("augmented_assignment", "left"), ("for_statement", "left"),
    ("for_in_clause", "left"), ("named_expression", "name"), ("as_pattern", "alias"),
    ("default_parameter", "name"), ("typed_default_parameter", "name"),
    # C / C++
    ("init_declarator", "declarator"), ("declaration", "declarator"), ("parameter_declaration", "declarator"),
    ("assignment_expression", "left"), ("for_range_loop", "declarator"),
    # Java / JavaScript / TypeScript
    ("variable_declarator", "name"), ("formal_parameter", "name"), ("catch_formal_parameter", "name"),
    ("enhanced_for_statement", "name"), ("augmented_assignment_expression", "left"),
    ("for_in_statement", "left"), ("required_parameter", "pattern"), ("optional_parameter", "pattern"),
    # Go
    ("short_var_declaration", "left"), ("assignment_statement", "left"), ("var_spec", "name"),
    ("const_spec", "name"), ("parameter_declaration", "name"), ("range_clause", "left"),
    # Rust
    ("let_declaration", "pattern"), ("parameter", "pattern"), ("compound_assignment_expr", "left"),
    ("for_expression", "pattern"),
})
# Node types whose unnamed-field children are binding targets (parameter lists).
BINDING_CONTAINERS = frozenset({"parameters", "lambda_parameters", "typed_parameter", "formal_parameters"})
# Node types that pass a binding through to their identifiers (destructuring and declarator wrappers).
BINDING_WRAPPERS = frozenset({
    "pattern_list", "tuple_pattern", "list_pattern", "expression_list", "as_pattern_target",
    "list_splat_pattern", "dictionary_splat_pattern", "pointer_declarator", "array_declarator",
    "reference_declarator", "array_pattern", "object_pattern", "shorthand_property_identifier_pattern",
})


def _ordinal(native_id: Any) -> tuple[int, ...] | None:
    if native_id == "root":
        return ()
    if not isinstance(native_id, str) or not native_id:
        return None
    try:
        return tuple(int(part) for part in native_id.split("/"))
    except ValueError:
        return None


def _int(value: Any) -> int | None:
    return value if type(value) is int else None


class _FileRows:
    """Identifier occurrences of one file version: ``(line, name, binds)`` plus parent availability."""

    def __init__(self, rows: Iterable[Any], path: str, file_sha256: str) -> None:
        self.projected = False
        self.structured = False
        nodes: dict[tuple[int, ...], tuple[str, Any]] = {}
        references: list[tuple[int, int, int, str, tuple[int, ...] | None, Any]] = []
        callees: set[tuple[int, int]] = set()
        for row in sorted((row for row in rows if isinstance(row, Mapping)), key=lambda row: str(row.get("identity"))):
            payload, location = row.get("payload"), row.get("location")
            if not isinstance(payload, Mapping) or not isinstance(location, Mapping):
                continue
            if location.get("path") != path or location.get("file_sha256") != file_sha256:
                continue
            if payload.get("schema") != NORMALIZER_SCHEMA or not isinstance(payload.get("grammar_native_type"), str):
                continue
            ordinal = _ordinal(row.get("native_id"))
            if ordinal is not None:
                nodes.setdefault(ordinal, (payload["grammar_native_type"], payload.get("field")))
            syntax = payload.get("syntax")
            if not isinstance(syntax, Mapping) or syntax.get("schema") != SYNTAX_SCHEMA:
                continue
            self.projected = True
            category, written = syntax.get("category"), syntax.get("written_name")
            if category == "call_expression":
                span = syntax.get("name_span")
                if isinstance(span, Mapping) and _int(span.get("start_byte")) is not None:
                    callees.add((span["start_byte"], _int(span.get("end_byte")) or -1))
                continue
            line, start, end = (_int(location.get(key)) for key in ("start_line", "start_byte", "end_byte"))
            if category != "reference" or not isinstance(written, str) or not written or line is None or line < 1:
                continue
            references.append((line, -1 if start is None else start, -1 if end is None else end, written, ordinal,
                               payload.get("field")))
        self.structured = bool(nodes)
        seen: set[tuple[int, int, int]] = set()
        self.occurrences: list[tuple[int, str, bool]] = []
        for line, start, end, written, ordinal, field in sorted(references, key=lambda item: item[:4]):
            if (line, start, end) in seen or (start, end) in callees or written in RECEIVER_NAMES:
                continue
            seen.add((line, start, end))
            self.occurrences.append((line, written, self._binds(nodes, ordinal, field)))

    @staticmethod
    def _binds(nodes: Mapping[tuple[int, ...], tuple[str, Any]], ordinal: tuple[int, ...] | None,
               field: Any) -> bool:
        if not ordinal:
            return False
        for _ in range(MAX_TARGET_DEPTH):
            parent = nodes.get(ordinal[:-1])
            if parent is None:
                return False
            parent_type, parent_field = parent
            if (parent_type, field) in BINDING_EDGES or (field is None and parent_type in BINDING_CONTAINERS):
                return True
            if parent_type not in BINDING_WRAPPERS or len(ordinal) < 2:
                return False
            ordinal, field = ordinal[:-1], parent_field
        return False


class _Span:
    """Per-function-span name indices built from one file's occurrences."""

    def __init__(self, span: FunctionSpan, file_rows: _FileRows) -> None:
        self.span = span
        self.names_on: dict[int, set[str]] = {}
        self.lines_of: dict[str, set[int]] = {}
        self.bindings_of: dict[str, set[int]] = {}
        for line, name, binds in file_rows.occurrences:
            if not span.first <= line <= span.last:
                continue
            self.names_on.setdefault(line, set()).add(name)
            self.lines_of.setdefault(name, set()).add(line)
            if binds:
                self.bindings_of.setdefault(name, set()).add(line)

    def key(self, line: int) -> LineKey:
        return LineKey(self.span.path, self.span.file_sha256, line)


class TreeSitterReferences:
    """Interacters and backward definitions from the tree-sitter syntax projection (see module docstring)."""

    name = NAME
    precision = Precision.SYNTAX

    def expand(self, request: SliceRequest) -> SliceContribution:
        if not request.functions:
            return self._outcome(StrategyState.NOT_APPLICABLE, {},
                                 [f"{GAP_NOT_APPLICABLE}: {NAME}: the request has no function spans"])
        gaps: list[str] = []
        files: dict[tuple[str, str], _FileRows] = {}
        rows_by_path: dict[str, Any] = {}
        partial = False
        for path, sha in sorted({(span.path, span.file_sha256) for span in request.functions}):
            if path not in rows_by_path:
                rows = request.sources.syntax_rows(path)
                rows_by_path[path] = None if rows is None else tuple(rows)
            rows = rows_by_path[path]
            if rows is None:
                partial = True
                gaps.append(f"{GAP_NOT_APPLICABLE}: {NAME}: {path}: no accepted tree-sitter syntax projection")
                continue
            file_rows = _FileRows(rows, path, sha)
            if rows and not file_rows.projected:
                partial = True
                gaps.append(f"{GAP_NOT_APPLICABLE}: {NAME}: {path}: accepted ast_node rows carry no syntax "
                            f"projection for file {sha}")
                continue
            if file_rows.occurrences and not file_rows.structured:
                partial = True
                gaps.append(f"{GAP_NOT_APPLICABLE}: {NAME}: {path}: syntax rows lack node structure (native_id); "
                            "backward definitions unavailable")
            files[(path, sha)] = file_rows
        if not files:
            return self._outcome(StrategyState.NOT_APPLICABLE, {}, gaps)
        spans = [_Span(span, files[(span.path, span.file_sha256)]) for span in request.functions
                 if (span.path, span.file_sha256) in files]
        anchors = set(request.anchor_lines())
        reasons: dict[LineKey, set[Reason]] = {}

        def add(key: LineKey, reason: Reason) -> None:
            if key not in anchors:
                reasons.setdefault(key, set()).add(reason)

        seeds: set[tuple[int, str, int]] = set()
        for key in sorted(anchors):
            for index, item in enumerate(spans):
                if not item.span.contains(key):
                    continue
                for name in item.names_on.get(key.line, ()):
                    seeds.add((index, name, key.line))
                    for line in item.lines_of[name]:
                        if line != key.line:
                            add(item.key(line), Reason.INTERACTER)
                            seeds.update((index, other, line) for other in item.names_on[line])
        frontier, seen, rounds = sorted(seeds), set(seeds), 0
        while frontier and rounds < MAX_ROUNDS:
            rounds += 1
            found: set[tuple[int, str, int]] = set()
            for index, name, use in frontier:
                item = spans[index]
                for line in sorted(item.bindings_of.get(name, ())):
                    if line >= use:
                        break
                    add(item.key(line), Reason.BACKWARD_DEF)
                    found.update((index, other, line) for other in item.names_on[line])
            frontier = sorted(found - seen)
            seen.update(found)
        # Pending uses cut work only if they reach a binding line that has not been kept as one yet.
        cut = sum(1 for index, name, use in frontier for line in spans[index].bindings_of.get(name, ())
                  if line < use and spans[index].key(line) not in anchors
                  and Reason.BACKWARD_DEF not in reasons.get(spans[index].key(line), ()))
        if cut:
            gaps.append(f"{GAP_TRUNCATED}: {NAME}: backward definitions cut after {MAX_ROUNDS} rounds")
        state = StrategyState.PARTIAL if partial else StrategyState.APPLIED
        return self._outcome(state, reasons, gaps)

    def _outcome(self, state: StrategyState, reasons: Mapping[LineKey, set[Reason]],
                 gaps: list[str]) -> SliceContribution:
        lines = tuple(SliceLine(key, frozenset(reasons[key]), NAME, Precision.SYNTAX) for key in sorted(reasons))
        return SliceContribution(NAME, Precision.SYNTAX, state, lines, tuple(gaps))


__all__ = ["BINDING_CONTAINERS", "BINDING_EDGES", "BINDING_WRAPPERS", "MAX_ROUNDS", "MAX_TARGET_DEPTH", "NAME",
           "NORMALIZER_SCHEMA", "RECEIVER_NAMES", "TreeSitterReferences"]
