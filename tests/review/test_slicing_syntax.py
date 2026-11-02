"""tree_sitter_references slice strategy over real tree-sitter syntax-projection row shapes.

Rows are built the way the accepted index holds them: tree-sitter node dicts (the container output shape
used by tests/test_syntax_retrieval.py) are projected by the real
``jobs.job_tree_sitter_ast.projection.project`` and wrapped like ``normalize_scope`` payloads/locations as
returned by ``RetrievalCore._entity`` (identity, kind, native_id, payload, location).
"""
from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA as REAL_NORMALIZER_SCHEMA
from appsec_review.jobs.job_tree_sitter_ast.projection import project
from appsec_review.retrieval import EntityKind, LogicalIdentity
from appsec_review.retrieval.syntax_contract import SCHEMA
from appsec_review.review.slicing import registry
from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_TRUNCATED, Anchor, FunctionSpan, LineKey, Precision, Reason, SliceRequest,
    SliceStrategy, StrategyState,
)
from appsec_review.review.slicing.strategies import tree_sitter
from appsec_review.review.slicing.strategies.tree_sitter import NORMALIZER_SCHEMA, TreeSitterReferences

I, BD = Reason.INTERACTER, Reason.BACKWARD_DEF
PATH_REF = "asr:dataflow_path:" + "1" * 64


class Src:
    def __init__(self, text: str) -> None:
        self.data = text.encode()
        self.lines = text.split("\n")
        self.offsets = [0]
        for line in self.lines[:-1]:
            self.offsets.append(self.offsets[-1] + len(line) + 1)
        self.sha = hashlib.sha256(self.data).hexdigest()

    def span(self, line: int, token: str, nth: int = 0) -> tuple[int, int]:
        match = list(re.finditer(r"(?<!\w)" + re.escape(token) + r"(?!\w)", self.lines[line - 1]))[nth]
        return self.offsets[line - 1] + match.start(), self.offsets[line - 1] + match.end()


def _n(kind: str, field: str | None, *children: tuple, span: tuple[int, int] | None = None) -> tuple:
    if span is None:
        span = (min(child[2][0] for child in children), max(child[2][1] for child in children))
    return (kind, field, span, children)


def _leaf(src: Src, kind: str, line: int, token: str, field: str | None = None, nth: int = 0) -> tuple:
    return (kind, field, src.span(line, token, nth), ())


def _id(src: Src, line: int, name: str, field: str | None = None, nth: int = 0) -> tuple:
    return _leaf(src, "identifier", line, name, field, nth)


def _field(spec: tuple, field: str) -> tuple:
    return (spec[0], field, *spec[2:])


def _assign(left: tuple, right: tuple) -> tuple:
    return _n("expression_statement", None, _n("assignment", None, _field(left, "left"), _field(right, "right")))


def _call(function: tuple, *arguments: tuple, field: str | None = None) -> tuple:
    if not arguments:
        return _n("call", field, _field(function, "function"))
    return _n("call", field, _field(function, "function"), _n("argument_list", "arguments", *arguments))


def _attr(obj: tuple, attribute: tuple, field: str | None = None) -> tuple:
    return _n("attribute", field, _field(obj, "object"), _field(attribute, "attribute"))


def _def(src: Src, line: int, name: str, params: Sequence[str], *body: tuple) -> tuple:
    parameters = _n("parameters", "parameters", *(_id(src, line, param) for param in params))
    return _n("function_definition", None, _id(src, line, name, "name"), parameters, _n("block", "body", *body))


def _point(data: bytes, offset: int) -> list[int]:
    prefix = data[:offset]
    return [prefix.count(b"\n"), offset - prefix.rfind(b"\n") - 1]


def rows_for(src: Src, path: str, *statements: tuple, native_ids: bool = True) -> list[dict[str, Any]]:
    """``RetrievalCore._entity``-shaped ``ast_node`` rows for ``normalize_scope`` output of ``src``."""
    nodes: list[dict[str, Any]] = []

    def walk(spec: tuple, ordinal: tuple[int, ...]) -> None:
        kind, field, (start, end), children = spec
        nodes.append({"type": kind, "ordinal_path": list(ordinal), "field": field, "named": True, "error": False,
                      "missing": False, "extra": False, "has_error": False, "start_byte": start, "end_byte": end,
                      "start_point": _point(src.data, start), "end_point": _point(src.data, end)})
        for index, child in enumerate(children):
            walk(child, (*ordinal, index))

    walk(("module", None, (0, len(src.data)), statements), ())
    source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, "snapshot", {"path": path, "sha256": src.sha}).value
    ids = {tuple(node["ordinal_path"]): "asr:ast_node:" + hashlib.sha256(
        f"{path}:{node['ordinal_path']}".encode()).hexdigest() for node in nodes}
    projection = project(nodes, src.data, grammar="python", source_identity=source_id, identities=ids)
    rows = []
    for node in nodes:
        ordinal = tuple(node["ordinal_path"])
        payload = {"schema": REAL_NORMALIZER_SCHEMA, "grammar_native_type": node["type"], "field": node["field"],
                   **{name: node[name] for name in ("named", "error", "missing", "extra", "has_error")},
                   "language": "Python", "syntax_only": True}
        if ordinal in projection:
            payload["syntax"] = projection[ordinal]
        row = {"identity": ids[ordinal], "kind": "ast_node", "name": node["type"], "index": "analysis",
               "payload": payload,
               "location": {"path": path, "file_sha256": src.sha, "start_byte": node["start_byte"],
                            "end_byte": node["end_byte"], "start_line": node["start_point"][0] + 1,
                            "end_line": node["end_point"][0] + 1, "start_column": node["start_point"][1] + 1,
                            "end_column": node["end_point"][1] + 1,
                            "mapping_method": "tree-sitter-byte-and-point-exact", "confidence": 1.0,
                            "ambiguous": False}}
        if native_ids:
            row["native_id"] = "/".join(map(str, ordinal)) or "root"
        rows.append(row)
    return rows


class FakeSources:
    def __init__(self, rows: Mapping[str, Sequence[Mapping[str, Any]] | None]) -> None:
        self.rows = rows
        self.calls: list[str] = []

    def source_lines(self, path, file_sha256):
        return None, "not used"

    def ir_flows(self, path):
        return None

    def svf_records(self, path, line):
        return None

    def syntax_rows(self, path):
        self.calls.append(path)
        return self.rows.get(path)


VIEWS = Src('def handler(request, mode):\n'            # 1
            '    base = "/srv"\n'                     # 2
            '    name = request.args["file"]\n'       # 3  source
            '    path = base + name\n'                # 4
            '    other = 1\n'                         # 5
            '    log(path)\n'                         # 6
            '    os.system(path)\n'                   # 7  sink
            '    return other\n'                      # 8
            '\n'                                      # 9
            'def unrelated(path):\n'                  # 10
            '    return path\n')                      # 11


def _views_rows(**options: Any) -> list[dict[str, Any]]:
    s = VIEWS
    handler = _def(s, 1, "handler", ("request", "mode"),
                   _assign(_id(s, 2, "base"), _leaf(s, "string", 2, '"/srv"')),
                   _assign(_id(s, 3, "name"), _n("subscript", None,
                                                 _attr(_id(s, 3, "request"), _id(s, 3, "args"), "value"),
                                                 _leaf(s, "string", 3, '"file"', "subscript"))),
                   _assign(_id(s, 4, "path"), _n("binary_operator", None, _id(s, 4, "base", "left"),
                                                 _id(s, 4, "name", "right"))),
                   _assign(_id(s, 5, "other"), _leaf(s, "integer", 5, "1")),
                   _n("expression_statement", None, _call(_id(s, 6, "log"), _id(s, 6, "path"))),
                   _n("expression_statement", None, _call(_attr(_id(s, 7, "os"), _id(s, 7, "system")),
                                                          _id(s, 7, "path"))),
                   _n("return_statement", None, _id(s, 8, "other")))
    unrelated = _def(s, 10, "unrelated", ("path",), _n("return_statement", None, _id(s, 11, "path")))
    return rows_for(s, "app/views.py", handler, unrelated, **options)


def _key(src: Src, path: str, line: int) -> LineKey:
    return LineKey(path, src.sha, line)


def _views_request(rows: Any, spans: Sequence[tuple[int, int]] = ((1, 8), (10, 11))) -> SliceRequest:
    anchors = (Anchor(_key(VIEWS, "app/views.py", 3), Reason.SOURCE, PATH_REF),
               Anchor(_key(VIEWS, "app/views.py", 7), Reason.SINK, PATH_REF))
    functions = tuple(FunctionSpan("app/views.py", VIEWS.sha, first, last) for first, last in spans)
    return SliceRequest(anchors, functions, FakeSources({"app/views.py": rows}))


def _lines(contribution) -> dict[int, set[Reason]]:
    return {line.key.line: set(line.reasons) for line in contribution.lines}


def test_projection_rows_are_the_real_shape() -> None:
    rows = _views_rows()
    assert NORMALIZER_SCHEMA == REAL_NORMALIZER_SCHEMA
    references = [row for row in rows if row["payload"].get("syntax", {}).get("category") == "reference"]
    assert {row["payload"]["syntax"]["schema"] for row in references} == {SCHEMA}
    assert {"request", "args", "path", "os", "system"} <= {row["payload"]["syntax"]["written_name"]
                                                           for row in references}
    calls = [row["payload"]["syntax"]["written_name"] for row in rows
             if row["payload"].get("syntax", {}).get("category") == "call_expression"]
    assert sorted(calls) == ["log", "os.system"]


def test_interacters_and_backward_definitions_from_anchor_identifiers() -> None:
    contribution = TreeSitterReferences().expand(_views_request(_views_rows()))
    assert contribution.state is StrategyState.APPLIED and contribution.gaps == ()
    assert contribution.strategy == "tree_sitter_references" and contribution.precision is Precision.SYNTAX
    # 1: request parameter (interacter of the source line, binding of request); 2: base = ... reaches line 4;
    # 4: path = base + name (shares name/path, binds path used by the sink); 6: log(path) shares path.
    # 5 and 8 (other) are unrelated; base + name does not bind base (binary_operator left).
    assert _lines(contribution) == {1: {I, BD}, 2: {BD}, 4: {I, BD}, 6: {I}}
    assert all(line.basis == "tree_sitter_references" and line.precision is Precision.SYNTAX
               for line in contribution.lines)
    assert [line.key for line in contribution.lines] == sorted(line.key for line in contribution.lines)


def test_lines_stay_inside_the_anchor_function_span() -> None:
    request = _views_request(_views_rows(), spans=((3, 7), (10, 11)))
    contribution = TreeSitterReferences().expand(request)
    # path in unrelated() is never related; lines 1-2 are outside the narrowed span.
    assert _lines(contribution) == {4: {I, BD}, 6: {I}}
    assert all(request.span_for(line.key) is not None for line in contribution.lines)


def test_receiver_and_callee_names_do_not_relate_lines() -> None:
    s = Src("class C:\n"                     # 1
            "    def go(self, data):\n"      # 2
            "        self.data = data\n"     # 3
            "        self.flush(sink)\n"     # 4
            "        sink(self.data)\n")     # 5 sink
    method = _def(s, 2, "go", ("self", "data"),
                  _assign(_attr(_id(s, 3, "self"), _id(s, 3, "data")), _id(s, 3, "data", nth=1)),
                  _n("expression_statement", None, _call(_attr(_id(s, 4, "self"), _id(s, 4, "flush")),
                                                         _id(s, 4, "sink"))),
                  _n("expression_statement", None, _call(_id(s, 5, "sink"), _attr(_id(s, 5, "self"),
                                                                                  _id(s, 5, "data")))))
    klass = _n("class_definition", None, _id(s, 1, "C", "name"), _n("block", "body", method))
    rows = rows_for(s, "app/c.py", klass)
    request = SliceRequest((Anchor(_key(s, "app/c.py", 5), Reason.SINK, PATH_REF),),
                           (FunctionSpan("app/c.py", s.sha, 2, 5),), FakeSources({"app/c.py": rows}))
    contribution = TreeSitterReferences().expand(request)
    # self.data = data writes an attribute, not the name data; line 4 shares only self and the callee sink.
    assert _lines(contribution) == {2: {I, BD}, 3: {I}}


CHAIN = Src("def chain(a0):\n"   # 1
            "    a1 = a0\n"      # 2
            "    a2 = a1\n"      # 3
            "    a3 = a2\n"      # 4
            "    a4 = a3\n"      # 5
            "    sink(a4)\n")    # 6 sink


def _chain_request() -> SliceRequest:
    s = CHAIN
    body = [_assign(_id(s, line, f"a{line - 1}"), _id(s, line, f"a{line - 2}")) for line in range(2, 6)]
    rows = rows_for(s, "app/chain.py", _def(s, 1, "chain", ("a0",), *body,
                                           _n("expression_statement", None, _call(_id(s, 6, "sink"),
                                                                                  _id(s, 6, "a4")))))
    return SliceRequest((Anchor(_key(s, "app/chain.py", 6), Reason.SINK, PATH_REF),),
                        (FunctionSpan("app/chain.py", s.sha, 1, 6),), FakeSources({"app/chain.py": rows}))


def test_backward_definitions_close_a_def_use_chain_within_the_round_cap() -> None:
    contribution = TreeSitterReferences().expand(_chain_request())
    assert contribution.state is StrategyState.APPLIED and contribution.gaps == ()
    assert _lines(contribution) == {1: {BD}, 2: {BD}, 3: {BD}, 4: {BD}, 5: {I, BD}}


def test_round_cap_cuts_backward_definitions_with_a_named_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tree_sitter, "MAX_ROUNDS", 2)
    contribution = TreeSitterReferences().expand(_chain_request())
    assert _lines(contribution) == {3: {BD}, 4: {BD}, 5: {I, BD}}
    assert contribution.gaps == (f"{GAP_TRUNCATED}: tree_sitter_references: backward definitions cut after 2 rounds",)


def test_missing_projection_for_every_span_file_is_not_applicable() -> None:
    sources = FakeSources({})
    base = _views_request(None)
    contribution = TreeSitterReferences().expand(SliceRequest(base.anchors, base.functions, sources))
    assert contribution.state is StrategyState.NOT_APPLICABLE and contribution.lines == ()
    assert contribution.gaps == (f"{GAP_NOT_APPLICABLE}: tree_sitter_references: app/views.py: "
                                 "no accepted tree-sitter syntax projection",)
    assert sources.calls == ["app/views.py"]
    empty = TreeSitterReferences().expand(SliceRequest(base.anchors, (), sources))
    assert empty.state is StrategyState.NOT_APPLICABLE and empty.gaps[0].startswith(GAP_NOT_APPLICABLE)


def test_rows_without_projection_or_for_another_file_version_are_unavailable() -> None:
    stripped = [{**row, "payload": {key: value for key, value in row["payload"].items() if key != "syntax"}}
                for row in _views_rows()]
    rehashed = [{**row, "location": {**row["location"], "file_sha256": "f" * 64}} for row in _views_rows()]
    for rows in (stripped, rehashed):
        contribution = TreeSitterReferences().expand(_views_request(rows))
        assert contribution.state is StrategyState.NOT_APPLICABLE and contribution.lines == ()
        assert "carry no syntax projection" in contribution.gaps[0]


def test_empty_rows_are_available_and_empty() -> None:
    contribution = TreeSitterReferences().expand(_views_request([]))
    assert contribution.state is StrategyState.APPLIED and contribution.lines == () and contribution.gaps == ()


def test_some_span_files_without_rows_are_partial() -> None:
    base = _views_request(_views_rows())
    other = FunctionSpan("app/other.py", "b" * 64, 1, 20)
    request = SliceRequest(base.anchors, (*base.functions, other),
                           FakeSources({"app/views.py": _views_rows(), "app/other.py": None}))
    contribution = TreeSitterReferences().expand(request)
    assert contribution.state is StrategyState.PARTIAL
    assert _lines(contribution) == {1: {I, BD}, 2: {BD}, 4: {I, BD}, 6: {I}}
    assert contribution.gaps == (f"{GAP_NOT_APPLICABLE}: tree_sitter_references: app/other.py: "
                                 "no accepted tree-sitter syntax projection",)


def test_rows_without_node_structure_keep_interacters_only() -> None:
    contribution = TreeSitterReferences().expand(_views_request(_views_rows(native_ids=False)))
    assert contribution.state is StrategyState.PARTIAL
    assert _lines(contribution) == {1: {I}, 4: {I}, 6: {I}}
    assert len(contribution.gaps) == 1 and "native_id" in contribution.gaps[0]


def test_output_is_deterministic_for_reordered_rows() -> None:
    rows = _views_rows()
    first = TreeSitterReferences().expand(_views_request(rows))
    shuffled = list(rows)
    random.Random(7).shuffle(shuffled)
    assert TreeSitterReferences().expand(_views_request(shuffled)) == first
    assert TreeSitterReferences().expand(_views_request(rows)) == first


def test_registry_loads_the_strategy() -> None:
    strategy = registry.load("tree_sitter_references")
    assert isinstance(strategy, TreeSitterReferences) and isinstance(strategy, SliceStrategy)
    assert strategy.name == "tree_sitter_references" and strategy.precision is Precision.SYNTAX
