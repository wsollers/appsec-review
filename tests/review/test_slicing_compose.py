"""package-slice/1 anchors and composer: dataflow_path facts -> request -> budgeted, schema-valid slice."""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import jsonschema

from appsec_review.review.slicing.anchors import GAP_FUNCTION_UNRESOLVED, build_request
from appsec_review.review.slicing.compose import GAP_NO_EXPANSION, GAP_OUT_OF_SPAN, compose
from appsec_review.review.slicing.contract import (
    GAP_FAILED, GAP_LEXICAL_ONLY, GAP_NOT_APPLICABLE, GAP_SOURCE_UNAVAILABLE, GAP_STEP_UNLOCATED, GAP_TRUNCATED,
    PATH_BASIS, Anchor, FunctionSpan, LineKey, Precision, Reason, SliceBudget, SliceContribution, SliceLine,
    SliceRequest, StrategyState,
)

ROOT = Path(__file__).parents[2]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
SHA, PY_SHA = "a" * 64, "b" * 64
P1, P2 = "asr:dataflow_path:" + "1" * 64, "asr:dataflow_path:" + "2" * 64
FN, HELPER, INNER = ("asr:symbol:" + "3" * 64, "asr:symbol:" + "4" * 64, "asr:symbol:" + "5" * 64)
GUARD = "asr:guard_fact:" + "6" * 64

C_SOURCE = """#include <string.h>

static int helper(int v) {
    return v + 1;
}

void handle(char *input) {
    char buf[16];
    int n = strlen(input);
    if (n > 15) {
        return;
    }
    strcpy(buf, input);
}

int other(void) {
    return helper(2);
}
""".splitlines()

PY_SOURCE = """import os

def run(cmd):
    x = cmd.strip()
    def inner(y):
        return y
    os.system(x)

x = input()
""".splitlines()


class FakeSources:
    """In-memory accepted data; only the source text boundary is faked."""

    def __init__(self, files: Mapping[tuple[str, str], Sequence[str]]):
        self.files = dict(files)

    def source_lines(self, path: str, file_sha256: str) -> tuple[Sequence[str] | None, str | None]:
        lines = self.files.get((path, file_sha256))
        return (lines, None) if lines is not None else (None, "not in the accepted source index")

    def ir_flows(self, path: str) -> None:
        return None

    def svf_records(self, path: str, line: int) -> None:
        return None

    def syntax_rows(self, path: str) -> None:
        return None


SOURCES = FakeSources({("src/a.c", SHA): C_SOURCE, ("src/app.py", PY_SHA): PY_SOURCE})


class FakeStrategy:
    def __init__(self, name: str, precision: Precision, lines: Sequence[tuple[LineKey, Reason]] = (),
                 state: StrategyState = StrategyState.APPLIED, gaps: Sequence[str] = (), error: Exception | None = None,
                 returns: Any = None):
        self.name, self.precision = name, precision
        self._lines, self._state, self._gaps, self._error, self._returns = lines, state, tuple(gaps), error, returns
        self.calls = 0

    def expand(self, request: SliceRequest) -> SliceContribution:
        self.calls += 1
        if self._error is not None:
            raise self._error
        if self._returns is not None:
            return self._returns
        return SliceContribution(self.name, self.precision, self._state,
                                 tuple(SliceLine(key, frozenset({reason}), self.name, self.precision)
                                       for key, reason in self._lines), self._gaps)


def _validate(record: Mapping[str, Any]) -> None:
    jsonschema.Draft202012Validator(
        {"$defs": SCHEMA["$defs"], "$ref": "#/$defs/inference_package_slice"}).validate(record)


def _loc(line: int, path: str = "src/a.c", sha: str = SHA, *, end: int | None = None,
         ambiguous: bool = False) -> dict[str, Any]:
    return {"target_snapshot": "snap", "path": path, "file_sha256": sha, "start_byte": 0, "end_byte": 1,
            "start_line": line, "end_line": end or line, "start_column": 1, "end_column": 2,
            "producer_location": {}, "mapping_method": "test", "confidence": 1.0, "ambiguous": ambiguous,
            "schema": "x"}


def _step(n: int, role: str, location: Mapping[str, Any] | None, symbol: str | None = FN,
          display: str = "expr") -> dict[str, Any]:
    return {"n": n, "location": location, "role": role, "symbol": symbol, "display": display}


def _c_path(**extra: Any) -> dict[str, Any]:
    result = {"source": {"entry_point": None, "source_class": "x"}, "sink": {"sink_site": "s"},
              "steps": [_step(0, "source", _loc(7), display="input"), _step(1, "step", _loc(9), display="n"),
                        _step(2, "sink", _loc(13), display="strcpy(buf, input)")],
              "hop_count": 2, "call_depth": 0, "guards": [], "sanitizers": [], "truncated_steps": False}
    result.update(extra)
    return result


def _key(line: int, path: str = "src/a.c", sha: str = SHA) -> LineKey:
    return LineKey(path, sha, line)


# -- anchors -------------------------------------------------------------------------------------------


def test_path_roles_guards_and_sanitizers_become_anchors_in_the_enclosing_function() -> None:
    fact = _c_path(guards=[{"identity": GUARD, "location": _loc(10)}, GUARD],
                   sanitizers=[{"api": "strlen", "location": _loc(9)}, {"api": "check", "location": None}])
    request, gaps = build_request([(P1, fact)], SOURCES, max_function_lines=160)
    reasons = {(anchor.key.line, anchor.reason) for anchor in request.anchors}
    assert reasons == {(7, Reason.SOURCE), (9, Reason.PATH_STEP), (9, Reason.SANITIZER), (10, Reason.GUARD),
                       (13, Reason.SINK)}
    sink = next(anchor for anchor in request.anchors if anchor.reason is Reason.SINK)
    assert (sink.ref, sink.function, sink.symbol) == (P1, FN, "strcpy(buf, input)")
    guard = next(anchor for anchor in request.anchors if anchor.reason is Reason.GUARD)
    assert guard.ref == GUARD and guard.function is None
    assert request.functions == (FunctionSpan("src/a.c", SHA, 7, 14, function=FN, truncated=False),)
    assert gaps == (f"{GAP_STEP_UNLOCATED}: {P1} guard {GUARD}: no location in the path fact",
                    f"{GAP_STEP_UNLOCATED}: {P1} sanitizer check: no location")


def test_unlocated_and_ambiguous_steps_are_named_gaps_and_ambiguous_steps_still_anchor() -> None:
    fact = _c_path()
    fact["steps"][1] = _step(1, "call", _loc(9, ambiguous=True))
    fact["steps"].insert(2, _step(2, "return", None))
    fact["steps"].insert(3, _step(3, "step", {**_loc(11), "file_sha256": "nothex"}))
    request, gaps = build_request([(P1, fact)], SOURCES, max_function_lines=160)
    assert [anchor.key.line for anchor in request.anchors] == [7, 9, 13]
    assert gaps == (f"{GAP_STEP_UNLOCATED}: {P1} step 1: ambiguous location at src/a.c:9",
                    f"{GAP_STEP_UNLOCATED}: {P1} step 2: no location",
                    f"{GAP_STEP_UNLOCATED}: {P1} step 3: invalid location")


def test_inherited_path_gaps_are_prefixed_with_the_path_identity() -> None:
    payload = {"result": _c_path(truncated_steps=True), "gaps": [
        "omitted_paths: 3 other paths to this sink exceed max_paths_per_sink=4",
        "ambiguous_step_location: step 1 at a.c:9 (line_only_location)",
        "unclassified_sink: the path's sink is not classified by the catalog"]}
    _request, gaps = build_request([(P1, payload)], SOURCES, max_function_lines=160)
    assert gaps == (f"{P1}: omitted_paths: 3 other paths to this sink exceed max_paths_per_sink=4",
                    f"{P1}: ambiguous_step_location: step 1 at a.c:9 (line_only_location)",
                    f"{P1}: truncated_steps: middle steps of the path were dropped")
    _request, gaps = build_request([(P1, {"result": _c_path(), "gaps": ["truncated_steps: 9 steps"]})], SOURCES,
                                   max_function_lines=160)
    assert gaps == (f"{P1}: truncated_steps: 9 steps",)
    _request, gaps = build_request([(P2, {"steps": []})], SOURCES, max_function_lines=160)
    assert gaps == (f"dataflow_path_unavailable: {P2}: the path fact carries no steps",)


def test_unavailable_source_drops_its_anchors_with_a_gap_and_never_invents_a_span() -> None:
    other = _c_path(steps=[_step(0, "source", _loc(3, "src/missing.c")), _step(1, "sink", _loc(12))])
    request, gaps = build_request([(P1, _c_path()), (P2, other)], SOURCES, max_function_lines=160)
    assert {anchor.key.path for anchor in request.anchors} == {"src/a.c"}
    assert [span.path for span in request.functions] == ["src/a.c"]
    assert gaps == (f"{GAP_SOURCE_UNAVAILABLE}: src/missing.c: not in the accepted source index",)


def test_spans_per_function_merge_when_overlapping_and_mark_truncation() -> None:
    two = _c_path(steps=[_step(0, "source", _loc(4), symbol=HELPER), _step(1, "sink", _loc(13))])
    request, gaps = build_request([(P1, two)], SOURCES, max_function_lines=160)
    assert request.functions == (FunctionSpan("src/a.c", SHA, 3, 5, function=HELPER),
                                 FunctionSpan("src/a.c", SHA, 7, 14, function=FN)) and gaps == ()

    nested = {"steps": [_step(0, "source", _loc(6, "src/app.py", PY_SHA), symbol=INNER),
                        _step(1, "sink", _loc(7, "src/app.py", PY_SHA), symbol=FN)]}
    request, gaps = build_request([(P1, nested)], SOURCES, max_function_lines=160)
    assert request.functions == (FunctionSpan("src/app.py", PY_SHA, 3, 8, function=None),) and gaps == ()
    assert all(request.span_for(anchor.key) for anchor in request.anchors)

    request, gaps = build_request([(P1, _c_path(steps=[_step(0, "source", _loc(9)), _step(1, "sink", _loc(13))]))],
                                  SOURCES, max_function_lines=4)
    assert request.functions == (FunctionSpan("src/a.c", SHA, 7, 10, function=FN, truncated=True),)
    assert [anchor.key.line for anchor in request.anchors] == [9]
    assert gaps == (f"{GAP_FUNCTION_UNRESOLVED}: src/a.c:13: no enclosing function found within 4 lines; "
                    "the sink anchor is not sliced",)


def test_module_level_and_out_of_file_anchors_are_dropped_with_gaps() -> None:
    fact = {"steps": [_step(0, "source", _loc(9, "src/app.py", PY_SHA)),
                      _step(1, "sink", _loc(7, "src/app.py", PY_SHA)),
                      _step(2, "sink", _loc(40, "src/app.py", PY_SHA))]}
    request, gaps = build_request([(P1, fact)], SOURCES, max_function_lines=160)
    assert [anchor.key.line for anchor in request.anchors] == [7]
    assert gaps == (f"{GAP_FUNCTION_UNRESOLVED}: src/app.py:9: no enclosing function found within 160 lines; "
                    "the source anchor is not sliced",
                    f"{GAP_STEP_UNLOCATED}: {P1}: line 40 is beyond the end of src/app.py")


def test_build_request_is_deterministic_across_input_order() -> None:
    second = _c_path(steps=[_step(0, "source", _loc(4), symbol=HELPER), _step(1, "sink", _loc(17))])
    first = build_request([(P1, _c_path()), (P2, second)], SOURCES, max_function_lines=160)
    again = build_request([(P2, second), (P1, _c_path())], SOURCES, max_function_lines=160)
    assert first == again


# -- composer ------------------------------------------------------------------------------------------


def _request(*anchors: tuple[int, Reason], spans: Sequence[FunctionSpan] = (FunctionSpan("src/a.c", SHA, 1, 40),)
             ) -> SliceRequest:
    return SliceRequest(tuple(Anchor(_key(line), reason, P1) for line, reason in anchors), tuple(spans), SOURCES)


def _lines(result: Any) -> dict[int, SliceLine]:
    return {line.key.line: line for line in result.lines}


def test_union_keeps_the_highest_precision_basis_and_every_reason() -> None:
    request = _request((20, Reason.SINK))
    strategies = [
        FakeStrategy("lexical", Precision.LEXICAL, [(_key(8), Reason.INTERACTER), (_key(20), Reason.INTERACTER),
                                                    (_key(9), Reason.INTERACTER)]),
        FakeStrategy("syntax_a", Precision.SYNTAX, [(_key(8), Reason.BACKWARD_DEF), (_key(10), Reason.BACKWARD_DEF)]),
        FakeStrategy("syntax_b", Precision.SYNTAX, [(_key(10), Reason.ALIAS)]),
    ]
    result = compose(request, strategies, SliceBudget(), paths=[P1, P1])
    lines = _lines(result)
    assert (lines[8].basis, lines[8].precision, lines[8].reasons) == (
        "syntax_a", Precision.SYNTAX, frozenset({Reason.INTERACTER, Reason.BACKWARD_DEF}))
    assert (lines[10].basis, lines[10].reasons) == ("syntax_a", frozenset({Reason.BACKWARD_DEF, Reason.ALIAS}))
    assert (lines[20].basis, lines[20].precision, lines[20].reasons) == (
        PATH_BASIS, Precision.PATH, frozenset({Reason.SINK, Reason.INTERACTER}))
    assert lines[9].basis == "lexical"
    assert [(item.name, item.state, item.lines) for item in result.strategies] == [
        ("lexical", StrategyState.APPLIED, 3), ("syntax_a", StrategyState.APPLIED, 2),
        ("syntax_b", StrategyState.APPLIED, 1)]
    assert result.paths == (P1,) and result.gaps == () and result.omitted_lines == 0
    _validate(result.record())


def test_a_failing_strategy_is_isolated_and_named() -> None:
    request = _request((20, Reason.SINK))
    good = FakeStrategy("syntax", Precision.SYNTAX, [(_key(19), Reason.BACKWARD_DEF)])
    strategies = [FakeStrategy("boom", Precision.COMPILER, error=RuntimeError("x")),
                  FakeStrategy("bogus", Precision.SYNTAX, returns=["not a contribution"]), good]
    result = compose(request, strategies, SliceBudget())
    assert [(item.name, item.state, item.gaps) for item in result.strategies[:2]] == [
        ("boom", StrategyState.FAILED, (f"{GAP_FAILED}: boom: RuntimeError",)),
        ("bogus", StrategyState.FAILED, (f"{GAP_FAILED}: bogus: TypeError",))]
    assert good.calls == 1 and sorted(_lines(result)) == [19, 20]
    assert f"{GAP_FAILED}: boom: RuntimeError" in result.gaps and GAP_NO_EXPANSION not in result.gaps
    _validate(result.record())


def test_lines_outside_the_spans_are_dropped_and_named() -> None:
    request = _request((5, Reason.SOURCE), spans=(FunctionSpan("src/a.c", SHA, 1, 10),))
    strategy = FakeStrategy("syntax", Precision.SYNTAX, [(_key(6), Reason.INTERACTER), (_key(11), Reason.INTERACTER),
                                                         (_key(2, "src/b.c"), Reason.INTERACTER)])
    result = compose(request, [strategy], SliceBudget())
    assert sorted(_lines(result)) == [5, 6] and result.strategies[0].lines == 1
    gap = f"{GAP_OUT_OF_SPAN}: syntax: 2 lines outside the function spans were dropped"
    assert result.strategies[0].gaps == (gap,) and gap in result.gaps


def test_no_applicable_strategy_still_yields_the_anchors_with_gaps() -> None:
    request = _request((5, Reason.SOURCE), (9, Reason.SINK))
    gap = f"{GAP_NOT_APPLICABLE}: ir: no ir"
    result = compose(request, [FakeStrategy("ir", Precision.COMPILER, state=StrategyState.NOT_APPLICABLE, gaps=[gap]),
                               FakeStrategy("boom", Precision.SYNTAX, error=ValueError())], SliceBudget(),
                     inherited_gaps=[f"{P1}: truncated_steps: x"])
    assert sorted(_lines(result)) == [5, 9] and {line.basis for line in result.lines} == {PATH_BASIS}
    assert result.gaps == (f"{P1}: truncated_steps: x", gap, f"{GAP_FAILED}: boom: ValueError", GAP_NO_EXPANSION)
    assert compose(request, [], SliceBudget()).gaps == (GAP_NO_EXPANSION,)
    _validate(result.record())


def test_partial_gaps_propagate() -> None:
    gap = "slice_partial: syntax: rows for src/b.c are missing"
    result = compose(_request((5, Reason.SOURCE)), [FakeStrategy("syntax", Precision.SYNTAX, [(_key(6), Reason.ALIAS)],
                                                                 state=StrategyState.PARTIAL, gaps=[gap])],
                     SliceBudget())
    assert result.strategies[0].state is StrategyState.PARTIAL and result.gaps == (gap,)


def test_per_function_trim_drops_low_precision_then_far_then_high_lines_and_anchors_last() -> None:
    budget = SliceBudget(max_lines=10, max_lines_per_function=3)
    request = _request((20, Reason.SINK))
    lexical = FakeStrategy("lexical", Precision.LEXICAL, [(_key(21), Reason.INTERACTER)])
    syntax = FakeStrategy("syntax", Precision.SYNTAX, [(_key(22), Reason.BACKWARD_DEF), (_key(30), Reason.ALIAS)])
    result = compose(request, [lexical, syntax], budget)
    assert sorted(_lines(result)) == [20, 22, 30]                       # precision: lexical 21 goes first
    assert result.omitted_lines == 1 and f"{GAP_TRUNCATED}: 1 lines omitted" in result.gaps

    budget = SliceBudget(max_lines=10, max_lines_per_function=2)
    result = compose(request, [syntax], budget)
    assert sorted(_lines(result)) == [20, 22]                           # distance: 30 is farther than 22
    result = compose(request, [FakeStrategy("syntax", Precision.SYNTAX, [(_key(18), Reason.ALIAS),
                                                                         (_key(22), Reason.ALIAS)])], budget)
    assert sorted(_lines(result)) == [18, 20]                           # tie: the higher line 22 goes

    anchors = _request((10, Reason.SOURCE), (20, Reason.PATH_STEP), (30, Reason.SINK))
    result = compose(anchors, [FakeStrategy("syntax", Precision.SYNTAX, [(_key(21), Reason.ALIAS)])], budget)
    assert sorted(_lines(result)) == [10, 20] and result.omitted_lines == 2
    assert result.gaps == (f"{GAP_TRUNCATED}: 2 lines omitted",
                           f"{GAP_TRUNCATED}: 1 path anchor lines omitted; the anchors alone exceed the line budget")
    _validate(result.record())


def test_total_trim_applies_after_the_per_function_cap() -> None:
    spans = (FunctionSpan("src/a.c", SHA, 1, 20, function=FN), FunctionSpan("src/a.c", SHA, 30, 50))
    request = _request((10, Reason.SOURCE), (40, Reason.SINK), spans=spans)
    strategy = FakeStrategy("syntax", Precision.SYNTAX, [(_key(line), Reason.ALIAS) for line in (8, 9, 11, 41, 45)])
    lexical = FakeStrategy("lexical", Precision.LEXICAL, [(_key(12), Reason.INTERACTER)])
    result = compose(request, [strategy, lexical], SliceBudget(max_lines=5, max_lines_per_function=3))
    assert sorted(_lines(result)) == [9, 10, 11, 40, 41]
    assert result.omitted_lines == 3 and result.gaps == (f"{GAP_TRUNCATED}: 3 lines omitted",)
    assert result.functions == spans
    _validate(result.record())


def test_a_function_with_only_lexical_expansion_is_named() -> None:
    spans = (FunctionSpan("src/a.c", SHA, 1, 10), FunctionSpan("src/a.c", SHA, 20, 30),
             FunctionSpan("src/a.c", SHA, 40, 50))
    request = _request((5, Reason.SOURCE), (25, Reason.PATH_STEP), (45, Reason.SINK), spans=spans)
    strategies = [FakeStrategy("syntax", Precision.SYNTAX, [(_key(26), Reason.ALIAS)]),
                  FakeStrategy("lexical", Precision.LEXICAL,
                               [(_key(6), Reason.INTERACTER), (_key(27), Reason.INTERACTER)])]
    result = compose(request, strategies, SliceBudget())
    assert result.gaps == (f"{GAP_LEXICAL_ONLY}: src/a.c:1-10",)
    _validate(result.record())


def test_anchors_to_slice_end_to_end_is_deterministic_and_schema_valid() -> None:
    second = _c_path(steps=[_step(0, "source", _loc(4), symbol=HELPER), _step(1, "sink", _loc(17), symbol=None)])
    paths = [(P1, _c_path(guards=[GUARD])), (P2, second)]
    request, gaps = build_request(paths, SOURCES, max_function_lines=160)
    strategies = [FakeStrategy("syntax", Precision.SYNTAX, [(_key(8), Reason.BACKWARD_DEF), (_key(2), Reason.ALIAS)]),
                  FakeStrategy("lexical", Precision.LEXICAL,
                               [(_key(13), Reason.INTERACTER), (_key(8), Reason.INTERACTER)])]
    result = compose(request, strategies, SliceBudget(), inherited_gaps=gaps, paths=[P2, P1])
    record = result.record()
    _validate(record)
    assert record["paths"] == [P1, P2]
    assert [(item["first"], item["last"], item["function"]) for item in record["functions"]] == [
        (3, 5, HELPER), (7, 14, FN), (16, 18, None)]
    assert [item["line"] for item in record["functions"][1]["lines"]] == [7, 8, 9, 13]
    assert f"{GAP_OUT_OF_SPAN}: syntax: 1 lines outside the function spans were dropped" in record["gaps"]
    reversed_strategies = [FakeStrategy(item.name, item.precision, list(reversed(item._lines))) for item in strategies]
    again = compose(build_request(list(reversed(paths)), SOURCES, max_function_lines=160)[0], reversed_strategies,
                    SliceBudget(), inherited_gaps=gaps, paths=[P1, P2])
    assert json.dumps(again.record(), sort_keys=True) == json.dumps(record, sort_keys=True)
