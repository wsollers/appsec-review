"""Compiler-precision slice strategies: ``llvm_ir_def_use`` and ``svf_points_to``.

Row shapes come from the real producers, not invented ones:

* LLVM IR rows are ``IrFunction.flow()`` payloads that ``jobs/job_cpp_compiled_analysis/llvm_ir.py``
  parses from the recorded clang ``-O0 -g`` module ``tests/fixtures/seeded_clang/recorded/ir/util.ll``
  (``DefUse`` = ``{value, def_line, use_lines, use_count}``; ``flow.truncated`` flags), wrapped as the
  ``{"function", "flow"}`` payload ``jobs/job_code_graph_index/producers.py::_flow_rows`` publishes.
  Hand-made rows copy that exact record shape.
* SVF rows are the accepted ``analysis`` shard that ``jobs/job_svf_alias_analysis/job.py`` publishes from
  the recorded SVF fixture (``tests/fixtures/svf``, as ``tests/graph/test_svf_crosscheck.py`` builds it),
  read through ``indexing.store.ShardSet`` and joined by line and ``REFERENCES`` exactly as
  ``review/memory_context.py`` does.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence

import pytest

from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_cpp_compiled_analysis import llvm_ir as ir
from appsec_review.jobs.job_svf_alias_analysis.job import _analyze_scope
from appsec_review.review.slicing import registry
from appsec_review.review.slicing.contract import (
    GAP_NOT_APPLICABLE, GAP_TRUNCATED, Anchor, FunctionSpan, LineKey, Precision, Reason, SliceRequest,
    SliceStrategy, StrategyState,
)
from appsec_review.review.slicing.strategies import llvm_ir, svf
from appsec_review.review.slicing.strategies.llvm_ir import LlvmIrDefUse
from appsec_review.review.slicing.strategies.svf import SvfPointsTo
from tests.fixtures.svf.builder import LINK_COMMANDS, ReplayExecutor, scope, unit
from tests.seeded_clang_support import RECORDED

SHA = "a" * 64
OTHER_SHA = "b" * 64
UTIL = "src/util.cpp"
GUARD, MAIN = "native/guard.c", "native/main.c"


class FakeSources:
    def __init__(self, flows: Mapping[str, Sequence[Any] | None] | None = None, records=None) -> None:
        self.flows = dict(flows or {})
        self.records = records or (lambda path, line: None)
        self.ir_calls: list[str] = []

    def source_lines(self, path: str, file_sha256: str):
        return None, "unused"

    def ir_flows(self, path: str):
        self.ir_calls.append(path)
        return self.flows.get(path)

    def svf_records(self, path: str, line: int):
        return self.records(path, line)

    def syntax_rows(self, path: str):
        return None


def _request(anchors: Sequence[tuple[str, int]], spans: Sequence[FunctionSpan], sources) -> SliceRequest:
    sha = {span.path: span.file_sha256 for span in spans}
    return SliceRequest(
        tuple(Anchor(LineKey(path, sha.get(path, SHA), line), Reason.SINK, f"asr:fact:{path}:{line}")
              for path, line in anchors),
        tuple(spans), sources)


def _lines(contribution) -> dict[tuple[str, int], set[Reason]]:
    return {(item.key.path, item.key.line): set(item.reasons) for item in contribution.lines}


def _du(def_line: int | None, *uses: int, value: str = "%v") -> dict[str, Any]:
    return {"value": value, "def_line": def_line, "use_lines": list(uses), "use_count": len(uses)}


def _fn(name: str, *records: dict[str, Any], truncated: Sequence[str] = ()) -> dict[str, Any]:
    return {"function": name, "flow": {"entry": "entry", "blocks": [], "dominators": {}, "post_dominators": {},
                                       "def_use": list(records), "indirect_calls": [], "truncated": list(truncated)}}


# --- llvm_ir_def_use -----------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def util_rows() -> list[dict[str, Any]]:
    module = ir.parse_module((RECORDED / "ir" / "util.ll").read_text(encoding="utf-8"))
    return [{"function": item.name, "flow": item.flow()} for item in module.functions if item.path == UTIL]


def test_real_clang_ir_selects_slot_interacters_of_the_memcpy_line(util_rows) -> None:
    # src/util.cpp copy_field 11-16; line 14 is ``memcpy(dst, src, n);``. At -O0 its operands live in
    # lineless allocas touched by 11 (parameters), 12 (``checked_len(n)``) and 13 (``src == nullptr``).
    span = FunctionSpan(UTIL, SHA, 11, 16, function="copy_field")
    result = LlvmIrDefUse().expand(_request([(UTIL, 14)], [span], FakeSources({UTIL: util_rows})))
    assert result.state is StrategyState.APPLIED and result.gaps == ()
    assert _lines(result) == {(UTIL, 11): {Reason.INTERACTER}, (UTIL, 12): {Reason.INTERACTER},
                              (UTIL, 13): {Reason.INTERACTER}}
    assert all(item.basis == "llvm_ir_def_use" and item.precision is Precision.COMPILER for item in result.lines)


def test_real_clang_ir_return_line_reaches_back_through_its_slot(util_rows) -> None:
    # line 15 ``return len;`` reads the ``len`` slot stored on 12; 12 then reads the ``n`` slot from 11.
    span = FunctionSpan(UTIL, SHA, 11, 16, function="copy_field")
    result = LlvmIrDefUse().expand(_request([(UTIL, 15)], [span], FakeSources({UTIL: util_rows})))
    assert result.state is StrategyState.APPLIED
    found = _lines(result)
    assert Reason.INTERACTER in found[(UTIL, 12)]
    assert found[(UTIL, 11)] == {Reason.BACKWARD_DEF}
    assert (UTIL, 15) not in found and all(11 <= line <= 16 for _, line in found)


def test_ssa_backward_chain_and_interacters() -> None:
    # 20 = f(%a) where %a defined on 18 from %b defined on 16; the anchor's own value is used on 22 and 24.
    rows = [_fn("f", _du(16, 18, value="%b"), _du(18, 20, value="%a"), _du(20, 22, 24, value="%r"),
                _du(12, 13, value="%unrelated"))]
    span = FunctionSpan("src/a.c", SHA, 10, 30)
    result = LlvmIrDefUse().expand(_request([("src/a.c", 20)], [span], FakeSources({"src/a.c": rows})))
    assert _lines(result) == {("src/a.c", 18): {Reason.BACKWARD_DEF}, ("src/a.c", 16): {Reason.BACKWARD_DEF},
                              ("src/a.c", 22): {Reason.INTERACTER}, ("src/a.c", 24): {Reason.INTERACTER}}
    assert result.state is StrategyState.APPLIED


def test_lines_stay_inside_the_anchor_span() -> None:
    rows = [_fn("f", _du(5, 20, value="%outside"), _du(18, 20, 40, value="%x"), _du(None, 20, 31, 12, value="%s"))]
    spans = [FunctionSpan("src/a.c", SHA, 10, 30), FunctionSpan("src/b.c", OTHER_SHA, 1, 50)]
    sources = FakeSources({"src/a.c": rows, "src/b.c": [_fn("g", _du(1, 2))]})
    result = LlvmIrDefUse().expand(_request([("src/a.c", 20)], spans, sources))
    assert _lines(result) == {("src/a.c", 18): {Reason.BACKWARD_DEF}, ("src/a.c", 12): {Reason.INTERACTER}}
    assert sources.ir_calls == ["src/a.c"]   # a span without anchors is never read
    assert all(item.key.file_sha256 == SHA for item in result.lines)


def test_closure_is_bounded_and_names_the_cut() -> None:
    chain = [_du(line - 1, line, value=f"%{line}") for line in range(30, 10, -1)]   # 29->30, 28->29, ...
    span = FunctionSpan("src/a.c", SHA, 1, 40)
    result = LlvmIrDefUse().expand(_request([("src/a.c", 30)], [span], FakeSources({"src/a.c": [_fn("f", *chain)]})))
    assert result.state is StrategyState.PARTIAL
    assert sorted(line for _, line in _lines(result)) == list(range(30 - llvm_ir.MAX_ROUNDS, 30))
    assert result.gaps == (f"{GAP_TRUNCATED}: llvm_ir_def_use: the backward closure in src/a.c:1-40 stopped "
                           f"after MAX_ROUNDS={llvm_ir.MAX_ROUNDS} rounds",)
    short = [_du(line - 1, line, value=f"%{line}") for line in range(30, 30 - llvm_ir.MAX_ROUNDS, -1)]
    exact = LlvmIrDefUse().expand(_request([("src/a.c", 30)], [span], FakeSources({"src/a.c": [_fn("f", *short)]})))
    assert exact.state is StrategyState.APPLIED and len(exact.lines) == llvm_ir.MAX_ROUNDS


def test_missing_ir_is_not_applicable_and_mixed_files_are_partial() -> None:
    spans = [FunctionSpan("src/a.c", SHA, 10, 30), FunctionSpan("src/b.c", OTHER_SHA, 1, 9)]
    none = LlvmIrDefUse().expand(_request([("src/a.c", 20), ("src/b.c", 3)], spans, FakeSources({})))
    assert none.state is StrategyState.NOT_APPLICABLE and none.lines == ()
    assert none.gaps[0].startswith(f"{GAP_NOT_APPLICABLE}: llvm_ir_def_use: no LLVM IR def-use rows for src/a.c, src/b.c")
    mixed = LlvmIrDefUse().expand(_request([("src/a.c", 20), ("src/b.c", 3)], spans,
                                           FakeSources({"src/b.c": [_fn("g", _du(2, 3))]})))
    assert mixed.state is StrategyState.PARTIAL
    assert _lines(mixed) == {("src/b.c", 2): {Reason.BACKWARD_DEF}}
    assert len(mixed.gaps) == 1 and "no LLVM IR def-use rows for src/a.c " in mixed.gaps[0]
    outside = LlvmIrDefUse().expand(_request([("src/z.c", 1)], spans, FakeSources({})))
    assert outside.state is StrategyState.NOT_APPLICABLE and "no anchor line lies inside" in outside.gaps[0]


def test_uncovered_span_truncated_flow_and_malformed_entries_are_named() -> None:
    spans = [FunctionSpan("src/a.c", SHA, 10, 30), FunctionSpan("src/a.c", SHA, 40, 50)]
    rows = [_fn("f", _du(18, 20), {"value": "%bad", "def_line": "x", "use_lines": [1]}, truncated=["def_use"]),
            "junk"]
    result = LlvmIrDefUse().expand(_request([("src/a.c", 20), ("src/a.c", 45)], spans, FakeSources({"src/a.c": rows})))
    assert result.state is StrategyState.PARTIAL and _lines(result) == {("src/a.c", 18): {Reason.BACKWARD_DEF}}
    gaps = "\n".join(result.gaps)
    assert "2 malformed LLVM IR def-use entries in src/a.c" in gaps
    assert "no LLVM IR def-use record falls inside src/a.c:40-50" in gaps
    assert "the LLVM IR flow of f is truncated (def_use)" in gaps
    uncovered = LlvmIrDefUse().expand(_request([("src/a.c", 45)], spans, FakeSources({"src/a.c": rows})))
    assert uncovered.state is StrategyState.NOT_APPLICABLE and uncovered.lines == ()


def test_store_row_payload_and_bare_records_are_accepted() -> None:
    span = FunctionSpan("src/a.c", SHA, 10, 30)
    store_row = {"identity": "asr:ir_entity:1", "kind": "ir_entity", "name": "f",
                 "payload": {"function": "f", "fact": "flow", "flow": {"def_use": [_du(18, 20)], "truncated": []}}}
    for rows in ([store_row], [_du(18, 20)]):
        result = LlvmIrDefUse().expand(_request([("src/a.c", 20)], [span], FakeSources({"src/a.c": rows})))
        assert result.state is StrategyState.APPLIED and _lines(result) == {("src/a.c", 18): {Reason.BACKWARD_DEF}}


def test_llvm_ir_is_deterministic(util_rows) -> None:
    span = FunctionSpan(UTIL, SHA, 11, 16)
    first = LlvmIrDefUse().expand(_request([(UTIL, 14), (UTIL, 15)], [span], FakeSources({UTIL: util_rows})))
    second = LlvmIrDefUse().expand(_request([(UTIL, 15), (UTIL, 14)], [span],
                                            FakeSources({UTIL: list(reversed(util_rows))})))
    assert first == second
    assert [item.key for item in first.lines] == sorted(item.key for item in first.lines)


# --- svf_points_to -------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def svf_store(tmp_path_factory) -> dict[tuple[str, int], list[dict[str, Any]]]:
    """Real SVF shard rows, joined by line and REFERENCES like ``review/memory_context.py``."""
    run_root = tmp_path_factory.mktemp("svf") / "run"
    executor = ReplayExecutor(run_root)
    result = _analyze_scope(unit(run_root), scope(run_root), LINK_COMMANDS, lambda _unit: executor)
    shard = dict(result["index_identity"])
    store = ShardSet(run_root, [shard])
    objects: dict[str, dict[str, Any]] = {}
    by_line: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in store.entities((shard,), kinds=("points_to_set", "indirect_call_targets", "memory_object")):
        location = row.get("location") or {}
        if row["kind"] == "memory_object":
            objects[row["identity"]] = row
            if location.get("path") and location.get("start_line"):
                by_line[(location["path"], location["start_line"])].append(row)
        elif location.get("path") and location.get("start_line") and not location.get("ambiguous"):
            by_line[(location["path"], location["start_line"])].append(row)
    references: dict[str, set[str]] = defaultdict(set)
    for relation in store.relations((shard,), kinds=("REFERENCES",)):
        references[relation["source_id"]].add(relation["target_id"])
    joined: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for key, rows in by_line.items():
        linked = [objects[target] for row in rows for target in sorted(references.get(row["identity"], ()))
                  if target in objects]
        joined[key] = list({row["identity"]: row for row in [*rows, *linked]}.values())
    return joined


def _svf_sources(store, paths=(GUARD, MAIN)) -> FakeSources:
    return FakeSources(records=lambda path, line: store.get((path, line), []) if path in paths else None)


def test_real_svf_heap_store_reaches_allocation_and_free(svf_store) -> None:
    # guard.c 17 ``*second = 1`` points to the malloc on 15, freed on 20 (guarded_unrelated, 13-21).
    span = FunctionSpan(GUARD, SHA, 13, 21, function="guarded_unrelated")
    result = SvfPointsTo().expand(_request([(GUARD, 17)], [span], _svf_sources(svf_store)))
    assert result.state is StrategyState.APPLIED and result.gaps == ()
    assert _lines(result) == {(GUARD, 15): {Reason.ALIAS}, (GUARD, 20): {Reason.ALIAS}}
    assert all(item.basis == "svf_points_to" and item.precision is Precision.COMPILER for item in result.lines)


def test_real_svf_stack_object_is_confined_to_the_span(svf_store) -> None:
    # guard.c 9 writes through a pointer to ``left`` declared at main.c:8 and compared on guard.c:8.
    span = FunctionSpan(GUARD, SHA, 6, 11, function="guarded_alias")
    result = SvfPointsTo().expand(_request([(GUARD, 9)], [span], _svf_sources(svf_store)))
    found = _lines(result)
    assert found[(GUARD, 8)] == {Reason.ALIAS}
    assert all(path == GUARD and 6 <= line <= 11 and line != 9 for path, line in found)
    with_main = SvfPointsTo().expand(_request([(GUARD, 9)], [span, FunctionSpan(MAIN, OTHER_SHA, 1, 20)],
                                              _svf_sources(svf_store)))
    assert (MAIN, 8) in _lines(with_main)
    assert next(item for item in with_main.lines if item.key.path == MAIN).key.file_sha256 == OTHER_SHA


def test_real_svf_incomplete_record_makes_the_slice_partial(svf_store) -> None:
    # guard.c 16 compares two pointers; one operand's points-to set is empty (incomplete).
    span = FunctionSpan(GUARD, SHA, 13, 21)
    result = SvfPointsTo().expand(_request([(GUARD, 16)], [span], _svf_sources(svf_store)))
    assert result.state is StrategyState.PARTIAL
    assert {(GUARD, 14), (GUARD, 19)} <= set(_lines(result))
    assert any(gap.startswith("slice_strategy_partial: svf_points_to:") and "empty_points_to_set" in gap
               for gap in result.gaps)


def test_svf_unavailable_is_not_applicable_and_mixed_files_are_partial(svf_store) -> None:
    spans = [FunctionSpan(GUARD, SHA, 13, 21), FunctionSpan("src/x.c", OTHER_SHA, 1, 9)]
    none = SvfPointsTo().expand(_request([(GUARD, 17)], spans, FakeSources()))
    assert none.state is StrategyState.NOT_APPLICABLE and none.lines == ()
    assert none.gaps[0].startswith(f"{GAP_NOT_APPLICABLE}: svf_points_to: no SVF records for native/guard.c")
    mixed = SvfPointsTo().expand(_request([(GUARD, 17), ("src/x.c", 3)], spans, _svf_sources(svf_store)))
    assert mixed.state is StrategyState.PARTIAL
    assert set(_lines(mixed)) == {(GUARD, 15), (GUARD, 20)}
    assert mixed.gaps == (f"{GAP_NOT_APPLICABLE}: svf_points_to: no SVF records for src/x.c "
                          "(job_svf_alias_analysis is opt-in or did not cover the file)",)
    empty = SvfPointsTo().expand(_request([(GUARD, 2)], [FunctionSpan(GUARD, SHA, 1, 21)], _svf_sources(svf_store)))
    assert empty.state is StrategyState.APPLIED and empty.lines == () and empty.gaps == ()


def _site(identity: str, points_to: Sequence[str], **payload: Any) -> dict[str, Any]:
    base = {"role": "load", "points_to": list(points_to), "objects": {key: {"kind": "heap"} for key in points_to},
            "complete": True, "incomplete_reasons": [], "open_world_reasons": [], "truncated": False}
    return {"identity": identity, "kind": "points_to_set", "location": {"path": "src/p.c", "start_line": 5},
            "payload": {**base, **payload}}


def test_svf_open_world_unresolved_objects_and_record_cap_are_gaps() -> None:
    obj = {"identity": "asr:memory_object:1", "kind": "memory_object",
           "location": {"path": "src/p.c", "start_line": 3, "ambiguous": True},
           "payload": {"object_key": "obj:heap:a", "accessors": [{"path": "src/p.c", "line": 7, "class": "write"},
                                                                 {"path": "src/p.c", "line": 99, "class": "free"},
                                                                 {"path": "src/q.c", "line": 4, "class": "read"}],
                       "complete": False, "truncated": True, "open_world_reasons": ["dlopen"]}}
    rows = [_site("asr:pts:1", ["obj:heap:a", "obj:heap:missing"], open_world_reasons=["dlopen"]), obj,
            {"identity": "asr:ict:1", "kind": "indirect_call_targets", "location": {"path": "src/p.c", "start_line": 5},
             "payload": {"targets": [{"name": "f"}], "complete": True, "open_world_reasons": []}}]
    span = FunctionSpan("src/p.c", SHA, 1, 10)
    result = SvfPointsTo().expand(_request([("src/p.c", 5)], [span], FakeSources(records=lambda path, line: rows)))
    assert _lines(result) == {("src/p.c", 3): {Reason.ALIAS}, ("src/p.c", 7): {Reason.ALIAS}}
    assert result.state is StrategyState.PARTIAL
    gaps = "\n".join(result.gaps)
    assert "open-world modules (dlopen)" in gaps
    assert "1 SVF record(s) at the anchor lines are incomplete (truncated)" in gaps
    assert "1 pointed-to object(s) have no memory_object record" in gaps
    many = [_site(f"asr:pts:{index:04d}", []) for index in range(svf.MAX_RECORDS_PER_LINE + 1)]
    capped = SvfPointsTo().expand(_request([("src/p.c", 5)], [span], FakeSources(records=lambda path, line: many)))
    assert capped.state is StrategyState.PARTIAL
    assert capped.gaps[0].startswith(f"{GAP_TRUNCATED}: svf_points_to: 1 anchor line(s) held more than")


def test_svf_is_deterministic(svf_store) -> None:
    span = FunctionSpan(GUARD, SHA, 13, 21)
    forward = SvfPointsTo().expand(_request([(GUARD, 16), (GUARD, 17)], [span], _svf_sources(svf_store)))
    reverse_store = {key: list(reversed(rows)) for key, rows in svf_store.items()}
    backward = SvfPointsTo().expand(_request([(GUARD, 17), (GUARD, 16)], [span], _svf_sources(reverse_store)))
    assert forward == backward
    assert [item.key for item in forward.lines] == sorted(item.key for item in forward.lines)


# --- registry ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "kind"), [("llvm_ir_def_use", LlvmIrDefUse), ("svf_points_to", SvfPointsTo)])
def test_registry_loads_compiler_strategies(name: str, kind: type) -> None:
    strategy = registry.load(name)
    assert isinstance(strategy, kind) and isinstance(strategy, SliceStrategy)
    assert strategy.name == name and strategy.precision is Precision.COMPILER
