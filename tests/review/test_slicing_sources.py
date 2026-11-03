"""``AcceptedSliceSources``: the read-only facade over accepted shards that the slice strategies use.

The shards are real sqlite indices built with ``IndexBuilder`` and held by a real ``AcceptedScope``; only the
source-text reader is injected. ``test_slicing_end_to_end.py`` covers the same facade over real producer output;
this file covers its bounds, joins, selection and failure answers.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from appsec_review.graph.contract import GRAPH_INDEX
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint,
)
from appsec_review.review.memory_context import SVF_JOB
from appsec_review.review.scope import AcceptedScope, SourceFile
from appsec_review.review.slicing import sources as facade
from appsec_review.review.slicing.contract import GAP_TRUNCATED
from appsec_review.review.slicing.sources import AcceptedSliceSources, UnavailableSliceSources

SNAPSHOT = "e" * 64
SHA = "a" * 64
C, PY = "native/a.c", "app/b.py"


def _location(path: str, line: int, *, ambiguous: bool = False) -> SourceLocation:
    return SourceLocation(SNAPSHOT, path, SHA, 0, 1, line, line, 1, 2, {}, "fixture", 0.5 if ambiguous else 1.0,
                          ambiguous)


def _entity(kind: EntityKind, key: str, payload: dict[str, Any], location: SourceLocation | None) -> EntityRecord:
    return EntityRecord(LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key}), key, key, key, payload, location)


def _id(kind: EntityKind, key: str) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key}).value


def _shard(run_root: Path, name: str, shard_id: str, producer: dict[str, Any], entities: Sequence[EntityRecord],
           relations: Sequence[RelationRecord] = ()) -> dict[str, Any]:
    fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                    tool_identity=producer, parser_identity="fixture/1",
                                    normalizer_identity="fixture/1", mapping_identity="fixture/1")
    path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for entity in entities:
        builder.add_entity(entity)
    for relation in relations:
        builder.add_relation(relation)
    return asdict(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                path.relative_to(run_root).as_posix(), producer, (), shard_id))


def _scope(run_root: Path, shards: Sequence[dict[str, Any]], paths: Sequence[str] = (C, PY)) -> AcceptedScope:
    files = tuple(SourceFile(path, _id(EntityKind.SOURCE_FILE, path), None) for path in paths)
    return AcceptedScope("fixture", run_root, run_root / "manifest.json", "0" * 64, SNAPSHOT, tuple(shards),
                         (), (), files, (), {}, ())


def _flow(key: str, path: str, *, fact: str = "flow") -> EntityRecord:
    return _entity(EntityKind.IR_ENTITY, key, {"fact": fact, "flow": {"def_use": []}}, _location(path, 3))


def _producers(run_root: Path, entities: Sequence[EntityRecord], *, kind: str = facade.PRODUCERS_KIND):
    return _shard(run_root, GRAPH_INDEX, f"producers-{kind}", {"kind": kind}, entities)


# --- selection and absence ----------------------------------------------------------------------------------


def test_no_accepted_producer_shard_answers_none_for_every_question(tmp_path) -> None:
    other = _shard(tmp_path, "analysis", "other", {"job": "job_other"}, [_flow("x", C)])
    sources = AcceptedSliceSources(_scope(tmp_path, [other]), read_source=lambda _i: (None, "unused"))
    assert sources.ir_flows(C) is None
    assert sources.svf_records(C, 3) is None
    assert sources.syntax_rows(C) is None
    assert sources.gaps() == ()


def test_shards_are_selected_by_index_name_and_producer_identity(tmp_path) -> None:
    wrong_kind = _producers(tmp_path, [_flow("a", C)], kind="codeql_database")
    wrong_name = _shard(tmp_path, "analysis", "p", {"kind": facade.PRODUCERS_KIND}, [_flow("b", C)])
    svf_wrong_id = _shard(tmp_path, "analysis", "not-svf", {"job": SVF_JOB},
                          [_entity(EntityKind.POINTS_TO_SET, "s", {}, _location(C, 3))])
    sources = AcceptedSliceSources(_scope(tmp_path, [wrong_kind, wrong_name, svf_wrong_id]))
    assert sources.ir_flows(C) is None and sources.svf_records(C, 3) is None


def test_max_syntax_rows_must_be_positive(tmp_path) -> None:
    with pytest.raises(ValueError, match="positive"):
        AcceptedSliceSources(_scope(tmp_path, []), max_syntax_rows=0)


def test_unavailable_sources_answer_none_with_the_reason() -> None:
    sources = UnavailableSliceSources("no accepted scope")
    assert sources.source_lines(C, SHA) == (None, "no accepted scope")
    assert (sources.ir_flows(C), sources.svf_records(C, 1), sources.syntax_rows(C), sources.gaps()) == (
        None, None, None, ())


# --- LLVM IR flow rows --------------------------------------------------------------------------------------


def test_ir_flows_keep_only_flow_facts_located_in_the_path_sorted_and_unique(tmp_path) -> None:
    rows = [_flow("f2", C), _flow("f1", "build/out/" + C), _flow("diag", C, fact="diagnostics"),
            _flow("other", "native/ab.c"), _flow("py", PY)]
    first = _producers(tmp_path, rows)
    second = _shard(tmp_path, GRAPH_INDEX, "producers-2", {"kind": facade.PRODUCERS_KIND}, [_flow("f2", C)])
    sources = AcceptedSliceSources(_scope(tmp_path, [first, second]))
    flows = sources.ir_flows(C)
    assert [row["identity"] for row in flows] == sorted([_id(EntityKind.IR_ENTITY, "f1"),
                                                         _id(EntityKind.IR_ENTITY, "f2")])
    assert sources.ir_flows(C) is flows
    assert sources.ir_flows("native/none.c") == []
    assert sources.gaps() == ()


def test_ir_flows_over_the_cap_are_truncated_with_a_named_gap(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(facade, "MAX_IR_FLOWS", 2)
    sources = AcceptedSliceSources(_scope(tmp_path, [_producers(tmp_path, [_flow(f"f{n}", C) for n in range(3)])]))
    assert len(sources.ir_flows(C)) == 2
    assert sources.gaps([C]) == (f"{GAP_TRUNCATED}: llvm_ir flow rows for {C} exceed 2; 1 omitted",)
    assert sources.gaps([PY]) == () and sources.gaps() == sources.gaps([C, PY])


# --- SVF records ---------------------------------------------------------------------------------------------


@pytest.fixture
def svf_sources(tmp_path) -> AcceptedSliceSources:
    """A store on line 5 references a heap object allocated on 2; an ambiguous record sits on line 7."""
    heap = _entity(EntityKind.MEMORY_OBJECT, "heap", {"kind": "heap"}, _location(C, 2))
    global_object = _entity(EntityKind.MEMORY_OBJECT, "global", {"kind": "global"}, None)
    store = _entity(EntityKind.POINTS_TO_SET, "store", {}, _location(C, 5))
    call = _entity(EntityKind.INDIRECT_CALL_TARGETS, "call", {}, _location(C, 5))
    vague = _entity(EntityKind.POINTS_TO_SET, "vague", {}, _location(C, 7, ambiguous=True))
    relations = [RelationRecord(RelationKind.REFERENCES, store.identity.value, heap.identity.value, True, 1.0),
                 RelationRecord(RelationKind.REFERENCES, store.identity.value, global_object.identity.value, True, 1.0),
                 RelationRecord(RelationKind.REFERENCES, call.identity.value, _id(EntityKind.MEMORY_OBJECT, "gone"),
                                True, 1.0)]
    shard = _shard(tmp_path, "analysis", "svf-native", {"job": SVF_JOB},
                   [heap, global_object, store, call, vague], relations)
    return AcceptedSliceSources(_scope(tmp_path, [shard]))


def test_svf_records_join_references_and_allocations_on_the_line(svf_sources) -> None:
    found = svf_sources.svf_records(C, 5)
    assert [row["identity"] for row in found] == sorted(_id(kind, key) for kind, key in (
        (EntityKind.POINTS_TO_SET, "store"), (EntityKind.INDIRECT_CALL_TARGETS, "call"),
        (EntityKind.MEMORY_OBJECT, "heap"), (EntityKind.MEMORY_OBJECT, "global")))
    assert [row["identity"] for row in svf_sources.svf_records(C, 2)] == [_id(EntityKind.MEMORY_OBJECT, "heap")]
    assert svf_sources.svf_records(C, 9) == []


def test_svf_records_drop_ambiguous_records_and_answer_none_off_the_analyzed_c_files(svf_sources) -> None:
    assert svf_sources.svf_records(C, 7) == []
    assert svf_sources.svf_records(PY, 5) is None
    assert svf_sources.svf_records("native/other.c", 5) is None
    assert svf_sources.gaps() == ()


# --- tree-sitter rows ----------------------------------------------------------------------------------------


def _ast_shard(run_root: Path, count: int, path: str = C) -> dict[str, Any]:
    nodes = [_entity(EntityKind.AST_NODE, f"{path}:{n}", {"grammar_native_type": "identifier", "n": n},
                     _location(path, n + 1)) for n in range(count)]
    return _shard(run_root, "analysis", f"ts-{path.replace('/', '-')}", {"job": facade.TREE_SITTER_JOB}, nodes)


def test_syntax_rows_return_every_node_of_the_path_with_payload_and_location(tmp_path) -> None:
    sources = AcceptedSliceSources(_scope(tmp_path, [_ast_shard(tmp_path, 3), _ast_shard(tmp_path, 2, PY)]))
    rows = sources.syntax_rows(C)
    assert [row["payload"]["n"] for row in sorted(rows, key=lambda row: row["location"]["start_line"])] == [0, 1, 2]
    assert all(row["kind"] == "ast_node" and row["location"]["path"] == C and row["native_id"] for row in rows)
    assert [row["identity"] for row in rows] == sorted(row["identity"] for row in rows)
    assert sources.syntax_rows(C) is rows and len(sources.syntax_rows(PY)) == 2
    assert sources.syntax_rows("native/none.c") == []


def test_syntax_rows_over_the_bound_are_withheld_with_a_named_gap(tmp_path) -> None:
    sources = AcceptedSliceSources(_scope(tmp_path, [_ast_shard(tmp_path, 4)]), max_syntax_rows=3)
    assert sources.syntax_rows(C) is None
    assert sources.gaps([C]) == (f"{GAP_TRUNCATED}: tree_sitter rows for {C} exceed 3; the syntax strategy does "
                                 "not read the file",)
    assert len(AcceptedSliceSources(_scope(tmp_path, [_ast_shard(tmp_path, 4)]), max_syntax_rows=4)
               .syntax_rows(C)) == 4


# --- source text ---------------------------------------------------------------------------------------------


class Reader:
    def __init__(self, answer) -> None:
        self.answer, self.calls = answer, []

    def __call__(self, identity: str):
        self.calls.append(identity)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_source_lines_are_read_once_through_the_accepted_source_identity(tmp_path) -> None:
    reader = Reader(({"location": {"file_sha256": SHA}, "lines": ["int x;", 7]}, None))
    sources = AcceptedSliceSources(_scope(tmp_path, []), read_source=reader)
    assert sources.source_lines(C, SHA) == (("int x;", "7"), None)
    assert sources.source_lines(C, SHA) == (("int x;", "7"), None)
    assert reader.calls == [_id(EntityKind.SOURCE_FILE, C)]


@pytest.mark.parametrize(("answer", "path", "reason"), [
    (({"location": {"file_sha256": "b" * 64}, "lines": ["x"]}, None), C,
     "the verified file hash differs from the path fact's file hash"),
    ((None, "custody check failed"), C, "custody check failed"),
    ((None, None), C, "source is unavailable"),
    (OSError("gone"), C, "source read failed: OSError"),
    (({"location": {"file_sha256": SHA}, "lines": []}, None), "native/unknown.c",
     "no accepted source_file entity for the path"),
])
def test_unreadable_or_mismatched_source_is_a_reason_never_text(tmp_path, answer, path, reason) -> None:
    sources = AcceptedSliceSources(_scope(tmp_path, []), read_source=Reader(answer))
    assert sources.source_lines(path, SHA) == (None, reason)
