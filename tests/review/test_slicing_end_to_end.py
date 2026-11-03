"""Every default slice strategy, end to end, over real recorded tool output and real accepted shards.

``native/guard.c`` and ``native/main.c`` (``containers/fixtures/svf/source``) pass through each producer's own
normaliser into real sqlite shards, which a real ``AcceptedScope`` holds:

* SVF: the recorded ``tool-svf`` output replayed through ``job_svf_alias_analysis._analyze_scope``.
* LLVM IR: the recorded clang-18 ``-g -O0`` IR (``tests/fixtures/slicing_end_to_end/ir``) parsed by
  ``llvm_ir.parse_module`` into the ``job_cpp_compiled_analysis`` ``ir_entity`` row shape, then lifted by the
  graph job's ``producers.build`` into a ``producer_neighborhood`` shard.
* Tree-sitter: the locked parser's recorded node records (``ast.json.gz``) through
  ``job_tree_sitter_ast.normalize_scope`` with syntax projection.

``AcceptedSliceSources`` reads those shards; ``build_request`` and ``compose`` slice one path fact. Only the
source-text reader is injected (the bytes are the fixture's own, hash-checked by the facade).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.graph.contract import GRAPH_INDEX, Producer
from appsec_review.jobs.job_code_graph_index import producers
from appsec_review.jobs.job_cpp_compiled_analysis import llvm_ir
from appsec_review.jobs.job_svf_alias_analysis.job import _analyze_scope
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, index_fingerprint,
)
from appsec_review.review.scope import AcceptedScope, SourceFile
from appsec_review.review.slicing import registry
from appsec_review.review.slicing.anchors import build_request
from appsec_review.review.slicing.compose import compose
from appsec_review.review.slicing.contract import Precision, Reason, SliceBudget, StrategyState
from appsec_review.review.slicing.sources import AcceptedSliceSources
from tests.fixtures.svf.builder import LINK_COMMANDS, SOURCE, ReplayExecutor, scope as svf_scope, unit

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "slicing_end_to_end"
SNAPSHOT = "e" * 64
GUARD, MAIN = "native/guard.c", "native/main.c"
DATA = {GUARD: (SOURCE / "guard.c").read_bytes(), MAIN: (SOURCE / "main.c").read_bytes()}
SHA = {path: hashlib.sha256(data).hexdigest() for path, data in DATA.items()}
PATH_REF = "asr:dataflow_path:" + "7" * 64
SYMBOL = "asr:symbol:" + "5" * 64


def _publish(run_root: Path, name: str, shard_id: str, producer: Mapping[str, Any],
             entities: list[EntityRecord]) -> dict[str, Any]:
    fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                    tool_identity=dict(producer), parser_identity="fixture/1",
                                    normalizer_identity="fixture/1", mapping_identity="fixture/1")
    path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for entity in entities:
        builder.add_entity(entity)
    return asdict(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                path.relative_to(run_root).as_posix(), dict(producer), (), shard_id))


def _ir_shards(run_root: Path) -> list[dict[str, Any]]:
    """The compiled-analysis ``ir_entity`` shard (seeded.py's row shape) and the graph producer shard over it."""
    entities = []
    for path in (GUARD, MAIN):
        module = llvm_ir.parse_module((FIXTURE / "ir" / f"{Path(path).stem}.ll").read_text(encoding="utf-8"))
        for fn in module.functions:
            assert fn.path == path, "the recorded IR debug info must name the accepted path"
            identity = LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {
                "compile_unit_id": path, "function": fn.linkage_name, "definition_line": fn.start_line})
            location = SourceLocation(SNAPSHOT, path, SHA[path], 0, len(DATA[path]), fn.start_line, fn.start_line,
                                      1, 1, {"path": path, "line": fn.start_line, "column": 1}, "ir-debug-info",
                                      1.0, False)
            entities.append(EntityRecord(identity, f"0:{fn.linkage_name}", fn.name, f"define {fn.linkage_name}",
                {"kind": "function", "linkage_name": fn.linkage_name, "internal": fn.internal, "distance": 0,
                 "flow": fn.flow(), "seeded": True, "project_id": "native", "compile_unit_id": path,
                 "shard_id": "ir-native"}, location))
    ir_shard = _publish(run_root, "analysis", "ir-native", {"job": "job_cpp_compiled_analysis"}, entities)
    graph_scope = {"scope_id": "cpp-native", "language": "cpp", "build_unit_id": "native",
                   "inputs": {"secondary": {Producer.LLVM_IR.value: [ir_shard]}, "analyzers": {}}}
    rows = producers.build(run_root, scope=graph_scope, snapshot=SNAPSHOT, relations=())
    assert rows.counts["flow"] == len(entities) > 0
    graph_shard = _publish(run_root, GRAPH_INDEX, "producers-cpp-native", {"kind": producers.PRODUCERS_KIND},
                           rows.entities)
    return [ir_shard, graph_shard]


def _syntax_shard(run_root: Path) -> dict[str, Any]:
    recorded = json.loads(gzip.decompress((FIXTURE / "ast.json.gz").read_bytes()))
    files = tuple({"path": path, "sha256": SHA[path], "size_bytes": len(DATA[path]), "language": "C"}
                  for path in (GUARD, MAIN))
    scope = Scope("ts-native-c", "component:native", "native", "source:native", "native", "C", files)
    records = []
    for path in (GUARD, MAIN):
        record = recorded["files"][path]
        assert record["sha256"] == SHA[path], "ast.json.gz is stale; re-run record.py"
        records.append({"kind": "file", "path": path, "status": "SUCCEEDED", "sha256": SHA[path],
                        "bytes": len(DATA[path]), "root_has_error": record["root_has_error"],
                        "nodes": record["nodes"]})
    output = {"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": scope.scope_id,
              "language": "C", "records": records}
    grammar = GrammarLock("C", "c", "https://example.invalid/tree-sitter-c", "a" * 40, "MIT",
                          "libtree_sitter_c.so", "b" * 64)
    _artifact, identity, counts = normalize_scope(
        run_root=run_root, target_snapshot=SNAPSHOT, scope=scope, grammar=grammar, fingerprint="f" * 64,
        container_output=output, producer={"job": "job_tree_sitter_ast"},
        artifact_path=run_root / "data" / "treesitter" / "ast.jsonl",
        index_path=run_root / "data" / "indices" / "analysis" / scope.scope_id / "ast.sqlite",
        source_bytes=DATA)
    assert counts["files_parsed"] == 2 and counts["diagnostic_count"] == 0
    return asdict(identity)


@pytest.fixture(scope="module")
def accepted(tmp_path_factory) -> AcceptedScope:
    run_root = tmp_path_factory.mktemp("slice-e2e") / "run"
    svf = dict(_analyze_scope(unit(run_root), svf_scope(run_root), LINK_COMMANDS,
                              lambda _unit: ReplayExecutor(run_root))["index_identity"])
    shards = (svf, *_ir_shards(run_root), _syntax_shard(run_root))
    sources = tuple(SourceFile(path, LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {
        "path": path, "sha256": SHA[path]}).value, "C") for path in (GUARD, MAIN))
    return AcceptedScope("fixture-run", run_root, run_root / "manifest.json", "0" * 64, SNAPSHOT, shards,
                         (), (), sources, (), {}, ())


def _reader(accepted: AcceptedScope):
    by_identity = {item.identity: item.path for item in accepted.source_files}

    def read(identity: str):
        path = by_identity[identity]
        return {"location": {"path": path, "file_sha256": SHA[path]},
                "lines": DATA[path].decode().split("\n")}, None
    return read


def _location(line: int, path: str = GUARD) -> dict[str, Any]:
    return {"target_snapshot": SNAPSHOT, "path": path, "file_sha256": SHA[path], "start_byte": 0, "end_byte": 1,
            "start_line": line, "end_line": line, "start_column": 1, "end_column": 2, "producer_location": {},
            "mapping_method": "test", "confidence": 1.0, "ambiguous": False}


def _fact(source: int, sink: int, sink_display: str) -> dict[str, Any]:
    step = lambda n, role, line, display: {"n": n, "location": _location(line), "role": role,  # noqa: E731
                                           "symbol": SYMBOL, "display": display}
    return {"source": {"entry_point": None, "source_class": "parameter"}, "sink": {"sink_site": "store"},
            "steps": [step(0, "source", source, "input"), step(1, "sink", sink, sink_display)],
            "hop_count": 1, "call_depth": 0, "guards": [], "sanitizers": [], "truncated_steps": False}


def _slice(accepted: AcceptedScope, fact: Mapping[str, Any]):
    sources = AcceptedSliceSources(accepted, read_source=_reader(accepted))
    request, gaps = build_request([(PATH_REF, fact)], sources, max_function_lines=160)
    result = compose(request, registry.load_all(registry.DEFAULT_STRATEGIES), SliceBudget(),
                     inherited_gaps=[*gaps, *sources.gaps()], paths=[PATH_REF])
    return request, result


def _by_line(result) -> dict[int, Any]:
    assert all(item.key.path == GUARD and item.key.file_sha256 == SHA[GUARD] for item in result.lines)
    return {item.key.line: item for item in result.lines}


def test_the_facade_reads_every_producer_shard(accepted) -> None:
    sources = AcceptedSliceSources(accepted, read_source=_reader(accepted))
    flows = sources.ir_flows(GUARD)
    assert sorted(row["name"] for row in flows) == ["guarded_alias", "guarded_unrelated"]
    assert all(row["payload"]["fact"] == "flow" and row["location"]["path"] == GUARD for row in flows)
    assert [row["name"] for row in sources.ir_flows(MAIN)] == ["main"]
    heap = {row["kind"] for row in sources.svf_records(GUARD, 17)}
    assert {"points_to_set", "memory_object"} <= heap
    assert sources.svf_records(GUARD, 3) == [] and sources.svf_records("native/notes.txt", 1) is None
    syntax = sources.syntax_rows(GUARD)
    assert syntax and all(row["kind"] == "ast_node" and row["location"]["path"] == GUARD for row in syntax)
    assert any((row["payload"].get("syntax") or {}).get("written_name") == "guarded_unrelated" for row in syntax)
    lines, reason = sources.source_lines(GUARD, SHA[GUARD])
    assert reason is None and lines[12] == "void guarded_unrelated(int input) {"
    assert sources.gaps() == ()


def test_every_default_strategy_contributes_to_one_real_slice(accepted) -> None:
    request, result = _slice(accepted, _fact(13, 17, "*written = input"))
    span = request.functions[0]
    assert len(request.functions) == 1
    assert (span.path, span.first, span.last, span.function, span.basis) == (
        GUARD, 13, 21, SYMBOL, "tree_sitter")
    outcomes = {item.name: item for item in result.strategies}
    assert tuple(outcomes) == registry.DEFAULT_STRATEGIES
    for name in ("llvm_ir_def_use", "svf_points_to", "tree_sitter_references", "lexical_identifiers"):
        assert outcomes[name].state is StrategyState.APPLIED, (name, outcomes[name].gaps)
        assert outcomes[name].lines > 0, name
    assert outcomes["llvm_ir_def_use"].precision is Precision.COMPILER
    assert outcomes["tree_sitter_references"].precision is Precision.SYNTAX
    found = _by_line(result)
    # The ``written`` flow only: the unrelated ``checked`` pointer (14, 16, 19) stays out of the slice.
    assert set(found) == {13, 15, 17, 20}
    assert found[13].basis == found[17].basis == "dataflow_path"
    # SVF: *written (17) points to the malloc on 15, freed on 20; only SVF gives the alias reason.
    assert Reason.ALIAS in found[15].reasons and Reason.ALIAS in found[20].reasons
    assert {found[15].precision, found[20].precision} == {Precision.COMPILER}
    assert {"llvm_ir_def_use", "svf_points_to"} & {item.basis for item in found.values()}
    assert not any(gap.startswith(("slice_function_fallback", "slice_strategy_failed")) for gap in result.gaps)


def test_the_real_slice_is_deterministic(accepted) -> None:
    first = _slice(accepted, _fact(13, 17, "*written = input"))[1]
    second = _slice(accepted, _fact(13, 17, "*written = input"))[1]
    assert first == second
