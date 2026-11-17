from __future__ import annotations

from dataclasses import asdict
import hashlib
from pathlib import Path
from typing import Any

from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_code_graph_index import producers
from appsec_review.jobs.job_code_graph_index.producers import (
    MAX_ROW_GAPS,
    ProducerRows,
    _cpg_rows,
    _diagnostic_rows,
    _flow_rows,
    _location,
    _names,
    _symbol_rows,
    _tail,
    build,
    symbol_links,
)
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    SourceLocation,
)
from appsec_review.retrieval.index import INDEX_SCHEMA

SNAP = "snap-unit-1"
SCOPE = {"scope_id": "cpp-s1", "language": "cpp", "build_unit_id": "bu-1"}


def _loc(path: str = "src/a.cpp", line: int = 10) -> SourceLocation:
    return SourceLocation(
        SNAP, path, "a" * 64, 0, 20, line, line + 2, 1, 10, {}, "exact", 1.0, False
    )


def _write_index_shard(
    run_root: Path,
    *,
    name: str,
    shard_id: str,
    producer_meta: dict[str, Any],
    entities: list[EntityRecord],
    relations: list[RelationRecord] | None = None,
) -> dict[str, Any]:
    fp = hashlib.sha256(shard_id.encode("utf-8")).hexdigest()
    path = run_root / "data" / "indices" / name / f"{shard_id}.sqlite"
    builder = IndexBuilder(
        path, name=name, fingerprint=fp, target_snapshot=SNAP, shard_id=shard_id
    )
    for ent in entities:
        builder.add_entity(ent)
    for rel in relations or ():
        builder.add_relation(rel)
    builder.add_coverage(f"{name}:{shard_id}", "complete", None)
    sha = builder.build()
    ident = IndexIdentity(
        name,
        INDEX_SCHEMA,
        sha,
        fp,
        path.relative_to(run_root).as_posix(),
        producer_meta,
        (),
        shard_id,
    )
    return asdict(ident)


def test_helpers_and_producer_rows_status() -> None:
    empty = ProducerRows()
    assert empty.status == "unavailable"
    ent = EntityRecord(
        LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"k": "1"}),
        "n1",
        "ns::pkg.fn(int)",
        "text",
        {},
        None,
    )
    assert ProducerRows(entities=[ent]).status == "partial"
    assert _tail("ns::pkg.fn(int)") == "fn"
    assert _tail(None) == ""
    assert _names("ns::fn(int)", "") == ["fn", "ns::fn(int)"]
    assert _location(SNAP, None) is None
    assert _location(SNAP, {"path": None}) is None
    loc = _location(SNAP, asdict(_loc()))
    assert loc is not None and loc.path == "src/a.cpp"


def test_flow_rows_empty_present_missing_source_cfg_and_truncation(
    tmp_path: Path, monkeypatch
) -> None:
    empty_out = ProducerRows()
    _flow_rows(ShardSet(tmp_path, []), [], SCOPE, SNAP, empty_out)
    assert any("no accepted llvm-ir output" in g for g in empty_out.gaps)

    monkeypatch.setattr(producers, "MAX_FLOW_FUNCTIONS", 2)
    ir_entities = [
        EntityRecord(
            LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAP, {"fn": "f1"}),
            "ir:f1",
            "f1",
            "ir f1",
            {
                "distance": 0,
                "qualified_name": "ns::f1",
                "flow": {"blocks": 2},
                "source_cfg": {"blocks": 2},
                "seeded": True,
            },
            _loc("src/a.cpp", 10),
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAP, {"fn": "f2"}),
            "ir:f2",
            "f2",
            "ir f2",
            {"distance": 1, "flow": {"blocks": 1}},
            _loc("src/a.cpp", 20),
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAP, {"fn": "f3"}),
            "ir:f3",
            "f3",
            "ir f3",
            {"distance": 2, "flow": {"blocks": 3}},
            None,
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAP, {"fn": "noflow"}),
            "ir:nf",
            "nf",
            "ir nf",
            {"distance": 0},
            None,
        ),
    ]
    ir_shard = _write_index_shard(
        tmp_path,
        name="analysis",
        shard_id="ir-1",
        producer_meta={"job": "job_cpp_compiled_analysis", "branch": "ir"},
        entities=ir_entities,
    )
    out = ProducerRows()
    _flow_rows(ShardSet(tmp_path, [ir_shard]), [ir_shard], SCOPE, SNAP, out)
    assert out.counts["flow"] == 2
    assert len(out.entities) == 2
    assert any("limit_reached: flow graphs are published for the 2 nearest of 3" in g for g in out.gaps)
    assert any("source_cfg_unavailable: 1 of 2" in g for g in out.gaps)
    assert "source_cfg_no_block_lines: source CFG blocks are not mapped to source lines" in out.gaps


def test_diagnostic_rows_empty_filtering_sorting_and_truncation(
    tmp_path: Path, monkeypatch
) -> None:
    empty_out = ProducerRows()
    _diagnostic_rows(ShardSet(tmp_path, []), [], SCOPE, SNAP, empty_out)
    assert any("no accepted clang-static output" in g for g in empty_out.gaps)

    monkeypatch.setattr(producers, "MAX_DIAGNOSTICS", 2)
    monkeypatch.setattr(producers, "MAX_TRACE_STEPS", 2)
    obs_entities = [
        EntityRecord(
            LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAP, {"o": "1"}),
            "o1",
            "check.one",
            "obs 1",
            {
                "scanner": "clang-static-analyzer",
                "native_rule_id": "core.NullDereference",
                "reported_severity": "warning",
                "message": "null ptr",
                "trace": [{"step": 1}, {"step": 2}, {"step": 3}, "skip-non-map"],
                "seeded": {"label": "at_seed", "function": "f1", "seeds": ["s1"]},
            },
            _loc("src/a.cpp", 12),
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAP, {"o": "2"}),
            "o2",
            "check.two",
            "obs 2",
            {
                "scanner": "clang-tidy",
                "reported_severity": "note",
                "seeded": {"label": "in_neighborhood"},
            },
            None,
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAP, {"o": "3"}),
            "o3",
            "check.three",
            "obs 3",
            {"scanner": "clang-tidy", "seeded": {"label": "outside_neighborhood"}},
            None,
        ),
        EntityRecord(
            LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAP, {"o": "ignored"}),
            "o4",
            "semgrep.rule",
            "obs 4",
            {"scanner": "semgrep"},
            None,
        ),
    ]
    obs_shard = _write_index_shard(
        tmp_path,
        name="observations",
        shard_id="cs-1",
        producer_meta={"job": "job_clang_static_analysis", "project_root": "."},
        entities=obs_entities,
    )
    out = ProducerRows()
    _diagnostic_rows(ShardSet(tmp_path, [obs_shard]), [obs_shard], SCOPE, SNAP, out)
    assert out.counts["diagnostics"] == 2
    assert out.entities[0].payload["check"] == "core.NullDereference"
    assert out.entities[0].payload["trace_truncated"] is True
    assert len(out.entities[0].payload["trace"]) == 2
    assert any("limit_reached: diagnostics are published for the first 2 of 3" in g for g in out.gaps)


def test_cpg_rows_empty_unavailable_and_truncated(tmp_path: Path, monkeypatch) -> None:
    # When alternate CPG synthesis succeeds (default), missing Joern CPG records ZERO degradation penalty.
    alt_ok_out = ProducerRows()
    _cpg_rows(ShardSet(tmp_path, []), [], SCOPE, SNAP, alt_ok_out)
    assert alt_ok_out.gaps == []

    # Only when alternate CPG did not succeed does missing Joern CPG record a producer_not_run gap.
    empty_out = ProducerRows()
    _cpg_rows(ShardSet(tmp_path, []), [], SCOPE, SNAP, empty_out, alternate_cpg_succeeded=False)
    assert any("no accepted joern-cpg output" in g for g in empty_out.gaps)

    other_ast = _write_index_shard(
        tmp_path,
        name="observations",
        shard_id="cpg-empty",
        producer_meta={"job": "job_cpg_analysis", "project_root": "."},
        entities=[
            EntityRecord(
                LogicalIdentity.derive(EntityKind.AST_NODE, SNAP, {"a": "1"}),
                "a1",
                "not_cpg",
                "ast",
                {"fact": "other"},
                None,
            )
        ],
    )
    unavail = ProducerRows()
    _cpg_rows(ShardSet(tmp_path, [other_ast]), [other_ast], SCOPE, SNAP, unavail)
    assert "cpg_export_unavailable: the Joern CPG export published no function row for this database" in unavail.gaps

    monkeypatch.setattr(producers, "MAX_CPG_FUNCTIONS", 1)
    cpg_shard = _write_index_shard(
        tmp_path,
        name="observations",
        shard_id="cpg-1",
        producer_meta={"job": "job_cpg_analysis", "project_root": "."},
        entities=[
            EntityRecord(
                LogicalIdentity.derive(EntityKind.AST_NODE, SNAP, {"c": "1"}),
                "c1",
                "f1",
                "cpg f1",
                {"fact": "cpg", "full_name": "ns::f1", "path": "src/a.cpp", "line": 10, "has_body": True},
                None,
            ),
            EntityRecord(
                LogicalIdentity.derive(EntityKind.AST_NODE, SNAP, {"c": "2"}),
                "c2",
                "f2",
                "cpg f2",
                {"fact": "cpg", "full_name": "ns::f2", "path": "src/a.cpp", "line": 30},
                None,
            ),
        ],
    )
    out = ProducerRows()
    _cpg_rows(ShardSet(tmp_path, [cpg_shard]), [cpg_shard], SCOPE, SNAP, out)
    assert out.counts["cpg"] == 1
    assert len(out.entities) == 1
    assert any("limit_reached: CPG rows are published for 1 of 2 functions" in g for g in out.gaps)


def test_symbol_rows_symbol_links_and_build_end_to_end(tmp_path: Path, monkeypatch) -> None:
    empty_out = ProducerRows()
    _symbol_rows(ShardSet(tmp_path, []), [], {}, SCOPE, SNAP, empty_out)
    assert any("no accepted clangd output" in g for g in empty_out.gaps)

    id_s1 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"s": "1"})
    id_s2 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"s": "2"})
    id_s3 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"s": "3"})
    id_missing = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"s": "missing"})
    id_cql1 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"cql": "1"})
    id_cql2 = LogicalIdentity.derive(EntityKind.SYMBOL, SNAP, {"cql": "2"})
    clangd_shard = _write_index_shard(
        tmp_path,
        name="analysis",
        shard_id="clangd-1",
        producer_meta={
            "job": "job_cpp_symbol_index",
            "seeded": {"gaps": [f"seed-gap-{i}" for i in range(5)]},
        },
        entities=[
            EntityRecord(id_s1, "u1", "ns::caller", "sym caller", {"kind": "Function"}, _loc("src/a.cpp", 10)),
            EntityRecord(id_s2, "u2", "ns::callee1", "sym c1", {"kind": "Function"}, _loc("src/a.cpp", 20)),
            EntityRecord(id_s3, "u3", "ns::callee2", "sym c2", {"kind": "Function"}, _loc("src/a.cpp", 30)),
        ],
        relations=[
            RelationRecord(RelationKind.CALLS, id_s1.value, id_s2.value, True, 1.0, False, {}),
            RelationRecord(RelationKind.CALLS, id_s1.value, id_s3.value, True, 1.0, False, {}),
            RelationRecord(RelationKind.CALLS, id_s1.value, id_missing.value, True, 1.0, False, {}),
        ],
    )
    # Unlinked case first.
    unlinked_out = ProducerRows()
    _symbol_rows(ShardSet(tmp_path, [clangd_shard]), [clangd_shard], {}, SCOPE, SNAP, unlinked_out)
    assert "symbols_unlinked: no clangd symbol is linked to a CodeQL symbol of this database" in unlinked_out.gaps

    # Linked + MAX_SYMBOLS & MAX_RELATED caps + symbol_links + build().
    monkeypatch.setattr(producers, "MAX_SYMBOLS", 1)
    monkeypatch.setattr(producers, "MAX_RELATED", 1)
    rels = [
        RelationRecord(RelationKind.SAME_AS, id_cql1.value, id_s1.value, True, 1.0, False, {"method": "usr"}),
        RelationRecord(RelationKind.SAME_AS, id_cql2.value, id_s2.value, True, 1.0, False, {"method": "span"}),
        RelationRecord(RelationKind.CONTAINS, id_cql1.value, id_s1.value, True, 1.0, False, {}),
    ]
    links = symbol_links(rels)
    assert set(links) == {id_s1.value, id_s2.value}

    ir_seeded = _write_index_shard(
        tmp_path,
        name="analysis",
        shard_id="ir-seeded",
        producer_meta={
            "job": "job_cpp_compiled_analysis",
            "branch": "ir",
            "seeded": {"gaps": ["ir-seed-gap-1", "ir-seed-gap-2"]},
        },
        entities=[],
    )
    scope_with_inputs = {
        **SCOPE,
        "inputs": {
            "secondary": {"clangd": [clangd_shard], "llvm-ir": [ir_seeded]},
            "analyzers": {},
        },
    }
    built = build(tmp_path, scope=scope_with_inputs, snapshot=SNAP, relations=rels)
    assert built.counts["symbols"] == 1
    assert len(built.entities[0].payload["callees"]) == 1
    assert any("clangd symbols are published for 1 of 2 linked symbols" in g for g in built.gaps)
    assert any("lists 2 callees; the first 1 are kept" in g for g in built.gaps)
    assert any("llvm-ir: ir-seed-gap-1" in g for g in built.gaps)
    assert len(built.gaps) <= MAX_ROW_GAPS * 3
