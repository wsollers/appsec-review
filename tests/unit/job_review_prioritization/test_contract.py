"""Unit contract, input/semantic parser, and 7-unit executor tests for job_review_prioritization."""

from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_review_prioritization import (
    build_job,
    load_accepted_prioritization,
)
from appsec_review.jobs.job_review_prioritization.composite import CompositePrioritizationSettings
from appsec_review.jobs.job_review_prioritization.datasets import (
    CONSUMES,
    CONTRACT,
    DATASETS,
)
from appsec_review.jobs.job_review_prioritization.inputs import (
    accepted_handoff,
    has_handoff,
    producer_entities,
    read_json,
    read_lines,
)
from appsec_review.jobs.job_review_prioritization.job import (
    JOB_ID,
    SCHEMA,
    TOPOLOGY,
    _load_inputs,
    _settings,
    _validate,
)
from appsec_review.jobs.job_review_prioritization.semantic import (
    _semgrep_pack,
    codeql_paths,
    semgrep_signals,
)
from appsec_review.jobs.job_review_prioritization.syntax import Node, SourceFile, build_tree
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    SourceLocation,
    write_manifest,
)
from appsec_review.retrieval.source_resolution import generated_path, publish_source
from appsec_review.runtime.datasets import validate_declarations
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.swift_policy import SWIFT_KNOWN_GAP
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests" / "fixtures" / "review_prioritization"
TARGET = FIXTURE / "target"
GOLDEN = json.loads(gzip.decompress((FIXTURE / "ast-golden.json.gz").read_bytes()))
BASE_CONFIG = load_config(ROOT / "appsec-review.toml")


class _Events:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    def write(self, event_type: str, **payload: Any) -> None:
        self.records.append((event_type, payload))


def _artifact_ref(run_root: Path, path: Path, value: Any | None = None) -> dict[str, Any]:
    if value is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, value)
    return {
        "path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _publish_handoff(run_root: Path, job_id: str, outputs: dict[str, Any], *, attempt_id: str = "att_0001") -> str:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / attempt_id
    attempt.mkdir(parents=True, exist_ok=True)
    handoff = attempt / "handoff.json"
    write_fixture_handoff(run_root, handoff, {
        "status": "ACCEPTED",
        "job_id": job_id,
        "attempt_id": attempt_id,
        "outputs": outputs,
    })
    sha = file_sha256(handoff)
    atomic_json(run_root / "data" / "jobs" / job_id / "latest.json", {
        "handoff_path": handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": sha,
    })
    return sha


def _shard_rows_for_golden(paths: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        rec = GOLDEN["files"][path]
        for node in rec["nodes"]:
            rows.append({
                "schema": "appsec-review/tree-sitter-ast-node/1",
                "path": path,
                "file_sha256": rec["sha256"],
                "grammar_native_type": node["type"],
                "field": node["field"],
                "named": node["named"],
                "error": node["error"],
                "missing": node["missing"],
                "location": {
                    "producer_location": {
                        "grammar": rec["grammar"],
                        "ordinal_path": node["ordinal_path"],
                    },
                    "start_byte": node["start_byte"],
                    "end_byte": node["end_byte"],
                    "start_line": node["start_point"][0] + 1,
                    "end_line": node["end_point"][0] + 1,
                    "start_column": node["start_point"][1] + 1,
                    "end_column": node["end_point"][1] + 1,
                },
            })
    return rows


def _seed_upstream_run(
    tmp_path: Path,
    *,
    golden_paths: tuple[str, ...] = ("go/server/handler.go", "go/store/store.go", "web/src/broken.js"),
    extra_catalog_files: list[dict[str, Any]] | None = None,
    extra_dispositions: list[dict[str, Any]] | None = None,
    generated_sources: list[dict[str, Any]] | None = None,
    main_disposition_extra: dict[str, Any] | None = None,
) -> tuple[Path, Path, str, dict[str, str]]:
    runs_dir = tmp_path / "runs"
    run_id = "2026-01-01-0001"
    run_root = runs_dir / run_id
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)

    catalog_files: list[dict[str, Any]] = []
    lang_by_suffix = {
        ".go": "Go", ".js": "JavaScript", ".ts": "TypeScript", ".java": "Java",
        ".rb": "Ruby", ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++", ".rs": "Rust", ".cs": "C#",
    }
    for rel in golden_paths:
        dst = target / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(TARGET / rel, dst)
        catalog_files.append({
            "path": rel,
            "sha256": file_sha256(dst),
            "size_bytes": dst.stat().st_size,
            "language": lang_by_suffix[dst.suffix],
            "generated": False,
            "delivery_role": "production",
            "first_party": True,
            "vendored": False,
        })
    for extra in extra_catalog_files or ():
        catalog_files.append(extra)
    for manifest_rel in ("go/go.mod", "rust/Cargo.toml", "php/composer.json", "web/package.json"):
        src_mf = TARGET / manifest_rel
        if src_mf.is_file() and any(f["path"].startswith(manifest_rel.split("/")[0] + "/") for f in catalog_files):
            dst_mf = target / manifest_rel
            dst_mf.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_mf, dst_mf)
            catalog_files.append({
                "path": manifest_rel,
                "sha256": file_sha256(dst_mf),
                "size_bytes": dst_mf.stat().st_size,
                "language": None,
                "generated": False,
                "delivery_role": "production",
                "first_party": True,
                "vendored": False,
            })

    snapshot = hashlib.sha256(json.dumps(sorted(f["path"] for f in catalog_files)).encode()).hexdigest()
    intake_ref = _artifact_ref(run_root, run_root / "fixture" / "intake.json", {
        "schema": "appsec-review/review-intake/1",
        "fingerprint": {"sha256": snapshot},
    })
    intake_sha = _publish_handoff(run_root, "job_review_intake", {
        "publish_intake.publish_handoff": {"artifact": intake_ref},
    })

    part_ref = _artifact_ref(run_root, run_root / "fixture" / "partition.json", {"files": catalog_files})
    comp_ref = _artifact_ref(run_root, run_root / "fixture" / "components.json", {
        "components": [
            {"component_id": "comp:go", "root": "go"},
            {"component_id": "comp:root", "root": "."},
        ],
    })
    cat_manifest_path = run_root / "data" / "indices" / "manifests" / "catalog.json"
    write_manifest(cat_manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=[])
    cat_manifest_ref = _artifact_ref(run_root, cat_manifest_path)
    cat_ref = _artifact_ref(run_root, run_root / "fixture" / "catalog.json", {
        "schema": "appsec-review/target-catalog/1",
        "source_fingerprint": snapshot,
        "artifacts": {
            "repository_discovery.partition_repository": part_ref,
            "component_discovery.catalog_components": comp_ref,
        },
    })
    cat_sha = _publish_handoff(run_root, "job_target_catalog", {
        "publish_catalog.publish_handoff": {"artifact": cat_ref, "index_manifest": cat_manifest_ref},
    })

    shard_path = run_root / "data" / "treesitter" / "shards" / ("a" * 64 + ".jsonl")
    shard_path.parent.mkdir(parents=True, exist_ok=True)
    rows = _shard_rows_for_golden(golden_paths)
    shard_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    shard_ref = _artifact_ref(run_root, shard_path)
    dispositions = [
        {"scope_id": "scope-main", "language": "Go", "terminal_status": "SUCCEEDED",
         "artifact": shard_ref, "gaps": [], **(main_disposition_extra or {})},
        *(extra_dispositions or ()),
    ]
    ts_ref = _artifact_ref(run_root, run_root / "fixture" / "tree-sitter.json", {
        "schema": "appsec-review/tree-sitter-ast/1",
        "target_snapshot": snapshot,
        "dispositions": dispositions,
        "generated_sources": list(generated_sources or ()),
    })
    ts_sha = _publish_handoff(run_root, "job_tree_sitter_ast", {
        "acceptance.publish_handoff": {"artifact": ts_ref},
    })
    return run_root, target, snapshot, {
        "job_review_intake": intake_sha,
        "job_target_catalog": cat_sha,
        "job_tree_sitter_ast": ts_sha,
    }


def _job_context(
    tmp_path: Path,
    run_root: Path,
    target: Path,
    snapshot: str,
    upstream_handoffs: dict[str, str],
    *,
    settings_override: dict[str, Any] | None = None,
    enable_swift: bool = True,
    attempt_id: str = "attempt_0001",
) -> SimpleNamespace:
    job_cfg = BASE_CONFIG.job(JOB_ID)
    merged = dict(job_cfg.settings)
    if settings_override:
        merged.update(settings_override)
    cfg = replace(job_cfg, settings=merged)
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    attempt_root.mkdir(parents=True, exist_ok=True)
    metadata_root = tmp_path / "metadata"
    metadata_root.mkdir(parents=True, exist_ok=True)
    cat_mf = run_root / "data" / "indices" / "manifests" / "catalog.json"
    return SimpleNamespace(
        job_id=JOB_ID,
        run_id=run_root.name,
        run_root=run_root,
        runs_dir=run_root.parent,
        repository_root=ROOT,
        target_root=target,
        source_fingerprint=snapshot,
        attempt_id=attempt_id,
        attempt_root=attempt_root,
        metadata_root=metadata_root,
        input_manifest_path=cat_mf if cat_mf.is_file() else None,
        input_manifest_sha256=file_sha256(cat_mf) if cat_mf.is_file() else None,
        config=cfg,
        tools=replace(BASE_CONFIG.tools, enable_swift=enable_swift),
        review_policy=BASE_CONFIG.review_policy,
        upstream_handoffs=upstream_handoffs,
        events=_Events(),
        contract=CONTRACT,
    )


def test_contract_datasets_and_registry_parity() -> None:
    built = build_job()
    registered = builtin_registry().build(JOB_ID)
    assert built.job_id == registered.job_id == JOB_ID
    assert built.name == registered.name == "review_prioritization"
    assert built.schema_identity == registered.schema_identity == SCHEMA
    assert built.datasets == registered.datasets == DATASETS
    assert built.contract == registered.contract == CONTRACT
    assert built.consumes == registered.consumes == CONSUMES
    validate_declarations(JOB_ID, DATASETS)
    assert {item.output_kind for item in DATASETS} == {
        "priority_items",
        "prioritization_documents",
        "prioritization_signals",
    }
    assert tuple(u.unit_id for u in built.units) == (
        "load.accepted_inputs",
        "extract.syntax_metrics",
        "extract.dependency_graph",
        "extract.semantic_evidence",
        "prioritize.score",
        "publish.index_priority",
        "publish.publish_handoff",
    )


def test_validate_and_settings_fail_closed_on_invalid_configuration() -> None:
    base_cfg = BASE_CONFIG.job(JOB_ID)
    ctx = SimpleNamespace(config=base_cfg)
    _validate(ctx, None)

    bad_steps = SimpleNamespace(steps=("load",), step=base_cfg.step, settings=base_cfg.settings)
    with pytest.raises(ValueError, match="topology does not match"):
        _validate(SimpleNamespace(config=bad_steps), None)

    def wrong_step(name: str):
        if name == "extract":
            return SimpleNamespace(tasks=("syntax_metrics",))
        return base_cfg.step(name)

    bad_tasks = SimpleNamespace(steps=tuple(TOPOLOGY), step=wrong_step, settings=base_cfg.settings)
    with pytest.raises(ValueError, match="task order mismatch: extract"):
        _validate(SimpleNamespace(config=bad_tasks), None)

    cases: list[tuple[dict[str, Any], str]] = [
        ({"max_files": 0}, "setting is invalid: max_files"),
        ({"max_files": True}, "setting is invalid: max_files"),
        ({"custom_parsing_min_density": -0.5}, "setting is invalid: custom_parsing_min_density"),
        ({"min_edge_confidence": True}, "setting is invalid: min_edge_confidence"),
        ({"cyclomatic_thresholds": [10, 5]}, "cyclomatic thresholds"),
        ({"cyclomatic_thresholds": [5, 20], "scored_threshold": 10}, "cyclomatic thresholds"),
        ({"count_error_propagation": 1}, "count_error_propagation"),
        ({"normalization_population": "repo"}, "normalization_population"),
        ({"priority_weights": {}}, "priority_weights are required"),
        ({"priority_weights": {"bogus_feature": 1.0}}, "unknown review prioritization feature"),
        ({"priority_weights": {"cyclomatic": -1.0}}, "weight is invalid: cyclomatic"),
        ({"priority_weights": {"cyclomatic": float("nan")}}, "weight is invalid: cyclomatic"),
        ({"priority_weights": {"cyclomatic": float("inf")}}, "weight is invalid: cyclomatic"),
        ({"priority_weights": {"cyclomatic": 1e308, "cognitive": 1e308}}, "finite total"),
        ({"priority_weights": {"cyclomatic": 0.0}}, "at least one positive weight"),
        ({"index": {"file_top_fraction": 0.2}}, "index settings are invalid"),
        ({"index": {**base_cfg.settings["index"], "file_top_fraction": 0.0}}, "index setting is invalid: file_top_fraction"),
        ({"index": {**base_cfg.settings["index"], "max_indexed_items": 0}}, "index setting is invalid: max_indexed_items"),
        ({"sources": {"history": True}}, "sources must enable or disable"),
        ({"sources": {"history": 1, "semgrep": True, "codeql": True}}, "sources must enable or disable"),
        ({"composite_weights": {"change_context_boost": float("nan")}}, "composite"),
        ({"composite_weights": {"change_context_boost": float("inf")}}, "composite"),
        ({"composite_weights": {"change_context_boost": -1.0}}, "composite"),
        ({"composite_weights": {"change_context_boost": True}}, "composite"),
        ({"composite_weights": {"change_context_boost": 1e308, "uncovered_risk_boost": 1e308}}, "finite"),
        ({"syntax_metrics_reservation": {"cpu": 0, "memory_mb": 64, "io_slots": 0, "admission_timeout_seconds": 10}},
         "syntax_metrics_reservation is invalid"),
    ]
    for patch, pattern in cases:
        mutated = SimpleNamespace(config=replace(base_cfg, settings={**base_cfg.settings, **patch}))
        with pytest.raises(ValueError, match=pattern):
            _settings(mutated)


@pytest.mark.parametrize("threshold", [-1, True, "5", 1.5, None, float("inf"), float("nan")],
                         ids=["negative", "boolean", "string", "fractional", "null", "infinity", "nan"])
def test_sast_silence_threshold_rejects_invalid_explicit_values(threshold) -> None:
    config = BASE_CONFIG.job(JOB_ID)
    settings = {**config.settings, "sast_silence_min_complexity": threshold}
    with pytest.raises(ValueError, match="sast_silence_min_complexity"):
        _settings(SimpleNamespace(config=replace(config, settings=settings)))
    with pytest.raises(ValueError, match="sast_silence_min_complexity"):
        CompositePrioritizationSettings.from_settings(settings)


@pytest.mark.parametrize("threshold", [0, 5, 1_000_000])
def test_sast_silence_threshold_preserves_valid_integer_policy(threshold: int) -> None:
    config = BASE_CONFIG.job(JOB_ID)
    settings = {**config.settings, "sast_silence_min_complexity": threshold}
    validated = _settings(SimpleNamespace(config=replace(config, settings=settings)))
    assert CompositePrioritizationSettings.from_settings(validated).sast_silence_min_complexity == threshold


def test_syntax_tree_guards_and_inputs_helpers(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="omit the root node"):
        build_tree([])
    root_row = {
        "grammar_native_type": "program", "field": None, "named": True, "error": False, "missing": False,
        "location": {"producer_location": {"ordinal_path": []}, "start_byte": 0, "end_byte": 1,
                     "start_line": 1, "end_line": 1, "start_column": 1, "end_column": 2},
    }
    with pytest.raises(ValueError, match="duplicate Tree-sitter ordinal path"):
        build_tree([root_row, root_row])
    orphan = {**root_row, "location": {**root_row["location"], "producer_location": {"ordinal_path": [0, 1]}}}
    with pytest.raises(ValueError, match="omit a parent node"):
        build_tree([root_row, orphan])

    root_node, _ = build_tree([root_row])
    assert root_node.operator() is None
    assert SourceFile("a.c", "0" * 64, "c", "C", b"", root_node, 0).line_count() == 0
    assert SourceFile("a.c", "0" * 64, "c", "C", b"int x;", root_node, 0).line_count() == 1
    assert SourceFile("a.c", "0" * 64, "c", "C", b"int x;\n", root_node, 0).line_count() == 1

    run_root = tmp_path / "run"
    run_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    for fn in (read_json, lambda r, i: list(read_lines(r, i))):
        with pytest.raises(ValueError, match="unavailable or outside"):
            fn(run_root, {"path": "../outside.json", "sha256": file_sha256(outside)})
        with pytest.raises(ValueError, match="unavailable or outside"):
            fn(run_root, {"path": "missing.json", "sha256": "0" * 64})

    jsonl_path = run_root / "data" / "rows.jsonl"
    jsonl_path.parent.mkdir(parents=True)
    jsonl_path.write_text('{"a": 1}\n\n{"a": 2}\n', encoding="utf-8")
    link = run_root / "data" / "link.jsonl"
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="unavailable or outside"):
        list(read_lines(run_root, {"path": "data/link.jsonl", "sha256": file_sha256(outside)}))
    with pytest.raises(ValueError, match="identity changed"):
        read_json(run_root, {"path": "data/rows.jsonl", "sha256": "0" * 64})
    with pytest.raises(ValueError, match="identity changed"):
        list(read_lines(run_root, {"path": "data/rows.jsonl", "sha256": "0" * 64}))
    assert list(read_lines(run_root, {"path": "data/rows.jsonl", "sha256": file_sha256(jsonl_path)})) == [
        {"a": 1}, {"a": 2},
    ]

    snapshot = "b" * 64
    target = tmp_path / "target"
    target.mkdir()
    (target / "f.go").write_text("package p\n", encoding="utf-8")
    shard_ok = run_root / "data" / "indices" / "observations" / "ok.sqlite"
    b_ok = IndexBuilder(shard_ok, name="observations", fingerprint="1" * 64, target_snapshot=snapshot, shard_id="ok")
    id1 = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"i": 1})
    id2 = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"i": 2})
    loc = SourceLocation(snapshot, "f.go", file_sha256(target / "f.go"), 0, 10, 1, 1, 1, 10, {}, "exact", 1.0)
    b_ok.add_entity(EntityRecord(id1, "1", "obs1", "obs1", {"k": "with_loc"}, loc))
    b_ok.add_entity(EntityRecord(id2, "2", "obs2", "obs2", {"k": "no_loc"}, None))
    b_ok.build()
    shard_other = run_root / "data" / "indices" / "observations" / "other.sqlite"
    b_other = IndexBuilder(shard_other, name="observations", fingerprint="2" * 64, target_snapshot=snapshot, shard_id="other")
    b_other.build()
    manifest_path = run_root / "data" / "indices" / "manifests" / "obs.json"
    write_manifest(manifest_path, run_id="run", target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(shard_ok), "1" * 64,
                      shard_ok.relative_to(run_root).as_posix(), {"job": "job_a", "producer": "tool-x"}, (), "ok"),
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(shard_other), "2" * 64,
                      shard_other.relative_to(run_root).as_posix(), {"job": "job_b", "producer": "tool-y"}, (), "other"),
    ])
    m_ref = _artifact_ref(run_root, manifest_path)
    items = list(producer_entities(run_root, m_ref, job="job_a", kind="tool_observation", producer="tool-x"))
    assert len(items) == 2
    by_k = {entry["payload"]["k"]: entry["location"] for _s, entry in items}
    assert by_k["with_loc"] is not None and by_k["with_loc"]["path"] == "f.go"
    assert by_k["no_loc"] is None
    assert list(producer_entities(run_root, m_ref, job="job_a", kind="tool_observation", producer="tool-z")) == []


def test_semgrep_signals_and_codeql_paths_all_dispositions_and_bounds(tmp_path: Path) -> None:
    assert "sha256" in _semgrep_pack(ROOT)
    assert _semgrep_pack(tmp_path / "missing-repo") == {"verified": False}

    run_root = tmp_path / "runs" / "r1"
    run_root.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    a_sha = file_sha256(target / "a.c")
    snapshot = "c" * 64

    assert semgrep_signals(run_root, ROOT)["status"] == "UNAVAILABLE"
    assert codeql_paths(run_root, limit=10)["status"] == "UNAVAILABLE"

    # Semgrep not planned
    ev_none = _artifact_ref(run_root, run_root / "fix" / "ev0.json", {"dispositions": []})
    _publish_handoff(run_root, "job_evidence_collection", {"evidence_publication.publish_handoff": {"artifact": ev_none}})
    res_none = semgrep_signals(run_root, ROOT)
    assert res_none["status"] == "UNAVAILABLE" and "not planned" in res_none["gaps"][0]

    # Semgrep FAILED disposition
    ev_fail = _artifact_ref(run_root, run_root / "fix" / "ev1.json", {
        "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "FAILED", "gaps": ["timeout"]}],
    })
    _publish_handoff(run_root, "job_evidence_collection", {"evidence_publication.publish_handoff": {"artifact": ev_fail}},
                     attempt_id="att_0002")
    res_fail = semgrep_signals(run_root, ROOT)
    assert res_fail["status"] == "UNAVAILABLE"
    assert any("Semgrep disposition FAILED" in g for g in res_fail["gaps"])

    # Semgrep SUCCEEDED with valid signal, banned-function signal, non-signal rule, and malformed signal
    sg_shard = run_root / "data" / "indices" / "observations" / "sg.sqlite"
    b_sg = IndexBuilder(sg_shard, name="observations", fingerprint="3" * 64, target_snapshot=snapshot, shard_id="sg")
    sg_payloads = [
        {"native_rule_id": "rules.appsec-review.review-signal.sink.cpp-banned-function-strcpy",
         "message": "strcpy", "evidence_id": "e1", "location": {"path": "a.c", "source_sha256": a_sha, "start_line": 1}},
        {"native_rule_id": "appsec-review.review-signal.validator",
         "message": "validator", "evidence_id": "e2", "location": {"path": "a.c", "start_line": 1, "end_line": 1}},
        {"native_rule_id": "appsec-review.other-rule", "location": {"path": "a.c", "start_line": 1}},
        {"native_rule_id": "appsec-review.review-signal.unknown_cat.foo", "location": {"path": "a.c", "start_line": 1}},
    ]
    for idx, payload in enumerate(sg_payloads):
        ident = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"sg": idx})
        b_sg.add_entity(EntityRecord(ident, str(idx), "sg", "sg", payload, None))
    b_sg.build()
    sg_manifest = run_root / "data" / "indices" / "manifests" / "sg.json"
    write_manifest(sg_manifest, run_id="r1", target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(sg_shard), "3" * 64,
                      sg_shard.relative_to(run_root).as_posix(),
                      {"job": "job_evidence_collection", "producer": "tool-semgrep"}, (), "sg"),
    ])
    ev_ok = _artifact_ref(run_root, run_root / "fix" / "ev2.json", {
        "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}],
    })
    _publish_handoff(run_root, "job_evidence_collection", {
        "evidence_publication.publish_handoff": {"artifact": ev_ok, "index_manifest": _artifact_ref(run_root, sg_manifest)},
    }, attempt_id="att_0003")
    res_sg = semgrep_signals(run_root, ROOT)
    assert res_sg["status"] == "PARTIAL"
    assert len(res_sg["signals"]) == 2
    assert any(s["rules"].startswith("semgrep-banned-functions@") for s in res_sg["signals"])
    assert any(s["surface"] == "validator" for s in res_sg["signals"])
    assert any("without category or location" in g for g in res_sg["gaps"])

    # CodeQL without index_manifest
    cq_no_mf = _artifact_ref(run_root, run_root / "fix" / "cq0.json", {
        "scopes": [{"language": "cpp", "terminal_status": "FAILED"}, {"language": "cpp", "terminal_status": "SUCCEEDED"},
                   {"language": "java", "terminal_status": "FAILED"}],
    })
    _publish_handoff(run_root, "job_codeql_analysis", {"acceptance.publish_handoff": {"artifact": cq_no_mf}})
    res_cq0 = codeql_paths(run_root, limit=1)
    assert res_cq0["status"] == "UNAVAILABLE"
    assert res_cq0["languages"] == {"cpp": "SUCCEEDED", "java": "FAILED"}
    assert any("no index manifest" in g for g in res_cq0["gaps"])

    # CodeQL with merged flows (code_flow=None), step_limit overflow, unmapped single-step, and limit truncation
    def step(line: int, cf: int | None, ordinal: int) -> dict[str, Any]:
        return {"ordinal": ordinal, "code_flow": cf, "thread_flow": 0, "message": "m",
                "location": {"path": "a.c", "file_sha256": a_sha, "start_line": line, "end_line": line,
                             "start_column": 1, "end_column": 2}}

    cq_shard = run_root / "data" / "indices" / "observations" / "cq.sqlite"
    b_cq = IndexBuilder(cq_shard, name="observations", fingerprint="4" * 64, target_snapshot=snapshot, shard_id="cq")
    cq_payloads = [
        {"rule_id": "cpp/taint-1", "query_identity": "q1", "language": "cpp", "message": "m1",
         "flows": [step(1, None, 0), step(2, None, 1)]},
        {"rule_id": "cpp/taint-2", "query_identity": "q1", "language": "cpp", "message": "m2",
         "flows": [step(1, 0, 0), step(3, 0, 1)]},
        {"rule_id": "cpp/too-long", "query_identity": "q1", "language": "cpp", "message": "m3",
         "flows": [step(1, 0, 0), step(2, 0, 1), step(3, 0, 2), step(4, 0, 3)]},
        {"rule_id": "cpp/unmapped", "query_identity": "q1", "language": "cpp", "message": "m4",
         "flows": [step(1, 0, 0), {"ordinal": 1, "code_flow": 0, "thread_flow": 0, "location": {}}]},
    ]
    for idx, payload in enumerate(cq_payloads):
        ident = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"cq": idx})
        b_cq.add_entity(EntityRecord(ident, str(idx), "cq", "cq", payload, None))
    b_cq.build()
    cq_manifest = run_root / "data" / "indices" / "manifests" / "cq.json"
    write_manifest(cq_manifest, run_id="r1", target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(cq_shard), "4" * 64,
                      cq_shard.relative_to(run_root).as_posix(), {"job": "job_codeql_analysis"}, (), "cq"),
    ])
    _publish_handoff(run_root, "job_codeql_analysis", {
        "acceptance.publish_handoff": {"artifact": cq_no_mf, "index_manifest": _artifact_ref(run_root, cq_manifest)},
    }, attempt_id="att_0002")
    res_cq = codeql_paths(run_root, limit=1, step_limit=3)
    assert res_cq["status"] == "PARTIAL"
    assert len(res_cq["paths"]) == 1 and res_cq["paths"][0]["path_id"].startswith("path-")
    gaps_joined = "\n".join(res_cq["gaps"])
    assert "semantic_path_step_bound_reached" in gaps_joined
    assert "semantic_path_flow_boundaries_unavailable" in gaps_joined
    assert "semantic_paths_truncated: kept 1 of 2" in gaps_joined


def test_load_inputs_validation_swift_filter_and_generated_sources(tmp_path: Path) -> None:
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path,
        golden_paths=("go/store/store.go",),
        extra_catalog_files=[{
            "path": "ios/App.swift", "sha256": "e" * 64, "size_bytes": 12,
            "language": "Swift", "generated": False, "delivery_role": "production",
            "first_party": True, "vendored": False,
        }],
    )
    assert load_accepted_prioritization(run_root) is None
    assert has_handoff(run_root, "job_review_intake") is True

    # Valid generated source backed under run_root via publish_source
    gen_bytes = b"package gen\nfunc Gen() int { return 1 }\n"
    gen_sha = hashlib.sha256(gen_bytes).hexdigest()
    gen_run_root, _, gen_snap, _ = _seed_upstream_run(
        tmp_path / "with_gen",
        golden_paths=("go/store/store.go",),
    )
    gen_canonical = LogicalIdentity.derive(EntityKind.BUILD_ARTIFACT, gen_snap, {
        "build_unit_id": "bu-1",
        "workspace_path": "go/gen.go",
        "sha256": gen_sha,
        "format": "generated-source",
    })
    gen_logical = generated_path(gen_canonical.value, "go/gen.go")
    backing = publish_source(
        gen_run_root,
        target_snapshot=gen_snap,
        logical_path=gen_logical,
        artifact={
            "sha256": gen_sha,
            "canonical_identity": gen_canonical.value,
            "kind": "generated-source",
            "workspace_path": "go/gen.go",
            "artifact_origin": "build-output",
            "scope_role": "target_source",
            "delivery_role": "production",
            "first_party": True,
            "vendored": False,
        },
        build_unit_id="bu-1",
        handoff_sha256="a" * 64,
        data=gen_bytes,
    )
    gen_entry = {
        "path": gen_logical,
        "workspace_path": "go/gen.go",
        "sha256": gen_sha,
        "size_bytes": len(gen_bytes),
        "language": "Go",
        "generated": True,
        "delivery_role": "production",
        "first_party": True,
        "vendored": False,
        "source_backing": backing,
    }
    gen_ts_prev = read_json(
        gen_run_root,
        json.loads((gen_run_root / "data" / "jobs" / "job_tree_sitter_ast" / "attempts" / "att_0001" / "handoff.json").read_text(encoding="utf-8"))["outputs"]["acceptance.publish_handoff"]["artifact"],
    )
    gen_ts_new = _artifact_ref(gen_run_root, gen_run_root / "fixture" / "ts-with-gen.json", {
        **gen_ts_prev,
        "generated_sources": [gen_entry],
    })
    _publish_handoff(gen_run_root, "job_tree_sitter_ast", {"acceptance.publish_handoff": {"artifact": gen_ts_new}},
                     attempt_id="att_gen")
    loaded_gen = _load_inputs(gen_run_root)
    assert gen_logical in loaded_gen["files"]
    assert loaded_gen["files"][gen_logical]["component_id"] == "comp:go"

    # Swift disabled filters Swift files and records SWIFT_KNOWN_GAP; fingerprint mismatch fails closed
    built = build_job()
    load_unit = built.units[0]
    swift_ctx = _job_context(tmp_path, run_root, target, snapshot, handoffs, enable_swift=False)
    unit_root = swift_ctx.attempt_root / "steps" / "load" / "tasks" / "accepted_inputs"
    unit_root.mkdir(parents=True, exist_ok=True)
    load_out = load_unit.handler(SimpleNamespace(job=swift_ctx, unit_id="load.accepted_inputs",
                                                 unit_root=unit_root, output=lambda _u: {}))
    assert load_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert SWIFT_KNOWN_GAP in load_out["gaps"]
    loaded_files = read_json(run_root, load_out["files_artifact"])
    assert "ios/App.swift" not in loaded_files

    bad_fp_ctx = _job_context(tmp_path, run_root, target, "f" * 64, handoffs, attempt_id="attempt_0002")
    with pytest.raises(ValueError, match="graph target fingerprint does not match"):
        load_unit.handler(SimpleNamespace(job=bad_fp_ctx, unit_id="load.accepted_inputs",
                                          unit_root=unit_root, output=lambda _u: {}))

    # Schema / snapshot / generated_sources error branches in _load_inputs
    bad_ts = _artifact_ref(run_root, run_root / "fixture" / "bad-ts.json", {
        "schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": snapshot,
        "dispositions": [], "generated_sources": ["not-a-mapping"],
    })
    _publish_handoff(run_root, "job_tree_sitter_ast", {"acceptance.publish_handoff": {"artifact": bad_ts}},
                     attempt_id="att_bad1")
    with pytest.raises(ValueError, match="invalid generated source"):
        _load_inputs(run_root)

    no_backing = {k: v for k, v in gen_entry.items() if k != "source_backing"}
    bad_ts2 = _artifact_ref(run_root, run_root / "fixture" / "bad-ts2.json", {
        "schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": snapshot,
        "dispositions": [], "generated_sources": [no_backing],
    })
    _publish_handoff(run_root, "job_tree_sitter_ast", {"acceptance.publish_handoff": {"artifact": bad_ts2}},
                     attempt_id="att_bad2")
    with pytest.raises(ValueError, match="generated source backing absent"):
        _load_inputs(run_root)

    bad_snap = _artifact_ref(run_root, run_root / "fixture" / "bad-snap.json", {
        "schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": "0" * 64, "dispositions": [],
    })
    _publish_handoff(run_root, "job_tree_sitter_ast", {"acceptance.publish_handoff": {"artifact": bad_snap}},
                     attempt_id="att_bad3")
    with pytest.raises(ValueError, match="identities disagree"):
        _load_inputs(run_root)

    bad_schema = _artifact_ref(run_root, run_root / "fixture" / "bad-schema.json", {"schema": "wrong/1"})
    _publish_handoff(run_root, "job_tree_sitter_ast", {"acceptance.publish_handoff": {"artifact": bad_schema}},
                     attempt_id="att_bad4")
    with pytest.raises(ValueError, match="unsupported schemas"):
        _load_inputs(run_root)


def test_full_unit_executor_with_disabled_sources_bounds_and_shard_reuse(tmp_path: Path) -> None:
    extra_files = [
        {"path": "README.md", "sha256": "1" * 64, "size_bytes": 10, "language": None,
         "generated": False, "delivery_role": "production", "first_party": True, "vendored": False},
        {"path": "scripts/tool.py", "sha256": "2" * 64, "size_bytes": 20, "language": "Python",
         "generated": False, "delivery_role": "production", "first_party": True, "vendored": False},
        {"path": "go/store/store_test.go", "sha256": "3" * 64, "size_bytes": 20, "language": "Go",
         "generated": False, "delivery_role": "test", "scope_role": "supplied_platform",
         "first_party": True, "vendored": False},
        {"path": "go/huge.go", "sha256": "4" * 64, "size_bytes": 10_000_000, "language": "Go",
         "generated": False, "delivery_role": "production", "first_party": True, "vendored": False},
        {"path": "go/no_rows.go", "sha256": "5" * 64, "size_bytes": 30, "language": "Go",
         "generated": False, "delivery_role": "production", "first_party": True, "vendored": False},
        {"path": "ruby/failed.rb", "sha256": "6" * 64, "size_bytes": 30, "language": "Ruby",
         "generated": False, "delivery_role": "production", "first_party": True, "vendored": False},
        {"path": "third_party/vendor.go", "sha256": "7" * 64, "size_bytes": 30, "language": "Go",
         "generated": False, "delivery_role": "production", "first_party": False, "vendored": True},
    ]
    extra_dispositions = [
        {"scope_id": "scope-rb", "language": "Ruby", "terminal_status": "FAILED", "reason": "crash", "gaps": []},
        {"scope_id": "scope-trunc", "language": "Java", "terminal_status": "PARTIAL",
         "gaps": ["java/src/main/java/com/example/web/UserController.java: file node limit reached"]},
    ]
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path,
        golden_paths=(
            "go/server/handler.go",
            "go/store/store.go",
            "java/src/main/java/com/example/web/UserController.java",
            "java/src/main/java/com/example/store/UserStore.java",
            "web/src/server.js",
            "web/src/util.js",
            "web/src/api.ts",
            "web/src/broken.js",
        ),
        extra_catalog_files=extra_files,
        extra_dispositions=extra_dispositions,
        main_disposition_extra={"counts": {"excluded_files": [
            {"path": "third_party/vendor.go", "disposition": "vendored", "reason": "node limit reached"}]}},
    )
    built = build_job()
    settings_override = {
        "max_file_bytes": 1_000_000,
        "sources": {"history": False, "semgrep": False, "codeql": False},
        "index": {
            **BASE_CONFIG.job(JOB_ID).settings["index"],
            "file_top_count": 2,
            "function_top_count": 1,
            "max_graph_neighbors": 1,
        },
    }
    ctx1 = _job_context(tmp_path, run_root, target, snapshot, handoffs,
                        settings_override=settings_override, attempt_id="attempt_0001")
    result1 = built.execute(ctx1)
    pub1 = result1["outputs"]["publish.publish_handoff"]
    assert pub1["schema"] == SCHEMA
    # The publish unit declares no gaps of its own; the upstream units declared theirs. The merged list is
    # carried as aggregated_gaps, so each reason is one producer-gap record in the job outcome.
    assert pub1["terminal_status"] == "SUCCEEDED" and pub1["gaps"] == []
    index_out = result1["outputs"]["publish.index_priority"]
    assert index_out["gaps"] == ["dependency_graph_context_bound_reached"]
    assert set(result1["outputs"]["extract.syntax_metrics"]["gaps"]) <= set(pub1["aggregated_gaps"])
    assert set(index_out["gaps"]) <= set(pub1["aggregated_gaps"]) == set(index_out["aggregated_gaps"])
    gaps = "\n".join(pub1["aggregated_gaps"])
    assert "go/huge.go: file_byte_bound_reached" in gaps
    assert "go/no_rows.go: ast_unavailable" in gaps
    # A vendored file the AST node budget excluded is a named exclusion, never ``ast_unavailable``.
    assert "third_party/vendor.go: excluded (node budget, vendored)" in gaps
    assert "third_party/vendor.go: ast_unavailable" not in gaps
    assert "ruby/failed.rb: ast_unavailable (tree-sitter scope FAILED: crash)" in gaps
    assert "java/src/main/java/com/example/web/UserController.java: ast_truncated" in gaps
    assert "language_not_scored:Python (1 files)" in gaps
    assert "semgrep_review_signals_disabled" in gaps
    assert "semantic_paths_disabled" in gaps
    assert "history_hotspots_disabled" in gaps
    assert "dependency_graph_context_bound_reached" in gaps

    syntax_meta = result1["outputs"]["extract.syntax_metrics"]
    assert syntax_meta["skipped"]["file_byte_bound"] == 1
    assert syntax_meta["skipped"]["out_of_delivery_scope"] == 1
    assert syntax_meta["skipped"]["not_source"] >= 1

    # Re-running with identical attempt/inputs/settings hits existing SQLite shard path (`if not path.exists():`)
    ctx2 = _job_context(tmp_path, run_root, target, snapshot, handoffs,
                        settings_override=settings_override, attempt_id="attempt_0001")
    result2 = built.execute(ctx2)
    assert result2["outputs"]["publish.index_priority"]["index_identity"]["sha256"] == (
        result1["outputs"]["publish.index_priority"]["index_identity"]["sha256"]
    )


def test_full_unit_executor_with_semantic_paths_semgrep_history_and_loader_guards(tmp_path: Path) -> None:
    run_root, target, snapshot, handoffs = _seed_upstream_run(
        tmp_path,
        golden_paths=tuple(sorted(GOLDEN["files"])),
    )
    handler = "go/server/handler.go"
    store = "go/store/store.go"
    java = "java/src/main/java/com/example/web/UserController.java"
    h_sha = file_sha256(target / handler)
    s_sha = file_sha256(target / store)
    j_sha = file_sha256(target / java)

    # Seed CodeQL (1 valid cross-file path + 1 path referencing unaccepted file)
    cq_shard = run_root / "data" / "indices" / "observations" / "cq.sqlite"
    b_cq = IndexBuilder(cq_shard, name="observations", fingerprint="5" * 64, target_snapshot=snapshot, shard_id="cq")
    b_cq.add_entity(EntityRecord(
        LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"cq": 1}), "1", "cq", "cq",
        {"producer": "codeql", "rule_id": "go/cmdi", "query_identity": "q1", "language": "go", "message": "cmdi",
         "flows": [
             {"ordinal": 0, "code_flow": 0, "thread_flow": 0, "message": "src",
              "location": {"path": handler, "file_sha256": h_sha, "start_line": 18, "end_line": 18,
                           "start_column": 32, "end_column": 33}},
             {"ordinal": 1, "code_flow": 0, "thread_flow": 0, "message": "mid",
              "location": {"path": store, "file_sha256": s_sha, "start_line": 15, "end_line": 15,
                           "start_column": 3, "end_column": 4}},
             {"ordinal": 2, "code_flow": 0, "thread_flow": 0, "message": "sink",
              "location": {"path": handler, "file_sha256": h_sha, "start_line": 22, "end_line": 22,
                           "start_column": 15, "end_column": 16}},
         ]}, None))
    b_cq.add_entity(EntityRecord(
        LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"cq": 2}), "2", "cq", "cq",
        {"producer": "codeql", "rule_id": "go/unbound", "query_identity": "q1", "language": "go", "message": "ub",
         "flows": [
             {"ordinal": 0, "code_flow": 0, "thread_flow": 0, "message": "src",
              "location": {"path": "missing.go", "start_line": 1, "end_line": 1, "start_column": 1, "end_column": 2}},
             {"ordinal": 1, "code_flow": 0, "thread_flow": 0, "message": "sink",
              "location": {"path": handler, "file_sha256": h_sha, "start_line": 22, "end_line": 22,
                           "start_column": 15, "end_column": 16}},
         ]}, None))
    b_cq.build()
    cq_mf = run_root / "data" / "indices" / "manifests" / "cq.json"
    write_manifest(cq_mf, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(cq_shard), "5" * 64,
                      cq_shard.relative_to(run_root).as_posix(), {"job": "job_codeql_analysis"}, (), "cq"),
    ])
    cq_sum = _artifact_ref(run_root, run_root / "fixture" / "cq-sum.json", {
        "scopes": [{"language": "go", "terminal_status": "SUCCEEDED"}],
    })
    handoffs["job_codeql_analysis"] = _publish_handoff(run_root, "job_codeql_analysis", {
        "acceptance.publish_handoff": {"artifact": cq_sum, "index_manifest": _artifact_ref(run_root, cq_mf)},
    })

    # Seed Semgrep (1 bound signal + 1 signal referencing unaccepted file)
    sg_shard = run_root / "data" / "indices" / "observations" / "sg.sqlite"
    b_sg = IndexBuilder(sg_shard, name="observations", fingerprint="6" * 64, target_snapshot=snapshot, shard_id="sg")
    b_sg.add_entity(EntityRecord(
        LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"sg": 1}), "1", "sg", "sg",
        {"tool_id": "tool-semgrep", "evidence_id": "ev-1",
         "native_rule_id": "rules.appsec-review.review-signal.privilege_shift.spring-permit-all",
         "message": "anon", "location": {"path": java, "source_sha256": j_sha, "start_line": 19, "end_line": 19}}, None))
    b_sg.add_entity(EntityRecord(
        LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"sg": 2}), "2", "sg", "sg",
        {"tool_id": "tool-semgrep", "evidence_id": "ev-2",
         "native_rule_id": "rules.appsec-review.review-signal.sink.exec",
         "message": "ub", "location": {"path": "unbound.java", "start_line": 1, "end_line": 1}}, None))
    b_sg.build()
    sg_mf = run_root / "data" / "indices" / "manifests" / "sg.json"
    write_manifest(sg_mf, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(sg_shard), "6" * 64,
                      sg_shard.relative_to(run_root).as_posix(),
                      {"job": "job_evidence_collection", "producer": "tool-semgrep"}, (), "sg"),
    ])
    ev_doc = _artifact_ref(run_root, run_root / "fixture" / "ev.json", {
        "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}],
    })
    handoffs["job_evidence_collection"] = _publish_handoff(run_root, "job_evidence_collection", {
        "evidence_publication.publish_handoff": {"artifact": ev_doc, "index_manifest": _artifact_ref(run_root, sg_mf)},
    })

    # Seed multi-repository source-history (1 repo with SII file+symbol scores, 1 repo with no ranking signals)
    sig_ref = _artifact_ref(run_root, run_root / "fixture" / "hist-sig.json", {
        "schema": "appsec-review/source-history-signals/2",
        "files": {store: {"sii": {"score": 88.5}}},
        "symbols": {"sym1": {"path": store, "start_byte": 0, "end_byte": 100, "sii": {"score": 77.0}}},
    })
    repo1 = _artifact_ref(run_root, run_root / "fixture" / "hist-r1.json", {
        "binding": "partial", "decision": "PARTIAL", "ranking": {"signals": sig_ref},
    })
    repo2 = _artifact_ref(run_root, run_root / "fixture" / "hist-r2.json", {
        "binding": "exact", "decision": "SKIPPED_SHALLOW", "source": {"source_id": "subrepo"}, "ranking": {},
    })
    hist_doc = _artifact_ref(run_root, run_root / "fixture" / "hist.json", {
        "schema": "appsec-review/source-history-analysis/2",
        "decision": "PARTIAL",
        "sources": {"repositories": [{"artifact": repo1}, {"artifact": repo2}]},
        "gaps": ["shallow clone"],
    })
    handoffs["job_source_history_analysis"] = _publish_handoff(
        run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": hist_doc}},
    )

    built = build_job()
    ctx = _job_context(tmp_path, run_root, target, snapshot, handoffs,
                       settings_override={"index": {**BASE_CONFIG.job(JOB_ID).settings["index"], "file_top_count": 10}})
    result = built.execute(ctx)
    pub = result["outputs"]["publish.publish_handoff"]
    prio_sha = _publish_handoff(run_root, JOB_ID, {"publish.publish_handoff": pub})
    loaded = load_accepted_prioritization(run_root)
    assert loaded is not None and loaded["handoff_sha256"] == prio_sha
    assert loaded["sources"] == {
        "tree_sitter": "PARTIAL", "semgrep": "SUCCEEDED", "codeql": "SUCCEEDED", "history": "PARTIAL",
    }
    assert loaded["gaps"] == []          # the publish unit declares no gaps of its own
    gaps_joined = "\n".join(loaded["aggregated_gaps"])
    assert "unbound.java: semgrep_signal_not_bound_to_accepted_file" in gaps_joined
    assert "is not bound to accepted files" in gaps_joined
    assert "subrepo history decision SKIPPED_SHALLOW" in gaps_joined

    # Verify priority index contains semantic_path, flow steps, semgrep signal, suppression, and context file
    core = RetrievalCore(
        run_root.parent,
        run_root.name,
        manifest_path=run_root / pub["index_manifest"]["path"],
        manifest_sha256=pub["index_manifest"]["sha256"],
    )
    assert len(core.find(kind="review_flow_step", indexes=("priority",))["results"]) == 3
    assert core.find(kind="review_context_file", indexes=("priority",))["results"]
    assert core.search(query="suppression", indexes=("priority",), kinds=("review_signal",))["results"]

    # Loader rejects unsupported schema on accepted prioritization artifact
    bad_prio = _artifact_ref(run_root, run_root / "fixture" / "bad-prio.json", {"schema": "wrong/1"})
    _publish_handoff(run_root, JOB_ID, {"publish.publish_handoff": {"artifact": bad_prio}}, attempt_id="att_bad")
    with pytest.raises(ValueError, match="accepted review prioritization schema is unsupported"):
        load_accepted_prioritization(run_root)

    # History error branches: unsupported SII schema, overlapping signal paths, and all-unavailable history
    score_unit = next(u for u in built.units if u.unit_id == "prioritize.score")
    unit_map = {k: v for k, v in result["outputs"].items()}

    bad_sig = _artifact_ref(run_root, run_root / "fixture" / "bad-sig.json", {"schema": "wrong-sii/1"})
    bad_hist = _artifact_ref(run_root, run_root / "fixture" / "bad-hist.json", {
        "schema": "appsec-review/source-history-analysis/2", "decision": "SUCCEEDED",
        "binding": "exact", "ranking": {"signals": bad_sig},
    })
    _publish_handoff(run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": bad_hist}},
                     attempt_id="att_h2")
    u_ctx = SimpleNamespace(job=ctx, unit_id="prioritize.score",
                            unit_root=ctx.attempt_root / "steps" / "prioritize" / "tasks" / "score",
                            output=lambda uid: unit_map[uid])
    with pytest.raises(ValueError, match="unsupported SII schema"):
        score_unit.handler(u_ctx)

    dup_hist = _artifact_ref(run_root, run_root / "fixture" / "dup-hist.json", {
        "schema": "appsec-review/source-history-analysis/2", "decision": "SUCCEEDED",
        "sources": {"repositories": [{"artifact": repo1}, {"artifact": repo1}]},
    })
    _publish_handoff(run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": dup_hist}},
                     attempt_id="att_h3")
    with pytest.raises(ValueError, match="overlapping signal paths"):
        score_unit.handler(u_ctx)

    unavail_hist = _artifact_ref(run_root, run_root / "fixture" / "unavail-hist.json", {
        "schema": "appsec-review/source-history-analysis/2", "decision": "SKIPPED_NO_GIT", "ranking": {},
    })
    _publish_handoff(run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": unavail_hist}},
                     attempt_id="att_h4")
    score_unavail = score_unit.handler(u_ctx)
    assert score_unavail["history_status"] == "UNAVAILABLE"
    assert any("SKIPPED_NO_GIT" in g for g in score_unavail["gaps"])
    assert accepted_handoff(run_root, "job_source_history_analysis")[1]


def test_graph_builder_and_heuristic_extractor_branches() -> None:
    from appsec_review.jobs.job_review_prioritization.dependencies import GraphBuilder
    from appsec_review.jobs.job_review_prioritization.heuristics import Extractor
    from appsec_review.jobs.job_review_prioritization.languages import SPECS

    files = {
        "c/main.c": {
            "grammar": "c",
            "imports": [
                {"kind": "include", "specifier": "local.h", "line": 1},
                {"kind": "include", "specifier": "unique.h", "line": 2},
                {"kind": "include", "specifier": "dup.h", "line": 3},
                {"kind": "include", "specifier": "missing.h", "line": 4},
                {"kind": "system_include", "specifier": "stdio.h", "line": 5},
                {"kind": "include", "specifier": None, "dynamic": True, "line": 6},
            ],
        },
        "c/local.h": {"grammar": "c", "imports": []},
        "inc/unique.h": {"grammar": "c", "imports": []},
        "a/dup.h": {"grammar": "c", "imports": []},
        "b/dup.h": {"grammar": "c", "imports": []},
        "web/app.ts": {
            "grammar": "typescript",
            "imports": [
                {"kind": "esm_import", "specifier": "/web/mod", "line": 1},
                {"kind": "esm_import", "specifier": "./missing", "line": 2},
                {"kind": "esm_import", "specifier": "@/alias", "line": 3},
                {"kind": "esm_import", "specifier": "express", "line": 4},
            ],
        },
        "web/mod/index.ts": {"grammar": "typescript", "imports": []},
        "go/cmd/main.go": {
            "grammar": "go",
            "imports": [
                {"kind": "go_import", "specifier": "example.com/mod/pkg", "line": 1},
                {"kind": "go_import", "specifier": "example.com/mod/empty", "line": 2},
                {"kind": "go_import", "specifier": "github.com/pkg/errors", "line": 3},
                {"kind": "go_import", "specifier": "fmt", "line": 4},
            ],
        },
        "go/pkg/lib.go": {"grammar": "go", "imports": []},
        "java/App.java": {
            "grammar": "java",
            "declarations": {"package": "com.acme.web", "types": ["App"]},
            "imports": [
                {"kind": "java_import", "specifier": "com.acme.store.*", "line": 1},
                {"kind": "java_static_import", "specifier": "com.acme.store.Repo.find", "line": 2},
                {"kind": "java_import", "specifier": "com.acme.missing.Ghost", "line": 3},
                {"kind": "java_import", "specifier": "org.slf4j.Logger", "line": 4},
            ],
        },
        "java/Repo.java": {"grammar": "java", "declarations": {"package": "com.acme.store", "types": ["Repo"]}, "imports": []},
        "cs/Api.cs": {
            "grammar": "csharp",
            "declarations": {"namespaces": ["Acme.Web"]},
            "imports": [
                {"kind": "csharp_using", "specifier": "Acme.Core", "line": 1},
                {"kind": "csharp_using", "specifier": "System.Text", "line": 2},
            ],
        },
        "cs/Core.cs": {"grammar": "csharp", "declarations": {"namespaces": ["Acme.Core"]}, "imports": []},
        "php/index.php": {
            "grammar": "php",
            "declarations": {"package": "Acme\\Web", "types": ["Index"]},
            "imports": [
                {"kind": "php_include", "specifier": "/boot.php", "base": True, "line": 1},
                {"kind": "php_include", "specifier": "boot.php", "base": False, "line": 2},
                {"kind": "php_include", "specifier": "missing.php", "base": False, "line": 3},
                {"kind": "php_use", "specifier": "Acme\\Core\\Auth", "line": 4},
                {"kind": "php_use", "specifier": "Acme\\Missing\\Nope", "line": 5},
                {"kind": "php_use", "specifier": "Vendor\\Pkg\\Thing", "line": 6},
            ],
        },
        "php/boot.php": {"grammar": "php", "declarations": {"package": "Acme\\Core", "types": ["Auth"]}, "imports": []},
        "rb/app.rb": {
            "grammar": "ruby",
            "imports": [
                {"kind": "ruby_require", "specifier": "json", "line": 1},
                {"kind": "ruby_require_relative", "specifier": "helper", "line": 2},
                {"kind": "ruby_require_relative", "specifier": "missing", "line": 3},
            ],
        },
        "rb/helper.rb": {"grammar": "ruby", "imports": []},
        "crate/src/lib.rs": {
            "grammar": "rust",
            "imports": [
                {"kind": "rust_mod", "specifier": "sub", "line": 1},
                {"kind": "rust_mod", "specifier": "missing", "line": 2},
                {"kind": "rust_extern_crate", "specifier": "serde", "line": 3},
                {"kind": "unknown_kind", "specifier": "x", "line": 4},
            ],
        },
        "crate/src/sub/mod.rs": {
            "grammar": "rust",
            "imports": [
                {"kind": "rust_use", "specifier": "crate::leaf::run", "line": 1},
                {"kind": "rust_use", "specifier": "self::inner", "line": 2},
                {"kind": "rust_use", "specifier": "super::leaf", "line": 3},
                {"kind": "rust_use", "specifier": "super::super::nope", "line": 4},
                {"kind": "rust_use", "specifier": "crate::missing::item", "line": 5},
                {"kind": "rust_use", "specifier": "tokio::spawn", "line": 6},
            ],
        },
        "crate/src/sub/inner.rs": {"grammar": "rust", "imports": []},
        "crate/src/leaf.rs": {"grammar": "rust", "imports": []},
    }
    inventory = set(files) | {"go/go.mod", "crate/Cargo.toml"}
    gb = GraphBuilder(
        files,
        inventory,
        lambda p: b"module example.com/mod\n" if p.endswith("go.mod") else b"",
        min_confidence=0.5,
        max_records=100,
    )
    built_graph = gb.build({p: f"comp:{p.split('/')[0]}" for p in files})
    assert built_graph["edges"]
    gb_trunc = GraphBuilder(files, inventory, lambda _: b"", min_confidence=0.5, max_records=2)
    assert gb_trunc.build({})["truncated"] is True

    # Exercise synthetic AST heuristic branches (TS as-any / JSX / NODE_TLS / rejectUnauthorized, C# nullable/pragma,
    # PHP @ & superglobal, C header & pragma, Go cgo / InsecureSkipVerify / struct tags)
    def _row(ordinal_path: list[int], ntype: str, start: int, end: int, field: str | None = None,
             named: bool = True) -> dict[str, Any]:
        return {
            "grammar_native_type": ntype, "field": field, "named": named, "error": False, "missing": False,
            "location": {"producer_location": {"ordinal_path": ordinal_path}, "start_byte": start, "end_byte": end,
                         "start_line": 1, "end_line": 1, "start_column": start + 1, "end_column": end + 1},
        }

    settings = BASE_CONFIG.job(JOB_ID).settings
    tsx_src = b'dangerouslySetInnerHTML x as any process.env.NODE_TLS_REJECT_UNAUTHORIZED="0" "rejectUnauthorized":false'
    tsx_root, _ = build_tree([
        _row([], "program", 0, len(tsx_src)),
        _row([0], "jsx_attribute", 0, 23),
        _row([1], "as_expression", 24, 32),
        _row([1, 0], "identifier", 24, 25),
        _row([1, 1], "predefined_type", 29, 32),
        _row([2], "assignment_expression", 33, 77),
        _row([2, 0], "member_expression", 33, 73, field="left"),
        _row([2, 1], "string", 74, 77, field="right"),
        _row([3], "pair", 78, len(tsx_src)),
        _row([3, 0], "string", 78, 98, field="key"),
        _row([3, 1], "false", 99, len(tsx_src), field="value"),
    ])
    ex_tsx = Extractor(SourceFile("a.tsx", "0" * 64, "tsx", "TypeScript", tsx_src, tsx_root, 0),
                       SPECS["tsx"], [], (), settings)
    ex_tsx.run()
    tsx_rules = {s["rule_id"] for s in ex_tsx.signals}
    assert {"sink.html.dangerously-set", "privilege.insecure_verification.node-tls",
            "privilege.insecure_verification.rejectUnauthorized"} <= tsx_rules
    assert any(s["rule_id"] == "suppression.ts-as-any" for s in ex_tsx.suppressions)

    c_hdr_src = b"#pragma GCC diagnostic ignored \"-Wformat\"\nint parse(char *p);"
    c_root, _ = build_tree([
        _row([], "translation_unit", 0, len(c_hdr_src)),
        _row([0], "preproc_call", 0, 41),
        _row([1], "declaration", 42, len(c_hdr_src)),
        _row([1, 0], "function_declarator", 46, 60),
    ])
    ex_c = Extractor(SourceFile("inc/api.h", "0" * 64, "c", "C", c_hdr_src, c_root, 0),
                     SPECS["c"], [], (), settings)
    ex_c.run()
    assert any(s["rule_id"] == "api.header-declaration" for s in ex_c.signals)
    assert ex_c.suppressions

    from appsec_review.jobs.job_review_prioritization.complexity import function_units

    # Rust: inner/outer attributes, unsafe, extern C + call, pub fn w/ Json extractor, danger_accept_invalid_certs,
    # let-else, try_expression, match w/ guard, macro_invocation w/ return
    rs_src = (
        b'#![allow(warnings)] extern "C" { fn cfn(); } '
        b'#[allow(unsafe_code)] #[get("/u")] #[derive(Deserialize)] '
        b'pub fn run(Json(x): Json<T>) { unsafe {} cfn(); cli.danger_accept_invalid_certs(true); '
        b'let Some(v) = x else { return }; v?; match x { 1 if ok => 2, _ => 3 }; bail!(return); }'
    )
    i_fn = rs_src.index(b"pub fn run")
    i_vis = i_fn
    i_params = rs_src.index(b"(Json(x): Json<T>)")
    i_jtype = rs_src.index(b"Json<T>")
    i_unsafe = rs_src.index(b"unsafe {}")
    i_cfn_decl = rs_src.index(b'extern "C"')
    i_cfn_sig = rs_src.index(b"fn cfn()")
    i_cfn_name = rs_src.index(b"cfn")
    i_a1 = rs_src.index(b"#[allow(unsafe_code)]")
    i_a2 = rs_src.index(b'#[get("/u")]')
    i_a3 = rs_src.index(b"#[derive(Deserialize)]")
    i_cfn_call = rs_src.index(b"cfn();")
    i_danger = rs_src.index(b"cli.danger_accept_invalid_certs(true)")
    i_d_recv = i_danger
    i_d_field = rs_src.index(b"danger_accept_invalid_certs")
    i_d_args = rs_src.index(b"(true)")
    i_d_true = rs_src.index(b"true)")
    i_let = rs_src.index(b"let Some(v)")
    i_else = rs_src.index(b"else { return }")
    i_try = rs_src.index(b"v?")
    i_match = rs_src.index(b"match x")
    i_mbody = rs_src.index(b"{ 1 if ok => 2, _ => 3 }")
    i_arm1 = rs_src.index(b"1 if ok => 2")
    i_arm2 = rs_src.index(b"_ => 3")
    i_macro = rs_src.index(b"bail!(return)")
    i_ret_tok = rs_src.index(b"return);")
    rs_root, _ = build_tree([
        _row([], "source_file", 0, len(rs_src)),
        _row([0], "inner_attribute_item", 0, 19),
        _row([0, 0], "attribute", 3, 18),
        _row([1], "foreign_mod_item", i_cfn_decl, i_a1 - 1),
        _row([1, 0], "function_signature_item", i_cfn_sig, i_cfn_sig + 9),
        _row([1, 0, 0], "identifier", i_cfn_name, i_cfn_name + 3, field="name"),
        _row([2], "attribute_item", i_a1, i_a1 + 21),
        _row([2, 0], "attribute", i_a1 + 2, i_a1 + 20),
        _row([3], "attribute_item", i_a2, i_a2 + 12),
        _row([3, 0], "attribute", i_a2 + 2, i_a2 + 11),
        _row([4], "attribute_item", i_a3, i_a3 + 22),
        _row([4, 0], "attribute", i_a3 + 2, i_a3 + 21),
        _row([5], "function_item", i_fn, len(rs_src)),
        _row([5, 0], "visibility_modifier", i_vis, i_vis + 3),
        _row([5, 1], "identifier", i_fn + 7, i_fn + 10, field="name"),
        _row([5, 2], "parameters", i_params, i_params + 18, field="parameters"),
        _row([5, 2, 0], "parameter", i_params + 1, i_params + 17),
        _row([5, 2, 0, 0], "generic_type", i_jtype, i_jtype + 7, field="type"),
        _row([5, 3], "block", i_unsafe - 2, len(rs_src), field="body"),
        _row([5, 3, 0], "unsafe_block", i_unsafe, i_unsafe + 9),
        _row([5, 3, 1], "call_expression", i_cfn_call, i_cfn_call + 5),
        _row([5, 3, 1, 0], "identifier", i_cfn_call, i_cfn_call + 3, field="function"),
        _row([5, 3, 1, 1], "arguments", i_cfn_call + 3, i_cfn_call + 5, field="arguments"),
        _row([5, 3, 2], "call_expression", i_danger, i_danger + 37),
        _row([5, 3, 2, 0], "field_expression", i_d_recv, i_d_args, field="function"),
        _row([5, 3, 2, 0, 0], "identifier", i_d_recv, i_d_recv + 3, field="value"),
        _row([5, 3, 2, 0, 1], "field_identifier", i_d_field, i_d_args, field="field"),
        _row([5, 3, 2, 1], "arguments", i_d_args, i_d_args + 6, field="arguments"),
        _row([5, 3, 2, 1, 0], "boolean_literal", i_d_true, i_d_true + 4),
        _row([5, 3, 3], "let_declaration", i_let, i_else + 15),
        _row([5, 3, 3, 0], "block", i_else, i_else + 15, field="alternative"),
        _row([5, 3, 4], "try_expression", i_try, i_try + 2),
        _row([5, 3, 5], "match_expression", i_match, i_mbody + 24),
        _row([5, 3, 5, 0], "match_block", i_mbody, i_mbody + 24, field="body"),
        _row([5, 3, 5, 0, 0], "match_arm", i_arm1, i_arm1 + 12),
        _row([5, 3, 5, 0, 0, 0], "match_pattern", i_arm1, i_arm1 + 7),
        _row([5, 3, 5, 0, 0, 0, 0], "identifier", i_arm1 + 5, i_arm1 + 7, field="condition"),
        _row([5, 3, 5, 0, 1], "match_arm", i_arm2, i_arm2 + 6),
        _row([5, 3, 6], "macro_invocation", i_macro, i_macro + 13),
        _row([5, 3, 6, 0], "return", i_ret_tok, i_ret_tok + 6, named=False),
    ])
    rs_sf = SourceFile("src/lib.rs", "0" * 64, "rust", "Rust", rs_src, rs_root, 0)
    rs_units, _ = function_units(rs_sf, SPECS["rust"], count_error_propagation=True, limit=50)
    ex_rs = Extractor(rs_sf, SPECS["rust"], rs_units, (), settings)
    ex_rs.run()
    rs_rules = {s["rule_id"] for s in ex_rs.signals}
    assert {
        "annotation.route", "annotation.schema", "wrapper.ffi.extern-block", "wrapper.ffi.extern-call",
        "api.rust-pub", "ingress.rust-extractor", "privilege.insecure_verification.danger_accept_invalid_certs",
    } <= rs_rules
    assert rs_units[0]["error_propagation"]["rust_try_operator"] == 1
    assert rs_units[0]["unsupported_constructs"]["macro_control_flow_not_analyzed"] == 1

    # Java + C + C# + PHP + Go remaining branches
    jv_src = (
        b'@SuppressWarnings("all") @native @RequestMapping("/x") '
        b'public interface I {} '
        b'class C { public native void jni(); void f() { '
        b'c.setHostnameVerifier((h, s) -> true); c.setDefaultHostnameVerifier((h, s) -> { return true; }); '
        b'try { a ?? b; } catch (Exception e) { break outer; } } }'
    )
    i_ji = jv_src.index(b"public interface I")
    i_jni = jv_src.index(b"public native void jni()")
    i_jf = jv_src.index(b"void f()")
    i_hv1 = jv_src.index(b"c.setHostnameVerifier")
    i_hv1_lam = jv_src.index(b"(h, s) -> true")
    i_hv1_true = jv_src.index(b"true);")
    i_hv2 = jv_src.index(b"c.setDefaultHostnameVerifier")
    i_hv2_lam = jv_src.index(b"(h, s) -> { return true; }")
    i_hv2_blk = jv_src.index(b"{ return true; }")
    i_hv2_ret = jv_src.index(b"return true;")
    i_qq = jv_src.index(b"a ?? b")
    i_catch = jv_src.index(b"catch (Exception e)")
    i_brk = jv_src.index(b"break outer;")
    jv_root, _ = build_tree([
        _row([], "program", 0, len(jv_src)),
        _row([0], "annotation", 0, 24),
        _row([0, 0], "identifier", 1, 17, field="name"),
        _row([0, 1], "annotation_argument_list", 17, 24, field="arguments"),
        _row([1], "marker_annotation", 25, 32),
        _row([1, 0], "identifier", 26, 32, field="name"),
        _row([2], "annotation", 33, 54),
        _row([2, 0], "identifier", 34, 48, field="name"),
        _row([2, 1], "annotation_argument_list", 48, 54, field="arguments"),
        _row([3], "interface_declaration", i_ji, i_ji + 21),
        _row([3, 0], "modifiers", i_ji, i_ji + 6),
        _row([4], "class_declaration", i_jni - 10, len(jv_src)),
        _row([4, 0], "identifier", i_jni - 4, i_jni - 3, field="name"),
        _row([4, 1], "method_declaration", i_jni, i_jni + 24),
        _row([4, 1, 0], "modifiers", i_jni, i_jni + 13),
        _row([4, 1, 1], "identifier", i_jni + 19, i_jni + 22, field="name"),
        _row([4, 2], "method_declaration", i_jf, len(jv_src) - 2),
        _row([4, 2, 0], "identifier", i_jf + 5, i_jf + 6, field="name"),
        _row([4, 2, 1], "block", i_hv1 - 2, len(jv_src) - 2, field="body"),
        _row([4, 2, 1, 0], "method_invocation", i_hv1, i_hv1_true + 5),
        _row([4, 2, 1, 0, 0], "identifier", i_hv1, i_hv1 + 1, field="object"),
        _row([4, 2, 1, 0, 1], "identifier", i_hv1 + 2, i_hv1 + 21, field="name"),
        _row([4, 2, 1, 0, 2], "argument_list", i_hv1_lam - 1, i_hv1_true + 5, field="arguments"),
        _row([4, 2, 1, 0, 2, 0], "lambda_expression", i_hv1_lam, i_hv1_true + 4),
        _row([4, 2, 1, 0, 2, 0, 0], "true", i_hv1_true, i_hv1_true + 4, field="body"),
        _row([4, 2, 1, 1], "method_invocation", i_hv2, i_hv2_blk + 17),
        _row([4, 2, 1, 1, 0], "identifier", i_hv2, i_hv2 + 1, field="object"),
        _row([4, 2, 1, 1, 1], "identifier", i_hv2 + 2, i_hv2 + 28, field="name"),
        _row([4, 2, 1, 1, 2], "argument_list", i_hv2_lam - 1, i_hv2_blk + 17, field="arguments"),
        _row([4, 2, 1, 1, 2, 0], "lambda_expression", i_hv2_lam, i_hv2_blk + 16),
        _row([4, 2, 1, 1, 2, 0, 0], "block", i_hv2_blk, i_hv2_blk + 16, field="body"),
        _row([4, 2, 1, 1, 2, 0, 0, 0], "return_statement", i_hv2_ret, i_hv2_ret + 12),
        _row([4, 2, 1, 2], "binary_expression", i_qq, i_qq + 6),
        _row([4, 2, 1, 2, 0], "??", i_qq + 2, i_qq + 4, field="operator", named=False),
        _row([4, 2, 1, 3], "catch_clause", i_catch, i_brk + 14),
        _row([4, 2, 1, 3, 0], "break_statement", i_brk, i_brk + 12),
        _row([4, 2, 1, 3, 0, 0], "identifier", i_brk + 6, i_brk + 11),
    ])
    jv_sf = SourceFile("C.java", "0" * 64, "java", "Java", jv_src, jv_root, 0)
    jv_units, _ = function_units(jv_sf, SPECS["java"], count_error_propagation=True, limit=50)
    ex_jv = Extractor(jv_sf, SPECS["java"], jv_units, (), settings)
    ex_jv.run()
    jv_rules = {s["rule_id"] for s in ex_jv.signals}
    assert {
        "api.public-modifier", "wrapper.ffi.java-native",
        "privilege.insecure_verification.setHostnameVerifier",
        "privilege.insecure_verification.setDefaultHostnameVerifier",
    } <= jv_rules

    # C: goto, ternary, switch/case, curl_setopt, SSL_CTX_set_verify
    c2_src = (
        b"void f(int x) { switch(x){case 1: break; default: goto end;} "
        b"x ? f(1) : 0; curl_setopt(h, CURLOPT_SSL_VERIFYPEER, 0); SSL_CTX_set_verify(c, SSL_VERIFY_NONE, 0); end:; }"
    )
    i_sw = c2_src.index(b"switch(x)")
    i_c1 = c2_src.index(b"case 1:")
    i_def = c2_src.index(b"default:")
    i_goto = c2_src.index(b"goto end;")
    i_tern = c2_src.index(b"x ? f(1) : 0")
    i_rec = c2_src.index(b"f(1)")
    i_curl = c2_src.index(b"curl_setopt(h, CURLOPT_SSL_VERIFYPEER, 0)")
    i_ssl = c2_src.index(b"SSL_CTX_set_verify(c, SSL_VERIFY_NONE, 0)")
    c2_root, _ = build_tree([
        _row([], "translation_unit", 0, len(c2_src)),
        _row([0], "function_definition", 0, len(c2_src)),
        _row([0, 0], "function_declarator", 5, 13, field="declarator"),
        _row([0, 0, 0], "identifier", 5, 6, field="declarator"),
        _row([0, 1], "compound_statement", i_sw - 2, len(c2_src), field="body"),
        _row([0, 1, 0], "switch_statement", i_sw, i_goto + 10),
        _row([0, 1, 0, 0], "case_statement", i_c1, i_c1 + 14),
        _row([0, 1, 0, 0, 0], "number_literal", i_c1 + 5, i_c1 + 6, field="value"),
        _row([0, 1, 0, 1], "case_statement", i_def, i_goto + 9),
        _row([0, 1, 0, 1, 0], "goto_statement", i_goto, i_goto + 9),
        _row([0, 1, 1], "conditional_expression", i_tern, i_tern + 12),
        _row([0, 1, 1, 0], "call_expression", i_rec, i_rec + 4),
        _row([0, 1, 1, 0, 0], "identifier", i_rec, i_rec + 1, field="function"),
        _row([0, 1, 2], "call_expression", i_curl, i_curl + 41),
        _row([0, 1, 2, 0], "identifier", i_curl, i_curl + 11, field="function"),
        _row([0, 1, 2, 1], "argument_list", i_curl + 11, i_curl + 41, field="arguments"),
        _row([0, 1, 2, 1, 0], "identifier", i_curl + 12, i_curl + 13),
        _row([0, 1, 2, 1, 1], "identifier", i_curl + 15, i_curl + 37),
        _row([0, 1, 2, 1, 2], "number_literal", i_curl + 39, i_curl + 40),
        _row([0, 1, 3], "call_expression", i_ssl, i_ssl + 41),
        _row([0, 1, 3, 0], "identifier", i_ssl, i_ssl + 18, field="function"),
        _row([0, 1, 3, 1], "argument_list", i_ssl + 18, i_ssl + 41, field="arguments"),
        _row([0, 1, 3, 1, 0], "identifier", i_ssl + 19, i_ssl + 20),
        _row([0, 1, 3, 1, 1], "identifier", i_ssl + 22, i_ssl + 37),
        _row([0, 1, 3, 1, 2], "number_literal", i_ssl + 39, i_ssl + 40),
    ])
    c2_sf = SourceFile("net.c", "0" * 64, "c", "C", c2_src, c2_root, 0)
    c2_units, _ = function_units(c2_sf, SPECS["c"], count_error_propagation=True, limit=50)
    ex_c2 = Extractor(c2_sf, SPECS["c"], c2_units, (), settings)
    ex_c2.run()
    assert c2_units[0]["recursive"] is True
    assert {"privilege.insecure_verification.curl_setopt",
            "privilege.insecure_verification.SSL_CTX_set_verify"} <= {s["rule_id"] for s in ex_c2.signals}

    # C#, PHP, Go, and JS route/schema/suppression branches
    cs_src = (
        b"#pragma warning disable CS8600\n#pragma nullable disable\n#nullable disable\n"
        b"[AuthorizeAttribute] public interface IApi {} "
        b"h.ServerCertificateCustomValidationCallback = DangerousAcceptAnyServerCertificateValidator; Request.Query"
    )
    i_p1 = 0
    i_p2 = cs_src.index(b"#pragma nullable")
    i_p3 = cs_src.index(b"#nullable disable")
    i_attr = cs_src.index(b"[AuthorizeAttribute]")
    i_cs_if = cs_src.index(b"public interface IApi")
    i_cb = cs_src.index(b"h.ServerCertificateCustomValidationCallback")
    i_cb_r = cs_src.index(b"DangerousAcceptAnyServerCertificateValidator")
    i_rq = cs_src.index(b"Request.Query")
    cs_root, _ = build_tree([
        _row([], "compilation_unit", 0, len(cs_src)),
        _row([0], "preproc_pragma", i_p1, i_p2 - 1),
        _row([1], "preproc_pragma", i_p2, i_p3 - 1),
        _row([2], "nullable_directive", i_p3, i_attr - 1),
        _row([3], "attribute_list", i_attr, i_attr + 20),
        _row([3, 0], "attribute", i_attr + 1, i_attr + 19),
        _row([3, 0, 0], "identifier", i_attr + 1, i_attr + 19, field="name"),
        _row([4], "interface_declaration", i_cs_if, i_cs_if + 24),
        _row([4, 0], "modifier", i_cs_if, i_cs_if + 6),
        _row([5], "assignment_expression", i_cb, i_cb_r + 44),
        _row([5, 0], "member_access_expression", i_cb, i_cb + 43, field="left"),
        _row([5, 1], "identifier", i_cb_r, i_cb_r + 44, field="right"),
        _row([6], "member_access_expression", i_rq, len(cs_src)),
        _row([6, 0], "identifier", i_rq, i_rq + 7, field="expression"),
        _row([6, 1], "identifier", i_rq + 8, len(cs_src), field="name"),
    ])
    ex_cs = Extractor(SourceFile("Api.cs", "0" * 64, "csharp", "C#", cs_src, cs_root, 0),
                      SPECS["csharp"], [], (), settings)
    ex_cs.run()
    assert {"privilege.insecure_verification.certificate-callback", "ingress.request-property"} <= {
        s["rule_id"] for s in ex_cs.signals
    }
    assert len(ex_cs.suppressions) >= 3

    go_src = (
        b'package api\nimport "C"\ntype Req struct { A string `json:"a"` }\n'
        b'func Wrap(h http.Handler) http.Handler { InsecureSkipVerify: true; r.URL }'
    )
    i_gimp = go_src.index(b'"C"')
    i_gts = go_src.index(b"type Req")
    i_gst = go_src.index(b"struct {")
    i_gfd = go_src.index(b'A string `json:"a"`')
    i_gtag = go_src.index(b'`json:"a"`')
    i_gfn = go_src.index(b"func Wrap")
    i_gp = go_src.index(b"(h http.Handler)")
    i_gr = go_src.index(b") http.Handler") + 2
    i_gkv = go_src.index(b"InsecureSkipVerify: true")
    i_gsel = go_src.index(b"r.URL")
    go_root, _ = build_tree([
        _row([], "source_file", 0, len(go_src)),
        _row([0], "package_clause", 0, 11),
        _row([1], "import_spec", i_gimp, i_gimp + 3),
        _row([2], "type_spec", i_gts + 5, i_gfn - 1),
        _row([2, 0], "type_identifier", i_gts + 5, i_gts + 8, field="name"),
        _row([2, 1], "struct_type", i_gst, i_gfn - 1, field="type"),
        _row([2, 1, 0], "field_declaration", i_gfd, i_gtag + 10),
        _row([2, 1, 0, 0], "raw_string_literal", i_gtag, i_gtag + 10, field="tag"),
        _row([3], "function_declaration", i_gfn, len(go_src)),
        _row([3, 0], "identifier", i_gfn + 5, i_gfn + 9, field="name"),
        _row([3, 1], "parameter_list", i_gp, i_gp + 16, field="parameters"),
        _row([3, 2], "qualified_type", i_gr, i_gr + 12, field="result"),
        _row([3, 3], "block", i_gkv - 2, len(go_src), field="body"),
        _row([3, 3, 0], "keyed_element", i_gkv, i_gkv + 24),
        _row([3, 3, 0, 0], "identifier", i_gkv, i_gkv + 18, field="key"),
        _row([3, 3, 0, 1], "true", i_gkv + 20, i_gkv + 24, field="value"),
        _row([3, 3, 1], "selector_expression", i_gsel, i_gsel + 5),
        _row([3, 3, 1, 0], "identifier", i_gsel, i_gsel + 1, field="operand"),
        _row([3, 3, 1, 1], "field_identifier", i_gsel + 2, i_gsel + 5, field="field"),
    ])
    go_sf = SourceFile("api.go", "0" * 64, "go", "Go", go_src, go_root, 0)
    go_units, _ = function_units(go_sf, SPECS["go"], count_error_propagation=True, limit=50)
    ex_go = Extractor(go_sf, SPECS["go"], go_units, (), settings)
    ex_go.run()
    assert {
        "wrapper.ffi.cgo", "schema.go-struct-tags", "api.go-exported", "middleware.go-handler-wrapper",
        "privilege.insecure_verification.InsecureSkipVerify", "ingress.request-field",
    } <= {s["rule_id"] for s in ex_go.signals}

    # TypeScript decorator, export interface, routes, schemas, TLS, innerHTML, CommonJS, and request properties
    ts_src = (
        b'@Controller() export interface IUser {} '
        b'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; el.innerHTML = x; module.exports = fn; '
        b'({ rejectUnauthorized: false }); req.query; z.object({}); new Schema({}); '
        b'app.get("/users", () => { db.commit(); JSON.parse(s); }); app.post("/items", handlerRef); '
        b'other.get("/x"); app.get("relative");'
    )
    i_dec = 0
    i_exp = ts_src.index(b"export interface IUser {}")
    i_iface = ts_src.index(b"interface IUser {}")
    i_tls = ts_src.index(b'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"')
    i_tls_r = ts_src.index(b'"0"')
    i_html = ts_src.index(b"el.innerHTML = x")
    i_cjs = ts_src.index(b"module.exports = fn")
    i_pair = ts_src.index(b"rejectUnauthorized: false")
    i_req = ts_src.index(b"req.query")
    i_zod = ts_src.index(b"z.object({})")
    i_sch = ts_src.index(b"new Schema({})")
    i_rg1 = ts_src.index(b'app.get("/users", () => { db.commit(); JSON.parse(s); })')
    i_rg1_u = ts_src.index(b'"/users"')
    i_rg1_fn = ts_src.index(b"() => { db.commit(); JSON.parse(s); }")
    i_rg1_blk = ts_src.index(b"{ db.commit(); JSON.parse(s); }")
    i_rg1_cm = ts_src.index(b"db.commit()")
    i_rg1_jp = ts_src.index(b"JSON.parse(s)")
    i_rg2 = ts_src.index(b'app.post("/items", handlerRef)')
    i_rg2_u = ts_src.index(b'"/items"')
    i_rg2_h = ts_src.index(b"handlerRef")
    i_rg3 = ts_src.index(b'other.get("/x")')
    i_rg3_u = ts_src.index(b'"/x"')
    i_rg4 = ts_src.index(b'app.get("relative")')
    i_rg4_u = ts_src.index(b'"relative"')
    ts_root, _ = build_tree([
        _row([], "program", 0, len(ts_src)),
        _row([0], "decorator", i_dec, i_dec + 13),
        _row([0, 0], "call_expression", i_dec + 1, i_dec + 13),
        _row([0, 0, 0], "identifier", i_dec + 1, i_dec + 11, field="function"),
        _row([0, 0, 1], "arguments", i_dec + 11, i_dec + 13, field="arguments"),
        _row([1], "export_statement", i_exp, i_exp + 25),
        _row([1, 0], "interface_declaration", i_iface, i_exp + 25, field="declaration"),
        _row([2], "assignment_expression", i_tls, i_tls_r + 3),
        _row([2, 0], "member_expression", i_tls, i_tls + 40, field="left"),
        _row([2, 1], "string", i_tls_r, i_tls_r + 3, field="right"),
        _row([3], "assignment_expression", i_html, i_html + 16),
        _row([3, 0], "member_expression", i_html, i_html + 12, field="left"),
        _row([3, 1], "identifier", i_html + 15, i_html + 16, field="right"),
        _row([4], "assignment_expression", i_cjs, i_cjs + 19),
        _row([4, 0], "member_expression", i_cjs, i_cjs + 14, field="left"),
        _row([4, 1], "identifier", i_cjs + 17, i_cjs + 19, field="right"),
        _row([5], "pair", i_pair, i_pair + 25),
        _row([5, 0], "property_identifier", i_pair, i_pair + 18, field="key"),
        _row([5, 1], "false", i_pair + 20, i_pair + 25, field="value"),
        _row([6], "member_expression", i_req, i_req + 9),
        _row([6, 0], "identifier", i_req, i_req + 3, field="object"),
        _row([6, 1], "property_identifier", i_req + 4, i_req + 9, field="property"),
        _row([7], "call_expression", i_zod, i_zod + 12),
        _row([7, 0], "member_expression", i_zod, i_zod + 8, field="function"),
        _row([7, 0, 0], "identifier", i_zod, i_zod + 1, field="object"),
        _row([7, 0, 1], "property_identifier", i_zod + 2, i_zod + 8, field="property"),
        _row([7, 1], "arguments", i_zod + 8, i_zod + 12, field="arguments"),
        _row([8], "new_expression", i_sch, i_sch + 14),
        _row([8, 0], "identifier", i_sch + 4, i_sch + 10, field="constructor"),
        _row([8, 1], "arguments", i_sch + 10, i_sch + 14, field="arguments"),
        _row([9], "call_expression", i_rg1, i_rg1 + 56),
        _row([9, 0], "member_expression", i_rg1, i_rg1 + 7, field="function"),
        _row([9, 0, 0], "identifier", i_rg1, i_rg1 + 3, field="object"),
        _row([9, 0, 1], "property_identifier", i_rg1 + 4, i_rg1 + 7, field="property"),
        _row([9, 1], "arguments", i_rg1 + 7, i_rg1 + 56, field="arguments"),
        _row([9, 1, 0], "string", i_rg1_u, i_rg1_u + 8),
        _row([9, 1, 1], "arrow_function", i_rg1_fn, i_rg1_fn + 37),
        _row([9, 1, 1, 0], "statement_block", i_rg1_blk, i_rg1_fn + 37, field="body"),
        _row([9, 1, 1, 0, 0], "call_expression", i_rg1_cm, i_rg1_cm + 11),
        _row([9, 1, 1, 0, 0, 0], "member_expression", i_rg1_cm, i_rg1_cm + 9, field="function"),
        _row([9, 1, 1, 0, 0, 0, 0], "identifier", i_rg1_cm, i_rg1_cm + 2, field="object"),
        _row([9, 1, 1, 0, 0, 0, 1], "property_identifier", i_rg1_cm + 3, i_rg1_cm + 9, field="property"),
        _row([9, 1, 1, 0, 0, 1], "arguments", i_rg1_cm + 9, i_rg1_cm + 11, field="arguments"),
        _row([9, 1, 1, 0, 1], "call_expression", i_rg1_jp, i_rg1_jp + 13),
        _row([9, 1, 1, 0, 1, 0], "member_expression", i_rg1_jp, i_rg1_jp + 10, field="function"),
        _row([9, 1, 1, 0, 1, 0, 0], "identifier", i_rg1_jp, i_rg1_jp + 4, field="object"),
        _row([9, 1, 1, 0, 1, 0, 1], "property_identifier", i_rg1_jp + 5, i_rg1_jp + 10, field="property"),
        _row([9, 1, 1, 0, 1, 1], "arguments", i_rg1_jp + 10, i_rg1_jp + 13, field="arguments"),
        _row([10], "call_expression", i_rg2, i_rg2 + 30),
        _row([10, 0], "member_expression", i_rg2, i_rg2 + 8, field="function"),
        _row([10, 0, 0], "identifier", i_rg2, i_rg2 + 3, field="object"),
        _row([10, 0, 1], "property_identifier", i_rg2 + 4, i_rg2 + 8, field="property"),
        _row([10, 1], "arguments", i_rg2 + 8, i_rg2 + 30, field="arguments"),
        _row([10, 1, 0], "string", i_rg2_u, i_rg2_u + 8),
        _row([10, 1, 1], "identifier", i_rg2_h, i_rg2_h + 10),
        _row([11], "call_expression", i_rg3, i_rg3 + 15),
        _row([11, 0], "member_expression", i_rg3, i_rg3 + 9, field="function"),
        _row([11, 0, 0], "identifier", i_rg3, i_rg3 + 5, field="object"),
        _row([11, 0, 1], "property_identifier", i_rg3 + 6, i_rg3 + 9, field="property"),
        _row([11, 1], "arguments", i_rg3 + 9, i_rg3 + 15, field="arguments"),
        _row([11, 1, 0], "string", i_rg3_u, i_rg3_u + 4),
        _row([12], "call_expression", i_rg4, i_rg4 + 19),
        _row([12, 0], "member_expression", i_rg4, i_rg4 + 7, field="function"),
        _row([12, 0, 0], "identifier", i_rg4, i_rg4 + 3, field="object"),
        _row([12, 0, 1], "property_identifier", i_rg4 + 4, i_rg4 + 7, field="property"),
        _row([12, 1], "arguments", i_rg4 + 7, i_rg4 + 19, field="arguments"),
        _row([12, 1, 0], "string", i_rg4_u, i_rg4_u + 10),
    ])
    ts_sf = SourceFile("routes.ts", "0" * 64, "typescript", "TypeScript", ts_src, ts_root, 0)
    ts_units, _ = function_units(ts_sf, SPECS["typescript"], count_error_propagation=True, limit=50)
    ex_ts = Extractor(ts_sf, SPECS["typescript"], ts_units, (), settings)
    ex_ts.run()
    ts_rules = {s["rule_id"] for s in ex_ts.signals}
    assert {
        "api.esm-export", "privilege.insecure_verification.node-tls", "sink.html.inner-html",
        "api.commonjs-export", "privilege.insecure_verification.rejectUnauthorized",
        "ingress.request-property", "schema.validation-object", "schema.model",
        "route.registration", "route.handler", "route.handler-reference",
    } <= ts_rules




