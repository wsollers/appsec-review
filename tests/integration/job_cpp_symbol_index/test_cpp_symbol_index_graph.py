"""Whole-graph integration tests for job_cpp_symbol_index over accepted C/C++ builds."""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.jobs.job_cpp_symbol_index import build_job as build_symbols
from appsec_review.retrieval.index import load_verified_manifest
from tests.test_cpp_index_jobs import IndexExecutor, _accepted_cpp, _outputs, _rows, _run


def test_symbol_index_publishes_accepted_symbols_with_complete_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    calls: list[str] = []
    outcome = _run(config, target, run_id, fingerprint,
                   build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls)))
    assert outcome["status"] == "SUCCEEDED" and calls == ["tool-clangd-indexer"]
    outputs = _outputs(outcome, "job_cpp_symbol_index")
    (scope,) = outputs["index.scopes"]["scopes"]
    assert scope["counts"]["symbols"] == 1 and scope["counts"]["external_symbols"] == 1
    assert scope["counts"]["processed_translation_units"] == scope["counts"]["translation_units"] == 1
    identity = scope["index_identity"]
    (entity,) = _rows(run_root, identity, "SELECT kind, native_id, name, payload_json FROM entities")
    assert entity[:3] == ("symbol", "AAAAAAAAAAAAAAA1", "main")
    payload = json.loads(entity[3])
    assert payload["definition"] == {"path": "native/main.cpp", "line": 1, "column": 5,
                                     "end_line": 1, "end_column": 9}
    (location,) = _rows(run_root, identity, "SELECT path, start_line, start_column, mapping_method FROM locations")
    assert location == ("native/main.cpp", 1, 5, "clangd-uri-exact-path")
    assert _rows(run_root, identity, "SELECT status FROM coverage") == [("complete",)]
    manifest = outputs["acceptance.publish_handoff"]["index_manifest"]
    document, _ = load_verified_manifest(run_root, run_root / manifest["path"], manifest["sha256"])
    producers = {item["producer"]["job"] for item in document["indexes"]}
    assert {"job_cpp_symbol_index", "job_cpp_compiled_analysis"} <= producers


def test_failed_clangd_run_is_scoped_unavailable_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    outcome = _run(config, target, run_id, fingerprint, build_symbols(
        executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [], clangd_exit=1)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    (scope,) = _outputs(outcome, "job_cpp_symbol_index")["index.scopes"]["scopes"]
    assert scope["counts"]["coverage"] == "unavailable" and scope["counts"]["symbols"] == 0
    assert "clangd-indexer exited with status 1" in scope["gaps"]
    assert _rows(run_root, scope["index_identity"], "SELECT status FROM coverage") == [("unavailable",)]


def test_rerun_reuses_verified_scope_checkpoints(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    calls: list[str] = []
    job = lambda: build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls))
    _run(config, target, run_id, fingerprint, job())
    outcome = _run(config, target, run_id, fingerprint, job(), force_from="job_cpp_symbol_index")
    (scope,) = _outputs(outcome, "job_cpp_symbol_index")["index.scopes"]["scopes"]
    assert calls == ["tool-clangd-indexer"] and scope["checkpoint_reused"] is True
