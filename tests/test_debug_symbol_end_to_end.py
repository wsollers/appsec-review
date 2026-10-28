"""Genuine compiler artifacts through the real readers, publisher and retrieval."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import JOB_ID
from appsec_review.debug_symbols.readers import extract_symbols
from appsec_review.jobs.job_debug_symbol_indexing import build_job
from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
from appsec_review.retrieval import RetrievalCore
from tests.test_debug_symbol_indexing import RUN_ID, _seed, _shard
from tests.test_debug_symbol_readers import FIXTURES, fixture_runner, settings


@pytest.mark.parametrize("target,binary,debug,export,tool", [
    ("clang", "tiny.elf", None, "tiny.dwarf.txt", "llvm_dwarfdump"),
    ("msvc", "tiny.exe", "tiny.pdb", "tiny.pdb.yaml", "llvm_pdbutil"),
])
def test_real_formats_flow_through_default_enabled_job_with_telemetry(
        tmp_path, target, binary, debug, export, tool):
    reader_settings = settings(tmp_path, tool)
    context, artifacts, _ = _seed(
        tmp_path, target, debug=debug is not None, run_name=RUN_ID,
        binary_bytes=(FIXTURES / binary).read_bytes(),
        debug_bytes=(FIXTURES / debug).read_bytes() if debug else None,
        source_bytes=(FIXTURES / "tiny.c").read_bytes(),
        source_path="tests/fixtures/debug_symbols/tiny.c")
    config = replace(context.config, settings=parse_debug_symbol_settings({
        "compiler_target": target, "reader": reader_settings}))
    events = EventLog(context.attempt_root / "events.jsonl", PipelineLog(context.run_root), {
        "run_id": RUN_ID, "job_id": JOB_ID, "attempt_id": context.attempt_id})
    context = replace(context, config=config, events=events)
    calls = []

    def extractor(binary_path, debug_path, *, target, settings):
        calls.append(target)
        return extract_symbols(binary_path, debug_path, target=target, settings=settings,
                               runner=fixture_runner(export))

    result = build_job(extractor=extractor).execute(context)
    assert result["failed_units"] == []
    assert len(calls) == 1
    _, database = _shard(context, result)
    try:
        rows = [json.loads(row[0]) for row in database.execute(
            "SELECT payload_json FROM entities").fetchall()]
    finally:
        database.close()
    assert any(row["record_kind"] == "symbol" for row in rows)
    assert any(row["record_kind"] == "type_layout" and row.get("byte_size") == 16 for row in rows)
    assert any(row["record_kind"] == "source_range" and row.get("source_identity") for row in rows)
    assert all(row["artifact_identity"] == artifacts[0]["canonical_identity"] for row in rows)
    assert all(row["artifact_sha256"] == artifacts[0]["sha256"] for row in rows)

    manifest = result["outputs"]["acceptance.publish_handoff"]["index_manifest"]
    core = RetrievalCore(tmp_path, RUN_ID, manifest_sha256=manifest["sha256"],
                         manifest_path=context.run_root / manifest["path"])
    response = core.query_debug_symbols(mode="symbol", artifact=artifacts[0]["canonical_identity"])
    assert response["results"]
    metrics = aggregate_run_metrics(context.run_root)["debug_symbols"]
    assert metrics["compiler_target"] == target
    assert metrics["index"]["available"] is True
    assert metrics["index"]["record_count"] == len(rows)
    assert metrics["queries"]["count"] == 1
    assert metrics["queries"]["returned_count"] == len(response["results"])
