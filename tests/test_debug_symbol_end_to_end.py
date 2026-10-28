"""Genuine compiler artifacts through the real readers, publisher and retrieval."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from appsec_review.config.debug_symbols import parse_debug_symbol_settings
from appsec_review.debug_symbols.contract import JOB_ID
from appsec_review.debug_symbols.readers import extract_symbols
from appsec_review.jobs.job_debug_symbol_indexing import build_job
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.observability import EventLog, PipelineLog, aggregate_run_metrics
from appsec_review.retrieval import RetrievalCore
from tests.test_debug_symbol_indexing import RUN_ID, _seed, _shard
from tests.test_debug_symbol_readers import FIXTURES, fixture_runner, settings


def _index_fixture(tmp_path, target, binary, debug, export, tool, source="tiny.c"):
    reader_settings = settings(tmp_path, tool)
    context, artifacts, _ = _seed(
        tmp_path, target, debug=debug is not None, run_name=RUN_ID,
        binary_bytes=(FIXTURES / binary).read_bytes(),
        debug_bytes=(FIXTURES / debug).read_bytes() if debug else None,
        source_bytes=(FIXTURES / source).read_bytes(),
        source_path="tests/fixtures/debug_symbols/" + source)
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
    return context, artifacts, result


@pytest.mark.parametrize("target,binary,debug,export,tool", [
    ("clang", "tiny.elf", None, "tiny.dwarf.txt", "llvm_dwarfdump"),
    ("msvc", "tiny.exe", "tiny.pdb", "tiny.pdb.yaml", "llvm_pdbutil"),
    ("msvc", "msvc-tiny.exe", "msvc-tiny.pdb", "msvc-tiny.pdb.yaml", "llvm_pdbutil"),
])
def test_real_formats_flow_through_default_enabled_job_with_telemetry(
        tmp_path, target, binary, debug, export, tool):
    context, artifacts, result = _index_fixture(tmp_path, target, binary, debug, export, tool)
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
    assert "/work/" not in json.dumps(rows)

    manifest = result["outputs"]["acceptance.publish_handoff"]["index_manifest"]
    core = RetrievalCore(tmp_path, RUN_ID, manifest_sha256=manifest["sha256"],
                         manifest_path=context.run_root / manifest["path"])
    response = core.query_debug_symbols(mode="symbol", artifact_identity=artifacts[0]["canonical_identity"])
    assert response["results"]
    responses = [response]
    mcp = RetrievalMcpAdapter(core).call("query_debug_symbols", {
        "mode": "symbol", "artifact_identity": artifacts[0]["canonical_identity"]})
    assert mcp["results"] == response["results"]
    responses.append(mcp)
    artifact_identity = artifacts[0]["canonical_identity"]
    symbol = next(row for row in response["results"] if row["payload"]["address_ranges"])
    address = symbol["payload"]["address_ranges"][0]["start"]
    addresses = core.query_debug_symbols(
        mode="address", artifact_identity=artifact_identity, address=address)
    assert any(row["identity"] == symbol["identity"] for row in addresses["results"])
    responses.append(addresses)
    layouts = core.query_debug_symbols(mode="type_layout", artifact_identity=artifact_identity)
    assert any(row["payload"].get("byte_size") == 16 for row in layouts["results"])
    responses.append(layouts)
    source_identity = next(row["source_identity"] for row in rows if row.get("source_identity"))
    sources = core.query_debug_symbols(
        mode="source_ranges", artifact_identity=artifact_identity, subject=source_identity)
    assert sources["results"]
    assert all(row["payload"]["source_identity"] == source_identity for row in sources["results"])
    responses.append(sources)
    units = core.query_debug_symbols(mode="compilation_units", artifact_identity=artifact_identity)
    assert units["results"]
    responses.append(units)
    coverage = core.query_debug_symbols(mode="coverage", artifact_identity=artifact_identity)
    assert coverage["results"]
    responses.append(coverage)
    links = core.query_debug_symbols(
        mode="graph_links", artifact_identity=artifact_identity, subject=symbol["identity"])
    assert not any(row.get("graph_links") for row in links["results"])
    responses.append(links)
    inline = core.query_debug_symbols(
        mode="inline_frames", artifact_identity=artifact_identity, subject=symbol["identity"])
    assert inline["results"] == []
    responses.append(inline)
    metrics = aggregate_run_metrics(context.run_root)["debug_symbols"]
    assert metrics["compiler_target"] == target
    assert metrics["index"]["available"] is True
    assert metrics["index"]["record_count"] == len(rows)
    assert metrics["queries"]["count"] == 9
    assert metrics["queries"]["returned_count"] == sum(len(item["results"]) for item in responses)


@pytest.mark.parametrize("target,binary,debug,export,tool", [
    ("clang", "inline.elf", None, "inline.dwarf.txt", "llvm_dwarfdump"),
    ("msvc", "inline.exe", "inline.pdb", "inline.pdb.yaml", "llvm_pdbutil"),
    ("msvc", "msvc-inline.exe", "msvc-inline.pdb", "msvc-inline.pdb.yaml", "llvm_pdbutil"),
])
def test_genuine_inline_ranges_survive_publication_and_address_queries(
        tmp_path, target, binary, debug, export, tool):
    context, artifacts, result = _index_fixture(
        tmp_path, target, binary, debug, export, tool, source="inline.c")
    manifest = result["outputs"]["acceptance.publish_handoff"]["index_manifest"]
    core = RetrievalCore(tmp_path, RUN_ID, manifest_sha256=manifest["sha256"],
                         manifest_path=context.run_root / manifest["path"])
    artifact = artifacts[0]["canonical_identity"]
    frames = core.query_debug_symbols(mode="inline_frames", artifact_identity=artifact)
    frame = next(row for row in frames["results"] if row["name"] == "add"
                 and row["payload"]["address_ranges"])
    interval = frame["payload"]["address_ranges"][0]
    for address in (interval["start"], interval["end"] - 1):
        response = core.query_debug_symbols(mode="address", artifact_identity=artifact, address=address)
        assert any(row["identity"] == frame["identity"] for row in response["results"])
    excluded = core.query_debug_symbols(
        mode="address", artifact_identity=artifact, address=interval["end"])
    assert not any(row["identity"] == frame["identity"] for row in excluded["results"])
    mcp = RetrievalMcpAdapter(core).call("query_debug_symbols", {
        "mode": "inline_frames", "artifact_identity": artifact})
    assert mcp["results"] == frames["results"]
    metrics = aggregate_run_metrics(context.run_root)["debug_symbols"]
    assert metrics["compiler_target"] == target
    assert metrics["queries"]["count"] == 5
