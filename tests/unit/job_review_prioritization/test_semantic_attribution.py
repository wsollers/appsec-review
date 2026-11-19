"""T-5179: source-bound semantic positions cannot jump to a later same-line function."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_review_prioritization import build_job
from appsec_review.jobs.job_review_prioritization.inputs import read_json
from appsec_review.jobs.job_review_prioritization.job import _innermost
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.storage import file_sha256
from tests.unit.job_review_prioritization.test_contract import (
    _artifact_ref, _job_context, _publish_handoff, _seed_upstream_run,
)
from tests.unit.job_review_prioritization.test_signals_and_rewiring import _sources


@pytest.mark.parametrize("coordinates", ["columns", "bytes", "line-only", "out-of-range"])
def test_same_line_semantic_producer_keeps_exact_owners(tmp_path: Path, coordinates: str) -> None:
    data = b"void a(){ foo(); } void b(){ bar(); }\n"
    target = tmp_path / "target"
    target.mkdir()
    (target / "same.c").write_bytes(data)
    sha = file_sha256(target / "same.c")
    run, target, snapshot, pins = _seed_upstream_run(
        tmp_path, golden_paths=(), extra_catalog_files=[{
            "path": "same.c", "sha256": sha, "size_bytes": len(data), "language": "C",
            "generated": False, "delivery_role": "production", "first_party": True, "vendored": False}])
    positions = [data.index(b"foo"), data.index(b"bar")]
    units = [
        {"function_id": "a", "start_line": 1, "end_line": 1, "start_byte": 0,
         "end_byte": data.index(b" void b")},
        {"function_id": "b", "start_line": 1, "end_line": 1, "start_byte": data.index(b"void b"),
         "end_byte": len(data) - 1},
    ]
    locations = []
    for position in positions:
        extra = ({"start_column": position + 1, "end_column": position + 4} if coordinates == "columns"
                 else {"start_byte": position, "end_byte": position + 3} if coordinates == "bytes"
                 else {"start_column": 999, "end_column": 1000} if coordinates == "out-of-range" else {})
        locations.append({"path": "same.c", "source_sha256": sha, "file_sha256": sha,
                          "start_line": 1, "end_line": 1, **extra})
    for producer, shard_id in (("job_evidence_collection", "sg"), ("job_codeql_analysis", "cq")):
        shard = run / f"data/indices/observations/{shard_id}.sqlite"
        builder = IndexBuilder(shard, name="observations", fingerprint=sha,
                               target_snapshot=snapshot, shard_id=shard_id)
        if shard_id == "sg":
            for number, location in enumerate(locations):
                identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"sg": number})
                builder.add_entity(EntityRecord(identity, str(number), "sg", "sg", {
                    "native_rule_id": "appsec-review.review-signal.sink.exec", "location": location}, None))
        else:
            identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"cq": 1})
            builder.add_entity(EntityRecord(identity, "cq", "cq", "cq", {
                "rule_id": "cpp/test", "query_identity": "q", "language": "cpp",
                "flows": [{"ordinal": number, "code_flow": 0, "thread_flow": 0, "location": location}
                          for number, location in enumerate(locations)]}, None))
        builder.build()
        manifest = run / f"fixture/{shard_id}-manifest.json"
        write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=[
            IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(shard), sha,
                          shard.relative_to(run).as_posix(), {"job": producer, "producer": "tool-semgrep"},
                          (), shard_id)])
        document = ({"dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}]}
                    if shard_id == "sg" else {"scopes": [{
                        "scope_id": "c", "language": "cpp", "root": ".", "query_profile": "security",
                        "terminal_status": "SUCCEEDED", "gaps": []}]})
        out = "evidence_publication.publish_handoff" if shard_id == "sg" else "acceptance.publish_handoff"
        pins[producer] = _publish_handoff(run, producer, {out: {
            "artifact": _artifact_ref(run, run / f"fixture/{shard_id}.json", document),
            "index_manifest": _artifact_ref(run, manifest)}})
    job = build_job()
    context = _job_context(tmp_path, run, target, snapshot, pins,
                           settings_override={"sources": _sources("semgrep", "codeql")})
    outputs = {}
    # Accepted syntax facts are inert upstream inputs to the real semantic handler.
    outputs["extract.syntax_metrics"] = {"artifact": _artifact_ref(
        run, run / "fixture/syntax.json", {"files": {"same.c": {
            "language": "C", "sha256": sha, "units": units}}})}
    for name in ("load.accepted_inputs", "extract.semantic_evidence"):
        unit = next(unit for unit in job.units if unit.unit_id == name)
        unit_context = SimpleNamespace(job=context, unit_id=name, output=outputs.__getitem__,
                                       unit_root=context.attempt_root / "steps" / name)
        outputs[name] = unit.handler(unit_context)
    result = outputs["extract.semantic_evidence"]
    semantic = read_json(run, result["artifact"])
    assert len(semantic["semgrep_signals"]) == 2 and len(semantic["semantic_paths"]) == 1
    signals = sorted(semantic["semgrep_signals"], key=lambda item: item.get("start_byte") or
                     item.get("start_column") or item["observation"])
    path = semantic["semantic_paths"][0]
    if coordinates in {"columns", "bytes"}:
        assert [item["function_id"] for item in signals] == ["a", "b"]
        assert path["source_function"] == "a" and path["sink_function"] == "b"
        assert path["flow_functions"] == ["a", "b"]
        assert not any("attribution_unavailable" in gap for gap in result["gaps"])
    else:
        assert all(item["function_id"] is None for item in signals)
        assert path["source_function"] is None and path["sink_function"] is None
        assert path["flow_functions"] == []
        assert any("attribution_unavailable" in gap for gap in result["gaps"])
    assert len({item["signal_id"] for item in signals}) == 2


def test_exact_position_handles_nested_spans_unicode_and_exclusive_end() -> None:
    source = b"/*\xc3\xa9*/ outer inner end"
    outer, inner = source.index(b"outer"), source.index(b"inner")
    units = [
        {"function_id": "outer", "start_line": 1, "end_line": 1, "start_byte": outer, "end_byte": len(source)},
        {"function_id": "inner", "start_line": 1, "end_line": 1, "start_byte": inner, "end_byte": inner + 5},
    ]
    assert _innermost(units, 1, source=source, start_byte=outer) == "outer"
    assert _innermost(units, 1, source=source, start_byte=inner) == "inner"
    assert _innermost(units, 1, source=source, start_byte=inner + 5) == "outer"
    assert _innermost(units, 1, source=source, start_column=inner + 1) is None
    assert _innermost(units, 1, source=source) is None
    assert _innermost(units, 1, source=source, start_byte=len(source)) is None
