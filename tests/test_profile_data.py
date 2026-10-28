from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.engineering_contracts import PROFILE_DATA_HANDOFF_SCHEMA
from appsec_review.jobs.job_profile_data import (
    ProfileBounds, build_job, detect_profile_format, ingest_profile_artifacts,
    load_accepted_profile_data, parse_profile,
)
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.storage import atomic_json, file_sha256


def test_parses_folded_stacks_and_bounds_frames() -> None:
    document = parse_profile(b"root;dispatch;hot 9\nroot;dispatch;cold 2\n", "folded-stacks",
                             max_frames_per_sample=2)
    values = {(row.symbol, row.count) for row in document.rows}
    assert values == {("dispatch", 11), ("hot", 9), ("cold", 2)}
    assert any("frame_truncation" in gap for gap in document.gaps)


def test_parses_perf_script_events_modules_and_unknown_as_gap() -> None:
    document = parse_profile(b"""worker 123/124 [001] 42.5: cycles:
    7fff hot_fn+0x2 (libdemo.so)
    7ffe [unknown] ([unknown])

worker 123/124 [001] 42.6: cycles:
    7fff hot_fn+0x2 (libdemo.so)
""", "perf-script")
    assert [(row.symbol, row.count, row.event, row.module) for row in document.rows] == [
        ("hot_fn+0x2", 2, "cycles", "libdemo.so")]
    assert any("ambiguous_symbol" in gap for gap in document.gaps)


def test_parses_callgrind_event_costs_with_source_and_line() -> None:
    document = parse_profile(b"""version: 1
events: Ir Dr
fl=src/main.c
fn=handle
12 80 4
13 20 1
""", "callgrind")
    values = {(row.event, row.line): row.count for row in document.rows}
    assert values == {("Ir", 12): 80, ("Dr", 12): 4, ("Ir", 13): 20, ("Dr", 13): 1}
    assert {row.source for row in document.rows} == {"src/main.c"}


def test_parses_callgrind_references_and_relative_positions() -> None:
    document = parse_profile(b"""events: Ir
fl=(1) src/main.c
fn=(1) hot
12 5
+1 4
fl=(1)
fn=(1)
* 3
""", "callgrind")
    values = {(row.symbol, row.source, row.line): row.count for row in document.rows}
    assert values == {
        ("hot", "src/main.c", 12): 5,
        ("hot", "src/main.c", 13): 7,
    }


def test_parses_callgrind_call_cost_against_callee() -> None:
    document = parse_profile(b"""events: Ir
fl=src/caller.c
fn=caller
cfl=src/callee.c
cfn=callee
calls=3 9
12 30
""", "callgrind")
    assert [(row.symbol, row.source, row.count) for row in document.rows] == [
        ("callee", "src/callee.c", 30)]


def test_parses_llvm_sample_profile_function_headers_only() -> None:
    document = parse_profile(b"""ns::hot:120:4
 1: 100
 2.1: callee:20
cold:3:0
""", "llvm-sample")
    assert [(row.symbol, row.count) for row in document.rows] == [("cold", 3), ("ns::hot", 120)]


def test_parsers_reject_binary_empty_and_malformed_input() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        parse_profile(b"x", "pickle")
    with pytest.raises(ValueError, match="NUL"):
        parse_profile(b"a\x00b", "folded-stacks")
    with pytest.raises(ValueError, match="invalid folded-stack"):
        parse_profile(b"root;bad nope\n", "folded-stacks")
    with pytest.raises(ValueError, match="no event costs"):
        parse_profile(b"events: Ir\nfn=f\n", "callgrind")


@pytest.mark.parametrize(("name", "expected"), [
    ("gmon.out", "gmon"), ("cpu.pprof", "pprof"),
    ("default.profraw", "LLVM raw"), ("merged.profdata", "LLVM indexed"),
])
def test_opaque_formats_are_recognized_as_explicit_unsupported_gaps(name: str, expected: str) -> None:
    format_name, gap = detect_profile_format(name, b"opaque")
    assert format_name is None and gap is not None and expected in gap


def _artifact(run_root: Path, relative: str, data: bytes, *, origin: str = "build-output",
              profile_format: str | None = None) -> dict:
    path = run_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    value = {"path": relative, "workspace_path": Path(relative).name, "sha256": file_sha256(path),
             "size_bytes": len(data), "kind": "execution-profile", "artifact_origin": origin}
    if profile_format:
        value["profile_format"] = profile_format
    return value


def test_ingestion_ranks_rows_and_preserves_report_identity_origin_and_semantics(tmp_path: Path) -> None:
    folded = _artifact(tmp_path, "data/build/u/profile/app.folded", b"root;hot 30\nroot;cold 2\n",
                       origin="accepted-input")
    callgrind = _artifact(tmp_path, "data/build/u/profile/callgrind.out", b"events: Ir\nfn=middle\n1 10\n")
    output = ingest_profile_artifacts(tmp_path, [{
        "build_unit_id": "u", "family": "native", "root": ".", "terminal_status": "SUCCEEDED",
        "artifacts": [folded, callgrind],
    }])
    unit = output["units"][0]
    ranked = sorted(unit["rows"], key=lambda row: row["hotness_rank"])
    assert [(row["symbol"], row["count"]) for row in ranked] == [
        ("root", 32), ("hot", 30), ("middle", 10), ("cold", 2)]
    assert ranked[0]["semantics"] == "context_only"
    assert ranked[0]["is_finding"] is False and ranked[0]["defect_probability"] is None
    hot = next(row for row in ranked if row["symbol"] == "hot")
    assert hot["report_sha256"] == folded["sha256"]
    assert hot["report_format"] == "folded-stacks" and hot["artifact_origin"] == "accepted-input"


def test_ingestion_records_absent_unsupported_malformed_and_truncated_gaps(tmp_path: Path) -> None:
    opaque = _artifact(tmp_path, "data/build/u/gmon.out", b"opaque")
    malformed = _artifact(tmp_path, "data/build/u/bad.folded", b"no-count\n")
    long = _artifact(tmp_path, "data/build/u/long.folded", b"a 1\nb 2\n", profile_format="folded-stacks")
    output = ingest_profile_artifacts(tmp_path, [
        {"build_unit_id": "u", "family": "native", "artifacts": [opaque, malformed, long]},
        {"build_unit_id": "empty", "family": "java", "artifacts": []},
    ], bounds=ProfileBounds(max_rows_per_artifact=1))
    gaps = "\n".join(output["gaps"])
    assert "unsupported_profile_format" in gaps
    assert "malformed_profile" in gaps
    assert "row_truncation" in gaps
    assert "missing_profile_data" in gaps


def test_ingestion_fails_on_changed_hash_and_invalid_origin(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, "data/build/u/a.folded", b"a 1\n")
    artifact["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="identity changed"):
        ingest_profile_artifacts(tmp_path, [{"build_unit_id": "u", "artifacts": [artifact]}])
    artifact = _artifact(tmp_path, "data/build/u/b.folded", b"b 1\n", origin="unknown")
    with pytest.raises(ValueError, match="invalid artifact origin"):
        ingest_profile_artifacts(tmp_path, [{"build_unit_id": "u", "artifacts": [artifact]}])


def test_job_contract_is_generic_and_declares_profile_datasets() -> None:
    job = build_job()
    assert job.job_id == "job_profile_data" and job.name == "profile_data"
    assert job.consumes == ("job_target_catalog", "job_language_build", "job_artifact_indexing")
    assert [unit.unit_id for unit in job.units] == [
        "load.accepted_inputs", "normalize.profile_data", "index.profile_data", "acceptance.publish_handoff"]
    assert {item.output_kind for item in job.datasets} == {"profile_data", "profile_data_handoff"}


def _identity(run_root: Path, path: Path) -> dict:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def test_accepted_publication_verifies_handoff_artifact_manifest_and_semantics(tmp_path: Path) -> None:
    snapshot = "snapshot"
    shard = tmp_path / "data/indices/analysis/profile.sqlite"
    builder = IndexBuilder(shard, name="analysis", fingerprint="f" * 64,
                           target_snapshot=snapshot, shard_id="profile-data-u")
    builder.add_coverage("profile-data:u", "complete")
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", builder.build(), "f" * 64,
                          shard.relative_to(tmp_path).as_posix(), {"job": "job_profile_data"}, (), "profile-data-u")
    manifest = tmp_path / "data/indices/manifests/profile.json"
    write_manifest(manifest, run_id="run", target_snapshot=snapshot, target_root=tmp_path, indexes=(index,))
    attempt = tmp_path / "data/jobs/job_profile_data/attempts/attempt_0001"
    summary = attempt / "artifacts/profile-data/accepted-profile-data.json"
    summary.parent.mkdir(parents=True)
    atomic_json(summary, {"schema": PROFILE_DATA_HANDOFF_SCHEMA, "source_fingerprint": snapshot,
                          "semantics": "context_only", "build_units": [], "gaps": [],
                          "index_manifest": _identity(tmp_path, manifest)})
    summary_identity, manifest_identity = _identity(tmp_path, summary), _identity(tmp_path, manifest)
    handoff = attempt / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(tmp_path, handoff, {"source_fingerprint": snapshot, "status": "ACCEPTED",
                          "job_id": "job_profile_data", "attempt_id": "attempt_0001",
                          "outputs": {"acceptance.publish_handoff": {
                              "artifact": summary_identity, "index_manifest": manifest_identity}},
                          "artifacts": [summary_identity, manifest_identity]})
    latest = tmp_path / "data/jobs/job_profile_data/latest.json"
    atomic_json(latest, {"handoff_path": handoff.relative_to(tmp_path).as_posix(),
                         "handoff_sha256": file_sha256(handoff)})
    assert load_accepted_profile_data(tmp_path)["handoff_sha256"] == file_sha256(handoff)
    summary.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="identity changed"):
        load_accepted_profile_data(tmp_path)
