"""Accepted coverage/profile producer lifecycles; external builds are recorded fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.jobs.job_artifact_indexing import build_job as artifact_job
from appsec_review.jobs.job_profile_data import build_job as profile_job, load_accepted_profile_data
from appsec_review.jobs.job_test_coverage import build_job as coverage_job, load_accepted_test_coverage
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.validation import validation_scope
from tests.test_artifact_indexing import RUN_ID, _identity, _publish_changed_language_receipts, _seed


REPORTS = {
    "coverage/lcov.info": b"SF:src/main.c\nDA:1,1\nDA:2,0\nend_of_record\n",
    "coverage/cobertura.xml": (
        b'<coverage><packages><package><classes><class filename="src/main.c"><lines>'
        b'<line number="1" hits="1"/><line number="2" hits="0"/>'
        b"</lines></class></classes></package></packages></coverage>"),
    "coverage/jacoco.xml": (
        b'<report name="tiny"><package name="src"><class name="src/main" sourcefilename="main.c"/>'
        b'<sourcefile name="main.c"><counter type="LINE" missed="1" covered="1"/>'
        b"</sourcefile></package></report>"),
    "coverage/llvm.json": json.dumps({
        "type": "llvm.coverage.json.export", "version": "2.0.1",
        "data": [{"files": [{"filename": "src/main.c",
                            "summary": {"lines": {"count": 2, "covered": 1}}}]}],
    }).encode(),
    "profiles/hot.folded": b"main;hot 9\nmain;cold 1\n",
}


def _prepare(workspace: LaneWorkspace):
    base = workspace.root / "fixture"
    base.mkdir()
    config, target, snapshot, run_root, receipts, accepted, handoff, latest = _seed(
        base, source_files={"src/main.c": "int hot(void) { return 1; }\nint main(void) { return hot(); }\n"},
        build_families=("native", "dotnet"))
    assert config.runtime.runs_dir.is_relative_to(workspace.root)
    receipt = receipts[0]
    build_root = run_root / receipt["workspace"]
    manifest_path = run_root / receipt["workspace_manifest"]["path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for relative, data in REPORTS.items():
        path = build_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest["files"][relative] = file_sha256(path)
        receipt["artifacts"].append({
            **_identity(run_root, path), "workspace_path": relative,
            "kind": "execution-profile" if relative.startswith("profiles/") else "test-coverage",
            "artifact_origin": "build-output", "build_unit_id": receipt["build_unit_id"],
            "mapping": "exact-workspace-path", "mapping_confidence": 1.0,
        })
    atomic_json(manifest_path, manifest)
    receipt["workspace_manifest"] = _identity(run_root, manifest_path)
    _publish_changed_language_receipts(run_root, receipts, accepted, handoff, latest)
    GraphRunner(config, [artifact_job()]).run(
        run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
    return config, target, snapshot, run_root


def _entities(run_root: Path, document, kind: str):
    manifest = json.loads((run_root / document["index_manifest"]["path"]).read_text(encoding="utf-8"))
    rows = []
    for shard in manifest["indexes"]:
        if shard["name"] != "analysis":
            continue
        with sqlite3.connect(f"file:{(run_root / shard['relative_path']).as_posix()}?mode=ro", uri=True) as db:
            rows.extend(json.loads(row[0]) for row in db.execute(
                "SELECT payload_json FROM entities WHERE kind = ?", (kind,)))
    return rows


def test_full_signal_jobs_preserve_report_source_and_context_semantics(acceptance_workspace: LaneWorkspace) -> None:
    workspace = LaneWorkspace.create(acceptance_workspace.root, "signal-jobs")
    started = time.monotonic()
    with workspace.span("acceptance.signal_jobs"):
        config, target, snapshot, run_root = _prepare(workspace)
        result = GraphRunner(config, [coverage_job(), profile_job()]).run(
            run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
        assert result["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
        with validation_scope(run_root):
            coverage = load_accepted_test_coverage(run_root)
            profile = load_accepted_profile_data(run_root)
        populated = next(unit for unit in coverage["build_units"] if unit["files"])
        assert {row["format"] for row in populated["artifacts"]} == {"lcov", "cobertura", "jacoco", "llvm"}
        assert len(populated["files"]) == 4
        source_hash = file_sha256(target / "src" / "main.c")
        assert all(row["path"] == "src/main.c" and row["file_sha256"] == source_hash
                   for row in populated["files"])
        indexed = [row for row in _entities(run_root, coverage, "coverage_cell") if "path" in row]
        assert len(indexed) == 4
        assert {row["artifact_sha256"] for row in indexed} == {
            row["artifact_sha256"] for row in populated["files"]}
        hotspots = _entities(run_root, profile, "hotspot")
        assert {row["symbol"]: row["count"] for row in hotspots} == {"main": 10, "hot": 9, "cold": 1}
        assert all(row["semantics"] == "context_only" and row["is_finding"] is False for row in hotspots)
        assert profile["gaps"] and coverage["gaps"]
        events = run_root / "data" / "logs" / "pipeline.jsonl"
        assert events.is_file() and events.is_relative_to(workspace.root)
    elapsed = time.monotonic() - started
    workspace.emit("ACCEPTANCE_CASE_COMPLETED", duration_ms=elapsed * 1000, outcome="passed",
                   fixture_runs_dir=str(config.runtime.runs_dir))
    assert elapsed < 120, f"signal job lane exceeded 120 seconds: {elapsed:.3f}s; {workspace.root}"


def test_changed_profile_cannot_publish_an_accepted_signal(acceptance_workspace: LaneWorkspace) -> None:
    workspace = LaneWorkspace.create(acceptance_workspace.root, "signal-integrity")
    started = time.monotonic()
    with workspace.span("acceptance.signal_integrity"):
        config, target, snapshot, run_root = _prepare(workspace)
        language_pointer = json.loads((
            run_root / "data" / "jobs" / "job_language_build" / "latest.json"
        ).read_text(encoding="utf-8"))
        language_handoff = json.loads((
            run_root / language_pointer["handoff_path"]
        ).read_text(encoding="utf-8"))
        accepted = language_handoff["outputs"]["acceptance.publish_handoff"]["artifact"]
        receipts = json.loads((run_root / accepted["path"]).read_text(encoding="utf-8"))["receipts"]
        profile = next(row for row in receipts[0]["artifacts"] if row["kind"] == "execution-profile")
        (run_root / profile["path"]).write_bytes(b"forged;hot 9999\n")
        with pytest.raises(RuntimeError, match="normalize.profile_data"):
            GraphRunner(config, [profile_job()]).run(
                run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
        assert not (run_root / "data" / "jobs" / "job_profile_data" / "latest.json").exists()
        records = [json.loads(line) for line in (
            run_root / "data" / "logs" / "pipeline.jsonl"
        ).read_text(encoding="utf-8").splitlines()]
        failures = [row for row in records if row["event_type"] == "TASK_FAILED"
                    and row["job_id"] == "job_profile_data"]
        assert failures and failures[-1]["details"]["error_type"] == "ProfileIntegrityError"
        assert failures[-1]["details"]["unit_id"] == "normalize.profile_data"
    elapsed = time.monotonic() - started
    workspace.emit("ACCEPTANCE_CASE_COMPLETED", duration_ms=elapsed * 1000, outcome="passed",
                   rejected_artifact_sha256=profile["sha256"])
    assert elapsed < 120, f"signal integrity exceeded 120 seconds: {elapsed:.3f}s; {workspace.root}"
