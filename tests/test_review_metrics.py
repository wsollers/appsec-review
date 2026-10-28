from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.container_runtime.measurement import COUNTERS, INVOCATION_SCHEMA, RESOURCE_SCHEMA
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.storage import atomic_json, file_sha256


def _receipt(root: Path, name: str, value: dict) -> dict[str, object]:
    path = root / "data" / "metrics-fixtures" / name
    atomic_json(path, value)
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def test_review_metrics_resolve_receipts_and_preserve_gaps_reuse_and_deduplication(tmp_path: Path) -> None:
    source = _receipt(tmp_path, "source.json", {
        "source_metrics_semantics": "appsec-review/source-counting/1",
        "source_metrics": [
            {"path": "src/a.py", "language": "Python", "sloc": 10,
             "generated": False, "vendored": False, "test": False},
            {"path": "tests/test_a.py", "language": "Python", "sloc": 5,
             "generated": False, "vendored": False, "test": True},
            {"path": "vendor/a.ts", "language": "TypeScript", "sloc": 7,
             "generated": False, "vendored": True, "test": False},
            {"path": "generated/b.ts", "language": "TypeScript", "sloc": 3,
             "generated": True, "vendored": False, "test": False},
        ], "source_metric_gaps": [{"path": "huge.py", "reason": "source_file_too_large"}],
    })
    projects = _receipt(tmp_path, "projects.json", {"projects": [
        {"root": "."}, {"root": "web"}]})
    targets = _receipt(tmp_path, "targets.json", {"targets": [
        {"build_unit_id": "py"}, {"build_unit_id": "web"}, {"build_unit_id": "missing"}]})
    shared_path = tmp_path / "data" / "build" / "shared.pkg"
    shared_path.parent.mkdir(parents=True)
    shared_path.write_bytes(b"x" * 100)
    shared = {"kind": "package", "path": shared_path.relative_to(tmp_path).as_posix(),
              "sha256": file_sha256(shared_path), "size_bytes": 100}
    builds = _receipt(tmp_path, "builds.json", {
        "schema": "appsec-review/language-build-handoff/1", "receipts": [
            {"build_unit_id": "py", "family": "python", "root": ".",
             "terminal_status": "SUCCEEDED", "checkpoint_reused": False, "gaps": [],
             "artifacts": [shared]},
            {"build_unit_id": "web", "family": "node", "root": "web",
             "terminal_status": "SUCCEEDED", "checkpoint_reused": True,
             "gaps": ["optional map absent"],
             "artifacts": [shared]},
            {"build_unit_id": "failed", "family": "node", "root": "web",
             "terminal_status": "FAILED", "checkpoint_reused": False,
             "gaps": ["build failed"], "artifacts": []},
            {"build_unit_id": "na", "family": "dotnet", "root": ".",
             "terminal_status": "NOT_APPLICABLE", "checkpoint_reused": False,
             "gaps": ["platform unavailable"], "artifacts": []},
        ]})
    codeql = _receipt(tmp_path, "codeql.json", {
        "schema": "appsec-review/codeql-analysis-handoff/1", "scopes": [
            {"scope_id": "scope-py", "language": "python", "root": ".",
             "build_unit_id": "py", "query_profile": "security", "gaps": []},
            {"scope_id": "scope-web", "language": "javascript", "root": "web",
             "build_unit_id": "web", "query_profile": "security", "gaps": ["query failed"]},
        ]})
    database = _receipt(tmp_path, "database.json", {"duration_ms": 8000})
    query = _receipt(tmp_path, "query.json", {"duration_ms": 6000})
    reused = _receipt(tmp_path, "query-reused.json", {"duration_ms": 0})
    log = PipelineLog(tmp_path)
    log.write("REVIEW_SCOPE_CATALOGED", run_id="run", details={
        "source_receipt": source, "project_receipt": projects, "build_target_receipt": targets})
    log.write("LANGUAGE_BUILDS_RECORDED", run_id="run", details={"receipt": builds})
    log.write("CODEQL_SCOPES_RECORDED", run_id="run", details={"receipt": codeql})
    common = {"tool_id": "codeql", "scope_id": "scope-py", "language": "python",
              "project_root": ".", "build_unit_id": "py"}
    log.write("TOOL_INVOCATION_STARTED", run_id="run", details={**common,
        "database_identity": "db"})
    log.write("TOOL_INVOCATION_COMPLETED", run_id="run", details={**common,
        "database_identity": "db", "duration_ms": 8000, "disposition": "SUCCEEDED",
        "gap_count": 0, "checkpoint_reused": False, "metrics_receipt": database})
    log.write("TOOL_INVOCATION_STARTED", run_id="run", details={**common,
        "database_identity": "db", "query_identity": "query", "query_profile": "security"})
    log.write("TOOL_INVOCATION_COMPLETED", run_id="run", details={**common,
        "database_identity": "db", "query_identity": "query", "query_profile": "security",
        "duration_ms": 6000, "disposition": "SUCCEEDED", "gap_count": 0,
        "checkpoint_reused": False, "metrics_receipt": query})
    log.write("TOOL_INVOCATION_STARTED", run_id="run", details={**common,
        "database_identity": "db", "query_identity": "query-reused", "query_profile": "security"})
    log.write("TOOL_INVOCATION_COMPLETED", run_id="run", details={**common,
        "database_identity": "db", "query_identity": "query-reused", "query_profile": "security",
        "duration_ms": 0, "disposition": "SUCCEEDED", "gap_count": 0,
        "checkpoint_reused": True, "metrics_receipt": reused})
    records, _ = log.read()
    stamps = ["2026-10-08T00:00:00+00:00", "2026-10-08T00:00:00+00:00",
              "2026-10-08T00:00:00+00:00", "2026-10-08T00:00:01+00:00",
              "2026-10-08T00:00:09+00:00", "2026-10-08T00:00:02+00:00",
              "2026-10-08T00:00:08+00:00", "2026-10-08T00:00:08+00:00",
              "2026-10-08T00:00:08+00:00"]
    for record, stamp in zip(records, stamps):
        record["timestamp"] = stamp
    log.path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in records), encoding="utf-8")

    review = aggregate_run_metrics(tmp_path)["review"]
    assert review["source_by_language"]["Python"] == {
        "file_count": 2, "sloc": 15, "generated_files": 0, "generated_sloc": 0,
        "vendored_files": 0, "vendored_sloc": 0, "test_files": 1, "test_sloc": 5}
    assert review["source_gap_count"] == 1
    assert review["projects"] == {"discovered": 2, "selected": 2}
    assert review["build_units"]["by_language"]["node"] == {
        "failure": 1, "gap": 2, "not_applicable": 0, "reuse": 1, "success": 0}
    assert review["artifacts"]["reference_count"] == 2
    assert review["artifacts"]["deduplicated_count"] == 1
    assert review["artifacts"]["deduplicated_bytes"] == 100
    assert review["codeql_timings"]["aggregate"]["query"] == {
        "count": 2, "fresh_count": 1, "reused_count": 1, "p50_ms": 0,
        "p95_ms": 6000, "max_ms": 6000, "summed_work_ms": 6000,
        "wall_span_ms": 6000, "gap_count": 0, "receipt_count": 2,
        "terminal_dispositions": {"SUCCEEDED": 2}}
    assert any("scope-web" in gap for gap in review["gaps"])


def test_review_metrics_turn_missing_or_changed_receipt_into_explicit_gap(tmp_path: Path) -> None:
    missing = {"path": "data/missing.json", "sha256": "f" * 64}
    PipelineLog(tmp_path).write("LANGUAGE_BUILDS_RECORDED", run_id="run",
                                details={"receipt": missing})
    review = aggregate_run_metrics(tmp_path)["review"]
    assert review["build_units"]["selected"] == 0
    assert review["gaps"] and "unavailable" in review["gaps"][0]


def test_review_metrics_name_absent_producers_as_coverage_gaps(tmp_path: Path) -> None:
    review = aggregate_run_metrics(tmp_path)["review"]
    assert review["gaps"] == [
        "source/catalog metrics producer receipt is unavailable",
        "language-build metrics producer receipt is unavailable",
        "CodeQL scope metrics producer receipt is unavailable",
    ]


def tree_invocation(root: Path, identity: str, *, start: int, end: int | None,
                    job: str = "job_source_history_analysis", status: str = "SUCCEEDED",
                    measured: bool = True, peak: int = 1024, attempt: str = "attempt_0001"):
    log = PipelineLog(root)
    common = {"tool_id": "tool-tree-sitter", "tool_invocation_id": identity}
    invocation = {
        "schema": INVOCATION_SCHEMA, "invocation_id": identity, "run_id": "run",
        "job_id": job, "attempt_id": attempt, "unit_id": "parse.scope", "scope_id": identity,
        "language": "C", "image_id": "sha256:" + "a" * 64, "configured_limits": {"memory": "1g"},
        "files": [{"path": "a.c", "sha256": "b" * 64}],
        "started_at": f"2026-10-27T00:00:{start:02}+00:00",
    }

    def event(kind, name, value):
        reference = _receipt(root, f"{identity}-{name}.json", value)
        details = {**common, "metrics_receipt": reference}
        log.write(kind, run_id="run", job_id=job, attempt_id=attempt, details=details)
        return details

    event("TOOL_INVOCATION_STARTED", "start", invocation)
    if end is None:
        return None
    resources = {"schema": RESOURCE_SCHEMA, **{key: 10 if measured else None for key in COUNTERS},
                 "memory_peak_bytes": peak if measured else None, "final_snapshot": measured,
                 "local_limits": {"memory.max": "1073741824"},
                 "limit_scope": "container_cgroup", "ancestor_limits_visible": False,
                 "unavailable": {} if measured else {"snapshot": "container_killed"}}
    completed = {**invocation, "completed_at": f"2026-10-27T00:00:{end:02}+00:00",
                 "duration_ms": (end - start) * 1000, "status": status, "resources": resources,
                 "resource_accounting_complete": measured, "exit_code": 0 if status == "SUCCEEDED" else 137,
                 "timed_out": False, "oom_killed": status == "OOM"}
    details = event("TOOL_INVOCATION_COMPLETED", "execution", completed)
    if status == "SUCCEEDED":
        event("TREE_SITTER_OUTPUT_VALIDATED", "output", {
            "schema": "appsec-review/tree-sitter-output-metrics/1", "invocation_id": identity,
            "files_requested": 1, "files_accounted": 1, "files_parsed": 1,
            "nodes_emitted": 20, "truncated_files": 0})
    return details


@pytest.mark.parametrize(("second_start", "elapsed", "concurrency"), ((5, 8000, 1), (2, 5000, 2)))
def test_tree_sitter_rollup_deduplicates_both_jobs_and_distinguishes_time_and_peak(
        tmp_path: Path, second_start: int, elapsed: int, concurrency: int) -> None:
    first = tree_invocation(tmp_path, "one", start=1, end=5, peak=1024)
    tree_invocation(tmp_path, "two", start=second_start, end=second_start + 4,
                    job="job_tree_sitter_ast", peak=4096, attempt="attempt_0002")
    PipelineLog(tmp_path).write("TOOL_INVOCATION_COMPLETED", run_id="run",
        job_id="job_source_history_analysis", attempt_id="attempt_0001", details=first)
    for _ in range(2):
        PipelineLog(tmp_path).write("TREE_SITTER_REUSED", run_id="run", details={
            "tool_id": "tool-tree-sitter", "reuse_id": "reuse-one", "source_invocation_id": "one"})
    summary = aggregate_run_metrics(tmp_path)["tree_sitter"]
    assert summary["invocation_count"] == 2 and summary["reused_scope_count"] == 1
    assert len(summary["by_job_attempt"]) == 2
    assert summary["summed_invocation_duration_ms"] == 8000
    assert summary["elapsed_window_ms"] == elapsed and summary["covered_wall_ms"] == elapsed
    assert summary["max_concurrency"] == concurrency and summary["timing_complete"]
    assert summary["measurements"]["memory_peak_bytes"]["value"] == 4096
    assert summary["measurements"]["cpu_usage_usec"]["value"] == 20
    assert summary["measurements"]["io_read_bytes"]["value"] == 20
    assert summary["counts"]["nodes_emitted"] == {"value": 40, "complete": True}
    assert not summary["incomplete_accounting"]


def test_tree_sitter_failures_cancellation_and_missing_completion_remain_incomplete(tmp_path: Path) -> None:
    tree_invocation(tmp_path, "oom", start=1, end=3, status="OOM", peak=1_073_741_824)
    tree_invocation(tmp_path, "canceled", start=3, end=4, status="CANCELED", measured=False)
    tree_invocation(tmp_path, "lost", start=4, end=None)
    summary = aggregate_run_metrics(tmp_path)["tree_sitter"]
    assert summary["outcomes"] == {"CANCELED": 1, "INCOMPLETE": 1, "OOM": 1}
    assert summary["incomplete_accounting"] and not summary["timing_complete"]
    assert summary["counts"]["nodes_emitted"] == {"value": None, "complete": False}
    assert summary["measurements"]["cpu_usage_usec"] == {
        "value": 10, "measured_invocations": 1, "unavailable_invocations": 2, "complete": False}
    assert summary["measurements"]["memory_peak_bytes"]["value"] == 1_073_741_824
    canceled = next(row for row in summary["invocations"] if row["invocation_id"] == "canceled")
    assert canceled["resources"]["memory_peak_bytes"] is None


def test_tree_sitter_conflicting_identity_is_not_summed_as_another_execution(tmp_path: Path) -> None:
    first = tree_invocation(tmp_path, "one", start=1, end=2)
    changed = json.loads((tmp_path / first["metrics_receipt"]["path"]).read_text())
    changed["duration_ms"] = 9000
    reference = _receipt(tmp_path, "conflict.json", changed)
    PipelineLog(tmp_path).write("TOOL_INVOCATION_COMPLETED", run_id="run",
        job_id="job_source_history_analysis", attempt_id="attempt_0001",
        details={**first, "metrics_receipt": reference})
    summary = aggregate_run_metrics(tmp_path)["tree_sitter"]
    assert summary["invocation_count"] == 1 and summary["outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["summed_invocation_duration_ms"] is None
    assert summary["measurements"]["memory_peak_bytes"]["value"] is None
    assert summary["gaps"] and summary["incomplete_accounting"]
