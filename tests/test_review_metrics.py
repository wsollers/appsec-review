from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.container_runtime.measurement import COUNTERS, INVOCATION_SCHEMA, RESOURCE_SCHEMA
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage import canonical_json


def _receipt(root: Path, name: str, value: dict) -> dict[str, object]:
    path = root / "data" / "metrics-fixtures" / name
    atomic_json(path, value)
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def test_run_metrics_preserve_additive_domain_sections(tmp_path: Path) -> None:
    report = aggregate_run_metrics(tmp_path)
    assert report["schema"] == "appsec-review/run-metrics/5"
    assert {"interchange", "native_sbom", "debug_symbols", "owasp", "review_flow",
            "completion", "review", "codeql"} <= report.keys()


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


def _scanner_metrics_receipts(root: Path, *, complete=True, truncated=False, attempt="attempt_0001", count=3):
    from appsec_review.runtime.datasets import dataset_contract, protected
    from appsec_review.storage.shared import SharedArtifacts, put_bytes, reference
    import hashlib

    job = "job_evidence_collection"
    attempt_root = root / "data" / "jobs" / job / "attempts" / attempt
    actor = {"run_id": root.name, "job_id": job, "attempt_id": attempt, "orchestration": {"system": "fixture"}}
    declaration = protected(
        "native", "scan", "execution_receipts", "native/1", "fixture native receipts",
        artifacts=(f"data/jobs/{job}/attempts/*/shared/native-output/*.json",), reason="protected native data")
    atomic_json(attempt_root / "claim.json", {
        **actor, "attempt_path": attempt_root.relative_to(root).as_posix(),
        "dataset_contract": dataset_contract(job, ("scan",), (declaration,)),
    })
    shared = SharedArtifacts(root, attempt_root, {**actor, "claim": reference(root, attempt_root / "claim.json")})
    artifact = put_bytes(root, b"private-native-report-and-source")
    retention = {
        "schema": "appsec-review/native-output-retention/1", "artifact": artifact,
        "execution_reference": None, "parser_identity": "fixture-parser/1",
        "complete": complete, "truncated": truncated, "retained_bytes": artifact["size_bytes"],
        "native_result_count": count,
    }
    fingerprint = hashlib.sha256(canonical_json(retention)).hexdigest()
    retention_receipt = shared.computed("native-output", fingerprint, artifact, computation=retention)
    provenance = {
        "schema": "appsec-review/observation-provenance-validation/1",
        "actor": {key: actor[key] for key in ("run_id", "job_id", "attempt_id")},
        "parser_identity": "fixture-parser/1", "observation_count": count, "native_reference_count": count,
        "provenance_gap_count": 0 if complete else count,
        "complete": complete, "truncated": truncated, "artifacts": [artifact],
    }
    provenance_object = put_bytes(root, canonical_json(provenance))
    fingerprint = hashlib.sha256(canonical_json(provenance)).hexdigest()
    provenance_receipt = shared.computed("native-output", fingerprint, provenance_object, computation=provenance)
    log = PipelineLog(root)
    event_actor = {key: actor[key] for key in ("run_id", "job_id", "attempt_id")}
    native_details = {**retention, "retention_receipt": retention_receipt, "retained_bytes": 999999}
    provenance_details = {"provenance_receipt": provenance_receipt, "observation_count": 999999}
    log.write("NATIVE_OUTPUT_RETAINED", **event_actor, details=native_details)
    log.write("OBSERVATION_PROVENANCE_VALIDATED", **event_actor, details=provenance_details)
    return artifact, retention_receipt, provenance_receipt, event_actor, native_details, provenance_details


def test_interchange_metrics_receipt_authority_deduplication_reuse_and_redaction(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    artifact, retention, provenance, actor, native_details, provenance_details = _scanner_metrics_receipts(root)
    log = PipelineLog(root)
    log.write("NATIVE_OUTPUT_RETAINED", **actor, details=native_details)
    log.write("OBSERVATION_PROVENANCE_VALIDATED", **actor, details=provenance_details)
    log.write("TASK_REUSED", **actor, details={"checkpoint_reused": True})
    report = aggregate_run_metrics(root)
    interchange = report["interchange"]
    assert report["schema"] == "appsec-review/run-metrics/5"
    assert interchange["schema"] == "appsec-review/interchange-metrics/1"
    assert interchange["native_outputs"] == {
        "reference_count": 1, "distinct_artifact_count": 1, "distinct_artifact_bytes": artifact["size_bytes"],
        "complete": 1, "incomplete": 0, "truncated": 0, "native_result_count": 3, "accounting_complete": True,
    }
    assert interchange["observations"]["count"] == 3
    assert interchange["observations"]["native_reference_count"] == 3
    assert interchange["observations"]["provenance_complete_count"] == 3
    assert interchange["observations"]["provenance_incomplete_count"] == 0
    assert interchange["duplicate_events"] == 2
    assert report["tool_calls"] == {}  # Reuse and retained references are not scanner executions.
    serialized = json.dumps(interchange)
    for private in ("private-native-report-and-source", artifact["path"], artifact["sha256"],
                    retention["path"], provenance["path"], "fixture-parser/1"):
        assert private not in serialized
    assert set(interchange["by_job"]) == {"job_evidence_collection"}


def test_interchange_distinct_bytes_do_not_double_count_same_artifact_from_different_publications(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    artifact, *_ = _scanner_metrics_receipts(root)
    _scanner_metrics_receipts(root, attempt="attempt_0002")
    metrics = aggregate_run_metrics(root)["interchange"]
    assert metrics["native_outputs"]["reference_count"] == 1
    assert metrics["native_outputs"]["distinct_artifact_bytes"] == artifact["size_bytes"]
    assert metrics["observations"]["count"] == 6


@pytest.mark.parametrize(("complete", "truncated"), [(False, False), (False, True), (True, False)])
def test_interchange_provenance_completeness_and_truncation_are_receipt_backed(tmp_path, complete, truncated):
    root = tmp_path / "2026-10-28-0001"
    _scanner_metrics_receipts(root, complete=complete, truncated=truncated)
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["native_outputs"]["incomplete"] == int(not complete)
    assert summary["native_outputs"]["truncated"] == int(truncated)
    assert summary["observations"]["incomplete_batches"] == int(not complete)
    assert summary["observations"]["provenance_incomplete_count"] == (0 if complete else 3)
    assert summary["observations"]["truncated_batches"] == int(truncated)


@pytest.mark.parametrize("damage", ["missing", "tampered", "malformed", "escaped", "identity", "unknown-job"])
def test_interchange_integrity_gaps_are_closed_redacted_and_not_zero_counts(tmp_path, damage):
    root = tmp_path / "2026-10-28-0001"
    artifact, retained, _, actor, details, _ = _scanner_metrics_receipts(root)
    path = root / retained["path"]
    if damage == "missing":
        path.unlink()
    elif damage == "tampered":
        path.write_bytes(b"tampered-private")
    elif damage == "malformed":
        path.write_bytes(b"[]")
        details["retention_receipt"] = {**retained, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    elif damage == "escaped":
        details["retention_receipt"] = {**retained, "path": "../customer-secret"}
    elif damage == "identity":
        actor["attempt_id"] = "attempt_9999"
    elif damage == "unknown-job":
        actor["job_id"] = "customer-specific-rule-or-package"
    PipelineLog(root).write("NATIVE_OUTPUT_RETAINED", **actor, details=details)
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["native_outputs"]["reference_count"] is None
    assert summary["native_outputs"]["distinct_artifact_bytes"] is None
    assert summary["integrity_gap_codes"] and not summary["native_outputs"]["accounting_complete"]
    serialized = json.dumps(summary)
    assert "customer-secret" not in serialized and "customer-specific-rule-or-package" not in serialized
    assert artifact["path"] not in serialized


def test_interchange_missing_producers_have_null_metrics_and_named_gaps(tmp_path):
    summary = aggregate_run_metrics(tmp_path)["interchange"]
    assert summary["handoffs"]["accepted"] is None
    assert summary["handoffs"]["coverage_dispositions"]["complete"] is None
    assert summary["native_outputs"]["reference_count"] is None
    assert summary["observations"]["count"] is None
    assert summary["integrity_gap_codes"] == {
        "handoffs_unavailable": 1, "native_outputs_unavailable": 1, "observations_unavailable": 1}


def test_interchange_verified_empty_results_are_zero_not_unavailable(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    _scanner_metrics_receipts(root, count=0)
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["native_outputs"]["native_result_count"] == 0
    assert summary["observations"]["count"] == summary["observations"]["native_reference_count"] == 0
    assert summary["observations"]["accounting_complete"]


def test_interchange_dimensions_do_not_expand_for_unregistered_jobs_or_claimed_tools(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    log = PipelineLog(root)
    for number in range(64):
        log.write("NATIVE_OUTPUT_RETAINED", run_id=root.name, job_id=f"private-customer-{number}", details={
            "tool_id": f"arbitrary-rule-{number}", "rule_id": f"arbitrary-path-{number}"})
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["by_job"] == {}
    assert summary["integrity_gap_codes"]["identity_mismatch"] == 64
    assert "private-customer" not in json.dumps(summary) and "arbitrary-" not in json.dumps(summary)


@pytest.mark.parametrize("count", [-1, True, 1.5])
def test_interchange_hash_bound_but_invalid_counts_are_rejected(tmp_path, count):
    root = tmp_path / "2026-10-28-0001"
    _scanner_metrics_receipts(root, count=count)
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["observations"]["count"] is None
    assert summary["native_outputs"]["native_result_count"] is None
    assert summary["integrity_gap_codes"]


def _handoff_metrics_receipt(root: Path, *, rejected=False):
    from appsec_review.runtime.handoff import build_outcomes, execution_status
    from appsec_review.storage.shared import reference
    from tests.handoff_fixture import write_fixture_handoff

    job, attempt = "job_target_catalog", "attempt_0001"
    base = root / "data" / "jobs" / job / "attempts" / attempt
    path = base / "handoff.json"
    write_fixture_handoff(root, path, {
        "job_id": job, "outputs": {"scan.publish": {"terminal_status": "FAILED"}},
        "source_fingerprint": "snapshot",
    })
    handoff = json.loads(path.read_bytes())
    if rejected:
        status = base / "steps" / "scan" / "tasks" / "publish" / "status.json"
        atomic_json(status, {"unit_id": "scan.publish", "step_id": "scan", "task_id": "publish", "status": "FAILED"})
        handoff["artifacts"] = [
            reference(root, status) if ref["path"] == status.relative_to(root).as_posix() else ref
            for ref in handoff["artifacts"]]
        handoff["status"] = "REJECTED"
    document = build_outcomes(root, run_id=root.name, job_id=job, attempt_id=attempt,
                              target_snapshot="snapshot", unit_ids=["scan.publish"], diagnostic=rejected)
    outcomes_path = root / handoff["outcomes"]["path"]
    atomic_json(outcomes_path, document)
    outcome_ref = reference(root, outcomes_path)
    handoff.update(outcomes=outcome_ref, coverage=document["coverage"], execution_status=execution_status(document))
    handoff["artifacts"] = [outcome_ref if ref["path"] == outcome_ref["path"] else ref
                            for ref in handoff["artifacts"]]
    atomic_json(path, handoff)
    return path, handoff


def _handoff_event(root, path, *, kind="HANDOFF_VALIDATED", duration=12.5):
    from appsec_review.storage.shared import reference
    PipelineLog(root).write(kind, run_id=root.name, job_id="job_target_catalog", attempt_id="attempt_0001",
                             details={"handoff_reference": reference(root, path), "duration_ms": duration,
                                      "unit_count": 999999, "gap_count": 999999, "coverage_disposition": "clean"})


def test_interchange_handoff_authority_coverage_retry_duration_and_publication_deduplication(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    path, _ = _handoff_metrics_receipt(root)
    _handoff_event(root, path)
    _handoff_event(root, path, kind="HANDOFF_ACCEPTED")
    _handoff_event(root, path)
    PipelineLog(root).write("JOB_REUSED", run_id=root.name, job_id="job_target_catalog")
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["handoffs"]["accepted"] == summary["handoffs"]["validated"] == 1
    assert summary["handoffs"]["rejected"] == 0
    assert summary["handoffs"]["units"] == summary["handoffs"]["retry_required"] == 1
    assert summary["handoffs"]["retryable_gaps"] == 1
    assert summary["handoffs"]["coverage_dispositions"]["unavailable"] == 1
    assert summary["handoffs"]["execution_statuses"] == {"SUCCEEDED": 1, "FAILED": 0, "SKIPPED": 0}
    assert summary["handoffs"]["duration_ms"]["sum"] == 12.5
    assert summary["handoffs"]["duration_ms"]["count"] == 1
    assert summary["handoffs"]["accounting_complete"]
    assert summary["duplicate_events"] == 1
    assert "clean" not in json.dumps(summary) and "999999" not in json.dumps(summary)


def test_interchange_rejected_admission_is_distinct_from_failed_execution(tmp_path):
    root = tmp_path / "2026-10-28-0001"
    path, _ = _handoff_metrics_receipt(root, rejected=True)
    _handoff_event(root, path, kind="HANDOFF_REJECTED")
    summary = aggregate_run_metrics(root)["interchange"]["handoffs"]
    assert summary["accepted"] == summary["validated"] == 0
    assert summary["rejected"] == summary["execution_statuses"]["FAILED"] == 1
    assert summary["retry_required"] == 1


@pytest.mark.parametrize("damage", ["coverage", "missing", "tampered", "old-schema", "nonfinite-duration"])
def test_interchange_handoff_outcome_integrity_failures_never_look_like_zero_coverage(tmp_path, damage):
    root = tmp_path / "2026-10-28-0001"
    path, handoff = _handoff_metrics_receipt(root)
    if damage == "coverage":
        handoff["coverage"] = {"disposition": "complete", "gap_count": 0, "retry_required": False}
        atomic_json(path, handoff)
    elif damage == "missing":
        (root / handoff["outcomes"]["path"]).unlink()
    elif damage == "tampered":
        (root / handoff["outcomes"]["path"]).write_text("{}", encoding="utf-8")
    elif damage == "old-schema":
        atomic_json(path, {**handoff, "schema": "appsec-review/job-handoff/1"})
    _handoff_event(root, path, duration=float("nan") if damage == "nonfinite-duration" else 10)
    summary = aggregate_run_metrics(root)["interchange"]
    assert summary["handoffs"]["accepted"] is None
    assert summary["handoffs"]["coverage_dispositions"]["complete"] is None
    assert summary["integrity_gap_codes"] and not summary["handoffs"]["accounting_complete"]
