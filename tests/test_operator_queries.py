import hashlib
import json
import os
from pathlib import Path

import pytest

from appsec_review.mcp.operator import CursorCodec, LOG_PATH, OperatorMcpAdapter
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError
from appsec_review.storage import atomic_json
from tests.test_retrieval_core import RUN_ID, _fixture


def adapter_fixture(tmp_path):
    root = tmp_path / RUN_ID
    root.mkdir()
    return OperatorMcpAdapter(tmp_path, RUN_ID), root


def write_failure(root, job="job_test", attempt="attempt_0001", **extra):
    path = root / f"data/jobs/{job}/attempts/{attempt}/status.json"
    atomic_json(path, {"run_id": RUN_ID, "job_id": job, "attempt_id": attempt,
                       "status": "FAILED", "orchestration": {},
                       "error": {"type": "ValueError", "message": "credential-value"},
                       "stdout": "protected-output", "argv": ["sensitive-command"], **extra})
    return path


def tree_bytes(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_missing_unaccepted_and_unsupported_are_distinct_and_read_only(tmp_path):
    adapter = OperatorMcpAdapter(tmp_path, RUN_ID)
    assert adapter.call("inspect_run", {})["coverage_gaps"] == ["application_run_unavailable"]
    assert not list(tmp_path.iterdir())
    root = tmp_path / RUN_ID
    root.mkdir()
    assert adapter.call("inspect_run", {})["results"] == [{"availability": "unaccepted"}]
    with pytest.raises(RetrievalGap):
        adapter.call("coverage", {})
    atomic_json(root / "data/indices/accepted.json", {"schema": "future"})
    assert adapter.call("inspect_run", {})["results"] == [{"availability": "unsupported"}]


def test_accepted_queries_pin_manifest_and_never_write_logs_or_other_run_bytes(tmp_path):
    runs, ids = _fixture(tmp_path)
    before = tree_bytes(runs)
    adapter = OperatorMcpAdapter(runs, RUN_ID)
    assert adapter.call("inspect_run", {})["results"] == [{"availability": "accepted"}]
    assert adapter.call("find", {"identity": ids["symbol"]})["results"][0]["identity"] == ids["symbol"]
    assert adapter.call("query_artifacts", {"artifact_identity": ids["artifact"]})
    assert "link map was unavailable" in json.dumps(adapter.call("coverage", {}))
    assert tree_bytes(runs) == before
    pin = adapter.manifest_sha256
    assert pin is not None
    with pytest.raises(RetrievalIntegrityError):
        OperatorMcpAdapter(runs, RUN_ID, manifest_sha256="0" * 64).call("find", {"identity": ids["symbol"]})


def test_manifest_run_path_and_shard_tampering_are_rejected(tmp_path):
    runs, _ = _fixture(tmp_path)
    root = runs / RUN_ID
    pointer_path = root / "data/indices/accepted.json"
    original = json.loads(pointer_path.read_bytes())
    atomic_json(pointer_path, {**original, "run_id": "2026-11-06-9999"})
    with pytest.raises(RetrievalIntegrityError):
        OperatorMcpAdapter(runs, RUN_ID).call("inspect_run", {})
    atomic_json(pointer_path, {**original, "manifest_path": "../elsewhere"})
    with pytest.raises(ValueError):
        OperatorMcpAdapter(runs, RUN_ID).call("inspect_run", {})
    atomic_json(pointer_path, original)
    core_adapter = OperatorMcpAdapter(runs, RUN_ID)
    core_adapter.call("inspect_run", {})
    shard = next(root.glob("data/indices/source/**/*.sqlite"))
    with shard.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError):
        core_adapter.call("coverage", {})


def test_status_failure_projection_distinguishes_dispatch_and_excludes_raw_data(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    dispatch = "3daa98c3-6373-4565-a580-e0e012ad4347"
    path = write_failure(root, orchestration={"system": "dagster", "run_id": dispatch})
    trace = path.parent / "logs/traceback.txt"
    trace.parent.mkdir()
    trace.write_text("trace-secret")
    before = tree_bytes(root)
    result = adapter.call("inspect_attempt", {"job_id": "job_test", "attempt_id": "attempt_0001"})
    row = result["results"][0]
    assert result["application_run_id"] == RUN_ID and row["dagster_dispatch_id"] == dispatch
    assert row["failure"]["error_type"] == "ValueError"
    assert row["status_reference"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert row["traceback_reference"]["content_available"] is False
    assert row["status_reference"]["acceptance"] == "not_asserted"
    text = json.dumps(result)
    for secret in ["credential-value", "protected-output", "sensitive-command", "trace-secret"]:
        assert secret not in text
    assert tree_bytes(root) == before
    assert adapter.call("inspect_dagster", {"dispatch_id": dispatch})["coverage_gaps"]
    with pytest.raises(ValueError):
        adapter.call("inspect_dagster", {"dispatch_id": RUN_ID})


@pytest.mark.parametrize("field,value", [("run_id", "2026-11-06-9999"),
                                       ("attempt_id", "attempt_0002"), ("job_id", "job_other"),
                                       ("status", "FUTURE")])
def test_attempt_identity_and_version_mismatch(tmp_path, field, value):
    adapter, root = adapter_fixture(tmp_path)
    path = write_failure(root)
    document = json.loads(path.read_bytes())
    atomic_json(path, {**document, field: value})
    with pytest.raises(ValueError):
        adapter.call("inspect_attempt", {"job_id": "job_test", "attempt_id": "attempt_0001"})


def test_attempt_discovery_never_auto_selects_latest_and_pages_exact_job(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    for job in ("job_one", "job_two"):
        for attempt in ("attempt_0001", "attempt_0002"):
            write_failure(root, job, attempt)
    jobs = adapter.call("list_jobs", {"limit": 1})
    assert jobs["results"] == [{"job_id": "job_one"}]
    assert adapter.call("list_jobs", {"limit": 1, "cursor": jobs["pagination"]["next_cursor"]})["results"] == [
        {"job_id": "job_two"}]
    args = {"job_id": "job_one", "limit": 1}
    first = adapter.call("list_attempts", args)
    cursor = first["pagination"]["next_cursor"]
    assert first["results"] == [{"attempt_id": "attempt_0001"}]
    assert adapter.call("list_attempts", {**args, "cursor": cursor})["results"] == [{"attempt_id": "attempt_0002"}]
    with pytest.raises(ValueError):
        adapter.call("list_attempts", {**args, "job_id": "job_two", "cursor": cursor})
    write_failure(root, "job_one", "attempt_0003")
    with pytest.raises(ValueError, match="changed"):
        adapter.call("list_attempts", {**args, "cursor": cursor})
    assert adapter.call("list_attempts", {"job_id": "job_absent"})["coverage_gaps"]


def test_logs_sanitize_scope_and_paginate_without_mutations(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    log = PipelineLog(root)
    for job in ["job_one", "job_two", "job_one"]:
        log.write("JOB_FAILED", run_id=RUN_ID, job_id=job, attempt_id="attempt_0001", level="ERROR",
                  message="hidden raw text", details={"stdout": "raw-stream", "path": "/private"})
    before = tree_bytes(root)
    args = {"job_id": "job_one", "level": "ERROR", "limit": 1}
    first = adapter.call("read_logs", args)
    assert first["results"][0]["sequence"] == 1
    second = adapter.call("read_logs", {**args, "cursor": first["pagination"]["next_cursor"]})
    assert second["results"][0]["sequence"] == 3
    assert second["pagination"]["next_cursor"] is None
    assert "hidden raw text" not in json.dumps(first) and "raw-stream" not in json.dumps(first)
    assert tree_bytes(root) == before
    reference = first["results"][0]["reference"]
    payload = (root / LOG_PATH).read_bytes()[reference["offset"]:reference["offset"] + reference["size_bytes"]]
    assert hashlib.sha256(payload).hexdigest() == reference["sha256"]
    with pytest.raises(ValueError):
        adapter.call("read_logs", {**args, "job_id": "job_two", "cursor": first["pagination"]["next_cursor"]})


def test_log_cursor_rejects_append_replacement_cross_session_and_expiry(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    log = PipelineLog(root)
    for _ in range(3):
        log.write("JOB_STARTED", run_id=RUN_ID)
    args = {"limit": 1}
    cursor = adapter.call("read_logs", args)["pagination"]["next_cursor"]
    with pytest.raises(ValueError):
        OperatorMcpAdapter(tmp_path, RUN_ID).call("read_logs", {**args, "cursor": cursor})
    adapter.cursors.clock = lambda: 10**12
    with pytest.raises(ValueError, match="expired"):
        adapter.call("read_logs", {**args, "cursor": cursor})
    adapter.cursors = CursorCodec()
    cursor = adapter.call("read_logs", args)["pagination"]["next_cursor"]
    log.write("JOB_FAILED", run_id=RUN_ID)
    with pytest.raises(ValueError, match="changed"):
        adapter.call("read_logs", {**args, "cursor": cursor})
    cursor = adapter.call("read_logs", args)["pagination"]["next_cursor"]
    path = root / LOG_PATH
    replacement = path.with_suffix(".new")
    replacement.write_bytes(path.read_bytes())
    replacement.replace(path)
    with pytest.raises(ValueError, match="changed"):
        adapter.call("read_logs", {**args, "cursor": cursor})


def test_logs_truthful_empty_torn_size_scan_schema_and_run_gaps(tmp_path, monkeypatch):
    from appsec_review.mcp import operator
    adapter, root = adapter_fixture(tmp_path)
    assert adapter.call("read_logs", {})["coverage_gaps"] == ["pipeline_log_unavailable"]
    log = PipelineLog(root)
    log.write("JOB_STARTED", run_id=RUN_ID, job_id="job_one")
    no_match = adapter.call("read_logs", {"job_id": "job_two"})
    assert not no_match["results"] and no_match["coverage_gaps"]
    path = root / LOG_PATH
    original = path.read_bytes()
    path.write_bytes(original + b'{"partial":')
    assert "incomplete_final_log_record_withheld" in adapter.call("read_logs", {})["coverage_gaps"]
    path.write_bytes(b"x" * (operator.MAX_RECORD_BYTES + 1))
    with pytest.raises(ValueError, match="bound"):
        adapter.call("read_logs", {})
    path.write_bytes(original + original.replace(b'"sequence":1', b'"sequence":2'))
    monkeypatch.setattr(operator, "MAX_SCAN_BYTES", len(original) + 10)
    page = adapter.call("read_logs", {"job_id": "job_two"})
    assert page["pagination"]["next_cursor"] and "log_scan_byte_bound_reached" in page["coverage_gaps"]
    monkeypatch.setattr(operator, "MAX_SCAN_BYTES", 1024 * 1024)
    for key, value in [("schema", "future"), ("run_id", "different"), ("sequence", 2)]:
        document = json.loads(original)
        path.write_text(json.dumps({**document, key: value}) + "\n")
        with pytest.raises(ValueError):
            adapter.call("read_logs", {})


def test_recovery_plan_is_exact_historical_nonexecuting_and_does_not_expose_reason_text(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    log = PipelineLog(root)
    log.write("JOB_FAILED", run_id=RUN_ID)
    log.write("RESUME_PLANNED", run_id=RUN_ID, details={"decisions": [
        {"job_id": "job_one", "action": "RUN", "reasons": ["raw-sensitive-reason"], "handoff_sha256": None},
        {"job_id": "job_two", "action": "INVALIDATE", "reasons": ["transitive downstream invalidation"]}]})
    events = adapter.call("read_logs", {"event_type": "RESUME_PLANNED"})["results"]
    ref = events[0]["reference"]
    before = tree_bytes(root)
    result = adapter.call("inspect_recovery_plan", {"offset": ref["offset"], "sha256": ref["sha256"]})
    row = result["results"][0]
    assert row["executes"] is False and len(row["decisions"]) == 2
    assert row["reference"] == ref and "historical_plan_not_current_restart_admission" in result["coverage_gaps"]
    assert (Path(__file__).parents[1] / row["references"]["unit_regression"]).is_file()
    assert "raw-sensitive-reason" not in json.dumps(result)
    assert tree_bytes(root) == before
    for args in [{"offset": ref["offset"], "sha256": "0" * 64},
                 {"offset": ref["offset"] + 1, "sha256": ref["sha256"]}]:
        with pytest.raises(ValueError):
            adapter.call("inspect_recovery_plan", args)


def test_operator_refuses_run_document_directory_symlinks_and_special_files(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    path = write_failure(root)
    outside = tmp_path / "outside.json"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(ValueError):
        adapter.call("inspect_attempt", {"job_id": "job_test", "attempt_id": "attempt_0001"})
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular"):
        adapter.call("inspect_attempt", {"job_id": "job_test", "attempt_id": "attempt_0001"})
    path.unlink()
    (root / "data/jobs/job_escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        adapter.call("list_jobs", {})
    (tmp_path / "2026-11-06-9999").symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        OperatorMcpAdapter(tmp_path, "2026-11-06-9999")


def test_retrieval_cursor_is_bound_to_manifest_filters_and_expiry(tmp_path):
    runs, _ = _fixture(tmp_path)
    adapter = OperatorMcpAdapter(runs, RUN_ID)
    args = {"path": "src/auth.c", "indexes": ["analysis"], "limit": 1}
    first = adapter.call("find", args)
    cursor = first["pagination"]["next_cursor"]
    assert cursor
    assert adapter.call("find", {**args, "cursor": cursor})["results"] != first["results"]
    for changed in [{**args, "limit": 2}, {**args, "indexes": ["source"]}]:
        with pytest.raises(ValueError):
            adapter.call("find", {**changed, "cursor": cursor})
    adapter.cursors.clock = lambda: 10**12
    with pytest.raises(ValueError, match="expired"):
        adapter.call("find", {**args, "cursor": cursor})


def test_unknown_entity_is_named_gap_not_empty_success(tmp_path):
    runs, _ = _fixture(tmp_path)
    result = OperatorMcpAdapter(runs, RUN_ID).call("find", {"identity": "asr:symbol:" + "f" * 64})
    assert not result["results"] and result["coverage_gaps"]


def test_workbench_keeps_its_separate_exact_manifest_pin(tmp_path):
    from tests.test_owasp_indexes import _accept, _publish
    runs, _ = _fixture(tmp_path)
    root = runs / RUN_ID
    adapter = OperatorMcpAdapter(runs, RUN_ID)
    assert adapter.call("query_owasp_workbench", {})["coverage_gaps"]
    manifest = _accept(root, [_publish(root)])
    before = tree_bytes(root)
    result = adapter.call("query_owasp_workbench", {})
    assert result["manifest_identity"]["sha256"] == manifest["sha256"]
    assert tree_bytes(root) == before
    _accept(root, [_publish(root, gaps=["new coverage gap"])])
    with pytest.raises(RetrievalIntegrityError, match="workbench manifest changed"):
        adapter.call("query_owasp_workbench", {})


def test_document_directory_bounds_and_missing_attempt_are_explicit(tmp_path, monkeypatch):
    from appsec_review.mcp import operator
    adapter, root = adapter_fixture(tmp_path)
    assert adapter.call("inspect_attempt", {"job_id": "job_missing", "attempt_id": "attempt_0001"})["coverage_gaps"]
    path = write_failure(root)
    original = path.read_bytes()
    monkeypatch.setattr(operator, "MAX_DOCUMENT_BYTES", len(original) - 1)
    with pytest.raises(ValueError, match="byte bound"):
        adapter.call("inspect_attempt", {"job_id": "job_test", "attempt_id": "attempt_0001"})
    monkeypatch.setattr(operator, "MAX_DIRECTORY_ENTRIES", 0)
    with pytest.raises(ValueError, match="scan bound"):
        adapter.call("list_jobs", {})


def test_recovery_missing_schema_unsupported_decisions_and_nonplan_event(tmp_path):
    adapter, root = adapter_fixture(tmp_path)
    log = PipelineLog(root)
    for event, details in [
        ("JOB_STARTED", {}),
        ("RESUME_PLANNED", {"truncated": True}),
        ("RESUME_PLANNED", {"decisions": []}),
        ("RESUME_PLANNED", {"decisions": [{"job_id": "job_test", "action": "EXECUTE"}]}),
    ]:
        log.write(event, run_id=RUN_ID, details=details)
    events = adapter.call("read_logs", {})["results"]

    def arguments(index):
        ref = events[index]["reference"]
        return {"offset": ref["offset"], "sha256": ref["sha256"]}

    with pytest.raises(ValueError, match="not a recorded recovery plan"):
        adapter.call("inspect_recovery_plan", arguments(0))
    assert adapter.call("inspect_recovery_plan", arguments(1))["coverage_gaps"] == [
        "recorded_plan_decisions_unavailable"]
    assert "recorded_plan_is_empty" in adapter.call("inspect_recovery_plan", arguments(2))["coverage_gaps"]
    with pytest.raises(ValueError, match="unsupported"):
        adapter.call("inspect_recovery_plan", arguments(3))
