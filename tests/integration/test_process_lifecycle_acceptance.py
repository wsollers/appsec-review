"""Real bounded process boundaries, never a deployment or a paid model invocation."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from dagster import DagsterInstance, DagsterRunStatus, DagsterEventType, build_sensor_context
from dagster._serdes import deserialize_value
import pytest

from appsec_review.config import load_config
from appsec_review.config.run_selection import RunConfigurations
from appsec_review.observability import PipelineLog, write_run_metrics
from appsec_review.orchestration.dagster.error_state import (
    STEP_FAILURE_SENSOR, build_error_state_definitions,
)
from appsec_review.runtime.resources import process_identity
from appsec_review.storage import file_sha256
from tests.fixtures.process_lifecycle import jobs
from tests.fixtures.process_lifecycle.support import (
    LINUX, case, completed, kill_owned, owns, prepare, process, read, wait_for,
)


def _outputs(run_root):
    result = next(run_root.glob("data/jobs/job_fixture/attempts/*/result.json"))
    return read(result)["outputs"]


def _run_root(workspace, result):
    run_id = result.get("tags", {}).get("appsec/application_run_id") or result["run_id"]
    return workspace.runs_dir / run_id


def test_tagged_multiprocess_workers_receive_layers_hash_and_pool_limit():
    with case("tagged-workers") as workspace:
        root = prepare(workspace)
        expected = RunConfigurations(load_config(
            root / "appsec-review.toml", profile="dev", overlay="")).for_tags({
                "appsec/profile": "prod",
                "appsec/overlay": str(root / "test" / "acceptance" / "capacity.toml")})
        with process(root, "propagation") as worker:
            try:
                wait_for(lambda: (root / "first-ready.json").exists(), timeout=35, child=worker)
                assert worker.poll() is None
                with DagsterInstance.from_ref(deserialize_value(read(root / "instance.json")["ref"])) as instance:
                    run_id = read(root / "dagster-started.json")["run_id"]
                    launched = instance.get_records_for_run(
                        run_id, of_type=DagsterEventType.STEP_WORKER_STARTING).records
                    steps = {item.event_log_entry.dagster_event.step_key for item in launched}
                    assert "fixture__work__first" in steps
                    assert "fixture__work__second" not in steps
            finally:
                (root / "release-first").touch()
            worker.wait(timeout=30)
            assert worker.returncode == 0
        outcome = read(root / "propagation.json")
        assert outcome["success"]
        run_root = _run_root(workspace, outcome)
        outputs = _outputs(run_root)
        first, second = outputs["work.first"], outputs["work.second"]
        assert first["pid"] != second["pid"] != os.getpid()
        assert first["end"] <= second["begin"] or second["end"] <= first["begin"]
        for value in (first, second):
            assert value["claim_sha256"] == value["resolved_sha256"] == expected.resolved_sha256
            assert value["profile"] == "prod"
            assert value["layers"] == [dict(layer) for layer in expected.layers]
            assert value["model"] == expected.job("job_target_analysis_plan").settings["model"]["model"]
        manifest = read(run_root / "data" / "configuration" / "manifest.json")
        assert manifest["selection"]["source"] == "run_tags"
        assert manifest["resolved_sha256"] == expected.resolved_sha256
        assert manifest["sources"] == first["layers"]
        metrics = write_run_metrics(run_root)
        records, torn = PipelineLog(run_root).read()
        assert not torn
        receipts = list(run_root.glob("data/jobs/job_fixture/attempts/*/steps/work/tasks/*/status.json"))
        assert len(receipts) == metrics["event_counts"]["TASK_SUCCEEDED"] == 2
        assert all(read(path)["status"] == "SUCCEEDED" for path in receipts)
        assert metrics["event_counts"].get("DAGSTER_QUEUE_DELAY", 0) == int(outcome["queue_timestamp_available"])
        if not outcome["queue_timestamp_available"]:
            workspace.emit("ACCEPTANCE_BOUNDARY_UNAVAILABLE", boundary="dagster-queue-delay",
                           reason="DagsterRun-has-no-create_timestamp")
        spans = [item for item in metrics["resource_spans"] if item["stage"] == "unit.execute"]
        assert len(spans) == 2 and all(item["duration_ms"] >= 0 for item in spans)
        assert all(item["resources"]["cpu_user_seconds"] >= 0 for item in spans)
        receipt = read(run_root / "data" / "orchestration" / "dagster" / f"{outcome['run_id']}.json")
        pointer = read(run_root / "data" / "jobs" / "job_fixture" / "latest.json")
        assert receipt["handoff_sha256"]["job_fixture"] == pointer["handoff_sha256"]
        assert metrics["raw_event_count"] == len(records)
        before = (root / "first-ready.json").stat().st_mtime_ns
        resumed = completed(root, "resume-selection", run_root.name)
        assert resumed["reused"] and resumed["attempt_id"] == "attempt_0001"
        assert resumed["observed_configuration"] == {
            "resolved_sha256": expected.resolved_sha256, "profile": "prod"}
        assert (root / "first-ready.json").stat().st_mtime_ns == before


def test_incompatible_profile_is_refused_by_actual_executor_before_worker_admission():
    with case("profile-refusal") as workspace:
        root = prepare(workspace)
        result = completed(root, "propagation", environment={"APPSEC_PROCESS_PROFILE": "copilot-prod"})
        assert not result["success"]
        assert not (root / "first-ready.json").exists()
        assert not list(workspace.runs_dir.glob("*/data/jobs"))
        errors = "".join(path.read_text(encoding="utf-8") for path in root.glob("propagation-*.stderr"))
        assert "provider is fixed" in errors
        assert not any(event["type"] == "STEP_START" for event in result["events"])


def test_killed_worker_preserves_accepted_predecessor_and_real_attempt_then_resumes():
    with case("worker-recovery") as workspace:
        root = prepare(workspace)
        with process(root, "interrupt-worker") as worker:
            wait_for(lambda: (root / "worker-ready.json").exists(), timeout=25, child=worker)
            ready = read(root / "worker-ready.json")
            assert owns(worker, ready["pid"])
            run_root = workspace.runs_dir / ready["run_id"]
            predecessor = run_root / "data/jobs/job_review_intake/latest.json"
            predecessor_before = predecessor.read_bytes()
            handoff = run_root / read(predecessor)["handoff_path"]
            accepted_sha = file_sha256(handoff)
            attempt = Path(ready["attempt"])
            status_before = (attempt / "status.json").read_bytes()
            assert read(attempt / "status.json")["status"] == "RUNNING"
            ledger = workspace.runs_dir / "metadata/resource-admission/leases.json"
            occupied = read(ledger)["leases"]
            assert list(occupied) == [ready["lease"]]
            assert occupied[ready["lease"]]["pid"] == ready["pid"]
            kill_owned(worker)
            assert worker.returncode != 0
        assert read(ledger)["leases"] == occupied
        if LINUX:
            assert process_identity(ready["pid"]) != ready["generation"]
        resumed = completed(root, "resume-worker")
        assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "RUN"]
        assert predecessor.read_bytes() == predecessor_before
        assert file_sha256(handoff) == accepted_sha
        assert (attempt / "status.json").read_bytes() == status_before
        catalog = resumed["jobs"]["job_target_catalog"]
        assert catalog["status"]["attempt_id"] == "attempt_0002"
        assert catalog["status"]["status"] == "SUCCEEDED"
        if LINUX:
            assert resumed["reconciled"] == [ready["lease"]]
            assert read(ledger)["leases"] == {}
        else:
            # Windows cannot prove Linux /proc generation identity; never credit reclamation.
            assert resumed["reconciled"] == []
            assert read(ledger)["leases"] == occupied
            workspace.emit("ACCEPTANCE_BOUNDARY_UNAVAILABLE",
                           boundary="linux-generation-lease-reconciliation", platform=os.name)


def test_fresh_dagster_record_and_local_replay_preserve_failures_without_live_transport():
    from appsec_review.inference.recording import RECORDINGS

    with case("cross-root-record-replay") as workspace:
        recording_root = prepare(workspace, "record checkout")
        recorded = completed(recording_root, "recording",
                             environment={"APPSEC_REVIEW_MODEL_RECORDING": "record"})
        assert recorded["success"]
        recorded_run = _run_root(workspace, recorded)
        recordings = recorded_run / RECORDINGS
        files = list((recordings / "job_fixture").glob("*.json"))
        assert len(files) == 3
        documents = sorted((read(path) for path in files), key=lambda item: item["sequence"])
        assert documents[0]["error"]["type"] == "ModelOutputError"
        assert [item["result"]["proposal"] for item in documents[1:]] == [{"value": 2}, {"value": 3}]
        assert str(recording_root) not in json.dumps(documents)
        replay_root = prepare(workspace, "different replay checkout")
        replayed = completed(replay_root, "replay-local", environment={
            "APPSEC_REVIEW_MODEL_RECORDING": "replay",
            "APPSEC_REVIEW_MODEL_REPLAY_DIR": str(recordings)})
        replayed_run = _run_root(workspace, replayed)
        assert _outputs(replayed_run) == _outputs(recorded_run)
        for run in (recorded_run, replayed_run):
            handoff = next(run.glob("data/jobs/job_fixture/attempts/*/handoff.json"))
            assert read(handoff)["status"] == "ACCEPTED"
            assert read(run / "data/telemetry/summary.json")["event_counts"]["TASK_SUCCEEDED"] == 1
        exhausted = completed(replay_root, "replay-exhaust", environment={
            "APPSEC_REVIEW_MODEL_RECORDING": "replay",
            "APPSEC_REVIEW_MODEL_REPLAY_DIR": str(recordings),
            "APPSEC_PROCESS_REPLAY_EXHAUST": "1"})
        assert "partial failure" in exhausted["error"]
        misses = list((recordings / "job_fixture" / "misses").glob("*.json"))
        assert len(misses) == 1 and read(misses[0])["sequence"] == 3
        missed = completed(replay_root, "replay-exhaust", environment={
            "APPSEC_REVIEW_MODEL_RECORDING": "replay",
            "APPSEC_REVIEW_MODEL_REPLAY_DIR": str(recordings),
            "APPSEC_PROCESS_REPLAY_MISS": "1"})
        assert "no recorded model response" in missed["error"]
        misses = [read(path) for path in (recordings / "job_fixture" / "misses").glob("*.json")]
        assert len(misses) == 2
        assert any(item["sequence"] == 0 and item["request"]["guidance"] == "unrecorded" for item in misses)
        failures = list(workspace.runs_dir.glob("*/data/jobs/job_fixture/attempts/*/steps/work/tasks/first/traceback.txt"))
        assert any("ModelReplayMiss" in path.read_text(encoding="utf-8") for path in failures)


def test_real_step_failure_sensor_observes_failure_while_multiprocess_sibling_is_active(monkeypatch):
    with case("active-failure-sensor") as workspace:
        root = prepare(workspace)
        monkeypatch.setenv("APPSEC_PROCESS_ROOT", str(root))
        with process(root, "sensor") as worker:
            try:
                wait_for(lambda: (root / "sensor-active.json").exists(), timeout=30, child=worker)
                with DagsterInstance.from_ref(deserialize_value(read(root / "instance.json")["ref"])) as instance:
                    run_id = read(root / "dagster-started.json")["run_id"]
                    wait_for(lambda: instance.get_records_for_run(
                        run_id, of_type=DagsterEventType.STEP_FAILURE).records, timeout=15)
                    assert instance.get_run_by_id(run_id).status == DagsterRunStatus.STARTED
                    _, sensors = build_error_state_definitions(jobs.define_sensor(), workspace.runs_dir)
                    sensor = next(value for value in sensors if value.name == STEP_FAILURE_SENSOR)
                    with build_sensor_context(instance=instance) as context:
                        result = sensor.evaluate_tick(context)
                    assert "recorded 1" in result.skip_message
                    assert run_id in json.loads(result.cursor)
                    logs = list(workspace.runs_dir.glob("metadata/dagster-error-state/*/steps/*.log"))
                    assert len(logs) == 1
                    assert "fixture failure while sibling active" in logs[0].read_text(encoding="utf-8")
                    assert worker.poll() is None
            finally:
                (root / "release-sensor").touch()
            worker.wait(timeout=15)
            assert worker.returncode == 0
        assert not read(root / "sensor.json")["success"]


@pytest.mark.skipif(not LINUX, reason="production SafetyExecutor requires Linux SO_PEERCRED and /proc")
def test_real_safety_executor_stops_child_grandchild_and_never_admits_queued_or_retry():
    with case("fail-fast-descendants") as workspace:
        root = prepare(workspace)
        outcome = completed(root, "fail_fast", timeout=48)
        assert not outcome["success"]
        assert not (root / "incorrectly-admitted.json").exists()
        returned = read(root / "tree-returned.json")
        assert returned["timed_out"] and all(returned["deaths"].values())
        journal = read(workspace.runs_dir / "metadata/dagster-safety" / f"{outcome['run_id']}.json")
        assert journal["first_error"]["reason"] == "fixture original failure"
        assert journal["first_error"]["action"] == "fixture.first"
        assert journal["status"] == "STOPPED"
        assert not any(event["type"] in {"STEP_RESTARTED", "STEP_UP_FOR_RETRY"}
                       for event in outcome["events"])
        for name in ("child-ready", "grandchild-ready"):
            owned = read(root / f"{name}.json")
            stat = Path(f"/proc/{owned['pid']}/stat")
            assert not stat.exists() or stat.read_text().split(") ", 1)[1].split()[0] in {"Z", "X"}
        ledger = read(workspace.runs_dir / "metadata/resource-admission/leases.json")
        assert not ledger["leases"] or all(value.get("quarantine") for value in ledger["leases"].values())
        records, _ = PipelineLog(root / "safety-run").read()
        assert [item["event_type"] for item in records].count("RESOURCE_ADMITTED") == 1
        assert sum(item["event_type"] in {"RESOURCE_RELEASED", "RESOURCE_QUARANTINED"}
                   for item in records) == 1
        released = next(item for item in records if item["event_type"] in {
            "RESOURCE_RELEASED", "RESOURCE_QUARANTINED"})
        assert datetime.fromisoformat(released["timestamp"]).timestamp() >= returned["observed_ns"] / 1e9
        safety_events = [
            json.loads(line) for line in (workspace.runs_dir / "metadata/dagster-safety" /
                                         f"{outcome['run_id']}.jsonl").read_text().splitlines()]
        assert not any(item.get("event") == "ADMIT" and item.get("action") == "dagster.z_queued"
                       for item in safety_events)
        assert all(entry["status"] == "CLEANUP_UNCONFIRMED" for entry in journal["active"].values())
