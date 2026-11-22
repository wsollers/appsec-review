from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.observability.events import PipelineLog
from appsec_review.observability.model_metrics import aggregate_model_calls
from appsec_review.observability.monitor import MonitorFollower, main, poll_run, render_report, snapshot_delta
from appsec_review.observability.monitor_inputs import freeze_run_graph, validate_graph
from appsec_review.runtime.release import digest
from appsec_review.storage import atomic_json, canonical_json

NOW = datetime(2026, 11, 22, 18, 0, tzinfo=timezone.utc)
DAGSTER = "11111111-2222-4333-8444-555555555555"


def emit(root, kind, job="-", attempt="-", **details):
    details.setdefault("dagster_run_id", DAGSTER)
    return PipelineLog(root).write(kind, run_id=root.name, job_id=job, attempt_id=attempt,
                                    orchestrator="dagster" if details["dagster_run_id"] else "application",
                                    details=details)


def timestamps(root, seconds):
    log = PipelineLog(root)
    records, _ = log.read()
    assert len(records) == len(seconds)
    for record, second in zip(records, seconds, strict=True):
        record["timestamp"] = (NOW + timedelta(seconds=second)).isoformat()
    log.path.write_bytes(b"".join(canonical_json(record) for record in records))
    return records


def configured(root, jobs=("job_a", "job_b", "job_c"), *, graph=True, dagster_run_id=DAGSTER):
    root.mkdir(exist_ok=True)
    config = {"jobs": {job: {"settings": {"enabled": True, "model": "fixture-model", "provider": "fixture"}}
                       for job in jobs}}
    config["jobs"]["job_disabled"] = {"settings": {"enabled": False}}
    payload = canonical_json(config)
    sha = hashlib.sha256(payload).hexdigest()
    directory = root / "data/configuration"
    directory.mkdir(parents=True)
    (directory / "resolved.json").write_bytes(payload)
    atomic_json(directory / "manifest.json", {
        "schema": "appsec-review/run-configuration/2", "resolved_sha256": sha,
        "selection": {"profile": "fixture-profile"}})
    release = {"schema": "appsec-review/implementation-release/1", "dependency_manifest": "a" * 64,
               "files": {}, "jobs": {job: {"implementation": "b" * 64, "validation": "c" * 64} for job in jobs},
               "scripts_sha256": "d" * 64, "environment_requirements": []}
    release["sha256"] = digest(release)
    release_payload = canonical_json(release)
    (directory / "release.json").write_bytes(release_payload)
    atomic_json(root / "data/recovery/current.json", {
        "schema": "appsec-review/implementation-binding/1", "release_sha256": release["sha256"],
        "release": {"path": "data/configuration/release.json", "sha256": hashlib.sha256(release_payload).hexdigest()}})
    emit(root, "RUN_STARTED", dagster_run_id=dagster_run_id)
    details = {"dagster_run_id": dagster_run_id}
    if graph:
        details["graph_reference"] = freeze_run_graph(root, {job: [] for job in jobs},
                                                     config_sha256=sha, dagster_run_id=dagster_run_id,
                                                     profile="fixture-profile", source_sha256=release["sha256"])
    emit(root, "GRAPH_STARTED", **details)
    return sha


def call(root, invocation, *, status="SUCCEEDED", retry=0, reused=False, usage=True,
         latency=1000, queue=20, job="job_a", role="reviewer", finish=True):
    details = {"model_invocation_id": invocation, "provider": "fixture", "model": "fixture-model",
               "role": role, "retry_count": retry, "execution_mode": "replay" if reused else "inference"}
    emit(root, "MODEL_CALL_STARTED", job, "attempt-1", **details)
    if finish:
        emit(root, "MODEL_CALL_COMPLETED", job, "attempt-1", **details, terminal_status=status,
             call_latency_ms=latency, queue_delay_ms=queue, duration_ms=latency + queue,
             input_tokens=100 if usage else None, output_tokens=20 if usage else None,
             cache_tokens=10 if usage else None, reasoning_tokens=5 if usage else None)


def test_frozen_graph_job_partition_retry_and_reused_disposition(tmp_path):
    jobs = tuple(f"job_{letter}" for letter in "abcdefgh")
    configured(tmp_path, jobs)
    emit(tmp_path, "JOB_STARTED", "job_a", "attempt-1")
    emit(tmp_path, "JOB_FAILED", "job_a", "attempt-1")
    emit(tmp_path, "JOB_STARTED", "job_a", "attempt-2")
    emit(tmp_path, "JOB_COMPLETED_WITH_GAPS", "job_a", "attempt-2")
    emit(tmp_path, "JOB_REUSED", "job_a", "attempt-2")
    emit(tmp_path, "JOB_STARTED", "job_b", "attempt-1")
    emit(tmp_path, "TASK_STARTED", "job_b", "attempt-1", unit_id="build.compile")
    emit(tmp_path, "JOB_CANCELLED", "job_c", "attempt-1")
    emit(tmp_path, "JOB_SUCCEEDED", "job_d", "attempt-1", completion_status="NOT_APPLICABLE")
    emit(tmp_path, "JOB_QUEUED", "job_e", "attempt-1")
    emit(tmp_path, "JOB_REUSED", "job_f", "attempt-1")
    emit(tmp_path, "JOB_SUCCEEDED", "job_g", "attempt-1")
    report = poll_run(tmp_path)
    state = report["state"]
    assert state["jobs"]["total"] == 8
    assert (state["jobs"]["completed"], state["jobs"]["running"], state["jobs"]["remaining"]) == (4, 1, 3)
    assert state["jobs"]["by_status"] == {
        "CANCELLED": 1, "COMPLETED_WITH_GAPS": 1, "NOT_APPLICABLE": 1, "QUEUED": 1,
        "REMAINING": 1, "REUSED_UNKNOWN": 1, "RUNNING": 1, "SUCCEEDED": 1}
    assert state["attempts"]["retry_attempts"] == 1 and state["attempts"]["reused"] == 2
    assert state["gaps"] == {"reused_completion_unavailable": 1}
    assert state["current_steps"][0]["task"] == "build.compile"
    assert report["profile"] == "fixture-profile" and report["source_sha256"]
    text = render_report(report)
    assert "8/4/1/3" in text and DAGSTER in text and tmp_path.name in text
    assert "not findings or quality assurance" in text


def test_model_statistics_overlap_retry_identity_replay_and_duplicates(tmp_path):
    call(tmp_path, "call-1", latency=1000, queue=20)
    call(tmp_path, "call-2", status="TIMED_OUT", retry=3, latency=3000, queue=40, usage=False)
    call(tmp_path, "replay", reused=True)
    records = timestamps(tmp_path, [0, 2, 1, 4, 5, 6])
    records.append({**records[1], "sequence": 7})
    metrics = aggregate_model_calls(records, complete=True)
    totals = metrics["totals"]
    assert (totals["fresh_calls"], totals["retry_calls"], totals["reused_calls"]) == (2, 1, 1)
    assert totals["statuses"] == {"SUCCEEDED": 1, "TIMED_OUT": 1}
    assert totals["call_latency"] == {"sample_count": 2, "missing_count": 0, "sum_ms": 4000,
                                     "p50_ms": 1000, "p95_ms": 3000, "max_ms": 3000}
    assert totals["queue_delay"]["p95_ms"] == 40
    assert totals["concurrent_dispatch_wall_ms"] == 4000
    assert totals["usage"]["input_tokens"] == {
        "known_sum": 100, "measured_calls": 1, "missing_calls": 1,
        "lower_bound": True, "reason": "incomplete_usage"}
    assert metrics["duplicate_records"] == 1 and metrics["hotspots"]["retries"][0]["known_value"] == 1
    assert metrics["cost"]["known_amounts"] == {} and metrics["credits"] is None


def test_unknown_usage_conflict_and_unfinished_call_never_become_zero(tmp_path):
    call(tmp_path, "unmeasured", usage=False)
    call(tmp_path, "running", finish=False)
    records, _ = PipelineLog(tmp_path).read()
    metrics = aggregate_model_calls(records, complete=False)
    totals = metrics["totals"]
    assert totals["usage"]["input_tokens"]["known_sum"] is None
    assert totals["usage"]["input_tokens"]["missing_calls"] == 2
    assert totals["statuses"] == {"RUNNING": 1, "SUCCEEDED": 1}
    assert totals["call_latency"]["missing_count"] == 1
    conflict = {**records[1], "details": {**records[1]["details"], "input_tokens": 1000}}
    metrics = aggregate_model_calls([*records, conflict], complete=True)
    assert metrics["gaps"] == {"conflicting_call_records": 1}
    assert metrics["totals"]["usage"]["input_tokens"]["known_sum"] is None


def test_actual_graph_missing_or_changed_never_uses_registry_or_config_denominator(tmp_path):
    configured(tmp_path, graph=False)
    emit(tmp_path, "JOB_SUCCEEDED", "job_a", "attempt-1")
    report = poll_run(tmp_path)
    assert report["configured_enabled_jobs"] == 3 and report["state"]["jobs"]["total"] is None
    assert "actual_run_graph_unavailable_or_invalid" in report["gaps"]
    (tmp_path / "data/configuration/resolved.json").write_text('{"jobs":{}}')
    report = poll_run(tmp_path)
    assert report["configuration_sha256"] is None
    assert "frozen_configuration_unavailable_or_invalid" in report["gaps"]


@pytest.mark.parametrize("tail,expected", [(b'{"sequence":3', "torn_tail"), (b"broken\n", "invalid_or_unreadable")],
                         ids=["torn", "malformed"])
def test_torn_and_invalid_complete_records_are_explicit_and_do_not_mutate_log(tmp_path, tail, expected):
    configured(tmp_path)
    path = PipelineLog(tmp_path).path
    with path.open("ab") as stream:
        stream.write(tail)
    before = path.read_bytes()
    report = poll_run(tmp_path)
    assert report["coverage"]["status"] == expected
    assert report["coverage"]["complete"] is False and not report["delta"]["available"]
    assert path.read_bytes() == before
    assert not (tmp_path / "data/telemetry/monitor").exists()


def test_incremental_checkpoint_bound_and_same_run_deltas(tmp_path):
    configured(tmp_path)
    call(tmp_path, "first")
    timestamps(tmp_path, [0, 0, 1, 2])
    first = poll_run(tmp_path, save=True, now=NOW + timedelta(seconds=10))
    call(tmp_path, "second", retry=1)
    timestamps(tmp_path, [0, 0, 1, 2, 11, 12])
    second = poll_run(tmp_path, save=True, now=NOW + timedelta(seconds=20))
    assert second["coverage"]["sequence"] == 6
    assert second["delta"]["fresh_calls"] == second["delta"]["retry_calls"] == 1
    assert second["delta"]["usage"]["input_tokens"] == 100
    assert snapshot_delta(second, {**first, "run_id": "different"})["reason"] == "snapshot_scope_changed"
    assert snapshot_delta(first, second)["reason"] in {"counter_reset_or_restart", "observation_clock_not_increasing"}
    path = PipelineLog(tmp_path).path
    path.unlink()
    emit(tmp_path, "RUN_STARTED")
    replaced = poll_run(tmp_path, now=datetime.now(timezone.utc) + timedelta(seconds=1))
    assert replaced["coverage"]["reset_reason"] == "log_replaced_or_truncated"
    assert not replaced["delta"]["available"]


def test_backlog_and_retention_capacity_never_claim_complete(tmp_path):
    configured(tmp_path)
    for _ in range(260):
        emit(tmp_path, "TASK_STARTED", "job_a", "attempt-1")
    report = poll_run(tmp_path, pages=1, save=True)
    assert report["coverage"]["status"] == "backlog"
    assert report["coverage"]["observed_event_count"] == 256
    assert not report["coverage"]["complete"]
    assert poll_run(tmp_path)["coverage"]["observed_event_count"] == 262
    follower = MonitorFollower(tmp_path, capacity=2)
    assert follower.poll() == "capacity_reached" and follower.cursor.sequence == 0


def test_quiet_terminal_and_missing_model_completion_are_not_invented_liveness(tmp_path):
    configured(tmp_path)
    emit(tmp_path, "JOB_STARTED", "job_a", "attempt-1")
    call(tmp_path, "unfinished", finish=False)
    records, _ = PipelineLog(tmp_path).read()
    timestamps(tmp_path, list(range(len(records))))
    report = poll_run(tmp_path, now=NOW + timedelta(hours=2))
    assert "no_recent_events_is_not_proof_of_dead_worker" in report["signals"]
    assert report["state"]["status"] == "ACTIVE_UNCONFIRMED"
    emit(tmp_path, "GRAPH_FAILED")
    report = poll_run(tmp_path)
    assert report["state"]["terminal_confirmed"]
    assert report["state"]["current"][0]["status"] == "UNCONFIRMED"
    assert report["models"]["gaps"]["missing_call_terminal_after_run_end"] == 1


def test_graph_receipt_validation_and_dagster_cross_run_binding(tmp_path):
    sha = configured(tmp_path)
    with pytest.raises(ValueError, match="cycle"):
        freeze_run_graph(tmp_path, {"job_a": ["job_b"], "job_b": ["job_a"]}, config_sha256=sha)
    with pytest.raises(ValueError, match="provenance"):
        validate_graph({"schema": "future/99"}, run_id=tmp_path.name, config_sha256=sha)
    report = poll_run(tmp_path, dagster_run_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    assert "dagster_graph_identity_mismatch" in report["gaps"]
    assert report["state"]["jobs"]["total"] is None
    ref = next((tmp_path / "data/configuration/graphs").glob("*.json"))
    ref.write_text("{}")
    assert "actual_run_graph_unavailable_or_invalid" in poll_run(tmp_path)["gaps"]


def test_cli_single_poll_json_path_and_strict_explicit_id(tmp_path, capsys):
    root = tmp_path / "example-run"
    configured(root)
    emit(root, "INCIDENTAL_LOG", "job_a", "attempt-1", opaque_payload="PRIVATE_TOOL_ARGS")
    result = main(["--runs-root", str(tmp_path), "--run-id", root.name, "--json", "--save"])
    report = json.loads(capsys.readouterr().out)
    assert result == 0 and report["run_id"] == root.name
    assert (root / "data/telemetry/monitor/snapshot.json").is_file()
    assert "PRIVATE_TOOL_ARGS" not in (root / "data/telemetry/monitor/checkpoint.json").read_text()
    assert "PRIVATE_TOOL_ARGS" not in json.dumps(report)
    assert set((root / "data/telemetry/monitor").iterdir()) == {
        root / "data/telemetry/monitor/snapshot.json", root / "data/telemetry/monitor/checkpoint.json"}
    with pytest.raises(SystemExit):
        main(["--run-id", "../latest"])
    with pytest.raises(SystemExit):
        main(["--runs-root", str(tmp_path), "--run-id", "not-created"])


def test_future_events_and_bad_snapshot_are_named(tmp_path):
    configured(tmp_path)
    timestamps(tmp_path, [10, 11])
    report = poll_run(tmp_path, now=NOW)
    assert "future_event_timestamp" in report["gaps"] and not report["coverage"]["complete"]
    atomic_json(tmp_path / "data/telemetry/monitor/snapshot.json", {"schema": "wrong"})
    report = poll_run(tmp_path, now=NOW + timedelta(seconds=20))
    assert report["delta"]["reason"] == "previous_snapshot_unavailable_or_invalid"


def test_real_graph_selection_is_bound_before_handlers_and_retained_on_failure(tmp_path):
    from appsec_review.runtime import GraphRunner, Job, Unit
    from tests.test_repair_admission import fixture

    config, _, _ = fixture(tmp_path, ("job_a", "job_b"))
    seen = []

    def fail(unit):
        report = poll_run(unit.job.run_root)
        seen.append(report)
        assert report["state"]["jobs"]["total"] == 2
        assert report["source_sha256"] and report["configuration_sha256"] == config.resolved_sha256
        raise ValueError("fixture failure")

    jobs = [Job("job_a", "job_a", fail, units=(Unit("work.only", fail),)),
            Job("job_b", "job_b", lambda _: {}, units=(Unit("work.only", lambda _: {}),))]
    with pytest.raises(Exception, match="fixture failure|failed"):
        GraphRunner(config, jobs, dependencies={"job_a": (), "job_b": ("job_a",)}).run(
            target_root=tmp_path, source_fingerprint="none")
    assert len(seen) == 1
    root = config.runtime.runs_dir / seen[0]["run_id"]
    graph = json.loads(next((root / "data/configuration/graphs").glob("*.json")).read_bytes())
    assert graph["jobs"] == {"job_a": [], "job_b": ["job_a"]}
    assert graph["profile"] == config.profile
    final = poll_run(root)
    assert final["state"]["status"] == "FAILED" and final["state"]["jobs"]["remaining"] == 1


def test_dagster_selection_metadata_is_deterministic_and_config_bound(tmp_path):
    from appsec_review.observability.monitor_inputs import record_graph_selection
    from tests.test_repair_admission import fixture

    config, _, _ = fixture(tmp_path)
    root = tmp_path / "metadata-run"
    # The driver can retain selection before an admitted attempt creates configuration receipts.
    selection = {"job_fixture": ()}
    first = record_graph_selection(config, root, selection, dagster_run_id=DAGSTER)
    second = record_graph_selection(config, root, selection, dagster_run_id=DAGSTER)
    assert first == second
    document = json.loads((root / first["path"]).read_bytes())
    assert document["dagster_run_id"] == DAGSTER
    assert document["resolved_config_sha256"] == config.resolved_sha256
    assert document["source_sha256"]
    events, _ = PipelineLog(root).read()
    assert all(event["event_type"] == "RUN_GRAPH_SNAPSHOT" for event in events)
    assert all(event["details"]["graph_reference"] == first for event in events)


def test_submitted_dagster_subset_does_not_claim_the_full_compiled_graph(tmp_path):
    from appsec_review.config import load_config
    from appsec_review.orchestration.dagster.adapter import _build_dagster_graph, _monitor_job_selection
    from appsec_review.runtime import JobRunner
    from tests.test_repair_admission import fixture

    config, jobs, _ = fixture(tmp_path, ("job_a", "job_b"))
    with config.source_path.open("a") as stream:
        for job in jobs:
            stream.write(f"\n[jobs.{job.job_id}.steps.work.tasks.only]\nworkers = 1\n")
    config = load_config(config.source_path)
    dependencies = {"job_a": (), "job_b": ("job_a",)}
    definition = _build_dagster_graph("monitor_fixture", jobs, config, JobRunner,
                                     job_dependencies=dependencies)
    assert _monitor_job_selection(definition, None, jobs, dependencies, "") == (dependencies, ())
    subset = definition.get_subset(op_selection=["a__begin"])
    selected, partial = _monitor_job_selection(subset, None, jobs, dependencies, "")
    assert selected == {"job_a": ()} and partial == ("job_a",)
    assert _monitor_job_selection(definition, ["a__work__only"], jobs, dependencies, "") == (selected, partial)
    configured(tmp_path / "partial", jobs=("job_a", "job_b"), graph=False)
    root = tmp_path / "partial"
    config_sha = json.loads((root / "data/configuration/manifest.json").read_bytes())["resolved_sha256"]
    ref = freeze_run_graph(root, selected, config_sha256=config_sha, partial_jobs=partial, dagster_run_id=DAGSTER)
    emit(root, "RUN_GRAPH_SNAPSHOT", graph_reference=ref)
    report = poll_run(root)
    assert report["state"]["jobs"]["total"] is None
    assert "partial_job_op_selection_has_no_whole_job_denominator" in report["gaps"]


def test_standalone_monitor_prompt_runs_documented_command_without_current_profile(tmp_path, capsys):
    import re
    import shlex

    repository = Path(__file__).resolve().parents[1]
    skill = (repository / ".claude/skills/monitor-review-run/SKILL.md").read_text()
    prompt = skill.split("## Standalone kickoff prompt", 1)[1].split("## Poll discipline", 1)[0]
    root = tmp_path / "prompt-run"
    configured(root)
    command = re.search(r"`(\.venv/bin/python -m appsec_review\.observability\.monitor [^`]+)`", prompt)[1]
    command = command.replace("<RUNS_ROOT>", str(tmp_path)).replace("<EXACT_APP_RUN_ID>", root.name)
    command = command.replace("<EXACT_DAGSTER_UUID>", DAGSTER)
    assert main(shlex.split(command)[3:]) == 0
    output = capsys.readouterr().out
    assert root.name in output and DAGSTER in output and "fixture-profile" in output
    assert (root / "data/telemetry/monitor/snapshot.json").is_file()
    # The standalone prompt binds the repeat and terminal paths to the same host session, not a shell loop.
    assert 'save_session_automation(interval="minutes", every_minutes=5, prompt=<this complete kickoff>)' in prompt
    assert "get_session_automation" in prompt and "save_session_automation(clear=true)" in prompt
    assert "every 5 minutes" in prompt and "automatic five-minute polling is unavailable" in prompt
    assert "<SOURCE_SHA256>" in prompt and "<FREEZE_OWNER_AND_TERMS>" in prompt
