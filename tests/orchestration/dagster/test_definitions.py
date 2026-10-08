from __future__ import annotations

from pathlib import Path

import pytest

dagster = pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions
from appsec_review.orchestration.dagster.adapter import _metadata_for_outcome
from appsec_review.runtime import Job
from appsec_review.runtime.registry import JobRegistry


def _config(root: Path, *, configured_job: str = "job_fixture") -> Path:
    path = root / "appsec-review.toml"
    path.write_text(
        f"""
[runtime]
runs_dir = "runs"
data_dir = "data"

[jobs.{configured_job}]
name = "fixture"
workers = 1

[jobs.{configured_job}.schedule]
enabled = true
cron = "15 2 * * *"
timezone = "UTC"
""".strip(),
        encoding="utf-8",
    )
    return path


def _registry() -> JobRegistry:
    registry = JobRegistry()
    registry.register("job_fixture", lambda: Job("job_fixture", "fixture", lambda context: {}))
    return registry


def test_definitions_discover_registry_and_configure_schedule(tmp_path: Path) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    class Runner:
        def __init__(self, config):
            self.config = config

        def run(self, job, *, trigger, orchestration):
            calls.append((trigger, orchestration))
            return {
                "status": {
                    "run_id": "test-run",
                    "attempt_id": "attempt_0001",
                    "trigger": trigger,
                    "status": "SUCCEEDED",
                },
                "attempt_root": str(tmp_path / "attempt"),
                "result": {
                    "status": "SUCCEEDED",
                    "steps": {},
                    "units": {},
                    "outputs": {},
                    "failed_units": [],
                    "skipped_units": [],
                },
            }

    definitions = build_definitions(
        _config(tmp_path), registry=_registry(), runner_factory=Runner
    )
    job = definitions.get_job_def("fixture")
    schedule = definitions.get_schedule_def("fixture_schedule")

    assert schedule.cron_schedule == "15 2 * * *"
    assert schedule.execution_timezone == "UTC"
    assert schedule.default_status is dagster.DefaultScheduleStatus.RUNNING
    assert schedule.job_name == "fixture"

    assert job.execute_in_process().success
    assert job.execute_in_process(tags={"dagster/schedule_name": schedule.name}).success
    assert [trigger for trigger, _ in calls] == ["manual", "schedule"]
    assert all(correlation["system"] == "dagster" for _, correlation in calls)
    assert all(correlation["run_id"] for _, correlation in calls)


def test_definitions_reject_registry_config_drift(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing_config=.*job_fixture"):
        build_definitions(_config(tmp_path, configured_job="job_other"), registry=_registry())


def test_application_failure_fails_dagster_run(tmp_path: Path) -> None:
    class Runner:
        def __init__(self, config):
            pass

        def run(self, job, *, trigger, orchestration):
            raise RuntimeError("application terminal failure")

    definitions = build_definitions(
        _config(tmp_path), registry=_registry(), runner_factory=Runner
    )
    result = definitions.get_job_def("fixture").execute_in_process(raise_on_error=False)
    assert not result.success
    assert any("application terminal failure" in str(event.event_specific_data)
               for event in result.all_node_events if event.is_step_failure)


def test_metadata_maps_units_snapshots_counts_gaps_and_receipts(tmp_path: Path) -> None:
    attempt = tmp_path / "runs" / "test-run" / "attempt_0001"
    outcome = {
        "status": {
            "run_id": "test-run",
            "attempt_id": "attempt_0001",
            "trigger": "manual",
            "status": "SUCCEEDED",
        },
        "attempt_root": str(attempt),
        "result": {
            "steps": {"nvd_sync": "SUCCEEDED"},
            "units": {
                "nvd_sync.publish": {
                    "step_id": "nvd_sync", "task_id": "publish", "status": "SUCCEEDED"
                }
            },
            "outputs": {
                "nvd_sync.publish": {
                    "identity": {"snapshot_id": "sha256-example", "record_count": 42},
                    "metadata_path": "/metadata/nvd.json",
                }
            },
            "failed_units": [],
            "skipped_units": [],
        },
    }
    metadata = _metadata_for_outcome(outcome, "dagster-run")

    assert metadata["application_run_id"] == "test-run"
    assert metadata["unit_statuses"].data == {"nvd_sync.publish": "SUCCEEDED"}
    assert metadata["published_snapshot_identities"].data["nvd_sync.publish"]["identity"]["snapshot_id"] == "sha256-example"
    assert metadata["counts"].data == {
        "nvd_sync.publish.identity.record_count": 42,
    }
    assert metadata["gaps"].data == {"failed_units": [], "skipped_units": []}
    assert metadata["receipt__nvd_sync__publish"].path.endswith(
        "steps/nvd_sync/tasks/publish/status.json"
    ) or metadata["receipt__nvd_sync__publish"].path.endswith(
        "steps\\nvd_sync\\tasks\\publish\\status.json"
    )


def test_production_schedule_is_midnight_utc_and_enabled() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    definitions = build_definitions(config)
    schedule = definitions.get_schedule_def("third_party_data_sync_schedule")

    assert schedule.cron_schedule == "0 0 * * *"
    assert schedule.execution_timezone == "UTC"
    assert schedule.default_status is dagster.DefaultScheduleStatus.RUNNING
    assert definitions.get_job_def("third_party_data_sync").name == "third_party_data_sync"
    assert definitions.get_job_def("review_intake").name == "review_intake"
    assert definitions.get_job_def("target_catalog").name == "target_catalog"
    assert definitions.get_job_def("wave1_review").name == "wave1_review"


def test_wave1_dagster_path_runs_application_graph(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    result = build_definitions(config).get_job_def("wave1_review").execute_in_process()
    assert result.success
    assert result.output_for_node("dispatch_wave1_review") is None
