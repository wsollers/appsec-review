from __future__ import annotations

from pathlib import Path

import pytest

dagster = pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions
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
    calls: list[str] = []

    class Runner:
        def __init__(self, config):
            self.config = config

        def run(self, job, *, trigger):
            calls.append(trigger)
            return {
                "status": {
                    "run_id": "test-run",
                    "attempt_id": "attempt_0001",
                    "trigger": trigger,
                },
                "attempt_root": str(tmp_path / "attempt"),
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
    assert calls == ["manual", "schedule"]


def test_definitions_reject_registry_config_drift(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing_config=.*job_fixture"):
        build_definitions(_config(tmp_path, configured_job="job_other"), registry=_registry())
