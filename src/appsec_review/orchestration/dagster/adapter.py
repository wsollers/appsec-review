from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path

from dagster import (
    DefaultScheduleStatus,
    Definitions,
    GraphDefinition,
    Nothing,
    Out,
    ScheduleDefinition,
    in_process_executor,
    op,
)

from appsec_review.config import AppConfig, load_config
from appsec_review.runtime.registry import JobRegistry, builtin_registry
from appsec_review.runtime.runner import JobRunner

RunnerFactory = Callable[[AppConfig], JobRunner]


def _trigger_for_run(tags: dict[str, str]) -> str:
    return "schedule" if "dagster/schedule_name" in tags else "manual"


def _dagster_job(job_id: str, name: str, config: AppConfig, registry: JobRegistry,
                 runner_factory: RunnerFactory):
    @op(
        name=f"dispatch_{job_id}",
        ins={},
        out=Out(Nothing),
        description="Dispatch the registered semantic job through JobRunner.",
    )
    def dispatch(context) -> None:
        outcome = runner_factory(config).run(
            registry.build(job_id),
            trigger=_trigger_for_run(dict(context.dagster_run.tags)),
        )
        status = outcome["status"]
        context.add_output_metadata(
            {
                "run_id": status["run_id"],
                "attempt_id": status["attempt_id"],
                "trigger": status["trigger"],
                "attempt_root": outcome["attempt_root"],
            }
        )

    graph = GraphDefinition(name=name, node_defs=[dispatch])
    return graph.to_job(
        description=f"Dagster adapter for {job_id}; lifecycle ownership remains in JobRunner.",
        executor_def=in_process_executor,
    )


def build_definitions(
    config_path: str | Path | None = None,
    *,
    registry: JobRegistry | None = None,
    runner_factory: RunnerFactory = JobRunner,
) -> Definitions:
    """Build Dagster definitions from the typed config and semantic job registry."""

    source = config_path or os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")
    config = load_config(source)
    registry = registry or builtin_registry()
    registered = set(registry.job_ids())
    configured = set(config.jobs)
    if registered != configured:
        missing_config = sorted(registered - configured)
        missing_registration = sorted(configured - registered)
        raise ValueError(
            "Dagster job/config mismatch: "
            f"missing_config={missing_config}, missing_registration={missing_registration}"
        )

    jobs = []
    schedules = []
    for job_id in registry.job_ids():
        job_config = config.job(job_id)
        dagster_job = _dagster_job(
            job_id, job_config.name, config, registry, runner_factory
        )
        jobs.append(dagster_job)
        if job_config.schedule is not None:
            schedule = job_config.schedule
            schedules.append(
                ScheduleDefinition(
                    name=f"{job_config.name}_schedule",
                    job=dagster_job,
                    cron_schedule=schedule.cron,
                    execution_timezone=schedule.timezone,
                    default_status=(
                        DefaultScheduleStatus.RUNNING
                        if schedule.enabled
                        else DefaultScheduleStatus.STOPPED
                    ),
                )
            )
    return Definitions(jobs=jobs, schedules=schedules)
