from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import os
from pathlib import Path
from typing import Any

from dagster import (
    DefaultScheduleStatus,
    Definitions,
    GraphDefinition,
    MetadataValue,
    Nothing,
    Out,
    ScheduleDefinition,
    in_process_executor,
    op,
)

from appsec_review.config import AppConfig, load_config
from appsec_review.runtime.registry import JobRegistry, builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.runtime import GraphRunner
from appsec_review.jobs.cataloging import source_fingerprint

RunnerFactory = Callable[[AppConfig], JobRunner]


def _trigger_for_run(tags: dict[str, str]) -> str:
    return "schedule" if "dagster/schedule_name" in tags else "manual"


def _collect_counts(value: object, prefix: str = "") -> dict[str, Any]:
    counts: dict[str, Any] = {}
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if str(key).endswith(("_count", "_counts")):
                counts[path] = child
            counts.update(_collect_counts(child, path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            counts.update(_collect_counts(child, f"{prefix}[{index}]"))
    return counts


def _metadata_for_outcome(outcome: Mapping[str, Any], dagster_run_id: str) -> dict[str, Any]:
    """Map run-owned application receipts into structured Dagster metadata."""

    status = dict(outcome["status"])
    result = dict(outcome["result"])
    attempt_root = Path(str(outcome["attempt_root"]))
    units = dict(result.get("units", {}))
    outputs = dict(result.get("outputs", {}))
    unit_statuses = {unit_id: receipt.get("status") for unit_id, receipt in units.items()}
    receipt_paths = {
        unit_id: str(
            attempt_root / "steps" / receipt["step_id"] / "tasks" / receipt["task_id"] / "status.json"
        )
        for unit_id, receipt in units.items()
    }
    publications = {
        unit_id: {
            key: output[key]
            for key in ("identity", "pointer", "metadata_path")
            if key in output
        }
        for unit_id, output in outputs.items()
        if unit_id.endswith(".publish")
    }
    metadata: dict[str, Any] = {
        "dagster_run_id": dagster_run_id,
        "application_run_id": status["run_id"],
        "application_attempt_id": status["attempt_id"],
        "application_status": status["status"],
        "trigger": status["trigger"],
        "application_status_receipt": MetadataValue.path(str(attempt_root / "status.json")),
        "application_result_receipt": MetadataValue.path(str(attempt_root / "result.json")),
        "step_statuses": MetadataValue.json(dict(result.get("steps", {}))),
        "unit_statuses": MetadataValue.json(unit_statuses),
        "unit_receipt_paths": MetadataValue.json(receipt_paths),
        "published_snapshot_identities": MetadataValue.json(publications),
        "counts": MetadataValue.json(_collect_counts(outputs)),
        "gaps": MetadataValue.json({
            "failed_units": list(result.get("failed_units", [])),
            "skipped_units": list(result.get("skipped_units", [])),
        }),
    }
    for unit_id, receipt_path in receipt_paths.items():
        metadata[f"receipt__{unit_id.replace('.', '__')}"] = MetadataValue.path(receipt_path)
    return metadata


def _dagster_job(job_id: str, name: str, config: AppConfig, registry: JobRegistry,
                 runner_factory: RunnerFactory):
    @op(
        name=f"dispatch_{job_id}",
        ins={},
        out=Out(Nothing),
        description=(
            "Execute the complete registered semantic job through JobRunner. Application task "
            "dependencies, validation, receipts, and publication remain owned by JobRunner; the "
            "task receipts are attached as structured Dagster metadata."
        ),
    )
    def dispatch(context) -> None:
        trigger = _trigger_for_run(dict(context.dagster_run.tags))
        outcome = runner_factory(config).run(
            registry.build(job_id),
            trigger=trigger,
            orchestration={"system": "dagster", "run_id": context.run_id},
        )
        status = outcome["status"]
        context.instance.add_run_tags(context.run_id, {
            "appsec/application_run_id": status["run_id"],
            "appsec/application_attempt_id": status["attempt_id"],
            "appsec/trigger": trigger,
        })
        context.add_output_metadata(_metadata_for_outcome(outcome, context.run_id))

    graph = GraphDefinition(name=name, node_defs=[dispatch])
    return graph.to_job(
        description=f"Dagster adapter for {job_id}; lifecycle ownership remains in JobRunner.",
        executor_def=in_process_executor,
    )


def _wave1_dagster_job(config: AppConfig, registry: JobRegistry):
    @op(name="dispatch_wave1_review", ins={}, out=Out(Nothing),
        description="Run the Wave 1 application graph with application-owned resume checkpoints.")
    def dispatch(context) -> None:
        target = Path(os.environ.get(
            "APPSEC_REVIEW_TARGET", config.runtime.repository_root / "targets" / "appsec-multi-vuln"
        )).resolve()
        trigger = _trigger_for_run(dict(context.dagster_run.tags))
        requested_run_id = dict(context.dagster_run.tags).get("appsec/application_run_id")
        jobs = [registry.build("job_review_intake"), registry.build("job_target_catalog")]
        if "job_evidence_collection" in registry.job_ids():
            jobs.append(registry.build("job_evidence_collection"))
        outcome = GraphRunner(config, jobs).run(
            target_root=target,
            source_fingerprint=source_fingerprint(target),
            run_id=requested_run_id,
            trigger=trigger,
            orchestration={"system": "dagster", "run_id": context.run_id},
        )
        context.instance.add_run_tags(context.run_id, {
            "appsec/application_run_id": outcome["run_id"],
            "appsec/trigger": trigger,
        })
        handoffs = {}
        attempts = {}
        receipts = {}
        application_root = config.runtime.runs_dir / outcome["run_id"]
        for job_id in outcome["jobs"]:
            pointer = json.loads((application_root / "data/jobs" / job_id / "latest.json").read_text())
            handoff = json.loads((application_root / pointer["handoff_path"]).read_text())
            handoffs[job_id] = pointer["handoff_sha256"]
            attempts[job_id] = handoff["attempt_id"]
            receipts[job_id] = str((application_root / pointer["handoff_path"]).parent)
        gaps = {job_id: value.get("result", {}).get("outputs", {}).get(
            "publish_catalog.publish_handoff", {}).get("gaps", [])
            for job_id, value in outcome["jobs"].items()}
        context.add_output_metadata({
            "dagster_run_id": context.run_id,
            "application_run_id": outcome["run_id"],
            "resume_decisions": MetadataValue.json(outcome["decisions"]),
            "handoff_identities": MetadataValue.json(handoffs),
            "attempt_identities": MetadataValue.json(attempts),
            "receipt_paths": MetadataValue.json(receipts),
            "orchestration_receipt": MetadataValue.path(outcome["orchestration_receipt"]),
            "gaps": MetadataValue.json(gaps),
        })

    return GraphDefinition(name="wave1_review", node_defs=[dispatch]).to_job(
        description="Intake then catalog through the generic application resume path.",
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
    if {"job_review_intake", "job_target_catalog"} <= registered:
        jobs.append(_wave1_dagster_job(config, registry))
    return Definitions(jobs=jobs, schedules=schedules)
