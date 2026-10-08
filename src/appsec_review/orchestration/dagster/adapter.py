from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from dagster import (
    DefaultScheduleStatus,
    Definitions,
    In,
    MetadataValue,
    Nothing,
    Out,
    ScheduleDefinition,
    graph,
    multiprocess_executor,
    op,
)

from appsec_review.config import AppConfig, load_config
from appsec_review.runtime.registry import JobRegistry, builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.runtime import Job, plan_jobs
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.observability import PipelineLog
from appsec_review.storage import atomic_json

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


def _node_name(job: Job, suffix: str, namespace: str = "") -> str:
    base = f"{job.job_id.removeprefix('job_')}__{suffix.replace('.', '__')}"
    return f"{namespace}__{base}" if namespace else base


def _pool_for(unit_id: str) -> str:
    step = unit_id.split(".", 1)[0]
    if step == "validation":
        return "owasp_validator"
    if step in {"verification", "join"}:
        return "owasp_verification"
    if step in {"prepare", "configure", "compile", "catalog", "image", "probe", "execute"}:
        return "cpp_build"
    if step in {"compiled", "ast", "ir", "codeql", "joern", "binary", "provenance",
                "inspection", "deterministic", "inference"}:
        return "cpp_analysis"
    task = unit_id.rsplit(".", 1)[-1]
    if task.endswith("_scan"):
        return "ci_linter" if unit_id.startswith("ci_analysis.") else "scanner"
    if task.endswith("_index"):
        return "index"
    return "lifecycle" if unit_id.startswith("__") else "application"


def _build_dagster_graph(name: str, jobs: tuple[Job, ...], config: AppConfig,
                         runner_factory: RunnerFactory, *, node_namespace: str = "",
                         job_dependencies: Mapping[str, tuple[str, ...]] | None = None):
    plan_jobs(jobs, config)
    dependencies_by_job = dict(job_dependencies or {})
    if not dependencies_by_job:
        dependencies_by_job = {job.job_id: (() if position == 0 else (jobs[position - 1].job_id,))
                               for position, job in enumerate(jobs)}
    begin_ops = {}
    unit_ops: dict[tuple[str, str], Any] = {}
    finalize_ops = {}
    terminal_jobs = {job.job_id for job in jobs} - {
        dependency for values in dependencies_by_job.values() for dependency in values}
    for position, job in enumerate(jobs):
        begin_ins = {f"upstream_{index}": In(dict)
                     for index, _dependency in enumerate(dependencies_by_job.get(job.job_id, ())) }

        def make_begin(selected: Job, ins: Mapping[str, In]):
            @op(name=_node_name(selected, "begin", node_namespace), ins=dict(ins), out=Out(dict),
                tags={"appsec/pool": "lifecycle"}, pool="lifecycle",
                description=f"Claim and validate an application attempt for {selected.job_id}.")
            def begin(context, **inputs):
                upstream_values = [dict(value) for value in inputs.values()]
                run_ids = {str(value.get("run_id")) for value in upstream_values if value.get("run_id")}
                if len(run_ids) > 1:
                    raise ValueError("parallel upstream branches belong to different application runs")
                upstream = {
                    "run_id": next(iter(run_ids), None),
                    "handoffs": {key: digest for value in upstream_values
                                 for key, digest in dict(value.get("handoffs", {})).items()},
                    "completion_status": ("COMPLETED_WITH_GAPS" if any(
                        value.get("completion_status") == "COMPLETED_WITH_GAPS" for value in upstream_values)
                        else "SUCCEEDED"),
                    "graph_started_at": next((value.get("graph_started_at") for value in upstream_values
                                               if value.get("graph_started_at")), None),
                    "resume_decisions": [decision for value in upstream_values
                                         for decision in value.get("resume_decisions", [])],
                }
                tags = dict(context.dagster_run.tags)
                target = Path(os.environ.get(
                    "APPSEC_REVIEW_TARGET", config.runtime.repository_root / "targets" / "appsec-multi-vuln"
                )).resolve()
                target_jobs = {
                    "job_review_intake", "job_target_catalog", "job_target_analysis_plan",
                    "job_project_build", "job_language_build", "job_evidence_collection", "job_cpp_compiled_analysis",
                    "job_post_build_security_assessment", "job_owasp_control_assessment",
                    "job_ci_configuration_analysis",
                }
                uses_target = selected.job_id in target_jobs
                run_id = upstream.get("run_id") or tags.get("appsec/application_run_id")
                upstream_handoffs = dict(upstream.get("handoffs", {}))
                runner = runner_factory(config)
                begin_method = getattr(runner, "begin_or_reuse_attempt", runner.begin_attempt)
                claim = begin_method(
                    selected, run_id=run_id, trigger=_trigger_for_run(tags),
                    orchestration={"system": "dagster", "run_id": context.run_id,
                                   "node": context.op.name},
                    target_root=target if uses_target else None,
                    source_fingerprint=source_fingerprint(target) if uses_target else "none",
                    upstream_handoffs=upstream_handoffs,
                )
                claim = {**dict(claim),
                         "graph_started_at": upstream.get("graph_started_at") or claim["started_at"],
                         "prior_graph_completion_status": upstream.get("completion_status", "SUCCEEDED"),
                         "resume_decisions": [*upstream.get("resume_decisions", []), {
                             "job_id": selected.job_id,
                             "action": "reuse" if claim.get("reused") else "execute",
                         }]}
                context.instance.add_run_tags(context.run_id, {
                    "appsec/application_run_id": str(claim["run_id"]),
                    "appsec/trigger": str(claim["trigger"]),
                })
                context.add_output_metadata({"application_run_id": claim["run_id"],
                                             "application_attempt_id": claim["attempt_id"],
                                             "job_id": selected.job_id})
                return dict(claim)
            return begin
        begin_ops[job.job_id] = make_begin(job, begin_ins)

        for unit in job.units:
            dependency_ins = {dependency.replace(".", "__"): In(Nothing)
                              for dependency in unit.dependencies}
            ins = {"claim": In(dict), **dependency_ins}

            def make_unit(selected_job: Job, selected_unit, selected_ins: Mapping[str, In]):
                @op(name=_node_name(selected_job, selected_unit.unit_id, node_namespace), ins=dict(selected_ins),
                    out=Out(Nothing), tags={"appsec/pool": _pool_for(selected_unit.unit_id)},
                    pool=_pool_for(selected_unit.unit_id),
                    description=f"Execute or reuse {selected_job.job_id}.{selected_unit.unit_id}.")
                def execute(context, claim, **_dependencies):
                    correlated = {**dict(claim), "orchestration": {
                        **dict(claim.get("orchestration", {})), "node": context.op.name}}
                    output = runner_factory(config).execute_or_reuse_unit(
                        selected_job, correlated, selected_unit.unit_id)
                    context.add_output_metadata({
                        "application_run_id": claim["run_id"], "application_attempt_id": claim["attempt_id"],
                        "job_id": selected_job.job_id, "unit_id": selected_unit.unit_id,
                        "producer": output.get("tool_id", "-"),
                        "disposition": output.get("terminal_status", "SUCCEEDED"),
                        "checkpoint_reused": bool(output.get("checkpoint_reused", False)),
                        "index_reused": bool(output.get("index_reused", False)),
                        "shard": MetadataValue.json(output.get("index_identity", {})),
                        "gaps": MetadataValue.json(list(output.get("gaps", ()))[:50]),
                    })
                return execute
            unit_ops[(job.job_id, unit.unit_id)] = make_unit(job, unit, ins)

        finalize_ins = {"claim": In(dict), **{
            unit.unit_id.replace(".", "__"): In(Nothing) for unit in job.units}}

        def make_finalize(selected: Job, selected_ins: Mapping[str, In], is_last: bool):
            @op(name=_node_name(selected, "finalize", node_namespace), ins=dict(selected_ins), out=Out(dict),
                tags={"appsec/pool": "lifecycle"}, pool="lifecycle",
                description=f"Validate and publish the accepted handoff for {selected.job_id}.")
            def finalize(context, claim, **_units):
                outcome = runner_factory(config).finalize_attempt(selected, claim)
                context.instance.add_run_tags(context.run_id, {
                    f"appsec/{selected.job_id}/attempt": outcome["status"]["attempt_id"],
                    f"appsec/{selected.job_id}/status": outcome["status"]["status"],
                })
                context.add_output_metadata(_metadata_for_outcome(outcome, context.run_id))
                if is_last:
                    job_completion = str(outcome["status"]["status"])
                    completion = ("COMPLETED_WITH_GAPS" if "COMPLETED_WITH_GAPS" in {
                        str(claim.get("prior_graph_completion_status", "SUCCEEDED")), job_completion,
                    } else job_completion)
                    event = "GRAPH_COMPLETED_WITH_GAPS" if completion == "COMPLETED_WITH_GAPS" else "GRAPH_SUCCEEDED"
                    log = PipelineLog(config.runtime.runs_dir / str(outcome["status"]["run_id"]))
                    log.write(event, run_id=str(outcome["status"]["run_id"]), trigger=str(claim["trigger"]),
                              orchestrator="dagster", details={"dagster_run_id": context.run_id,
                              "completion_status": completion,
                              "duration_ms": max(0, int((datetime.now(timezone.utc) - datetime.fromisoformat(
                                  str(claim["graph_started_at"]))).total_seconds() * 1000))})
                    log.write("RUN_COMPLETED", run_id=str(outcome["status"]["run_id"]),
                              trigger=str(claim["trigger"]), orchestrator="dagster",
                              details={"dagster_run_id": context.run_id, "completion_status": completion})
                    orchestration_path = (config.runtime.runs_dir / str(outcome["status"]["run_id"]) /
                                          "data" / "orchestration" / "dagster" / f"{context.run_id}.json")
                    atomic_json(orchestration_path, {
                        "schema": "appsec-review/orchestration-receipt/1",
                        "status": "SUCCEEDED",
                        "completion_status": completion,
                        "application_run_id": str(outcome["status"]["run_id"]),
                        "orchestrator": {"system": "dagster", "run_id": context.run_id},
                        "decisions": list(claim.get("resume_decisions", [])),
                        "handoff_sha256": {
                            **dict(claim.get("upstream_handoffs", {})),
                            selected.job_id: outcome["handoff_sha256"],
                        },
                    })
                return {"run_id": outcome["status"]["run_id"],
                        "handoffs": {**dict(claim.get("upstream_handoffs", {})),
                                     selected.job_id: outcome["handoff_sha256"]},
                        "completion_status": ("COMPLETED_WITH_GAPS" if "COMPLETED_WITH_GAPS" in {
                            str(claim.get("prior_graph_completion_status", "SUCCEEDED")),
                            str(outcome["status"]["status"]),
                        } else outcome["status"]["status"]),
                        "graph_started_at": claim["graph_started_at"],
                        "resume_decisions": list(claim.get("resume_decisions", []))}
            return finalize
        finalize_ops[job.job_id] = make_finalize(job, finalize_ins, job.job_id in terminal_jobs)

    @graph(name=name)
    def generated_graph():
        finalized = {}
        for job in jobs:
            upstream_inputs = {f"upstream_{index}": finalized[dependency]
                               for index, dependency in enumerate(dependencies_by_job.get(job.job_id, ())) }
            claim = begin_ops[job.job_id](**upstream_inputs)
            values = {}
            for unit in job.units:
                dependencies = {dependency.replace(".", "__"): values[dependency]
                                for dependency in unit.dependencies}
                values[unit.unit_id] = unit_ops[(job.job_id, unit.unit_id)](
                    claim=claim, **dependencies)
            finalized[job.job_id] = finalize_ops[job.job_id](
                claim=claim, **{unit_id.replace(".", "__"): value for unit_id, value in values.items()})
        if len(terminal_jobs) != 1:
            raise ValueError(f"Dagster application graph requires one terminal job: {sorted(terminal_jobs)}")
        return finalized[next(iter(terminal_jobs))]

    executor = multiprocess_executor.configured({
        "max_concurrent": config.dagster.max_concurrent,
        "tag_concurrency_limits": [
            {"key": "appsec/pool", "value": pool, "limit": limit}
            for pool, limit in sorted(config.dagster.pool_limits.items())
        ],
    })
    return generated_graph.to_job(
        description=f"Application-owned integrity lifecycle exposed as the real {name} Dagster DAG.",
        executor_def=executor,
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
        dagster_job = _build_dagster_graph(
            job_config.name, (registry.build(job_id),), config, runner_factory,
            node_namespace="standalone",
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
    if {"job_review_intake", "job_target_catalog", "job_target_analysis_plan"} <= registered:
        wave_jobs = [registry.build("job_review_intake"), registry.build("job_target_catalog")]
        wave_dependencies: dict[str, tuple[str, ...]] = {
            "job_review_intake": (), "job_target_catalog": ("job_review_intake",),
        }
        if "job_ci_configuration_analysis" in registered:
            wave_jobs.append(registry.build("job_ci_configuration_analysis"))
            wave_dependencies["job_ci_configuration_analysis"] = ("job_target_catalog",)
        wave_jobs.append(registry.build("job_target_analysis_plan"))
        wave_dependencies["job_target_analysis_plan"] = (("job_ci_configuration_analysis",)
            if "job_ci_configuration_analysis" in registered else ("job_target_catalog",))
        if "job_project_build" in registered:
            wave_jobs.append(registry.build("job_project_build"))
            wave_dependencies["job_project_build"] = ("job_target_analysis_plan",)
        if "job_language_build" in registered:
            wave_jobs.append(registry.build("job_language_build"))
            wave_dependencies["job_language_build"] = (("job_project_build",)
                if "job_project_build" in registered else ("job_target_analysis_plan",))
        if "job_cpp_compiled_analysis" in registered:
            wave_jobs.append(registry.build("job_cpp_compiled_analysis"))
            wave_dependencies["job_cpp_compiled_analysis"] = (("job_language_build",)
                if "job_language_build" in registered else
                ("job_project_build",) if "job_project_build" in registered else ("job_target_analysis_plan",))
        if "job_post_build_security_assessment" in registered:
            wave_jobs.append(registry.build("job_post_build_security_assessment"))
            wave_dependencies["job_post_build_security_assessment"] = (("job_cpp_compiled_analysis",)
                if "job_cpp_compiled_analysis" in registered else
                ("job_project_build",) if "job_project_build" in registered else ("job_target_analysis_plan",))
        if "job_evidence_collection" in registered:
            wave_jobs.append(registry.build("job_evidence_collection"))
            wave_dependencies["job_evidence_collection"] = ("job_target_analysis_plan",)
        if "job_owasp_control_assessment" in registered:
            wave_jobs.append(registry.build("job_owasp_control_assessment"))
            build_terminal = ("job_post_build_security_assessment" if "job_post_build_security_assessment" in registered
                              else "job_cpp_compiled_analysis" if "job_cpp_compiled_analysis" in registered
                              else "job_project_build" if "job_project_build" in registered
                              else "job_target_analysis_plan")
            owasp_dependencies = [build_terminal]
            if "job_evidence_collection" in registered:
                owasp_dependencies.append("job_evidence_collection")
            wave_dependencies["job_owasp_control_assessment"] = tuple(dict.fromkeys(owasp_dependencies))
        jobs.append(_build_dagster_graph("wave1_review", tuple(wave_jobs), config, runner_factory,
                                         job_dependencies=wave_dependencies))
    if {"job_review_intake", "job_target_catalog", "job_ci_configuration_analysis"} <= registered:
        jobs.append(_build_dagster_graph(
            "ci_configuration_review",
            (registry.build("job_review_intake"), registry.build("job_target_catalog"),
             registry.build("job_ci_configuration_analysis")),
            config, runner_factory, node_namespace="ci_review",
        ))
    if {"job_review_intake", "job_target_catalog", "job_target_analysis_plan",
        "job_project_build", "job_language_build"} <= registered:
        jobs.append(_build_dagster_graph(
            "project_build_review",
            (registry.build("job_review_intake"), registry.build("job_target_catalog"),
             registry.build("job_target_analysis_plan"), registry.build("job_project_build"),
             registry.build("job_language_build")),
            config, runner_factory, node_namespace="project_build_review",
        ))
    return Definitions(jobs=jobs, schedules=schedules)
