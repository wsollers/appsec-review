"""The one way a job attempt is started, executed and validated, whatever drives it.

The Dagster ``begin`` op and the local ``appsec-review run`` command both derive a job's inputs
with :func:`launch_inputs` and claim the attempt with :func:`begin`. Each unit then runs through
``JobRunner.execute_or_reuse_unit`` and the attempt is published by ``JobRunner.finalize_attempt``.
Dagster schedules the units as parallel ops; :func:`launch` runs them in process, in dependency
order. Only scheduling differs between the two drivers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any

from appsec_review.runtime.job import Job

# Jobs that read the target checkout. Every other job receives no target root and the "none"
# source fingerprint, so its identity does not depend on the target. The inference review, the gate, the PoC
# job and the report are deliberately absent: they read accepted run state only (the PoC job copies the
# run's hash-verified native build workspace, not the target).
TARGET_JOBS = frozenset({
    "job_review_intake", "job_target_catalog", "job_target_analysis_plan",
    "job_project_build", "job_language_build", "job_artifact_indexing", "job_test_coverage",
    "job_profile_data",
    "job_artifact_security_analysis", "job_evidence_collection", "job_dependency_intelligence",
    "job_cpp_compiled_analysis",
    "job_clang_static_analysis", "job_svf_alias_analysis", "job_sanitizer_build",
    "job_cpp_symbol_index", "job_cpg_analysis", "job_codeql_analysis", "job_code_graph_index",
    "job_post_build_security_assessment", "job_owasp_control_assessment",
    "job_ci_configuration_analysis", "job_tree_sitter_ast", "job_source_history_analysis",
    "job_change_context_analysis", "job_review_prioritization", "job_security_tagging",
    "job_review_data_indexing", "job_review_package_assembly", "job_document_issue_analysis",
})
TARGET_ENVIRONMENT = "APPSEC_REVIEW_TARGET"


@dataclass(frozen=True)
class LaunchInputs:
    """What an attempt is claimed with: the target it reads and the upstream handoffs it binds."""

    target_root: Path | None
    source_fingerprint: str
    upstream_handoffs: Mapping[str, str] = field(default_factory=dict)


def configured_target(repository_root: Path) -> Path:
    """The target a launch reviews: ``APPSEC_REVIEW_TARGET``, else the repository's default corpus."""

    return Path(os.environ.get(TARGET_ENVIRONMENT, Path(repository_root) / "targets" / "appsec-multi-vuln")).resolve()


def launch_inputs(job: Job, *, target: Path, upstream_handoffs: Mapping[str, str]) -> LaunchInputs:
    from appsec_review.jobs.cataloging import source_fingerprint

    if job.job_id not in TARGET_JOBS:
        return LaunchInputs(None, "none", dict(upstream_handoffs))
    target = Path(target).resolve()
    return LaunchInputs(target, source_fingerprint(target), dict(upstream_handoffs))


def begin(runner: Any, job: Job, inputs: LaunchInputs, *, run_id: str | None, trigger: str,
          orchestration: Mapping[str, str]) -> Mapping[str, Any]:
    """Claim (or reuse) the attempt exactly as every driver does."""

    begin_method = getattr(runner, "begin_or_reuse_attempt", runner.begin_attempt)
    return begin_method(job, run_id=run_id, trigger=trigger, orchestration=dict(orchestration),
                        target_root=inputs.target_root, source_fingerprint=inputs.source_fingerprint,
                        upstream_handoffs=dict(inputs.upstream_handoffs))


def unit_order(job: Job) -> tuple[str, ...]:
    """The job's units in declaration order, each after every unit it depends on."""

    units = {unit.unit_id: unit for unit in job.units}
    ordered: list[str] = []
    state: dict[str, str] = {}

    def visit(unit_id: str) -> None:
        if state.get(unit_id) == "done":
            return
        if state.get(unit_id) == "active":
            raise ValueError(f"unit dependency cycle in {job.job_id} at {unit_id}")
        if unit_id not in units:
            raise ValueError(f"unit declares an unknown dependency: {unit_id}")
        state[unit_id] = "active"
        for dependency in units[unit_id].dependencies:
            visit(dependency)
        state[unit_id] = "done"
        ordered.append(unit_id)

    for unit in job.units:
        visit(unit.unit_id)
    return tuple(ordered)


def complete(runner: Any, job: Job, claim: Mapping[str, Any]) -> Mapping[str, Any]:
    """Execute every unit of a claimed attempt in dependency order, then finalize it.

    As in Dagster, a failed unit does not stop independent units; only the units that depend on
    it are skipped, and the job is not finalized. The attempt is then marked FAILED and a
    ``job reported partial failure`` error names the failed units, caused by the first failure.
    """

    units = {unit.unit_id: unit for unit in job.units}
    blocked: set[str] = set()
    failed: list[str] = []
    first: Exception | None = None
    for unit_id in unit_order(job):
        if blocked & set(units[unit_id].dependencies):
            blocked.add(unit_id)
            continue
        try:
            runner.execute_or_reuse_unit(job, claim, unit_id)
        except Exception as exc:  # noqa: BLE001 - recorded on the unit's receipt; raised below
            blocked.add(unit_id)
            failed.append(unit_id)
            first = first or exc
    if first is not None:
        error = RuntimeError(f"job reported partial failure: {', '.join(failed)}: {first}")
        error.__cause__ = first
        if not claim.get("reused"):
            runner.fail_attempt(job, claim, error)
        raise error
    return runner.finalize_attempt(job, claim)


def launch(runner: Any, job: Job, inputs: LaunchInputs, *, run_id: str | None, trigger: str = "manual",
           orchestration: Mapping[str, str] | None = None) -> Mapping[str, Any]:
    """Begin (or reuse), execute and finalize one attempt in process, as Dagster does with ops."""

    claim = begin(runner, job, inputs, run_id=run_id, trigger=trigger,
                  orchestration=orchestration or {"system": "local"})
    return complete(runner, job, claim)
