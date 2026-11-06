"""Shared scheduling and immutable input projections for local and Dagster drivers."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from appsec_review.runtime.job import Job
from appsec_review.orchestration.topology import (
    WAVE1_REQUIRED, enabled_wave1_dependencies, upstream_closure, wave1_dependencies,
)


def graph_dependencies(jobs: Sequence[Job],
                       explicit: Mapping[str, Sequence[str]] | None = None) -> dict[str, tuple[str, ...]]:
    ids = {job.job_id for job in jobs}
    if explicit is not None:
        result = {key: tuple(value) for key, value in explicit.items()}
    else:
        if WAVE1_REQUIRED <= ids:
            from appsec_review.runtime.registry import builtin_registry
            result = enabled_wave1_dependencies(ids, set(builtin_registry().job_ids()))
        else:
            result = wave1_dependencies(ids)
        if result is None:
            # Small public graphs historically used declaration order. Explicit consumes edges
            # take precedence; callers with an independent synthetic DAG can pass explicit edges.
            declared = any(set(job.consumes) & ids for job in jobs)
            result = {
                job.job_id: tuple(dep for dep in job.consumes if dep in ids) if declared else
                (() if index == 0 else (jobs[index - 1].job_id,))
                for index, job in enumerate(jobs)
            }
    if set(result) != ids:
        raise ValueError("dependency graph differs from enabled job selection")
    seen: set[str] = set()
    for job in jobs:
        if not set(result[job.job_id]) <= seen:
            raise ValueError(f"unknown, cyclic or unordered dependencies for {job.job_id}")
        seen.add(job.job_id)
    return result


def input_projection(job_id: str, upstream: Mapping[str, str],
                     dependencies: Mapping[str, Sequence[str]],
                     propagating: set[str]) -> dict[str, str]:
    return {key: upstream[key] for key in upstream_closure(job_id, dependencies, propagating)
            if key in upstream}


def force_selected(job_id: str, force_from: str | None, dependencies: Mapping[str, Sequence[str]]) -> bool:
    if force_from is not None and force_from not in dependencies:
        raise ValueError(f"cannot force a disabled or absent graph job: {force_from}")
    return force_from is not None and force_from in {
        job_id, *upstream_closure(job_id, dependencies, set(dependencies))}
