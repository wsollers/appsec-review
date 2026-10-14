"""Configuration-driven selection of optional semantic jobs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from appsec_review.config import AppConfig


def job_is_enabled(config: AppConfig, job_id: str) -> bool:
    """Return whether a configured job belongs in an execution graph.

    Jobs without a job-level ``settings.enabled`` key are enabled. Nested feature flags do not
    affect dispatch of their containing job.
    """

    settings = config.job(job_id).settings
    if "enabled" not in settings:
        return True
    value = settings["enabled"]
    if not isinstance(value, bool):
        raise ValueError(f"jobs.{job_id}.settings.enabled must be a boolean")
    return value


def active_job_ids(config: AppConfig, job_ids: Iterable[str]) -> tuple[str, ...]:
    """Preserve order while removing optional jobs disabled by configuration."""

    return tuple(job_id for job_id in job_ids if job_is_enabled(config, job_id))


def resolved_job_is_enabled(job_id: str, job: Mapping[str, Any]) -> bool:
    """Apply the same selection rule to an immutable resolved configuration entry."""

    settings = job.get("settings") or {}
    if not isinstance(settings, Mapping) or "enabled" not in settings:
        return True
    value = settings["enabled"]
    if not isinstance(value, bool):
        raise ValueError(f"jobs.{job_id}.settings.enabled must be a boolean")
    return value
