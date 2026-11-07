"""Resumable OWASP control-assessment workbench job."""
from __future__ import annotations

from appsec_review.inference import Infer
from appsec_review.runtime import Job


def build_job(*, fail_cell: str | None = None, infer: Infer | None = None) -> Job:
    # Dataset imports must not eagerly re-enter the workbench's evidence module.
    from .job import build_job as factory
    return factory(fail_cell=fail_cell, infer=infer)

__all__ = ["build_job"]
