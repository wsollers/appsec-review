"""Run telemetry report: one end-of-review rollup of a run's telemetry, runtimes and metrics.

``telemetry_document`` reads a run directory read-only and builds a renderer-neutral
:class:`~appsec_review.reporting.model.Document`: the whole-run overview first (Part I), per-job
supporting detail after it (Part II), provenance last. ``render_latex`` turns it into LaTeX for the
``tool-report-latex`` image. Telemetry is observational process data, never security evidence.
"""
from __future__ import annotations

from pathlib import Path

from ..model import Document
from .inputs import STATUS_TONE, JobSpan, TelemetryInputs, load_inputs
from .jobs import job_sections
from .overview import appendix_sections, overview_sections

RENDERER = "appsec-review-telemetry-report/1"
TITLE = "Review run telemetry"


def build_document(inputs: TelemetryInputs) -> Document:
    blocks = (*overview_sections(inputs), *job_sections(inputs), *appendix_sections(inputs))
    return Document(
        title=TITLE, run_id=inputs.run_id,
        subtitle="Runtimes, throughput, model and tool usage, and data quality for one review run",
        status_badge=inputs.completion_status, status_tone=STATUS_TONE[inputs.completion_status],
        source_date_epoch=inputs.source_date_epoch,
        ledger_head=inputs.summary_sha256 or "unavailable", head_label="metrics summary sha256",
        blocks=blocks, named_gaps=inputs.named_gaps, renderer=RENDERER)


def telemetry_document(run_dir: Path) -> Document:
    return build_document(load_inputs(Path(run_dir)))


__all__ = ["RENDERER", "JobSpan", "TelemetryInputs", "build_document", "load_inputs", "telemetry_document"]
