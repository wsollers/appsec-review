"""Best-effort end-of-review telemetry report, called once a run's terminal status and metrics exist.

``finalize_telemetry_report`` never raises an ``Exception``, never writes ``pipeline.jsonl`` and never
changes a completion status: a renderer error is logged as one warning naming the exception type and
the run keeps the status it already has. Rendering may take up to ``settings.timeout_seconds``.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from appsec_review.config.telemetry_report import TelemetryReportSettings
from .telemetry_render import TelemetryReportReceipt, render_telemetry_report

LOGGER = logging.getLogger(__name__)
Renderer = Callable[..., TelemetryReportReceipt]


def finalize_telemetry_report(run_root: Path, settings: TelemetryReportSettings, *,
                              repository_root: Path | None = None,
                              renderer: Renderer | None = None) -> TelemetryReportReceipt | None:
    """Render ``run_root``'s telemetry report; ``None`` when disabled or when rendering raised."""
    if not settings.enabled:
        return None
    try:
        return (renderer or render_telemetry_report)(Path(run_root), settings, repository_root=repository_root)
    except Exception as exc:  # the report is advisory; it must never fail or delay run completion
        LOGGER.warning("telemetry report for run %s was not produced: %s", Path(run_root).name, type(exc).__name__)
        return None


__all__ = ["finalize_telemetry_report"]
