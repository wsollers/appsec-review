"""Part I of the run telemetry report: the whole-run overview, and the closing appendix.

Owned by chunk A1. Contract: pure, deterministic functions of :class:`TelemetryInputs`, returning
renderer-neutral blocks; every string passes through ``reporting.text`` cleaning/bounding.
"""
from __future__ import annotations

from ..model import Block
from .inputs import TelemetryInputs


def overview_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Executive summary, run timeline, where the time went, run-wide usage, data quality."""
    return ()


def appendix_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Provenance (summary / event-log hashes and sources) and how to read the report."""
    return ()
