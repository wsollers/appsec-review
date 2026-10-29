"""Part II of the run telemetry report: one supporting-detail section per job attempt.

Owned by chunk A2. Contract: pure, deterministic functions of :class:`TelemetryInputs`, returning
renderer-neutral blocks; every string passes through ``reporting.text`` cleaning/bounding.
"""
from __future__ import annotations

from ..model import Block
from .inputs import TelemetryInputs


def job_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Per job, in ``inputs.jobs`` order: status, timings, model/tool use, subsystem metrics, gaps."""
    return ()
