"""Declared per-test time budgets for the integration and live tiers.

Each integration or live test has a budget: the tier default from the pytest ini option, or a
reviewed exception declared with ``@pytest.mark.time_budget(seconds, reason=...)``. A test whose
own setup and call, or setup, call and teardown, exceed it fails with the measured and declared
times. The check is made after the phase ends; commands inside a test keep their own hard
timeouts, so a hung test is still stopped by those, not by this budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import pytest


# Defaults, also written out in pyproject.toml so they are visible and overridable with
# ``-o <name>=<seconds>``. Integration: a Docker probe plus one bounded build or tool command,
# whose own timeouts are 60-180 s. Live: one CodeQL database (900 s cap) plus its query run.
TIER_INI_OPTIONS: Mapping[str, str] = {
    "integration": "integration_time_budget_seconds",
    "live": "live_time_budget_seconds",
}
DEFAULT_TIER_BUDGETS: Mapping[str, float] = {"integration": 300.0, "live": 1800.0}
MARKER = "time_budget"
MARKER_HELP = (f"{MARKER}(seconds, reason): a reviewed per-test time budget that replaces the tier default; "
               "the reason is required")


@dataclass(frozen=True)
class TimeBudget:
    seconds: float
    source: str


def tier_of(path: Path, tests_root: Path) -> str | None:
    """``integration`` or ``live`` for a test file in those tiers, else ``None``."""
    try:
        relative = Path(path).resolve().relative_to(tests_root.resolve())
    except ValueError:
        return None
    if not relative.parts:
        return None
    if relative.parts[0] == "integration":
        return "integration"
    if relative.parts[0] == "live" or (len(relative.parts) == 1 and relative.name.startswith("test_live_")):
        return "live"
    return None


def parse_seconds(value: Any, *, where: str) -> float:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        raise pytest.UsageError(f"{where} must be a number of seconds; received {value!r}") from None
    if not seconds > 0 or seconds == float("inf"):
        raise pytest.UsageError(f"{where} must be a positive, finite number of seconds; received {value!r}")
    return seconds


def tier_budgets(getini) -> dict[str, float]:
    return {tier: parse_seconds(getini(name), where=f"ini option {name}") for tier, name in TIER_INI_OPTIONS.items()}


def budget_for(nodeid: str, tier: str | None, marker: Any, budgets: Mapping[str, float]) -> TimeBudget | None:
    """The budget that applies to one test: its declared exception, else its tier default."""
    if marker is not None:
        if len(marker.args) != 1 or set(marker.kwargs) != {"reason"}:
            raise pytest.UsageError(f"{nodeid}: use @pytest.mark.{MARKER}(seconds, reason='...')")
        reason = marker.kwargs["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise pytest.UsageError(f"{nodeid}: @pytest.mark.{MARKER} needs a non-empty reason")
        seconds = parse_seconds(marker.args[0], where=f"{nodeid}: @pytest.mark.{MARKER} seconds")
        return TimeBudget(seconds, f"declared exception: {reason.strip()}")
    if tier in budgets:
        return TimeBudget(budgets[tier], f"{tier} default {TIER_INI_OPTIONS[tier]}")
    return None


def overrun(budget: TimeBudget, elapsed: float, phases: str) -> str | None:
    if elapsed <= budget.seconds:
        return None
    return (f"time budget exceeded: {phases} took {elapsed:.1f}s, budget {budget.seconds:g}s ({budget.source}). "
            f"Make the test faster or narrower, or declare a reviewed exception with "
            f"@pytest.mark.{MARKER}(seconds, reason=...); never raise a budget only to make a test pass.")


class PhaseClock:
    """Accumulates one test's phase durations and fails the first phase that crosses its budget."""

    def __init__(self, budget: TimeBudget) -> None:
        self.budget = budget
        self.elapsed = 0.0
        self.failed = False

    def observe(self, report: pytest.TestReport) -> None:
        self.elapsed += report.duration
        if report.failed:
            self.failed = True
        if self.failed or report.when not in {"call", "teardown"} or not report.passed:
            return
        phases = "setup and call" if report.when == "call" else "setup, call and teardown"
        message = overrun(self.budget, self.elapsed, phases)
        if message is not None:
            report.outcome = "failed"
            report.longrepr = message
            self.failed = True
