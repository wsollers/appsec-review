"""Run-wide job budget counters for the inference security review.

The counters live in one JSON document under the run's data directory and change only under a
kernel file lock, so the lane units (separate processes) and their worker threads share one
budget. A finite ``budget_team_packages`` and the turn, token, query, and wall-clock ceilings are hard job
limits: reaching any of them stops new launches for the rest of the run, and every package still
queued ends ``not_launched`` with a ``budget_gap`` (design: "Budgets", R8).
``budget_team_packages = "all"`` removes only the package-count ceiling.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import threading
import time
from typing import Any, Mapping

from appsec_review.config.inference_review import BudgetSettings
from appsec_review.review.models import Lane
from appsec_review.storage import atomic_json, bounded_file_lock


BUDGET_SCHEMA = "appsec-review/inference-review-budget/1"
BUDGET_DIRECTORY = Path("data") / "jobs" / "job_inference_security_review" / "budget"
USAGE_COUNTERS = ("model_turns", "input_tokens", "output_tokens", "retrieval_queries")
# Usage counter -> the job ceiling that bounds it, in the order exhaustion is reported.
_CEILINGS = (("model_turns", "max_model_turns"), ("input_tokens", "max_input_tokens"),
             ("output_tokens", "max_output_tokens"), ("retrieval_queries", "max_retrieval_queries"))


@dataclass(frozen=True, slots=True)
class BudgetSnapshot:
    team_packages: Mapping[str, int]     # per lane value
    model_turns: int
    input_tokens: int
    output_tokens: int
    retrieval_queries: int
    started_at: float
    exhausted: str | None                # the first ceiling reached, or None


class JobBudget:
    """Persisted, lock-protected job budget; see :meth:`reserve`, :meth:`charge`, :meth:`not_launched`."""

    def __init__(self, root: Path, limits: BudgetSettings, *, lock_timeout_seconds: int = 60,
                 clock: Callable[[], float] = time.time) -> None:
        self.root = Path(root)
        self.limits = limits
        self.state_path = self.root / "budget.json"
        self.lock_path = self.root / "budget.lock"
        self.lock_timeout_seconds = lock_timeout_seconds
        self.clock = clock
        self._thread_lock = threading.Lock()
        self._transact(lambda state: None)

    @classmethod
    def for_run(cls, run_root: Path, limits: BudgetSettings, **kwargs: Any) -> "JobBudget":
        return cls(Path(run_root) / BUDGET_DIRECTORY, limits, **kwargs)

    def _transact(self, mutate: Callable[[dict[str, Any]], Any]) -> tuple[Any, dict[str, Any]]:
        with self._thread_lock, bounded_file_lock(self.lock_path, self.lock_timeout_seconds):
            if self.state_path.exists():
                state = json.loads(self.state_path.read_text(encoding="utf-8"))
                if state.get("schema") != BUDGET_SCHEMA or state.get("limits") != asdict(self.limits):
                    raise ValueError("job budget was opened with different limits")
                before = json.dumps(state, sort_keys=True)
            else:
                state = {"schema": BUDGET_SCHEMA, "limits": asdict(self.limits), "started_at": self.clock(),
                         "team_packages": {lane.value: 0 for lane in Lane},
                         **{name: 0 for name in USAGE_COUNTERS}, "exhausted": None}
                before = None
            result = mutate(state)
            self._update_exhaustion(state)
            if json.dumps(state, sort_keys=True) != before:
                atomic_json(self.state_path, state)
            return result, state

    def _update_exhaustion(self, state: dict[str, Any]) -> None:
        if state["exhausted"] is not None:
            return                      # sticky: once stopped, launches never resume
        for counter, ceiling in _CEILINGS:
            if state[counter] >= getattr(self.limits, ceiling):
                state["exhausted"] = ceiling
                return
        if (self.limits.budget_team_packages != "all" and
                sum(state["team_packages"].values()) >= self.limits.budget_team_packages):
            state["exhausted"] = "budget_team_packages"
        elif self.clock() - state["started_at"] >= self.limits.timeout_seconds:
            state["exhausted"] = "timeout_seconds"

    def reserve(self, lane: Lane | str) -> bool:
        """Count one team-package launch for ``lane``; False (launch nothing) when exhausted."""
        selected = Lane(lane)

        def mutate(state: dict[str, Any]) -> bool:
            self._update_exhaustion(state)
            if state["exhausted"] is not None:
                return False
            state["team_packages"][selected.value] += 1
            return True

        return self._transact(mutate)[0]

    def can_launch(self) -> bool:
        """Whether a new team may start; checked before every team launch."""
        return self._transact(lambda state: None)[1]["exhausted"] is None

    def usage_exhausted(self) -> str | None:
        """The first usage or wall-clock ceiling reached, ignoring ``budget_team_packages``.

        A team already launched keeps launching its own cells after the team-package ceiling is
        reached; any turn, token, query, or wall-clock ceiling stops new cell launches.
        """
        state = self._transact(lambda state: None)[1]
        for counter, ceiling in _CEILINGS:
            if state[counter] >= getattr(self.limits, ceiling):
                return ceiling
        if self.clock() - state["started_at"] >= self.limits.timeout_seconds:
            return "timeout_seconds"
        return None

    def cell_launch_allowed(self) -> bool:
        """Whether a new cell inside a launched team may start; checked before every cell launch."""
        return self.usage_exhausted() is None

    def charge(self, *, model_turns: int = 0, input_tokens: int = 0, output_tokens: int = 0,
               retrieval_queries: int = 0) -> str | None:
        """Record usage reported by finished turns; returns the exhausted ceiling, if any.

        In-flight work is charged truthfully even past a ceiling; the ceiling stops new launches.
        """
        usage = {"model_turns": model_turns, "input_tokens": input_tokens, "output_tokens": output_tokens,
                 "retrieval_queries": retrieval_queries}
        if any(type(value) is not int or value < 0 for value in usage.values()):
            raise ValueError("budget charges must be non-negative integers")

        def mutate(state: dict[str, Any]) -> None:
            for name, value in usage.items():
                state[name] += value

        return self._transact(mutate)[1]["exhausted"]

    def snapshot(self) -> BudgetSnapshot:
        state = self._transact(lambda state: None)[1]
        return BudgetSnapshot(team_packages=dict(state["team_packages"]),
                              **{name: state[name] for name in USAGE_COUNTERS},
                              started_at=state["started_at"], exhausted=state["exhausted"])

    def team_packages(self) -> dict[Lane, int]:
        """Per-lane launched team-packages, the consumed counts for ``FairShareScheduler.next``."""
        counts = self.snapshot().team_packages
        return {lane: int(counts[lane.value]) for lane in Lane}

    def not_launched(self, queued: Iterable[str]) -> list[tuple[str, str]]:
        """``(subject_id, reason)`` for every still-queued item, in the given canonical order.

        Each becomes a ``not_launched`` cell with a ``budget_gap``; the caller mints the gap ids.
        """
        exhausted = self.snapshot().exhausted
        if exhausted is None:
            raise ValueError("job budget is not exhausted; queued work must still be launched")
        reason = f"not launched: job budget exhausted ({exhausted})"
        return [(str(subject_id), reason) for subject_id in queued]
