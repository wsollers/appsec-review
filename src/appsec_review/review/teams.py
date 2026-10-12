"""Review-team capacity: a cross-process team semaphore and the fair-share lane scheduler.

A review team is ``red_per_team`` red cells, ``blue_per_team`` blue cells, and
``verifier_per_team`` verifiers working one package (design: "Review teams"). ``review_teams`` is
the number of teams that may run at once on the host, whichever Dagster units are active; it is
capacity, never semantics. Which package a lane launches next is decided deterministically by
:class:`FairShareScheduler`; only wall-clock interleaving depends on the semaphore.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import math
from pathlib import Path
import threading
import time

from appsec_review.review.models import Lane
from appsec_review.storage.lock import FileLock, LockUnavailable


TEAM_DIRECTORY = Path("data") / "jobs" / "job_inference_security_review" / "review-teams"
MAX_TEAMS = 64


class TeamUnavailable(LockUnavailable):
    """No team slot became free within the bounded wait."""


@dataclass(frozen=True, slots=True)
class TeamSlot:
    lane: Lane
    slot: int
    path: Path


class ReviewTeamSemaphore:
    """A counting semaphore over ``slots`` kernel file locks, one lock file per slot.

    Every process (and thread) that acquires from the same ``root`` competes for the same slots,
    so at most ``slots`` teams run on the host. A slot is a kernel lock, so the kernel releases it
    when its holder dies; there is no stale-lock recovery to get wrong.
    """

    def __init__(self, root: Path, slots: int, *, wait_seconds: float = 3600.0,
                 poll_seconds: float = 0.05) -> None:
        if type(slots) is not int or not 1 <= slots <= MAX_TEAMS:
            raise ValueError(f"review team slots must be an integer between 1 and {MAX_TEAMS}")
        if wait_seconds < 0 or poll_seconds <= 0:
            raise ValueError("review team wait bounds are invalid")
        self.root = Path(root)
        self.slots = slots
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds

    @classmethod
    def for_run(cls, run_root: Path, slots: int, **kwargs: float) -> "ReviewTeamSemaphore":
        """The run-wide semaphore every lane unit of one run shares."""
        return cls(Path(run_root) / TEAM_DIRECTORY, slots, **kwargs)

    def slot_path(self, slot: int) -> Path:
        return self.root / f"team-{slot:02d}.lock"

    def _try_any(self) -> tuple[int, FileLock] | None:
        for slot in range(self.slots):
            lock = FileLock(self.slot_path(slot))
            try:
                lock.__enter__()
            except LockUnavailable:
                continue
            return slot, lock
        return None

    @contextmanager
    def acquire(self, lane: Lane | str, *, wait_seconds: float | None = None) -> Iterator[TeamSlot]:
        """Hold one team slot for ``lane``: try every slot without blocking, then poll, bounded."""
        selected_lane = Lane(lane)
        deadline = time.monotonic() + (self.wait_seconds if wait_seconds is None else wait_seconds)
        while (acquired := self._try_any()) is None:
            if time.monotonic() >= deadline:
                raise TeamUnavailable(f"no review team became free within the wait bound: {self.root}")
            time.sleep(self.poll_seconds)
        slot, lock = acquired
        try:
            yield TeamSlot(selected_lane, slot, self.slot_path(slot))
        finally:
            lock.__exit__(None, None, None)


@dataclass(frozen=True, slots=True, order=True)
class QueuedPackage:
    """A package waiting for a team; canonical order is rank, then ``package_id``."""

    rank: int
    package_id: str


class FairShareScheduler:
    """Decide which lane gets the next free team.

    Shares are ``lead_share`` and ``1 - lead_share`` of ``budget_team_packages``. The next team goes
    to the lane that has consumed the smaller fraction of its share (lead on ties). The scheduler is
    work-conserving: a lane with no queued packages releases its unused share, so the other lane may
    exceed its own share. It never exceeds the job total. Packages within a lane are taken by rank,
    then ``package_id``. The decision is a pure function of the queues and the consumed counts.
    """

    def __init__(self, lead_share: float, budget_team_packages: int) -> None:
        if not isinstance(lead_share, (int, float)) or not math.isfinite(lead_share) or not 0 <= lead_share <= 1:
            raise ValueError("lead_share must be between 0 and 1")
        if type(budget_team_packages) is not int or budget_team_packages < 0:
            raise ValueError("budget_team_packages must be a non-negative integer")
        self.total = budget_team_packages
        self.shares = {Lane.LEAD: float(lead_share) * budget_team_packages,
                       Lane.HUNT: (1.0 - float(lead_share)) * budget_team_packages}
        self._consumed = {Lane.LEAD: 0, Lane.HUNT: 0}
        self._lock = threading.Lock()

    @property
    def consumed(self) -> Mapping[Lane, int]:
        with self._lock:
            return dict(self._consumed)

    def _fraction(self, lane: Lane, consumed: Mapping[Lane, int]) -> float:
        share = self.shares[lane]
        return consumed[lane] / share if share > 0 else math.inf

    def choose(self, queues: Mapping[Lane, Sequence[QueuedPackage]],
               consumed: Mapping[Lane, int]) -> tuple[Lane, str] | None:
        """The next (lane, package_id) given ``consumed`` team-packages per lane, without recording it."""
        counts = {lane: int(consumed.get(lane, 0)) for lane in (Lane.LEAD, Lane.HUNT)}
        if sum(counts.values()) >= self.total:
            return None
        waiting = {lane: sorted(queues.get(lane, ())) for lane in (Lane.LEAD, Lane.HUNT)}
        eligible = []
        for lane, other in ((Lane.LEAD, Lane.HUNT), (Lane.HUNT, Lane.LEAD)):
            if not waiting[lane]:
                continue
            # Within its own share, or the other lane has nothing queued and released its share.
            if counts[lane] < self.shares[lane] or not waiting[other]:
                eligible.append(lane)
        if not eligible:
            return None
        lane = min(eligible, key=lambda item: (self._fraction(item, counts), item is not Lane.LEAD))
        return lane, waiting[lane][0].package_id

    def next(self, queues: Mapping[Lane, Sequence[QueuedPackage]],
             consumed: Mapping[Lane, int] | None = None) -> tuple[Lane, str] | None:
        """Choose and record the next launch.

        ``consumed`` replaces the scheduler's own counts, for example with the shared job budget's
        per-lane team-package counters when lanes run in separate processes; the caller then records
        the launch there (``JobBudget.reserve``) and the scheduler's own counts are left unchanged.
        The caller removes the returned package from its queue.
        """
        with self._lock:
            decision = self.choose(queues, self._consumed if consumed is None else consumed)
            if decision is not None and consumed is None:
                self._consumed[decision[0]] += 1
            return decision
