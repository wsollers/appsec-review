from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import random
import signal
import time

import pytest

from appsec_review.review.models import Lane
from appsec_review.review.teams import (
    FairShareScheduler, QueuedPackage, ReviewTeamSemaphore, TeamUnavailable,
)


_CONTEXT = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")


# ---------------------------------------------------------------- cross-process semaphore


def _hold_team(root: str, slots: int, lane: str, active, peak, guard, rounds: int) -> None:
    semaphore = ReviewTeamSemaphore(Path(root), slots, wait_seconds=60, poll_seconds=0.005)
    for _ in range(rounds):
        with semaphore.acquire(lane) as team:
            assert 0 <= team.slot < slots
            with guard:
                active.value += 1
                peak.value = max(peak.value, active.value)
            time.sleep(0.02)
            with guard:
                active.value -= 1


@pytest.mark.parametrize("slots", [1, 3, 7])
def test_semaphore_never_exceeds_its_slots_across_processes(tmp_path: Path, slots: int) -> None:
    active, peak, guard = _CONTEXT.Value("i", 0), _CONTEXT.Value("i", 0), _CONTEXT.Lock()
    workers = [_CONTEXT.Process(target=_hold_team, args=(
        str(tmp_path / "teams"), slots, (Lane.LEAD, Lane.HUNT)[index % 2].value, active, peak, guard, 4))
        for index in range(max(6, slots + 2))]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(60)
    assert [worker.exitcode for worker in workers] == [0] * len(workers)
    assert 1 <= peak.value <= slots
    assert active.value == 0
    assert {path.name for path in (tmp_path / "teams").iterdir()} <= {
        f"team-{slot:02d}.lock" for slot in range(slots)}


def _hold_forever(root: str, ready) -> None:
    with ReviewTeamSemaphore(Path(root), 1).acquire(Lane.HUNT):
        ready.set()
        time.sleep(600)


def test_a_crashed_holder_releases_its_team(tmp_path: Path) -> None:
    root = tmp_path / "teams"
    ready = _CONTEXT.Event()
    holder = _CONTEXT.Process(target=_hold_forever, args=(str(root), ready))
    holder.start()
    try:
        assert ready.wait(30)
        semaphore = ReviewTeamSemaphore(root, 1, poll_seconds=0.01)
        with pytest.raises(TeamUnavailable):
            with semaphore.acquire(Lane.LEAD, wait_seconds=0.1):
                pass
        os.kill(holder.pid, signal.SIGKILL)
        holder.join(30)
        with semaphore.acquire(Lane.LEAD, wait_seconds=10) as team:
            assert (team.lane, team.slot) == (Lane.LEAD, 0)
    finally:
        if holder.is_alive():
            holder.kill()
            holder.join()


def test_slots_within_one_process_are_exclusive_and_released(tmp_path: Path) -> None:
    semaphore = ReviewTeamSemaphore.for_run(tmp_path, 2, poll_seconds=0.01)
    assert semaphore.root == tmp_path / "data/jobs/job_inference_security_review/review-teams"
    with semaphore.acquire("lead") as first, semaphore.acquire("hunt") as second:
        assert {first.slot, second.slot} == {0, 1}
        with pytest.raises(TeamUnavailable):
            with semaphore.acquire(Lane.LEAD, wait_seconds=0):
                pass
    with semaphore.acquire(Lane.LEAD, wait_seconds=0) as again:
        assert again.slot == 0


@pytest.mark.parametrize("slots", [0, 65, True])
def test_semaphore_slot_count_is_bounded(tmp_path: Path, slots) -> None:
    with pytest.raises(ValueError):
        ReviewTeamSemaphore(tmp_path, slots)


def test_unknown_lane_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        with ReviewTeamSemaphore(tmp_path, 1).acquire("triage"):
            pass


# ---------------------------------------------------------------- fair-share scheduler


def _queue(prefix: str, count: int) -> list[QueuedPackage]:
    return [QueuedPackage(rank=index // 3, package_id=f"{prefix}-{index:03d}") for index in range(count)]


def _drain(scheduler: FairShareScheduler, queues: dict[Lane, list[QueuedPackage]]) -> list[tuple[Lane, str]]:
    launched = []
    while (decision := scheduler.next(queues)) is not None:
        launched.append(decision)
        lane, package_id = decision
        queues[lane] = [item for item in queues[lane] if item.package_id != package_id]
    return launched


def test_equal_shares_alternate_and_stop_at_the_job_total() -> None:
    launched = _drain(FairShareScheduler(0.5, 10), {Lane.LEAD: _queue("a", 20), Lane.HUNT: _queue("b", 20)})
    assert [lane for lane, _ in launched] == [Lane.LEAD, Lane.HUNT] * 5


def test_unequal_shares_follow_consumed_fraction() -> None:
    scheduler = FairShareScheduler(0.75, 8)
    launched = _drain(scheduler, {Lane.LEAD: _queue("a", 20), Lane.HUNT: _queue("b", 20)})
    assert sum(lane is Lane.LEAD for lane, _ in launched) == 6
    assert sum(lane is Lane.HUNT for lane, _ in launched) == 2
    assert scheduler.consumed == {Lane.LEAD: 6, Lane.HUNT: 2}


def test_an_empty_lane_releases_its_share() -> None:
    launched = _drain(FairShareScheduler(0.5, 10), {Lane.LEAD: _queue("a", 20), Lane.HUNT: []})
    assert [lane for lane, _ in launched] == [Lane.LEAD] * 10
    # A lane whose queue empties mid-run hands the rest of the budget to the other lane.
    launched = _drain(FairShareScheduler(0.5, 10), {Lane.LEAD: _queue("a", 2), Lane.HUNT: _queue("b", 20)})
    assert sum(lane is Lane.HUNT for lane, _ in launched) == 8


def test_a_zero_share_lane_runs_only_on_released_share() -> None:
    scheduler = FairShareScheduler(0.0, 4)
    assert _drain(scheduler, {Lane.LEAD: _queue("a", 3), Lane.HUNT: _queue("b", 2)}) == [
        (Lane.HUNT, "b-000"), (Lane.HUNT, "b-001"), (Lane.LEAD, "a-000"), (Lane.LEAD, "a-001")]


def test_package_order_is_rank_then_package_id_and_deterministic() -> None:
    packages = [QueuedPackage(2, "p-a"), QueuedPackage(0, "p-z"), QueuedPackage(1, "p-b"), QueuedPackage(0, "p-c")]
    orders = []
    for seed in range(5):
        shuffled = list(packages)
        random.Random(seed).shuffle(shuffled)
        orders.append(_drain(FairShareScheduler(0.5, 10), {Lane.LEAD: shuffled, Lane.HUNT: []}))
    assert all(order == orders[0] for order in orders)
    assert [package_id for _, package_id in orders[0]] == ["p-c", "p-z", "p-b", "p-a"]


def test_external_consumed_counts_drive_the_choice_without_recording() -> None:
    scheduler = FairShareScheduler(0.5, 10)
    queues = {Lane.LEAD: _queue("a", 3), Lane.HUNT: _queue("b", 3)}
    assert scheduler.next(queues, {Lane.LEAD: 3, Lane.HUNT: 1}) == (Lane.HUNT, "b-000")
    assert scheduler.next(queues, {Lane.LEAD: 5, Lane.HUNT: 5}) is None
    assert scheduler.consumed == {Lane.LEAD: 0, Lane.HUNT: 0}
    assert scheduler.next({Lane.LEAD: [], Lane.HUNT: []}) is None


@pytest.mark.parametrize("share, total", [(-0.1, 10), (1.1, 10), (float("nan"), 10), (0.5, -1)])
def test_scheduler_rejects_invalid_shares(share: float, total: int) -> None:
    with pytest.raises(ValueError):
        FairShareScheduler(share, total)
