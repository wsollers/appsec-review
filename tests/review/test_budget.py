from __future__ import annotations

import multiprocessing
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

from appsec_review.config.inference_review import BudgetSettings, TeamPackageBudget
from appsec_review.review.budget import JobBudget
from appsec_review.review.models import Lane


_CONTEXT = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")


def _limits(*, budget_team_packages: TeamPackageBudget = 200, **overrides: int) -> BudgetSettings:
    values = {"max_model_turns": 12000, "max_input_tokens": 60_000_000,
              "max_output_tokens": 6_000_000, "max_retrieval_queries": 40000, "timeout_seconds": 28800}
    return BudgetSettings(budget_team_packages=budget_team_packages, **{**values, **overrides})


def test_team_package_budget_stops_launches_and_names_the_unlaunched(tmp_path: Path) -> None:
    budget = JobBudget.for_run(tmp_path, _limits(budget_team_packages=3))
    assert budget.root == tmp_path / "data/jobs/job_inference_security_review/budget"
    assert [budget.reserve(lane) for lane in (Lane.LEAD, Lane.HUNT, "lead", Lane.HUNT)] == [True, True, True, False]
    assert budget.team_packages() == {Lane.LEAD: 2, Lane.HUNT: 1}
    assert budget.can_launch() is False
    assert budget.not_launched(["pkg-hunt-007", "pkg-hunt-009"]) == [
        ("pkg-hunt-007", "not launched: job budget exhausted (budget_team_packages)"),
        ("pkg-hunt-009", "not launched: job budget exhausted (budget_team_packages)")]


def test_all_packages_budget_reserves_asymmetric_queues_and_persists(tmp_path: Path) -> None:
    limits = _limits(budget_team_packages="all")
    budget = JobBudget(tmp_path, limits)
    for lane, count in ((Lane.LEAD, 485), (Lane.HUNT, 114)):
        assert all(budget.reserve(lane) for _ in range(count))
    reopened = JobBudget(tmp_path, limits)
    assert reopened.team_packages() == {Lane.LEAD: 485, Lane.HUNT: 114}
    assert reopened.can_launch() and reopened.cell_launch_allowed()
    assert reopened.snapshot().exhausted is None
    assert reopened.reserve(Lane.HUNT)
    with pytest.raises(ValueError, match="different limits"):
        JobBudget(tmp_path, _limits(budget_team_packages=200))


@pytest.mark.parametrize("package_limit", [200, "all"])
@pytest.mark.parametrize("charge, ceiling", [
    ({"model_turns": 10}, "max_model_turns"),
    ({"input_tokens": 1000}, "max_input_tokens"),
    ({"output_tokens": 100}, "max_output_tokens"),
    ({"retrieval_queries": 6}, "max_retrieval_queries"),
])
def test_any_hard_ceiling_stops_new_launches(tmp_path: Path, charge: dict[str, int], ceiling: str,
                                           package_limit: TeamPackageBudget) -> None:
    budget = JobBudget(tmp_path, _limits(budget_team_packages=package_limit,
                                         max_model_turns=10, max_input_tokens=1000, max_output_tokens=100,
                                         max_retrieval_queries=5))
    assert budget.reserve(Lane.LEAD) and budget.charge() is None
    half = {name: value // 2 for name, value in charge.items()}
    assert budget.charge(**half) is None and budget.can_launch()
    assert budget.charge(**half) == ceiling
    assert budget.can_launch() is False and budget.reserve(Lane.HUNT) is False
    assert budget.cell_launch_allowed() is False
    # In-flight work is still charged truthfully, and exhaustion is sticky.
    assert budget.charge(**charge) == ceiling
    snapshot = budget.snapshot()
    assert getattr(snapshot, next(iter(charge))) == 2 * charge[next(iter(charge))]
    assert snapshot.exhausted == ceiling
    assert budget.not_launched(["cell-1"]) == [("cell-1", f"not launched: job budget exhausted ({ceiling})")]


@pytest.mark.parametrize("package_limit", [200, "all"])
def test_wall_clock_ceiling_stops_new_launches(tmp_path: Path, package_limit: TeamPackageBudget) -> None:
    now = [1000.0]
    budget = JobBudget(tmp_path, _limits(budget_team_packages=package_limit, timeout_seconds=60), clock=lambda: now[0])
    assert budget.reserve(Lane.LEAD)
    now[0] += 60
    assert budget.reserve(Lane.LEAD) is False
    assert budget.snapshot().exhausted == "timeout_seconds"
    assert budget.cell_launch_allowed() is False


def test_counters_persist_and_limits_are_bound(tmp_path: Path) -> None:
    first = JobBudget(tmp_path, _limits())
    first.reserve(Lane.HUNT)
    first.charge(model_turns=3, input_tokens=10, output_tokens=4, retrieval_queries=2)
    second = JobBudget(tmp_path, _limits())
    snapshot = second.snapshot()
    assert (snapshot.team_packages, snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens,
            snapshot.retrieval_queries, snapshot.exhausted) == ({"lead": 0, "hunt": 1}, 3, 10, 4, 2, None)
    with pytest.raises(ValueError, match="different limits"):
        JobBudget(tmp_path, _limits(budget_team_packages=201))


def test_not_launched_requires_exhaustion_and_charges_are_validated(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    with pytest.raises(ValueError, match="not exhausted"):
        budget.not_launched(["pkg-1"])
    with pytest.raises(ValueError):
        budget.charge(model_turns=-1)
    with pytest.raises(ValueError):
        budget.reserve("triage")


def test_threads_never_overspend_the_budget(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits(budget_team_packages=40))
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda index: budget.reserve((Lane.LEAD, Lane.HUNT)[index % 2]), range(100)))
    assert sum(results) == 40
    assert sum(budget.team_packages().values()) == 40


def _reserve_many(root: str, attempts: int, lane: str, granted) -> None:
    budget = JobBudget(Path(root), _limits(budget_team_packages=50))
    count = 0
    for _ in range(attempts):
        if budget.reserve(lane):
            count += 1
        budget.charge(model_turns=1)
    with granted.get_lock():
        granted.value += count


def test_processes_never_overspend_the_budget(tmp_path: Path) -> None:
    granted = _CONTEXT.Value("i", 0)
    JobBudget(tmp_path, _limits(budget_team_packages=50))
    workers = [_CONTEXT.Process(target=_reserve_many, args=(str(tmp_path), 30, ("lead", "hunt")[index % 2], granted))
               for index in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(120)
    assert [worker.exitcode for worker in workers] == [0, 0, 0, 0]
    assert granted.value == 50
    snapshot = JobBudget(tmp_path, _limits(budget_team_packages=50)).snapshot()
    assert sum(snapshot.team_packages.values()) == 50
    assert snapshot.model_turns == 120


def test_team_package_ceiling_stops_teams_but_not_cells_of_launched_teams(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path / "budget", _limits(budget_team_packages=1, max_model_turns=3))
    assert budget.reserve(Lane.LEAD) and not budget.can_launch()
    assert budget.usage_exhausted() is None and budget.cell_launch_allowed()
    budget.charge(model_turns=3)
    assert budget.usage_exhausted() == "max_model_turns" and not budget.cell_launch_allowed()
