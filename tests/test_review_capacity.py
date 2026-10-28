"""Resolved profile capacity, balanced exploration, and honest package cutoffs."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review import teams
from appsec_review.review.budget import JobBudget
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.ledger import merge_shards, project
from appsec_review.review.models import Lane
from appsec_review.review.packages import PackageSettings, admitted_leads
from appsec_review.review.teams import ReviewTeamSemaphore, TeamUnavailable

ROOT = Path(__file__).resolve().parents[1]
JOB = "job_inference_security_review"
PROFILES = ("dev", "copilot-dev", "prod", "copilot-prod")


def settings(profile):
    return load_config(ROOT / "appsec-review.toml", profile=profile).job(JOB).typed_settings


def work(lane, index, severity=None):
    menu = [] if severity is None else [{"reported_severity": severity, "admission_reasons": ["exploration_reserve"],
                                        "observation_id": f"lead-{index}"}]
    return teams.PackageWork(f"{lane.value}-{index:04d}", lane, "a" * 64, {"lead_menu": menu},
                             (index, str(index)), "fixture", (), None)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(("medium", "low", "expected"), [
    (30, 30, (10, 10)), (2, 30, (2, 18)), (30, 2, (18, 2)), (0, 30, (0, 20)),
    (30, 0, (20, 0)), (2, 3, (2, 3)), (0, 0, (0, 0)),
])
def test_exploration_balances_population_and_reassigns_unused_slots(profile, medium, low, expected):
    leads = [SimpleNamespace(effective_severity=severity, effective_from="reported", kev_listed=False,
                             observation_id=f"{severity}-{index:03d}")
             for severity, count in (("medium", medium), ("low", low)) for index in range(count)]
    collection = LeadCollection(tuple(reversed(leads)), (), {}, None)
    configured = PackageSettings.from_review_settings(settings(profile))
    chosen = admitted_leads(collection, configured)
    counts = Counter(lead.effective_severity for lead in chosen)
    assert (counts["medium"], counts["low"]) == (expected if profile.endswith("prod") else (0, 0))
    assert len(chosen) <= configured.exploration_reserve
    assert chosen == admitted_leads(replace(collection, leads=tuple(leads)), configured)
    if counts["medium"] and counts["low"]:
        assert [lead.effective_severity for lead in chosen[:2]] == ["medium", "low"]


@pytest.mark.parametrize(("capacity", "expected"), [(1, ["medium"]), (2, ["medium", "low"]),
                                                   (3, ["medium", "low", "medium"])])
def test_launch_cutoff_preserves_balanced_exploration(tmp_path, monkeypatch, capacity, expected):
    configured = settings("prod")
    configured = replace(configured, rounds=replace(configured.rounds, max_active_claims=capacity))
    packages = [work(Lane.LEAD, index, "medium" if index < 5 else "low") for index in range(10)]
    selected = []

    def record(ctx, package, *, launch, not_launched_reason):
        if launch:
            assert package.active_claim_limit >= 1
            selected.append(package.document["lead_menu"][0]["reported_severity"])
        else:
            assert package.active_claim_limit == 0 and "max_active_claims" in not_launched_reason
        return teams.TeamResult(package.package_id, package.lane, None, launched=launch)

    monkeypatch.setattr(teams, "run_team", record)
    # One worker makes observing the already deterministic dispatch order independent of thread timing.
    configured = replace(configured, teams=replace(configured.teams, review_teams=1))
    result = teams.run_lane(SimpleNamespace(settings=configured), Lane.LEAD, list(reversed(packages)),
                            other_lane_count=0, ledger_path=tmp_path / "lane.jsonl", stream="lead",
                            signal_dir=tmp_path / "signals")
    assert selected == expected and len(result["launched"]) == capacity


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("lane_order", [(Lane.LEAD, Lane.HUNT), (Lane.HUNT, Lane.LEAD)])
def test_packages_beyond_capacity_never_launch_with_zero_claim_slots(tmp_path, monkeypatch, profile, lane_order):
    configured = settings(profile)
    count = configured.rounds.max_active_claims + 1
    budget = configured.budgets.budget_team_packages
    limit = configured.rounds.max_active_claims if budget == "all" else min(budget, configured.rounds.max_active_claims)
    assigned, skipped = {}, {}

    def record(ctx, package, *, launch, not_launched_reason):
        if launch:
            assert package.active_claim_limit >= 1
            assigned[package.package_id] = package.active_claim_limit
        else:
            assert package.active_claim_limit == 0
            skipped[package.package_id] = not_launched_reason
        return teams.TeamResult(package.package_id, package.lane, None, launched=launch)

    monkeypatch.setattr(teams, "run_team", record)
    for lane in lane_order:
        result = teams.run_lane(SimpleNamespace(settings=configured), lane,
                                [work(lane, index) for index in reversed(range(count))],
                                other_lane_count=count, ledger_path=tmp_path / lane.value / "ledger.jsonl",
                                stream=lane.value, signal_dir=tmp_path / "signals")
        assert result["allocation"] == {"lead": limit // 2, "hunt": limit // 2}
    assert len(assigned) == limit
    assert sum(assigned.values()) <= configured.rounds.max_active_claims
    assert len(skipped) == 2 * count - limit
    assert all(("max_active_claims" if budget == "all" else "budget_team_packages") in reason
               for reason in skipped.values())


@pytest.mark.parametrize(("lead_count", "hunt_count", "expected"), [
    (12, 0, (5, 0)), (0, 12, (0, 5)), (1, 12, (1, 4)), (12, 1, (4, 1)), (12, 12, (3, 2)),
])
def test_claim_limited_launches_release_scarce_lane_share(tmp_path, monkeypatch, lead_count, hunt_count, expected):
    configured = settings("prod")
    configured = replace(configured, rounds=replace(configured.rounds, max_active_claims=5))
    assigned = {}

    def record(ctx, package, *, launch, not_launched_reason):
        if launch:
            assigned[package.package_id] = package.active_claim_limit
        else:
            assert "max_active_claims" in not_launched_reason
        return teams.TeamResult(package.package_id, package.lane, None, launched=launch)

    monkeypatch.setattr(teams, "run_team", record)
    for lane, count, other_count in ((Lane.LEAD, lead_count, hunt_count), (Lane.HUNT, hunt_count, lead_count)):
        result = teams.run_lane(SimpleNamespace(settings=configured), lane,
                                [work(lane, index) for index in range(count)], other_lane_count=other_count,
                                ledger_path=tmp_path / lane.value / "ledger.jsonl", stream=lane.value,
                                signal_dir=tmp_path / "signals")
        assert result["allocation"] == dict(zip(("lead", "hunt"), expected))
    assert len(assigned) == 5 and set(assigned.values()) == {1}


def test_claim_capacity_cutoff_is_a_persisted_gap_without_a_reservation(tmp_path, monkeypatch):
    configured = settings("prod")
    configured = replace(configured, rounds=replace(configured.rounds, max_active_claims=1))
    ctx = SimpleNamespace(settings=configured, budget=JobBudget(tmp_path / "budget", configured.budgets),
                          semaphore=ReviewTeamSemaphore.for_run(tmp_path, configured.teams.review_teams))
    monkeypatch.setattr(teams, "route", lambda *_: {"gaps": []})
    monkeypatch.setattr(teams, "_red_cells", lambda *_: [])
    monkeypatch.setattr(teams, "_run_rounds", lambda *_: None)
    ledger = tmp_path / "lane.jsonl"
    result = teams.run_lane(ctx, Lane.LEAD, [work(Lane.LEAD, 0), work(Lane.LEAD, 1)],
                            other_lane_count=0, ledger_path=ledger, stream="lead", signal_dir=tmp_path / "signals")
    assert result["launched"] == ["lead-0000"]
    assert ctx.budget.team_packages() == {Lane.LEAD: 1, Lane.HUNT: 0}
    assert any(gap.subject_id == "lead-0001" and "max_active_claims" in gap.reason
               for gap in project(merge_shards([ledger]).events).gaps)


@pytest.mark.parametrize("profile", PROFILES)
def test_resolved_team_capacity_is_reachable_and_shared_by_both_lane_executors(tmp_path, monkeypatch, profile):
    configured = settings(profile)
    slots = configured.teams.review_teams
    assert slots == (7 if profile.endswith("prod") else 3)
    active = peak = 0
    guard, filled, release = threading.Lock(), threading.Event(), threading.Event()
    monkeypatch.setattr(teams, "route", lambda *_: {"gaps": []})
    monkeypatch.setattr(teams, "_red_cells", lambda *_: [])

    def hold_rounds(*_):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
            if active == slots:
                filled.set()
        try:
            assert release.wait(30), "test did not release the team"
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(teams, "_run_rounds", hold_rounds)
    contexts = [SimpleNamespace(settings=configured, budget=JobBudget(tmp_path / "budget", configured.budgets),
                                 semaphore=ReviewTeamSemaphore.for_run(tmp_path, slots)) for _ in Lane]
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(teams.run_lane, ctx, lane, [work(lane, index) for index in range(slots + 1)],
                                   other_lane_count=slots + 1, ledger_path=tmp_path / lane.value / "ledger.jsonl",
                                   stream=lane.value, signal_dir=tmp_path / "signals")
                   for ctx, lane in zip(contexts, Lane)]
        try:
            assert filled.wait(20), "resolved team capacity was not reachable"
            with pytest.raises(TeamUnavailable):
                with ReviewTeamSemaphore.for_run(tmp_path, slots).acquire(Lane.LEAD, wait_seconds=0):
                    pass
            assert peak == slots
        finally:
            release.set()
        results = [future.result(timeout=30) for future in futures]
    assert active == 0 and peak == slots
    assert sum(len(result["launched"]) for result in results) == 2 * (slots + 1)
