from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
import multiprocessing
import os
from pathlib import Path

import pytest

import appsec_review.review.budget as budget_module
from appsec_review.config.inference_review import BudgetSettings
from appsec_review.inference.errors import ExecutionContractError
from appsec_review.inference.request import ModelResult
from appsec_review.inference.usage import Usage
from appsec_review.review.budget import BUDGET_DIRECTORY, BUDGET_SCHEMA, BUDGET_SCHEMA_V1, JobBudget


_CONTEXT = multiprocessing.get_context("fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn")


def _limits(**overrides: int) -> BudgetSettings:
    return BudgetSettings(**{"budget_team_packages": "all", "max_model_turns": 20,
                             "max_input_tokens": 1000, "max_output_tokens": 500,
                             "max_retrieval_queries": 20, "timeout_seconds": 1000, **overrides})


def _reserve(budget: JobBudget, owner: str = "attempt-1", *, input_tokens: int = 100,
             output_tokens: int = 50, replay: bool = False) -> str:
    identifier = budget.reserve_call(owner_id=owner, input_tokens=input_tokens,
                                     output_tokens=output_tokens, replay=replay)
    assert identifier is not None
    return identifier


def _state(budget: JobBudget) -> dict:
    return json.loads(budget.state_path.read_text(encoding="utf-8"))


def test_reservations_are_not_actual_and_pressure_is_not_sticky(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits(max_input_tokens=100, max_output_tokens=50))
    identifier = _reserve(budget)
    snapshot = budget.snapshot()
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens) == (0, 0, 0)
    assert (snapshot.actual_input_tokens, snapshot.actual_output_tokens) == (None, None)
    assert (snapshot.reserved_model_turns, snapshot.reserved_input_tokens,
            snapshot.reserved_output_tokens) == (1, 100, 50)
    assert snapshot.exhausted == "max_input_tokens"
    assert _state(budget)["exhausted"] is None
    before = _state(budget)
    assert budget.reserve_call(owner_id="attempt-2", input_tokens=1, output_tokens=1) is None
    assert _state(budget)["reservations"] == before["reservations"]
    assert budget.settle_call(identifier, usage=Usage(30, 10, 5)) is None
    snapshot = budget.snapshot()
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens, snapshot.cache_tokens) == (1, 30, 10, 5)
    assert (snapshot.actual_input_tokens, snapshot.actual_output_tokens, snapshot.actual_cache_tokens) == (30, 10, 5)
    assert snapshot.live_reservations == 0 and budget.can_launch()
    assert budget.reserve_call(owner_id="attempt-2", input_tokens=70, output_tokens=40)


def test_exact_bounds_admit_but_oversized_request_is_atomic_noop(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits(max_model_turns=1, max_input_tokens=100, max_output_tokens=50))
    for input_tokens, output_tokens in ((101, 0), (0, 51)):
        assert budget.reserve_call(owner_id="attempt-1", input_tokens=input_tokens, output_tokens=output_tokens) is None
        assert budget.snapshot().reserved_model_turns == 0
    identifier = _reserve(budget)
    assert budget.reserve_call(owner_id="attempt-2", input_tokens=0, output_tokens=0) is None
    budget.settle_call(identifier, dispatched=False)
    assert budget.snapshot().model_turns == 0
    assert _reserve(budget)


@pytest.mark.parametrize("dimension,maximum", [("input_tokens", 100), ("output_tokens", 50)])
def test_actual_provider_overrun_is_never_clipped(tmp_path: Path, dimension: str, maximum: int) -> None:
    budget = JobBudget(tmp_path, _limits(max_input_tokens=100, max_output_tokens=50))
    identifier = _reserve(budget)
    usage = {"input_tokens": 10, "output_tokens": 10, "cache_tokens": 300}
    usage[dimension] = maximum + 37
    assert budget.settle_call(identifier, usage=Usage(**usage)) == f"max_{dimension}"
    snapshot = JobBudget(tmp_path, budget.limits).snapshot()
    assert getattr(snapshot, dimension) == maximum + 37
    assert getattr(snapshot, f"actual_{dimension}") == maximum + 37
    assert snapshot.cache_tokens == 300  # No subtraction or invented cache/input relationship.
    assert snapshot.reserved_model_turns == 0
    assert not budget.cell_launch_allowed()


@pytest.mark.parametrize("bad", [None, -1, 1.5, "10", True, False])
@pytest.mark.parametrize("dimension", ["input_tokens", "output_tokens", "cache_tokens"])
def test_invalid_or_missing_usage_stays_unknown(tmp_path: Path, bad: object, dimension: str) -> None:
    budget = JobBudget(tmp_path, _limits())
    values = {"input_tokens": 23, "output_tokens": 7, "cache_tokens": 3}
    values[dimension] = bad
    identifier = _reserve(budget)
    budget.settle_call(identifier, usage=Usage(**values))
    snapshot = budget.snapshot()
    assert getattr(snapshot, dimension) == 0
    assert getattr(snapshot, f"actual_{dimension}") is None
    assert snapshot.unknown_usage[dimension] == 1
    for other in set(values) - {dimension}:
        assert getattr(snapshot, f"actual_{other}") == values[other]
    if dimension != "cache_tokens":
        assert getattr(snapshot, f"liability_{dimension}") == {"input_tokens": 100, "output_tokens": 50}[dimension]
    assert snapshot.live_reservations == 0


def test_normalized_usage_contract_and_known_partial_spend(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    first = _reserve(budget)
    budget.settle_call(first, usage=Usage.from_result(ModelResult({}, input_tokens=30, output_tokens=-2)))
    receipt = _state(budget)["settlements"][first]
    second = _reserve(budget)
    budget.settle_call(second, usage=Usage(10, 5, 0))
    snapshot = budget.snapshot()
    assert (snapshot.input_tokens, snapshot.output_tokens) == (40, 5)
    assert (snapshot.actual_input_tokens, snapshot.actual_output_tokens) == (40, None)
    assert snapshot.liability_output_tokens == 50
    assert receipt == _state(budget)["settlements"][first]


@pytest.mark.parametrize("early_replay", [False, True])
def test_replayed_tokens_are_reported_but_never_new_billing(tmp_path: Path, early_replay: bool) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget, replay=early_replay)
    assert budget.snapshot().reserved_input_tokens == (0 if early_replay else 100)
    budget.settle_call(identifier, usage=Usage(10000, 5000, 2000, source="replay"))
    snapshot = budget.snapshot()
    assert (snapshot.input_tokens, snapshot.output_tokens, snapshot.cache_tokens) == (0, 0, 0)
    assert (snapshot.actual_input_tokens, snapshot.actual_output_tokens, snapshot.actual_cache_tokens) == (0, 0, 0)
    assert (snapshot.replayed_input_tokens, snapshot.replayed_output_tokens, snapshot.replayed_cache_tokens) == (
        10000, 5000, 2000)
    assert snapshot.model_turns == snapshot.replayed_model_turns == 1
    assert snapshot.exhausted is None


def test_missing_replay_usage_has_no_billable_liability(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget, replay=True)
    budget.settle_call(identifier)
    snapshot = budget.snapshot()
    assert snapshot.unknown_usage == dict.fromkeys(("input_tokens", "output_tokens", "cache_tokens"), 0)
    assert snapshot.replayed_unknown_usage == dict.fromkeys(snapshot.unknown_usage, 1)
    assert snapshot.liability_input_tokens == snapshot.liability_output_tokens == 0
    assert snapshot.actual_input_tokens == snapshot.actual_output_tokens == 0


def test_cancellation_before_dispatch_releases_all_and_after_dispatch_retains_liability(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits(max_input_tokens=100, max_output_tokens=50))
    first = _reserve(budget)
    budget.settle_call(first, dispatched=False)
    assert budget.can_launch()
    assert budget.snapshot().model_turns == 0
    second = _reserve(budget)
    assert budget.settle_call(second) == "max_input_tokens"
    snapshot = budget.snapshot()
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens) == (1, 0, 0)
    assert (snapshot.actual_input_tokens, snapshot.actual_output_tokens) == (None, None)
    assert snapshot.live_reservations == 0
    assert (snapshot.liability_input_tokens, snapshot.liability_output_tokens) == (100, 50)
    assert budget.reserve_call(owner_id="attempt-2", input_tokens=1, output_tokens=1) is None


def test_identical_settlements_are_idempotent_and_conflicts_do_not_mutate_receipts(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget)
    usage = Usage(30, 10, 2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: budget.settle_call(identifier, usage=usage), range(8))) == [None] * 8
    receipt = _state(budget)["settlements"][identifier]
    assert (budget.snapshot().model_turns, budget.snapshot().input_tokens) == (1, 30)
    with pytest.raises(ExecutionContractError, match="conflicting"):
        budget.settle_call(identifier, usage=Usage(31, 10, 2))
    with pytest.raises(ExecutionContractError, match="conflicting"):
        budget.settle_call(identifier, dispatched=False)
    with pytest.raises(ExecutionContractError, match="unknown call reservation"):
        budget.settle_call("missing-id")
    assert receipt == _state(budget)["settlements"][identifier]


def test_reservation_identity_collision_never_overwrites_live_or_settled_usage(tmp_path: Path, monkeypatch) -> None:
    identifier = budget_module.uuid4()
    monkeypatch.setattr(budget_module, "uuid4", lambda: identifier)
    budget = JobBudget(tmp_path, _limits())
    first = _reserve(budget)
    with pytest.raises(ExecutionContractError, match="identity collision"):
        _reserve(budget, "other-owner")
    assert budget.snapshot().live_reservations == 1
    budget.settle_call(first, usage=Usage(10, 5, 0))
    with pytest.raises(ExecutionContractError, match="identity collision"):
        _reserve(budget, "other-owner")
    assert budget.snapshot().input_tokens == 10


@pytest.mark.parametrize("kwargs", [
    {"owner_id": ""}, {"owner_id": True}, {"input_tokens": -1}, {"input_tokens": True},
    {"output_tokens": 1.5}, {"replay": 1},
])
def test_bad_reservation_arguments_are_contract_errors(tmp_path: Path, kwargs: dict) -> None:
    budget = JobBudget(tmp_path, _limits())
    with pytest.raises(ExecutionContractError):
        budget.reserve_call(**{"owner_id": "attempt-1", "input_tokens": 1, "output_tokens": 1, **kwargs})
    assert budget.snapshot().live_reservations == 0


@pytest.mark.parametrize("kwargs", [
    {"usage": {}}, {"usage": Usage(source="estimated")}, {"usage": Usage(unavailable_reason=True)},
    {"dispatched": 1}, {"dispatched": False, "usage": Usage(0, 0)},
])
def test_invalid_settlement_contract_keeps_reservation(tmp_path: Path, kwargs: dict) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget)
    with pytest.raises(ExecutionContractError):
        budget.settle_call(identifier, **kwargs)
    assert budget.snapshot().live_reservations == 1


def test_provider_usage_cannot_be_disguised_as_reserved_replay(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget, replay=True)
    with pytest.raises(ExecutionContractError, match="source"):
        budget.settle_call(identifier, usage=Usage(10, 10))
    assert budget.snapshot().live_reservations == 1


def test_concurrent_instances_reserve_all_dimensions_atomically(tmp_path: Path) -> None:
    limits = _limits(max_model_turns=8, max_input_tokens=400, max_output_tokens=100)
    budgets = [JobBudget(tmp_path, limits) for _ in range(6)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda i: budgets[i % 6].reserve_call(
            owner_id=f"attempt-{i}", input_tokens=60, output_tokens=20), range(24)))
    assert len(set(filter(None, results))) == 5
    snapshot = budgets[0].snapshot()
    assert (snapshot.reserved_model_turns, snapshot.reserved_input_tokens, snapshot.reserved_output_tokens) == (5, 300, 100)
    assert snapshot.model_turns == snapshot.input_tokens == snapshot.output_tokens == 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda rid: budgets[0].settle_call(rid, usage=Usage(60, 20, 0)), filter(None, results)))
    snapshot = budgets[0].snapshot()
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens) == (5, 300, 100)
    assert snapshot.live_reservations == 0


def _process_reserve(root: str, owner: str, admitted) -> None:
    budget = JobBudget(Path(root), _limits(max_model_turns=6, max_input_tokens=500, max_output_tokens=150))
    count = sum(budget.reserve_call(owner_id=owner, input_tokens=100, output_tokens=20) is not None
                for _ in range(5))
    with admitted.get_lock():
        admitted.value += count


def _join(workers: list) -> None:
    try:
        for worker in workers:
            worker.join(20)
        assert [worker.exitcode for worker in workers] == [0] * len(workers)
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
                worker.join(5)


def test_process_reservations_survive_owner_exit_until_positive_reconciliation(tmp_path: Path) -> None:
    admitted = _CONTEXT.Value("i", 0)
    limits = _limits(max_model_turns=6, max_input_tokens=500, max_output_tokens=150)
    budget = JobBudget(tmp_path, limits)
    workers = [_CONTEXT.Process(target=_process_reserve, args=(str(tmp_path), f"attempt-{i}", admitted))
               for i in range(3)]
    for worker in workers:
        worker.start()
    _join(workers)
    assert admitted.value == 5
    reopened = JobBudget(tmp_path, limits)
    assert reopened.snapshot().live_reservations == 5
    assert reopened.snapshot().reserved_input_tokens == 500
    owners = {r["owner_id"] for r in _state(budget)["reservations"].values()}
    for owner in owners:
        reopened.reconcile_owner(owner, cessation_evidence=f"run/attempts/{owner}/process-exited.json")
    snapshot = reopened.snapshot()
    assert snapshot.live_reservations == 0 and snapshot.model_turns == 5
    assert snapshot.liability_input_tokens == 500 and snapshot.liability_output_tokens == 100
    assert snapshot.actual_input_tokens is None


def _process_settle(root: str, reservation_id: str) -> None:
    JobBudget(Path(root), _limits()).settle_call(reservation_id, usage=Usage(1500, 25, 0))


def test_concurrent_process_settlement_retains_overrun_exactly_once(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget)
    workers = [_CONTEXT.Process(target=_process_settle, args=(str(tmp_path), identifier)) for _ in range(3)]
    for worker in workers:
        worker.start()
    _join(workers)
    snapshot = budget.snapshot()
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens) == (1, 1500, 25)
    assert snapshot.actual_input_tokens == 1500 and snapshot.live_reservations == 0


def _process_crash(root: str) -> None:
    budget = JobBudget(Path(root), _limits())
    _reserve(budget, "crashed-attempt")
    os._exit(9)


def test_crash_keeps_unknown_call_reserved_until_explicit_owner_evidence(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    worker = _CONTEXT.Process(target=_process_crash, args=(str(tmp_path),))
    worker.start()
    try:
        worker.join(20)
        assert worker.exitcode == 9
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
    assert budget.snapshot().live_reservations == 1
    assert budget.snapshot().model_turns == 0
    assert budget.snapshot().actual_input_tokens is None
    budget.reconcile_owner("crashed-attempt", cessation_evidence="run/attempts/crashed-attempt/exit-9")
    assert budget.snapshot().model_turns == 1
    assert budget.snapshot().liability_input_tokens == 100


def test_age_is_not_evidence_and_reconciliation_is_idempotent(tmp_path: Path) -> None:
    now = [1000.0]
    budget = JobBudget(tmp_path, _limits(timeout_seconds=1_000_000), clock=lambda: now[0])
    first = _reserve(budget)
    _reserve(budget, "other-owner")
    now[0] += 100_000
    reopened = JobBudget(tmp_path, budget.limits, clock=lambda: now[0])
    assert reopened.snapshot().live_reservations == 2
    with pytest.raises(ExecutionContractError, match="evidence"):
        reopened.reconcile_owner("attempt-1", cessation_evidence="")
    evidence = "run/attempt-1/termination-receipt"
    assert reopened.reconcile_owner("attempt-1", cessation_evidence=evidence) == (first,)
    receipt = _state(budget)["settlements"][first]
    assert reopened.reconcile_owner("attempt-1", cessation_evidence=evidence) == (first,)
    assert _state(budget)["settlements"][first] == receipt
    assert reopened.snapshot().live_reservations == 1
    with pytest.raises(ExecutionContractError, match="conflicting"):
        reopened.reconcile_owner("attempt-1", cessation_evidence=evidence, dispatched=False)
    with pytest.raises(ExecutionContractError, match="ceased"):
        _reserve(reopened)
    with pytest.raises(ExecutionContractError, match="unknown budget owner"):
        reopened.reconcile_owner("unrelated", cessation_evidence=evidence)


def test_positive_no_dispatch_reconciliation_releases_without_spend(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits(max_input_tokens=100, max_output_tokens=50))
    identifier = _reserve(budget)
    assert budget.reconcile_owner("attempt-1", cessation_evidence="run/not-dispatched", dispatched=False) == (identifier,)
    assert budget.snapshot().model_turns == 0
    assert budget.snapshot().actual_input_tokens == 0
    assert budget.snapshot().liability_input_tokens == 0
    assert _reserve(budget, "attempt-2")


def test_active_execution_counts_union_time_and_pauses_without_resetting_usage(tmp_path: Path) -> None:
    now = [1000.0]
    limits = _limits(timeout_seconds=30)
    budget = JobBudget(tmp_path, limits, clock=lambda: now[0], timing_mode="active_v2")
    now[0] += 500  # No active attempt: repair/queue time is not execution.
    assert budget.snapshot().elapsed_seconds == 0
    budget.resume_execution("attempt-a")
    budget.resume_execution("attempt-a")
    identifier = _reserve(budget, "attempt-a")
    budget.settle_call(identifier, usage=Usage(20, 5, 2))
    receipt = _state(budget)["settlements"][identifier]
    now[0] += 10
    budget.resume_execution("attempt-b")
    now[0] += 5
    budget.pause_execution("attempt-a", cessation_evidence="run/a/completed")
    now[0] += 5
    budget.pause_execution("attempt-b", cessation_evidence="run/b/completed")
    budget.pause_execution("attempt-b", cessation_evidence="run/b/completed")
    assert budget.snapshot().elapsed_seconds == 20
    assert budget.snapshot().active_owners == ()
    now[0] += 10_000
    reopened = JobBudget(tmp_path, limits, clock=lambda: now[0])
    assert reopened.snapshot().elapsed_seconds == 20
    assert reopened.snapshot().input_tokens == 20
    assert reopened.snapshot().actual_output_tokens == 5
    assert _state(reopened)["settlements"][identifier] == receipt
    with pytest.raises(ExecutionContractError, match="immutable"):
        reopened.resume_execution("attempt-a")
    reopened.resume_execution("attempt-c")
    now[0] += 9
    assert reopened.cell_launch_allowed()
    now[0] += 1
    assert reopened.usage_exhausted() == "timeout_seconds"
    assert reopened.snapshot().active_execution_seconds == 30


def test_active_owner_reconciliation_requires_evidence_and_charges_until_observed(tmp_path: Path) -> None:
    now = [1000.0]
    budget = JobBudget(tmp_path, _limits(), clock=lambda: now[0], timing_mode="active_v2")
    with pytest.raises(ExecutionContractError, match="active execution"):
        _reserve(budget)
    budget.resume_execution("attempt-1")
    identifier = _reserve(budget)
    now[0] += 20
    with pytest.raises(ExecutionContractError, match="live reservations"):
        budget.pause_execution("attempt-1", cessation_evidence="run/attempt-1/stopped")
    assert budget.snapshot().active_owners == ("attempt-1",)
    now[0] += 10
    budget.reconcile_owner("attempt-1", cessation_evidence="run/attempt-1/confirmed-stopped")
    snapshot = budget.snapshot()
    assert snapshot.active_owners == ()
    assert snapshot.elapsed_seconds == 30
    assert snapshot.model_turns == 1 and snapshot.liability_input_tokens == 100
    receipt = _state(budget)["settlements"][identifier]
    now[0] += 100
    assert budget.snapshot().elapsed_seconds == 30
    assert _state(budget)["settlements"][identifier] == receipt


def test_timing_modes_cannot_change_and_clock_regression_fails(tmp_path: Path) -> None:
    now = [1000.0]
    budget = JobBudget(tmp_path, _limits(), clock=lambda: now[0])
    with pytest.raises(ExecutionContractError, match="reinterpreted"):
        JobBudget(tmp_path, _limits(), timing_mode="active_v2", clock=lambda: now[0])
    with pytest.raises(ExecutionContractError, match="wall-clock"):
        budget.resume_execution("attempt-1")
    with pytest.raises(ExecutionContractError, match="wall-clock"):
        budget.pause_execution("attempt-1", cessation_evidence="run/completed")
    now[0] -= 1
    with pytest.raises(ExecutionContractError, match="regressed"):
        budget.snapshot()


def test_legacy_document_preserves_wall_clock_counters_and_unknown_history(tmp_path: Path) -> None:
    limits = _limits(timeout_seconds=30)
    legacy = {"schema": BUDGET_SCHEMA_V1, "limits": asdict(limits), "started_at": 1000.0,
              "team_packages": {"lead": 2, "hunt": 1}, "model_turns": 2, "input_tokens": 10,
              "output_tokens": 3, "retrieval_queries": 4, "exhausted": None}
    path = tmp_path / "budget.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    now = [1010.0]
    with pytest.raises(ExecutionContractError, match="reinterpreted"):
        JobBudget(tmp_path, limits, timing_mode="active_v2", clock=lambda: now[0])
    assert json.loads(path.read_text()) == legacy
    budget = JobBudget(tmp_path, limits, clock=lambda: now[0])
    snapshot = budget.snapshot()
    assert snapshot.timing_mode == "wall_clock_v1" and snapshot.elapsed_seconds == 10
    assert snapshot.team_packages == legacy["team_packages"]
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens, snapshot.retrieval_queries) == (2, 10, 3, 4)
    assert snapshot.historical_usage_complete is False
    assert snapshot.historical_usage_quality == "legacy_unverified"
    assert snapshot.actual_input_tokens is snapshot.actual_output_tokens is None
    assert _state(budget)["schema"] == BUDGET_SCHEMA_V1
    identifier = _reserve(budget)
    budget.settle_call(identifier, usage=Usage(20, 4, 0))
    assert budget.snapshot().input_tokens == 30 and budget.snapshot().actual_input_tokens is None
    now[0] = 1030.0
    assert budget.usage_exhausted() == "timeout_seconds"


def test_direct_legacy_charges_do_not_turn_missing_tokens_into_zero_actual(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    budget.charge(model_turns=1, input_tokens=5)
    snapshot = budget.snapshot()
    assert snapshot.input_tokens == snapshot.actual_input_tokens == 5
    assert snapshot.output_tokens == 0 and snapshot.actual_output_tokens is None
    assert snapshot.liability_output_tokens == budget.limits.max_output_tokens
    assert budget.reserve_call(owner_id="attempt-2", input_tokens=1, output_tokens=1) is None


@pytest.mark.parametrize("change", [
    lambda s: s.update(model_turns=True),
    lambda s: s.update(input_tokens=1),
    lambda s: s.update(exhausted=[]),
    lambda s: s.pop("settlements"),
    lambda s: s.update(accounting_version=True),
    lambda s: s["direct_usage"].update(input_tokens=-1),
    lambda s: s["reservations"].update(bad={}),
    lambda s: s["timing"].update(active_seconds=1),
    lambda s: s["timing"].update(last_observed_at=float("nan")),
    lambda s: s["timing"].update(owners={"bad": {"started_at": 0, "stopped_at": None}}),
])
def test_malformed_state_fails_explicitly_without_repair_or_writes(tmp_path: Path, change) -> None:
    budget = JobBudget(tmp_path, _limits())
    state = _state(budget)
    change(state)
    content = json.dumps(state)
    budget.state_path.write_text(content, encoding="utf-8")
    with pytest.raises(ExecutionContractError):
        JobBudget(tmp_path, _limits())
    assert budget.state_path.read_text(encoding="utf-8") == content


@pytest.mark.parametrize("change", ["usage", "dispatched", "duplicate", "cessation"])
def test_corrupted_receipts_are_not_repaired_or_recharged(tmp_path: Path, change: str) -> None:
    budget = JobBudget(tmp_path, _limits())
    identifier = _reserve(budget)
    budget.settle_call(identifier, usage=Usage(10, 5, 0))
    state = _state(budget)
    receipt = state["settlements"][identifier]
    if change == "usage":
        receipt["usage"]["cache_tokens"] = True
    elif change == "dispatched":
        receipt["dispatched"] = False
    elif change == "duplicate":
        state["reservations"][identifier] = receipt["reservation"]
    else:
        receipt["cessation_evidence"] = "unrecorded-owner-cessation"
    content = json.dumps(state)
    budget.state_path.write_text(content, encoding="utf-8")
    with pytest.raises(ExecutionContractError):
        budget.settle_call(identifier, usage=Usage(10, 5, 0))
    assert budget.state_path.read_text(encoding="utf-8") == content


@pytest.mark.parametrize("content", ['{', '[]', '{"schema": "bad"}', '{"schema": "first", "schema": "second"}'])
def test_invalid_json_or_schema_is_not_treated_as_new_budget(tmp_path: Path, content: str) -> None:
    (tmp_path / "budget.json").write_text(content, encoding="utf-8")
    with pytest.raises(ExecutionContractError):
        JobBudget(tmp_path, _limits())


def test_new_document_is_versioned_and_does_not_claim_hard_billed_limit(tmp_path: Path) -> None:
    budget = JobBudget(tmp_path, _limits())
    assert _state(budget)["schema"] == BUDGET_SCHEMA
    assert budget.snapshot().accounting_version == 2
    assert budget.snapshot().historical_usage_complete is True


def _legacy_attempt(root: Path, number: int = 1, *, limits: BudgetSettings | None = None,
                    started_at: float = 1000.0, status: str = "FAILED", **usage: int) -> Path:
    limits = limits or _limits()
    attempt = root / BUDGET_DIRECTORY.parent / "attempts" / f"attempt_{number:04d}"
    (attempt / "budget").mkdir(parents=True)
    identity = {"run_id": root.name, "job_id": "job_inference_security_review", "attempt_id": attempt.name}
    claim = {**identity, "schema": "appsec-review/attempt-claim/1",
             "attempt_path": attempt.relative_to(root).as_posix(), "started_at": "2026-01-01T00:00:00+00:00"}
    terminal = {**identity, "status": status, "started_at": claim["started_at"],
                "completed_at": "2026-01-01T00:00:01+00:00"}
    (attempt / "claim.json").write_text(json.dumps(claim), encoding="utf-8")
    (attempt / "status.json").write_text(json.dumps(terminal), encoding="utf-8")
    path = attempt / "budget" / "budget.json"
    path.write_text(json.dumps({
        "schema": BUDGET_SCHEMA_V1, "limits": asdict(limits), "started_at": started_at,
        "team_packages": {"lead": number, "hunt": 0}, "exhausted": None,
        "model_turns": 2, "input_tokens": 100, "output_tokens": 10, "retrieval_queries": 1, **usage,
    }), encoding="utf-8")
    return path


def test_for_run_imports_all_legacy_attempt_spend_once_and_pins_source_identity(tmp_path: Path) -> None:
    first = _legacy_attempt(tmp_path)
    second = _legacy_attempt(tmp_path, 2, started_at=1050.0, input_tokens=150, output_tokens=20)
    originals = {path: path.read_bytes() for path in (first, second)}
    now = [1100.0]
    budget = JobBudget.for_run(tmp_path, _limits(), clock=lambda: now[0])
    snapshot = budget.snapshot()
    assert snapshot.team_packages == {"lead": 3, "hunt": 0}
    assert (snapshot.model_turns, snapshot.input_tokens, snapshot.output_tokens, snapshot.retrieval_queries) == (
        4, 250, 30, 2)
    assert snapshot.started_at == 1000.0 and snapshot.elapsed_seconds == 100
    assert snapshot.timing_mode == "wall_clock_v1" and snapshot.historical_usage_complete is False
    assert snapshot.historical_usage_quality == "legacy_unverified"
    assert snapshot.actual_input_tokens is snapshot.actual_output_tokens is None
    assert snapshot.imported_ledgers == {path.relative_to(tmp_path).as_posix(): hashlib.sha256(content).hexdigest()
                                         for path, content in originals.items()}
    manifest = _state(budget)["legacy_imports"]
    identifier = _reserve(budget, "attempt_0003")
    budget.settle_call(identifier, usage=Usage(20, 3, 0))
    now[0] += 10
    reopened = JobBudget.for_run(tmp_path, _limits(), clock=lambda: now[0])
    assert reopened.snapshot().model_turns == 5 and reopened.snapshot().input_tokens == 270
    assert reopened.snapshot().elapsed_seconds == 110
    assert _state(reopened)["legacy_imports"] == manifest
    assert all(path.read_bytes() == content for path, content in originals.items())


def test_for_run_concurrent_legacy_import_does_not_double_charge(tmp_path: Path) -> None:
    _legacy_attempt(tmp_path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        totals = list(pool.map(lambda _: JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)
                               .snapshot().input_tokens, range(8)))
    assert totals == [100] * 8


@pytest.mark.parametrize("change", [
    "missing_claim", "mismatched_claim", "missing_status", "running_status",
    "different_limits", "noninteger_usage", "v2_attempt_ledger",
])
def test_for_run_refuses_ambiguous_import_without_creating_reset_budget(tmp_path: Path, change: str) -> None:
    source = _legacy_attempt(tmp_path)
    claim = source.parent.parent / "claim.json"
    status = source.parent.parent / "status.json"
    if change == "missing_claim":
        claim.unlink()
    elif change == "missing_status":
        status.unlink()
    elif change == "mismatched_claim":
        content = json.loads(claim.read_text())
        content["attempt_id"] = "attempt_9999"
        claim.write_text(json.dumps(content))
    elif change == "running_status":
        content = json.loads(status.read_text())
        content["status"] = "RUNNING"
        status.write_text(json.dumps(content))
    else:
        content = json.loads(source.read_text())
        if change == "different_limits":
            content["limits"]["max_input_tokens"] += 1
        elif change == "noninteger_usage":
            content["input_tokens"] = True
        else:
            content["schema"] = BUDGET_SCHEMA
        source.write_text(json.dumps(content))
    with pytest.raises((ExecutionContractError, ValueError)):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)
    assert not (tmp_path / BUDGET_DIRECTORY / "budget.json").exists()


@pytest.mark.parametrize("change", ["ledger", "claim", "status", "deleted", "added"])
def test_import_sources_cannot_change_or_be_summed_again(tmp_path: Path, change: str) -> None:
    source = _legacy_attempt(tmp_path)
    budget = JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)
    before = budget.state_path.read_bytes()
    if change == "deleted":
        source.unlink()
    elif change == "added":
        _legacy_attempt(tmp_path, 2)
    else:
        path = source if change == "ledger" else source.parent.parent / f"{change}.json"
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ExecutionContractError, match="changed"):
        budget.snapshot()
    assert budget.state_path.read_bytes() == before
    with pytest.raises(ExecutionContractError, match="changed"):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)


def test_existing_unlinked_run_ledger_and_attempt_history_are_ambiguous(tmp_path: Path) -> None:
    original = JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1000.0)
    original.charge(input_tokens=20)
    before = original.state_path.read_bytes()
    _legacy_attempt(tmp_path)
    with pytest.raises(ExecutionContractError, match="ledger set changed"):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)
    assert original.state_path.read_bytes() == before


def test_legacy_import_never_reinterprets_wall_clock_as_active_time(tmp_path: Path) -> None:
    _legacy_attempt(tmp_path)
    with pytest.raises(ExecutionContractError, match="reinterpreted"):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 2000.0, timing_mode="active_v2")
    assert not (tmp_path / BUDGET_DIRECTORY / "budget.json").exists()
    budget = JobBudget.for_run(tmp_path, _limits(), clock=lambda: 2000.0)
    assert budget.usage_exhausted() == "timeout_seconds"


def test_import_rejects_symlinked_ledgers_even_inside_run(tmp_path: Path) -> None:
    first = _legacy_attempt(tmp_path)
    second = _legacy_attempt(tmp_path, 2)
    second.unlink()
    second.symlink_to(first)
    with pytest.raises(ExecutionContractError, match="legacy budget path"):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)


def test_existing_attempt_budget_directory_without_a_ledger_is_not_zero_history(tmp_path: Path) -> None:
    source = _legacy_attempt(tmp_path)
    source.unlink()
    with pytest.raises(ExecutionContractError, match="missing its ledger"):
        JobBudget.for_run(tmp_path, _limits(), clock=lambda: 1010.0)
    assert not (tmp_path / BUDGET_DIRECTORY / "budget.json").exists()


def test_new_run_timing_option_preserves_existing_or_imported_wall_clock(tmp_path: Path) -> None:
    new_root = tmp_path / "new-run"
    fresh = JobBudget.for_run(new_root, _limits(), clock=lambda: 1000.0, new_timing_mode="active_v2")
    assert fresh.snapshot().timing_mode == "active_v2"
    fresh.resume_execution("attempt_0001")
    assert JobBudget.for_run(new_root, _limits(), clock=lambda: 1010.0).snapshot().elapsed_seconds == 10
    old_root = tmp_path / "old-run"
    JobBudget.for_run(old_root, _limits(), clock=lambda: 1000.0)
    old = JobBudget.for_run(old_root, _limits(), clock=lambda: 1010.0, new_timing_mode="active_v2")
    assert old.snapshot().timing_mode == "wall_clock_v1" and old.snapshot().elapsed_seconds == 10
    imported_root = tmp_path / "imported-run"
    _legacy_attempt(imported_root)
    imported = JobBudget.for_run(imported_root, _limits(), clock=lambda: 1010.0, new_timing_mode="active_v2")
    assert imported.snapshot().timing_mode == "wall_clock_v1" and imported.snapshot().elapsed_seconds == 10
    assert imported.snapshot().input_tokens == 100
