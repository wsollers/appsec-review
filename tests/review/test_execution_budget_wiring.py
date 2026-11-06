from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import threading
import time
from types import SimpleNamespace

import pytest

from appsec_review.config.inference_review import ModelProfileSettings, RetrySettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ModelCancelled
from appsec_review.jobs.job_inference_security_review.teams import _Cell, _Guard, _run
from appsec_review.review.budget import JobBudget
from appsec_review.review.models import CellStatus, IntegrityError
from tests.review.test_budget import _limits
from tests.review.test_cells import FakeCore, LEAD, capability, final, spec, validate
from tests.test_bounded_execution import request


def context(tmp_path, infer, *, timing_mode="active_v2", clock=time.time, **limits):
    profile = ModelProfileSettings("test", "test-model", "high", 32_000, 8_000, 4, 4, 60)
    return SimpleNamespace(
        run_root=tmp_path, run_id="run-1", attempt_id="attempt-1", infer=infer, core=FakeCore(),
        receipts_root=tmp_path / "data" / "jobs" / "job_inference_security_review" / "cells",
        budget=JobBudget.for_run(tmp_path, _limits(**limits), new_timing_mode=timing_mode, clock=clock),
        result_cache=None,
        settings=SimpleNamespace(retry=RetrySettings(2, True, True, False, (0,))),
        profile=lambda role: profile)


def cell(task="test"):
    return _Cell(replace(spec(), task=task), capability(), "red")


def result(request, **kwargs):
    return ModelResult({"schema": request.schema, **final(LEAD)}, 100, 20)


def test_atomic_admission_prevents_simultaneous_oversubscription(tmp_path):
    started, release = threading.Event(), threading.Event()
    calls = []

    def slow(request, **kwargs):
        calls.append(request)
        started.set()
        assert release.wait(3)
        return result(request)

    ctx = context(tmp_path, slow, max_model_turns=1)
    first, second = cell("first"), cell("second")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_run, ctx, first, validate)
        try:
            assert started.wait(3)
            _run(ctx, second, validate)
            assert second.record.status is CellStatus.NOT_LAUNCHED
            assert len(calls) == 1
        finally:
            release.set()
        future.result(timeout=3)
    assert first.record.status is CellStatus.SUCCEEDED
    assert ctx.budget.snapshot().model_turns == 1
    assert not ctx.budget.snapshot().active_owners


def test_provider_overrun_is_settled_before_cell_is_rejected(tmp_path):
    ctx = context(tmp_path, lambda request, **kw: replace(result(request), input_tokens=40_000),
                  max_input_tokens=32_000)
    current = cell()
    _run(ctx, current, validate)
    assert current.record.status is CellStatus.TIMED_OUT
    assert ctx.budget.snapshot().input_tokens == 40_000
    receipt = json.loads(current.outcome.receipt_paths[0].read_text())
    assert receipt["counts"]["input_tokens"] == 40_000
    assert ctx.budget.usage_exhausted() == "max_input_tokens"


def test_unknown_usage_is_not_a_free_budget_launch(tmp_path):
    ctx = context(tmp_path, lambda request, **kw: replace(result(request), input_tokens=None),
                  max_input_tokens=32_000)
    current = cell()
    _run(ctx, current, validate)
    assert current.record.status is CellStatus.SUCCEEDED
    assert current.outcome.counts["input_tokens"] is None
    assert ctx.budget.usage_exhausted() == "max_input_tokens"
    later = cell("later")
    _run(ctx, later, validate)
    assert later.record.status is CellStatus.NOT_LAUNCHED


def test_replay_records_historical_usage_without_new_billing(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_REVIEW_MODEL_RECORDING", "replay")
    ctx = context(tmp_path, lambda request, **kw: replace(result(request), usage_source="replay"))
    current = cell()
    _run(ctx, current, validate)
    assert current.record.status is CellStatus.SUCCEEDED
    assert ctx.budget.snapshot().input_tokens == ctx.budget.snapshot().output_tokens == 0
    assert current.outcome.counts["input_tokens"] == 0


def test_contract_failure_survives_team_gap_boundary(tmp_path):
    def broken(*args, **kwargs):
        raise TypeError("bad Infer implementation")

    ctx = context(tmp_path, broken)
    with pytest.raises(IntegrityError, match="execution contract failed") as raised:
        _run(ctx, cell(), validate)
    assert isinstance(raised.value.__cause__, TypeError)
    assert ctx.budget.snapshot().model_turns == 1


def test_cancel_between_reservation_and_dispatch_releases_without_charging(tmp_path, monkeypatch):
    from appsec_review.runtime import execution_safety
    checks = []

    def check():
        checks.append(True)
        if len(checks) == 2:
            raise ModelCancelled("cancelled before dispatch")

    ctx = context(tmp_path, lambda *a, **kw: pytest.fail("must not dispatch"), timing_mode="wall_clock_v1")
    monkeypatch.setattr(execution_safety, "check_running", check)
    current = cell()
    guard = _Guard(ctx, current, ctx.profile(current.spec.role), capture=False)
    with pytest.raises(ModelCancelled):
        guard(request(), timeout_seconds=60)
    assert guard.dispatches == 0 and ctx.budget.snapshot().model_turns == 0
    assert ctx.budget.cell_launch_allowed()


def test_exhaustion_blocks_new_calls_but_keeps_verified_receipt_reuse(tmp_path):
    calls = []

    def provider(request, **kwargs):
        calls.append(request)
        return result(request)

    ctx = context(tmp_path, provider, max_model_turns=1)
    first = cell()
    _run(ctx, first, validate)
    assert not ctx.budget.cell_launch_allowed()
    ctx.attempt_id = "attempt-2"
    again = cell()
    _run(ctx, again, validate)
    assert again.record.status is CellStatus.SUCCEEDED
    assert again.outcome.reused and again.outcome.result == first.outcome.result
    assert len(calls) == 1 and ctx.budget.snapshot().model_turns == 1
    assert not ctx.budget.snapshot().active_owners
    ctx.allow_new_calls = False
    fresh = cell("new-work")
    _run(ctx, fresh, validate)
    assert fresh.record.status is CellStatus.NOT_LAUNCHED and len(calls) == 1
