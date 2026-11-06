"""Manual bounded-worker recovery scenarios; does not commission a live review or deployment."""
from dataclasses import replace
from functools import partial
import json
from pathlib import Path

import pytest
import redis

from appsec_review.config.inference_review import ResultCacheSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ModelCancelled, ModelOutputError, ProviderError
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import _Cell, _memo, _run
from appsec_review.review.models import CellStatus, GapClass, Role
from appsec_review.review.result_cache import GarnetResultCache
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes
from tests.review.test_cells import capability, spec
from tests.review.test_execution_budget_wiring import context
from tests.test_bounded_execution import Clock

ROOT = Path(__file__).resolve().parents[2]
CLAIM = "claim-" + "a" * 64
BLUE = {"schema": "appsec-review/blue-result/1", "claim_id": CLAIM, "citations": {},
        "proposed_relations": [], "evidence_requests": [], "rationale": "Missing decisive evidence.",
        "task": "blue_control", "disposition": "unresolved"}


def _blue(case="blue_control"):
    return _Cell(spec(role=Role.BLUE_TEAM_REFUTER, claim_id=CLAIM, task="blue_control",
                      task_input={"case": case}, output_schema=BLUE["schema"]),
                 capability(role=Role.BLUE_TEAM_REFUTER), "blue")


def _answer(request, *, input_tokens=100, **_kwargs):
    return ModelResult({"schema": request.schema, "action": "final", "result": BLUE},
                       input_tokens=input_tokens, output_tokens=20)


def _validate():
    return partial(SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review").errors, "blue-result")


def test_interrupted_review_pause_and_resume_preserve_spend_and_prior_receipts(tmp_path):
    clock = Clock()
    phase = "normal"
    stopped = False

    def provider(request, **kwargs):
        nonlocal stopped
        clock.now += 2
        try:
            if phase == "interrupt":
                raise ModelCancelled("operator interrupted bounded worker")
            return _answer(request)
        finally:
            stopped = True

    ctx = context(tmp_path, provider, clock=clock, timeout_seconds=30)
    first = _blue()
    _run(ctx, first, _validate())
    prior = {path: path.read_bytes() for path in first.outcome.receipt_paths}
    phase = "interrupt"
    stopped = False
    interrupted = _blue("interrupted")
    with pytest.raises(ModelCancelled):
        _run(ctx, interrupted, _validate())
    snapshot = ctx.budget.snapshot()
    assert stopped and snapshot.live_reservations == 0 and len(snapshot.active_owners) == 1
    assert snapshot.model_turns == 2 and snapshot.input_tokens == 100
    assert snapshot.actual_input_tokens is None
    terminal = sorted((ctx.receipts_root / interrupted.cell_id).glob("attempt-*.json"))[-1]
    assert json.loads(terminal.read_text())["reason"] == "run_stopped"
    proof = immutable_bytes(tmp_path, "data/test-evidence/stopped.json", canonical_json({
        "owner_id": snapshot.active_owners[0], "provider_boundary_returned": stopped,
        "receipt": terminal.relative_to(tmp_path).as_posix(), "receipt_sha256": file_sha256(terminal),
    }))
    ctx.budget.reconcile_owner(snapshot.active_owners[0],
                              cessation_evidence=f"{proof['path']}#sha256={proof['sha256']}")
    paused = ctx.budget.snapshot()
    clock.now += 10_000
    assert ctx.budget.snapshot().elapsed_seconds == paused.elapsed_seconds == 4
    assert ctx.budget.snapshot().input_tokens == 100
    phase, ctx.attempt_id = "normal", "attempt-2"
    resumed = _blue("interrupted")
    _run(ctx, resumed, _validate())
    assert resumed.record.status is CellStatus.SUCCEEDED
    assert resumed.outcome.result == first.outcome.result == BLUE
    assert ctx.budget.snapshot().input_tokens == 200
    assert ctx.budget.snapshot().actual_input_tokens is None
    assert ctx.budget.snapshot().elapsed_seconds == 6
    assert all(path.read_bytes() == payload for path, payload in prior.items())
    assert terminal.exists() and json.loads(terminal.read_text())["reason"] == "run_stopped"


@pytest.mark.parametrize("failure", [
    ProviderError("transient transport", retryable=True),
    ModelOutputError("malformed reply"),
])
def test_transient_and_malformed_replies_keep_failed_receipts_and_truthful_costs(tmp_path, failure):
    calls = []

    def provider(request, **kwargs):
        calls.append(request)
        if len(calls) == 1:
            raise failure
        return _answer(request)

    ctx = context(tmp_path, provider)
    ctx.settings.retry = replace(ctx.settings.retry, retry_on_invalid_output=True)
    current = _blue()
    _run(ctx, current, _validate())
    assert current.outcome.result == BLUE and len(current.outcome.receipt_paths) == 2
    assert current.record.status is CellStatus.SUCCEEDED
    assert ctx.budget.snapshot().model_turns == 2
    assert ctx.budget.snapshot().input_tokens == 100
    assert ctx.budget.snapshot().actual_input_tokens is None
    assert json.loads(current.outcome.receipt_paths[0].read_text())["status"] in {"failed", "invalid"}


def test_cache_outage_preserves_unresolved_results_and_verifier_isolation(tmp_path, monkeypatch, caplog):
    class UnavailableClient:
        def get(self, key):
            raise redis.ConnectionError("offline cache")

    monkeypatch.setattr(redis.Redis, "from_url", lambda *args, **kwargs: UnavailableClient())
    cache = GarnetResultCache(endpoint="redis://offline.invalid:6379/0", run_id="run-1",
                              ttl_seconds=60, timeout_seconds=0.1)
    ctx = context(tmp_path, _answer)
    ctx.result_cache = cache
    ctx.settings.result_cache = ResultCacheSettings(enabled=True)
    current = _blue()
    _run(ctx, current, _validate())
    assert current.outcome.result == BLUE and current.outcome.memo_status == "unavailable"
    assert "review result cache unavailable" in caplog.text
    assert ctx.budget.snapshot().actual_input_tokens == 100
    for role in (Role.INDEPENDENT_VERIFIER, Role.ADJUDICATION_JUDGE):
        independent = _Cell(replace(current.spec, role=role), capability(role=role), "verifier")
        assert _memo(ctx, independent) is None


def test_missing_usage_exhausts_admission_without_becoming_zero_actual_cost(tmp_path):
    ctx = context(tmp_path, lambda request, **kw: _answer(request, input_tokens=None),
                  max_input_tokens=32_000)
    first = _blue()
    _run(ctx, first, _validate())
    assert first.outcome.result == BLUE
    assert ctx.budget.snapshot().actual_input_tokens is None
    assert ctx.budget.snapshot().liability_input_tokens == 32_000
    later = _blue("later")
    _run(ctx, later, _validate())
    assert later.record.status is CellStatus.NOT_LAUNCHED
    assert later.outcome.gaps[0].gap_class is GapClass.BUDGET_GAP
