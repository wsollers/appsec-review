from dataclasses import replace
import json
import shutil

import pytest

from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ModelCancelled, ProviderError
from appsec_review.review.models import CellStatus, GapClass, IntegrityError
from tests.review.test_cells import (
    LEAD, FakeCore, ScriptedInfer, capability, final, run, spec,
)
from tests.test_bounded_execution import Clock


def test_review_backoff_consumes_deadline_without_resetting_usage_or_receipts(tmp_path):
    clock = Clock()
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append((clock(), timeout_seconds))
        if len(calls) == 1:
            raise ProviderError("temporary", retryable=True)
        return ModelResult({"schema": request.schema, **final(LEAD)}, 100, 10)

    outcome = run(tmp_path, infer, max_attempts=2, backoff_seconds=(3,),
                  clock=clock, sleep=clock.sleep)
    assert calls == [(0, 60), (pytest.approx(3), 57)]
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert len(outcome.receipt_paths) == 2
    first, second = [json.loads(path.read_text()) for path in outcome.receipt_paths]
    assert first["turns"][0]["execution"]["failure_category"] == "provider"
    assert second["turns"][0]["execution"]["retry_reason"] == "provider"
    assert first["counts"]["input_tokens"] is None
    assert second["counts"]["input_tokens"] == 100
    assert outcome.counts["input_tokens"] is None


def test_retry_backoff_cannot_extend_cell_deadline(tmp_path):
    clock = Clock()
    infer = ScriptedInfer(ProviderError("temporary", retryable=True))
    outcome = run(tmp_path, infer, max_attempts=3, backoff_seconds=(61,),
                  clock=clock, sleep=clock.sleep)
    assert len(infer.requests) == 1
    assert outcome.record.status is CellStatus.TIMED_OUT
    assert outcome.gaps[-1].gap_class is GapClass.BUDGET_GAP
    assert json.loads(outcome.receipt_paths[-1].read_text())["turns"] == []


def test_nontransient_provider_failure_never_retries(tmp_path):
    infer = ScriptedInfer(ProviderError("authentication failed"), final(LEAD))
    outcome = run(tmp_path, infer, max_attempts=3)
    assert outcome.record.status is CellStatus.FAILED
    assert len(infer.requests) == 1


@pytest.mark.parametrize("error", [RuntimeError("bug"), TypeError("bad contract"), IntegrityError("bad evidence")])
def test_programming_and_integrity_errors_propagate_with_receipt(tmp_path, error):
    infer = ScriptedInfer(error)
    with pytest.raises(type(error)) as raised:
        run(tmp_path, infer, max_attempts=3)
    assert raised.value is error and len(infer.requests) == 1
    [path] = list((tmp_path / "cells").glob("*/attempt-*.json"))
    receipt = json.loads(path.read_text())
    assert receipt["reason"] == f"execution_contract_error:{type(error).__name__}"
    assert receipt["turns"][0]["execution"]["failure_category"] == "contract"


def test_cancel_during_call_and_backoff_preserves_prior_attempts(tmp_path):
    with pytest.raises(ModelCancelled):
        run(tmp_path, ScriptedInfer(ModelCancelled("stop")), max_attempts=3)
    [path] = list((tmp_path / "cells").glob("*/attempt-*.json"))
    assert json.loads(path.read_text())["reason"] == "run_stopped"
    clock = Clock()

    def cancel_wait(seconds):
        raise ModelCancelled("stop waiting")

    with pytest.raises(ModelCancelled):
        run(tmp_path / "wait", ScriptedInfer(ProviderError("temporary", retryable=True)),
            max_attempts=3, backoff_seconds=(1,), clock=clock, sleep=cancel_wait)
    paths = list((tmp_path / "wait" / "cells").glob("*/attempt-*.json"))
    assert len(paths) == 2
    assert json.loads(paths[-1].read_text())["reason"] == "run_stopped"


@pytest.mark.parametrize("value", [None, -1, True, "100", 3.5])
def test_cell_missing_invalid_usage_is_unknown_not_zero(tmp_path, value):
    outcome = run(tmp_path, lambda request, **kw: ModelResult(
        {"schema": request.schema, **final(LEAD)}, input_tokens=value, output_tokens=7))
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert outcome.counts["input_tokens"] is None and outcome.counts["output_tokens"] == 7
    turn = json.loads(outcome.receipt_paths[0].read_text())["turns"][0]
    assert turn["input_tokens"] is None


def test_cell_replay_and_no_evidence_answer_are_not_new_spend(tmp_path):
    outcome = run(tmp_path, lambda request, **kw: ModelResult(
        {"schema": request.schema, **final()}, 100, 20, usage_source="replay"))
    assert outcome.record.status is CellStatus.SUCCEEDED
    assert outcome.result == final()["result"]
    assert outcome.counts["input_tokens"] == 0 and outcome.counts["output_tokens"] == 0
    turn = json.loads(outcome.receipt_paths[0].read_text())["turns"][0]
    assert turn["replayed_usage"]["input_tokens"] == 100
    assert turn["usage_source"] == "replay"


def test_cell_input_and_output_bounds_prevent_unbounded_transcript(tmp_path):
    infer = ScriptedInfer(final(LEAD))
    outcome = run(tmp_path, infer, cell_spec=replace(spec(), task_input={"text": "x" * 128_000}))
    assert not infer.requests
    assert outcome.record.status is CellStatus.TIMED_OUT
    assert outcome.gaps[-1].gap_class is GapClass.BUDGET_GAP
    result = {"schema": "appsec-review/worker-turn/1", **final(LEAD)}
    result["result"]["text"] = "x" * 64_001
    outcome = run(tmp_path / "output", lambda *a, **kw: ModelResult(result, 10, 10))
    assert outcome.record.status is CellStatus.INVALID
    assert outcome.counts["input_tokens"] == 10


def test_first_error_mode_preserves_one_failed_receipt_and_no_retry(tmp_path, monkeypatch):
    from appsec_review.runtime import execution_safety as safety
    monkeypatch.setattr(safety, "active", lambda: True)
    infer = ScriptedInfer(ProviderError("temporary", retryable=True), final(LEAD))
    with pytest.raises(safety.ReviewStopped):
        run(tmp_path, infer, max_attempts=3)
    assert len(infer.requests) == 1
    assert len(list((tmp_path / "cells").glob("*/attempt-*.json"))) == 1


def test_recorded_timeout_replays_through_real_cell_retries_without_billing(tmp_path, monkeypatch):
    from appsec_review.inference.recording import (
        MODE_ENVIRONMENT, RECORDINGS, REPLAY_ENVIRONMENT, recorded, unit_scope,
    )
    from appsec_review.inference.execution import CallContext
    from appsec_review.observability.events import PipelineLog

    first_root, replay_root = tmp_path / "record", tmp_path / "replay-run"
    provider = ScriptedInfer(TimeoutError("bounded timeout"), final(LEAD))
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with unit_scope(run_root=first_root, job_id="job_inference_security_review",
                    repository_root=None, target_root=None):
        first = run(first_root, recorded(provider), max_attempts=2)
    assert first.record.status is CellStatus.SUCCEEDED and len(provider.requests) == 2
    recordings = first_root / RECORDINGS
    replay_copy = tmp_path / "recording-copy"
    shutil.copytree(recordings, replay_copy)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(replay_copy))

    def never(*args, **kwargs):
        pytest.fail("replay must not call a provider")

    with unit_scope(run_root=replay_root, job_id="job_inference_security_review",
                    repository_root=None, target_root=None):
        replay = run(replay_root, recorded(never), max_attempts=2,
                     execution_context=CallContext(replay_root, "run", "job_inference_security_review", "attempt"))
    assert replay.result == first.result and len(replay.receipt_paths) == 2
    assert replay.counts["input_tokens"] == replay.counts["output_tokens"] == 0
    events, _ = PipelineLog(replay_root).read()
    completed = [row["details"] for row in events if row["event_type"] == "MODEL_CALL_COMPLETED"]
    assert completed[0]["terminal_status"] == "TIMED_OUT"
    assert all(row["execution_mode"] == "replay" and row["input_tokens"] is None for row in completed)
