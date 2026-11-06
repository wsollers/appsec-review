from dataclasses import FrozenInstanceError, replace
import json

import pytest

from appsec_review.inference import ModelResult, ReviewModelRequest
from appsec_review.inference.errors import (
    ExecutionContractError, ExecutionLimit, FailureCategory, ModelCancelled, ModelOutputError,
    ProviderError,
)
from appsec_review.inference.execution import CallContext, Deadline, Execution, RetryPolicy
from appsec_review.inference.usage import Usage
from appsec_review.observability.events import PipelineLog


class Clock:
    def __init__(self):
        self.now = 0.0
        self.waits = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


def request(**changes):
    return replace(ReviewModelRequest(
        "appsec-review/worker-turn/1", "test_role", "test_persona", "", "a" * 64,
        "PRIVATE_GUIDANCE", {"source": "PRIVATE_SOURCE"}, (), "test", "test-model", "high",
        10_000, 1_000, cell_id="cell-1"), **changes)


def answer(**changes):
    return replace(ModelResult({"schema": "appsec-review/worker-turn/1", "action": "final",
                                "result": {"text": "PRIVATE_OUTPUT"}},
                               input_tokens=10, output_tokens=5, cache_tokens=2), **changes)


def test_hash_only_correlated_receipts_are_immutable_and_not_replaced(tmp_path):
    context = CallContext(tmp_path, "run-1", "job-1", "attempt-1", "step-1", "task-1")
    engine = Execution(timeout_seconds=20, max_calls=2, context=context)
    for retry in (0, 1):
        engine.call(lambda *a, **kw: answer(served_model="reported", served_provider="provider"),
                    request(), timeout_seconds=20, retry_count=retry,
                    retry_reason="provider" if retry else None)
    paths = sorted((tmp_path / "data" / "inference-executions").rglob("*.json"))
    assert len(paths) == 2 and len(engine.receipts) == 2
    first = paths[0].read_bytes()
    assert engine.receipts[0].invocation_id != engine.receipts[1].invocation_id
    with pytest.raises(FrozenInstanceError):
        engine.receipts[0].status = "changed"
    records, incomplete = PipelineLog(tmp_path).read()
    assert not incomplete
    assert [row["event_type"] for row in records] == ["MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"] * 2
    completed = records[-1]["details"]
    assert completed["retry_count"] == 1 and completed["retry_reason"] == "provider"
    assert completed["served_model"] == "reported"
    assert completed["input_tokens"] == 10 and completed["cache_tokens"] == 2
    assert records[-1]["attempt_id"] == "attempt-1"
    for payload in (json.dumps(records), first.decode()):
        assert all(secret not in payload for secret in ("PRIVATE_GUIDANCE", "PRIVATE_SOURCE", "PRIVATE_OUTPUT"))
    assert paths[0].read_bytes() == first


@pytest.mark.parametrize("value", [None, -1, True, 1.25, "5"])
def test_invalid_or_missing_usage_is_unknown(value):
    engine = Execution(timeout_seconds=20, max_calls=1)
    result = engine.call(lambda *a, **kw: answer(input_tokens=value), request(), timeout_seconds=20)
    assert result.input_tokens is None
    assert engine.receipts[0].usage.actual["input_tokens"] is None
    assert engine.receipts[0].usage.output_tokens == 5
    assert result.usage_unavailable_reason == ("provider_usage_missing" if value is None
                                              else "invalid_provider_usage")


def test_replayed_usage_is_retained_but_not_new_billing(tmp_path):
    engine = Execution(timeout_seconds=20, max_calls=1,
                       context=CallContext(tmp_path, "run", "job", "attempt"))
    result = engine.call(lambda *a, **kw: answer(usage_source="replay"), request(), timeout_seconds=20)
    assert result.input_tokens == 10 and result.usage_source == "replay"
    assert Usage.from_result(result).actual == dict.fromkeys(("input_tokens", "output_tokens", "cache_tokens"))
    rows, _ = PipelineLog(tmp_path).read()
    assert rows[-1]["details"]["input_tokens"] is None
    assert rows[-1]["details"]["usage_unavailable_reason"] == "recorded_replay"


def test_backoff_uses_configured_schedule_and_checks_cancellation():
    clock = Clock()
    checks = []
    engine = Execution(timeout_seconds=20, max_calls=3, clock=clock, sleep=clock.sleep,
                       check_cancelled=lambda: checks.append(clock()))
    policy = RetryPolicy(3, on_provider_error=True, backoff_seconds=(2, 5))
    error = ProviderError("transient", retryable=True)
    assert engine.retry(1, error, policy)
    assert sum(clock.waits) == pytest.approx(2)
    assert engine.retry(2, error, policy)
    assert sum(clock.waits) == pytest.approx(7)
    assert len(checks) > 60 and max(clock.waits) <= 0.1
    assert not engine.retry(3, error, policy)
    assert not engine.retry(1, ProviderError("authentication"), policy)
    assert not engine.retry(1, RuntimeError("programming error"), policy)
    assert not engine.retry(1, ModelOutputError("invalid"), policy)


def test_cancel_during_backoff_and_deadline_never_launch_again():
    clock = Clock()

    def cancel():
        if clock.now >= 0.3:
            raise ModelCancelled("stopped")

    deadline = Deadline(10, clock=clock, check_cancelled=cancel)
    with pytest.raises(ModelCancelled):
        deadline.wait(5, sleep=clock.sleep)
    assert clock.now < 0.5
    deadline = Deadline(0.2, clock=clock)
    with pytest.raises(ExecutionLimit, match="execution_deadline"):
        deadline.wait(5, sleep=clock.sleep)


def test_first_error_mode_never_retries(monkeypatch):
    from appsec_review.runtime import execution_safety
    monkeypatch.setattr(execution_safety, "active", lambda: True)
    policy = RetryPolicy(10, True, True, True, (2,))
    assert policy.attempts == 1
    assert not policy.allows(1, FailureCategory.SCHEMA)
    assert not policy.allows(1, ProviderError("transient", retryable=True))


@pytest.mark.parametrize(("failure", "category", "status"), [
    (TimeoutError("PRIVATE_ERROR"), "timeout", "TIMED_OUT"),
    (ModelCancelled("PRIVATE_ERROR"), "cancelled", "CANCELLED"),
    (ProviderError("PRIVATE_ERROR", retryable=True), "provider", "FAILED"),
    (ModelOutputError("PRIVATE_ERROR"), "schema", "FAILED"),
    (TypeError("PRIVATE_ERROR"), "contract", "FAILED"),
    (RuntimeError("PRIVATE_ERROR"), "contract", "FAILED"),
])
def test_typed_failure_is_retained_without_reclassifying_or_leaking(tmp_path, failure, category, status):
    engine = Execution(timeout_seconds=20, max_calls=1,
                       context=CallContext(tmp_path, "run", "job", "attempt"))

    def fail(*args, **kwargs):
        raise failure

    with pytest.raises(type(failure)) as raised:
        engine.call(fail, request(), timeout_seconds=20)
    assert raised.value is failure
    assert engine.receipts[0].category == category and engine.receipts[0].status == status
    records, _ = PipelineLog(tmp_path).read()
    assert records[-1]["details"]["failure_category"] == category
    assert "PRIVATE_ERROR" not in json.dumps(records)


def test_cancellation_after_call_preserves_returned_spend():
    stopped = False

    def check():
        if stopped:
            raise ModelCancelled("cancelled during teardown")

    def infer(*args, **kwargs):
        nonlocal stopped
        stopped = True
        return answer()

    engine = Execution(timeout_seconds=20, max_calls=1, check_cancelled=check)
    with pytest.raises(ModelCancelled):
        engine.call(infer, request(), timeout_seconds=20)
    assert engine.receipts[0].usage.input_tokens == 10
    assert engine.receipts[0].category == "cancelled"


def test_input_output_transcript_and_call_bounds():
    engine = Execution(timeout_seconds=20, max_calls=1, max_request_bytes=1)
    with pytest.raises(ExecutionLimit, match="input_byte_bound"):
        engine.call(lambda *a, **kw: pytest.fail("not admitted"), request(), timeout_seconds=20)
    assert engine.calls == 0 and not engine.receipts[0].dispatched
    engine = Execution(timeout_seconds=20, max_calls=1, max_response_bytes=1)
    with pytest.raises(ModelOutputError, match="response byte bound"):
        engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    assert engine.receipts[0].usage.input_tokens == 10
    engine = Execution(timeout_seconds=20, max_calls=2, max_total_response_bytes=180)
    engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    with pytest.raises(ExecutionLimit, match="cumulative_output"):
        engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    engine = Execution(timeout_seconds=20, max_calls=1)
    engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    with pytest.raises(ExecutionLimit, match="model_call_bound"):
        engine.call(lambda *a, **kw: pytest.fail("not admitted"), request(), timeout_seconds=20)
    engine = Execution(timeout_seconds=20, max_calls=1)
    with pytest.raises(ExecutionLimit, match="input_byte_bound"):
        engine.call(lambda *a, **kw: pytest.fail("not admitted"),
                    request(transcript=({"text": "x" * 40_000},)), timeout_seconds=20)


def test_deadline_and_provider_overrun_preserve_actual_usage():
    clock = Clock()
    engine = Execution(timeout_seconds=20, max_calls=1, clock=clock)

    def slow(*args, **kwargs):
        assert kwargs["timeout_seconds"] == 20
        clock.now = 21
        return answer()

    with pytest.raises(ExecutionLimit, match="execution_deadline"):
        engine.call(slow, request(), timeout_seconds=30)
    assert engine.receipts[0].usage.input_tokens == 10
    engine = Execution(timeout_seconds=20, max_calls=1)
    with pytest.raises(ExecutionLimit, match="model_token_cap"):
        engine.call(lambda *a, **kw: answer(output_tokens=2000), request(), timeout_seconds=20)
    assert engine.receipts[0].usage.output_tokens == 2000


def test_invalid_boundary_result_is_a_contract_error():
    engine = Execution(timeout_seconds=20, max_calls=1)
    with pytest.raises(ExecutionContractError, match="ModelResult"):
        engine.call(lambda *a, **kw: {}, request(), timeout_seconds=20)
    assert engine.receipts[0].category == "contract"
