from dataclasses import FrozenInstanceError, replace
import json

import pytest

from appsec_review.inference import ModelRequest, ModelResult, ReviewModelRequest
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


@pytest.mark.parametrize("outcome", ["success", "timeout", "cancelled", "invalid"], ids=str)
def test_transport_latency_and_admission_are_measured_separately_on_all_paths(tmp_path, outcome):
    clock = Clock()

    class Accounting:
        def reserve(self, _request):
            clock.sleep(2)
            return "reservation"

        def settle(self, _reservation, *, usage, dispatched):
            assert dispatched
            clock.sleep(3)

    engine = Execution(timeout_seconds=30, max_calls=1, clock=clock, accounting=Accounting(),
                       context=CallContext(tmp_path, "run", "job", "attempt"))

    def provider(*args, **kwargs):
        clock.sleep(5)
        if outcome == "timeout":
            raise TimeoutError("private timeout text")
        if outcome == "cancelled":
            raise ModelCancelled("private cancellation text")
        if outcome == "invalid":
            raise ModelOutputError("private invalid text", usage={"input_tokens": 70, "output_tokens": 30})
        return answer()

    if outcome == "success":
        engine.call(provider, request(), timeout_seconds=20)
    else:
        with pytest.raises((TimeoutError, ModelCancelled, ModelOutputError)):
            engine.call(provider, request(), timeout_seconds=20)
    receipt = engine.receipts[0]
    assert receipt.queue_delay_ms == 2000 and receipt.call_latency_ms == 5000 and receipt.elapsed_ms == 10000
    events, _ = PipelineLog(tmp_path).read()
    details = events[-1]["details"]
    assert details["queue_delay_ms"] == 2000 and details["call_latency_ms"] == 5000
    assert details["terminal_status"] == {
        "success": "SUCCEEDED", "timeout": "TIMED_OUT", "cancelled": "CANCELLED", "invalid": "FAILED"}[outcome]
    if outcome == "invalid":
        assert details["input_tokens"] == receipt.usage.input_tokens == 70
        assert details["output_tokens"] == 30 and details["cache_tokens"] is None
    assert "private" not in json.dumps(events)


def test_uninstrumented_admission_is_unknown_and_legacy_request_role_is_retained(tmp_path):
    clock = Clock()
    model_request = ModelRequest(
        "fixture/1", "persona", "planner", "PRIVATE_GUIDANCE", {}, (), (), (), (), (),
        "provider", "model", "high", 10000, 1000)
    engine = Execution(timeout_seconds=30, max_calls=1, clock=clock,
                       context=CallContext(tmp_path, "run", "job", "attempt"))

    def provider(*args, **kwargs):
        clock.sleep(1)
        return answer()

    engine.call(provider, model_request, timeout_seconds=10)
    details = PipelineLog(tmp_path).read()[0][-1]["details"]
    assert details["queue_delay_ms"] is None and details["call_latency_ms"] == 1000
    assert details["role"] == "planner" and details["persona"] == "persona"
    from appsec_review.observability.telemetry import aggregate_run_metrics
    summary = aggregate_run_metrics(tmp_path)
    assert summary["model_invocations"][0]["queue_delay_ms"] is None
    assert summary["model_invocations"][0]["call_latency_ms"] == 1000
    assert summary["model_invocations"][0]["role"] == "planner"


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
    with pytest.raises(ExecutionLimit, match="model_token_cap") as caught:
        engine.call(lambda *a, **kw: answer(output_tokens=2000), request(), timeout_seconds=20)
    assert engine.receipts[0].usage.output_tokens == 2000


def test_an_output_token_cap_overrun_hands_the_parsed_reply_to_the_caller_and_still_fails_the_call():
    """Run 2026-11-16-0005 discarded complete final answers whose terminal turn exceeded max_output_tokens: the
    cap is checked after the reply was parsed, so the reply exists and the caller decides what it is worth."""
    from appsec_review.inference.errors import ModelTokenCapExceeded
    engine = Execution(timeout_seconds=20, max_calls=2)
    with pytest.raises(ModelTokenCapExceeded) as caught:
        engine.call(lambda *a, **kw: answer(output_tokens=2000), request(), timeout_seconds=20)
    assert caught.value.code == "model_token_cap" and caught.value.args == ("model_token_cap",)
    assert caught.value.result.proposal == answer().proposal and (caught.value.tokens, caught.value.cap) == (2000, 1000)
    receipt = engine.receipts[0]
    assert receipt.status == "FAILED" and receipt.failure_code == "model_token_cap" and receipt.usage.output_tokens == 2000
    # An input-token overrun is not a reply worth keeping: it stays a plain limit.
    with pytest.raises(ExecutionLimit, match="model_token_cap") as plain:
        engine.call(lambda *a, **kw: answer(input_tokens=20_000), request(), timeout_seconds=20)
    assert not isinstance(plain.value, ModelTokenCapExceeded)


def test_invalid_boundary_result_is_a_contract_error():
    engine = Execution(timeout_seconds=20, max_calls=1)
    with pytest.raises(ExecutionContractError, match="ModelResult"):
        engine.call(lambda *a, **kw: {}, request(), timeout_seconds=20)
    assert engine.receipts[0].category == "contract"


def test_legacy_request_uses_pinned_guidance_and_safe_correlations(tmp_path):
    context = CallContext(tmp_path, "run", "job", "attempt", package_id="package-1", lane="lead")
    engine = Execution(timeout_seconds=20, max_calls=1, context=context, guidance_sha256="b" * 64)
    legacy = ModelRequest("test", "PRIVATE_PERSONA prose", "PRIVATE_ROLE prose", "PRIVATE_GUIDANCE",
                          {"source": "PRIVATE_SOURCE"}, (), (), (), (), (), "test", "test-model",
                          "high", 10_000, 1_000)
    engine.call(lambda *a, **kw: answer(), legacy, timeout_seconds=20)
    rows, _ = PipelineLog(tmp_path).read()
    details = rows[-1]["details"]
    assert details["guidance_bundle_sha256"] == "b" * 64
    assert details["package_id"] == "package-1" and details["lane"] == "lead"
    assert "PRIVATE_" not in json.dumps(rows)


def test_invalid_retry_contract_is_explicit():
    with pytest.raises(ValueError, match="switches"):
        RetryPolicy(on_timeout="true")
    with pytest.raises(ValueError, match="attempt"):
        RetryPolicy(2).allows(0, FailureCategory.TIMEOUT)


def test_accounting_refusal_never_reports_a_physical_model_call(tmp_path):
    class Accounting:
        def reserve(self, request):
            raise ExecutionLimit("job_budget_exhausted")

        def settle(self, *args, **kwargs):
            pytest.fail("no reservation was made")

    engine = Execution(timeout_seconds=20, max_calls=1, accounting=Accounting(),
                       context=CallContext(tmp_path, "run", "job", "attempt"))
    with pytest.raises(ExecutionLimit):
        engine.call(lambda *a, **kw: pytest.fail("not admitted"), request(), timeout_seconds=20)
    assert not engine.receipts[0].dispatched and engine.calls == 0
    assert PipelineLog(tmp_path).read() == ([], False)


def test_cancellation_after_reserving_settles_without_new_spend():
    reserved = False
    settled = []

    class Accounting:
        def reserve(self, request):
            nonlocal reserved
            reserved = True
            return "reservation-1"

        def settle(self, reservation, *, usage, dispatched):
            settled.append((reservation, dispatched, usage))

    def check():
        if reserved:
            raise ModelCancelled("cancelled before transport")

    engine = Execution(timeout_seconds=20, max_calls=1, accounting=Accounting(), check_cancelled=check)
    with pytest.raises(ModelCancelled):
        engine.call(lambda *a, **kw: pytest.fail("not admitted"), request(), timeout_seconds=20)
    assert settled[0][:2] == ("reservation-1", False)
    assert not engine.receipts[0].dispatched


def test_accounting_failure_is_explicit_and_does_not_hide_cancellation():
    class Accounting:
        def reserve(self, request):
            return "reservation-1"

        def settle(self, *args, **kwargs):
            raise OSError("storage unavailable")

    engine = Execution(timeout_seconds=20, max_calls=1, accounting=Accounting())
    with pytest.raises(ExecutionContractError, match="settlement failed"):
        engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    assert engine.receipts[0].accounting_error_class == "OSError"
    assert engine.receipts[0].category == "contract"
    engine = Execution(timeout_seconds=20, max_calls=1, accounting=Accounting())

    def cancelled(*args, **kwargs):
        raise ModelCancelled("stop")

    with pytest.raises(ModelCancelled) as raised:
        engine.call(cancelled, request(), timeout_seconds=20)
    assert "settlement failed" in raised.value.__notes__[0]
    assert engine.receipts[0].category == "cancelled"
    assert engine.receipts[0].accounting_error_class == "OSError"


def test_new_receipts_and_run_budget_have_declared_inventory_owners(tmp_path):
    from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
    from appsec_review.jobs.job_inference_security_review.datasets import DATASETS
    from appsec_review.review.budget import JobBudget
    from tests.review.test_budget import _limits

    engine = Execution(timeout_seconds=20, max_calls=1,
                       context=CallContext(tmp_path, "run", "job", "attempt"))
    engine.call(lambda *a, **kw: answer(), request(), timeout_seconds=20)
    budget = JobBudget.for_run(tmp_path, _limits())
    dataset = next(item for item in DATASETS if item.output_kind == "review_cells")
    claims = FileClaims([*runtime_claims({}),
                         Claim("job_inference_security_review", dataset.step, dataset.output_kind, dataset)])
    assert claims.file(budget.state_path.relative_to(tmp_path).as_posix()).declaration.disposition == "protected"
    tree = scan_run_tree(tmp_path, claims, max_files=100)
    assert tree.unaccounted == [] and not tree.scan_errors
    assert any(key[2] == "model_executions" for key in tree.groups)
