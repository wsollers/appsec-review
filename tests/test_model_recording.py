from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import threading

import pytest

from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.inference import recording
from appsec_review.inference.recording import (
    MODE_ENVIRONMENT, REPLAY_ENVIRONMENT, ModelReplayMiss, recorded, unit_scope)
from appsec_review.inference.errors import (
    ExecutionContractError, ExecutionLimit, ModelCancelled, ModelOutputError, ModelTimeout, ProviderError,
)
from appsec_review.inference.usage import Usage


def _request(root: Path, note: str = "plan") -> ModelRequest:
    return ModelRequest(
        schema="appsec-review/plan/1", persona="planner", role="build", guidance="g",
        summary={"target": f"{root}/targets/relay/src/main.cpp", "note": note},
        allowed_scanners=(), allowed_build_systems=("cmake",), allowed_components=(),
        allowed_paths=("src/main.cpp",), allowed_build_units=(), provider="anthropic-api",
        model="model", reasoning="low", max_input_tokens=10, max_output_tokens=10)


def _scope(root: Path, run_root: Path):
    return unit_scope(run_root=run_root, job_id="job_target_analysis_plan", repository_root=root,
                      target_root=root / "targets" / "relay")


def test_a_recorded_response_replays_for_the_same_request_under_other_roots(tmp_path, monkeypatch) -> None:
    container, host = tmp_path / "opt" / "app", tmp_path / "home" / "checkout"
    for root in (container, host):
        (root / "targets" / "relay").mkdir(parents=True)
    calls: list[ModelRequest] = []

    def live(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({"steps": [len(calls)]}, input_tokens=3, raw_response="{}")

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(container, container / "runs" / "r1"):
        first = recorded(live)(_request(container), timeout_seconds=5)
        repeated = recorded(live)(_request(container), timeout_seconds=5)

    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(container / "runs" / "r1" / recording.RECORDINGS))
    replay = recorded(lambda *args, **kwargs: pytest.fail("replay must not reach the model"))
    with _scope(host, host / "runs" / "r1"):
        assert replay(_request(host), timeout_seconds=5) == replace(
            first, usage_source="replay", usage_unavailable_reason="recorded_replay")
        assert replay(_request(host), timeout_seconds=5) == replace(
            repeated, usage_source="replay", usage_unavailable_reason="recorded_replay")
        with pytest.raises(ModelReplayMiss) as missed:
            replay(_request(host), timeout_seconds=5)
    assert len(calls) == 2 and first != repeated
    assert missed.value.sequence == 2


def test_a_request_the_recorder_never_made_fails_closed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "app"
    (root / "targets" / "relay").mkdir(parents=True)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(tmp_path / "empty"))
    with _scope(root, root / "runs" / "r1"), pytest.raises(ModelReplayMiss) as missed:
        recorded(lambda *args, **kwargs: None)(_request(root, "other"), timeout_seconds=5)
    assert missed.value.request["summary"]["target"] == "<target>/src/main.cpp"
    kept, = (root / "runs" / "r1" / recording.RECORDINGS /
             "job_target_analysis_plan" / "misses").glob("*.json")
    assert json.loads(kept.read_text(encoding="utf-8"))["request"] == missed.value.request
    assert not (tmp_path / "empty").exists()


def test_the_environment_switch_is_validated_and_scoped(tmp_path, monkeypatch) -> None:
    root = tmp_path / "app"
    live = lambda request, *, timeout_seconds: ModelResult({"ok": True})  # noqa: E731
    monkeypatch.delenv(MODE_ENVIRONMENT, raising=False)
    assert recorded(live)(_request(root), timeout_seconds=5).proposal == {"ok": True}
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with pytest.raises(RuntimeError, match="outside a job unit"):
        recorded(live)(_request(root), timeout_seconds=5)
    monkeypatch.setenv(MODE_ENVIRONMENT, "sometimes")
    with pytest.raises(ValueError, match="record or replay"):
        recorded(live)(_request(root), timeout_seconds=5)


def test_a_failed_call_is_recorded_and_replays_as_the_same_failure(tmp_path, monkeypatch) -> None:
    from appsec_review.inference import ModelOutputError

    container = tmp_path / "opt" / "app"
    (container / "targets" / "relay").mkdir(parents=True)

    def live(request, *, timeout_seconds):
        if request.summary["note"] == "first":
            raise ModelOutputError("expected exactly one proposal JSON object, found 0")
        if request.summary["note"] == "second":
            raise TimeoutError("model call timed out")
        return ModelResult({"ok": True}, input_tokens=1, raw_response="{}")

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(container, container / "runs" / "r1"):
        for note in ("first", "second"):
            with pytest.raises(Exception):
                recorded(live)(_request(container, note), timeout_seconds=5)
        recorded(live)(_request(container, "third"), timeout_seconds=5)

    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(container / "runs" / "r1" / recording.RECORDINGS))
    replay = recorded(lambda *args, **kwargs: pytest.fail("a replay must not call the model"))
    with _scope(container, container / "runs" / "r1"):
        with pytest.raises(ModelOutputError) as first:
            replay(_request(container, "first"), timeout_seconds=5)
        with pytest.raises(ModelTimeout) as second:
            replay(_request(container, "second"), timeout_seconds=5)
        assert replay(_request(container, "third"), timeout_seconds=5).proposal == {"ok": True}
    assert str(first.value) == "expected exactly one proposal JSON object, found 0"
    assert str(second.value) == "model call timed out"


def _record_one(root, monkeypatch, *, result=None, error=None):
    def live(*args, **kwargs):
        if error is not None:
            raise error
        return result or ModelResult({"ok": True}, input_tokens=11, output_tokens=7)

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(root, root / "runs" / "recorded"):
        if error is not None:
            with pytest.raises(type(error)) as raised:
                recorded(live)(_request(root), timeout_seconds=5)
            assert raised.value is error
        else:
            recorded(live)(_request(root), timeout_seconds=5)
    source = root / "runs" / "recorded" / recording.RECORDINGS
    path, = (source / "job_target_analysis_plan").glob("*.json")
    return source, path


def _replay_one(root, source, monkeypatch):
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(source))
    with _scope(root, root / "runs" / "replayed"):
        return recorded(lambda *a, **kw: pytest.fail("provider reached during replay"))(
            _request(root), timeout_seconds=5)


@pytest.mark.parametrize("error", [
    ModelTimeout("bounded timeout", code="deadline"),
    ModelCancelled("stop requested"),
    ProviderError("network unavailable", retryable=True, code="network"),
    ProviderError("authentication unavailable", code="authentication_missing"),
    ModelOutputError("invalid reply", raw_response="raw", rejected_output="reject"),
    ExecutionLimit("max_calls"),
    TypeError("programming bug"),
    RuntimeError("unexpected application error"),
])
def test_closed_error_round_trip(tmp_path, monkeypatch, error):
    source, path = _record_one(tmp_path, monkeypatch, error=error)
    doc = json.loads(path.read_text())
    assert "result" not in doc and doc["schema"] == recording.SCHEMA
    expected = ExecutionContractError if type(error) in (TypeError, RuntimeError) else type(error)
    with pytest.raises(expected) as raised:
        _replay_one(tmp_path, source, monkeypatch)
    if expected is ExecutionContractError:
        assert type(raised.value) is ExecutionContractError
        assert type(error).__name__ in str(raised.value)
    else:
        assert str(raised.value) == str(error)
    for name in ("code", "retryable", "raw_response", "rejected_output"):
        if hasattr(error, name):
            assert getattr(raised.value, name) == getattr(error, name)


def test_subprocess_timeout_recording_never_retains_command(tmp_path, monkeypatch):
    import subprocess
    source, path = _record_one(tmp_path, monkeypatch,
        error=subprocess.TimeoutExpired(["secret-command", "secret-argument"], 1, output="secret-output"))
    assert "secret" not in path.read_text()
    with pytest.raises(ModelTimeout, match="model transport timed out"):
        _replay_one(tmp_path, source, monkeypatch)


def test_replay_usage_is_historical_not_new_spend_and_counts_reset_per_invocation(tmp_path, monkeypatch):
    source, _ = _record_one(tmp_path, monkeypatch)
    for _ in range(2):
        result = _replay_one(tmp_path, source, monkeypatch)
        assert (result.input_tokens, result.output_tokens) == (11, 7)
        assert result.usage_source == "replay"
        assert Usage.from_result(result).actual == {
            "input_tokens": None, "output_tokens": None, "cache_tokens": None}


@pytest.mark.parametrize("value", [-1, True, 2.5, "3", None])
def test_live_recording_normalizes_unknown_usage(tmp_path, monkeypatch, value):
    source, path = _record_one(tmp_path, monkeypatch,
                              result=ModelResult({}, input_tokens=value, output_tokens=2))
    assert json.loads(path.read_text())["result"]["input_tokens"] is None
    result = _replay_one(tmp_path, source, monkeypatch)
    assert result.input_tokens is None and result.output_tokens == 2


def test_identical_concurrent_calls_reserve_sequence_before_completion(tmp_path, monkeypatch):
    started, release = threading.Event(), threading.Event()
    lock = threading.Lock()
    calls = 0

    def live(*args, **kwargs):
        nonlocal calls
        with lock:
            ordinal = calls
            calls += 1
        if ordinal == 0:
            started.set()
            assert release.wait(5)
        return ModelResult({"ordinal": ordinal})

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, tmp_path / "runs" / "recorded"), ThreadPoolExecutor(2) as pool:
        first = pool.submit(recorded(live), _request(tmp_path), timeout_seconds=5)
        assert started.wait(5)
        try:
            assert pool.submit(recorded(live), _request(tmp_path), timeout_seconds=5).result(5).proposal == {
                "ordinal": 1}
        finally:
            release.set()
        assert first.result(5).proposal == {"ordinal": 0}
    source = tmp_path / "runs" / "recorded" / recording.RECORDINGS
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(source))
    with _scope(tmp_path, tmp_path / "runs" / "replay"):
        replay = recorded(lambda *a, **kw: pytest.fail("unexpected live call"))
        assert [replay(_request(tmp_path), timeout_seconds=5).proposal["ordinal"]
                for _ in range(2)] == [0, 1]


def test_a_rerun_attempt_appends_its_recordings_after_an_earlier_attempt(tmp_path, monkeypatch):
    """A repair re-runs a job under the same run root; its model calls for the same request must be
    recorded after the first attempt's, not refused. Regression for smoke-cpp run 2026-11-14-0001,
    where dependency_intelligence attempt_0002 failed with "stale model recording exists at dispatch
    admission"."""
    source, first = _record_one(tmp_path, monkeypatch)
    live = lambda *args, **kwargs: ModelResult({"ok": "again"}, input_tokens=1, output_tokens=1)
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        result = recorded(live)(_request(tmp_path), timeout_seconds=5)
        second_call = recorded(live)(_request(tmp_path), timeout_seconds=5)
    assert result.proposal == {"ok": "again"} and second_call.proposal == {"ok": "again"}
    paths = sorted((source / "job_target_analysis_plan").glob("*.json"))
    assert [path.name.rsplit(".", 2)[1] for path in paths] == ["0000", "0001", "0002"]
    assert paths[0] == first
    assert json.loads(paths[1].read_text())["sequence"] == 1
    # Replay still serves the first attempt's recording for the first call.
    assert _replay_one(tmp_path, source, monkeypatch).proposal == {"ok": True}


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(job_id="other"),
    lambda d: d.update(key="0" * 64),
    lambda d: d.update(sequence=True),
    lambda d: d.update(sequence="0"),
    lambda d: d.update(sequence=1),
    lambda d: d["request"]["summary"].update(note="changed"),
    lambda d: d.update(origin="0" * 32),
    lambda d: d.update(extra="unrecognized"),
    lambda d: d.update(error={"category": "timeout", "message": "", "code": "deadline"}),
    lambda d: d.pop("result"),
    lambda d: d["result"].update(input_tokens=True),
    lambda d: d["result"].update(output_tokens=-1),
    lambda d: d["result"].update(cache_tokens=1.1),
    lambda d: d["result"].update(raw_response=17),
    lambda d: d["result"].update(served_provider=[]),
    lambda d: d["result"].update(usage_source="cache"),
    lambda d: d["result"].pop("usage_source"),
    lambda d: d["result"].update(proposal=[]),
    lambda d: d["result"]["proposal"].update(number=float("nan")),
    lambda d: d["result"]["proposal"].update(number=float("inf")),
    lambda d: d["result"]["proposal"].update(number=2 ** 64),
    lambda d: d["result"].update(usage_unavailable_reason="x" * 257),
])
def test_malformed_or_stale_recording_fails_closed(tmp_path, monkeypatch, mutation):
    source, path = _record_one(tmp_path, monkeypatch)
    doc = json.loads(path.read_text())
    mutation(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ExecutionContractError):
        _replay_one(tmp_path, source, monkeypatch)


@pytest.mark.parametrize("error", [
    {"category": "other", "message": "bad"},
    {"category": "timeout", "message": [], "code": "deadline"},
    {"category": "timeout", "message": "", "code": "bad code"},
    {"category": "provider", "message": "", "code": "network", "retryable": 1},
    {"category": "cancelled", "message": "", "code": "execute_command"},
    {"category": "schema", "message": "", "raw_response": "x", "rejected_output": 3},
    {"category": "schema", "message": "", "raw_response": "x"},
    {"category": "contract", "message": "", "code": "application_contract_failure",
     "exception_type": "fake", "module": "os"},
    {"category": "budget", "message": "other", "code": "max_calls"},
])
def test_error_fields_are_closed_and_strict(tmp_path, monkeypatch, error):
    source, path = _record_one(tmp_path, monkeypatch, error=ModelTimeout())
    doc = json.loads(path.read_text())
    doc["error"] = {**error, "notes": [], "cause": None}
    path.write_text(json.dumps(doc))
    with pytest.raises(ExecutionContractError):
        _replay_one(tmp_path, source, monkeypatch)


@pytest.mark.parametrize("raw", ['{"schema":', "[]", '{"key":1,"key":2}', '{"a":' + "[" * 1000])
def test_malformed_json_is_explicit_contract_failure(tmp_path, monkeypatch, raw):
    source, path = _record_one(tmp_path, monkeypatch)
    path.write_text(raw)
    with pytest.raises(ExecutionContractError):
        _replay_one(tmp_path, source, monkeypatch)


def test_v2_requires_bound_recording_root(tmp_path, monkeypatch):
    source, _ = _record_one(tmp_path, monkeypatch)
    (source / recording._ROOT_FILE).unlink()
    with pytest.raises(ExecutionContractError, match="source root"):
        _replay_one(tmp_path, source, monkeypatch)


def test_replay_source_cannot_change_within_an_invocation(tmp_path, monkeypatch):
    source, _ = _record_one(tmp_path, monkeypatch)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(source))
    with _scope(tmp_path, tmp_path / "runs" / "replay"):
        replay = recorded(lambda *a, **kw: pytest.fail("unexpected provider call"))
        replay(_request(tmp_path), timeout_seconds=5)
        monkeypatch.setenv(REPLAY_ENVIRONMENT, str(tmp_path / "other"))
        with pytest.raises(ExecutionContractError, match="source changed"):
            replay(_request(tmp_path), timeout_seconds=5)


def test_v1_success_is_readable_without_guessing_error_semantics(tmp_path, monkeypatch):
    source, path = _record_one(tmp_path, monkeypatch)
    doc = json.loads(path.read_text())
    doc["schema"] = recording._LEGACY_SCHEMA
    doc.pop("origin")
    doc["result"].pop("usage_source")
    doc["result"].pop("usage_unavailable_reason")
    path.write_text(json.dumps(doc))
    (source / recording._ROOT_FILE).unlink()
    assert _replay_one(tmp_path, source, monkeypatch).input_tokens == 11
    for name in ("TimeoutError", "TimeoutExpired", "ModelOutputError", "RuntimeError", "CustomError"):
        doc["result"] = None
        doc["error"] = {"type": name, "message": "old failure"}
        path.write_text(json.dumps(doc))
        with pytest.raises(ExecutionContractError, match="v1 recorded errors"):
            _replay_one(tmp_path, source, monkeypatch)


def test_stale_recording_rejected_before_another_live_call(tmp_path, monkeypatch):
    _, path = _record_one(tmp_path, monkeypatch)
    before = path.read_bytes()
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        with pytest.raises(ExecutionContractError, match="stale"):
            recorded(lambda *a, **kw: pytest.fail("stale recording reached provider"))(
                _request(tmp_path), timeout_seconds=5)
    assert path.read_bytes() == before


def test_publication_is_complete_and_immutable(tmp_path, monkeypatch):
    link = recording.os.link
    observed = []

    def check(staging, destination):
        assert not destination.exists()
        observed.append(json.loads(staging.read_text()))
        link(staging, destination)

    monkeypatch.setattr(recording.os, "link", check)
    _, path = _record_one(tmp_path, monkeypatch)
    assert len(observed) == 2
    assert observed[1]["result"]["proposal"] == {"ok": True}
    assert list(path.parent.glob("*.pending")) == []
    monkeypatch.setattr(recording.os, "link", link)
    before = path.read_bytes()
    with pytest.raises(ExecutionContractError, match="stale or competing"):
        recording._publish(path, {"different": True})
    assert path.read_bytes() == before


def test_cancellation_survives_recording_write_failure(tmp_path, monkeypatch):
    publish = recording._publish

    def fail_record(path, doc):
        if "error" in doc:
            raise OSError("disk full")
        publish(path, doc)

    monkeypatch.setattr(recording, "_publish", fail_record)
    cancelled = ModelCancelled("stop")
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        def live(*a, **kw):
            raise cancelled
        with pytest.raises(ModelCancelled) as raised:
            recorded(live)(_request(tmp_path), timeout_seconds=5)
    assert raised.value is cancelled
    assert raised.value.__notes__ == ["model error recording could not be published"]
    assert isinstance(raised.value.__cause__, OSError)


def test_miss_diagnostic_failure_is_visible(tmp_path, monkeypatch):
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(tmp_path / "empty"))
    monkeypatch.setattr(recording, "_publish", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with _scope(tmp_path, tmp_path / "runs" / "replay"):
        with pytest.raises(ModelReplayMiss) as raised:
            recorded(lambda *a, **kw: pytest.fail("replay reached model"))(_request(tmp_path), timeout_seconds=5)
    assert raised.value.diagnostic_error == "replay miss diagnostic publication failed"
    assert raised.value.__notes__ == [raised.value.diagnostic_error]


def test_success_cannot_escape_an_unpublished_recording(tmp_path, monkeypatch):
    publish = recording._publish

    def fail_result(path, document):
        if "result" in document:
            raise ExecutionContractError("publication failed")
        publish(path, document)

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    monkeypatch.setattr(recording, "_publish", fail_result)
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        with pytest.raises(ExecutionContractError, match="publication failed"):
            recorded(lambda *a, **kw: ModelResult({}))(_request(tmp_path), timeout_seconds=5)


def test_schema_repair_replays_exact_bounded_evidence(tmp_path, monkeypatch):
    original = ModelOutputError("bad reply", raw_response='{"result": "not JSON"}',
                                rejected_output="not JSON")

    def live(req, **kwargs):
        if not req.repair_errors:
            raise original
        return ModelResult({"repaired": True})

    def exchange():
        wrapped = recorded(live)
        with pytest.raises(ModelOutputError) as raised:
            wrapped(_request(tmp_path), timeout_seconds=5)
        repaired = replace(_request(tmp_path), repair_errors=(str(raised.value),),
                           prior_response=raised.value.rejected_output)
        assert raised.value.raw_response == original.raw_response
        assert wrapped(repaired, timeout_seconds=5).proposal == {"repaired": True}

    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        exchange()
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(tmp_path / "runs" / "recorded" / recording.RECORDINGS))
    with _scope(tmp_path, tmp_path / "runs" / "replay"):
        exchange()


def test_oversized_error_evidence_is_rejected_not_silently_truncated(tmp_path, monkeypatch):
    error = ModelOutputError("bad reply", raw_response="a" * (recording._RESPONSE_BYTES + 1))
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, tmp_path / "runs" / "recorded"):
        def live(*a, **kw):
            raise error
        with pytest.raises(ModelOutputError) as raised:
            recorded(live)(_request(tmp_path), timeout_seconds=5)
    assert raised.value is error
    assert isinstance(raised.value.__cause__, ExecutionContractError)
    assert not list((tmp_path / "runs" / "recorded" / recording.RECORDINGS /
                     "job_target_analysis_plan").glob("*.json"))


def test_oversized_document_and_overdeep_json_are_explicit_contract_failures(tmp_path, monkeypatch):
    source, path = _record_one(tmp_path, monkeypatch)
    original = json.loads(path.read_text())
    path.write_bytes(b" " * (recording._DOCUMENT_BYTES + 1))
    with pytest.raises(ExecutionContractError, match="bounded regular"):
        _replay_one(tmp_path, source, monkeypatch)
    value = {}
    for _ in range(70):
        value = {"nested": value}
    original["result"]["proposal"] = value
    path.write_text(json.dumps(original))
    with pytest.raises(ExecutionContractError, match="structure bounds"):
        _replay_one(tmp_path, source, monkeypatch)


def test_recording_symlink_is_not_followed(tmp_path, monkeypatch):
    source, path = _record_one(tmp_path, monkeypatch)
    target = tmp_path / "external.json"
    path.rename(target)
    path.symlink_to(target)
    with pytest.raises(ExecutionContractError, match="unreadable"):
        _replay_one(tmp_path, source, monkeypatch)


def test_recording_writes_cannot_follow_a_run_directory_symlink(tmp_path, monkeypatch):
    run = tmp_path / "runs" / "recorded"
    outside = tmp_path / "other"
    run.mkdir(parents=True)
    outside.mkdir()
    (run / "data").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv(MODE_ENVIRONMENT, "record")
    with _scope(tmp_path, run):
        with pytest.raises(ExecutionContractError, match="run-owned"):
            recorded(lambda *a, **kw: pytest.fail("provider called before path validation"))(
                _request(tmp_path), timeout_seconds=5)
    assert list(outside.iterdir()) == []


def test_changed_root_identity_during_a_unit_is_detected(tmp_path, monkeypatch):
    source, _ = _record_one(tmp_path, monkeypatch)
    monkeypatch.setenv(MODE_ENVIRONMENT, "replay")
    monkeypatch.setenv(REPLAY_ENVIRONMENT, str(source))
    with _scope(tmp_path, tmp_path / "runs" / "replay"):
        replay = recorded(lambda *a, **kw: pytest.fail("provider called during replay"))
        replay(_request(tmp_path), timeout_seconds=5)
        (source / recording._ROOT_FILE).write_text(json.dumps({
            "schema": recording._ROOT_SCHEMA, "recording_id": "0" * 32}))
        with pytest.raises(ExecutionContractError, match="identity changed"):
            replay(_request(tmp_path), timeout_seconds=5)


def test_cancelled_replay_preserves_secondary_cleanup_failure_and_notes(tmp_path, monkeypatch):
    cancelled = ModelCancelled("stop")
    cancelled.add_note("cleanup unconfirmed")
    cancelled.__cause__ = ExecutionContractError("Copilot session abort failed")
    source, _ = _record_one(tmp_path, monkeypatch, error=cancelled)
    with pytest.raises(ModelCancelled) as replayed:
        _replay_one(tmp_path, source, monkeypatch)
    assert replayed.value.__notes__ == ["cleanup unconfirmed"]
    assert isinstance(replayed.value.__cause__, ExecutionContractError)
    assert "Copilot session abort failed" in str(replayed.value.__cause__)


@pytest.mark.parametrize("mutate", [
    lambda error: error.update(notes="not a list"),
    lambda error: error.update(notes=["n"] * 9),
    lambda error: error.update(notes=[3]),
    lambda error: error.update(notes=["n" * 1025]),
    lambda error: error.update(cause=[]),
    lambda error: error.pop("cause"),
    lambda error: error.pop("notes"),
])
def test_closed_secondary_error_evidence(tmp_path, monkeypatch, mutate):
    source, path = _record_one(tmp_path, monkeypatch, error=ModelCancelled("stop"))
    doc = json.loads(path.read_text())
    mutate(doc["error"])
    path.write_text(json.dumps(doc))
    with pytest.raises(ExecutionContractError):
        _replay_one(tmp_path, source, monkeypatch)
