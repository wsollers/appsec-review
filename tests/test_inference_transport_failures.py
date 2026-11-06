"""Offline failure/usage contracts at the real subprocess and HTTP adapter boundaries."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from io import BytesIO
from http.client import BadStatusLine, IncompleteRead
import json
import socket
import ssl
import subprocess
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest

from appsec_review import inference
from appsec_review.inference import anthropic_api, claude_cli
from appsec_review.inference.errors import (
    ExecutionContractError, ModelCancelled, ModelOutputError, ModelTimeout, ProviderError,
)
from appsec_review.inference.request import ModelRequest, ModelResult
from appsec_review.runtime import execution_safety as safety


SCHEMA = "appsec-review/worker-turn/1"
PROPOSAL = {"schema": SCHEMA, "action": "final", "result": {}}


def request(provider="anthropic-api"):
    return ModelRequest(schema=SCHEMA, persona="p", role="r", guidance="g", summary={},
                        allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
                        allowed_paths=(), allowed_build_units=(), provider=provider, model="example",
                        reasoning="low", max_input_tokens=100, max_output_tokens=100)


class Response(BytesIO):
    pass


def fail(error):
    def raise_error(*args, **kwargs):
        raise error
    return raise_error


@pytest.fixture
def cli(monkeypatch):
    state = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({
        "result": json.dumps(PROPOSAL), "usage": {"input_tokens": 2, "output_tokens": 3},
        "model": "example"}))
    monkeypatch.setattr(claude_cli.shutil, "which", lambda _: "/fixture/claude")
    monkeypatch.setattr(claude_cli.subprocess, "run", lambda *a, **kw: state)
    return state


@pytest.fixture
def http(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture-key")
    state = SimpleNamespace(value={
        "content": [{"type": "text", "text": json.dumps(PROPOSAL)}],
        "usage": {"input_tokens": 2, "output_tokens": 3}, "model": "example"}, raw=None)
    monkeypatch.setattr(anthropic_api, "urlopen", lambda *a, **kw: Response(
        state.raw if state.raw is not None else json.dumps(state.value).encode()))
    return state


def test_subprocess_timeout_is_typed_without_command_or_streams(cli, monkeypatch):
    monkeypatch.setattr(claude_cli.subprocess, "run", fail(subprocess.TimeoutExpired(
        ["claude", "secret-argument"], 2, output="private stdout", stderr="private stderr")))
    with pytest.raises(ModelTimeout) as raised:
        inference.infer(request("claude-cli"), timeout_seconds=2)
    assert str(raised.value) == "Claude CLI call timed out"
    assert raised.value.code == "provider_timeout"
    assert raised.value.__suppress_context__


def test_cli_nonzero_exit_is_nontransient_provider_error_without_raw_stderr(cli):
    cli.returncode, cli.stderr = 1, "secret stderr"
    with pytest.raises(ProviderError) as raised:
        claude_cli.send(request("claude-cli"), timeout_seconds=2)
    assert not raised.value.retryable
    assert raised.value.code == "cli_exit"
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("status,retryable", [
    (400, False), (401, False), (403, False), (404, False), (408, True), (429, True),
    (500, True), (501, False), (502, True), (503, True), (504, True), (529, True),
])
def test_http_status_is_typed_and_only_transient_statuses_retry(http, monkeypatch, status, retryable):
    body = BytesIO(b"secret-body")
    error = HTTPError("https://private.invalid", status, "secret detail", {}, body)
    monkeypatch.setattr(anthropic_api, "urlopen", fail(error))
    with pytest.raises(ProviderError) as raised:
        anthropic_api.send(request(), timeout_seconds=2)
    assert raised.value.code == f"http_{status}" and raised.value.retryable is retryable
    assert "secret" not in str(raised.value) and "private" not in str(raised.value)
    assert body.closed


@pytest.mark.parametrize("error,expected,retryable", [
    (URLError(socket.timeout("secret")), ModelTimeout, None),
    (TimeoutError("secret"), ModelTimeout, None),
    (URLError(ConnectionResetError("secret")), ProviderError, True),
    (ConnectionResetError("secret"), ProviderError, True),
    (URLError(socket.gaierror(socket.EAI_AGAIN, "secret")), ProviderError, True),
    (URLError(socket.gaierror(socket.EAI_NONAME, "secret")), ProviderError, False),
    (URLError(ssl.SSLCertVerificationError("secret")), ProviderError, False),
    (URLError("unclassified reason"), ProviderError, False),
    (ssl.SSLCertVerificationError("secret"), ProviderError, False),
    (IncompleteRead(b"secret"), ProviderError, True),
    (BadStatusLine("secret"), ProviderError, False),
])
def test_http_network_failure_categories(http, monkeypatch, error, expected, retryable):
    monkeypatch.setattr(anthropic_api, "urlopen", fail(error))
    with pytest.raises(expected) as raised:
        anthropic_api.send(request(), timeout_seconds=2)
    assert "secret" not in str(raised.value)
    if retryable is not None:
        assert raised.value.retryable is retryable


@pytest.mark.parametrize("provider", ["anthropic-api", "claude-cli"])
@pytest.mark.parametrize("error", [TypeError("bug"), ValueError("bug"), RuntimeError("bug")])
def test_unexpected_boundary_bugs_are_not_provider_failures(cli, http, monkeypatch, provider, error):
    if provider == "anthropic-api":
        monkeypatch.setattr(anthropic_api, "urlopen", fail(error))
    else:
        monkeypatch.setattr(claude_cli.subprocess, "run", fail(error))
    evidence = []
    monkeypatch.setattr(safety, "retain_failure", lambda action, error, **kw: evidence.append((error, kw)))
    with pytest.raises(type(error)) as raised:
        inference.infer(request(provider), timeout_seconds=2)
    assert raised.value is error
    assert evidence[0][1]["category"] == "contract"
    assert evidence[0][1]["exception_type"] == type(error).__name__


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"[]", b'{"content": null}',
    b'{"content": 12}', b'{"content": ["bad"]}', b'{"content": [{"type": "text"}]}',
    b'{"content": [{"type": "text", "text": 123}]}'])
def test_malformed_http_json_and_content_are_schema_failures(http, raw):
    http.raw = raw
    with pytest.raises(ModelOutputError):
        anthropic_api.send(request(), timeout_seconds=2)


@pytest.mark.parametrize("provider", ["anthropic-api", "claude-cli"])
@pytest.mark.parametrize("value", [None, -1, True, "2", 1.5])
def test_transports_normalize_unknown_usage_independently(cli, http, provider, value):
    if provider == "anthropic-api":
        http.value["usage"] = {"input_tokens": value, "output_tokens": 3, "cache_read_input_tokens": 0}
    else:
        envelope = json.loads(cli.stdout)
        envelope["usage"] = {"input_tokens": value, "output_tokens": 3, "cache_read_input_tokens": 0}
        cli.stdout = json.dumps(envelope)
    result = inference.PROVIDERS[provider](request(provider), timeout_seconds=2)
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (None, 3, 0)
    assert result.usage_unavailable_reason == (
        "provider_usage_missing" if value is None else "invalid_provider_usage")


@pytest.mark.parametrize("provider", ["anthropic-api", "claude-cli"])
@pytest.mark.parametrize("value", [None, [], "3", True])
def test_nonobject_usage_is_unknown_not_an_application_crash(cli, http, provider, value):
    if provider == "anthropic-api":
        http.value["usage"] = value
    else:
        envelope = json.loads(cli.stdout)
        envelope["usage"] = value
        cli.stdout = json.dumps(envelope)
    result = inference.PROVIDERS[provider](request(provider), timeout_seconds=2)
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (None, None, None)
    assert result.usage_unavailable_reason == "invalid_provider_usage"


@pytest.mark.parametrize("error,expected", [
    (ModelOutputError("private error", raw_response="secret", rejected_output="private"), ModelOutputError),
    (ModelTimeout("private timeout"), ModelTimeout),
    (ProviderError("private auth", code="authentication_missing"), ProviderError),
    (TypeError("private bug"), ExecutionContractError),
])
def test_planning_sanitizes_without_erasing_categories(monkeypatch, error, expected):
    req = replace(request(), schema="appsec-review/target-analysis-proposal/3")
    monkeypatch.setitem(inference.PROVIDERS, req.provider, fail(error))
    with pytest.raises(expected) as raised:
        inference.infer(req, timeout_seconds=2)
    assert "private" not in str(raised.value)
    assert getattr(raised.value, "raw_response", None) is None
    assert getattr(raised.value, "rejected_output", None) is None


def test_first_error_planning_failure_leaves_safety_operation_as_failure(monkeypatch):
    seen = []

    @contextmanager
    def operation(action):
        try:
            yield
        except BaseException as error:
            seen.append(type(error))
            raise ModelCancelled("first error stop")

    monkeypatch.setattr(safety, "operation", operation)
    monkeypatch.setattr(safety, "active", lambda: True)
    monkeypatch.setattr(safety, "retain_failure", lambda *a, **kw: None)
    monkeypatch.setitem(inference.PROVIDERS, "anthropic-api", fail(ModelOutputError("invalid")))
    with pytest.raises(ModelCancelled, match="first error"):
        inference.infer(replace(request(), schema="appsec-review/target-analysis-proposal/3"),
                        timeout_seconds=2)
    assert seen == [ModelOutputError]


def test_dispatch_rejects_invalid_result_contract(monkeypatch):
    monkeypatch.setitem(inference.PROVIDERS, "anthropic-api", lambda *a, **kw: {"proposal": {}})
    with pytest.raises(ExecutionContractError, match="Infer must return ModelResult"):
        inference.infer(request(), timeout_seconds=2)


def test_cancellation_is_not_swallowed_when_evidence_cannot_be_written(monkeypatch):
    cancelled = ModelCancelled("cancelled")
    monkeypatch.setitem(inference.PROVIDERS, "anthropic-api", fail(cancelled))
    monkeypatch.setattr(safety, "retain_failure", fail(OSError("disk full")))
    with pytest.raises(ModelCancelled) as raised:
        inference.infer(request(), timeout_seconds=2)
    assert raised.value is cancelled
    assert raised.value.__notes__ == ["model cancellation evidence could not be published"]
    assert isinstance(raised.value.__cause__, OSError)


def test_http_cancellation_checks_before_success_and_closes_response(http, monkeypatch):
    response = Response(json.dumps(http.value).encode())
    monkeypatch.setattr(anthropic_api, "urlopen", lambda *a, **kw: response)

    def check():
        if response.closed:
            raise ModelCancelled("stopped during bounded IO")

    monkeypatch.setattr(safety, "check_running", check)
    with pytest.raises(ModelCancelled):
        anthropic_api.send(request(), timeout_seconds=2)
    assert response.closed


def test_http_elapsed_deadline_cannot_return_late_success(http, monkeypatch):
    ticks = iter((0, 3))
    monkeypatch.setattr(anthropic_api.time, "monotonic", lambda: next(ticks))
    with pytest.raises(ModelTimeout):
        anthropic_api.send(request(), timeout_seconds=2)


def test_http_streaming_checks_cancellation_between_chunks(http, monkeypatch):
    class StreamingResponse(Response):
        reads = 0

        def read1(self, limit):
            self.reads += 1
            return b"x"

    response = StreamingResponse(b"")
    monkeypatch.setattr(anthropic_api, "urlopen", lambda *a, **kw: response)

    def check():
        if response.reads:
            raise ModelCancelled("stopped while streaming")

    monkeypatch.setattr(safety, "check_running", check)
    with pytest.raises(ModelCancelled):
        anthropic_api.send(request(), timeout_seconds=2)
    assert response.reads == 1 and response.closed


def test_http_streaming_keeps_one_deadline_and_reduces_socket_timeout(http, monkeypatch):
    budgets = []

    class StreamingResponse(Response):
        reads = 0
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=budgets.append)))

        def read1(self, limit):
            self.reads += 1
            return b"x"

    response = StreamingResponse(b"")
    ticks = iter((0, 0.5, 1, 2))
    monkeypatch.setattr(anthropic_api.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(anthropic_api, "urlopen", lambda *a, **kw: response)
    with pytest.raises(ModelTimeout):
        anthropic_api.send(request(), timeout_seconds=2)
    assert response.reads == 2 and budgets == [1.5, 1]
    assert response.closed


@pytest.mark.parametrize("provider", ["claude-cli", "anthropic-api"])
@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), "1"])
def test_transport_deadlines_are_finite_positive_values(cli, http, provider, timeout):
    with pytest.raises(ExecutionContractError, match="finite and positive"):
        inference.PROVIDERS[provider](request(provider), timeout_seconds=timeout)


@pytest.mark.parametrize("failed_cleanup", [False, True])
def test_cli_cancellation_reaps_owned_process_and_never_becomes_provider_gap(cli, monkeypatch, failed_cleanup):
    from appsec_review.runtime import resources
    state = SimpleNamespace(polls=0, killed=[], cleaned=False, failures=[], quarantined=[])
    cancelled = ModelCancelled("stop requested")

    def check():
        if state.polls:
            raise cancelled

    class Process:
        pid = 12345
        returncode = None

        def poll(self):
            return None

        def communicate(self, input=None, timeout=None):
            if state.killed:
                if failed_cleanup:
                    raise subprocess.TimeoutExpired(["secret-command"], timeout)
                state.cleaned = True
                return "", ""
            state.polls += 1
            raise subprocess.TimeoutExpired(["secret-command"], timeout)

    monkeypatch.setattr(safety, "check_running", check)
    monkeypatch.setattr(safety, "active", lambda: True)
    monkeypatch.setattr(safety, "retain_failure", lambda *a, **kw: state.failures.append(a))
    monkeypatch.setattr(resources, "quarantine_resources", state.quarantined.append)
    monkeypatch.setattr(claude_cli.subprocess, "Popen", lambda *a, **kw: Process())
    monkeypatch.setattr(claude_cli.os, "killpg", lambda pid, sig: state.killed.append(pid))
    with pytest.raises(ModelCancelled) as raised:
        claude_cli.send(request("claude-cli"), timeout_seconds=2)
    assert raised.value is cancelled
    assert state.killed == [12345]
    if failed_cleanup:
        assert state.failures and state.quarantined
        assert isinstance(raised.value.__cause__, ExecutionContractError)
    else:
        assert state.cleaned
