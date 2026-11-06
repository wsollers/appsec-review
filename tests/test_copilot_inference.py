from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.inference import PROVIDERS, MODEL_CHECKS
from appsec_review.inference import copilot_sdk
from appsec_review.inference.claude_cli import ModelOutputError
from appsec_review.inference.request import ModelRequest, ReviewModelRequest
from appsec_review.inference.errors import ExecutionContractError, ModelCancelled, ModelTimeout, ProviderError
from appsec_review.jobs.job_review_intake.job import configured_models


ROOT = Path(__file__).parents[1]
SCHEMA = "appsec-review/target-analysis-proposal/2"
VALUE = {"schema": SCHEMA, "component_proposals": [], "build_recipes": []}


def request() -> ModelRequest:
    return ModelRequest(
        schema=SCHEMA, persona="p", role="r", guidance="registered guidance", summary={},
        allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
        allowed_paths=(), allowed_build_units=(), provider="copilot-sdk",
        model="claude-haiku-5.5", reasoning="low", max_input_tokens=1000, max_output_tokens=200,
    )


@pytest.fixture(autouse=True)
def fake_sdk_modules(monkeypatch):
    """Exercise our real adapter with only the optional SDK boundary replaced."""
    package, session, events = (ModuleType(name) for name in
                                ("copilot", "copilot.session", "copilot.session_events"))
    package.CopilotClient = SimpleNamespace
    session.ModelCapabilitiesOverride = SimpleNamespace
    session.ModelLimitsOverride = SimpleNamespace
    session.PermissionDecisionUserNotAvailable = lambda: SimpleNamespace(kind="user-not-available")

    class AssistantMessageData(SimpleNamespace):
        pass

    class AssistantUsageData(SimpleNamespace):
        pass

    events.AssistantMessageData = AssistantMessageData
    events.AssistantUsageData = AssistantUsageData
    for module in (package, session, events):
        monkeypatch.setitem(sys.modules, module.__name__, module)


@pytest.fixture
def sdk(monkeypatch, fake_sdk_modules):
    from copilot.session_events import AssistantMessageData, AssistantUsageData

    state = SimpleNamespace(options=None, prompt=None, closed=False, aborted=False,
                            response=json.dumps(VALUE), served="claude-haiku-5.5",
                            policy="enabled", reasoning=["low"], delay=0, tools=None,
                            models=["claude-haiku-5.5"], input_tokens=10, output_tokens=20,
                            cache_read_tokens=3, extra_usage=[], usage=True, failure=None,
                            abort_error=None, exit_error=None, exit_delay=0, abort_delay=0,
                            exit_started=False, client_closed=False)

    class Session:
        session_id = "test-session"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            state.exit_started = True
            await asyncio.sleep(state.exit_delay)
            state.closed = True
            if state.exit_error:
                raise state.exit_error

        async def abort(self):
            state.aborted = True
            await asyncio.sleep(state.abort_delay)
            if state.abort_error:
                raise state.abort_error

        async def send_and_wait(self, prompt, *, timeout):
            state.prompt = json.loads(prompt)
            await asyncio.sleep(state.delay)
            if state.failure:
                raise state.failure
            if state.usage:
                for counts in [(state.input_tokens, state.output_tokens, state.cache_read_tokens),
                               *state.extra_usage]:
                    state.options["on_event"](SimpleNamespace(agent_id=None, data=AssistantUsageData(
                        model=state.served, input_tokens=counts[0], output_tokens=counts[1],
                        cache_read_tokens=counts[2])))
            return SimpleNamespace(data=AssistantMessageData(
                content=state.response, message_id="message", model=state.served,
                tool_requests=state.tools))

    class Client:
        async def list_models(self):
            return [SimpleNamespace(id=name, policy=SimpleNamespace(state=state.policy),
                                    supported_reasoning_efforts=state.reasoning) for name in state.models]

        async def create_session(self, **options):
            state.options = options
            return Session()

    @asynccontextmanager
    async def client():
        try:
            yield Client(), "/isolated"
        finally:
            state.client_closed = True

    monkeypatch.setattr(copilot_sdk, "_client", client)
    return state


def test_profile_preserves_dev_settings_except_provider_and_model_name():
    dev = load_config(ROOT / "appsec-review.toml", profile="dev")
    copilot = load_config(ROOT / "appsec-review.toml", profile="copilot-dev")
    before, after = json.loads(dev.resolved_json), json.loads(copilot.resolved_json)
    required = configured_models(after)
    assert len(required) == len(configured_models(before))
    assert {item["provider"] for item in required} == {"copilot-sdk"}
    assert {item["model"] for item in required} == {"claude-haiku-5.5"}
    for item in required:
        settings = after["jobs"][item["job_id"]]
        original = before["jobs"][item["job_id"]]
        for key in item["setting"].split("."):
            settings, original = settings[key], original[key]
        settings["provider"], settings["model"] = original["provider"], original["model"]
    assert after["jobs"] == before["jobs"]
    assert copilot.profile_sha256 and copilot.profile_sha256 != dev.profile_sha256
    assert PROVIDERS["copilot-sdk"] is copilot_sdk.send
    assert MODEL_CHECKS["copilot-sdk"] is copilot_sdk.models


def test_transport_is_tool_free_and_records_usage(sdk):
    result = copilot_sdk.send(request(), timeout_seconds=5)
    assert result.proposal == VALUE
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (10, 20, 3)
    options = sdk.options
    assert options["available_tools"] == options["tools"] == options["custom_agents"] == []
    assert options["excluded_tools"] == ["builtin:*", "mcp:*", "custom:*"]
    assert options["mcp_servers"] == {} and options["skip_custom_instructions"] is True
    for key in ("enable_config_discovery", "enable_on_demand_instruction_discovery", "enable_file_hooks",
                "enable_host_git_operations", "enable_skills", "enable_session_store",
                "enable_session_telemetry", "request_extensions"):
        assert options[key] is False
    assert options["on_permission_request"](None, None).kind == "user-not-available"
    assert options["model_capabilities"].limits.max_output_tokens == 200
    assert sdk.prompt["task"] == "registered guidance"
    assert sdk.closed


def test_production_profile_preserves_all_prod_settings_except_transport():
    prod = load_config(ROOT / "appsec-review.toml", profile="prod")
    copilot = load_config(ROOT / "appsec-review.toml", profile="copilot-prod")
    before, after = json.loads(prod.resolved_json), json.loads(copilot.resolved_json)
    names = {"claude-sonnet-5-5": "claude-sonnet-5.5", "claude-opus-5-5": "claude-opus-5.5"}
    for item in configured_models(before):
        model = before["jobs"][item["job_id"]]
        for key in item["setting"].split("."):
            model = model[key]
        assert model["provider"] == "claude-cli"
        model["provider"] = "copilot-sdk"
        model["model"] = names[model["model"]]
    assert after["jobs"] == before["jobs"]
    review = copilot.job("job_inference_security_review").typed_settings
    assert review.models["default"].model == "claude-sonnet-5.5"
    assert review.models["strong"].model == "claude-opus-5.5"
    for role in ("independent_verifier", "adjudication_judge"):
        assert review.roles[role].model_profile == "strong"
    assert {item["provider"] for item in configured_models(after)} == {"copilot-sdk"}
    assert copilot.profile_sha256 and copilot.profile_sha256 != prod.profile_sha256
    assert copilot.resolved_sha256 != prod.resolved_sha256
    record = after["configuration_profile"]
    assert record["name"] == "copilot-prod"
    assert record["sha256"] == copilot.profile_sha256
    assert record["document"]["jobs"]["job_inference_security_review"]["settings"]["models"]["strong"]["model"] == "claude-opus-5.5"


def test_production_verification_requires_both_models_without_inference(sdk, monkeypatch):
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "copilot-prod")
    sdk.models = ["claude-sonnet-5.5", "claude-opus-5.5"]
    assert copilot_sdk.verify()["models"] == ["claude-opus-5.5", "claude-sonnet-5.5"]
    assert sdk.options is None
    sdk.models.remove("claude-opus-5.5")
    with pytest.raises(RuntimeError, match="claude-opus-5.5"):
        copilot_sdk.verify()
    assert sdk.options is None


def test_review_turn_uses_shared_prompt_and_repair(sdk):
    req = ReviewModelRequest(schema="appsec-review/worker-turn/1", role="red", persona="p",
                             stack_profile="native", guidance_bundle_sha256="a" * 64,
                             guidance_text="registered", task_input={"id": 1}, transcript=(),
                             provider="copilot-sdk", model="claude-haiku-5.5", reasoning="low",
                             max_input_tokens=1000, max_output_tokens=200, repair_errors=("invalid",))
    sdk.response = json.dumps({"schema": req.schema, "action": "final", "result": {}})
    assert copilot_sdk.send(req, timeout_seconds=5).proposal["action"] == "final"
    assert sdk.prompt["guidance"] == "registered"
    assert sdk.prompt["repair"]["validation_errors"] == ["invalid"]
    assert "catalog_summary" not in sdk.prompt


@pytest.mark.parametrize("policy", ["disabled", "unconfigured"])
def test_unavailable_model_never_falls_back(sdk, policy):
    sdk.policy = policy
    assert not copilot_sdk.models([request().model], timeout_seconds=5)["models"][request().model]["available"]
    with pytest.raises(RuntimeError, match="unavailable"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert sdk.options is None


def test_exact_model_and_reasoning_are_required(sdk):
    with pytest.raises(RuntimeError, match="unavailable"):
        copilot_sdk.send(replace(request(), model="not-listed"), timeout_seconds=5)
    with pytest.raises(ValueError, match="reasoning"):
        copilot_sdk.send(replace(request(), reasoning="max"), timeout_seconds=5)
    sdk.served = "another-model"
    with pytest.raises(ModelOutputError, match="exact requested model"):
        copilot_sdk.send(request(), timeout_seconds=5)


def test_invalid_output_retains_repair_evidence(sdk):
    sdk.response = "not JSON"
    with pytest.raises(ModelOutputError) as error:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert error.value.raw_response == error.value.rejected_output == "not JSON"
    assert sdk.closed


def test_tools_and_oversized_output_are_rejected(sdk):
    sdk.tools = ["unexpected tool request"]
    with pytest.raises(ModelOutputError, match="tool-free"):
        copilot_sdk.send(request(), timeout_seconds=5)
    sdk.tools = None
    sdk.response = "x" * (2 * 1024 * 1024 + 1)
    with pytest.raises(ModelOutputError, match="response bound") as error:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert len(error.value.raw_response) == 2 * 1024 * 1024
    assert len(error.value.rejected_output) == 131072


def test_verification_uses_selected_configuration_without_inference(sdk, monkeypatch):
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "copilot-dev")
    assert copilot_sdk.verify()["models"] == ["claude-haiku-5.5"]
    assert sdk.options is None
    sdk.policy = "disabled"
    with pytest.raises(RuntimeError, match="unavailable"):
        copilot_sdk.verify()
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "dev")
    with pytest.raises(RuntimeError, match="select the copilot-dev"):
        copilot_sdk.verify()


def test_timeout_aborts_and_disconnects_session(sdk):
    sdk.delay = 10
    with pytest.raises(TimeoutError):
        copilot_sdk.send(request(), timeout_seconds=0.01)
    assert sdk.aborted and sdk.closed


def test_client_uses_only_dedicated_login(monkeypatch, tmp_path):
    import copilot
    home = tmp_path / "worker-home"
    home.mkdir()
    monkeypatch.setenv("APPSEC_COPILOT_HOME", str(home))
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN", "ANTHROPIC_API_KEY"):
        monkeypatch.setenv(name, "must-not-reach-worker")
    monkeypatch.setattr(copilot_sdk.tempfile, "tempdir", str(tmp_path))
    seen = {}

    class Client:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

    monkeypatch.setattr(copilot, "CopilotClient", Client)

    async def check():
        async with copilot_sdk._client():
            pass

    asyncio.run(check())
    assert seen["mode"] == "empty" and seen["base_directory"] == str(home)
    assert seen["use_logged_in_user"] is True
    assert not any(key in seen["env"] for key in ("GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN"))
    assert seen["env"]["COPILOT_SKIP_CLI_DOWNLOAD"] == "1"
    assert seen["working_directory"] != str(ROOT)
    assert not Path(seen["working_directory"]).exists()


def test_missing_dedicated_login_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_COPILOT_HOME", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="worker login is missing"):
        copilot_sdk.models(["claude-haiku-5.5"], timeout_seconds=5)


@pytest.mark.parametrize("bad", [None, -1, True, "2", 1.2])
def test_sdk_usage_does_not_sum_invalid_or_missing_counts(sdk, bad):
    sdk.extra_usage = [(bad, 2, 0)]
    result = copilot_sdk.send(request(), timeout_seconds=5)
    assert result.input_tokens is None
    assert result.output_tokens == 22 and result.cache_tokens == 3
    assert result.usage_unavailable_reason == (
        "provider_usage_missing" if bad is None else "invalid_provider_usage")


def test_sdk_absent_usage_is_unknown_not_zero(sdk):
    sdk.usage = False
    result = copilot_sdk.send(request(), timeout_seconds=5)
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (None, None, None)


@pytest.mark.parametrize("error", [TypeError("bug"), ValueError("bug"), RuntimeError("bug")])
def test_sdk_programming_failures_do_not_become_provider_errors(sdk, error):
    sdk.failure = error
    with pytest.raises(type(error)) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value is error and not isinstance(raised.value, ProviderError)
    assert sdk.closed and sdk.client_closed


def test_sdk_network_failure_is_typed_and_transient(sdk):
    sdk.failure = ConnectionResetError("raw connection data")
    with pytest.raises(ProviderError) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.retryable and raised.value.code == "network"
    assert "raw" not in str(raised.value)


def test_sdk_cancellation_checks_during_call_and_confirms_cleanup(sdk, monkeypatch):
    from appsec_review.runtime import execution_safety as safety
    sdk.delay = 10
    cancelled = ModelCancelled("stop requested")

    def check():
        if sdk.prompt is not None:
            raise cancelled

    monkeypatch.setattr(safety, "check_running", check)
    with pytest.raises(ModelCancelled) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value is cancelled
    assert sdk.aborted and sdk.closed and sdk.client_closed


def test_sdk_abort_failure_has_explicit_evidence_and_preserves_cancellation(sdk, monkeypatch):
    from appsec_review.runtime import execution_safety as safety
    from appsec_review.runtime import resources
    sdk.delay = 10
    sdk.abort_error = RuntimeError("private sdk output")
    retained, quarantined = [], []
    monkeypatch.setattr(safety, "retain_failure", lambda action, error, **kw: retained.append((action, error)))
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)

    def check():
        if sdk.prompt is not None:
            raise ModelCancelled("stop")

    monkeypatch.setattr(safety, "check_running", check)
    with pytest.raises(ModelCancelled) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert isinstance(raised.value.__cause__, ExecutionContractError)
    assert quarantined == ["copilot_teardown_unconfirmed"]
    assert retained[0][0] == "copilot.cleanup"
    assert "private" not in str(retained[0][1])
    assert sdk.closed and sdk.client_closed


def test_sdk_timeout_with_failed_abort_is_not_an_ordinary_timeout(sdk, monkeypatch):
    from appsec_review.runtime import resources
    monkeypatch.setattr(resources, "quarantine_resources", lambda _: None)
    sdk.delay = 10
    sdk.abort_error = RuntimeError("broken abort")
    with pytest.raises(ExecutionContractError, match="abort failed"):
        copilot_sdk.send(request(), timeout_seconds=0.001)


def test_sdk_deadline_includes_session_teardown_and_marks_unconfirmed_cleanup(sdk, monkeypatch):
    from appsec_review.runtime import resources
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    sdk.exit_delay = 10
    with pytest.raises(ExecutionContractError, match="session teardown failed"):
        copilot_sdk.send(request(), timeout_seconds=0.01)
    assert sdk.exit_started and sdk.client_closed
    assert quarantined == ["copilot_teardown_unconfirmed"]


def test_sdk_failed_teardown_never_returns_success(sdk, monkeypatch):
    from appsec_review.runtime import resources
    monkeypatch.setattr(resources, "quarantine_resources", lambda _: None)
    sdk.exit_error = TypeError("teardown contract bug")
    with pytest.raises(ExecutionContractError, match="session teardown failed") as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.__cause__ is sdk.exit_error
    assert sdk.client_closed


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), "10"])
def test_sdk_rejects_invalid_deadline_without_opening_client(sdk, timeout):
    with pytest.raises(ExecutionContractError, match="finite and positive"):
        copilot_sdk.send(request(), timeout_seconds=timeout)
    assert sdk.options is None


def test_sdk_cancelled_admission_never_starts_the_sdk(sdk, monkeypatch):
    from appsec_review.runtime import execution_safety as safety

    def stop():
        raise ModelCancelled("cancelled before admission")

    monkeypatch.setattr(safety, "check_running", stop)
    with pytest.raises(ModelCancelled, match="before admission"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert sdk.options is None and not sdk.client_closed


def test_sdk_cancellation_during_teardown_keeps_control_flow_and_cleanup_evidence(sdk, monkeypatch):
    from appsec_review.runtime import execution_safety as safety, resources
    sdk.exit_delay = 10
    retained = []
    monkeypatch.setattr(resources, "quarantine_resources", lambda _: None)
    monkeypatch.setattr(safety, "retain_failure", lambda action, error, **kw: retained.append((action, error)))

    def stop_during_exit():
        if sdk.exit_started:
            raise ModelCancelled("cancelled during exit")

    monkeypatch.setattr(safety, "check_running", stop_during_exit)
    with pytest.raises(ModelCancelled, match="during exit") as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert isinstance(raised.value.__cause__, ExecutionContractError)
    assert retained and retained[0][0] == "copilot.cleanup"
    assert sdk.client_closed


def test_sdk_unconfirmed_background_cleanup_never_returns_success(sdk, monkeypatch):
    from appsec_review.runtime import execution_safety as safety, resources
    retained, cleaned = [], []
    monkeypatch.setattr(resources, "quarantine_resources", lambda _: None)
    monkeypatch.setattr(safety, "retain_failure",
                        lambda action, error, **kw: retained.append((action, error, kw)))
    monkeypatch.setattr(copilot_sdk, "_CLEANUP_SECONDS", 0.001)
    real_loop = asyncio.new_event_loop

    def loop_for_fake_sdk():
        loop = real_loop()
        close = loop.close

        def close_and_dispose_fake():
            # The fake worker intentionally resists the first cancellation. Dispose it at
            # the external boundary after verifying our adapter declared cleanup unconfirmed.
            for pending in asyncio.all_tasks(loop):
                pending.cancel()
                loop.run_until_complete(asyncio.gather(pending, return_exceptions=True))
                cleaned.append(True)
            close()

        loop.close = close_and_dispose_fake
        return loop

    monkeypatch.setattr(copilot_sdk.asyncio, "new_event_loop", loop_for_fake_sdk)

    async def operation():
        async def background():
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                await asyncio.sleep(10)

        asyncio.create_task(background())
        await asyncio.sleep(0)
        return "must not return success"

    with pytest.raises(ExecutionContractError, match="cancellation bound"):
        copilot_sdk._run(operation(), timeout_seconds=1)
    assert cleaned and retained[0][2]["pending_tasks"] == 1
