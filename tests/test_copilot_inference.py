from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.inference import PROVIDERS, MODEL_CHECKS, _copilot_worker, worker_scope
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

    class SessionErrorData(SimpleNamespace):
        pass

    class SessionWarningData(SimpleNamespace):
        pass

    events.AssistantMessageData = AssistantMessageData
    events.AssistantUsageData = AssistantUsageData
    events.SessionErrorData = SessionErrorData
    events.SessionWarningData = SessionWarningData
    for module in (package, session, events):
        monkeypatch.setitem(sys.modules, module.__name__, module)


@pytest.fixture
def sdk(monkeypatch, tmp_path, fake_sdk_modules):
    import copilot
    from copilot.session_events import AssistantMessageData, AssistantUsageData

    state = SimpleNamespace(options=None, prompt=None, closed=False, aborted=False,
                            response=json.dumps(VALUE), served="claude-haiku-5.5",
                            policy="enabled", reasoning=["low"], delay=0, tools=None,
                            models=["claude-haiku-5.5"], input_tokens=10, output_tokens=20,
                            cache_read_tokens=3, write_usage={}, extra_usage=[], usage=True, failure=None,
                            abort_error=None, exit_error=None, exit_delay=0, abort_delay=0,
                            exit_started=False, client_closed=False, raw_prompt=None,
                            starts=0, stops=0, listings=0, session_count=0, sends=0, loops=[],
                            working_dirs=[], deleted=[], stop_error=None, delete_error=None, ping_error=None)

    class Session:
        def __init__(self, number):
            self.session_id = f"test-session-{number}"

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
            state.sends += 1
            state.raw_prompt = prompt
            state.prompt = json.loads(prompt)
            await asyncio.sleep(state.delay)
            for event_data in getattr(state, "session_events", ()):
                state.options["on_event"](SimpleNamespace(agent_id=None, data=event_data))
            if state.failure:
                raise state.failure
            if getattr(state, "no_response", False):
                return None
            if state.usage:
                for counts in [(state.input_tokens, state.output_tokens, state.cache_read_tokens),
                               *state.extra_usage]:
                    state.options["on_event"](SimpleNamespace(agent_id=None, data=AssistantUsageData(
                        model=state.served, input_tokens=counts[0], output_tokens=counts[1],
                        cache_read_tokens=counts[2], **(counts[3] if len(counts) > 3 else state.write_usage))))
            return SimpleNamespace(data=AssistantMessageData(
                content=state.response, message_id="message", model=state.served,
                tool_requests=state.tools))

    class Client:
        def __init__(self, **options):
            self.working = options["working_directory"]

        async def start(self):
            state.starts += 1
            state.loops.append(asyncio.get_running_loop())
            self.reader = asyncio.create_task(asyncio.Event().wait())

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

        async def stop(self):
            state.stops += 1
            state.client_closed = True
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
            if state.stop_error:
                raise state.stop_error

        async def ping(self):
            assert not self.reader.done() and Path(self.working).is_dir()
            if state.ping_error:
                raise state.ping_error

        async def delete_session(self, session_id):
            if state.delete_error:
                raise state.delete_error
            state.deleted.append(session_id)

        async def list_models(self):
            state.listings += 1
            return [SimpleNamespace(id=name, policy=SimpleNamespace(state=state.policy),
                                    supported_reasoning_efforts=state.reasoning) for name in state.models]

        async def create_session(self, **options):
            state.options = options
            state.session_count += 1
            path = Path(options["working_directory"])
            assert path == Path(options["config_directory"]) and str(path) != self.working
            assert path.is_dir() and path.stat().st_mode & 0o077 == 0
            state.working_dirs.append(path)
            return Session(state.session_count)

    monkeypatch.setattr(copilot, "CopilotClient", Client)
    monkeypatch.setenv("APPSEC_COPILOT_HOME", str(tmp_path))
    monkeypatch.setattr(_copilot_worker.tempfile, "tempdir", str(tmp_path))
    return state


def test_profile_preserves_legacy_dev_bindings_and_only_increases_aggregate_budgets():
    dev = load_config(ROOT / "appsec-review.toml", profile="dev")
    copilot = load_config(ROOT / "appsec-review.toml", profile="copilot-dev")
    before, after = json.loads(dev.resolved_json), json.loads(copilot.resolved_json)
    required = configured_models(after)
    assert len(required) == len(configured_models(before))
    inherited = []
    for item in required:
        settings = after["jobs"][item["job_id"]]
        original = before["jobs"][item["job_id"]]
        for key in item["setting"].split("."):
            settings, original = settings[key], original[key]
        if item["provider"] == "claude-cli":
            inherited.append((item["job_id"], item["setting"]))
            assert settings == original
        else:
            assert (item["provider"], item["model"]) == ("copilot-sdk", "claude-haiku-5.5")
            settings["provider"], settings["model"] = original["provider"], original["model"]
    assert sorted(inherited) == [
        ("job_inference_security_review", "settings.models.planner"),
        ("job_inference_security_review", "settings.models.verifier"),
    ]
    budgets = after["jobs"]["job_inference_security_review"]["settings"]["budgets"]
    assert budgets == {
        "max_input_tokens": 1920000000, "max_output_tokens": 192000000,
        "max_model_turns": 48000, "max_retrieval_queries": 160000,
        "budget_team_packages": 800, "timeout_seconds": 28800,
    }
    original_budgets = before["jobs"]["job_inference_security_review"]["settings"]["budgets"]
    for key, value in original_budgets.items():
        assert budgets[key] == value * (1 if key == "timeout_seconds" else 4)
    after["jobs"]["job_inference_security_review"]["settings"]["budgets"] = original_budgets
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


@pytest.mark.parametrize("profile,model", [
    pytest.param("copilot-dev-astra-6.2", "gpt-6.2-astra", id="astra"),
    pytest.param("copilot-dev-gemini", "gemini-4-carbon", id="gemini"),
])
def test_verification_uses_selected_configuration_without_inference(sdk, monkeypatch, profile, model):
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "copilot-dev")
    sdk.models = [model]
    sdk.reasoning = ["low", "medium", "high"]
    assert copilot_sdk.verify(profile)["models"] == [model]
    assert sdk.options is None
    sdk.policy = "disabled"
    with pytest.raises(RuntimeError, match="unavailable"):
        copilot_sdk.verify(profile)
    assert sdk.options is None


@pytest.mark.parametrize("profile", ["dev", "copilot-dev", "copilot-prod"])
def test_verification_refuses_any_inherited_non_copilot_model_before_catalog_access(sdk, monkeypatch, profile):
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", profile)
    def unexpected_catalog(*args, **kwargs):
        pytest.fail("mixed-provider profile must be refused before catalog access")
    monkeypatch.setattr(copilot_sdk, "models", unexpected_catalog)
    with pytest.raises(RuntimeError, match="every configured model to use copilot-sdk"):
        copilot_sdk.verify()


def test_carbon_production_verification_checks_gemini_carbon_without_inference(sdk, monkeypatch):
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "copilot-dev")
    sdk.models = ["gemini-4-carbon"]
    sdk.reasoning = ["low", "medium", "high"]
    assert copilot_sdk.verify("copilot-carbon-prod") == {
        "provider": "copilot-sdk",
        "method": "catalog",
        "models": ["gemini-4-carbon"],
    }
    assert sdk.options is None


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
    monkeypatch.setattr(_copilot_worker.tempfile, "tempdir", str(tmp_path))
    seen = {}

    class Client:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        async def start(self):
            pass

        async def stop(self):
            pass

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

    monkeypatch.setattr(copilot, "CopilotClient", Client)

    async def check():
        async with _copilot_worker._client():
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
    retained, closed = [], []
    monkeypatch.setattr(resources, "quarantine_resources", lambda _: None)
    monkeypatch.setattr(safety, "retain_failure",
                        lambda action, error, **kw: retained.append((action, error, kw)))
    monkeypatch.setattr(_copilot_worker, "_CLEANUP_SECONDS", 0.001)
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
            close()
            closed.append(loop.is_closed())

        loop.close = close_and_dispose_fake
        return loop

    monkeypatch.setattr(_copilot_worker.asyncio, "new_event_loop", loop_for_fake_sdk)

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
    assert closed == [True] and retained[0][2]["pending_tasks"] == 1


def test_scoped_turns_share_only_healthy_transport_and_bounded_catalog(sdk, monkeypatch):
    now = [100.]
    monkeypatch.setattr(_copilot_worker, "_catalog_clock", lambda: now[0])
    model = request().model
    with worker_scope():
        assert copilot_sdk.models([model], timeout_seconds=5)["models"][model]["available"]
        assert copilot_sdk.send(request(), timeout_seconds=5).input_tokens == 10
        sdk.input_tokens = 7
        assert copilot_sdk.send(request(), timeout_seconds=5).input_tokens == 7
        assert (sdk.starts, sdk.listings, sdk.stops) == (1, 1, 0)
        assert sdk.deleted == ["test-session-1", "test-session-2"]
        assert len(set(sdk.working_dirs)) == 2 and not any(path.exists() for path in sdk.working_dirs)
        now[0] += _copilot_worker._CATALOG_TTL_SECONDS
        sdk.policy = "disabled"
        assert not copilot_sdk.models([model], timeout_seconds=5)["models"][model]["available"]
        assert (sdk.starts, sdk.listings, sdk.stops) == (2, 2, 1)
    assert sdk.stops == 2 and all(loop.is_closed() for loop in sdk.loops)


def test_failed_reused_transport_is_closed_without_resending(sdk):
    with worker_scope():
        copilot_sdk.send(request(), timeout_seconds=5)
        sdk.ping_error = ConnectionResetError()
        with pytest.raises(ProviderError) as error:
            copilot_sdk.send(request(), timeout_seconds=5)
        assert error.value.code == "network" and (sdk.starts, sdk.stops, sdk.sends) == (1, 1, 1)
        sdk.ping_error = None
        copilot_sdk.send(request(), timeout_seconds=5)
    assert (sdk.starts, sdk.stops, sdk.sends) == (2, 2, 2)


def test_session_deletion_failure_quarantines_and_blocks_worker_reuse(sdk, monkeypatch):
    from appsec_review.runtime import resources
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    with worker_scope():
        sdk.delete_error = RuntimeError("private error")
        with pytest.raises(ExecutionContractError, match="session deletion teardown failed"):
            copilot_sdk.send(request(), timeout_seconds=5)
        with pytest.raises(ExecutionContractError, match="unconfirmed"):
            copilot_sdk.send(request(), timeout_seconds=5)
    assert quarantined == ["copilot_teardown_unconfirmed"] and sdk.starts == sdk.stops == 1


def test_scope_exit_fails_closed_on_stop(sdk, monkeypatch):
    from appsec_review.runtime import resources
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    with pytest.raises(ExecutionContractError, match="client teardown failed"):
        with worker_scope():
            copilot_sdk.send(request(), timeout_seconds=5)
            sdk.stop_error = RuntimeError("private stop failure")
    assert quarantined == ["copilot_teardown_unconfirmed"] and sdk.loops[0].is_closed()


def test_scopes_do_not_share_transport_across_threads(sdk):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context

    model = request().model
    with worker_scope():
        copilot_sdk.models([model], timeout_seconds=5)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(copy_context().run, copilot_sdk.models, [model], timeout_seconds=5).result()
        assert sdk.starts == 2 and sdk.stops == 1 and sdk.loops[1].is_closed()
        copilot_sdk.models([model], timeout_seconds=5)
    assert sdk.starts == sdk.stops == 2


def test_review_wire_prefix_survives_changed_cell_input_and_turn(sdk):
    from appsec_review.inference.request import review_prompt
    turn = {"actions": ["final"], "tool_catalog": []}
    req = ReviewModelRequest(schema="appsec-review/worker-turn/1", role="red", persona="p",
                             stack_profile="native", guidance_bundle_sha256="a" * 64,
                             guidance_text="registered", task_input={"input": {"id": 1}, "turn_protocol": turn},
                             transcript=(), provider="copilot-sdk", model="claude-haiku-5.5", reasoning="low",
                             max_input_tokens=1000, max_output_tokens=200)
    sdk.response = json.dumps({"schema": req.schema, "action": "final", "result": {}})
    copilot_sdk.send(req, timeout_seconds=5)
    first = sdk.raw_prompt
    assert first.startswith('{"guidance":"registered"')
    prefix = first[:first.index('"input":')]
    assert '"tool_catalog":' in prefix and '"capability_artifact_card":' not in prefix
    req = replace(req, task_input={"turn_protocol": dict(reversed(tuple(turn.items()))), "input": {"id": 2}},
                  transcript=({"turn": 1},), repair_errors=("invalid",))
    copilot_sdk.send(req, timeout_seconds=5)
    assert sdk.raw_prompt.startswith(prefix)
    assert sdk.prompt == json.loads(json.dumps(review_prompt(req, include_guidance=True)))


def test_sdk_own_send_timeout_with_failed_abort_is_a_contract_failure(sdk, monkeypatch):
    from appsec_review.runtime import resources
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    sdk.failure = TimeoutError("private SDK timeout")
    sdk.abort_error = RuntimeError("private SDK abort error")
    with pytest.raises(ExecutionContractError, match="abort failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert sdk.aborted and sdk.closed and sdk.stops == 1 and sdk.sends == 1
    assert quarantined == ["copilot_teardown_unconfirmed"]


@pytest.mark.parametrize(("reports", "expected"), [
    ([{}, {}], None), ([{"cache_write_tokens": 0}, {"cacheWriteTokens": 0}], 0),
    ([{"cache_write_tokens": 5}, {"cache_creation_input_tokens": 9}], 14),
    ([{"cache_write_tokens": 5}, {}], None), ([{"cache_write_tokens": True}, {"cache_write_tokens": 1}], None),
])
def test_sdk_cache_writes_preserve_zero_missing_and_billing(sdk, reports, expected):
    sdk.write_usage, second = reports
    sdk.extra_usage = [(7, 1, 0, second)]
    result = copilot_sdk.send(request(), timeout_seconds=5)
    assert result.cache_write_tokens == expected
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (17, 21, 3)


def test_sdk_reports_reuse_and_cold_time_only_for_this_call(sdk, monkeypatch):
    # Use a clock dedicated to the instrumentation, not sleeps or the RPC deadline.
    ticks = iter([10.0, 10.25, 50.0, 50.5])
    monkeypatch.setattr(_copilot_worker, "_startup_clock", lambda: next(ticks))
    with worker_scope():
        cold = copilot_sdk.send(request(), timeout_seconds=5)
        warm = copilot_sdk.send(request(), timeout_seconds=5)
        assert (cold.client_reused, cold.client_cold_start_ms) == (False, 250)
        assert (warm.client_reused, warm.client_cold_start_ms) == (True, 0)
        sdk.ping_error = ConnectionResetError()
        with pytest.raises(ProviderError) as failed:
            copilot_sdk.send(request(), timeout_seconds=5)
        assert (failed.value.client_reused, failed.value.client_cold_start_ms) == (True, 0)
        sdk.ping_error = None
        rotated = copilot_sdk.send(request(), timeout_seconds=5)
        assert (rotated.client_reused, rotated.client_cold_start_ms) == (False, 500)


def test_sdk_ephemeral_session_not_found_on_delete_succeeds_only_when_unpersisted_and_disconnected(
    sdk, monkeypatch, tmp_path
):
    import copilot
    from appsec_review.runtime import resources

    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)

    # Simulate Copilot CLI 1.0.25 writing scratch events/locks under per-turn config_directory
    # and releasing inuse.* locks on session.__aexit__ while client._sessions still tracks the ID.
    orig_client_cls = copilot.CopilotClient
    hold_inuse = [False]
    observed_sessions_maps = []

    class RealisticClient(orig_client_cls):
        def __init__(self, **options):
            super().__init__(**options)
            self._sessions = {}

        async def create_session(self, **options):
            sess = await super().create_session(**options)
            self._sessions[sess.session_id] = sess
            observed_sessions_maps.append(self._sessions)
            turn_state = Path(options["config_directory"]) / "session-state"
            sdir = turn_state / sess.session_id
            sdir.mkdir(parents=True, exist_ok=True)
            (sdir / "events.jsonl").write_text("{}", encoding="utf-8")
            inuse = sdir / "inuse.7461.lock"
            inuse.write_text("", encoding="utf-8")
            locks = turn_state / ".session-operation-locks"
            locks.mkdir(parents=True, exist_ok=True)
            (locks / f"{sess.session_id}.lock").write_text("", encoding="utf-8")
            orig_aexit = sess.__aexit__

            async def aexit_release(*args):
                if not hold_inuse[0]:
                    inuse.unlink(missing_ok=True)
                return await orig_aexit(*args)

            sess.__aexit__ = aexit_release
            return sess

    monkeypatch.setattr(copilot, "CopilotClient", RealisticClient)

    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-1: Session file not found for test-session-1"
    )
    result = copilot_sdk.send(request(), timeout_seconds=5)
    assert result.proposal == VALUE
    assert quarantined == []
    assert observed_sessions_maps[-1] == {}

    # Unreleased inuse.* lock inside per-turn session-state must fail closed.
    hold_inuse[0] = True
    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-2: Session file not found for test-session-2"
    )
    with pytest.raises(ExecutionContractError, match="session deletion teardown failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert quarantined == ["copilot_teardown_unconfirmed"]
    hold_inuse[0] = False

    # Persisted auth_home() session-state residue must still fail closed.
    quarantined.clear()
    (tmp_path / "session-state" / "test-session-3").mkdir(parents=True)
    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-3: Session file not found for test-session-3"
    )
    with pytest.raises(ExecutionContractError, match="session deletion teardown failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert quarantined == ["copilot_teardown_unconfirmed"]

    # Unclean session disconnect must also still fail closed.
    quarantined.clear()
    sdk.exit_error = RuntimeError("disconnect failed")
    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-4: Session file not found for test-session-4"
    )
    with pytest.raises(ExecutionContractError, match="session deletion teardown failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert "copilot_teardown_unconfirmed" in quarantined
def test_worker_close_cancels_tasks_with_grace_after_aclose_exhausts_deadline(monkeypatch):
    monkeypatch.setattr("appsec_review.runtime.resources.quarantine_resources", lambda *_: None)
    monkeypatch.setattr("appsec_review.runtime.execution_safety.retain_failure", lambda *_, **__: None)
    worker = _copilot_worker._Worker()
    loop = worker.loop = asyncio.new_event_loop()
    events = {"aclose_cancelled": False, "task_unwound": False}

    class SlowResource:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            try:
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                events["aclose_cancelled"] = True
                raise

    async def setup():
        await worker.stack.enter_async_context(SlowResource())

        async def background():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.02)
                events["task_unwound"] = True
                raise

        return asyncio.create_task(background())

    bg_task = loop.run_until_complete(setup())
    expired_deadline = _copilot_worker.time.monotonic() - 0.01
    with pytest.raises(ExecutionContractError, match="client teardown exceeded its cancellation bound"):
        worker.close(expired_deadline)
    assert worker.poisoned is True
    assert loop.is_closed()
    assert bg_task.cancelled() and events["task_unwound"] is True
    assert events["aclose_cancelled"] is True


def test_worker_close_chains_client_and_task_cancellation_failures(monkeypatch):
    monkeypatch.setattr("appsec_review.runtime.resources.quarantine_resources", lambda *_: None)
    monkeypatch.setattr("appsec_review.runtime.execution_safety.retain_failure", lambda *_, **__: None)
    worker = _copilot_worker._Worker()
    loop = worker.loop = asyncio.new_event_loop()

    class BrokenResource:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            raise RuntimeError("stack close boom")

    async def setup():
        await worker.stack.enter_async_context(BrokenResource())

        async def bad_cleanup():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                raise ValueError("task cleanup boom")

        return asyncio.create_task(bad_cleanup())

    loop.run_until_complete(setup())
    with pytest.raises(ExecutionContractError, match="cancellation cleanup failed") as exc_info:
        worker.close(_copilot_worker.time.monotonic() + 2.0)
    err = exc_info.value
    assert worker.poisoned is True
    assert loop.is_closed()
    assert isinstance(err.__cause__, ExecutionContractError)
    assert "client teardown failed" in str(err.__cause__)
    assert isinstance(err.__cause__.__cause__, RuntimeError)
    assert any("Prior client teardown failure" in note for note in getattr(err, "__notes__", ()))


def test_sdk_delete_after_use_runs_when_session_setup_fails_after_create(sdk, monkeypatch):
    import copilot
    from appsec_review.runtime import resources

    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    orig_client = copilot.CopilotClient

    class FailEnterClient(orig_client):
        async def create_session(self, **options):
            sess = await super().create_session(**options)

            async def broken_enter():
                raise RuntimeError("session enter failed")

            sess.__aenter__ = broken_enter
            return sess

    monkeypatch.setattr(copilot, "CopilotClient", FailEnterClient)

    with pytest.raises(RuntimeError, match="session enter failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert sdk.deleted == ["test-session-1"]
    assert quarantined == []

    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-2: Session file not found for test-session-2"
    )
    with pytest.raises(RuntimeError, match="session enter failed"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert quarantined == []


def test_sdk_preserves_turn_and_disconnect_causes_when_delete_raises_not_found(sdk, monkeypatch):
    from appsec_review.runtime import resources

    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)

    sdk.failure = ProviderError("upstream gateway error", code="gateway", retryable=True)
    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-1: Session file not found for test-session-1"
    )
    with pytest.raises(ProviderError, match="upstream gateway error"):
        copilot_sdk.send(request(), timeout_seconds=5)
    assert quarantined == []

    sdk.failure = None
    sdk.exit_error = RuntimeError("disconnect failed")
    sdk.delete_error = RuntimeError(
        "Failed to delete session test-session-2: Session file not found for test-session-2"
    )
    with pytest.raises(ExecutionContractError, match="Copilot session teardown failed") as exc_info:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert str(exc_info.value.__cause__) == "disconnect failed"
    assert any("session deletion teardown failed" in note for note in getattr(exc_info.value, "__notes__", ()))
    assert "copilot_teardown_unconfirmed" in quarantined


def test_sdk_session_error_422_content_filter_is_non_retryable_sanitized_provider_error(sdk):
    from copilot.session_events import SessionErrorData
    from appsec_review.inference.execution import Execution, RetryPolicy

    raw_msg = (
        "Execution failed: 422 This content was flagged for possible cybersecurity risk. "
        "If this seems wrong, try rephrasing your request. If you're doing authorized security "
        "work that requires more cyber permissive safeguards, apply for Daybreak access via "
        "https://platform.openai.com/settings/organization/status-and-access before retrying. "
        "(Request ID: D508:B2F79:98853:BC24B:6B0A642D)"
    )
    sdk.session_events = [SessionErrorData(error_type="execution", message=raw_msg, status_code=422)]
    sdk.failure = Exception(f"Session error: {raw_msg}")

    policy = RetryPolicy(3, on_provider_error=True)
    execution = Execution(timeout_seconds=10, max_calls=3)
    with worker_scope():
        with pytest.raises(ProviderError) as raised:
            execution.call(copilot_sdk.send, request(), timeout_seconds=5)
        err = raised.value
        assert err.code == "content_filter" and err.retryable is False
        assert err.__cause__ is None
        assert "Daybreak" not in str(err) and "D508" not in str(err)
        assert policy.allows(1, err) is False
        assert execution.receipts[-1].category == "provider"
        assert execution.receipts[-1].failure_code == "content_filter"
        # Subsequent turn on the same worker_scope recovers cleanly with a fresh client.
        sdk.session_events = []
        sdk.failure = None
        recovered = copilot_sdk.send(request(), timeout_seconds=5)
        assert recovered.proposal == VALUE
    assert (sdk.starts, sdk.stops, sdk.sends) == (2, 2, 2)


def test_sdk_policy_blocked_warning_without_assistant_message_is_content_filter(sdk):
    from copilot.session_events import SessionWarningData

    sdk.session_events = [SessionWarningData(warning_type="policy_blocked", message="raw policy text")]
    sdk.no_response = True
    with pytest.raises(ProviderError) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.code == "content_filter" and raised.value.retryable is False
    assert "raw policy" not in str(raised.value)


@pytest.mark.parametrize(("status_code", "error_code", "message", "expected_code", "expected_retryable"), [
    (429, "rate_limit_exceeded", "Execution failed: 429 rate limit sensitive detail", "rate_limit", True),
    (503, "service_unavailable", "Execution failed: 503 service unavailable internal host", "upstream_error", True),
    (None, None, "Execution failed: 422 This content was flagged for possible cybersecurity risk.", "content_filter", False),
    (400, "invalid_request_error", "Execution failed: 400 invalid parameter secret", "session_error", False),
])
def test_sdk_session_errors_classify_retryability_without_leaking_raw_messages(
    sdk, status_code, error_code, message, expected_code, expected_retryable
):
    from copilot.session_events import SessionErrorData

    sdk.session_events = (
        [SessionErrorData(error_type="execution", message=message, status_code=status_code, error_code=error_code)]
        if status_code is not None else []
    )
    sdk.failure = Exception(f"Session error: {message}")
    with pytest.raises(ProviderError) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.code == expected_code
    assert raised.value.retryable is expected_retryable
    for leaked in ("sensitive", "internal host", "cybersecurity", "secret"):
        assert leaked not in str(raised.value)


@pytest.mark.parametrize("kind", ["closed", "aborted", "autopilot_error", "disconnected", "eof", "process_exited"])
def test_sdk_mid_call_transport_disconnects_become_retryable_network_provider_errors(sdk, kind):
    class ProcessExitedError(Exception):
        __module__ = "copilot._jsonrpc"

    failures = {
        "closed": RuntimeError("Session closed before response completed"),
        "aborted": RuntimeError("Session aborted before response completed"),
        "autopilot_error": RuntimeError("Autopilot request failed"),
        "disconnected": RuntimeError("Session is disconnected"),
        "eof": EOFError("Unexpected end of stream while reading JSON-RPC message"),
        "process_exited": ProcessExitedError("CLI exited with raw stderr"),
    }
    sdk.failure = failures[kind]
    with pytest.raises(ProviderError) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.code == "network" and raised.value.retryable is True
    assert "raw stderr" not in str(raised.value)


def test_sdk_session_aborted_after_session_error_preserves_422_classification(sdk):
    from copilot.session_events import SessionErrorData

    sdk.session_events = [
        SessionErrorData(
            error_type="execution",
            message="Execution failed: 422 This content was flagged for possible cybersecurity risk.",
            status_code=422,
        )
    ]
    sdk.failure = RuntimeError("Session aborted before response completed")
    with pytest.raises(ProviderError) as raised:
        copilot_sdk.send(request(), timeout_seconds=5)
    assert raised.value.code == "content_filter" and raised.value.retryable is False
    assert "cybersecurity" not in str(raised.value)
