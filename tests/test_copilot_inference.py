from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.inference import PROVIDERS, MODEL_CHECKS
from appsec_review.inference import copilot_sdk
from appsec_review.inference.claude_cli import ModelOutputError
from appsec_review.inference.request import ModelRequest, ReviewModelRequest
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


@pytest.fixture
def sdk(monkeypatch):
    pytest.importorskip("copilot")
    from copilot.session_events import AssistantMessageData, AssistantUsageData

    state = SimpleNamespace(options=None, prompt=None, closed=False, aborted=False,
                            response=json.dumps(VALUE), served="claude-haiku-5.5",
                            policy="enabled", reasoning=["low"], delay=0, tools=None,
                            models=["claude-haiku-5.5"])

    class Session:
        session_id = "test-session"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            state.closed = True

        async def abort(self):
            state.aborted = True

        async def send_and_wait(self, prompt, *, timeout):
            state.prompt = json.loads(prompt)
            await asyncio.sleep(state.delay)
            state.options["on_event"](SimpleNamespace(agent_id=None, data=AssistantUsageData(
                model=state.served, input_tokens=10, output_tokens=20, cache_read_tokens=3)))
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
        yield Client(), "/isolated"

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
    for job_id, job in before["jobs"].items():
        settings = job["settings"]
        models = ([settings["model"]] if "model" in settings else
                  list(settings.get("models", {}).values()))
        for model in models:
            assert model["provider"] == "claude-cli"
            model["provider"] = "copilot-sdk"
            model["model"] = names[model["model"]]
        assert after["jobs"][job_id] == job
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
    copilot = pytest.importorskip("copilot")
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
    pytest.importorskip("copilot")
    monkeypatch.setenv("APPSEC_COPILOT_HOME", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError, match="worker login is missing"):
        copilot_sdk.models(["claude-haiku-5.5"], timeout_seconds=5)
