"""Tool-free Copilot subscription inference using a dedicated operator login."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Sequence

from .claude_cli import ModelOutputError, _plan_prompt, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, review_prompt
from .errors import ExecutionContractError, ModelTimeout, ProviderError, FailureCategory, failure_category
from .usage import Usage, token_count, total_reported


_CLEANUP_SECONDS = 5


@asynccontextmanager
async def _managed(manager, label: str):
    """Treat an interrupted/failed SDK exit as unconfirmed cleanup, never as success."""
    entered = False
    body_error = None
    try:
        async with manager as value:
            entered = True
            try:
                yield value
            except BaseException as error:
                body_error = error
                raise
    except BaseException as error:
        if not entered or error is body_error:
            raise
        failure = _cleanup_failure(f"Copilot {label} teardown failed")
        cancellation = next((item for item in (body_error, error) if item is not None and
                             failure_category(item) is FailureCategory.CANCELLED), None)
        if cancellation is not None:
            cancellation.add_note(str(failure))
            raise cancellation from failure
        raise failure from error
    if body_error is not None:
        # An SDK context manager may not suppress cancellation or an application failure.
        raise body_error


def auth_home() -> Path:
    return Path(os.environ.get("APPSEC_COPILOT_HOME") or
                Path.home() / ".config" / "appsec-review" / "copilot").expanduser().resolve()


@asynccontextmanager
async def _client():
    try:
        from copilot import CopilotClient
    except ImportError as exc:
        raise ProviderError("Copilot SDK is unavailable; install appsec-review[copilot]",
                            code="sdk_unavailable") from exc
    home = auth_home()
    if not home.is_dir():
        raise ProviderError("Copilot worker login is missing", code="authentication_missing")
    # Git's identity must never become the inference identity, even when inherited from CI.
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN",
                                  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"}}
    environment["COPILOT_HOME"] = str(home)
    environment["COPILOT_SKIP_CLI_DOWNLOAD"] = "1"
    environment["COPILOT_GITHUB_TELEMETRY_DISABLED"] = "true"
    with tempfile.TemporaryDirectory(prefix="appsec-copilot-") as working:
        async with _managed(CopilotClient(
            mode="empty", base_directory=str(home), working_directory=working,
            env=environment, use_logged_in_user=True,
        ), "client") as client:
            status = await client.get_auth_status()
            if not status.isAuthenticated:
                raise ProviderError("Copilot worker subscription login is required in APPSEC_COPILOT_HOME",
                                    code="authentication_missing")
            yield client, working


def _available(model: Any) -> bool:
    return model.policy is None or model.policy.state == "enabled"


async def _models(names: Sequence[str]) -> dict[str, Any]:
    async with _client() as (client, _working):
        catalog = {model.id: model for model in await client.list_models()}
        return {
            "method": "catalog", "listed": sorted(catalog),
            "models": {name: {
                "available": name in catalog and _available(catalog[name]),
                "detail": ("listed and enabled for the Copilot worker account"
                           if name in catalog and _available(catalog[name])
                           else "not listed or not enabled for the Copilot worker account"),
            } for name in names},
        }


async def _send(request: ModelRequest | ReviewModelRequest, timeout_seconds: int) -> ModelResult:
    async with _client() as (client, working):
        from copilot.session import (
            ModelCapabilitiesOverride, ModelLimitsOverride, PermissionDecisionUserNotAvailable,
        )
        from copilot.session_events import AssistantMessageData, AssistantUsageData

        catalog = {model.id: model for model in await client.list_models()}
        model = catalog.get(request.model)
        if model is None or not _available(model):
            raise ProviderError("Copilot model is unavailable", code="model_unavailable")
        if request.reasoning not in (model.supported_reasoning_efforts or []):
            raise ValueError(f"Copilot model {request.model} does not support reasoning "
                             f"effort {request.reasoning}")
        prompt = (review_prompt(request, include_guidance=True)
                  if isinstance(request, ReviewModelRequest) else _plan_prompt(request))
        usage: list[AssistantUsageData] = []

        def observe(event):
            if not event.agent_id and isinstance(event.data, AssistantUsageData):
                usage.append(event.data)

        session = await client.create_session(
            model=request.model, reasoning_effort=request.reasoning,
            working_directory=working, config_directory=working,
            available_tools=[], tools=[], mcp_servers={}, custom_agents=[],
            excluded_tools=["builtin:*", "mcp:*", "custom:*"],
            on_permission_request=lambda *_: PermissionDecisionUserNotAvailable(),
            skip_custom_instructions=True, enable_config_discovery=False,
            enable_on_demand_instruction_discovery=False, enable_file_hooks=False,
            enable_host_git_operations=False, enable_skills=False, enable_session_store=False,
            enable_session_telemetry=False, request_extensions=False,
            infinite_sessions={"enabled": False},
            model_capabilities=ModelCapabilitiesOverride(limits=ModelLimitsOverride(
                max_prompt_tokens=request.max_input_tokens, max_output_tokens=request.max_output_tokens)),
            on_event=observe,
        )
        async with _managed(session, "session"):
            # The outer deadline covers authentication, catalog lookup, creation, and inference.
            try:
                response = await session.send_and_wait(json.dumps(prompt, sort_keys=True),
                                                       timeout=timeout_seconds)
            except (asyncio.CancelledError, TimeoutError) as original:
                try:
                    # _run owns the single cleanup deadline; wait_for could itself wait forever
                    # for a cancellation-resistant abort coroutine.
                    await session.abort()
                except BaseException:
                    failure = _cleanup_failure("Copilot session abort failed")
                    original.add_note("Copilot session abort failed")
                    raise original from failure
                raise
            if response is None or not isinstance(response.data, AssistantMessageData):
                raise ModelOutputError("Copilot returned no final assistant message")
            data = response.data
            if data.tool_requests:
                raise ModelOutputError("Copilot requested tools in a tool-free inference session")
            served = {item.model for item in usage}
            if data.model:
                served.add(data.model)
            if served != {request.model}:
                raise ModelOutputError("Copilot did not confirm the exact requested model")
            raw = data.content
            try:
                proposal = parse_model_payload(raw, request.schema)
            except ModelOutputError as exc:
                bounded = raw.encode("utf-8") if isinstance(raw, str) else b""
                raise ModelOutputError(str(exc), raw_response=bounded[:2 * 1024 * 1024].decode("utf-8", "ignore"),
                                       rejected_output=bounded[:131072].decode("utf-8", "ignore")) from exc

            def tokens(field: str) -> int | None:
                return total_reported([token_count(getattr(item, field, None)) for item in usage])

            invalid_usage = any(getattr(item, name, None) is not None and
                                token_count(getattr(item, name)) is None
                                for item in usage
                                for name in ("input_tokens", "output_tokens", "cache_read_tokens"))
            result = ModelResult(proposal=proposal, input_tokens=tokens("input_tokens"),
                               output_tokens=tokens("output_tokens"), cache_tokens=tokens("cache_read_tokens"),
                               raw_response=raw, served_model=request.model, served_provider="copilot-sdk",
                               usage_unavailable_reason="invalid_provider_usage" if invalid_usage else None)
            return Usage.from_result(result).normalize(result)


def _cleanup_failure(message: str, *, pending_tasks: int = 0) -> ExecutionContractError:
    from appsec_review.runtime import execution_safety as safety
    from appsec_review.runtime.resources import quarantine_resources
    error = ExecutionContractError(message)
    try:
        quarantine_resources("copilot_teardown_unconfirmed")
    except Exception as failure:
        error.add_note(f"Copilot resource quarantine failed ({type(failure).__name__})")
    try:
        safety.retain_failure("copilot.cleanup", error, pending_tasks=pending_tasks, category="contract")
    except Exception as failure:
        error.add_note(f"Copilot cleanup evidence publication failed ({type(failure).__name__})")
    return error


def _run(operation, timeout_seconds: int):
    from appsec_review.runtime import execution_safety as safety
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0):
        operation.close()
        raise ExecutionContractError("Copilot timeout_seconds must be finite and positive")
    try:
        safety.check_running()
    except BaseException:
        operation.close()
        raise

    loop = asyncio.new_event_loop()
    task = loop.create_task(operation)
    deadline = time.monotonic() + timeout_seconds
    original: BaseException | None = None

    async def bounded():
        while not task.done():
            safety.check_running()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ModelTimeout("Copilot call timed out")
            await asyncio.wait({task}, timeout=min(0.1, remaining))
        safety.check_running()
        return task.result()

    try:
        result = loop.run_until_complete(bounded())
    except TimeoutError:
        original = ModelTimeout("Copilot call timed out")
    except ConnectionError:
        original = ProviderError("Copilot connection failed", code="network", retryable=True)
    except BaseException as error:
        original = error
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            cleanup_error = None
            if pending:
                for pending_task in pending:
                    pending_task.cancel()
                done, pending = loop.run_until_complete(asyncio.wait(pending, timeout=_CLEANUP_SECONDS))
                for completed in done:
                    if completed.cancelled():
                        try:
                            completed.result()
                        except asyncio.CancelledError as cancellation:
                            if isinstance(cancellation.__cause__, ExecutionContractError):
                                cleanup_error = cancellation.__cause__
                    elif completed.exception() is not None:
                        cleanup_error = _cleanup_failure("Copilot cancellation cleanup failed")
            if pending:
                cleanup_error = _cleanup_failure("Copilot teardown exceeded its cancellation bound",
                                                 pending_tasks=len(pending))
            if cleanup_error is not None:
                if original is not None and failure_category(original) is FailureCategory.CANCELLED:
                    original.add_note(str(cleanup_error))
                    raise original from cleanup_error
                raise cleanup_error from original
        finally:
            loop.close()
    if original is not None:
        raise original
    return result


def send(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
    return _run(_send(request, timeout_seconds), timeout_seconds)


def models(names: Sequence[str], *, timeout_seconds: int) -> dict[str, Any]:
    return _run(_models(names), timeout_seconds)


def verify() -> dict[str, Any]:
    """Check the selected profile's account/model catalog without running a review or inference."""
    from appsec_review.config import load_config
    from appsec_review.jobs.job_review_intake.job import configured_models

    config = load_config(os.environ.get("APPSEC_REVIEW_CONFIG") or "appsec-review.toml")
    required = configured_models(json.loads(config.resolved_json))
    if not required or any(item["provider"] != "copilot-sdk" for item in required):
        raise RuntimeError("select the copilot-dev or copilot-prod profile before checking Copilot worker authentication")
    names = sorted({item["model"] for item in required})
    report = models(names, timeout_seconds=120)
    unavailable = [name for name in names if not report["models"][name]["available"]]
    if unavailable:
        raise RuntimeError(f"Copilot worker models are unavailable: {', '.join(unavailable)}")
    return {"provider": "copilot-sdk", "method": "catalog", "models": names}
