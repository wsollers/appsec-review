"""Tool-free Copilot subscription inference using a dedicated operator login."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Sequence

from .claude_cli import ModelOutputError, _plan_prompt, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, review_prompt


def auth_home() -> Path:
    return Path(os.environ.get("APPSEC_COPILOT_HOME") or
                Path.home() / ".config" / "appsec-review" / "copilot").expanduser().resolve()


@asynccontextmanager
async def _client():
    try:
        from copilot import CopilotClient
    except ImportError as exc:
        raise RuntimeError("install appsec-review[copilot] and run "
                           "`python -m copilot download-runtime`") from exc
    home = auth_home()
    if not home.is_dir():
        raise RuntimeError("Copilot worker login is missing; run `COPILOT_HOME="
                           "\"$HOME/.config/appsec-review/copilot\" copilot login`")
    # Git's identity must never become the inference identity, even when inherited from CI.
    environment = {key: value for key, value in os.environ.items()
                   if key not in {"GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN",
                                  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"}}
    environment["COPILOT_HOME"] = str(home)
    environment["COPILOT_SKIP_CLI_DOWNLOAD"] = "1"
    environment["COPILOT_GITHUB_TELEMETRY_DISABLED"] = "true"
    with tempfile.TemporaryDirectory(prefix="appsec-copilot-") as working:
        async with CopilotClient(
            mode="empty", base_directory=str(home), working_directory=working,
            env=environment, use_logged_in_user=True,
        ) as client:
            status = await client.get_auth_status()
            if not status.isAuthenticated:
                raise RuntimeError("Copilot worker subscription login is required in APPSEC_COPILOT_HOME")
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
            raise RuntimeError(f"Copilot model is unavailable: {request.model}")
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
        async with session:
            # The outer deadline covers authentication, catalog lookup, creation, and inference.
            try:
                response = await session.send_and_wait(json.dumps(prompt, sort_keys=True),
                                                       timeout=timeout_seconds)
            except (asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(session.abort(), timeout=5)
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
                raise ModelOutputError(str(exc), raw_response=raw[:2 * 1024 * 1024],
                                       rejected_output=raw[:131072]) from exc

            def tokens(field: str) -> int | None:
                values = [getattr(item, field) for item in usage]
                return sum(values) if values and all(value is not None for value in values) else None

            return ModelResult(proposal=proposal, input_tokens=tokens("input_tokens"),
                               output_tokens=tokens("output_tokens"), cache_tokens=tokens("cache_read_tokens"),
                               raw_response=raw, served_model=request.model, served_provider="copilot-sdk")


def _run(operation, timeout_seconds: int):
    from appsec_review.runtime import execution_safety as safety
    if timeout_seconds <= 0:
        operation.close()
        raise ValueError("Copilot timeout_seconds must be positive")

    async def bounded():
        async with asyncio.timeout(timeout_seconds):
            if not safety.active():
                return await operation
            task = asyncio.create_task(operation)
            try:
                while not task.done():
                    safety.check_running()
                    await asyncio.wait({task}, timeout=0.1)
                return await task
            except BaseException:
                task.cancel()
                done, pending = await asyncio.wait({task}, timeout=5)
                if not pending:
                    await asyncio.gather(*done, return_exceptions=True)
                raise

    if not safety.active():
        return asyncio.run(bounded())
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(bounded())
    finally:
        pending = asyncio.all_tasks(loop)
        try:
            if pending:
                for task in pending:
                    task.cancel()
                done, pending = loop.run_until_complete(asyncio.wait(pending, timeout=5))
                for task in done:
                    if not task.cancelled():
                        task.exception()
            if pending:
                from appsec_review.runtime.resources import quarantine_resources
                quarantine_resources("copilot_teardown_unconfirmed")
                error = RuntimeError("Copilot teardown exceeded its cancellation bound")
                safety.retain_failure("copilot.cleanup", error, pending_tasks=len(pending))
                safety.fail(str(error), action="copilot.cleanup")
        finally:
            loop.close()


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
