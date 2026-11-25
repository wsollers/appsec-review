"""Tool-free Copilot subscription inference using a dedicated operator login."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
from typing import Any, Sequence

from .claude_cli import ModelOutputError, _plan_prompt, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, review_user_text
from .errors import ProviderError
from ._copilot_worker import ConnectionObservation, _cleanup_failure, _connection, _managed, _private_directory, _run, auth_home
from .usage import Usage, reported_cache_write, token_count, total_reported


def _available(model: Any) -> bool:
    return model.policy is None or model.policy.state == "enabled"


async def _models(names: Sequence[str]) -> dict[str, Any]:
    _, catalog = await _connection()
    return {
        "method": "catalog", "listed": sorted(catalog),
        "models": {name: {
            "available": name in catalog and _available(catalog[name]),
            "detail": ("listed and enabled for the Copilot worker account"
                       if name in catalog and _available(catalog[name])
                       else "not listed or not enabled for the Copilot worker account"),
        } for name in names},
    }


def _ephemeral_session_persisted(session_id: str, working: str) -> bool:
    for root in (auth_home(), Path(working)):
        state_dir = root / "session-state"
        if (state_dir / session_id).exists() or (state_dir / f"{session_id}.jsonl").exists():
            return True
    return False


@asynccontextmanager
async def _session_scope(session, state: dict[str, bool]):
    await session.__aenter__()
    try:
        yield session
    finally:
        await session.__aexit__(None, None, None)
        state["disconnected"] = True


@asynccontextmanager
async def _delete_after_use(client, session_id: str, working: str, state: dict[str, bool]):
    # SDK disconnect releases handlers; ephemeral sessions (enable_session_store=False,
    # infinite_sessions disabled) never write a session-state file on disk, so Copilot CLI
    # 1.0.25+ reports "Session file not found" on delete_session after clean disconnect.
    try:
        yield
    finally:
        try:
            await client.delete_session(session_id)
        except RuntimeError as exc:
            expected = f"Failed to delete session {session_id}: Session file not found for {session_id}"
            if not (state["disconnected"] and str(exc) == expected
                    and not _ephemeral_session_persisted(session_id, working)):
                raise


def _prompt_text(request: ModelRequest | ReviewModelRequest) -> str:
    if not isinstance(request, ReviewModelRequest):
        return json.dumps(_plan_prompt(request), sort_keys=True)

    return review_user_text(request)


async def _send(request: ModelRequest | ReviewModelRequest, timeout_seconds: int,
                observation: ConnectionObservation) -> ModelResult:
    client, catalog = await _connection(observation)
    async with _managed(_private_directory("appsec-copilot-turn-"), "turn directory") as working:
        from copilot.session import (
            ModelCapabilitiesOverride, ModelLimitsOverride, PermissionDecisionUserNotAvailable,
        )
        from copilot.session_events import AssistantMessageData, AssistantUsageData

        model = catalog.get(request.model)
        if model is None or not _available(model):
            raise ProviderError("Copilot model is unavailable", code="model_unavailable")
        if request.reasoning not in (model.supported_reasoning_efforts or []):
            raise ValueError(f"Copilot model {request.model} does not support reasoning "
                             f"effort {request.reasoning}")
        prompt = _prompt_text(request)
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
        session_state = {"disconnected": False}
        async with (
            _managed(_delete_after_use(client, session.session_id, working, session_state), "session deletion"),
            _managed(_session_scope(session, session_state), "session"),
        ):
            # The outer deadline covers authentication, catalog lookup, creation, and inference.
            try:
                response = await session.send_and_wait(prompt, timeout=timeout_seconds)
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

            def counts(item):
                return {"input_tokens": getattr(item, "input_tokens", None),
                        "output_tokens": getattr(item, "output_tokens", None),
                        "cache_tokens": getattr(item, "cache_read_tokens", None),
                        "cache_write_tokens": reported_cache_write(item)}

            reports = [counts(item) for item in usage]
            totals = {name: total_reported([token_count(row[name]) for row in reports])
                      for name in ("input_tokens", "output_tokens", "cache_tokens", "cache_write_tokens")}
            invalid_usage = any(value is not None and token_count(value) is None
                                for row in reports for value in row.values())
            result = ModelResult(proposal=proposal, **totals, raw_response=raw, served_model=request.model,
                                 served_provider="copilot-sdk",
                                 usage_unavailable_reason="invalid_provider_usage" if invalid_usage else None)
            return Usage.from_result(result).normalize(result)


def send(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
    observation = ConnectionObservation()
    try:
        result = _run(_send(request, timeout_seconds, observation), timeout_seconds)
    except BaseException as error:
        error.client_reused = observation.client_reused
        error.client_cold_start_ms = observation.client_cold_start_ms
        raise
    return replace(result, client_reused=observation.client_reused,
                   client_cold_start_ms=observation.client_cold_start_ms)


def models(names: Sequence[str], *, timeout_seconds: int) -> dict[str, Any]:
    return _run(_models(names), timeout_seconds)


def verify(profile: str | None = None) -> dict[str, Any]:
    """Check the selected profile's account/model catalog without running a review or inference."""
    from appsec_review.config import load_config
    from appsec_review.jobs.job_review_intake.job import configured_models

    config = load_config(os.environ.get("APPSEC_REVIEW_CONFIG") or "appsec-review.toml", profile=profile)
    required = configured_models(json.loads(config.resolved_json))
    if not required or any(item["provider"] != "copilot-sdk" for item in required):
        raise RuntimeError(
            "Copilot worker authentication requires every configured model to use copilot-sdk; "
            f"profile {config.profile!r} contains non-Copilot models or no configured models"
        )
    names = sorted({item["model"] for item in required})
    report = models(names, timeout_seconds=120)
    unavailable = [name for name in names if not report["models"][name]["available"]]
    if unavailable:
        raise RuntimeError(f"Copilot worker models are unavailable: {', '.join(unavailable)}")
    return {"provider": "copilot-sdk", "method": "catalog", "models": names}
