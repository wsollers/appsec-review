"""Tool-free Copilot subscription inference using a dedicated operator login."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
from typing import Any, Sequence

from .claude_cli import ModelOutputError, _plan_prompt, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, review_prompt
from .errors import ProviderError
from ._copilot_worker import _cleanup_failure, _connection, _managed, _private_directory, _run, auth_home
from .usage import Usage, token_count, total_reported


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


@asynccontextmanager
async def _delete_after_use(client, session_id):
    # SDK disconnect releases handlers but preserves a resumable conversation on disk.
    try:
        yield
    finally:
        await client.delete_session(session_id)


def _prompt_text(request: ModelRequest | ReviewModelRequest) -> str:
    if not isinstance(request, ReviewModelRequest):
        return json.dumps(_plan_prompt(request), sort_keys=True)

    prompt = review_prompt(request, include_guidance=True)
    # Canonicalize nested objects too, without sorting mutable fields to the front of the wire payload.
    first = {
        (): ("guidance", "response_schema", "guidance_bundle_sha256", "role", "persona", "stack_profile",
             "limits", "tool_catalog", "task_input", "capability_artifact_card", "transcript", "repair"),
        ("task_input",): ("tool_catalog", "turn_protocol", "protocol", "output_schema", "task"),
        ("task_input", "turn_protocol"): ("tool_catalog",),
    }

    def encode(value, path=()):
        priority = first.get(path)
        if priority is None or not isinstance(value, dict):
            return json.dumps(value, separators=(",", ":"), sort_keys=True)
        keys = [key for key in priority if key in value] + sorted(value.keys() - set(priority))
        return "{" + ",".join(json.dumps(key) + ":" + encode(value[key], (*path, key)) for key in keys) + "}"

    return encode(prompt)


async def _send(request: ModelRequest | ReviewModelRequest, timeout_seconds: int) -> ModelResult:
    client, catalog = await _connection()
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
        async with (
            _managed(_delete_after_use(client, session.session_id), "session deletion"),
            _managed(session, "session"),
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


def send(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
    return _run(_send(request, timeout_seconds), timeout_seconds)


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
