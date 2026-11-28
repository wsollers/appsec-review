"""Tool-free Copilot subscription inference using a dedicated operator login."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, Sequence

from .claude_cli import ModelOutputError, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, plan_prompt, review_user_text
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


def _ephemeral_session_persisted(session_id: str) -> bool:
    state_dir = auth_home() / "session-state"
    return (state_dir / session_id).exists() or (state_dir / f"{session_id}.jsonl").exists()


def _cleanup_ephemeral_turn_session(client, session_id: str, working: str) -> bool:
    if _ephemeral_session_persisted(session_id):
        return False
    turn_state = Path(working) / "session-state"
    turn_dir = turn_state / session_id
    if turn_dir.is_dir():
        if any(turn_dir.glob("inuse.*")):
            return False
        shutil.rmtree(turn_dir)
    elif turn_dir.exists():
        turn_dir.unlink()
    (turn_state / f"{session_id}.jsonl").unlink(missing_ok=True)
    (turn_state / ".session-operation-locks" / f"{session_id}.lock").unlink(missing_ok=True)
    if turn_dir.exists() or (turn_state / f"{session_id}.jsonl").exists():
        return False
    sessions = getattr(client, "_sessions", None)
    if isinstance(sessions, dict):
        lock = getattr(client, "_sessions_lock", None)
        if lock is not None:
            with lock:
                sessions.pop(session_id, None)
        else:
            sessions.pop(session_id, None)
    return True


@asynccontextmanager
async def _session_scope(session, state: dict[str, bool]):
    await session.__aenter__()
    state["entered"] = True
    try:
        yield session
    except BaseException as exc:
        suppressed = await session.__aexit__(type(exc), exc, exc.__traceback__)
        state["disconnected"] = True
        if not suppressed:
            raise
    else:
        await session.__aexit__(None, None, None)
        state["disconnected"] = True


@asynccontextmanager
async def _delete_after_use(client, session_id: str, working: str, state: dict[str, bool]):
    # CopilotClient runs with base_directory=auth_home(), whereas each turn isolates
    # config_directory=working. On delete_session, Copilot CLI 1.0.25+ checks base_directory
    # and raises "Session file not found"; accept that exact error only after clean disconnect
    # (or pre-entry setup failure) when auth_home() has no session-state residue and per-turn
    # scratch state is unheld and removed.
    try:
        yield
    finally:
        try:
            await client.delete_session(session_id)
        except RuntimeError as exc:
            expected = f"Failed to delete session {session_id}: Session file not found for {session_id}"
            if not ((state["disconnected"] or not state["entered"]) and str(exc) == expected
                    and _cleanup_ephemeral_turn_session(client, session_id, working)):
                _cleanup_ephemeral_turn_session(client, session_id, working)
                raise
        else:
            if not _cleanup_ephemeral_turn_session(client, session_id, working):
                raise _cleanup_failure(f"Copilot session {session_id} persisted after deletion")


_DISCONNECTED_SESSION_MESSAGES = frozenset({
    "Session closed before response completed",
    "Session is disconnected",
})
_CONTENT_FILTER_CODES = frozenset({
    "content_filter",
    "content_policy_violation",
    "policy_blocked",
    "cyber_policy_violation",
    "safety",
})
_CONTENT_FILTER_MARKERS = (
    "flagged for possible cybersecurity risk",
    "content_filter",
    "content management policy",
    "content policy",
    "safety system",
    "policy_blocked",
    "violates our usage policy",
)
_RATE_LIMIT_CODES = frozenset({"rate_limit", "rate_limit_exceeded", "too_many_requests"})
_TRANSIENT_STATUS_CODES = frozenset({408, 500, 502, 503, 504, 529})
_TRANSIENT_ERROR_CODES = frozenset({
    "server_error",
    "overloaded",
    "overloaded_error",
    "service_unavailable",
    "bad_gateway",
    "gateway_timeout",
})
_TRANSIENT_MARKERS = (
    "overloaded",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
    "connection reset",
    "econnreset",
    "etimedout",
    "socket hang up",
)
_EXECUTION_STATUS_RE = re.compile(r"(?:^|\bExecution failed:\s*)([1-5]\d\d)\b")


def _classify_session_error(error_data: Any | None, raw_message: str) -> ProviderError:
    raw_status = getattr(error_data, "status_code", None)
    if isinstance(raw_status, int) and not isinstance(raw_status, bool):
        status_code: int | None = raw_status
    else:
        match = _EXECUTION_STATUS_RE.search(raw_message)
        status_code = int(match.group(1)) if match else None
    error_code = str(getattr(error_data, "error_code", None) or "").strip().lower()
    error_type = str(getattr(error_data, "error_type", None) or "").strip().lower()
    provider_error_type = str(getattr(error_data, "provider_error_type", None) or "").strip().lower()
    combined_msg = f"{getattr(error_data, 'message', None) or ''}\n{raw_message}".lower()

    if (error_code in _CONTENT_FILTER_CODES
            or provider_error_type in _CONTENT_FILTER_CODES
            or any(marker in combined_msg for marker in _CONTENT_FILTER_MARKERS)
            or (status_code == 422 and any(word in combined_msg for word in (
                "flagged", "cybersecurity", "safeguards", "policy", "safety")))):
        return ProviderError(
            "Copilot provider blocked the request under content policy",
            retryable=False,
            code="content_filter",
        )
    if (status_code == 429
            or error_code in _RATE_LIMIT_CODES
            or provider_error_type in _RATE_LIMIT_CODES
            or "rate limit" in combined_msg
            or "too many requests" in combined_msg):
        return ProviderError(
            "Copilot provider rate limit exceeded",
            retryable=True,
            code="rate_limit",
        )
    if (status_code in _TRANSIENT_STATUS_CODES
            or error_code in _TRANSIENT_ERROR_CODES
            or provider_error_type in _TRANSIENT_ERROR_CODES
            or error_type in {"network", "connection", "transient"}
            or any(marker in combined_msg for marker in _TRANSIENT_MARKERS)):
        return ProviderError(
            "Copilot upstream provider failed transiently",
            retryable=True,
            code="upstream_error",
        )
    return ProviderError(
        "Copilot session failed with a non-retryable provider error",
        retryable=False,
        code="session_error",
    )


def _prompt_text(request: ModelRequest | ReviewModelRequest) -> str:
    if not isinstance(request, ReviewModelRequest):
        return json.dumps(plan_prompt(request), sort_keys=True)

    return review_user_text(request)


async def _send(request: ModelRequest | ReviewModelRequest, timeout_seconds: int,
                observation: ConnectionObservation) -> ModelResult:
    client, catalog = await _connection(observation)
    async with _managed(_private_directory("appsec-copilot-turn-"), "turn directory") as working:
        from copilot.session import (
            ModelCapabilitiesOverride, ModelLimitsOverride, PermissionDecisionUserNotAvailable,
        )
        import copilot.session_events as session_events
        AssistantMessageData = session_events.AssistantMessageData
        AssistantUsageData = session_events.AssistantUsageData
        session_error_cls = getattr(session_events, "SessionErrorData", None)
        session_warning_cls = getattr(session_events, "SessionWarningData", None)

        model = catalog.get(request.model)
        if model is None or not _available(model):
            raise ProviderError("Copilot model is unavailable", code="model_unavailable")
        if request.reasoning not in (model.supported_reasoning_efforts or []):
            raise ValueError(f"Copilot model {request.model} does not support reasoning "
                             f"effort {request.reasoning}")
        prompt = _prompt_text(request)
        usage: list[AssistantUsageData] = []
        session_errors: list[Any] = []
        policy_blocked = False

        def observe(event):
            nonlocal policy_blocked
            if event.agent_id:
                return
            if isinstance(event.data, AssistantUsageData):
                usage.append(event.data)
            elif session_error_cls is not None and isinstance(event.data, session_error_cls):
                session_errors.append(event.data)
            elif session_warning_cls is not None and isinstance(event.data, session_warning_cls):
                if getattr(event.data, "warning_type", None) == "policy_blocked":
                    policy_blocked = True

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
        session_state = {"entered": False, "disconnected": False}
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
            except RuntimeError as exc:
                if type(exc) is RuntimeError and str(exc) in _DISCONNECTED_SESSION_MESSAGES:
                    raise ProviderError(
                        "Copilot session disconnected before response completed",
                        retryable=True,
                        code="network",
                    ) from None
                raise
            except Exception as exc:
                if type(exc) is Exception and (session_errors or str(exc).startswith("Session error:")):
                    raise _classify_session_error(
                        session_errors[-1] if session_errors else None,
                        str(exc),
                    ) from None
                raise
            if response is None or not isinstance(response.data, AssistantMessageData):
                if session_errors:
                    raise _classify_session_error(
                        session_errors[-1],
                        str(getattr(session_errors[-1], "message", "") or ""),
                    )
                if policy_blocked:
                    raise ProviderError(
                        "Copilot provider blocked the request under content policy",
                        retryable=False,
                        code="content_filter",
                    )
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
