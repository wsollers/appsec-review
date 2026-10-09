from __future__ import annotations

import json
import os
from typing import Any, Mapping, Sequence
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .claude_cli import ModelOutputError, parse_model_payload
from .request import ModelRequest, ModelResult


_THINKING_BUDGETS = {"low": 1024, "medium": 2048, "high": 4096, "xhigh": 6144}


ENDPOINT = "https://api.anthropic.com/v1/messages"


def send(request: ModelRequest, *, timeout_seconds: int, endpoint: str = ENDPOINT) -> ModelResult:
    """Anthropic Messages API transport; no SDK or agent tools are involved."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is unavailable to the configured inference provider")
    prompt = {
        "task": request.guidance, "response_schema": request.schema,
        "catalog_summary": request.summary,
        "allowlists": {"scanners": request.allowed_scanners,
                       "build_systems": request.allowed_build_systems,
                       "components": request.allowed_components,
                       "paths": request.allowed_paths,
                       "build_units": request.allowed_build_units},
        "limits": {"max_input_tokens": request.max_input_tokens,
                   "max_output_tokens": request.max_output_tokens},
    }
    if request.repair_errors:
        prompt["repair"] = {"validation_errors": request.repair_errors,
                            "rejected_response": request.prior_response,
                            "instruction": ("Return only one corrected JSON object. Its top-level "
                                            f"schema must be exactly {request.schema}.")}
    budget = min(_THINKING_BUDGETS.get(request.reasoning, 2048),
                 max(1024, request.max_output_tokens - 1024))
    body: dict[str, Any] = {
        "model": request.model, "max_tokens": request.max_output_tokens,
        "messages": [{"role": "user", "content": json.dumps(prompt, sort_keys=True)}],
        "thinking": {"type": "enabled", "budget_tokens": budget},
    }
    system = "\n\n".join(part for part in (request.persona, request.role) if part)
    if system:
        body["system"] = system
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    http_request = Request(endpoint, data=encoded, method="POST", headers={
        "content-type": "application/json", "x-api-key": key,
        "anthropic-version": "2023-06-01", "user-agent": "appsec-review/0.0.0",
    })
    try:
        with urlopen(http_request, timeout=timeout_seconds) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise RuntimeError(f"Anthropic API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Anthropic API request failed: {exc.reason}") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise ModelOutputError("Anthropic API response exceeded the response bound")
    envelope = json.loads(raw)
    if not isinstance(envelope, Mapping):
        raise ModelOutputError("Anthropic API response is not an object")
    text = "\n".join(str(item["text"]) for item in envelope.get("content", ())
                     if isinstance(item, Mapping) and item.get("type") == "text")
    try:
        proposal = parse_model_payload(text, request.schema)
    except ModelOutputError as exc:
        stop_reason = str(envelope.get("stop_reason", "unknown"))
        raise ModelOutputError(
            f"Anthropic response was not a complete {request.schema} object "
            f"(stop_reason={stop_reason}; parse_error={exc})",
            raw_response=raw.decode("utf-8", "replace"),
            rejected_output=text[:131072],
        ) from exc
    usage = envelope.get("usage", {}) if isinstance(envelope.get("usage"), Mapping) else {}
    return ModelResult(proposal=proposal, input_tokens=usage.get("input_tokens"),
                       output_tokens=usage.get("output_tokens"),
                       cache_tokens=usage.get("cache_read_input_tokens"),
                       raw_response=raw.decode("utf-8", "replace"))


MODELS_ENDPOINT = "https://api.anthropic.com/v1/models"


def _get(url: str, key: str, timeout_seconds: int) -> tuple[int, Mapping[str, Any]]:
    http_request = Request(url, method="GET", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "user-agent": "appsec-review/0.0.0"})
    try:
        with urlopen(http_request, timeout=timeout_seconds) as response:
            value = json.loads(response.read(4 * 1024 * 1024))
    except HTTPError as exc:
        if exc.code == 404:
            return 404, {}
        raise RuntimeError(f"Anthropic API returned HTTP {exc.code}: "
                           f"{exc.read(1024).decode('utf-8', 'replace')}") from exc
    except URLError as exc:
        raise RuntimeError(f"Anthropic API request failed: {exc.reason}") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError("Anthropic API model response is not an object")
    return 200, value


def models(names: Sequence[str], *, timeout_seconds: int,
           endpoint: str = MODELS_ENDPOINT) -> dict[str, Any]:
    """List the account's models and confirm each named model, resolving aliases by lookup."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is unavailable to the configured inference provider")
    _status, listing = _get(endpoint + "?limit=1000", key, timeout_seconds)
    listed = sorted(str(item["id"]) for item in listing.get("data", ())
                    if isinstance(item, Mapping) and isinstance(item.get("id"), str))
    result: dict[str, Any] = {}
    for name in names:
        if name in listed:
            result[name] = {"available": True, "detail": "listed by the provider"}
            continue
        # An alias is served but not listed; the provider resolves it on direct lookup.
        status, value = _get(f"{endpoint}/{quote(name, safe='')}", key, timeout_seconds)
        result[name] = ({"available": True, "detail": f"resolved by the provider to {value.get('id')}"}
                        if status == 200 and value.get("id") else
                        {"available": False, "detail": "the provider does not serve this model"})
    return {"method": "catalog", "listed": listed, "models": result}
