from __future__ import annotations

import json
import os
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from appsec_review.jobs.job_target_analysis_plan.planning import ModelRequest, ModelResult

from .claude_cli import ModelOutputError, parse_model_payload


_THINKING_BUDGETS = {"low": 1024, "medium": 2048, "high": 4096, "xhigh": 6144}


class AnthropicApiModelClient:
    """Minimal bounded Claude Messages API adapter; no SDK or agent tools are involved."""

    def __init__(self, *, endpoint: str = "https://api.anthropic.com/v1/messages") -> None:
        self.endpoint = endpoint

    def complete(self, request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
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
                                "instruction": "Return only one corrected JSON object."}
        budget = min(_THINKING_BUDGETS.get(request.reasoning, 2048),
                     max(1024, request.max_output_tokens - 1024))
        body: dict[str, Any] = {
            "model": request.model, "max_tokens": request.max_output_tokens,
            "messages": [{"role": "user", "content": json.dumps(prompt, sort_keys=True)}],
            "thinking": {"type": "enabled", "budget_tokens": budget},
        }
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        http_request = Request(self.endpoint, data=encoded, method="POST", headers={
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
                f"(stop_reason={stop_reason})"
            ) from exc
        usage = envelope.get("usage", {}) if isinstance(envelope.get("usage"), Mapping) else {}
        return ModelResult(proposal=proposal, input_tokens=usage.get("input_tokens"),
                           output_tokens=usage.get("output_tokens"),
                           cache_tokens=usage.get("cache_read_input_tokens"),
                           raw_response=raw.decode("utf-8", "replace"))


class ConfiguredClaudeModelClient:
    def __init__(self) -> None:
        from .claude_cli import ClaudeCliModelClient
        self._clients = {"anthropic-api": AnthropicApiModelClient(),
                         "claude-cli": ClaudeCliModelClient()}

    def complete(self, request: ModelRequest, *, timeout_seconds: int) -> ModelResult:
        try:
            client = self._clients[request.provider]
        except KeyError as exc:
            raise ValueError(f"unsupported inference provider: {request.provider}") from exc
        return client.complete(request, timeout_seconds=timeout_seconds)
