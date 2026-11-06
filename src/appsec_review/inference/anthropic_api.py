from __future__ import annotations

import json
import math
from http.client import HTTPException, IncompleteRead
import os
import socket
import ssl
import time
from typing import Any, Mapping, Sequence
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .claude_cli import ModelOutputError, parse_model_payload
from .request import ModelRequest, ModelResult, ReviewModelRequest, review_prompt
from .errors import ExecutionContractError, ModelTimeout, ProviderError
from .usage import Usage


_THINKING_BUDGETS = {"low": 1024, "medium": 2048, "high": 4096, "xhigh": 6144}


ENDPOINT = "https://api.anthropic.com/v1/messages"


def send(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int,
         endpoint: str = ENDPOINT) -> ModelResult:
    """Anthropic Messages API transport; no SDK or agent tools are involved."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ProviderError("Anthropic API authentication is unavailable", code="authentication_missing")
    if isinstance(request, ReviewModelRequest):
        # Hash-pinned guidance is the trusted system channel; task input and the
        # application-mediated transcript are the untrusted user message.
        prompt, system = review_prompt(request, include_guidance=False), request.guidance_text
    else:
        prompt, system = _plan_prompt(request), "\n\n".join(
            part for part in (request.persona, request.role) if part)
    budget = min(_THINKING_BUDGETS.get(request.reasoning, 2048),
                 max(1024, request.max_output_tokens - 1024))
    body: dict[str, Any] = {
        "model": request.model, "max_tokens": request.max_output_tokens,
        "messages": [{"role": "user", "content": json.dumps(prompt, sort_keys=True)}],
        "thinking": {"type": "enabled", "budget_tokens": budget},
    }
    if system:
        body["system"] = system
    return _post(body, request.schema, key=key, endpoint=endpoint, timeout_seconds=timeout_seconds)


def _plan_prompt(request: ModelRequest) -> dict[str, Any]:
    from .request import plan_prompt
    return plan_prompt(request, include_persona=False)


def _post(body: Mapping[str, Any], schema: str, *, key: str, endpoint: str,
          timeout_seconds: int) -> ModelResult:
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    http_request = Request(endpoint, data=encoded, method="POST", headers={
        "content-type": "application/json", "x-api-key": key,
        "anthropic-version": "2023-06-01", "user-agent": "appsec-review/0.0.0",
    })
    raw = _read_response(http_request, timeout_seconds, 2 * 1024 * 1024)
    if len(raw) > 2 * 1024 * 1024:
        raise ModelOutputError("Anthropic API response exceeded the response bound")
    raw_text = raw.decode("utf-8", "replace").encode("utf-8")[:2 * 1024 * 1024].decode("utf-8", "ignore")
    try:
        envelope = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ModelOutputError("Anthropic API returned invalid JSON",
                               raw_response=raw_text) from None
    if not isinstance(envelope, Mapping):
        raise ModelOutputError("Anthropic API response is not an object")
    content = envelope.get("content")
    if (not isinstance(content, list) or
            any(not isinstance(item, Mapping) or
                item.get("type") == "text" and not isinstance(item.get("text"), str)
                for item in content)):
        raise ModelOutputError("Anthropic API returned invalid content blocks")
    text = "\n".join(item["text"] for item in content if item.get("type") == "text")
    try:
        proposal = parse_model_payload(text, schema)
    except ModelOutputError as exc:
        raise ModelOutputError(
            "Anthropic response was not a complete schema object",
            raw_response=raw_text,
            rejected_output=text.encode("utf-8")[:131072].decode("utf-8", "ignore"),
        ) from exc
    usage = envelope.get("usage", {}) if isinstance(envelope.get("usage"), Mapping) else {}
    if envelope.get("model") is not None and not isinstance(envelope["model"], str):
        raise ModelOutputError("Anthropic API returned an invalid model identity")
    result = ModelResult(proposal=proposal, input_tokens=usage.get("input_tokens"),
                       output_tokens=usage.get("output_tokens"),
                       cache_tokens=usage.get("cache_read_input_tokens"),
                       raw_response=raw_text,
                       served_model=envelope.get("model"), served_provider="anthropic-api",
                       usage_unavailable_reason=("invalid_provider_usage"
                           if "usage" in envelope and not isinstance(envelope["usage"], Mapping) else None))
    return Usage.from_result(result).normalize(result)


def _read_response(request: Request, timeout_seconds: int, limit: int) -> bytes:
    from appsec_review.runtime import execution_safety as safety
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0):
        raise ExecutionContractError("Anthropic timeout_seconds must be finite and positive")
    safety.check_running()
    deadline = time.monotonic() + timeout_seconds
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            read = getattr(response, "read1", response.read)
            streaming = hasattr(response, "read1")
            chunks = bytearray()
            while len(chunks) <= limit:
                safety.check_running()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ModelTimeout("Anthropic API call timed out")
                # urllib's HTTPResponse retains the socket under its buffered reader.
                # Refresh the read budget after headers and every chunk; never restart a POST.
                transport_socket = getattr(getattr(getattr(response, "fp", None), "raw", None),
                                           "_sock", None)
                if transport_socket is not None:
                    transport_socket.settimeout(remaining)
                chunk = read(min(65536, limit + 1 - len(chunks)) if streaming else limit + 1)
                if not chunk:
                    break
                chunks.extend(chunk)
                if not streaming:
                    break
            raw = bytes(chunks)
    except HTTPError as exc:
        exc.close()
        raise ProviderError(f"Anthropic API returned HTTP {exc.code}", code=f"http_{exc.code}",
                            retryable=exc.code in {408, 425, 429, 500, 502, 503, 504, 529}) from None
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise ModelTimeout("Anthropic API call timed out") from None
        transient = (isinstance(exc.reason, ConnectionError) or
                     isinstance(exc.reason, socket.gaierror) and exc.reason.errno == socket.EAI_AGAIN)
        if isinstance(exc.reason, ssl.SSLError):
            transient = False
        raise ProviderError("Anthropic API connection failed", code="network",
                            retryable=transient) from None
    except TimeoutError:
        raise ModelTimeout("Anthropic API call timed out") from None
    except ConnectionError:
        raise ProviderError("Anthropic API connection failed", code="network", retryable=True) from None
    except ssl.SSLError:
        raise ProviderError("Anthropic API TLS connection failed", code="tls") from None
    except HTTPException as exc:
        raise ProviderError("Anthropic API HTTP transport failed", code="http_protocol",
                            retryable=isinstance(exc, IncompleteRead)) from None
    safety.check_running()
    if time.monotonic() >= deadline:
        raise ModelTimeout("Anthropic API call timed out")
    return raw


MODELS_ENDPOINT = "https://api.anthropic.com/v1/models"


def _get(url: str, key: str, timeout_seconds: int) -> tuple[int, Mapping[str, Any]]:
    http_request = Request(url, method="GET", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "user-agent": "appsec-review/0.0.0"})
    try:
        raw = _read_response(http_request, timeout_seconds, 4 * 1024 * 1024)
    except ProviderError as exc:
        if exc.code == "http_404":
            return 404, {}
        raise
    if len(raw) > 4 * 1024 * 1024:
        raise ModelOutputError("Anthropic model catalog exceeds the response bound")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ModelOutputError("Anthropic model catalog returned invalid JSON") from None
    if not isinstance(value, Mapping):
        raise ModelOutputError("Anthropic API model response is not an object")
    return 200, value


def models(names: Sequence[str], *, timeout_seconds: int,
           endpoint: str = MODELS_ENDPOINT) -> dict[str, Any]:
    """List the account's models and confirm each named model, resolving aliases by lookup."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ProviderError("Anthropic API authentication is unavailable", code="authentication_missing")
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
