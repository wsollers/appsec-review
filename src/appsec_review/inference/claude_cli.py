from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

from .request import ModelRequest, ModelResult, ReviewModelRequest, review_user_text
from .errors import (
    ExecutionContractError, FailureCategory, ModelOutputError, ModelTimeout, ProviderError, failure_category,
)
from .usage import Usage, reported_cache_write, token_count


def _text_from_envelope(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("result", "output_text", "text", "content"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
            if isinstance(candidate, list):
                texts = [str(item.get("text")) for item in candidate
                         if isinstance(item, Mapping) and isinstance(item.get("text"), str)]
                if texts:
                    return "\n".join(texts)
    raise ModelOutputError("model envelope does not contain textual output")


_WORKER_TURN_SCHEMA = "appsec-review/worker-turn/1"
_NATIVE_RESOLUTION_SCHEMA = "appsec-review/native-dependency-resolution-proposal/1"
# The proposal's complete field set. On run 2026-11-14-0005 every one of the 79 failed native
# resolution replies was exactly this object without a `schema` field (T-5022); the authenticated
# request fixes the schema and apply_model_resolution still authorizes every value.
_NATIVE_RESOLUTION_FIELDS = frozenset({"candidate_id", "repository", "confidence", "evidence_refs", "rationale"})
_RESPONSE_BYTES = 2 * 1024 * 1024
_REJECTED_BYTES = 131072


def parse_model_payload(raw: str, schema: str) -> Mapping[str, Any]:
    """Accept a CLI envelope or prose/fence wrapper, but exactly one schema-bearing JSON object.

    A rejection carries a closed ``failure_class`` so the recording and the job's gap can say why.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ModelOutputError("model response is empty or exceeds the response bound",
                               failure_class="empty_reply")
    if len(raw.encode("utf-8")) > _RESPONSE_BYTES:
        raise ModelOutputError("model response is empty or exceeds the response bound")
    text = raw.strip()
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        envelope = text
    if isinstance(envelope, Mapping) and envelope.get("schema") == schema:
        return envelope
    try:
        text = _text_from_envelope(envelope).strip()
    except ModelOutputError:
        # Not a CLI envelope with text (a bare JSON object, for example): scan the original text, because
        # the repr of a parsed object is not JSON.
        text = raw.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.I | re.S)
    if fenced:
        text = fenced.group(1).strip()
    decoder = json.JSONDecoder()
    candidates: list[Mapping[str, Any]] = []
    objects = 0
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        objects += 1
        if isinstance(value, Mapping) and value.get("schema") == schema:
            candidates.append(value)
        elif (schema == _NATIVE_RESOLUTION_SCHEMA and isinstance(value, Mapping) and
              set(value) == _NATIVE_RESOLUTION_FIELDS):
            candidates.append({"schema": schema, **value})
        elif (schema == "appsec-review/target-analysis-proposal/2" and
              isinstance(value, Mapping) and "schema" not in value and
              set(value) == {"component_proposals", "build_recipes"}):
            # The expected schema is already fixed by the authenticated request.  Accept
            # only this exact, unambiguous omission; conflicting or extra fields remain
            # invalid and the ordinary proposal validators still authorize every value.
            candidates.append({"schema": schema, **value})
        elif (schema == _WORKER_TURN_SCHEMA and isinstance(value, Mapping) and "schema" not in value and
              value.get("action") in {"retrieve", "final"}):
            # Same rule for a review cell's turn: the authenticated request fixes the schema, the model often
            # leaves the field out of an otherwise valid turn, and the turn validators still check every other field.
            candidates.append({"schema": schema, **value})
    unique = {json.dumps(value, sort_keys=True, separators=(",", ":")): value for value in candidates}
    if len(unique) != 1:
        failure_class = ("several_objects" if len(unique) > 1 else "empty_reply" if not text
                         else "schema_mismatch" if objects else "no_json_object")
        raise ModelOutputError(f"expected exactly one {schema} JSON object, found {len(unique)}",
                               failure_class=failure_class)
    return next(iter(unique.values()))


def _envelope(raw: str) -> Mapping[str, Any] | None:
    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, RecursionError):
        return None
    return envelope if isinstance(envelope, Mapping) else None


def _usage(envelope: Mapping[str, Any] | None) -> dict[str, int | None]:
    usage = envelope.get("usage") if envelope is not None else None
    usage = usage if isinstance(usage, Mapping) else {}
    counts = {"input_tokens": token_count(usage.get("input_tokens")),
              "output_tokens": token_count(usage.get("output_tokens")),
              "cache_tokens": token_count(usage.get("cache_read_input_tokens"))}
    if (value := reported_cache_write(usage)) is not None:
        counts["cache_write_tokens"] = token_count(value)
    return counts


def _stop_reason(envelope: Mapping[str, Any] | None) -> str | None:
    value = envelope.get("stop_reason") if envelope is not None else None
    return value[:256] if isinstance(value, str) and value else None


def _refused(envelope: Mapping[str, Any] | None) -> bool:
    if envelope is None:
        return False
    subtype = envelope.get("subtype")
    return (envelope.get("is_error") is True or _stop_reason(envelope) == "refusal"
            or (isinstance(subtype, str) and subtype.startswith("error")))


def contract_failure(exc: ModelOutputError, raw: str, *, retained_bytes: int) -> ModelOutputError:
    """The failed path keeps what the success path keeps: bounded reply text, stop reason and usage.

    ``retained_bytes`` is derived from the request's typed output budget, the same derivation the
    execution engine applies to an accepted reply; the truncation is recorded, never silent.
    """
    encoded = raw.encode("utf-8")
    truncated = len(encoded) > retained_bytes
    retained = encoded[:retained_bytes].decode("utf-8", "ignore")
    envelope = _envelope(raw)
    try:
        rejected = _text_from_envelope(envelope if envelope is not None else raw)
    except ModelOutputError:
        rejected = raw
    stop_reason = _stop_reason(envelope)
    failure_class = ("truncated_output" if stop_reason == "max_tokens" else
                     "refusal" if _refused(envelope) else exc.failure_class)
    return ModelOutputError(str(exc), raw_response=retained,
                            rejected_output=rejected.encode("utf-8")[:_REJECTED_BYTES].decode("utf-8", "ignore"),
                            failure_class=failure_class, stop_reason=stop_reason, usage=_usage(envelope),
                            raw_response_truncated=truncated)


def retained_reply_bytes(max_output_tokens: int) -> int:
    """Bytes of a rejected reply a recording keeps: the typed output budget, eight bytes a token."""
    if type(max_output_tokens) is not int or max_output_tokens < 1:
        raise ExecutionContractError("max_output_tokens must be a positive integer")
    return min(_RESPONSE_BYTES, max_output_tokens * 8)


def send(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int, binary: str = "claude",
         auth_mode: str = "subscription") -> ModelResult:
    """Operator-authenticated Claude CLI transport; the model is granted no tools."""
    executable = shutil.which(binary)
    if executable is None:
        raise ProviderError("configured Claude CLI is unavailable", code="cli_unavailable")
    prompt = (review_user_text(request)
              if isinstance(request, ReviewModelRequest) else json.dumps(_plan_prompt(request), sort_keys=True))
    return _run(executable, prompt, request.schema, model=request.model, reasoning=request.reasoning,
                timeout_seconds=timeout_seconds, auth_mode=auth_mode,
                retained_bytes=retained_reply_bytes(request.max_output_tokens))


def _plan_prompt(request: ModelRequest) -> dict[str, Any]:
    from .request import plan_prompt
    return plan_prompt(request)


_GITHUB_TOKEN_NAMES = ("GH_TOKEN", "GITHUB_TOKEN", "COPILOT_GITHUB_TOKEN")


def _worker_environment(auth_mode: str) -> dict[str, str]:
    """The CLI's environment: never the application's GitHub credentials, nor API keys in subscription mode."""
    environment = {key: value for key, value in os.environ.items() if key not in _GITHUB_TOKEN_NAMES}
    if auth_mode == "subscription":
        environment.pop("ANTHROPIC_API_KEY", None)
        environment.pop("ANTHROPIC_AUTH_TOKEN", None)
    return environment


def _run(executable: str, prompt: str, schema: str, *, model: str, reasoning: str,
         timeout_seconds: int, auth_mode: str, retained_bytes: int = _RESPONSE_BYTES) -> ModelResult:
    environment = _worker_environment(auth_mode)
    argv = [executable, "-p", "--output-format", "json", "--no-session-persistence",
            "--safe-mode", "--tools", "", "--allowedTools", "",
            "--model", model, "--effort", reasoning]
    completed = _invoke(argv, input=prompt, environment=environment,
                        timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        raise ProviderError("Claude CLI exited with a nonzero status", code="cli_exit")
    try:
        proposal = parse_model_payload(completed.stdout, schema)
    except ModelOutputError as exc:
        raise contract_failure(exc, completed.stdout, retained_bytes=retained_bytes) from exc
    usage = {}
    served_model = None
    try:
        envelope = json.loads(completed.stdout)
        usage = envelope.get("usage", {}) if isinstance(envelope, Mapping) else {}
        if isinstance(envelope, Mapping):
            served_model = envelope.get("model")
            model_usage = envelope.get("modelUsage")
            if served_model is None and isinstance(model_usage, Mapping) and len(model_usage) == 1:
                served_model = next(iter(model_usage))
    except json.JSONDecodeError:
        pass
    invalid_usage = not isinstance(usage, Mapping)
    if invalid_usage:
        usage = {}
    if served_model is not None and not isinstance(served_model, str):
        raise ModelOutputError("Claude CLI returned an invalid model identity")
    result = ModelResult(
        proposal=proposal,
        input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"),
        cache_tokens=usage.get("cache_read_input_tokens"), cache_write_tokens=reported_cache_write(usage),
        raw_response=completed.stdout,
        served_model=served_model, served_provider="claude-cli",
        usage_unavailable_reason="invalid_provider_usage" if invalid_usage else None,
    )
    return Usage.from_result(result).normalize(result)


def _invoke(argv: list[str], *, input: str, environment: Mapping[str, str],
            timeout_seconds: int) -> subprocess.CompletedProcess:
    """Keep cancellation in the calling thread and reap the owned subprocess before returning."""
    from appsec_review.runtime import execution_safety as safety
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0):
        raise ExecutionContractError("Claude CLI timeout_seconds must be finite and positive")
    safety.check_running()
    options = dict(text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                   env=environment)
    try:
        if not safety.active():
            result = subprocess.run(argv, input=input, timeout=timeout_seconds, check=False, **options)
        else:
            deadline = time.monotonic() + timeout_seconds
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, start_new_session=True, **options)
            finished = False
            try:
                first = True
                while True:
                    safety.check_running()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ModelTimeout()
                    try:
                        stdout, stderr = process.communicate(input=input if first else None,
                                                              timeout=min(0.1, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        first = False
                result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
                finished = True
            finally:
                original = sys.exception()
                if not finished or process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired as error:
                        failure = ExecutionContractError("Claude CLI cleanup could not be confirmed")
                        from appsec_review.runtime.resources import quarantine_resources
                        try:
                            quarantine_resources("claude_teardown_unconfirmed")
                            safety.retain_failure("inference.cleanup", failure, provider="claude-cli")
                        except Exception as publication_error:
                            failure.add_note(
                                f"Claude CLI cleanup evidence/quarantine failed ({type(publication_error).__name__})")
                        if original is not None and failure_category(original) is FailureCategory.CANCELLED:
                            original.add_note(str(failure))
                            raise original from failure
                        raise failure from error
    except ModelTimeout:
        raise
    except subprocess.TimeoutExpired:
        raise ModelTimeout("Claude CLI call timed out") from None
    except TimeoutError:
        raise ModelTimeout("Claude CLI call timed out") from None
    except UnicodeError:
        raise ModelOutputError("Claude CLI returned invalid text") from None
    except OSError:
        raise ProviderError("Claude CLI could not be started or read", code="cli_io") from None
    safety.check_running()
    return result


def models(names: Sequence[str], *, timeout_seconds: int, binary: str = "claude",
           auth_mode: str = "subscription") -> dict[str, Any]:
    """Confirm each named model by one minimal call; the CLI offers no model listing."""
    executable = shutil.which(binary)
    if executable is None:
        raise ProviderError("configured Claude CLI is unavailable", code="cli_unavailable")
    environment = _worker_environment(auth_mode)
    result: dict[str, Any] = {}
    for name in names:
        argv = [executable, "-p", "--output-format", "json", "--no-session-persistence",
                "--safe-mode", "--tools", "", "--allowedTools", "", "--model", name,
                "--system-prompt", "Reply with the single word ok."]
        try:
            completed = _invoke(argv, input="ok", environment=environment, timeout_seconds=timeout_seconds)
        except ModelTimeout:
            result[name] = {"available": False, "detail": "the availability probe timed out"}
            continue
        try:
            envelope = json.loads(completed.stdout)
        except json.JSONDecodeError:
            envelope = None
        if not isinstance(envelope, Mapping):
            detail = completed.stderr.strip()[:512] or "the CLI returned no result envelope"
            result[name] = {"available": False, "detail": f"Claude CLI exited {completed.returncode}: {detail}"}
            continue
        served = sorted(str(key) for key in envelope.get("modelUsage", {}) or {})
        answered = (completed.returncode == 0 and envelope.get("is_error") is False and
                    any(key == name or key.startswith(name) for key in served))
        result[name] = ({"available": True, "detail": "answered an availability probe"} if answered else
                        {"available": False, "detail": "probe was not answered by this model: " + str(
                            envelope.get("result") or envelope.get("terminal_reason") or
                            envelope.get("subtype") or "unknown")[:256]})
    return {"method": "probe", "listed": None, "models": result}
