from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any, Mapping

from .request import ModelRequest, ModelResult


class ModelOutputError(ValueError):
    def __init__(self, message: str, *, raw_response: str | None = None,
                 rejected_output: str | None = None) -> None:
        super().__init__(message)
        self.raw_response = raw_response
        self.rejected_output = rejected_output


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


def parse_model_payload(raw: str, schema: str) -> Mapping[str, Any]:
    """Accept a CLI envelope or prose/fence wrapper, but exactly one schema-bearing JSON object."""
    if not isinstance(raw, str) or not raw.strip() or len(raw.encode("utf-8")) > 2 * 1024 * 1024:
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
        text = str(envelope).strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.I | re.S)
    if fenced:
        text = fenced.group(1).strip()
    decoder = json.JSONDecoder()
    candidates: list[Mapping[str, Any]] = []
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, Mapping) and value.get("schema") == schema:
            candidates.append(value)
        elif (schema == "appsec-review/target-analysis-proposal/2" and
              isinstance(value, Mapping) and "schema" not in value and
              set(value) == {"component_proposals", "build_recipes"}):
            # The expected schema is already fixed by the authenticated request.  Accept
            # only this exact, unambiguous omission; conflicting or extra fields remain
            # invalid and the ordinary proposal validators still authorize every value.
            candidates.append({"schema": schema, **value})
    unique = {json.dumps(value, sort_keys=True, separators=(",", ":")): value for value in candidates}
    if len(unique) != 1:
        raise ModelOutputError(f"expected exactly one {schema} JSON object, found {len(unique)}")
    return next(iter(unique.values()))


def send(request: ModelRequest, *, timeout_seconds: int, binary: str = "claude",
         auth_mode: str = "subscription") -> ModelResult:
    """Operator-authenticated Claude CLI transport; the model is granted no tools."""
    executable = shutil.which(binary)
    if executable is None:
        raise FileNotFoundError(f"configured Claude CLI is unavailable: {binary}")
    prompt = {
        "persona": request.persona,
        "role": request.role,
        "task": request.guidance,
        "response_schema": request.schema,
        "catalog_summary": request.summary,
        "allowlists": {
            "scanners": request.allowed_scanners,
            "build_systems": request.allowed_build_systems,
            "components": request.allowed_components,
            "paths": request.allowed_paths,
            "build_units": request.allowed_build_units,
        },
        "limits": {"max_input_tokens": request.max_input_tokens,
                   "max_output_tokens": request.max_output_tokens},
    }
    if request.repair_errors:
        prompt["repair"] = {"validation_errors": request.repair_errors,
                            "rejected_response": request.prior_response,
                            "instruction": ("Return only one corrected JSON object. Its top-level "
                                            f"schema must be exactly {request.schema}. Do not reinvestigate.")}
    environment = dict(os.environ)
    if auth_mode == "subscription":
        environment.pop("ANTHROPIC_API_KEY", None)
        environment.pop("ANTHROPIC_AUTH_TOKEN", None)
    argv = [executable, "-p", "--output-format", "json", "--no-session-persistence",
            "--permission-mode", "bypassPermissions", "--model", request.model,
            "--effort", request.reasoning, "--allowedTools", ""]
    completed = subprocess.run(
        argv, input=json.dumps(prompt, sort_keys=True), text=True, encoding="utf-8",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds,
        check=False, env=environment,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip()[:4096]
        raise RuntimeError(f"Claude CLI exited {completed.returncode}: {error}")
    try:
        proposal = parse_model_payload(completed.stdout, request.schema)
    except ModelOutputError as exc:
        raw = completed.stdout[:2 * 1024 * 1024]
        try:
            rejected = _text_from_envelope(json.loads(raw))
        except (json.JSONDecodeError, ModelOutputError):
            rejected = raw
        raise ModelOutputError(str(exc), raw_response=raw,
                               rejected_output=rejected[:131072]) from exc
    usage = {}
    try:
        envelope = json.loads(completed.stdout)
        usage = envelope.get("usage", {}) if isinstance(envelope, Mapping) else {}
    except json.JSONDecodeError:
        pass
    return ModelResult(
        proposal=proposal,
        input_tokens=usage.get("input_tokens"), output_tokens=usage.get("output_tokens"),
        cache_tokens=usage.get("cache_read_input_tokens"), raw_response=completed.stdout,
    )
