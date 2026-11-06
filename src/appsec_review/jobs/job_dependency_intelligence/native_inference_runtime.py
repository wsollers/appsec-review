"""Bounded, no-tools native SBOM proposals through the application's Infer boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, replace
import hashlib
import itertools
import json
import logging
from pathlib import Path
import subprocess
from typing import Any, Literal

from appsec_review.guidance.fragments import GuidanceError
from appsec_review.inference import Infer, ModelRequest, ModelResult
from appsec_review.inference.errors import (
    ExecutionLimit, FailureCategory, ModelOutputError, ProviderError, failure_category,
)
from appsec_review.inference.execution import Execution, RetryPolicy
from appsec_review.inference.usage import Usage, total_reported
from appsec_review.observability.events import EventLog
from appsec_review.runtime import execution_safety as safety
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import immutable_bytes, safe_path

from .native_inference_contracts import (
    CURATION_SCHEMA, METADATA_SCHEMA, PLAN_SCHEMA, NativeInferenceBounds, NativeInferenceError,
)


PERSONA_ID = "native_dependency_analyst"
ROLE_ID = "native_sbom_investigator"
RUNTIME_SKILL_ID = "native-sbom-investigation"
STAGES = {
    "curate": (CURATION_SCHEMA, "native_component_curation"),
    "plan": (PLAN_SCHEMA, "native_metadata_investigation"),
    "metadata": (METADATA_SCHEMA, "native_metadata_investigation"),
}
TRANSPORT_COUNTERS = (
    "model_calls", "model_failures", "input_tokens", "output_tokens", "cache_tokens", "unknown_usage_calls",
)
_LOG = logging.getLogger(__name__)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _clip(text: str, limit: int) -> str:
    return text.encode("utf-8", errors="backslashreplace")[:limit].decode("utf-8", errors="ignore")


def _json_bytes(value: Any, *, limit: int, field_bytes: int, kind: str) -> bytes:
    try:
        # canonical_json is also the on-disk encoding; reject non-JSON numbers before using it.
        json.dumps(value, allow_nan=False)
        payload = canonical_json(value)
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise NativeInferenceError(kind, f"value must be finite JSON: {type(exc).__name__}") from exc
    if len(payload) > limit:
        raise NativeInferenceError("bounds", f"JSON exceeds its {limit}-byte bound")
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if len(item.encode("utf-8")) > field_bytes:
                raise NativeInferenceError("bounds", "JSON string exceeds the field byte bound")
        elif isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise NativeInferenceError(kind, "JSON object keys must be strings")
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return payload


class NativeProposer:
    """Keep immutable guidance and every physical attempt, without retrieving target evidence."""

    def __init__(self, *, repository_root: Path, run_root: Path, model: Mapping[str, Any],
                 infer: Infer | None, bounds: NativeInferenceBounds, events: EventLog | None = None,
                 unit_id: str | None = None) -> None:
        self.repository_root = Path(repository_root)
        self.run_root = Path(run_root)
        self.model = dict(model)
        self.infer = infer
        self.bounds = bounds
        self.events = events
        self.unit_id = unit_id
        self.metrics = dict.fromkeys(TRANSPORT_COUNTERS, 0)
        self._usage: list[Usage] = []
        self.artifacts: list[dict[str, Any]] = []
        self.guidance_hashes: list[str] = []
        self._bundles: dict[str, dict[str, Any]] = {}
        self._scope = "unit-" + _digest(canonical_json({"unit_id": unit_id}))

    def _failure(self, error: NativeInferenceError, *, stage: str,
                 request_id: str | None = None) -> None:
        _LOG.warning("Native inference %s failed (%s): %s", stage, error.kind,
                     type(error.__cause__ or error).__name__)
        if self.events is not None:
            self.events.write(
                "NATIVE_INFERENCE_FAILED", unit_id=self.unit_id, stage=stage, request_id=request_id,
                kind=error.kind, error_type=type(error.__cause__ or error).__name__,
            )
        safety.retain_failure("dependency.native_inference", error.__cause__ or error,
                              unit_id=self.unit_id, stage=stage, request_id=request_id)
        safety.fail(str(error), action="dependency.native_inference")

    def _check_model(self) -> None:
        if self.model.get("enabled") is not True:
            raise NativeInferenceError("unavailable", "native SBOM inference is disabled")
        if self.infer is None:
            raise NativeInferenceError("unavailable", "native SBOM inference transport is unavailable")
        for key in ("provider", "model", "reasoning"):
            value = self.model.get(key)
            if (not isinstance(value, str) or not value.strip()
                    or len(value.encode("utf-8")) > self.bounds.field_bytes):
                raise NativeInferenceError("unavailable", f"central model setting {key} is invalid")
        for key in ("max_input_tokens", "max_output_tokens", "timeout_seconds", "retries"):
            value = self.model.get(key)
            if type(value) is not int or value < (0 if key == "retries" else 1):
                raise NativeInferenceError("unavailable", f"central model setting {key} is invalid")

    def _guidance(self, task: str, *, stage: str | None = None) -> tuple[str, str]:
        from appsec_review.guidance.compose import pin_bundle, render_prompt
        from appsec_review.guidance.workers import worker_bundle
        worker = {"curate": "native_curation", "plan": "native_plan", "metadata": "native_metadata"}.get(
            stage or ("curate" if task == "native_component_curation" else "plan"))
        if worker is None or task not in {record[1] for record in STAGES.values()}:
            raise GuidanceError("native SBOM task is not registered")
        if not self._bundles:
            self._bundles = {name: worker_bundle(self.repository_root, name)
                             for name in ("native_curation", "native_plan", "native_metadata")}
        bundle = self._bundles[worker]
        digest = pin_bundle(self.run_root, bundle)["bundle_sha256"]
        if digest not in self.guidance_hashes:
            self.guidance_hashes.append(digest)
        return render_prompt(bundle), digest

    def _request(self, stage: str, payload: Mapping[str, Any]) -> tuple[ModelRequest, str, str]:
        self._check_model()
        if stage not in STAGES:
            raise NativeInferenceError("invalid_output", "native inference stage is not supported")
        if not isinstance(payload, Mapping):
            raise NativeInferenceError("bounds", "native inference payload must be an object")
        raw = _json_bytes(dict(payload), limit=self.bounds.max_payload_bytes,
                          field_bytes=self.bounds.field_bytes, kind="bounds")
        value = json.loads(raw)
        for key in ("candidates", "input_records"):
            if isinstance(value.get(key), list) and len(value[key]) > self.bounds.batch_candidates:
                raise NativeInferenceError("bounds", "native candidate batch exceeds its bound")
        if type(value.get("input_records")) is int and value["input_records"] > self.bounds.batch_candidates:
            raise NativeInferenceError("bounds", "native candidate batch exceeds its bound")
        schema, task = STAGES[stage]
        guidance, guidance_hash = self._guidance(task, stage=stage)
        summary = {"stage": stage, "payload": value, "guidance_bundle_sha256": guidance_hash}
        if len(canonical_json(summary)) > self.bounds.max_payload_bytes:
            raise NativeInferenceError("bounds", "native request summary exceeds its byte bound")
        request = ModelRequest(
            schema=schema, persona=PERSONA_ID, role=ROLE_ID, guidance=guidance, summary=summary,
            allowed_scanners=(), allowed_build_systems=(), allowed_components=(), allowed_paths=(),
            allowed_build_units=(), provider=self.model["provider"], model=self.model["model"],
            reasoning=self.model["reasoning"], max_input_tokens=self.model["max_input_tokens"],
            max_output_tokens=self.model["max_output_tokens"],
        )
        request_id = _digest(canonical_json({"stage": stage, "request": asdict(request),
                                            "model": self.model, "guidance": guidance_hash}))
        return request, request_id, guidance_hash

    def _persist(self, directory: str, name: str, value: Any) -> dict[str, Any]:
        ref = immutable_bytes(self.run_root, f"{directory}/{name}.json", canonical_json(value))
        self.artifacts.append(ref)
        return ref

    def _attempt_directory(self, request_id: str) -> str:
        prefix = f"data/native-inference/{self._scope}/{request_id}"
        for number in itertools.count(1):
            relative = f"{prefix}/attempt-{number:06d}"
            try:
                safe_path(self.run_root, relative).mkdir(parents=True, exist_ok=False)
                return relative
            except FileExistsError:
                # Only a real pre-existing directory reserves an attempt ordinal.
                if not safe_path(self.run_root, relative).is_dir():
                    raise ValueError("native inference attempt path is not a directory") from None
        raise AssertionError("unreachable attempt ordinal")

    def _account_usage(self, usage: Usage) -> dict[str, int | None]:
        self._usage.append(usage)
        actual = usage.actual
        # The existing integer-only publication counters are known subtotals, not complete usage.
        for key, value in actual.items():
            if value is not None:
                self.metrics[key] += value
        self.metrics["unknown_usage_calls"] += int(any(value is None for value in actual.values()))
        return actual

    @property
    def usage_totals(self) -> dict[str, int | None]:
        return {key: total_reported([usage.actual[key] for usage in self._usage])
                for key in ("input_tokens", "output_tokens", "cache_tokens")}

    def _response(self, result: ModelResult) -> tuple[dict[str, Any], Mapping[str, Any]]:
        limit = min(self.bounds.max_payload_bytes, self.model["max_output_tokens"] * 4)
        proposal = _json_bytes(result.proposal, limit=limit, field_bytes=self.bounds.field_bytes,
                               kind="invalid_output")
        if not isinstance(result.proposal, Mapping):
            raise NativeInferenceError("invalid_output", "native model output must be an object")
        if result.raw_response is not None:
            if not isinstance(result.raw_response, str):
                raise NativeInferenceError("invalid_output", "raw model response must be text")
            if len(result.raw_response.encode("utf-8")) > limit:
                raise NativeInferenceError("bounds", "raw model response exceeds its byte bound")
        for value in (result.served_model, result.served_provider):
            if value is not None and (not isinstance(value, str)
                                      or len(value.encode("utf-8")) > self.bounds.field_bytes):
                raise NativeInferenceError("bounds", "served model identity exceeds its field bound")
        value = json.loads(proposal)
        return {"proposal": value, "raw_response": result.raw_response,
                "served_model": result.served_model, "served_provider": result.served_provider}, value

    def _rejected_response(self, result: ModelResult | None, error: NativeInferenceError,
                           usage: Mapping[str, int | None]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "schema": "appsec-review/native-inference-response/1", "rejected": True, "usage": dict(usage),
        }
        limit = min(self.bounds.max_payload_bytes, self.model["max_output_tokens"] * 4)
        if isinstance(result, ModelResult):
            try:
                json.dumps(result.proposal, allow_nan=False)
                raw_proposal = canonical_json(result.proposal)
            except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
                record["proposal_encoding_error"] = type(exc).__name__
            else:
                record.update(proposal_sha256=_digest(raw_proposal), proposal_size_bytes=len(raw_proposal),
                              proposal=json.loads(raw_proposal) if len(raw_proposal) <= limit else None,
                              proposal_omitted=len(raw_proposal) > limit)
            record.update(served_model=_clip(str(result.served_model), self.bounds.field_bytes)
                          if result.served_model is not None else None,
                          served_provider=_clip(str(result.served_provider), self.bounds.field_bytes)
                          if result.served_provider is not None else None)
        raw = getattr(result, "raw_response", None) if result is not None else getattr(
            error.__cause__, "raw_response", None)
        if isinstance(raw, str):
            encoded = raw.encode("utf-8", errors="backslashreplace")
            excerpt_limit = min(self.bounds.field_bytes, limit)
            record.update(raw_response_excerpt=_clip(raw, excerpt_limit),
                          raw_response_sha256=_digest(encoded), raw_response_size_bytes=len(encoded),
                          raw_response_omitted=len(encoded) > excerpt_limit)
        return record

    def __call__(self, stage: Literal["curate", "plan", "metadata"],
                 payload: Mapping[str, Any]) -> Mapping[str, Any]:
        request_id = None
        try:
            request, request_id, guidance_hash = self._request(stage, payload)
        except (GuidanceError, OSError, UnicodeError) as exc:
            error = NativeInferenceError("unavailable", f"native SBOM guidance unavailable: {exc}")
            self._failure(error, stage=stage)
            raise error from exc
        except NativeInferenceError as exc:
            self._failure(exc, stage=stage)
            raise
        policy = RetryPolicy(self.model["retries"] + 1, True, True, True)
        engine = Execution(timeout_seconds=self.model["timeout_seconds"], max_calls=policy.attempts,
                           guidance_sha256=guidance_hash)
        retry_reason = None
        for attempt in range(1, policy.attempts + 1):
            try:
                safety.check_running()
                if self.metrics["model_calls"] >= self.bounds.max_calls:
                    raise NativeInferenceError("bounds", "native inference model call bound reached")
                if len(canonical_json(asdict(request))) > request.max_input_tokens * 4:
                    raise NativeInferenceError("bounds", "native request exceeds its token-derived byte bound")
            except NativeInferenceError as exc:
                self._failure(exc, stage=stage, request_id=request_id)
                raise
            directory = self._attempt_directory(request_id)
            request_ref = self._persist(directory, "request", {
                "schema": "appsec-review/native-inference-request/1", "request_id": request_id,
                "stage": stage, "guidance_bundle_sha256": guidance_hash,
                "timeout_seconds": self.model["timeout_seconds"], "request": asdict(request),
            })
            result = None
            error = None
            retry_error: BaseException | FailureCategory = FailureCategory.SCHEMA
            receipt_count = len(engine.receipts)
            def dispatch(request, *, timeout_seconds):
                nonlocal result
                assert self.infer is not None
                result = self.infer(request, timeout_seconds=timeout_seconds)
                return result
            try:
                result = engine.call(dispatch, request, timeout_seconds=self.model["timeout_seconds"],
                                     retry_count=attempt - 1, retry_reason=retry_reason)
            except (ModelOutputError, TimeoutError, subprocess.TimeoutExpired, ProviderError, ExecutionLimit) as exc:
                kind = ("bounds" if isinstance(exc, ExecutionLimit) or
                        isinstance(exc, ModelOutputError) and "byte bound" in str(exc) else
                        "invalid_output" if isinstance(exc, ModelOutputError) else "model_failure")
                error = NativeInferenceError(kind, f"{type(exc).__name__}: {exc}")
                error.__cause__ = exc
                retry_error = exc
            finally:
                if len(engine.receipts) > receipt_count:
                    self.metrics["model_calls"] += int(engine.receipts[-1].dispatched)
                    usage = self._account_usage(engine.receipts[-1].usage)
            response_ref = None
            if error is None:
                try:
                    response, proposal = self._response(result)
                    response_ref = self._persist(directory, "response", {
                        "schema": "appsec-review/native-inference-response/1", **response, "usage": usage,
                    })
                    if proposal.get("schema") != request.schema:
                        raise NativeInferenceError("invalid_output", "native model output schema does not match stage")
                except UnicodeError as exc:
                    error = NativeInferenceError("invalid_output", "model response is not valid UTF-8")
                    error.__cause__ = exc
                except NativeInferenceError as exc:
                    error = exc
            if error is not None and response_ref is None:
                response_ref = self._persist(directory, "response", self._rejected_response(result, error, usage))
            receipt = {
                "schema": "appsec-review/native-inference-attempt/1", "request_id": request_id,
                "stage": stage, "retry": attempt - 1, "request": request_ref, "response": response_ref,
                "guidance_bundle_sha256": guidance_hash, "usage": usage,
                "usage_source": engine.receipts[-1].usage.source,
                "usage_unavailable_reason": engine.receipts[-1].usage.unavailable_reason,
                "usage_totals": self.usage_totals,
                "known_usage_subtotals": {key: self.metrics[key] for key in self.usage_totals},
                "status": "FAILED" if error is not None else "SUCCEEDED",
            }
            if error is not None:
                message = str(error.__cause__ or error)
                receipt["error"] = {
                    "kind": error.kind, "type": type(error.__cause__ or error).__name__,
                    "message": _clip(message, self.bounds.field_bytes),
                    "message_sha256": _digest(message.encode("utf-8", errors="backslashreplace")),
                    "message_size_bytes": len(message.encode("utf-8", errors="backslashreplace")),
                    "message_truncated": len(message.encode("utf-8", errors="backslashreplace"))
                    > self.bounds.field_bytes,
                }
            self._persist(directory, "attempt", receipt)
            if error is None:
                if self.events is not None:
                    self.events.write("NATIVE_INFERENCE_COMPLETED", unit_id=self.unit_id, stage=stage,
                                      request_id=request_id, guidance_bundle_sha256=guidance_hash,
                                      served_model=engine.receipts[-1].served_model,
                                      served_provider=engine.receipts[-1].served_provider,
                                      **usage)
                return proposal
            self.metrics["model_failures"] += 1
            self._failure(error, stage=stage, request_id=request_id)
            try:
                retry = engine.retry(attempt, retry_error, policy)
            except ExecutionLimit:
                retry = False
            if not retry:
                raise error
            retry_reason = (retry_error.value if isinstance(retry_error, FailureCategory)
                            else failure_category(retry_error).value)
            request = replace(request, repair_errors=(_clip(str(error), self.bounds.field_bytes),),
                              prior_response=None)
        raise AssertionError("unreachable native inference retry state")


def make_proposer(*, repository_root: Path, run_root: Path, model: Mapping[str, Any],
                  infer: Infer | None, bounds: NativeInferenceBounds, events: EventLog | None = None,
                  unit_id: str | None = None) -> NativeProposer:
    return NativeProposer(repository_root=repository_root, run_root=run_root, model=model, infer=infer,
                          bounds=bounds, events=events, unit_id=unit_id)


__all__ = ["NativeProposer", "make_proposer"]
