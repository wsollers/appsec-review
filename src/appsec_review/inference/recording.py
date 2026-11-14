"""Immutable, run-owned model recordings; replay never calls a provider.

V2 uses closed error categories, strict bounded JSON and a recording-root identity. Ordinals
are reserved at admission, not completion, and reset with each unit invocation. Re-entering a
recording unit never silently appends to stale evidence. V1 successes remain readable; V1
errors cannot establish exception semantics and are explicitly rejected.

APPSEC_REVIEW_MODEL_RECORDING=record writes <run>/data/inference-recordings/<job>/<key>.<ordinal>.json.
Replay reads APPSEC_REVIEW_MODEL_REPLAY_DIR; copy its recording-root.json with the job directories.
The root identity cannot change mid-unit. Documents are at most 16 MiB, with finite JSON of depth
64 and at most 200,000 values. Error messages are at most 4 KiB, raw output 2 MiB and rejected
output 128 KiB. Explicit causes (not suppressed implicit contexts) have at most four levels;
each error has at most eight 1-KiB notes. Unsupported/oversized evidence is rejected, not guessed
or silently truncated. Only closed application error types are reconstructed.

Replay keeps historical usage, but marks it as replay (not new billable usage). Failed replay
requests and diagnostic-write failures belong to the replaying run, not the immutable source.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import threading
from typing import Any
from uuid import uuid4

from .errors import (
    ExecutionContractError, ExecutionLimit, FailureCategory, ModelCancelled, ModelOutputError,
    ModelTimeout, ProviderError, failure_category,
)
from .request import Infer, ModelRequest, ModelResult, ReviewModelRequest
from .usage import Usage, token_count

MODE_ENVIRONMENT = "APPSEC_REVIEW_MODEL_RECORDING"
REPLAY_ENVIRONMENT = "APPSEC_REVIEW_MODEL_REPLAY_DIR"
RECORDINGS = Path("data") / "inference-recordings"
SCHEMA = "appsec-review/model-recording/2"
_LEGACY_SCHEMA = "appsec-review/model-recording/1"
_ROOT_SCHEMA = "appsec-review/model-recording-root/2"
_ROOT_FILE = "recording-root.json"
_DOCUMENT_BYTES = 16 * 1024 * 1024
_RESPONSE_BYTES = 2 * 1024 * 1024
_REJECTED_BYTES = 131072
_MESSAGE_BYTES = 4096
_MAX_SEQUENCE = 10_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")


class ModelReplayMiss(ExecutionContractError):
    """A replay has no matching call; diagnostic failure never hides the miss."""

    def __init__(self, job_id: str, key: str, sequence: int, request: Mapping[str, Any]):
        super().__init__(f"no recorded model response for {job_id} request {key} (call {sequence}); "
                         "the replaying driver built a request the recording driver did not")
        self.job_id, self.key, self.sequence, self.request = job_id, key, sequence, request
        self.diagnostic_error: str | None = None


@dataclass
class _Scope:
    run_root: Path
    job_id: str
    literals: tuple[tuple[str, str], ...]
    counts: Counter = field(default_factory=Counter)
    replay_root: Path | None = None
    origins: dict[Path, str | None] = field(default_factory=dict)
    seeded: set[tuple[str, Path, str]] = field(default_factory=set)


_scope: _Scope | None = None
_lock = threading.Lock()


@contextmanager
def unit_scope(*, run_root: Path, job_id: str, repository_root: Path | None,
               target_root: Path | None) -> Iterator[None]:
    """One process owns one unit; its worker threads share admission ordinals."""
    global _scope
    if not isinstance(job_id, str) or not _IDENTIFIER.fullmatch(job_id):
        raise ExecutionContractError("invalid model recording job identity")
    run_root = Path(run_root).resolve()
    literals = [(str(run_root), "<run>")]
    literals += [(str(Path(root).resolve()), placeholder) for root, placeholder in
                 ((target_root, "<target>"), (repository_root, "<repo>")) if root is not None]
    previous = _scope
    _scope = _Scope(run_root, job_id, tuple(sorted(literals, key=lambda item: -len(item[0]))))
    try:
        yield
    finally:
        _scope = previous


def _masked(value: Any, literals: tuple[tuple[str, str], ...]) -> Any:
    if isinstance(value, Mapping):
        return {_masked(key, literals): _masked(child, literals) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_masked(child, literals) for child in value]
    if isinstance(value, str):
        for source, placeholder in literals:
            value = value.replace(source, placeholder)
    return value


def _text(value: Any, limit: int, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not str or len(value.encode("utf-8")) > limit:
        raise ExecutionContractError("model recording has invalid or oversized text")


def _json_tree(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > 200_000 or depth > 64:
            raise ExecutionContractError("model recording exceeds JSON structure bounds")
        if type(item) is dict:
            for key, child in item.items():
                _text(key, _RESPONSE_BYTES)
                pending.append((child, depth + 1))
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            _text(item, _RESPONSE_BYTES)
        elif item is None or type(item) is bool:
            pass
        elif type(item) is int:
            if not -(2 ** 63) <= item < 2 ** 63:
                raise ExecutionContractError("model recording integer exceeds its bound")
        elif type(item) is float and math.isfinite(item):
            pass
        else:
            raise ExecutionContractError("model recording requires finite JSON values")


def _encoded(value: Any) -> bytes:
    _json_tree(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    if len(raw) + 1 > _DOCUMENT_BYTES:
        raise ExecutionContractError("model recording exceeds its document bound")
    return raw


def request_key(request: ModelRequest | ReviewModelRequest,
                literals: tuple[tuple[str, str], ...] = ()) -> tuple[str, dict[str, Any]]:
    if type(request) not in (ModelRequest, ReviewModelRequest):
        raise ExecutionContractError("unsupported model recording request")
    masked = {"type": type(request).__name__, **_masked(asdict(request), literals)}
    canonical = _encoded(masked)
    return hashlib.sha256(canonical).hexdigest(), masked


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionContractError("model recording contains duplicate JSON keys")
        result[key] = value
    return result


def _read(path: Path) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _DOCUMENT_BYTES:
                raise ExecutionContractError("model recording is not a bounded regular file")
            raw = handle.read(_DOCUMENT_BYTES + 1)
        if len(raw) > _DOCUMENT_BYTES:
            raise ExecutionContractError("model recording exceeds its document bound")
        document = json.loads(raw, object_pairs_hook=_object)
        _json_tree(document)
        if type(document) is not dict:
            raise ExecutionContractError("model recording must be a JSON object")
        return document
    except FileNotFoundError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        raise ExecutionContractError("model recording is unreadable or malformed") from error


def _directory(root: Path, job_id: str) -> Path:
    path = root / job_id
    if path.is_symlink() or root.is_symlink():
        raise ExecutionContractError("model recording directory cannot be a symlink")
    return path


def _run_recordings(scope: _Scope) -> Path:
    root = scope.run_root / RECORDINGS
    if root.parent.is_symlink() or root.is_symlink():
        raise ExecutionContractError("model recording root escapes run-owned directories")
    return root


def _publish(path: Path, document: Mapping[str, Any]) -> None:
    """Publish complete bytes with a no-replace link; never expose partial JSON."""
    raw = _encoded(document) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.{uuid4().hex}.pending")
    created = False
    try:
        with staging.open("xb") as handle:
            created = True
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(staging, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise ExecutionContractError("stale or competing model recording already exists") from error
    except OSError as error:
        raise ExecutionContractError("model recording publication failed") from error
    finally:
        if created:
            staging.unlink(missing_ok=True)


def _origin(root: Path, *, create: bool) -> str | None:
    path = root / _ROOT_FILE
    try:
        document = _read(path)
    except FileNotFoundError:
        if not create:
            return None
        document = {"schema": _ROOT_SCHEMA, "recording_id": uuid4().hex}
        try:
            _publish(path, document)
        except ExecutionContractError as error:
            # A concurrent unit may have won root publication; validate its complete identity.
            if not isinstance(error.__cause__, FileExistsError):
                raise
            document = _read(path)
    if (set(document) != {"schema", "recording_id"} or document["schema"] != _ROOT_SCHEMA
            or type(document["recording_id"]) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", document["recording_id"])):
        raise ExecutionContractError("invalid model recording root identity")
    return document["recording_id"]


def _admit(scope: _Scope, mode: str, key: str) -> tuple[Path, int, str | None]:
    with _lock:
        if mode == "record":
            root = _run_recordings(scope)
        else:
            source = os.environ.get(REPLAY_ENVIRONMENT)
            if not source:
                raise ExecutionContractError(f"{MODE_ENVIRONMENT}=replay requires {REPLAY_ENVIRONMENT}")
            root = Path(source).resolve()
            if scope.replay_root is not None and scope.replay_root != root:
                raise ExecutionContractError("model replay source changed during a unit invocation")
            scope.replay_root = root
        origin = _origin(root, create=mode == "record")
        if root in scope.origins and scope.origins[root] != origin:
            raise ExecutionContractError("model recording root identity changed during invocation")
        scope.origins[root] = origin
        if mode == "record" and (mode, root, key) not in scope.seeded:
            # An earlier attempt of this job in the same run may have recorded the same request
            # (a repair re-runs the job under the same run root). This invocation appends after
            # those recordings; a path that still exists afterwards is a competing writer.
            directory = _directory(root, scope.job_id)
            existing = sorted(directory.glob(f"{key}.*.json")) if directory.is_dir() else []
            scope.counts[(mode, root, key)] = max(scope.counts[(mode, root, key)], len(existing))
            scope.seeded.add((mode, root, key))
        sequence = scope.counts[(mode, root, key)]
        if sequence >= _MAX_SEQUENCE:
            raise ExecutionContractError("model recording sequence space exhausted")
        path = _directory(root, scope.job_id) / f"{key}.{sequence:04d}.json"
        if mode == "record" and os.path.lexists(path):
            raise ExecutionContractError("stale model recording exists at dispatch admission")
        scope.counts[(mode, root, key)] += 1
        return path, sequence, origin


def _error_envelope(error: BaseException, *, depth: int = 0) -> dict[str, Any]:
    if depth > 3:
        raise ExecutionContractError("model recording error cause chain exceeds its bound")
    category = failure_category(error)
    message = ("model transport timed out" if isinstance(error, subprocess.TimeoutExpired)
               else str(error))
    value: dict[str, Any] = {"category": category.value, "message": message}
    if category is FailureCategory.TIMEOUT:
        value["code"] = error.code if isinstance(error, ModelTimeout) else "provider_timeout"
    elif category is FailureCategory.CANCELLED:
        value["code"] = "model_cancelled"
    elif category is FailureCategory.PROVIDER:
        value.update(code=error.code, retryable=error.retryable)
    elif category is FailureCategory.SCHEMA:
        value.update(raw_response=error.raw_response, rejected_output=error.rejected_output)
    elif category is FailureCategory.BUDGET:
        value["code"] = error.code
    else:
        value.update(code="application_contract_failure", exception_type=type(error).__name__)
    value["notes"] = getattr(error, "__notes__", [])
    value["cause"] = (_error_envelope(error.__cause__, depth=depth + 1)
                      if error.__cause__ is not None else None)
    _recorded_error(value)  # Validate before publishing any evidence.
    return value


def _recorded_error(error: Any, *, depth: int = 0) -> BaseException:
    if (depth > 3 or type(error) is not dict or not {"notes", "cause"} <= set(error)
            or type(error["notes"]) is not list or len(error["notes"]) > 8):
        raise ExecutionContractError("invalid or oversized model recording error evidence")
    result = _primary_error({key: value for key, value in error.items() if key not in {"notes", "cause"}})
    for note in error["notes"]:
        _text(note, 1024)
        result.add_note(note)
    if error["cause"] is not None:
        result.__cause__ = _recorded_error(error["cause"], depth=depth + 1)
    return result


def _primary_error(error: Any) -> BaseException:
    if type(error) is not dict:
        raise ExecutionContractError("invalid model recording error envelope")
    category = error.get("category")
    fields = {
        "timeout": {"code"}, "cancelled": {"code"}, "provider": {"code", "retryable"},
        "schema": {"raw_response", "rejected_output"}, "budget": {"code"},
        "contract": {"code", "exception_type"},
    }
    if type(category) is not str or category not in fields or set(error) != {
            "category", "message", *fields[category]}:
        raise ExecutionContractError("unsupported model recording error semantics")
    _text(error["message"], _MESSAGE_BYTES)
    message = error["message"]
    if "code" in error:
        if type(error["code"]) is not str or not _CODE.fullmatch(error["code"]):
            raise ExecutionContractError("invalid model recording error code")
    if category == "timeout":
        return ModelTimeout(message, code=error["code"])
    if category == "cancelled":
        if error["code"] != "model_cancelled":
            raise ExecutionContractError("unsupported recorded cancellation")
        return ModelCancelled(message)
    if category == "provider":
        if type(error["retryable"]) is not bool:
            raise ExecutionContractError("invalid recorded provider retryability")
        return ProviderError(message, retryable=error["retryable"], code=error["code"])
    if category == "schema":
        _text(error["raw_response"], _RESPONSE_BYTES, optional=True)
        _text(error["rejected_output"], _REJECTED_BYTES, optional=True)
        return ModelOutputError(message, raw_response=error["raw_response"],
                                rejected_output=error["rejected_output"])
    if category == "budget":
        if message != error["code"]:
            raise ExecutionContractError("inconsistent recorded execution limit")
        return ExecutionLimit(error["code"])
    _text(error["exception_type"], 128)
    if error["code"] != "application_contract_failure":
        raise ExecutionContractError("unsupported recorded contract error")
    return ExecutionContractError(f"recorded {error['exception_type']}: {message}")


def _result(value: Any, *, legacy: bool = False) -> ModelResult:
    required = {"proposal", "input_tokens", "output_tokens", "cache_tokens", "raw_response",
                "served_model", "served_provider"}
    metadata = {"usage_source", "usage_unavailable_reason"}
    if type(value) is not dict or not required <= set(value) or set(value) - required - metadata:
        raise ExecutionContractError("invalid model recording result fields")
    if not legacy and set(value) != required | metadata:
        raise ExecutionContractError("incomplete model recording result")
    if type(value["proposal"]) is not dict:
        raise ExecutionContractError("model recording proposal must be an object")
    if not legacy:
        for name in ("input_tokens", "output_tokens", "cache_tokens"):
            if value[name] is not None and token_count(value[name]) is None:
                raise ExecutionContractError("invalid recorded usage")
    _text(value["raw_response"], _RESPONSE_BYTES, optional=True)
    for name in ("served_model", "served_provider"):
        _text(value[name], 256, optional=True)
    _text(value.get("usage_unavailable_reason"), 256, optional=True)
    if value.get("usage_source", "provider") not in ("provider", "replay"):
        raise ExecutionContractError("invalid recorded usage source")
    result = ModelResult(**value)
    return Usage.from_result(result).normalize(result)


def _record(scope: _Scope, path: Path, key: str, sequence: int, origin: str | None,
            masked: Mapping[str, Any], *, result: ModelResult | None = None,
            error: BaseException | None = None) -> None:
    document = {"schema": SCHEMA, "job_id": scope.job_id, "key": key, "sequence": sequence,
                "origin": origin, "request": masked}
    if error is not None:
        document["error"] = _error_envelope(error)
    else:
        result = Usage.from_result(result).normalize(result)
        document["result"] = asdict(result)
        _result(document["result"])
    _publish(path, document)


def _keep_miss(scope: _Scope, missed: ModelReplayMiss) -> None:
    try:
        directory = _directory(_run_recordings(scope), scope.job_id) / "misses"
        if directory.is_symlink():
            raise ExecutionContractError("replay miss directory is not run-owned")
        path = directory / f"{missed.key}.{missed.sequence:04d}.{uuid4().hex}.json"
        _publish(path, {"schema": SCHEMA, "job_id": scope.job_id, "key": missed.key,
                        "sequence": missed.sequence, "request": missed.request,
                        "diagnostic": "replay_miss"})
    except (OSError, ExecutionContractError) as error:
        missed.diagnostic_error = "replay miss diagnostic publication failed"
        missed.add_note(missed.diagnostic_error)
        from appsec_review.runtime import execution_safety as safety
        try:
            safety.retain_failure("inference.recording", missed, diagnostic_error=type(error).__name__)
        except Exception:
            missed.add_note("replay miss failure-evidence publication also failed")


def _replay(scope: _Scope, path: Path, key: str, sequence: int, origin: str | None,
            masked: Mapping[str, Any]) -> ModelResult:
    try:
        document = _read(path)
    except FileNotFoundError:
        missed = ModelReplayMiss(scope.job_id, key, sequence, masked)
        _keep_miss(scope, missed)
        raise missed from None
    legacy = document.get("schema") == _LEGACY_SCHEMA
    if document.get("schema") not in (SCHEMA, _LEGACY_SCHEMA):
        raise ExecutionContractError("unsupported model recording version")
    if (document.get("job_id") != scope.job_id or document.get("key") != key
            or type(document.get("sequence")) is not int or document["sequence"] != sequence
            or _encoded(document.get("request")) != _encoded(masked)):
        raise ExecutionContractError("model recording does not match job/key/sequence/request")
    fields = {"schema", "job_id", "key", "sequence", "request"}
    if legacy:
        if "error" in document:
            raise ExecutionContractError("v1 recorded errors have unsupported exception semantics")
        if set(document) != fields | {"result"}:
            raise ExecutionContractError("invalid legacy model recording")
    else:
        if origin is None or document.get("origin") != origin:
            raise ExecutionContractError("model recording does not belong to its source root")
        if ("result" in document) == ("error" in document):
            raise ExecutionContractError("model recording requires exactly one result or error")
        outcome = "result" if "result" in document else "error"
        if set(document) != fields | {"origin", outcome}:
            raise ExecutionContractError("invalid model recording envelope fields")
        if outcome == "error":
            raise _recorded_error(document["error"])
    result = _result(document["result"], legacy=legacy)
    from dataclasses import replace
    return replace(result, usage_source="replay", usage_unavailable_reason="recorded_replay")


def recorded(infer: Infer) -> Infer:
    def wrapper(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        mode = os.environ.get(MODE_ENVIRONMENT, "")
        if not mode:
            return infer(request, timeout_seconds=timeout_seconds)
        if mode not in {"record", "replay"}:
            raise ValueError(f"{MODE_ENVIRONMENT} must be record or replay, not {mode!r}")
        scope = _scope
        if scope is None:
            raise ExecutionContractError("a model call outside a job unit cannot be recorded or replayed")
        key, masked = request_key(request, scope.literals)
        path, sequence, origin = _admit(scope, mode, key)
        if mode == "replay":
            return _replay(scope, path, key, sequence, origin, masked)
        try:
            result = infer(request, timeout_seconds=timeout_seconds)
            if not isinstance(result, ModelResult):
                raise ExecutionContractError("Infer must return ModelResult")
            result = Usage.from_result(result).normalize(result)
        except BaseException as error:
            try:
                _record(scope, path, key, sequence, origin, masked, error=error)
            except Exception as publication_error:
                error.add_note("model error recording could not be published")
                raise error from publication_error
            raise
        _record(scope, path, key, sequence, origin, masked, result=result)
        return result

    return wrapper
