"""Record model responses under one driver and replay them under another.

The local and Dagster parity walk (docs/processes/local-dagster-parity.md, section 6) compares two
drivers of the same job. Model output is not deterministic, so the Dagster run records every
response and the local run replays them: a difference then always means the drivers built
different requests or handled the answers differently.

The mode comes from the process environment, never from the configuration, so both runs keep the
same resolved configuration:

- ``APPSEC_REVIEW_MODEL_RECORDING=record`` writes each request and result to
  ``<run>/data/inference-recordings/<job>/<key>.<sequence>.json``;
- ``APPSEC_REVIEW_MODEL_RECORDING=replay`` answers from ``$APPSEC_REVIEW_MODEL_REPLAY_DIR/<job>/``
  and raises :class:`ModelReplayMiss` for a request that was never recorded.

A key is the SHA-256 of the canonical request with the run, target and repository roots replaced
by placeholders, so the container and host spellings of one request share a key. Repeated
identical requests are told apart by their sequence number, in call order.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any

from .request import Infer, ModelRequest, ModelResult, ReviewModelRequest

MODE_ENVIRONMENT = "APPSEC_REVIEW_MODEL_RECORDING"
REPLAY_ENVIRONMENT = "APPSEC_REVIEW_MODEL_REPLAY_DIR"
RECORDINGS = Path("data") / "inference-recordings"
SCHEMA = "appsec-review/model-recording/1"


class ModelReplayMiss(RuntimeError):
    """The replaying driver made a request the recording driver never made."""

    def __init__(self, job_id: str, key: str, sequence: int, request: Mapping[str, Any]):
        super().__init__(f"no recorded model response for {job_id} request {key} (call {sequence}); "
                         f"the replaying driver built a request the recording driver did not")
        self.job_id, self.key, self.sequence, self.request = job_id, key, sequence, request


@dataclass(frozen=True)
class _Scope:
    run_root: Path
    job_id: str
    literals: tuple[tuple[str, str], ...]


_scope: _Scope | None = None
_lock = threading.Lock()
_replayed: Counter = Counter()


@contextmanager
def unit_scope(*, run_root: Path, job_id: str, repository_root: Path | None,
               target_root: Path | None) -> Iterator[None]:
    """Attribute the model calls one unit makes to its run and job.

    A process runs one unit at a time (Dagster's multiprocess executor gives each op its own
    process, and the local driver is sequential), so a process-wide scope is visible to every
    thread the unit starts.
    """

    global _scope
    literals = [(str(Path(run_root).resolve()), "<run>")]
    literals += [(str(Path(root).resolve()), placeholder) for root, placeholder in
                 ((target_root, "<target>"), (repository_root, "<repo>")) if root is not None]
    previous = _scope
    _scope = _Scope(Path(run_root), job_id, tuple(sorted(literals, key=lambda item: -len(item[0]))))
    try:
        yield
    finally:
        _scope = previous


def _masked(value: Any, literals: tuple[tuple[str, str], ...]) -> Any:
    if isinstance(value, Mapping):
        return {_masked(str(key), literals): _masked(child, literals) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_masked(child, literals) for child in value]
    if isinstance(value, str):
        for source, placeholder in literals:
            value = value.replace(source, placeholder)
    return value


def request_key(request: ModelRequest | ReviewModelRequest,
                literals: tuple[tuple[str, str], ...] = ()) -> tuple[str, dict[str, Any]]:
    """The recording key of ``request`` and the masked request it was computed over."""

    masked = {"type": type(request).__name__, **_masked(asdict(request), literals)}
    canonical = json.dumps(masked, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), masked


def _record(scope: _Scope, key: str, masked: Mapping[str, Any], result: ModelResult) -> None:
    directory = scope.run_root / RECORDINGS / scope.job_id
    directory.mkdir(parents=True, exist_ok=True)
    document = {"schema": SCHEMA, "job_id": scope.job_id, "key": key, "request": masked,
                "result": asdict(result)}
    for sequence in range(10_000):
        path = directory / f"{key}.{sequence:04d}.json"
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump({**document, "sequence": sequence}, handle, indent=1, sort_keys=True)
                handle.write("\n")
            return
        except FileExistsError:
            continue
    raise RuntimeError(f"model recording sequence space exhausted for {key}")


def _keep_miss(root: Path, job_id: str, key: str, sequence: int, masked: Mapping[str, Any]) -> None:
    """Keep the masked request a replay could not answer, so it can be diffed against the recordings."""

    path = root / job_id / "misses" / f"{key}.{sequence:04d}.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": SCHEMA, "job_id": job_id, "key": key, "sequence": sequence,
                                    "request": masked}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        pass  # the miss is still raised; the copy is a diagnostic


def _replay(scope: _Scope, key: str, masked: Mapping[str, Any]) -> ModelResult:
    root = os.environ.get(REPLAY_ENVIRONMENT)
    if not root:
        raise RuntimeError(f"{MODE_ENVIRONMENT}=replay requires {REPLAY_ENVIRONMENT}")
    with _lock:
        sequence = _replayed[(scope.job_id, key)]
        _replayed[(scope.job_id, key)] += 1
    path = Path(root) / scope.job_id / f"{key}.{sequence:04d}.json"
    if not path.is_file():
        _keep_miss(Path(root), scope.job_id, key, sequence, masked)
        raise ModelReplayMiss(scope.job_id, key, sequence, masked)
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA or document.get("key") != key:
        raise RuntimeError(f"model recording {path.name} does not belong to request {key}")
    return ModelResult(**document["result"])


def recorded(infer: Infer) -> Infer:
    """Wrap ``infer`` so the process environment can switch it to recording or replay."""

    def wrapper(request: ModelRequest | ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        mode = os.environ.get(MODE_ENVIRONMENT, "")
        if not mode:
            return infer(request, timeout_seconds=timeout_seconds)
        if mode not in {"record", "replay"}:
            raise ValueError(f"{MODE_ENVIRONMENT} must be record or replay, not {mode!r}")
        scope = _scope
        if scope is None:
            raise RuntimeError("a model call outside a job unit cannot be recorded or replayed")
        key, masked = request_key(request, scope.literals)
        if mode == "replay":
            return _replay(scope, key, masked)
        result = infer(request, timeout_seconds=timeout_seconds)
        _record(scope, key, masked, result)
        return result

    return wrapper
