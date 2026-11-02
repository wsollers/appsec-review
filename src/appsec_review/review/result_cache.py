"""Run-scoped memo of blue review-cell results per (function, value).

RepoAudit-style agent memory: within one run, a blue cell (``blue_control`` / ``blue_reachability``)
that asks the model exactly the question an earlier cell of this run already answered reuses that
answer instead of re-querying the model. A claim's ``claim_id`` already binds the affected function and
the tracked value (``review.claims.claim_identity``); :func:`memo_key` adds everything else that shapes
the model request except the round-bearing fields, so a repeated claim's blue cells in a later round
hit while any change to the claim prose, package view, evidence set, guidance, model, budgets,
validator or capability misses.

This is a cost optimization only. Model output stays judgment data, never evidence: a hit copies a
result that the cell executor revalidates against the current cell's evidence set before it is used,
and the reusing cell writes its own receipt naming its source (``reused_from``). Red cells, the blind
independent verifier (R6: no shared cache entry) and the adjudication judge are never memoized.

The store is an external Garnet (Redis protocol) key-value service; it owns storage and expiry (``SET
key value EX ttl NX``). This module implements no caching or TTL itself. Every store, socket, timeout
or import failure is fail-open: the lookup is a miss, the write is skipped, the failure is counted
and logged once without credentials, and the review proceeds exactly as with no cache.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
import re
import threading
from typing import TYPE_CHECKING, Any, Mapping, Protocol

from appsec_review.review.identity import sha256_hex

if TYPE_CHECKING:
    from appsec_review.config.inference_review import ResultCacheSettings
    from appsec_review.review.capability import CellCapability
    from appsec_review.review.cells import CellSpec

MEMO_KEY_DOMAIN = "appsec-review/review-memo-key/1"
MEMO_POINTER_SCHEMA = "appsec-review/review-memo-pointer/1"
KEY_PREFIX = "appsec-review:review-memo:"
PASSWORD_ENVIRONMENT = "APPSEC_RESULT_CACHE_PASSWORD"
# Top-level task-input fields that carry the round; stripped so a later round's identical question hits.
ROUND_BEARING_INPUT_FIELDS = frozenset({"round", "round_delta", "round_delta_sha256"})
_CELL_ID = re.compile(r"cell-[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_LOG = logging.getLogger(__name__)


def memo_key(spec: "CellSpec", capability: "CellCapability", run_id: str) -> str:
    """The round-free SHA-256 identity of a blue cell's model request within one run.

    Every ``CellSpec`` field that shapes the request is an input. Excluded, with reasons:

    * ``round``, ``round_delta_sha256`` and ``capability.capability_sha256``: round-bearing; excluding
      them is the point of the memo (the capability's round-free ``semantic_body`` is included).
    * ``guidance_text``: its exact bytes are pinned by ``guidance_bundle_sha256``.
    * ``view`` and ``expand``: the view is already part of ``task_input``; the expansion is fixed by
      ``output_schema`` and ``validator_version``.
    """
    from appsec_review.review.cells import EXECUTOR_VERSION, _plain
    from appsec_review.review.models import Lane, Role

    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("memo key needs a run id")
    if not spec.claim_id:
        raise ValueError("memo key needs a claim id: only claim-bound cells are memoized")
    task_input = _plain(spec.task_input)
    if isinstance(task_input, dict):
        task_input = {key: value for key, value in task_input.items() if key not in ROUND_BEARING_INPUT_FIELDS}
    body = {
        "domain": MEMO_KEY_DOMAIN,
        "run_id": run_id,
        "claim_id": spec.claim_id,
        "run_input_manifest": spec.manifest_sha256,
        "package": {"id": spec.package_id, "sha256": spec.package_sha256},
        "reuse_basis": spec.reuse_basis,
        "lane": Lane(spec.lane).value,
        "role": Role(spec.role).value,
        "persona": spec.persona,
        "stack_profile": spec.stack_profile,
        "strategy": spec.strategy,
        "task": {"id": spec.task, "input_sha256": sha256_hex(task_input)},
        "readable_evidence_set": sorted(set(spec.evidence_set)),
        "guidance_bundle": spec.guidance_bundle_sha256,
        "model": {"provider": spec.provider, "model": spec.model, "reasoning": spec.reasoning},
        "budgets": {"max_input_tokens": spec.max_input_tokens, "max_output_tokens": spec.max_output_tokens,
                    "timeout_seconds": spec.timeout_seconds},
        "output_schema": spec.output_schema,
        "validator_version": {"executor": EXECUTOR_VERSION, "result": spec.validator_version},
        "capability": capability.semantic_body(),
    }
    return sha256_hex(body)


@dataclass(frozen=True, slots=True)
class MemoPointer:
    """Where a memoized result lives: one succeeded receipt of this run, pinned by its file hash."""

    cell_id: str
    attempt: int
    receipt_sha256: str

    def __post_init__(self) -> None:
        if (not isinstance(self.cell_id, str) or not _CELL_ID.fullmatch(self.cell_id)
                or type(self.attempt) is not int or not 1 <= self.attempt <= 999_999
                or not isinstance(self.receipt_sha256, str) or not _SHA256.fullmatch(self.receipt_sha256)):
            raise ValueError("invalid memo pointer")

    def encode(self) -> bytes:
        return json.dumps({"schema": MEMO_POINTER_SCHEMA, "cell_id": self.cell_id, "attempt": self.attempt,
                           "receipt_sha256": self.receipt_sha256},
                          sort_keys=True, separators=(",", ":")).encode("ascii")

    @classmethod
    def decode(cls, raw: object) -> "MemoPointer | None":
        """The pointer, or ``None`` for anything malformed (a miss, never an error)."""
        try:
            text = raw.decode("ascii") if isinstance(raw, (bytes, bytearray)) else raw
            if not isinstance(text, str) or len(text) > 1024:
                return None
            document = json.loads(text)
            if not isinstance(document, dict) or set(document) != {"schema", "cell_id", "attempt",
                                                                   "receipt_sha256"}:
                return None
            if document["schema"] != MEMO_POINTER_SCHEMA:
                return None
            return cls(document["cell_id"], document["attempt"], document["receipt_sha256"])
        except (UnicodeDecodeError, ValueError, TypeError):
            return None


class ResultCache(Protocol):
    """The key-value boundary. Implementations never raise into the review."""

    @property
    def available(self) -> bool: ...

    @property
    def unavailable(self) -> int: ...

    def get(self, key: str) -> MemoPointer | None: ...

    def put_if_absent(self, key: str, pointer: MemoPointer) -> bool: ...


@dataclass(frozen=True, slots=True)
class Memo:
    """What the cell executor needs to consult the memo for one run."""

    cache: ResultCache
    run_id: str


class InMemoryResultCache:
    """A process-local stand-in for the external store, for tests. It never expires entries."""

    def __init__(self, *, available: bool = True) -> None:
        self.entries: dict[str, bytes] = {}
        self.gets = 0
        self.puts = 0
        self._available = available
        self._unavailable = 0
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return self._available

    @property
    def unavailable(self) -> int:
        return self._unavailable

    def get(self, key: str) -> MemoPointer | None:
        with self._lock:
            self.gets += 1
            if not self._available:
                self._unavailable += 1
                return None
            raw = self.entries.get(key)
        return MemoPointer.decode(raw) if raw is not None else None

    def put_if_absent(self, key: str, pointer: MemoPointer) -> bool:
        with self._lock:
            self.puts += 1
            if not self._available:
                self._unavailable += 1
                return False
            if key in self.entries:
                return False
            self.entries[key] = pointer.encode()
            return True


class GarnetResultCache:
    """Garnet (Redis protocol) client. The first failure opens a sticky breaker for this instance.

    After it opens, every operation is a no-op miss, so one unreachable store costs at most one
    connect timeout per job attempt. The breaker never closes within an attempt; a resumed attempt
    builds a new client. A pointer written just before the breaker opens is still usable by later
    attempts; one that never got written is only a lost saving.
    """

    def __init__(self, *, endpoint: str, run_id: str, ttl_seconds: int, timeout_seconds: float,
                 password: str | None = None) -> None:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
            raise ValueError("result cache needs a run id")
        self.endpoint = endpoint
        self.prefix = f"{KEY_PREFIX}{run_id}:"
        self.ttl_seconds = int(ttl_seconds)
        self._client: Any = None
        self._available = True
        self._unavailable = 0
        self._warned = False
        self._lock = threading.Lock()
        try:
            import redis
            from redis.backoff import NoBackoff
            from redis.retry import Retry
            # No client-side retries: a slow or absent store must cost at most one bounded timeout.
            self._client = redis.Redis.from_url(endpoint, password=password, socket_connect_timeout=timeout_seconds,
                                                socket_timeout=timeout_seconds, retry=Retry(NoBackoff(), 0))
        except Exception as exc:  # missing library or unusable endpoint: no cache, never a failure
            self._fail("client", exc)

    @property
    def available(self) -> bool:
        return self._available

    @property
    def unavailable(self) -> int:
        return self._unavailable

    def get(self, key: str) -> MemoPointer | None:
        if not self._available:
            self._count()
            return None
        try:
            raw = self._client.get(self.prefix + key)
        except Exception as exc:
            self._fail("get", exc)
            return None
        return MemoPointer.decode(raw) if raw is not None else None

    def put_if_absent(self, key: str, pointer: MemoPointer) -> bool:
        if not self._available:
            self._count()
            return False
        try:
            return bool(self._client.set(self.prefix + key, pointer.encode(), ex=self.ttl_seconds, nx=True))
        except Exception as exc:
            self._fail("put", exc)
            return False

    def _count(self) -> None:
        with self._lock:
            self._unavailable += 1

    def _fail(self, operation: str, exc: BaseException) -> None:
        with self._lock:
            self._available = False
            self._unavailable += 1
            warn, self._warned = not self._warned, True
        if warn:
            # The endpoint carries no credentials (validated); the password is never formatted.
            _LOG.warning("review result cache unavailable; continuing without it", extra={"event": {
                "event_type": "REVIEW_RESULT_CACHE_UNAVAILABLE", "endpoint": self.endpoint,
                "operation": operation, "error_type": type(exc).__name__}})


def cache_from_settings(settings: "ResultCacheSettings", run_id: str,
                        environ: Mapping[str, str] | None = None) -> GarnetResultCache | None:
    """The run's Garnet client, or ``None`` when the memo is disabled. No connection is made here."""
    if not settings.enabled:
        return None
    password = (os.environ if environ is None else environ).get(PASSWORD_ENVIRONMENT) or None
    return GarnetResultCache(endpoint=settings.endpoint, run_id=run_id, ttl_seconds=settings.ttl_seconds,
                             timeout_seconds=settings.connect_timeout_seconds, password=password)


__all__ = ["GarnetResultCache", "InMemoryResultCache", "KEY_PREFIX", "MEMO_KEY_DOMAIN", "Memo", "MemoPointer",
           "PASSWORD_ENVIRONMENT", "ResultCache", "cache_from_settings", "memo_key"]
