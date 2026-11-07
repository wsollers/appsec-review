"""The one way a job reads another job's accepted handoff.

A consumer binds to the producer attempt its own ``claim.json`` pinned (``upstream_handoffs``),
never to whatever ``latest.json`` points at while it runs. The runner opens an :func:`upstream_scope`
around every unit it executes; inside it, :func:`accepted_upstream` resolves the pinned digest and
refuses a producer the claim did not pin. Outside any scope (operator tooling, acceptance scripts,
unit tests that build a run tree by hand) it falls back to the hash-verified ``latest.json`` pointer
and reports ``pinned=False``.

Every path verifies the handoff bytes against their recorded SHA-256 and decodes them through
``decode_handoff``; nothing here trusts a pointer or a file name.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping

from appsec_review.interchange import decode_handoff
from appsec_review.storage import file_sha256

_JOB = re.compile(r"[a-z][a-z0-9_]*")


class UpstreamNotPinnedError(ValueError):
    """The consumer's claim does not pin the producer it tried to read."""


class UpstreamIntegrityError(ValueError):
    """A pinned or pointed-to handoff is missing, moved outside the run or has other bytes."""


@dataclass(frozen=True, slots=True)
class _Scope:
    run_root: Path
    consumer_job_id: str
    upstream_handoffs: Mapping[str, str]


_ACTIVE: ContextVar[_Scope | None] = ContextVar("appsec_review_upstream_scope", default=None)


@contextmanager
def upstream_scope(run_root: Path, consumer_job_id: str,
                   upstream_handoffs: Mapping[str, str]) -> Iterator[None]:
    """Bind the pinned producer digests of one attempt for the duration of its work."""
    if not _JOB.fullmatch(consumer_job_id):
        raise ValueError("invalid consumer job identity")
    pins = {}
    for job_id, digest in dict(upstream_handoffs).items():
        if not isinstance(job_id, str) or not _JOB.fullmatch(job_id):
            raise ValueError("invalid pinned upstream job identity")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"pinned upstream digest for {job_id} is not a SHA-256")
        pins[job_id] = digest
    token = _ACTIVE.set(_Scope(Path(run_root).resolve(), consumer_job_id, MappingProxyType(pins)))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def current_pins(run_root: Path) -> Mapping[str, str] | None:
    """The active attempt's pinned upstream digests for ``run_root``, or ``None`` outside a scope."""
    scope = _ACTIVE.get()
    if scope is None or scope.run_root != Path(run_root).resolve():
        return None
    return scope.upstream_handoffs


@dataclass(frozen=True, slots=True)
class AcceptedUpstream:
    """One verified accepted handoff: the decoded document, its digest and run-relative path."""
    job_id: str
    handoff: Mapping[str, Any]
    sha256: str
    path: str
    pinned: bool

    @property
    def identity(self) -> dict[str, str]:
        return {"path": self.path, "sha256": self.sha256}

    def as_tuple(self) -> tuple[Mapping[str, Any], str]:
        """The ``(handoff, sha256)`` shape the per-job readers used to return."""
        return self.handoff, self.sha256


def _safe(run_root: Path, relative: str) -> Path:
    from appsec_review.storage.shared import safe_path
    return safe_path(run_root, relative)


def _pointer(run_root: Path, job_id: str) -> Mapping[str, Any] | None:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None
    try:
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise UpstreamIntegrityError(f"accepted {job_id} pointer is not JSON") from exc
    if not isinstance(pointer, Mapping) or not isinstance(pointer.get("handoff_path"), str) \
            or not isinstance(pointer.get("handoff_sha256"), str):
        raise UpstreamIntegrityError(f"accepted {job_id} pointer is malformed")
    return pointer


def _verified(run_root: Path, job_id: str, relative: str, expected: str) -> AcceptedUpstream:
    path = _safe(run_root, relative)
    if not path.is_file() or path.is_symlink():
        raise UpstreamIntegrityError(f"accepted {job_id} handoff is unavailable: {relative}")
    if file_sha256(path) != expected:
        raise UpstreamIntegrityError(f"accepted {job_id} handoff changed after it was recorded")
    try:
        handoff = decode_handoff(json.loads(path.read_text(encoding="utf-8")),
                                 run_id=run_root.name, job_id=job_id)
    except ValueError as exc:
        raise UpstreamIntegrityError(f"{job_id} handoff is not an accepted handoff") from exc
    return AcceptedUpstream(job_id, handoff, expected, path.relative_to(run_root).as_posix(), pinned=False)


def _by_digest(run_root: Path, job_id: str, expected: str) -> AcceptedUpstream:
    pointer = _pointer(run_root, job_id)
    if pointer is not None and pointer["handoff_sha256"] == expected:
        return _verified(run_root, job_id, pointer["handoff_path"], expected)
    # latest.json moved on (a newer attempt was accepted after this claim); find the pinned one.
    attempts = _safe(run_root, f"data/jobs/{job_id}/attempts")
    matches = [path for path in sorted(attempts.glob("attempt_*/handoff.json"))
               if path.is_file() and not path.is_symlink() and file_sha256(path) == expected]
    if len(matches) != 1:
        raise UpstreamIntegrityError(
            f"expected exactly one accepted {job_id} handoff with the pinned digest, found {len(matches)}")
    return _verified(run_root, job_id, matches[0].relative_to(run_root).as_posix(), expected)


def accepted_upstream(run_root: Path, job_id: str, *, required: bool = True) -> AcceptedUpstream | None:
    """Return the accepted handoff of ``job_id`` the current attempt may use.

    Inside an :func:`upstream_scope` the producer must be pinned by the consumer's claim; an unpinned
    producer raises :class:`UpstreamNotPinnedError` when ``required`` and returns ``None`` otherwise,
    which is how an optional producer that did not run in this graph (or is not an ancestor of the
    consumer) is seen. Outside a scope the hash-verified ``latest.json`` pointer is used and the
    result carries ``pinned=False``.
    """
    if not _JOB.fullmatch(job_id):
        raise ValueError("invalid upstream job identity")
    run_root = Path(run_root).resolve()
    pins = current_pins(run_root)
    if pins is not None:
        digest = pins.get(job_id)
        if digest is None:
            if not required:
                return None
            if _pointer(run_root, job_id) is None:
                raise UpstreamIntegrityError(f"accepted {job_id} handoff is required")
            scope = _ACTIVE.get()
            consumer = scope.consumer_job_id if scope is not None else "?"
            raise UpstreamNotPinnedError(
                f"{consumer} reads {job_id}, which was accepted in this run but is not pinned by the "
                "attempt claim; declare the dependency in the topology and the job's CONSUMES")
        found = _by_digest(run_root, job_id, digest)
        return AcceptedUpstream(found.job_id, found.handoff, found.sha256, found.path, pinned=True)
    pointer = _pointer(run_root, job_id)
    if pointer is None:
        if required:
            raise UpstreamIntegrityError(f"accepted {job_id} handoff is required")
        return None
    return _verified(run_root, job_id, pointer["handoff_path"], pointer["handoff_sha256"])


def accepted_latest(run_root: Path, job_id: str) -> AcceptedUpstream | None:
    """The job's own most recent accepted attempt, by hash-verified pointer, ignoring pins.

    Only for a job reading *itself* (checkpoint and cache reuse across its own attempts) or for
    operator tooling. Consumers of another job's evidence use :func:`accepted_upstream`.
    """
    if not _JOB.fullmatch(job_id):
        raise ValueError("invalid job identity")
    run_root = Path(run_root).resolve()
    pointer = _pointer(run_root, job_id)
    if pointer is None:
        return None
    return _verified(run_root, job_id, pointer["handoff_path"], pointer["handoff_sha256"])


def has_accepted_upstream(run_root: Path, job_id: str) -> bool:
    """Whether ``job_id`` has an accepted handoff this attempt may use (pinned inside a scope)."""
    return accepted_upstream(run_root, job_id, required=False) is not None


def consumable_handoffs(run_root: Path, job_id: str, consumes: Iterable[str],
                        upstream_handoffs: Mapping[str, str]) -> dict[str, str]:
    """Everything one attempt may read, fixed when its claim is written.

    The runner's projected ``upstream_handoffs`` (the producers that ran or were reused in this
    graph) are always included unchanged. Producers the job declares in ``consumes``, and every
    ancestor in the full ``wave1_review`` topology, are added when the run already holds an accepted
    handoff for them: the digest recorded is the one accepted at claim time, so a producer accepted
    later in the run can never be read by this attempt. Producers without an accepted handoff are
    simply absent, which :func:`accepted_upstream` reports as unavailable.
    """
    run_root = Path(run_root).resolve()
    pins = dict(upstream_handoffs)
    candidates = set(consumes)
    try:
        from appsec_review.orchestration.topology import upstream_closure, wave1_dependencies
        from appsec_review.runtime.registry import builtin_registry
        full = wave1_dependencies(set(builtin_registry().job_ids()))
    except Exception:  # noqa: BLE001 - the topology is a convenience here, never a gate
        full = None
    if full and job_id in full:
        candidates |= set(upstream_closure(job_id, full, set(full)))
    for candidate in sorted(candidates - set(pins)):
        if not _JOB.fullmatch(candidate) or candidate == job_id:
            continue
        # Pin the bytes the pointer names as they are now; nothing is decoded or judged here. A
        # corrupt pointer or an invalid handoff is reported by the read that needs it, inside the
        # attempt, where it fails that unit with the exact reason and leaves a receipt.
        try:
            pointer = _pointer(run_root, candidate)
        except UpstreamIntegrityError:
            continue
        if pointer is None:
            continue
        try:
            path = _safe(run_root, pointer["handoff_path"])
        except ValueError:
            continue
        if not path.is_file() or path.is_symlink():
            continue
        pins[candidate] = file_sha256(path)
    return pins
