"""The one way a job reads another job's accepted handoff.

A consumer needs both a typed handoff requirement and the exact digest admitted into its claim.
Scheduling ancestry and available accepted producers grant no read permission. The runner opens an
:func:`upstream_scope` around its work; reads resolve admitted pins and record typed observations.
Outside any runtime scope, operator tooling may use the verified pointer and reports ``pinned=False``.

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
from appsec_review.runtime.contracts import InputChannel, JobContract
from appsec_review.runtime.inputs import _read_boundary, observe_handoff
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
    contract: JobContract | None


_ACTIVE: ContextVar[_Scope | None] = ContextVar("appsec_review_upstream_scope", default=None)


@contextmanager
def upstream_scope(run_root: Path, consumer_job_id: str,
                   upstream_handoffs: Mapping[str, str], *,
                   contract: JobContract | None = None) -> Iterator[None]:
    """Bind typed permission and admitted producer digests, never an availability expansion."""
    if not _JOB.fullmatch(consumer_job_id):
        raise ValueError("invalid consumer job identity")
    pins = {}
    for job_id, digest in dict(upstream_handoffs).items():
        if not isinstance(job_id, str) or not _JOB.fullmatch(job_id):
            raise ValueError("invalid pinned upstream job identity")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"pinned upstream digest for {job_id} is not a SHA-256")
        pins[job_id] = digest
    if contract is not None:
        contract.validate(consumer_job_id)
    token = _ACTIVE.set(_Scope(Path(run_root).resolve(), consumer_job_id, MappingProxyType(pins), contract))
    try:
        yield
    finally:
        _ACTIVE.reset(token)


@_read_boundary
def current_pins(run_root: Path) -> Mapping[str, str] | None:
    """The active attempt's pinned upstream digests for ``run_root``, or ``None`` outside a scope."""
    scope = _ACTIVE.get()
    if scope is None:
        return None
    if scope.run_root != Path(run_root).resolve():
        raise UpstreamIntegrityError("consumed handoff belongs to a foreign run")
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


@_read_boundary
def accepted_upstream(run_root: Path, job_id: str, *, required: bool = True) -> AcceptedUpstream | None:
    """Return the accepted handoff of ``job_id`` the current attempt may use.

    Runtime reads require a typed envelope declaration and an admitted pin. An optional declared
    producer with no supply returns ``None``; an undeclared read always fails. Outside a scope the
    verified pointer is an operator lookup, not a runtime grant.
    """
    if not _JOB.fullmatch(job_id):
        raise ValueError("invalid upstream job identity")
    run_root = Path(run_root).resolve()
    pins = current_pins(run_root)
    if pins is not None:
        scope = _ACTIVE.get()
        assert scope is not None
        requirements = scope.contract.inputs if scope.contract is not None else ()
        requirement = next((item for item in requirements
                            if item.producer == job_id and item.output_kind == "handoff"
                            and item.channel is InputChannel.HANDOFF), None)
        if requirement is None:
            raise UpstreamNotPinnedError(
                f"undeclared consumption by {scope.consumer_job_id}: {job_id}/handoff")
        digest = pins.get(job_id)
        if digest is None:
            if not required:
                return None
            if _pointer(run_root, job_id) is None:
                raise UpstreamIntegrityError(f"accepted {job_id} handoff is required")
            raise UpstreamNotPinnedError(
                f"{scope.consumer_job_id} reads {job_id}, which is not supplied by the "
                "attempt claim; provide the declared typed input")
        found = _by_digest(run_root, job_id, digest)
        if found.handoff["schema"] != requirement.schema:
            raise UpstreamIntegrityError(f"input envelope schema mismatch: {job_id}")
        observe_handoff(run_root, found.handoff)
        return AcceptedUpstream(found.job_id, found.handoff, found.sha256, found.path, pinned=True)
    pointer = _pointer(run_root, job_id)
    if pointer is None:
        if required:
            raise UpstreamIntegrityError(f"accepted {job_id} handoff is required")
        return None
    found = _verified(run_root, job_id, pointer["handoff_path"], pointer["handoff_sha256"])
    observe_handoff(run_root, found.handoff)
    return found


@_read_boundary
def accepted_latest(run_root: Path, job_id: str) -> AcceptedUpstream | None:
    """The job's own most recent accepted attempt, by hash-verified pointer, ignoring pins.

    Only for a job reading *itself* (checkpoint and cache reuse across its own attempts) or for
    operator tooling. Consumers of another job's evidence use :func:`accepted_upstream`.
    """
    if not _JOB.fullmatch(job_id):
        raise ValueError("invalid job identity")
    run_root = Path(run_root).resolve()
    scope = _ACTIVE.get()
    if scope is not None:
        current_pins(run_root)
        if scope.consumer_job_id != job_id:
            raise UpstreamNotPinnedError("accepted_latest is restricted to the current job's own cache")
    pointer = _pointer(run_root, job_id)
    if pointer is None:
        return None
    return _verified(run_root, job_id, pointer["handoff_path"], pointer["handoff_sha256"])


def has_accepted_upstream(run_root: Path, job_id: str) -> bool:
    """Whether ``job_id`` has an accepted handoff this attempt may use (pinned inside a scope)."""
    return accepted_upstream(run_root, job_id, required=False) is not None


def consumable_handoffs(run_root: Path, job_id: str, consumes: Iterable[str],
                        upstream_handoffs: Mapping[str, str]) -> dict[str, str]:
    """Available declared producers for planning/diagnostics, not supplied-input authority.

    The runner gives readers only its separately selected, typed-admitted ``upstream_handoffs``.
    An accepted pointer here neither supplies an input nor establishes a read or citation.
    """
    run_root = Path(run_root).resolve()
    pins = dict(upstream_handoffs)
    candidates = set(consumes)
    for candidate in sorted(candidates - set(pins)):
        if not _JOB.fullmatch(candidate) or candidate == job_id:
            continue
        pointer = _pointer(run_root, candidate)
        if pointer is None:
            continue
        pins[candidate] = pointer["handoff_sha256"]
    return pins
