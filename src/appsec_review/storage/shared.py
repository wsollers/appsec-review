"""Run-local immutable bytes and attempt-local computation/reuse receipts.

An object hash identifies bytes, not a computation or its first producer. Request directories
contain immutable references to *computed* receipts, never a replaceable "winning result".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
from contextvars import ContextVar, copy_context
from copy import deepcopy
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
from typing import Any, Mapping, Protocol, TYPE_CHECKING

from .atomic import canonical_json, file_sha256, timed_fsync
from .validation import (
    current_validation, observed_digest, remember_digest, validation_operation, validation_scope,
    verified_digest,
)

if TYPE_CHECKING:
    from appsec_review.runtime.job import JobContext

RECEIPT_SCHEMA = "appsec-review/shared-receipt/1"
REQUEST_SCHEMA = "appsec-review/shared-request/1"
OBJECTS = "data/shared/objects"
REQUESTS = "data/shared/requests"
NAMED = "data/shared/named"
_HASH = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-zA-Z0-9_-]+")
_ACTIVE: ContextVar[SharedArtifacts | None] = ContextVar("shared_artifact_attempt", default=None)
_READ_POLICY: ContextVar[tuple[Path, ReceiptReadPolicy] | None] = ContextVar("receipt_read_policy", default=None)


class ReceiptReadPolicy(Protocol):
    identity: str

    def admit_reference(self, root: Path, ref: Mapping[str, Any]) -> None: ...

    def admit_metadata(self, root: Path, ref: Mapping[str, Any]) -> None: ...

    def metadata_reference(self, root: Path, relative: str) -> Mapping[str, Any] | None: ...

    def admit_receipt(self, root: Path, value: Mapping[str, Any], *,
                      origin: Mapping[str, Any], origin_claim: Mapping[str, Any],
                      origin_ref: Mapping[str, Any]) -> None: ...


def _read_policy(root: Path) -> ReceiptReadPolicy | None:
    selected = _READ_POLICY.get()
    if selected is None:
        return None
    if selected[0] != root and selected[0] != Path(root).resolve():
        raise ValueError("receipt read policy belongs to another run")
    return selected[1]


@contextmanager
def receipt_read_scope(root: Path, policy: ReceiptReadPolicy | None):
    if policy is None:
        yield
        return
    from .validation import current_validation, isolated_validation_scope
    policy_id = "receipt-read:" + policy.identity
    existing = current_validation(root)
    if existing is not None and existing.policy_identity == policy_id:
        token = _READ_POLICY.set((Path(root).resolve(), policy))
        try:
            yield
        finally:
            _READ_POLICY.reset(token)
        return
    with isolated_validation_scope(root, policy_identity=policy_id):
        token = _READ_POLICY.set((Path(root).resolve(), policy))
        try:
            yield
        finally:
            _READ_POLICY.reset(token)


def _metadata_reference(root: Path, ref: Mapping[str, Any], pattern: str) -> None:
    policy = _read_policy(root)
    if policy is not None:
        if not re.fullmatch(pattern, str(ref.get("path", ""))):
            raise ValueError("receipt metadata reference has an invalid control-record identity")
        policy.admit_metadata(root, ref)


def _admit_target(root: Path, path: Path, expected: str | None = None) -> None:
    policy = _read_policy(root)
    if policy is not None:
        policy.admit_reference(root, {"path": path.relative_to(root).as_posix(), "sha256": expected})


def _metadata_write_target(root: Path, path: Path) -> None:
    policy = _read_policy(root)
    if policy is not None:
        policy.admit_metadata(root, {"path": path.relative_to(root).as_posix()})


def _control_reference(root: Path, path: Path, *,
                       expected: Mapping[str, Any] | None = None) -> dict[str, Any]:
    policy = _read_policy(root)
    if policy is None:
        return reference(root, path)
    relative = path.relative_to(root).as_posix()
    owner = current()
    if owner is not None and owner.run_root != root:
        raise ValueError("control discovery belongs to another run")
    pinned = expected or (owner._control_refs.get(relative) if owner is not None else None)
    if pinned is None:
        pinned = policy.metadata_reference(root, relative)
    if pinned is None or pinned["path"] != relative:
        raise ValueError(f"selected control identity is unavailable before discovery: {relative}")
    policy.admit_metadata(root, pinned)
    return dict(pinned)


def _binding_reference(root: Path, namespace: str, obj: Mapping[str, Any]) -> dict[str, Any]:
    relative = _binding_path(namespace, obj)
    payload = canonical_json({"schema": "appsec-review/shared-named/1", "namespace": namespace,
                              "object": dict(obj)})
    expected = {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
    return _control_reference(root, safe_path(root, relative), expected=expected)
NAMED_LAYOUTS = {
    "index-shard": ("data/indices/",),
    "owasp-shard": ("data/indexes/owasp/",),
    "guidance": ("data/guidance/",),
    "review-package": ("data/review-packages/",),
    "review-cell": ("data/jobs/job_inference_security_review/cells/",),
    "cell-check": ("data/jobs/job_inference_security_review/cells/",),
}


def _named_layout(namespace: str, relative: str) -> bool:
    if relative.startswith(NAMED_LAYOUTS[namespace]):
        return True
    if namespace == "review-cell":
        return re.fullmatch(
            r"data/jobs/job_inference_security_review/attempts/attempt_[0-9]{4}/cells/[^/]+/"
            r"attempt-[1-9][0-9]*\.json", relative) is not None
    if namespace == "cell-check":
        return re.fullmatch(
            r"data/jobs/job_inference_security_review/attempts/attempt_[0-9]{4}/cells/[^/]+/"
            r"(?:independence-attempt|judge-request-check)-[1-9][0-9]*\.json", relative) is not None
    return False


def _hash(value: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("invalid shared content/fingerprint hash")
    return value


@lru_cache(maxsize=32768)
def _path_components(root: Path, relative: str) -> tuple[Path, ...]:
    """Cache immutable path parsing, never filesystem state or access decisions."""
    parts = PurePosixPath(relative).parts
    if (not parts or PurePosixPath(relative).is_absolute() or "\\" in relative
            or ":" in relative or any(part in {".", ".."} for part in parts)
            or "/".join(parts) != relative):
        raise ValueError("shared artifact path is not run-relative canonical POSIX")
    path = root
    paths = [root]
    for part in parts:
        path /= part
        paths.append(path)
    return tuple(paths)


def safe_path(root: Path, relative: str) -> Path:
    """Reject noncanonical paths and every symlink, including links within the run."""
    paths = _path_components(Path(root).absolute(), relative)
    root, path = paths[0], paths[-1]
    for candidate in paths[1:]:
        if candidate.is_symlink():
            raise ValueError(f"shared artifact symlink: {relative}")
    if root.is_symlink():
        raise ValueError("shared artifact path escapes run")
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    if path_real == root_real or not path_real.startswith(os.path.join(root_real, "")):
        raise ValueError("shared artifact path escapes run")
    return path


def reference(root: Path, path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    path = safe_path(root, relative)
    if not path.is_file():
        raise ValueError(f"shared artifact missing: {relative}")
    if relative.startswith(OBJECTS + "/"):
        identity = _hash(path.name)
        if expected_sha256 is not None and expected_sha256 != identity:
            raise ValueError("shared object path differs from expected identity")
        expected_sha256 = identity
    if _read_policy(root) is not None:
        digest = observed_digest(root, path)
        if expected_sha256 is not None and digest != _hash(expected_sha256):
            raise ValueError("shared artifact integrity mismatch")
    else:
        digest = (verified_digest(root, path, _hash(expected_sha256)) if expected_sha256 is not None
                  else observed_digest(root, path))
    return {"path": relative, "sha256": digest, "size_bytes": path.stat().st_size}


def verify_reference(root: Path, ref: Mapping[str, Any]) -> Path:
    path = safe_path(root, ref["path"])
    expected = _hash(ref["sha256"])
    if (not path.is_file() or (observed_digest(root, path) if _read_policy(root) is not None
                              else verified_digest(root, path, expected)) != expected
            or path.stat().st_size != ref["size_bytes"]):
        raise ValueError(f"shared artifact integrity mismatch: {ref['path']}")
    return path


def immutable_bytes(root: Path, relative: str, payload: bytes) -> dict[str, Any]:
    """Publish complete, fsynced bytes with an atomic no-replace link."""
    path = safe_path(root, relative)
    digest = hashlib.sha256(payload).hexdigest()
    if path.exists() or path.is_symlink():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise ValueError(f"immutable shared artifact conflicts: {relative}")
        remember_digest(root, path, digest)
        return reference(root, path, expected_sha256=digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            timed_fsync(stream.fileno())
        safe_path(root, relative)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
                raise ValueError(f"immutable shared artifact conflicts: {relative}") from None
        remember_digest(root, path, digest)
        return reference(root, path, expected_sha256=digest)
    finally:
        os.unlink(temporary)


def put_bytes(root: Path, payload: bytes) -> dict[str, Any]:
    return immutable_bytes(root, f"{OBJECTS}/{hashlib.sha256(payload).hexdigest()}", payload)


def put_file(root: Path, source: Path) -> dict[str, Any]:
    """Stream large objects; never keep a second durable copy of a SQLite shard."""
    safe_path(root, source.relative_to(root).as_posix())
    digest = file_sha256(source)
    relative = f"{OBJECTS}/{digest}"
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        from appsec_review.observability.spans import count_work, operation_phase
        with os.fdopen(descriptor, "wb") as output, source.open("rb") as stream:
            with operation_phase("storage.copy"):
                shutil.copyfileobj(stream, output)
            output.flush()
            timed_fsync(output.fileno())
            copied_bytes = output.tell()
        count_work("copy_bytes", copied_bytes)
        count_work("copy_objects")
        if file_sha256(Path(temporary)) != digest:
            raise ValueError("shared artifact changed during publication")
        safe_path(root, relative)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or file_sha256(path) != digest:
                raise ValueError(f"immutable shared artifact conflicts: {relative}") from None
        return reference(root, path)
    finally:
        os.unlink(temporary)


def _conflict_free(root: Path, path: Path, relative: str, digest: str) -> None:
    """Confirm an existing immutable path holds ``digest`` (hashed once per validation context)."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"immutable shared artifact conflicts: {relative}")
    try:
        verified_digest(root, path, digest)
    except ValueError:
        raise ValueError(f"immutable shared artifact conflicts: {relative}") from None


def _link(root: Path, source: Path, relative: str, digest: str) -> dict[str, Any]:
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, path)
    except FileExistsError:
        _conflict_free(root, path, relative, digest)
    ref = reference(root, path)
    if ref["sha256"] != digest:
        raise ValueError("immutable source changed during publication")
    return ref


def put_private_file(root: Path, source: Path) -> dict[str, Any]:
    """Detach publication from a builder's potentially writable aliases."""
    return put_file(root, source)


def adopt_private_file(root: Path, source: Path, digest: str) -> dict[str, Any]:
    """Publish a builder's closed, fsynced private file as ``objects/<digest>`` without copying.

    The caller must already have hashed ``source`` (``digest``) and must not write it again; its
    private directory is removed after publication, so the object keeps no writable builder alias.
    Across filesystems (EXDEV) this falls back to the copying ``put_file`` path.
    """
    safe_path(root, source.relative_to(root).as_posix())
    relative = f"{OBJECTS}/{_hash(digest)}"
    path = safe_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, path)
    except FileExistsError:
        _conflict_free(root, path, relative, digest)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        return put_file(root, source)
    else:
        from appsec_review.observability.spans import count_work
        count_work("custody_alias_objects")
    return reference(root, path, expected_sha256=digest)


def _verified_bytes(root: Path, ref: Mapping[str, Any]) -> bytes:
    size = ref.get("size_bytes")
    if type(size) is not int or size < 0:
        raise ValueError("shared artifact size must be a nonnegative integer")
    expected = _hash(ref["sha256"])
    path = safe_path(root, ref["path"])
    signature = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise ValueError(f"shared artifact size mismatch: {ref['path']}")
        remaining, chunks, digest = size, [], hashlib.sha256()
        with path.open("rb") as stream:
            if signature(os.fstat(stream.fileno())) != signature(before):
                raise ValueError(f"shared artifact changed before read: {ref['path']}")
            while True:
                # Match storage hashing's existing 1 MiB block size, not the advertised allocation.
                chunk = stream.read(min(1024 * 1024, remaining + 1))
                if not chunk:
                    break
                if len(chunk) > remaining:
                    raise ValueError(f"shared artifact grew during read: {ref['path']}")
                digest.update(chunk)
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(stream.fileno())
        safe_path(root, ref["path"])
        current = path.stat()
    except OSError as error:
        raise ValueError(f"shared artifact unavailable: {ref['path']}") from error
    if (remaining or digest.hexdigest() != expected
            or signature(before) != signature(after) or signature(before) != signature(current)):
        raise ValueError(f"shared artifact integrity mismatch: {ref['path']}")
    return b"".join(chunks)


def _read(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    raw = (_verified_bytes(root, ref) if _read_policy(root) is not None
           else verify_reference(root, ref).read_bytes())
    value = json.loads(raw)
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise ValueError("shared metadata must be canonical JSON")
    return value


def _binding_path(namespace: str, obj: Mapping[str, Any]) -> str:
    return f"{NAMED}/{namespace}/{hashlib.sha256(obj['path'].encode()).hexdigest()}.json"


def verify_binding(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    _metadata_reference(root, ref, r"data/shared/named/[a-zA-Z0-9_-]+/[0-9a-f]{64}\.json")
    value = _read(root, ref)
    namespace, obj = value["namespace"], value["object"]
    if (value.get("schema") != "appsec-review/shared-named/1"
            or namespace not in NAMED_LAYOUTS or not _named_layout(namespace, obj["path"])
            or ref["path"] != _binding_path(namespace, obj)):
        raise ValueError("invalid named immutable binding")
    policy = _read_policy(root)
    if policy is not None:
        policy.admit_reference(root, obj)
    verify_reference(root, obj)
    return value


@validation_operation
def verify_receipt(root: Path, ref: Mapping[str, Any], *,
                   seen: frozenset[str] = frozenset()) -> dict[str, Any]:
    if ref["path"] in seen:
        raise ValueError("shared receipt provenance cycle")
    _metadata_reference(root, ref, r"data/jobs/[a-zA-Z0-9_-]+/attempts/[a-zA-Z0-9_-]+/shared/[a-zA-Z0-9_-]+/[0-9a-f]{64}\.json")
    from appsec_review.observability.spans import count_work
    count_work("receipt_references")
    context = current_validation(root)
    key = ("receipt", ref["path"], _hash(ref["sha256"]))
    if _read_policy(root) is not None:
        # Cached provenance never stands in for the current reader's dependency grants.
        value = _verify_receipt(root, ref, seen=seen)
        count_work("receipt_validations")
        return value
    verify_reference(root, ref)
    if context is not None:
        with context.lock:
            admitted = context.admitted_receipts.get(ref["path"])
            if admitted is not None and admitted["sha256"] == ref["sha256"]:
                value = deepcopy(admitted["value"])
                for artifact in (value["object"], *value["dependencies"]):
                    path = safe_path(root, artifact["path"])
                    if not path.is_file() or path.stat().st_size != artifact["size_bytes"]:
                        raise ValueError("admitted receipt output is unavailable")
                return value
            if key in context.records:
                return deepcopy(context.records[key])
            value = _verify_receipt(root, ref, seen=seen)
            context.records[key] = deepcopy(value)
            count_work("receipt_validations")
            return value
    return _verify_receipt(root, ref, seen=seen)


def _verify_receipt(root: Path, ref: Mapping[str, Any], *,
                    seen: frozenset[str]) -> dict[str, Any]:
    value = _read(root, ref)
    if value.get("schema") != RECEIPT_SCHEMA or value.get("mode") not in {"computed", "reused"}:
        raise ValueError("invalid shared receipt schema/mode")
    if value.get("layout") not in {None, "named-immutable", "public-feed"}:
        raise ValueError("unsupported shared immutable layout")
    actor = value["actor"]
    if (not isinstance(actor, dict) or not isinstance(value.get("dependencies"), list)
            or not isinstance(value.get("object"), dict)):
        raise ValueError("invalid shared receipt fields")
    namespace, fingerprint = value["namespace"], _hash(value["fingerprint"])
    if namespace == "feed-snapshot" and value.get("layout") != "public-feed":
        raise ValueError("feed-snapshot receipt requires public-feed validation")
    if not _NAME.fullmatch(namespace):
        raise ValueError("invalid shared namespace")
    expected = f"data/jobs/{actor['job_id']}/attempts/{actor['attempt_id']}"
    if ref["path"] != f"{expected}/shared/{namespace}/{fingerprint}.json":
        raise ValueError("shared receipt identity differs from its attempt path")
    policy = _read_policy(root)
    if policy is not None and actor["claim"]["path"] != f"{expected}/claim.json":
        raise ValueError("shared receipt claim is not its producing control record")
    _metadata_reference(root, actor["claim"], re.escape(f"{expected}/claim.json"))
    from appsec_review.runtime.datasets import read_dataset_contract
    if policy is not None:
        claim = json.loads(_verified_bytes(root, actor["claim"]))
        _, declarations = read_dataset_contract(claim["dataset_contract"], actor["job_id"])
        shared_namespaces = frozenset(claim["dataset_contract"].get("shared_namespaces", ()))
        artifact_patterns = tuple(pattern for declaration in declarations for pattern in declaration.artifacts)
    else:
        claim_path = verify_reference(root, actor["claim"])
        context = current_validation(root)
        claim_key = ("actor-claim", actor["claim"]["path"], _hash(actor["claim"]["sha256"]))
        cached_claim = context.records.get(claim_key) if context is not None else None
        if cached_claim is None:
            claim = json.loads(claim_path.read_bytes())
            _, declarations = read_dataset_contract(claim["dataset_contract"], actor["job_id"])
            shared_namespaces = frozenset(claim["dataset_contract"].get("shared_namespaces", ()))
            artifact_patterns = tuple(pattern for declaration in declarations for pattern in declaration.artifacts)
            if context is not None:
                with context.lock:
                    context.records[claim_key] = (claim, shared_namespaces, artifact_patterns)
        else:
            claim, shared_namespaces, artifact_patterns = cached_claim
    if actor["claim"]["path"] != f"{expected}/claim.json" or any(
        claim.get(key) != actor[key] for key in ("run_id", "job_id", "attempt_id", "orchestration")
    ) or claim.get("attempt_path") != expected or actor["run_id"] != root.name:
        raise ValueError("shared receipt actor differs from its original claim")
    if not (namespace in shared_namespaces
            or any(PurePosixPath(ref["path"]).match(pattern) for pattern in artifact_patterns)):
        raise ValueError("shared receipt is not declared by its pinned attempt contract")
    if not isinstance(value["computation"], dict):
        raise ValueError("invalid shared computation identity")
    producer = value["producer_receipt"]
    original = None
    if value["mode"] == "computed":
        if producer is not None or value["legacy"] is not None:
            raise ValueError("computed receipt cannot invent an earlier producer")
        if value.get("layout") == "named-immutable":
            if namespace not in NAMED_LAYOUTS or not _named_layout(namespace, value["object"]["path"]):
                raise ValueError("shared named object is outside its registered immutable layout")
            if (len(value["dependencies"]) != 1
                    or value["dependencies"][0]["path"] != f"{OBJECTS}/{value['object']['sha256']}"
                    or value["dependencies"][0]["sha256"] != value["object"]["sha256"]):
                raise ValueError("named object lacks its exact-byte content reference")
        elif any(artifact["path"] != f"{OBJECTS}/{artifact['sha256']}"
                 for artifact in (value["object"], *value["dependencies"])):
            raise ValueError("new computations must publish content-addressed objects")
    elif producer is not None:
        original = verify_receipt(root, producer, seen=seen | {ref["path"]})
        if namespace == "shared-input":
            if (fingerprint != hashlib.sha256(canonical_json(producer)).hexdigest()
                    or any(original[key] != value[key] for key in
                           ("object", "dependencies", "computation", "legacy"))
                    or value.get("layout") is not None):
                raise ValueError("shared input reference differs from its selected source")
        elif (original["mode"] != "computed" or any(original[key] != value[key] for key in
                ("namespace", "fingerprint", "object", "dependencies", "computation"))
                or value.get("layout") != original.get("layout") or value["legacy"] is not None):
            raise ValueError("reused receipt differs from producing computation")
    elif value["legacy"] != "unknown-original-producer" and value.get("layout") != "public-feed":
        raise ValueError("reused receipt lacks verified producer or explicit legacy provenance")
    if policy is not None:
        origin, origin_ref, origin_claim = value, ref, claim
        context = current_validation(root)
        if producer is not None:
            origin, origin_claim, origin_ref = context.records[
                ("receipt-origin:" + policy.identity, producer["path"], producer["sha256"])]
        policy.admit_receipt(root, value, origin=origin, origin_claim=origin_claim, origin_ref=origin_ref)
    for artifact in (value["object"], *value["dependencies"]):
        verify_reference(root, artifact)
        if artifact["path"].startswith(OBJECTS + "/") and artifact["path"] != f"{OBJECTS}/{artifact['sha256']}":
            raise ValueError("shared object filename differs from exact byte hash")
    if value["mode"] == "computed" and value.get("layout") == "named-immutable":
        binding = _binding_reference(root, namespace, value["object"])
        if verify_binding(root, binding)["object"] != value["object"]:
            raise ValueError("named immutable object changed after publication")
    if value.get("layout") == "public-feed":
        if namespace != "feed-snapshot":
            raise ValueError("public-feed proof has an invalid namespace")
        from .feed_provenance import verify_feed_receipt
        verify_feed_receipt(root, value, claim)
    if policy is not None:
        context.records[("receipt-origin:" + policy.identity, ref["path"], ref["sha256"])] = (
            origin, origin_claim, origin_ref)
        context.records[("receipt-claim:" + policy.identity, ref["path"], ref["sha256"])] = claim
    return value


@dataclass(frozen=True)
class SharedArtifacts:
    run_root: Path
    attempt_root: Path
    actor: Mapping[str, Any]
    _named_refs: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict, repr=False, compare=False)
    _control_refs: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False, compare=False)
    _input_handoffs: dict[tuple[str, str], Mapping[str, Any]] = field(
        default_factory=dict, repr=False, compare=False)

    @classmethod
    def for_job(cls, context: JobContext) -> SharedArtifacts:
        claim_ref = reference(context.run_root, context.attempt_root / "claim.json")
        claim = json.loads(verify_reference(context.run_root, claim_ref).read_bytes())
        actor = {key: claim[key] for key in ("run_id", "job_id", "attempt_id", "orchestration")}
        original_invocation = dict(actor["orchestration"])
        current_invocation = dict(context.orchestration)
        if original_invocation.get("system") == "dagster" and original_invocation.get("run_id"):
            # Dagster correlates each task with its own node within the same invocation.
            original_invocation.pop("node", None)
            current_invocation.pop("node", None)
        if (actor["run_id"] != context.run_id or actor["attempt_id"] != context.attempt_id
                or actor["job_id"] != context.config.job_id
                or original_invocation != current_invocation):
            raise ValueError("shared publication context differs from original invocation")
        return cls(context.run_root, context.attempt_root, {**actor, "claim": claim_ref})

    def _slot(self, namespace: str, fingerprint: str) -> str:
        if not _NAME.fullmatch(namespace):
            raise ValueError("invalid shared namespace")
        return (self.attempt_root.relative_to(self.run_root).as_posix()
                + f"/shared/{namespace}/{_hash(fingerprint)}.json")

    def _claim(self) -> dict[str, Any]:
        ref = self.actor["claim"]
        if _read_policy(self.run_root) is None:
            return json.loads(verify_reference(self.run_root, ref).read_bytes())
        expected = (self.attempt_root / "claim.json").relative_to(self.run_root).as_posix()
        _metadata_reference(self.run_root, ref, re.escape(expected))
        return json.loads(_verified_bytes(self.run_root, ref))

    def _receipt_value(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
                computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = (),
                mode: str, producer: Mapping[str, Any] | None = None, legacy: str | None = None,
                layout: str | None = None,
                ) -> dict[str, Any]:
        value = {"schema": RECEIPT_SCHEMA, "namespace": namespace, "fingerprint": fingerprint,
                 "actor": dict(self.actor), "mode": mode, "object": dict(obj),
                 "dependencies": list(dependencies), "computation": dict(computation),
                 "producer_receipt": producer, "legacy": legacy}
        if layout is not None:
            value["layout"] = layout
        return value

    def _record(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
                computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = (),
                mode: str, producer: Mapping[str, Any] | None = None, legacy: str | None = None,
                layout: str | None = None,
                ) -> tuple[dict[str, Any], dict[str, Any]]:
        value = self._receipt_value(namespace, fingerprint, obj, computation=computation,
                                    dependencies=dependencies, mode=mode, producer=producer,
                                    legacy=legacy, layout=layout)
        slot = self._slot(namespace, fingerprint)
        _metadata_write_target(self.run_root, self.run_root / slot)
        ref = immutable_bytes(self.run_root, slot, canonical_json(value))
        verify_receipt(self.run_root, ref)
        self._control_refs[ref["path"]] = dict(ref)
        return value, ref

    def computed(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
                 computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = (),
                 layout: str | None = None,
                 ) -> dict[str, Any]:
        _, receipt = self._record(namespace, fingerprint, obj, computation=computation,
                                  dependencies=dependencies, mode="computed", layout=layout)
        request_path = f"{REQUESTS}/{namespace}/{fingerprint}/{receipt['sha256']}.json"
        _metadata_write_target(self.run_root, self.run_root / request_path)
        request = immutable_bytes(self.run_root, request_path,
                                  canonical_json({"schema": REQUEST_SCHEMA, "receipt": receipt}))
        self._control_refs[request["path"]] = dict(request)
        return receipt

    def _requests(self, namespace: str, fingerprint: str):
        directory = safe_path(self.run_root, f"{REQUESTS}/{namespace}/{_hash(fingerprint)}")
        if not directory.exists():
            return
        for path in sorted(directory.iterdir()):
            candidate = verify_request(self.run_root, _control_reference(
                self.run_root, path, expected=self._control_refs.get(path.relative_to(self.run_root).as_posix())))
            yield candidate, verify_receipt(self.run_root, candidate)

    def lookup(self, namespace: str, fingerprint: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        from appsec_review.runtime.repair import ComputationAdmission, IncompatibleComputation
        claim = self._claim()
        admission = ComputationAdmission.for_repair(self.run_root, claim)
        slot = safe_path(self.run_root, self._slot(namespace, fingerprint))
        if slot.exists():
            relative = slot.relative_to(self.run_root).as_posix()
            policy = _read_policy(self.run_root)
            expected = self._control_refs.get(relative)
            if policy is not None and expected is None:
                expected = policy.metadata_reference(self.run_root, relative)
                if expected is None:
                    sources = list(self._requests(namespace, fingerprint))
                    if len(sources) == 1:
                        producer, original = sources[0]
                        payload = canonical_json(self._receipt_value(
                            namespace, fingerprint, original["object"], computation=original["computation"],
                            dependencies=tuple(original["dependencies"]), mode="reused", producer=producer,
                            layout=original.get("layout")))
                        expected = {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(),
                                    "size_bytes": len(payload)}
            ref = _control_reference(self.run_root, slot, expected=expected)
            value = verify_receipt(self.run_root, ref)
            if admission is not None:
                admission.verify(self.run_root, value)
            if value["mode"] == "computed":
                self.computed(namespace, fingerprint, value["object"], computation=value["computation"],
                              dependencies=tuple(value["dependencies"]), layout=value.get("layout"))
            return value, ref
        candidates = []
        for candidate, value in self._requests(namespace, fingerprint):
            actor = value.get("actor", {})
            if (claim.get("recovery_boundary") == "whole_job"
                    and actor.get("job_id") == self.actor["job_id"]
                    and actor.get("attempt_id") != self.actor["attempt_id"]):
                continue
            if claim.get("recovery_boundary") == "whole_job" and actor.get("job_id") != self.actor["job_id"]:
                upstream = actor.get("job_id")
                pin = claim.get("upstream_handoffs", {}).get(upstream)
                if pin is None:
                    continue
                from appsec_review.runtime.consume import accepted_upstream
                accepted = accepted_upstream(self.run_root, upstream, required=False)
                if (accepted is None or accepted.sha256 != pin
                        or accepted.as_tuple()[0]["attempt_id"] != actor.get("attempt_id")):
                    continue
            if admission is not None:
                try:
                    admission.verify(self.run_root, value)
                except IncompatibleComputation as exc:
                    from appsec_review.observability import PipelineLog
                    PipelineLog(self.run_root).write(
                        "CHECKPOINT_MISSED", run_id=self.actor["run_id"], job_id=self.actor["job_id"],
                        attempt_id=self.actor["attempt_id"], message=str(exc),
                        details={"producer_receipt": candidate})
                    continue
            candidates.append((candidate, value))
        if not candidates:
            return None
        # Stable among the complete candidates visible to this lookup. Once selected, the
        # attempt's receipt never changes when later computations publish another result.
        producer, value = candidates[0]
        return self._record(namespace, fingerprint, value["object"], computation=value["computation"],
                            dependencies=tuple(value["dependencies"]), mode="reused", producer=producer,
                            layout=value.get("layout"))

    def named(self, namespace: str, path: Path, *, computed: bool,
              computation: Mapping[str, Any] | None = None,
              expected_sha256: str | None = None) -> dict[str, Any]:
        """Record an explicitly registered immutable layout without copying its bytes."""
        if not computed:
            _admit_target(self.run_root, path, expected_sha256)
        policy = _read_policy(self.run_root)
        if not computed and policy is not None and expected_sha256 is not None:
            relative = path.relative_to(self.run_root).as_posix()
            fingerprint = hashlib.sha256(canonical_json({
                "namespace": namespace, "path": relative, "sha256": expected_sha256})).hexdigest()
            cached = self._named_refs.get((namespace, fingerprint))
            if cached is not None:
                # Only the receipt identity is retained. Its bytes, lineage and current grants
                # are verified again on every read.
                value = verify_receipt(self.run_root, cached)
                if (value["namespace"], value["fingerprint"], value["object"]["path"],
                        value["object"]["sha256"], value["actor"]) != (
                        namespace, fingerprint, relative, expected_sha256, dict(self.actor)):
                    raise ValueError("named receipt differs from the requested publication")
                claim = current_validation(self.run_root).records[
                    ("receipt-claim:" + policy.identity, cached["path"], cached["sha256"])]
                from appsec_review.runtime.repair import ComputationAdmission
                admission = ComputationAdmission.for_repair(self.run_root, claim)
                if admission is not None:
                    admission.verify(self.run_root, value)
                return dict(cached)
        obj = reference(self.run_root, path, expected_sha256=expected_sha256)
        if namespace not in NAMED_LAYOUTS or not _named_layout(namespace, obj["path"]):
            raise ValueError("unregistered named immutable publication")
        fingerprint = hashlib.sha256(canonical_json(
            {"namespace": namespace, "path": obj["path"], "sha256": obj["sha256"]})).hexdigest()
        if computed:
            content = _link(self.run_root, path, f"{OBJECTS}/{obj['sha256']}", obj["sha256"])
            immutable_bytes(self.run_root, _binding_path(namespace, obj), canonical_json({
                "schema": "appsec-review/shared-named/1", "namespace": namespace, "object": obj}))
            return self.computed(namespace, fingerprint, obj, computation=computation or {},
                                 dependencies=(content,), layout="named-immutable")
        binding = safe_path(self.run_root, _binding_path(namespace, obj))
        if binding.exists():
            if verify_binding(self.run_root, _binding_reference(self.run_root, namespace, obj))["object"] != obj:
                raise ValueError("named immutable object changed after publication")
        hit = self.lookup(namespace, fingerprint)
        if hit is not None:
            if policy is not None:
                self._named_refs[(namespace, fingerprint)] = dict(hit[1])
            return hit[1]
        claim = self._claim()
        if (claim.get("repair_admission_sha256")
                and safe_path(self.run_root, f"{REQUESTS}/{namespace}/{fingerprint}").exists()):
            raise ValueError("repair cannot relabel an unresolved or incompatible named computation as legacy; "
                             "regenerate it with a new computation identity or use a successor run")
        if claim.get("recovery_boundary") == "whole_job" and binding.exists():
            for _, value in self._requests(namespace, fingerprint):
                actor = value.get("actor", {})
                if (actor.get("job_id") == self.actor["job_id"]
                        and actor.get("attempt_id") != self.actor["attempt_id"]
                        and value.get("object") == obj):
                    return dict(obj)
        if binding.exists():
            raise ValueError("named immutable publication has no complete producer receipt")
        receipt = self.legacy(namespace, fingerprint, obj, computation=computation or {})[1]
        if policy is not None:
            self._named_refs[(namespace, fingerprint)] = dict(receipt)
        return receipt

    def legacy(self, namespace: str, fingerprint: str, obj: Mapping[str, Any], *,
               computation: Mapping[str, Any], dependencies: tuple[Mapping[str, Any], ...] = ()
               ) -> tuple[dict[str, Any], dict[str, Any]]:
        return self._record(namespace, fingerprint, obj, computation=computation, dependencies=dependencies,
                            mode="reused", legacy="unknown-original-producer")

    def consume_receipt(self, source: Mapping[str, Any]) -> dict[str, Any]:
        value = verify_receipt(self.run_root, source)
        if value.get("layout") == "public-feed":
            from .feed_provenance import consume_pin
            proof = _read(self.run_root, value["object"])
            from .feed_provenance import _configured_root
            root, _ = _configured_root(self.run_root, _read(self.run_root, self.actor["claim"]),
                                       proof["feed_id"])
            with publication_scope_for_owner(self):
                consumed = consume_pin(self.run_root, {
                    "feed_id": proof["feed_id"],
                    "snapshot_id": Path(proof["manifest"]["path"]).parent.name,
                    "manifest_sha256": proof["manifest"]["sha256"],
                    "directory": str(root / Path(proof["manifest"]["path"]).parent),
                    "provenance": source}, observe=False)
            if consumed is None:
                raise ValueError("claimed feed consumer did not record its use")
            return consumed
        while value["producer_receipt"] is not None:
            source = value["producer_receipt"]
            value = verify_receipt(self.run_root, source)
        if value["actor"] == self.actor:
            return dict(source)
        fingerprint = hashlib.sha256(canonical_json(source)).hexdigest()
        return self._record("shared-input", fingerprint, value["object"],
                            computation=value["computation"], dependencies=tuple(value["dependencies"]),
                            mode="reused", producer=source, legacy=value["legacy"])[1]

    def consume_named_input(self, namespace: str, obj: Mapping[str, Any]) -> bool:
        from appsec_review.runtime.inputs import supplied_named_receipts
        from appsec_review.runtime.repair import verify_publication
        fingerprint = hashlib.sha256(canonical_json(
            {"namespace": namespace, "path": obj["path"], "sha256": obj["sha256"]})).hexdigest()
        for handoff, digest, ref in supplied_named_receipts(
                self.run_root, namespace, fingerprint, claim=self._claim(), cache=self._input_handoffs):
            value = _read(self.run_root, ref)
            if value.get("schema") != RECEIPT_SCHEMA:
                raise ValueError("supplied named input provenance is not a shared receipt")
            if value.get("object") != obj:
                continue
            verify_publication(self.run_root, handoff, digest)
            self.consume_receipt(ref)
            return True
        return False


def verify_request(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    _metadata_reference(root, ref, r"data/shared/requests/[a-zA-Z0-9_-]+/[0-9a-f]{64}/[0-9a-f]{64}\.json")
    request = _read(root, ref)
    if request.get("schema") != REQUEST_SCHEMA:
        raise ValueError("invalid shared request schema")
    receipt = request["receipt"]
    value = verify_receipt(root, receipt)
    expected = f"{REQUESTS}/{value['namespace']}/{value['fingerprint']}/{receipt['sha256']}.json"
    if ref["path"] != expected or value["mode"] != "computed":
        raise ValueError("shared request does not identify a producing receipt")
    return receipt


@validation_operation
def attempt_artifacts(root: Path, attempt_root: Path) -> list[dict[str, Any]]:
    """Verify and return the complete receipt closure for handoff/resume integrity."""
    artifacts: dict[str, dict[str, Any]] = {}
    visited: set[tuple[str, str]] = set()

    def collect(ref: Mapping[str, Any]) -> None:
        receipt_key = (ref["path"], ref["sha256"])
        if receipt_key in visited:
            return
        visited.add(receipt_key)
        value = verify_receipt(root, ref)
        for artifact in (ref, value["actor"]["claim"], value["object"], *value["dependencies"]):
            artifacts[artifact["path"]] = dict(artifact)
        if value.get("layout") == "named-immutable":
            binding = _binding_reference(root, value["namespace"], value["object"])
            artifacts[binding["path"]] = binding
        if value["producer_receipt"]:
            collect(value["producer_receipt"])

    directory = attempt_root / "shared"
    if directory.exists() or directory.is_symlink():
        safe_path(root, directory.relative_to(root).as_posix())
        for namespace in sorted(directory.iterdir()):
            safe_path(root, namespace.relative_to(root).as_posix())
            if not namespace.is_dir() or not _NAME.fullmatch(namespace.name):
                raise ValueError("invalid shared receipt directory")
            for path in sorted(namespace.iterdir()):
                collect(_control_reference(root, path))
    return list(artifacts.values())


@validation_operation
def verify_handoff(root: Path, handoff: Mapping[str, Any]) -> None:
    from appsec_review.interchange import decode_handoff
    from appsec_review.runtime.handoff import verify_handoff_integrity
    handoff = decode_handoff(handoff, run_id=root.name)
    from .admission import consume_admission
    admitted = consume_admission(root, handoff)
    verify_handoff_integrity(root, handoff)
    if admitted:
        return
    verify_attempt_provenance(root, handoff["resolving_paths"]["attempt"], handoff["artifacts"])


def verify_attempt_provenance(root: Path, attempt_path: str, artifacts: list[Mapping[str, Any]]) -> None:
    """Verify pinned shared artifacts and require every attempt-owned provenance file to be pinned."""
    attempt = safe_path(root, attempt_path)
    pinned = {item["path"]: item for item in artifacts}
    for artifact in artifacts:
        if artifact["path"].startswith(OBJECTS + "/"):
            verify_reference(root, artifact)
        elif re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", artifact["path"]):
            verify_receipt(root, artifact)
    for artifact in attempt_artifacts(root, attempt):
        if pinned.get(artifact["path"]) != artifact:
            raise ValueError(f"shared provenance missing from handoff: {artifact['path']}")


def consume_handoff(root: Path, handoff: Mapping[str, Any]) -> None:
    from appsec_review.runtime.inputs import observe_handoff
    observe_handoff(root, handoff)
    owner = current()
    if owner is not None:
        if owner.run_root != root:
            raise ValueError("shared input handoff belongs to another run")
        for artifact in handoff["artifacts"]:
            if re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", artifact["path"]):
                owner.consume_receipt(artifact)


def audit_file(root: Path, relative: str) -> None:
    """Validate registered shared files; declaration never substitutes for integrity."""
    ref = reference(root, safe_path(root, relative))
    if relative.startswith(OBJECTS + "/"):
        if relative != f"{OBJECTS}/{_hash(Path(relative).name)}" or ref["sha256"] != Path(relative).name:
            raise ValueError("shared object exact-byte identity mismatch")
    elif relative.startswith(REQUESTS + "/"):
        verify_request(root, ref)
    elif relative.startswith(NAMED + "/"):
        verify_binding(root, ref)
    elif re.fullmatch(r"data/jobs/[^/]+/attempts/[^/]+/shared/[^/]+/[^/]+\.json", relative):
        verify_receipt(root, ref)
    else:
        raise ValueError("undeclared shared artifact")


def current() -> SharedArtifacts | None:
    return _ACTIVE.get()


class PublicationThreadPoolExecutor(ThreadPoolExecutor):
    """Preserve the invoking attempt across explicitly parallel producer tasks."""

    def submit(self, fn, /, *args, **kwargs):
        from appsec_review.runtime.execution_safety import operation

        def guarded():
            with operation(f"thread.{getattr(fn, '__name__', type(fn).__name__)}"):
                return fn(*args, **kwargs)
        return super().submit(copy_context().run, guarded)


@contextmanager
def publication_scope(context: JobContext):
    """Bind provenance only for the explicit immutable writers using this module."""
    from appsec_review.runtime.scope import review_scope
    from appsec_review.runtime.resources import review_resource_scope
    from appsec_review.container_runtime.image_builder import image_builder_scope
    from appsec_review.container_runtime.native_client import native_engine_scope
    from appsec_review.runtime.inputs import input_read_scope
    with input_read_scope(context), \
            review_resource_scope(context.metadata_root, context.review_policy.resources, context.events,
                                  dispatch=(context.orchestration.get("run_id")
                                            if context.orchestration.get("system") == "dagster" else None)), \
            image_builder_scope(context), \
            native_engine_scope(context), \
            review_scope(context.repository_root, context.run_root, context.target_root), validation_scope(
            context.run_root, target_snapshot=getattr(context, "evidence_target_snapshot", None) or context.source_fingerprint,
            policy_identity=hashlib.sha256(canonical_json(context.review_policy.view())).hexdigest()), \
            publication_scope_for_owner(SharedArtifacts.for_job(context)):
        yield


@contextmanager
def publication_scope_for_owner(owner: SharedArtifacts):
    token = _ACTIVE.set(owner)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def publish_named(root: Path, path: Path, payload: bytes, *, namespace: str,
                  computation: Mapping[str, Any] | None = None,
                  shared: SharedArtifacts | None = None) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    safe_path(root, relative)
    if namespace not in NAMED_LAYOUTS:
        raise ValueError("unregistered named immutable publication")
    owner = shared or current()
    if owner is not None:
        if owner.run_root != root or not _named_layout(namespace, relative):
            raise ValueError("immutable publication belongs to another run")
        content = put_bytes(root, payload)
        obj = _link(root, verify_reference(root, content), relative, content["sha256"])
        owner.named(namespace, path, computed=True, computation=computation)
    else:
        obj = immutable_bytes(root, relative, payload)
    return obj


def consume_named(root: Path, path: Path, *, namespace: str,
                  shared: SharedArtifacts | None = None,
                  expected_sha256: str | None = None) -> None:
    owner = shared or current()
    if namespace not in NAMED_LAYOUTS:
        raise ValueError("unregistered named immutable consumption")
    safe_path(root, path.relative_to(root).as_posix())
    _admit_target(root, path, expected_sha256)
    obj = reference(root, path, expected_sha256=expected_sha256)
    binding = safe_path(root, _binding_path(namespace, obj))
    if binding.exists():
        if verify_binding(root, _binding_reference(root, namespace, obj))["object"] != obj:
            raise ValueError("named immutable object changed after publication")
        fingerprint = hashlib.sha256(canonical_json(
            {"namespace": namespace, "path": obj["path"], "sha256": obj["sha256"]})).hexdigest()
        candidates = safe_path(root, f"{REQUESTS}/{namespace}/{fingerprint}")
        if owner is None:
            paths = sorted(candidates.iterdir()) if candidates.exists() else []
            if not paths:
                raise ValueError("named immutable publication has no complete producer receipt")
            for candidate in paths:
                verify_request(root, _control_reference(root, candidate))
    if owner is not None:
        if owner.run_root != root:
            raise ValueError("immutable consumption belongs to another run")
        if owner.consume_named_input(namespace, obj):
            return
        owner.named(namespace, path, computed=False, expected_sha256=obj["sha256"])
