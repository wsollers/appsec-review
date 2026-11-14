"""Bounded custody and immutable publication for the protected projection sidecar."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterator, Mapping
import uuid

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import consume_named, current, safe_path

from . import contracts as c
from .metadata import POLICY_VERSION, build_publication, policy_document


class AuditUnavailable(RuntimeError):
    """An explicit capability/capacity limitation, never an integrity failure."""

    def __init__(self, detail: str):
        super().__init__(detail)
        self.reason = ("disabled" if detail == "disabled" else
                       "input_unavailable" if detail.startswith("input_unavailable") else "capacity_exceeded")


@dataclass(frozen=True)
class PublishedAudit:
    manifest: c.ManifestRef | None
    metadata_artifact: Mapping[str, Any]
    artifacts: tuple[Mapping[str, Any], ...]
    source_artifacts: tuple[Mapping[str, Any], ...] = ()

    def unit_output(self) -> dict[str, Any]:
        return {"metadata_path": self.metadata_artifact["path"],
                "audit_metadata_artifact": dict(self.metadata_artifact),
                "audit_artifacts": [dict(ref) for ref in self.artifacts],
                "audit_source_artifacts": [dict(ref) for ref in self.source_artifacts]}


def publish_descriptor(*, run_root: Path, attempt_root: Path, origin: c.Origin,
                       settings: DecisionAuditSettings, manifest: c.ManifestRef | None = None,
                       artifacts: tuple[Mapping[str, Any], ...] = (),
                       unavailable_reason: str | None = None) -> PublishedAudit:
    """Pin through existing metadata_path/collect_artifacts, without new control keys."""
    directory = audit_directory(run_root, attempt_root, origin)
    if manifest is not None and manifest.path != directory + "/manifest.json":
        raise IntegrityError("manifest is outside the exact audit directory")
    if len({ref["path"] for ref in artifacts}) != len(artifacts) or any(
            not ref["path"].startswith(directory + "/") or ref["path"] == directory + "/publication.json"
            for ref in artifacts):
        raise IntegrityError("publication artifact membership is not exact")
    if manifest is not None and not any(
            (ref["path"], ref["sha256"]) == (manifest.path, manifest.sha256) for ref in artifacts):
        raise IntegrityError("publication does not pin its manifest artifact")
    if manifest is None and artifacts:
        raise IntegrityError("unavailable publication cannot claim payload artifacts")
    body = build_publication(origin, settings=settings, manifest=manifest, unavailable_reason=unavailable_reason)
    data = canonical_json(body)
    path = directory + "/publication.json"
    _write(run_root, path, data)
    ref = {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    return PublishedAudit(manifest, ref, artifacts)


def audit_directory(run_root: Path, attempt_root: Path, origin: c.Origin) -> str:
    root = Path(run_root).absolute()
    expected = f"data/jobs/job_inference_security_review/attempts/{origin.review_attempt_id}"
    if root.name != origin.run_id or Path(attempt_root).absolute() != root / expected or root != root.resolve():
        raise IntegrityError("decision audit has a foreign run or attempt")
    try:
        safe_path(root, expected)
    except ValueError as exc:
        raise IntegrityError("decision audit attempt custody failed") from exc
    return expected + "/artifacts/decision-audit"


@contextmanager
def _directory(root: Path, relative: str, *, create: bool = False) -> Iterator[tuple[int, str]]:
    """Walk held directory descriptors, never following a replaced directory symlink."""
    try:
        safe_path(root, relative)
        parts = (Path(root).absolute() / relative).parts
        fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[1:-1]:
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd, parts[-1]
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise IntegrityError("decision audit path custody failed") from exc


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError("duplicate JSON field in audit input")
        result[key] = value
    return result


class BoundReader:
    """Hash exact bytes once per pin; all reads share the configured aggregate budget."""

    def __init__(self, run_root: Path, settings: DecisionAuditSettings):
        self.root = Path(run_root).absolute()
        self.remaining = settings.max_input_bytes
        self.cache: dict[str, tuple[str, bytes]] = {}

    def read(self, reference: Mapping[str, Any], *, namespace: str | None = None) -> bytes:
        path, digest = reference.get("path"), reference.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str) or len(digest) != 64:
            raise IntegrityError("malformed audit input reference")
        if path in self.cache:
            previous, data = self.cache[path]
            if previous != digest:
                raise IntegrityError("conflicting audit input hashes")
            if "size_bytes" in reference and (type(reference["size_bytes"]) is not int
                                              or reference["size_bytes"] != len(data)):
                raise IntegrityError("audit input size differs from its reference")
            if namespace is not None and current() is not None:
                consume_named(self.root, self.root / path, namespace=namespace, expected_sha256=digest)
            return data
        with _directory(self.root, path) as (parent, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise IntegrityError("audit input is not a regular file")
                data = stream.read(self.remaining + 1)
        if len(data) > self.remaining:
            raise AuditUnavailable("max_input_bytes")
        if hashlib.sha256(data).hexdigest() != digest:
            raise IntegrityError("audit input bytes changed after acceptance")
        if "size_bytes" in reference and (type(reference["size_bytes"]) is not int
                                          or reference["size_bytes"] != len(data)):
            raise IntegrityError("audit input size differs from its reference")
        self.remaining -= len(data)
        if namespace is not None and current() is not None:
            consume_named(self.root, self.root / path, namespace=namespace, expected_sha256=digest)
        self.cache[path] = (digest, data)
        return data

    def json(self, reference: Mapping[str, Any], *, namespace: str | None = None) -> Mapping[str, Any]:
        try:
            value = json.loads(self.read(reference, namespace=namespace), object_pairs_hook=_object)
        except (ValueError, UnicodeDecodeError) as exc:
            raise IntegrityError("invalid JSON in audit input") from exc
        if not isinstance(value, dict):
            raise IntegrityError("audit input requires an object")
        return value


def _write(root: Path, path: str, payload: bytes) -> None:
    with _directory(root, path, create=True) as (parent, name):
        temporary = ".audit-" + uuid.uuid4().hex
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                old = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                with os.fdopen(old, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or stream.read(len(payload) + 1) != payload:
                        raise IntegrityError("changed immutable audit publication")
            os.fsync(parent)
        finally:
            os.unlink(temporary, dir_fd=parent)


def publish_bundle(*, run_root: Path, attempt_root: Path, origin: c.Origin,
                   settings: DecisionAuditSettings, records: tuple[c.Product, ...],
                   coverage: tuple[c.CoverageCount, ...],
                   continuations: Mapping[str, tuple[c.SourceRef | c.RelationRef, ...]],
                   artifact_sink: list[Mapping[str, Any]] | None = None,
                   byte_budget: int | None = None) -> c.ManifestRef:
    """Validate the *entire* bundle before writing any file; publish its manifest last."""
    directory = audit_directory(run_root, attempt_root, origin)
    if not settings.enabled:
        raise AuditUnavailable("disabled")
    if (origin.projection_policy_version != POLICY_VERSION
            or origin.projection_policy_sha256 != policy_document(settings)["sha256"]):
        raise IntegrityError("publication policy differs from accepted origin")
    if len(records) + sum(len(rows) for rows in continuations.values()) > settings.max_records:
        raise AuditUnavailable("max_records")
    shards: dict[str, tuple[c.Product, ...]] = {}
    refs = []
    for kind, cls in ((c.ProductKind.DECISION, c.DecisionRecord),
                      (c.ProductKind.VERIFICATION, c.VerificationRecord),
                      (c.ProductKind.BASIS, c.DecisionBasisRecord)):
        group: list[c.Product] = []
        size = 0

        def finish() -> None:
            path = f"{directory}/{kind}/{len(shards):06d}.jsonl"
            shards[path] = tuple(group)
            refs.append(c.make_shard(path, group))

        for record in sorted((item for item in records if isinstance(item, cls)), key=lambda item: item.record_id):
            length = len(c.canonical_bytes(record))
            if length > settings.shard_bytes:
                raise AuditUnavailable("record_exceeds_shard_bytes")
            if group and (len(group) >= settings.shard_records or size + length > settings.shard_bytes):
                finish()
                group, size = [], 0
            group.append(record)
            size += length
        if group:
            finish()
    manifest = c.AuditManifest(origin, tuple(refs), coverage)
    reference = c.ManifestRef.of(directory + "/manifest.json", manifest)
    c.validate_bundle(manifest, shards, expected_origin=origin, manifest_reference=reference,
                      continuations=continuations)
    payloads = {path: b"".join(c.canonical_bytes(row) for row in rows) for path, rows in shards.items()}
    for record in records:
        for ref in record.context.continuations:
            if not ref.path.startswith(directory + "/continuations/") or not ref.path.endswith(".jsonl"):
                raise IntegrityError("continuation is outside the exact audit directory")
            payloads[ref.path] = c.reference_bytes(ref.field, continuations[ref.path],
                                                  origin=origin, claim_id=record.context.subject.claim_id)
    payloads[reference.path] = c.canonical_bytes(manifest)
    descriptor_bytes = len(canonical_json(build_publication(origin, settings=settings, manifest=reference)))
    if sum(map(len, payloads.values())) + descriptor_bytes > (
            settings.max_input_bytes if byte_budget is None else byte_budget):
        raise AuditUnavailable("max_input_bytes:verification_bundle")
    for path in sorted(set(payloads) - {reference.path}):
        _write(Path(run_root), path, payloads[path])
    _write(Path(run_root), reference.path, c.canonical_bytes(manifest))
    if artifact_sink is not None:
        artifact_sink.extend({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                             for path, data in sorted(payloads.items()))
    return reference
