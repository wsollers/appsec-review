"""Application-private, authenticated admission records for managed evidence consumers."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import tempfile
from copy import deepcopy
from typing import Any, Mapping

from appsec_review.config.assurance import AssuranceMode, VALIDATION_VERSION
from .atomic import canonical_json, file_sha256
from .lock import bounded_file_lock
from .validation import current_validation, validation_scope, verified_digest


_DOCUMENT_CACHE_BYTES = 1024 * 1024
_CUSTODY_DURABILITY = "fsync-inodes-and-parents/1"


def _sync_directories(directories: set[Path], boundary: Path) -> None:
    parents: set[Path] = set()
    for directory in directories:
        if directory != boundary and not directory.is_relative_to(boundary):
            raise ValueError("durability directory escapes admission custody")
        while True:
            parents.add(directory)
            if directory == boundary:
                break
            directory = directory.parent
    for directory in sorted(parents, key=lambda value: (-len(value.parts), str(value))):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _sync_admission_artifacts(root: Path, paths: list[Path], detached: set[Path]) -> None:
    synced: set[tuple[int, int]] = set()
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or (path in detached and metadata.st_mode & 0o222)):
                raise ValueError("admission artifact lost custody before durability barrier")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity not in synced:
                os.fsync(descriptor)
                synced.add(identity)
        finally:
            os.close(descriptor)
    _sync_directories({path.parent for path in paths}, root.parent)


def _private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("admission custody directory is unavailable or indirect")
    metadata = path.stat()
    if os.name == "posix" and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o022):
        raise ValueError("admission requires application-owned, non-shared directory custody")


def _key(root: Path, *, create: bool) -> bytes:
    directory = root.parent / "metadata" / "evidence-admission"
    if directory.is_symlink():
        raise ValueError("admission custody directory must not be a symlink")
    if create:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for parent in (root, root.parent, root.parent / "metadata", directory):
        _private_directory(parent)
    path = directory / "authentication.key"
    with bounded_file_lock(directory / "key.lock", 30):
        if create and not path.exists():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directories({directory}, root.parent)
        if path.is_symlink() or not path.is_file():
            raise ValueError("managed evidence admission key is unavailable")
        metadata = path.stat()
        if os.name == "posix" and (
                metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise ValueError("managed evidence admission key lacks private application custody")
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError("invalid evidence admission key")
        return key


def publish_projection(root: Path, relative: str, body: Mapping[str, Any]) -> None:
    from .shared import immutable_bytes
    key = _key(root, create=True)
    signature = hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()
    immutable_bytes(root.parent / "metadata", relative, canonical_json({
        "body": body, "authentication": signature}))


def read_projection(root: Path, relative: str) -> Mapping[str, Any]:
    from .shared import safe_path
    path = safe_path(root.parent / "metadata", relative)
    if not path.is_file():
        raise ValueError("validated assembly projection is missing; strict re-admission is required")
    record = json.loads(path.read_bytes())
    body, signature = record.get("body"), record.get("authentication")
    expected = hmac.new(_key(root, create=False), canonical_json(body), hashlib.sha256).hexdigest()
    if not isinstance(body, dict) or not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise ValueError("validated assembly projection authentication failed")
    return body


def _frozen(root: Path) -> tuple[dict[str, Any], str]:
    from .shared import safe_path
    from appsec_review.runtime.scope import require_hashable_evidence
    from appsec_review.observability.spans import count_work
    manifest = json.loads(safe_path(root, "data/configuration/manifest.json").read_bytes())
    path = safe_path(root, "data/configuration/resolved.json")
    require_hashable_evidence(path)
    payload = path.read_bytes()
    validation = current_validation(root)
    cache_key = ("admission-configuration", "data/configuration/resolved.json", "")
    cached = None
    if validation is not None:
        with validation.lock:
            cached = validation.records.get(cache_key)
    if cached is not None and cached[0] == payload:
        _, policy, digest = cached
    else:
        digest = hashlib.sha256(payload).hexdigest()
        count_work("target_hash_bytes", len(payload))
        count_work("target_hash_objects")
        policy = json.loads(payload).get("review_policy", {})
    if digest != manifest.get("resolved_sha256"):
        raise ValueError("managed evidence configuration identity mismatch")
    if validation is not None and len(payload) <= _DOCUMENT_CACHE_BYTES:
        with validation.lock:
            validation.records[cache_key] = (payload, policy, digest)
    return deepcopy(policy), digest


def claim_identity(claim: Mapping[str, Any]) -> dict[str, Any]:
    # Dagster adds scheduling annotations and changes the current op name between processes.
    annotations = {"managed_claim_authentication", "graph_started_at", "prior_graph_completion_status",
                   "completed_handoffs", "resume_decisions"}
    body = {key: value for key, value in claim.items() if key not in annotations}
    body["orchestration"] = {key: value for key, value in claim.get("orchestration", {}).items()
                             if key != "node"}
    return body


def sign_claim(root: Path, claim: Mapping[str, Any]) -> str:
    """Seal a prepared managed claim in application custody, outside worker authority."""
    return hmac.new(_key(root, create=False), canonical_json({
        "schema": "appsec-review/managed-claim/1", "claim": claim_identity(claim)}), hashlib.sha256).hexdigest()


def verify_claim(root: Path, claim: Mapping[str, Any]) -> None:
    policy, digest = _frozen(root)
    if (claim.get("run_id") != root.name or claim.get("review_policy") != policy
            or claim.get("resolved_config_sha256") != digest):
        raise ValueError("managed attempt claim run or frozen policy mismatch")
    signature = claim.get("managed_claim_authentication")
    if not isinstance(signature, str) or not hmac.compare_digest(signature, sign_claim(root, claim)):
        raise ValueError("managed attempt claim authentication failed; strict re-admission is required")


def _upstream_records(context: Any, handoffs: Mapping[str, str]) -> list[tuple[str, str, Any]]:
    from appsec_review.retrieval.core import _accepted_handoff
    if not isinstance(handoffs, Mapping):
        raise ValueError("claimed upstream handoffs must be a mapping")
    policy, _ = _frozen(context.run_root)
    if policy != context.review_policy.view():
        raise ValueError("managed consumer differs from frozen policy")
    records = []
    validation = current_validation(context.run_root)
    for job_id, digest in sorted(handoffs.items()):
        if validation is not None:
            with validation.lock:
                cached = validation.records.get(("upstream-admission", job_id, digest))
            if isinstance(cached, Mapping):
                if context.source_fingerprint == "none" and "handoff_binding" not in cached:
                    raise ValueError("target-independent evidence requires authenticated upstream origin")
                records.append((job_id, digest, cached))
                continue
        handoff, _ = _accepted_handoff(context.run_root, job_id, digest)
        if (context.source_fingerprint != "none"
                and handoff.get("source_fingerprint") not in {"none", context.source_fingerprint}):
            raise ValueError("claimed upstream admission belongs to a different target")
        record = _read_admission(context.run_root, handoff)
        if context.source_fingerprint == "none" and (
                record is None or "handoff_binding" not in record):
            raise ValueError("target-independent evidence requires authenticated upstream origin")
        records.append((job_id, digest, record))
    return records


def _evidence_snapshot(context: Any, records: list[tuple[str, str, Any]]) -> str:
    if context.source_fingerprint == "none":
        from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS, TARGET_INDEPENDENT_METADATA_JOBS
        if context.target_root is not None or context.config.job_id not in TARGET_INDEPENDENT_JOBS:
            raise ValueError("managed absent-target claim is not a target-independent job")
        snapshots = {record["target_snapshot"] for _, _, record in records
                     if record is not None and record["target_snapshot"] != "none"}
        if len(snapshots) > 1:
            raise ValueError("claimed upstream admission belongs to a different target")
        if not snapshots and context.config.job_id not in TARGET_INDEPENDENT_METADATA_JOBS:
            raise ValueError("target-independent consumer requires an authenticated target origin")
        return next(iter(snapshots), "none")
    snapshot = context.source_fingerprint
    if any(record is not None and record["target_snapshot"] not in {"none", snapshot}
           for _, _, record in records):
        raise ValueError("claimed upstream admission belongs to a different target")
    return snapshot


def resolve_evidence_target(context: Any, handoffs: Mapping[str, str]) -> str:
    """Derive target trust only from the explicitly selected authenticated publications."""
    if context.review_policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
        return _evidence_snapshot(context, _upstream_records(context, handoffs))
    from appsec_review.retrieval.core import _accepted_handoff
    from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS, TARGET_INDEPENDENT_METADATA_JOBS
    from .shared import verify_handoff
    snapshots = set()
    for job_id, digest in sorted(handoffs.items()):
        handoff, _ = _accepted_handoff(context.run_root, job_id, digest)
        verify_handoff(context.run_root, handoff)
        if handoff["target_snapshot"] != "none":
            snapshots.add(handoff["target_snapshot"])
    if len(snapshots) > 1:
        raise ValueError("claimed upstream handoffs disagree on the target snapshot")
    if context.source_fingerprint != "none":
        if snapshots - {context.source_fingerprint}:
            raise ValueError("claimed upstream handoff belongs to a different target")
        return context.source_fingerprint
    if context.config.job_id in TARGET_INDEPENDENT_JOBS:
        if context.target_root is not None:
            raise ValueError("absent-target claim cannot grant target access")
        if not snapshots and context.config.job_id not in TARGET_INDEPENDENT_METADATA_JOBS:
            raise ValueError("target-independent consumer requires a verified target origin")
        return next(iter(snapshots), "none")
    return "none"


def admit_upstreams(context: Any, handoffs: Mapping[str, str]) -> None:
    """Restore claimed publications atomically after checking their shared evidence binding."""
    if context.review_policy.mode is not AssuranceMode.FIRST_PARTY_MANAGED:
        return
    validation = current_validation(context.run_root)
    if validation is None:
        raise ValueError("upstream admission requires an operation-scoped validation context")
    records = _upstream_records(context, handoffs)
    snapshot = _evidence_snapshot(context, records)
    if snapshot != (getattr(context, "evidence_target_snapshot", None) or context.source_fingerprint):
        raise ValueError("claimed upstream evidence binding changed")
    policy_identity = hashlib.sha256(canonical_json(context.review_policy.view())).hexdigest()
    with validation.lock:
        if (validation.target_snapshot not in ("unknown", snapshot)
                or validation.policy_identity not in ("strict-legacy", policy_identity)):
            raise ValueError("managed admission differs from operation policy or snapshot")
        # Preflight every record before any can grant an operation-local payload exemption.
        for _, _, record in records:
            if record is not None:
                _check_admitted_outputs(context.run_root, record)
        validation.target_snapshot = snapshot
        validation.policy_identity = policy_identity
        for job_id, digest, record in records:
            if record is not None:
                _activate_admission(validation, record)
                validation.records[("upstream-admission", job_id, digest)] = record


def create_admission(context: Any, handoff: Mapping[str, Any]) -> dict[str, Any] | None:
    if context.review_policy.mode is not AssuranceMode.FIRST_PARTY_MANAGED:
        return None
    if os.name != "posix":
        raise ValueError("managed evidence admission requires verified POSIX custody")
    from .shared import immutable_bytes, safe_path, verify_handoff
    from appsec_review.retrieval.index import MANIFEST_SCHEMA, load_verified_manifest
    root = context.run_root
    policy, config_digest = _frozen(root)
    if policy != context.review_policy.view():
        raise ValueError("managed publication differs from frozen policy")
    if context.source_fingerprint == "none":
        snapshot = resolve_evidence_target(context, handoff.get("upstream_handoff_sha256", {}))
        if snapshot != getattr(context, "evidence_target_snapshot", None):
            raise ValueError("managed publication lacks its authenticated evidence binding")
        if handoff.get("evidence_target_snapshot") != snapshot:
            raise ValueError("managed handoff differs from its evidence binding")
    else:
        context.review_policy.check_target(context.target_root)
        snapshot = context.source_fingerprint
    key = _key(root, create=True)
    receipts, manifests, summaries = {}, {}, {}
    with validation_scope(root) as validation:
        admit_upstreams(context, handoff.get("upstream_handoff_sha256", {}))
        verify_handoff(root, handoff)
        detachments: dict[str, list[Path]] = {}
        publications: list[Path] = []
        for ref in handoff["artifacts"]:
            path = safe_path(root, ref["path"])
            if (not path.is_file() or path.stat().st_size != ref["size_bytes"]
                    or verified_digest(root, path, ref["sha256"]) != ref["sha256"]):
                raise ValueError("new evidence failed admission integrity")
            if ref["path"].startswith(("data/shared/objects/", "data/indices/")) and path.suffix != ".json":
                if os.name == "posix" and path.stat().st_uid != os.getuid():
                    raise ValueError("managed evidence is not application-owned")
                parent = path.parent
                while parent != root:
                    _private_directory(parent)
                    parent = parent.parent
                admitted = validation.admitted.get((ref["path"], ref["sha256"]))
                if admitted is not None:
                    if admitted != ref["size_bytes"] or path.stat().st_mode & 0o222:
                        raise ValueError("previously admitted evidence lost immutable custody")
                else:
                    detachments.setdefault(ref["sha256"], []).append(path)
            if (ref["path"], ref["sha256"]) not in validation.admitted:
                publications.append(path)
        for digest, paths in detachments.items():
            _detach_payload(paths[0], digest, aliases=tuple(paths[1:]))
        # JSON/terminal receipts also require durable replacement before authenticated publication.
        _sync_admission_artifacts(
            root, publications, {path for paths in detachments.values() for path in paths})
        for ref in handoff["artifacts"]:
            if "/shared/" in ref["path"] and ref["path"].endswith(".json"):
                path = safe_path(root, ref["path"])
                value = json.loads(path.read_bytes())
                if value.get("schema") == "appsec-review/shared-receipt/1":
                    receipts[ref["path"]] = {"sha256": ref["sha256"], "value": value}
            if ref["path"].startswith("data/indices/manifests/") and ref["path"].endswith(".json"):
                path = safe_path(root, ref["path"])
                value = json.loads(path.read_bytes())
                if value.get("schema") == MANIFEST_SCHEMA:
                    document, _ = load_verified_manifest(root, path, ref["sha256"])
                    manifests[ref["path"]] = {"sha256": ref["sha256"], "document": document}
                    from appsec_review.indexing.store import shard_summary
                    for shard in document["indexes"]:
                        identity = shard["sha256"]
                        if identity not in summaries:
                            summaries[identity] = shard_summary(root, shard)
    body = {
        "schema": VALIDATION_VERSION, "run_id": root.name,
        "custody_durability": _CUSTODY_DURABILITY,
        "target_snapshot": snapshot, "source_fingerprint": context.source_fingerprint,
        "resolved_config_sha256": config_digest,
        "policy": policy, "producer": {"job_id": handoff["job_id"], "attempt_id": handoff["attempt_id"]},
        "handoff_binding": dict(handoff),
        "artifacts": handoff["artifacts"], "receipts": receipts, "manifests": manifests,
        "shard_summaries": summaries,
    }
    signature = hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()
    payload = canonical_json({**body, "authentication": signature})
    identity = hashlib.sha256(payload).hexdigest()
    # Outside all review-run mounts; only the application can issue admission records.
    metadata = root.parent / "metadata"
    record = immutable_bytes(metadata, f"evidence-admission/{root.name}/{identity}.json", payload)
    _sync_directories({metadata / "evidence-admission" / root.name}, root.parent)
    return record


def prepare_custody(root: Path, policy: Any) -> None:
    if policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
        if os.name != "posix":
            raise ValueError("managed evidence admission requires verified POSIX custody")
        _key(root, create=True)


def _detach_payload(path: Path, expected: str, *, aliases: tuple[Path, ...] = ()) -> None:
    from appsec_review.observability.spans import count_work

    descriptor, temporary = tempfile.mkstemp(prefix=".admit-", dir=path.parent)
    pending = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as destination, path.open("rb") as source:
            shutil.copyfileobj(source, destination, 1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if file_sha256(pending) != expected:
            raise ValueError("evidence changed while detaching publication custody")
        mode = stat.S_IMODE(path.stat().st_mode) & ~0o222
        pending.chmod(mode)
        detached = pending.stat()
        for alias in aliases:
            descriptor, temporary_alias = tempfile.mkstemp(prefix=".admit-", dir=alias.parent)
            os.close(descriptor)
            pending_alias = Path(temporary_alias)
            try:
                destination = pending_alias.stat()
                compatible = (
                    destination.st_dev == detached.st_dev and destination.st_gid == detached.st_gid
                    and stat.S_IMODE(alias.stat().st_mode) & ~0o222 == mode)
                pending_alias.unlink()
                if compatible:
                    # Link only the freshly copied inode, never the original producer's inode.
                    os.link(pending, pending_alias)
                    os.replace(pending_alias, alias)
                    count_work("custody_alias_objects")
                else:
                    _detach_payload(alias, expected)
            finally:
                pending_alias.unlink(missing_ok=True)
        os.replace(pending, path)
        count_work("copy_objects")
        count_work("copy_bytes", path.stat().st_size)
    finally:
        pending.unlink(missing_ok=True)


def _read_admission(root: Path, handoff: Mapping[str, Any]) -> Mapping[str, Any] | None:
    ref = handoff.get("validation_record")
    if ref is None:
        return None
    policy, config_digest = _frozen(root)
    if policy.get("mode") != AssuranceMode.FIRST_PARTY_MANAGED.value:
        return None
    from .shared import safe_path
    metadata = root.parent / "metadata"
    if not isinstance(ref, Mapping) or not str(ref.get("path", "")).startswith(
            f"evidence-admission/{root.name}/"):
        raise ValueError("admission record escapes its run")
    path = safe_path(metadata, ref["path"])
    from appsec_review.runtime.scope import require_hashable_evidence
    from appsec_review.observability.spans import count_work
    require_hashable_evidence(path)
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    count_work("target_hash_bytes", len(payload))
    count_work("target_hash_objects")
    if digest != ref["sha256"]:
        raise ValueError("evidence admission record integrity mismatch")
    record = json.loads(payload)
    signature = record.pop("authentication", None)
    key = _key(root, create=False)
    validation = current_validation(root)
    cache_key = ("admission-authentication", "latest", "")
    cached = None
    if validation is not None:
        with validation.lock:
            cached = validation.records.get(cache_key)
    if cached != (payload, key):
        expected = hmac.new(key, canonical_json(record), hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise ValueError("evidence admission authentication failed")
        if validation is not None and len(payload) <= _DOCUMENT_CACHE_BYTES:
            with validation.lock:
                validation.records[cache_key] = (payload, key)
    if (record.get("schema") != VALIDATION_VERSION or record.get("run_id") != root.name
            or record.get("policy") != policy or record.get("resolved_config_sha256") != config_digest
            or record.get("source_fingerprint", record.get("target_snapshot")) != handoff.get("source_fingerprint")
            or record.get("target_snapshot") != handoff.get("evidence_target_snapshot", handoff.get("source_fingerprint"))
            or ("handoff_binding" in record and canonical_json(record["handoff_binding"]) != canonical_json({
                key: value for key, value in handoff.items() if key != "validation_record"}))
            or (handoff.get("resolved_config_sha256", config_digest) != config_digest)
            or record.get("producer") != {"job_id": handoff.get("job_id"), "attempt_id": handoff.get("attempt_id")}
            or record.get("artifacts") != handoff.get("artifacts")):
        raise ValueError("evidence admission run, producer, target or policy mismatch")
    if record.get("custody_durability") != _CUSTODY_DURABILITY:
        raise ValueError("admission lacks crash-durable custody proof; fresh admission is required")
    _check_admitted_outputs(root, record)
    return record


def _check_admitted_outputs(root: Path, record: Mapping[str, Any]) -> None:
    from .shared import safe_path
    for artifact in record["artifacts"]:
        candidate = safe_path(root, artifact["path"])
        if not candidate.is_file() or candidate.stat().st_size != artifact["size_bytes"]:
            raise ValueError("admitted output is missing or unavailable")
        if (artifact["path"].startswith(("data/shared/objects/", "data/indices/"))
                and not artifact["path"].endswith(".json") and candidate.stat().st_mode & 0o222):
            raise ValueError("admitted evidence has regained a writable alias")


def _activate_admission(validation: Any, record: Mapping[str, Any]) -> None:
    # Readiness/metadata publications authenticate origin, never target evidence.
    if record["target_snapshot"] == "none":
        return
    for artifact in record["artifacts"]:
        if (artifact["path"].startswith(("data/shared/objects/", "data/indices/"))
                and not artifact["path"].endswith(".json")):
            validation.admitted[(artifact["path"], artifact["sha256"])] = artifact["size_bytes"]
    validation.admitted_receipts.update(record["receipts"])
    validation.admitted_manifests.update(record["manifests"])
    for identity, summary in record["shard_summaries"].items():
        validation.records[("admitted-summary", identity, record["target_snapshot"])] = summary


def consume_admission(root: Path, handoff: Mapping[str, Any]) -> bool:
    record = _read_admission(root, handoff)
    if record is None:
        return False
    validation = current_validation(root)
    if validation is None:
        raise ValueError("managed consumer requires an operation-scoped validation context")
    policy_identity = hashlib.sha256(canonical_json(record["policy"])).hexdigest()
    with validation.lock:
        if ((record["target_snapshot"] != "none"
             and validation.target_snapshot not in ("unknown", record["target_snapshot"]))
                or validation.policy_identity not in ("strict-legacy", policy_identity)):
            raise ValueError("managed admission differs from operation policy or snapshot")
        if record["target_snapshot"] != "none":
            validation.target_snapshot = record["target_snapshot"]
        validation.policy_identity = policy_identity
        _activate_admission(validation, record)
    return True
