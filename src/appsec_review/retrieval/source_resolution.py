"""Bounded source reads from a target or an explicitly accepted generated-source publication.

Generated backing references travel only through verified producer/index records.
They name detached, immutable run objects, never a mutable build workspace.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.storage import canonical_json
from appsec_review.storage.shared import immutable_bytes, put_bytes, safe_path


SCHEMA = "appsec-review/generated-source-backing/1"
BINARY_SCHEMA = "appsec-review/binary-source-backing/1"
IDENTITY = "appsec-review/source-resolution/1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192
PREFIX = "data/treesitter/sources/"
BINARY_PREFIX = "data/binary-evidence/sources/"
_HASH = re.compile(r"[0-9a-f]{64}")
_BINARY_PATH = re.compile(r"@binary/([0-9a-f]{64})/(0x[0-9a-f]{1,16})\.c")


def run_binding(run_root: Path) -> str:
    return hashlib.sha256(str(run_root.resolve()).encode("utf-8")).hexdigest()


def binary_source_path(binary_sha256: str, address: str) -> str:
    """The logical path of one function's pseudo-C: it names the binary hash and the address."""
    path = f"@binary/{binary_sha256}/{address}.c"
    if not _BINARY_PATH.fullmatch(path):
        raise ValueError("invalid binary pseudo-C identity")
    return path


def parse_binary_source_path(path: str) -> tuple[str, str] | None:
    """``(binary_sha256, function_address)`` for a pseudo-C logical path, else ``None``."""
    match = _BINARY_PATH.fullmatch(path or "")
    return (match.group(1), match.group(2)) if match else None


def backing_reference(value: Any, prefix: str = PREFIX) -> dict[str, Any]:
    """Expose only the bounded canonical reference, not arbitrary native provenance."""
    if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "size_bytes"}:
        raise ValueError("invalid generated source backing reference")
    digest, size = value["sha256"], value["size_bytes"]
    if (not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or value["path"] != f"{prefix}{digest}.json"
            or type(size) is not int or not 0 < size <= MAX_MANIFEST_BYTES):
        raise ValueError("invalid generated source backing identity")
    return dict(value)


def source_native(row: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        raise ValueError("invalid source provenance")
    domain = row.get("source_domain")
    if domain is not None and not isinstance(domain, str):
        raise ValueError("invalid source backing domain")
    if domain == "binary":
        return {"source_domain": "binary",
                "source_backing": backing_reference(row.get("source_backing"), BINARY_PREFIX)}
    if "source_backing" in row:
        if row.get("source_domain") not in {None, "generated"}:
            raise ValueError("unknown source backing domain")
        return {"source_domain": "generated", "source_backing": backing_reference(row["source_backing"])}
    if row.get("source_domain") not in {None, "target"}:
        raise ValueError("generated source has no accepted backing")
    return {}


def _read_exact(root: Path, reference: Mapping[str, Any], limit: int) -> bytes:
    size = reference.get("size_bytes")
    if type(size) is not int or not 0 <= size <= limit:
        raise ValueError("source exceeds excerpt verification bound")
    path = safe_path(root, reference["path"])
    if not path.is_file() or path.stat().st_size != size:
        raise ValueError("source publication is missing or changed")
    with path.open("rb") as stream:
        data = stream.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != reference["sha256"]:
        raise ValueError("source publication digest changed")
    return data


def publish_source(run_root: Path, *, target_snapshot: str, logical_path: str,
                   artifact: Mapping[str, Any], build_unit_id: str,
                   handoff_sha256: str, data: bytes) -> dict[str, Any]:
    """Caller has verified accepted receipt membership, source scope and exact bytes."""
    from appsec_review.jobs.delivery_scope import source_in_scope
    if (not source_in_scope(artifact)
            or artifact.get("artifact_origin") not in {"accepted-input", "build-output"}):
        raise ValueError("out-of-scope source cannot enter detached publication")
    if len(data) > MAX_SOURCE_BYTES or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise ValueError("generated source publication bytes differ from accepted artifact")
    reference = put_bytes(run_root, data)
    safe_path(run_root, reference["path"]).chmod(0o444)
    document = {
        "schema": SCHEMA, "run_binding": run_binding(run_root),
        "target_snapshot": target_snapshot, "logical_path": logical_path,
        "source": reference, "canonical_artifact_identity": artifact["canonical_identity"],
        "artifact_kind": artifact["kind"],
        "build_unit_id": build_unit_id, "workspace_path": artifact["workspace_path"],
        "artifact_origin": artifact["artifact_origin"], "scope_role": artifact["scope_role"],
        "language_build_handoff_sha256": handoff_sha256,
    }
    payload = canonical_json(document)
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ValueError("generated source backing exceeds metadata bound")
    digest = hashlib.sha256(payload).hexdigest()
    backing = immutable_bytes(run_root, f"{PREFIX}{digest}.json", payload)
    safe_path(run_root, backing["path"]).chmod(0o444)
    return backing


def publish_binary_source(run_root: Path, *, target_snapshot: str, binary_sha256: str, address: str,
                          publication_identity: str, manifest_sha256: str, data: bytes) -> dict[str, Any]:
    """Detach one verified pseudo-C file into the run and bind it to its binary and publication.

    The caller has verified the publication chain; this records which binary, function address and
    publication the bytes came from, so a later excerpt read re-verifies all of them.
    """
    logical_path = binary_source_path(binary_sha256, address)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("pseudo-C exceeds the source verification bound")
    for value in (publication_identity, manifest_sha256):
        if not _HASH.fullmatch(value):
            raise ValueError("binary publication identity is not a SHA-256")
    reference = put_bytes(run_root, data)
    document = {"schema": BINARY_SCHEMA, "run_binding": run_binding(run_root),
                "target_snapshot": target_snapshot, "logical_path": logical_path,
                "binary_sha256": binary_sha256, "function_address": address,
                "publication_identity": publication_identity, "manifest_sha256": manifest_sha256,
                "provenance": "binary-derived", "source": reference}
    payload = canonical_json(document)
    digest = hashlib.sha256(payload).hexdigest()
    return immutable_bytes(run_root, f"{BINARY_PREFIX}{digest}.json", payload)


def _read_binary(run_root: Path, *, target_snapshot: str, path: str, sha256: str,
                 native: Mapping[str, Any], limit: int) -> bytes:
    ref = backing_reference(native.get("source_backing"), BINARY_PREFIX)
    document = json.loads(_read_exact(run_root, ref, MAX_MANIFEST_BYTES))
    identity = parse_binary_source_path(path)
    if (not isinstance(document, Mapping) or document.get("schema") != BINARY_SCHEMA
            or identity is None or document.get("run_binding") != run_binding(run_root)
            or document.get("target_snapshot") != target_snapshot
            or document.get("logical_path") != path
            or (document.get("binary_sha256"), document.get("function_address")) != identity
            or document.get("provenance") != "binary-derived"):
        raise ValueError("binary pseudo-C backing has invalid run, target or binary binding")
    source = document.get("source")
    if (not isinstance(source, Mapping) or source.get("sha256") != sha256
            or source.get("path") != f"data/shared/objects/{sha256}"):
        raise ValueError("binary pseudo-C is not a canonical detached object")
    return _read_exact(run_root, source, min(limit, MAX_SOURCE_BYTES))


def read_source_bytes(run_root: Path, target_root: Path, *, target_snapshot: str,
                      path: str, sha256: str, native: Mapping[str, Any] | None = None,
                      limit: int = MAX_SOURCE_BYTES) -> bytes:
    from appsec_review.jobs.delivery_scope import source_in_scope
    from appsec_review.retrieval.model import LogicalIdentity, normalize_relative_path

    if native is not None and not isinstance(native, Mapping):
        raise ValueError("invalid source provenance")
    native = native or {}
    domain = native.get("source_domain", "target")
    if domain == "binary":
        return _read_binary(run_root, target_snapshot=target_snapshot, path=path, sha256=sha256,
                            native=native, limit=limit)
    if parse_binary_source_path(path) is not None:
        raise ValueError("binary pseudo-C has no accepted backing")
    if domain == "target" and "source_backing" not in native:
        candidate = safe_path(target_root, normalize_relative_path(path))
        if not candidate.is_file():
            raise ValueError("indexed source is unavailable")
        try:
            return _read_exact(target_root, {"path": path, "sha256": sha256,
                                             "size_bytes": candidate.stat().st_size}, limit)
        except ValueError as exc:
            if "digest changed" in str(exc):
                raise ValueError("target source changed after indexing") from exc
            raise
    if domain != "generated" or "source_backing" not in native:
        raise ValueError("unknown or incomplete source backing domain")
    ref = backing_reference(native["source_backing"])
    document = json.loads(_read_exact(run_root, ref, MAX_MANIFEST_BYTES))
    if (not isinstance(document, Mapping) or document.get("schema") != SCHEMA
            or document.get("run_binding") != run_binding(run_root)
            or document.get("target_snapshot") != target_snapshot
            or document.get("logical_path") != path
            or document.get("artifact_origin") not in {"accepted-input", "build-output"}
            or not source_in_scope(document)):
        raise ValueError("generated source backing has invalid run, target or origin binding")
    canonical = LogicalIdentity.parse(str(document.get("canonical_artifact_identity", "")))
    if not isinstance(document.get("language_build_handoff_sha256"), str) or not _HASH.fullmatch(
            document["language_build_handoff_sha256"]):
        raise ValueError("generated source has no accepted producer binding")
    if path != generated_path(canonical.value, str(document.get("workspace_path", ""))):
        raise ValueError("generated logical path differs from its canonical producer")
    expected = LogicalIdentity.derive(canonical.kind, target_snapshot, {
        "build_unit_id": document.get("build_unit_id"), "workspace_path": document["workspace_path"],
        "sha256": sha256, "format": document.get("artifact_kind"),
    })
    if expected != canonical:
        raise ValueError("generated source canonical artifact binding changed")
    source = document.get("source")
    if (not isinstance(source, Mapping) or source.get("sha256") != sha256
            or source.get("path") != f"data/shared/objects/{sha256}"):
        raise ValueError("generated source is not a canonical detached object")
    return _read_exact(run_root, source, min(limit, MAX_SOURCE_BYTES))


def generated_path(canonical_identity: str, workspace_path: str) -> str:
    from appsec_review.retrieval.model import LogicalIdentity, normalize_relative_path
    from pathlib import PurePosixPath

    identity = LogicalIdentity.parse(canonical_identity)
    original = normalize_relative_path(workspace_path)
    return f"@generated/{identity.value.rsplit(':', 1)[-1]}/{PurePosixPath(original).name}"
