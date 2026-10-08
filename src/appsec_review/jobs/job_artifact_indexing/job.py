from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import time
from typing import Any

from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import (
    INDEX_SCHEMA,
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.retrieval.model import canonical_json, normalize_relative_path
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, LockUnavailable, atomic_json, file_sha256


SCHEMA = "appsec-review/artifact-indexing/1"
CATALOG_PARSER = "appsec-review/produced-artifact-catalog/1"
MEMBER_EXTRACTOR = "appsec-review/accepted-archive-member-manifest/1"
RELATION_NORMALIZER = "appsec-review/produced-artifact-relations/1"
MAPPING_IDENTITY = "appsec-review/receipt-workspace-mapping/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECEIPT_SCHEMAS = {
    "appsec-review/language-build-receipt/1",
    "appsec-review/wasm-build-receipt/1",
}
_TOPOLOGY = {
    "load": ("accepted_builds",),
    "index": ("catalogs", "members", "relationships"),
    "acceptance": ("publish_handoff",),
}


class ArtifactIndexIntegrityError(ValueError):
    """An accepted input or immutable shard failed verification."""


def artifact_family(kind: str) -> EntityKind:
    value = str(kind).lower()
    if value == "object":
        return EntityKind.OBJECT_FILE
    if value in {"static-library", "shared-library", "library"}:
        return EntityKind.LIBRARY
    if value in {"executable", "native-output"}:
        return EntityKind.EXECUTABLE
    if value in {"wheel", "source-distribution", "jar", "war", "ear", "package-archive"}:
        return EntityKind.PACKAGE
    if value in {"bytecode", "python-bytecode", "jvm-class", "dex", "llvm-bitcode"}:
        return EntityKind.BYTECODE_MODULE
    if value == "managed-assembly":
        return EntityKind.MANAGED_ASSEMBLY
    if value in {"wasm-module", "wasm-component"}:
        return EntityKind.WASM_MODULE
    return EntityKind.BUILD_ARTIFACT


def _artifact_fields(artifact: Mapping[str, Any]) -> tuple[str, str, str]:
    path = normalize_relative_path(str(artifact.get("workspace_path", "")))
    digest = str(artifact.get("sha256", ""))
    kind = str(artifact.get("kind", ""))
    if not _SHA256.fullmatch(digest) or not kind:
        raise ArtifactIndexIntegrityError("produced artifact requires a canonical path, hash, and format")
    size = artifact.get("size_bytes")
    if type(size) is not int or size < 0:
        raise ArtifactIndexIntegrityError("produced artifact size is invalid")
    return path, digest, kind


def canonical_artifact_identity(
    target_snapshot: str, build_unit_id: str, artifact: Mapping[str, Any]
) -> LogicalIdentity:
    path, digest, kind = _artifact_fields(artifact)
    entity_kind = artifact_family(kind)
    return LogicalIdentity.derive(entity_kind, target_snapshot, {
        "build_unit_id": str(build_unit_id),
        "workspace_path": path,
        "sha256": digest,
        "format": kind,
    })


def _member_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ArtifactIndexIntegrityError("archive member path is invalid")
    raw = value.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise ArtifactIndexIntegrityError("archive member path must be relative")
    pieces = raw.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces):
        raise ArtifactIndexIntegrityError("archive member path is non-canonical")
    return PurePosixPath(*pieces).as_posix()


def canonical_archive_member_identity(
    target_snapshot: str,
    parent_identity: LogicalIdentity | str,
    member: Mapping[str, Any],
) -> LogicalIdentity:
    parent = (parent_identity if isinstance(parent_identity, LogicalIdentity)
              else LogicalIdentity.parse(parent_identity))
    path = _member_path(str(member.get("member", "")))
    size = member.get("size_bytes")
    if type(size) is not int or size < 0:
        raise ArtifactIndexIntegrityError("archive member size is invalid")
    digest = member.get("sha256")
    if digest is not None and not _SHA256.fullmatch(str(digest)):
        raise ArtifactIndexIntegrityError("archive member hash is invalid")
    return LogicalIdentity.derive(EntityKind.ARCHIVE_MEMBER, target_snapshot, {
        "parent": parent.value,
        "path": path,
        "size_bytes": size,
        "sha256": digest,
    })


def artifact_index_fingerprint(
    *,
    name: str,
    target_snapshot: str,
    receipt: Mapping[str, Any],
    artifacts: Iterable[Mapping[str, Any]],
    upstream_manifests: Iterable[str],
    extractor_identity: str,
    parser_identity: str,
    normalizer_identity: str,
    mapping_identity: str,
) -> str:
    artifact_values = []
    for artifact in artifacts:
        path, digest, kind = _artifact_fields(artifact)
        artifact_values.append({"workspace_path": path, "sha256": digest,
                                "size_bytes": artifact["size_bytes"], "format": kind})
    actions = [{key: command.get(key) for key in
                ("command_id", "argv_sha256", "image_id", "role", "tool_kind")}
               for command in receipt.get("commands", ()) if isinstance(command, Mapping)]
    dependency_identities = {
        "receipt": receipt.get("fingerprint"),
        "recipe": receipt.get("recipe_identity"),
        "probe": receipt.get("probe_identity"),
        "upstream_handoff": receipt.get("upstream_handoff_sha256"),
        "upstream_builds": receipt.get("upstream_build_fingerprints", {}),
    }
    bound = {
        "build_unit_id": receipt.get("build_unit_id"),
        "artifact_family": sorted({artifact_family(str(item["format"])).value
                                    for item in artifact_values}),
        "artifacts": sorted(artifact_values, key=lambda item: (item["workspace_path"], item["sha256"])),
        "producing_actions": sorted(actions, key=lambda item: (str(item.get("command_id")),
                                                                str(item.get("argv_sha256")))),
        "dependency_identities": dependency_identities,
        "image_toolchain": {
            "image": receipt.get("image"),
            "executor": receipt.get("executor_identity"),
            "capture": receipt.get("capture_identity"),
            "family": receipt.get("family", receipt.get("source_family")),
            "producer": receipt.get("producer"),
        },
        "extractor": extractor_identity,
        "schema": INDEX_SCHEMA,
    }
    return index_fingerprint(
        name=name,
        target_snapshot=target_snapshot,
        producer_artifacts=[bound],
        tool_identity=bound["image_toolchain"],
        parser_identity=parser_identity,
        normalizer_identity=normalizer_identity,
        mapping_identity=mapping_identity,
        upstream_manifests=upstream_manifests,
    )


def _manifest_entries(receipt: Mapping[str, Any], artifacts: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    return tuple(sorted(hashlib.sha256(canonical_json({
        "schema": "appsec-review/build-workspace-manifest/1",
        "build_unit_id": receipt.get("build_unit_id"),
        "workspace_path": artifact.get("workspace_path"),
        "sha256": artifact.get("sha256"),
    })).hexdigest() for artifact in artifacts))


def _safe_file(run_root: Path, identity: Mapping[str, Any], label: str) -> Path:
    candidate = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
        raise ArtifactIndexIntegrityError(f"{label} path is invalid")
    digest = str(identity.get("sha256", ""))
    if not _SHA256.fullmatch(digest) or file_sha256(candidate) != digest:
        raise ArtifactIndexIntegrityError(f"{label} hash mismatch")
    size = identity.get("size_bytes")
    if size is not None and (type(size) is not int or candidate.stat().st_size != size):
        raise ArtifactIndexIntegrityError(f"{label} size mismatch")
    return candidate


def _accepted_language_manifest(run_root: Path) -> dict[str, str]:
    pointer_path = run_root / "data" / "jobs" / "job_language_build" / "latest.json"
    if not pointer_path.is_file():
        raise ArtifactIndexIntegrityError("accepted language-build handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = _safe_file(run_root, {"path": pointer.get("handoff_path"),
                                        "sha256": pointer.get("handoff_sha256")},
                              "language-build handoff")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != "job_language_build"):
        raise ArtifactIndexIntegrityError("language-build handoff is not accepted")
    raw = handoff.get("outputs", {}).get("acceptance.publish_handoff", {}).get("index_manifest")
    if not isinstance(raw, Mapping):
        raise ArtifactIndexIntegrityError("accepted language-build index manifest is required")
    path = _safe_file(run_root, raw, "language-build index manifest")
    relative = path.relative_to(run_root).as_posix()
    if not any(item.get("path") == relative and item.get("sha256") == raw.get("sha256")
               for item in handoff.get("artifacts", ())):
        raise ArtifactIndexIntegrityError("language-build index manifest is not bound to its accepted handoff")
    load_verified_manifest(run_root, path, str(raw["sha256"]))
    return {"path": relative, "sha256": str(raw["sha256"])}


def _load_workspace_manifest(run_root: Path, receipt: Mapping[str, Any]) -> Mapping[str, str]:
    identity = receipt.get("workspace_manifest")
    if not isinstance(identity, Mapping):
        raise ArtifactIndexIntegrityError("successful build receipt has no workspace manifest")
    path = _safe_file(run_root, identity, "workspace manifest")
    document = json.loads(path.read_text(encoding="utf-8"))
    if (document.get("schema") != "appsec-review/build-workspace-manifest/1" or
            document.get("build_unit_id") != receipt.get("build_unit_id") or
            not isinstance(document.get("files"), Mapping)):
        raise ArtifactIndexIntegrityError("workspace manifest schema or build-unit identity is invalid")
    files: dict[str, str] = {}
    for raw_path, raw_digest in document["files"].items():
        canonical = normalize_relative_path(str(raw_path))
        digest = str(raw_digest)
        if canonical in files or not _SHA256.fullmatch(digest):
            raise ArtifactIndexIntegrityError("workspace manifest contains a duplicate or invalid identity")
        files[canonical] = digest
    return files


def _validate_receipts(run_root: Path, source_fingerprint: str,
                       receipts: Iterable[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    validated: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen_units: set[str] = set()
    seen_artifacts: set[str] = set()
    for raw_receipt in receipts:
        if not isinstance(raw_receipt, Mapping) or raw_receipt.get("schema") not in _RECEIPT_SCHEMAS:
            raise ArtifactIndexIntegrityError("language-build receipt schema is invalid")
        receipt = dict(raw_receipt)
        unit_id = str(receipt.get("build_unit_id", ""))
        if not unit_id or unit_id in seen_units:
            raise ArtifactIndexIntegrityError("language-build receipts contain a duplicate build-unit identity")
        seen_units.add(unit_id)
        if receipt.get("source_fingerprint") not in {None, source_fingerprint}:
            raise ArtifactIndexIntegrityError("language-build receipt target snapshot changed")
        status = str(receipt.get("terminal_status", ""))
        artifacts = receipt.get("artifacts", ())
        if not isinstance(artifacts, list):
            raise ArtifactIndexIntegrityError("language-build artifact list is invalid")
        if status != "SUCCEEDED":
            gaps.extend(f"{unit_id}: {gap}" for gap in receipt.get("gaps", ()))
            if artifacts:
                raise ArtifactIndexIntegrityError("non-successful build receipt publishes artifacts")
            receipt["validated_artifacts"] = []
            validated.append(receipt)
            continue
        workspace = normalize_relative_path(str(receipt.get("workspace", "")))
        manifest_files = _load_workspace_manifest(run_root, receipt)
        verified: list[dict[str, Any]] = []
        if not artifacts:
            gaps.append(f"{unit_id}: accepted successful build produced no artifact entries")
        for raw_artifact in artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise ArtifactIndexIntegrityError("produced artifact identity is invalid")
            artifact = dict(raw_artifact)
            workspace_path, digest, _ = _artifact_fields(artifact)
            path = _safe_file(run_root, artifact, "produced artifact")
            expected = (run_root / workspace / Path(*PurePosixPath(workspace_path).parts)).resolve()
            if path != expected or manifest_files.get(workspace_path) != digest:
                raise ArtifactIndexIntegrityError("produced artifact is not bound to its workspace manifest")
            identity = canonical_artifact_identity(source_fingerprint, unit_id, artifact)
            if identity.value in seen_artifacts:
                raise ArtifactIndexIntegrityError("duplicate canonical produced-artifact identity")
            seen_artifacts.add(identity.value)
            artifact["canonical_identity"] = identity.value
            verified.append(artifact)
        receipt["validated_artifacts"] = verified
        validated.append(receipt)
        gaps.extend(f"{unit_id}: {gap}" for gap in receipt.get("gaps", ()))
    return validated, list(dict.fromkeys(gaps))


def _verify_shard(path: Path, *, name: str, fingerprint: str, shard_id: str,
                  target_snapshot: str) -> str:
    try:
        uri = f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as database:
            metadata = dict(database.execute("SELECT key, value FROM metadata"))
            if (metadata.get("schema"), metadata.get("name"), metadata.get("fingerprint"),
                    metadata.get("shard_id"), metadata.get("target_snapshot")) != (
                    INDEX_SCHEMA, name, fingerprint, shard_id, target_snapshot):
                raise ArtifactIndexIntegrityError("completed artifact shard metadata changed")
            if database.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ArtifactIndexIntegrityError("completed artifact shard is corrupt")
    except sqlite3.DatabaseError as exc:
        raise ArtifactIndexIntegrityError("completed artifact shard is corrupt") from exc
    return file_sha256(path)


def _finish_shard(builder: IndexBuilder, path: Path) -> tuple[str, bool]:
    lock = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + 30
    while True:
        try:
            with FileLock(lock):
                if path.exists():
                    return _verify_shard(path, name=builder.name, fingerprint=builder.fingerprint,
                                         shard_id=builder.shard_id,
                                         target_snapshot=builder.target_snapshot), True
                return builder.build(), False
        except LockUnavailable:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _index_identity(unit: UnitContext, builder: IndexBuilder, path: Path,
                    gaps: Iterable[str], family: str) -> tuple[dict[str, Any], bool]:
    sha, reused = _finish_shard(builder, path)
    identity = IndexIdentity(
        "artifacts", INDEX_SCHEMA, sha, builder.fingerprint,
        path.relative_to(unit.job.run_root).as_posix(),
        {"job": "job_artifact_indexing", "unit": unit.unit_id, "family": family},
        tuple(dict.fromkeys(str(gap) for gap in gaps)), builder.shard_id,
    )
    return asdict(identity), reused


def _shard_path(unit: UnitContext, fingerprint: str, shard_id: str) -> Path:
    # The fingerprint already binds the shard identity. Keeping the filename compact also keeps
    # restart-safe test and run paths below the Windows legacy path-length boundary.
    return unit.job.run_root / "data" / "indices" / "artifacts" / f"{fingerprint}.sqlite"


def _catalogs(unit: UnitContext) -> Mapping[str, Any]:
    loaded = unit.output("load.accepted_builds")
    identities: list[dict[str, Any]] = []
    reused = 0
    for receipt in loaded["receipts"]:
        groups: dict[EntityKind, list[Mapping[str, Any]]] = defaultdict(list)
        for artifact in receipt["validated_artifacts"]:
            groups[artifact_family(str(artifact["kind"]))].append(artifact)
        for family in sorted(groups, key=lambda item: item.value):
            artifacts = groups[family]
            fingerprint = artifact_index_fingerprint(
                name="artifacts", target_snapshot=unit.job.source_fingerprint, receipt=receipt,
                artifacts=artifacts, upstream_manifests=_manifest_entries(receipt, artifacts),
                extractor_identity="none", parser_identity=unit.job.config.settings["catalog_parser_identity"],
                normalizer_identity=unit.job.config.settings["normalizer_identity"],
                mapping_identity=unit.job.config.settings["mapping_identity"],
            )
            shard_id = f"catalog-{receipt['build_unit_id']}-{family.value}"
            path = _shard_path(unit, fingerprint, shard_id)
            builder = IndexBuilder(path, name="artifacts", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
            for artifact in artifacts:
                logical = LogicalIdentity.parse(str(artifact["canonical_identity"]))
                payload = {key: artifact.get(key) for key in
                           ("workspace_path", "sha256", "size_bytes", "kind", "build_unit_id",
                            "mapping", "mapping_confidence", "loader_dependencies",
                            "loader_dependency_status", "build_id_sha256")}
                payload.update({"artifact_family": family.value,
                                "producer_family": receipt.get("family", receipt.get("source_family"))})
                builder.add_entity(EntityRecord(logical, str(artifact["sha256"]),
                    PurePosixPath(str(artifact["workspace_path"])).name,
                    f"{artifact['kind']} {artifact['workspace_path']}", payload))
            builder.add_coverage(f"{receipt['build_unit_id']}:{family.value}", "complete")
            identity, was_reused = _index_identity(unit, builder, path, (), family.value)
            identities.append(identity)
            reused += int(was_reused)
    return {"indexes": identities, "shard_count": len(identities), "reused_count": reused,
            "gaps": loaded["producer_gaps"],
            "terminal_status": "COMPLETED_WITH_GAPS" if loaded["producer_gaps"] else
                               "SUCCEEDED" if identities else "NOT_APPLICABLE"}


def _members(unit: UnitContext) -> Mapping[str, Any]:
    loaded = unit.output("load.accepted_builds")
    identities: list[dict[str, Any]] = []
    gaps: list[str] = []
    reused = 0
    for receipt in loaded["receipts"]:
        rows_by_path: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for row in receipt.get("package_members", ()):
            if not isinstance(row, Mapping):
                raise ArtifactIndexIntegrityError("package member manifest row is invalid")
            rows_by_path[normalize_relative_path(str(row.get("package_path", "")))].append(row)
        for artifact in receipt["validated_artifacts"]:
            if artifact_family(str(artifact["kind"])) != EntityKind.PACKAGE:
                continue
            rows = rows_by_path.get(str(artifact["workspace_path"]), [])
            artifact_gaps = [] if rows else [f"{artifact['workspace_path']}: archive member manifest unavailable"]
            gaps.extend(artifact_gaps)
            fingerprint = artifact_index_fingerprint(
                name="artifacts", target_snapshot=unit.job.source_fingerprint, receipt=receipt,
                artifacts=(artifact,), upstream_manifests=_manifest_entries(receipt, (artifact,)),
                extractor_identity=unit.job.config.settings["member_extractor_identity"],
                parser_identity=unit.job.config.settings["member_parser_identity"],
                normalizer_identity=unit.job.config.settings["normalizer_identity"],
                mapping_identity=unit.job.config.settings["mapping_identity"],
            )
            shard_id = f"members-{str(artifact['canonical_identity']).rsplit(':', 1)[-1][:24]}"
            path = _shard_path(unit, fingerprint, shard_id)
            builder = IndexBuilder(path, name="artifacts", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
            parent = LogicalIdentity.parse(str(artifact["canonical_identity"]))
            seen: set[str] = set()
            for row in sorted(rows, key=lambda item: str(item.get("member", ""))):
                member = canonical_archive_member_identity(unit.job.source_fingerprint, parent, row)
                if member.value in seen:
                    raise ArtifactIndexIntegrityError("archive member manifest contains a duplicate identity")
                seen.add(member.value)
                member_path = _member_path(str(row["member"]))
                builder.add_entity(EntityRecord(member, member_path, PurePosixPath(member_path).name,
                    member_path, {"member_path": member_path, "size_bytes": row["size_bytes"],
                                  "sha256": row.get("sha256"), "parent_artifact": parent.value,
                                  "extractor_identity": unit.job.config.settings["member_extractor_identity"]}))
                builder.add_relation(RelationRecord(RelationKind.CONTAINS, parent.value,
                                                     member.value, True, 1.0))
            builder.add_coverage(str(artifact["workspace_path"]),
                                 "partial" if artifact_gaps else "complete",
                                 artifact_gaps[0] if artifact_gaps else None)
            identity, was_reused = _index_identity(unit, builder, path, artifact_gaps, "members")
            identities.append(identity)
            reused += int(was_reused)
    return {"indexes": identities, "shard_count": len(identities), "reused_count": reused,
            "gaps": list(dict.fromkeys(gaps)),
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                               "SUCCEEDED" if identities else "NOT_APPLICABLE"}


def _relationships(unit: UnitContext) -> Mapping[str, Any]:
    loaded = unit.output("load.accepted_builds")
    identities: list[dict[str, Any]] = []
    gaps: list[str] = []
    reused = 0
    for receipt in loaded["receipts"]:
        artifacts_by_path = {str(item["workspace_path"]): item for item in receipt["validated_artifacts"]}
        artifacts_by_hash = {str(item["sha256"]): item for item in receipt["validated_artifacts"]}
        actions = {str(item.get("command_id")): item for item in receipt.get("commands", ())
                   if isinstance(item, Mapping) and item.get("command_id")}
        for artifact in receipt["validated_artifacts"]:
            artifact_gaps: list[str] = []
            fingerprint = artifact_index_fingerprint(
                name="artifacts", target_snapshot=unit.job.source_fingerprint, receipt=receipt,
                artifacts=(artifact,), upstream_manifests=_manifest_entries(receipt, (artifact,)),
                extractor_identity="none", parser_identity=unit.job.config.settings["relationship_parser_identity"],
                normalizer_identity=unit.job.config.settings["normalizer_identity"],
                mapping_identity=unit.job.config.settings["mapping_identity"],
            )
            shard_id = f"relations-{str(artifact['canonical_identity']).rsplit(':', 1)[-1][:24]}"
            path = _shard_path(unit, fingerprint, shard_id)
            builder = IndexBuilder(path, name="artifacts", fingerprint=fingerprint,
                                   target_snapshot=unit.job.source_fingerprint, shard_id=shard_id)
            target = str(artifact["canonical_identity"])
            mapped_actions: set[str] = set()
            for row in receipt.get("relationships", ()):
                if (not isinstance(row, Mapping) or row.get("artifact_sha256") != artifact["sha256"] or
                        str(row.get("command_id", "")) not in actions):
                    continue
                command_id = str(row["command_id"])
                action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                    {"build_unit_id": receipt["build_unit_id"], "command_id": command_id})
                confidence = float(row.get("confidence", 0.5))
                builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, target,
                    action.value, False, confidence, "producer supplied bounded build attribution",
                    {"mapping": row.get("mapping")}))
                mapped_actions.add(command_id)
            for invocation in receipt.get("tool_invocations", ()):
                if not isinstance(invocation, Mapping):
                    continue
                outputs = invocation.get("outputs", ())
                if not isinstance(outputs, list) or not any(
                        isinstance(item, Mapping) and item.get("workspace_path") == artifact["workspace_path"] and
                        item.get("sha256") == artifact["sha256"] for item in outputs):
                    continue
                parent = str(invocation.get("parent_command_id", ""))
                if parent in actions:
                    action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                        {"build_unit_id": receipt["build_unit_id"], "command_id": parent})
                    exact = invocation.get("mapping_confidence") == 1.0
                    builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, target,
                        action.value, exact, 1.0 if exact else float(invocation.get("mapping_confidence", 0.5)),
                        None if exact else "tool invocation output mapping was heuristic"))
                    mapped_actions.add(parent)
                if str(invocation.get("tool_kind", "")) in {"linker", "linker-driver", "archiver",
                                                                 "compiler-driver-link"}:
                    for raw_input in invocation.get("inputs", ()):
                        if not isinstance(raw_input, Mapping):
                            continue
                        source = artifacts_by_path.get(str(raw_input.get("workspace_path", "")))
                        if source is None and raw_input.get("sha256"):
                            source = artifacts_by_hash.get(str(raw_input["sha256"]))
                        if source is not None:
                            exact = raw_input.get("mapping_confidence") == 1.0
                            builder.add_relation(RelationRecord(RelationKind.LINKS_INTO,
                                str(source["canonical_identity"]), target, exact,
                                1.0 if exact else float(raw_input.get("mapping_confidence", 0.5)),
                                None if exact else "link input mapping was heuristic"))
            if not mapped_actions and actions:
                ambiguity = "receipt did not attribute the artifact to a unique producing action"
                for command_id in sorted(actions):
                    action = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                        {"build_unit_id": receipt["build_unit_id"], "command_id": command_id})
                    builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, target,
                                                        action.value, False, 0.25, ambiguity))
                artifact_gaps.append(f"{artifact['workspace_path']}: producing action mapping is ambiguous")
            elif not actions:
                artifact_gaps.append(f"{artifact['workspace_path']}: producing action receipt unavailable")
            gaps.extend(artifact_gaps)
            builder.add_coverage(str(artifact["workspace_path"]),
                                 "partial" if artifact_gaps else "complete",
                                 artifact_gaps[0] if artifact_gaps else None)
            identity, was_reused = _index_identity(unit, builder, path, artifact_gaps, "relationships")
            identities.append(identity)
            reused += int(was_reused)
    return {"indexes": identities, "shard_count": len(identities), "reused_count": reused,
            "gaps": list(dict.fromkeys(gaps)),
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                               "SUCCEEDED" if identities else "NOT_APPLICABLE"}


def _artifact(unit: UnitContext, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != tuple(_TOPOLOGY):
        raise ValueError("artifact-indexing topology does not match central configuration")
    for step, tasks in _TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"artifact-indexing task order mismatch: {step}")
    required = {"catalog_parser_identity", "member_extractor_identity", "member_parser_identity",
                "relationship_parser_identity", "normalizer_identity", "mapping_identity"}
    if set(context.config.settings) != required or any(
            not isinstance(context.config.settings[key], str) or not context.config.settings[key]
            for key in required):
        raise ValueError("artifact-indexing identities are invalid")


def load_accepted_artifact_index(run_root: Path) -> Mapping[str, Any]:
    pointer_path = Path(run_root) / "data" / "jobs" / "job_artifact_indexing" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted artifact-indexing handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = _safe_file(Path(run_root), {"path": pointer.get("handoff_path"),
                                               "sha256": pointer.get("handoff_sha256")},
                              "artifact-indexing handoff")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != "job_artifact_indexing"):
        raise ValueError("artifact-indexing handoff is not accepted")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    manifest = published.get("index_manifest") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping) or not isinstance(manifest, Mapping):
        raise ValueError("artifact-indexing publication is unavailable")
    if not any(item.get("path") == identity.get("path") and item.get("sha256") == identity.get("sha256")
               for item in handoff.get("artifacts", ())):
        raise ArtifactIndexIntegrityError("artifact-indexing summary is not bound to its accepted handoff")
    document = json.loads(_safe_file(Path(run_root), identity, "artifact-indexing summary").read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA:
        raise ValueError("artifact-indexing publication schema is unsupported")
    manifest_path = _safe_file(Path(run_root), manifest, "artifact-indexing manifest")
    load_verified_manifest(Path(run_root), manifest_path, str(manifest["sha256"]))
    return {**document, "handoff_sha256": pointer["handoff_sha256"]}


def build_job() -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_language_build(unit.job.run_root)
        if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
            raise ArtifactIndexIntegrityError("artifact-indexing target snapshot differs from language-build")
        upstream = _accepted_language_manifest(unit.job.run_root)
        upstream_path = unit.job.run_root / upstream["path"]
        upstream_sha = upstream["sha256"]
        receipts, producer_gaps = _validate_receipts(
            unit.job.run_root, unit.job.source_fingerprint, accepted.get("receipts", ()))
        if not receipts:
            producer_gaps.append("accepted language-build handoff contained no receipts")
        all_gaps = list(dict.fromkeys([*accepted.get("gaps", ()), *producer_gaps]))
        return {"receipts": receipts, "receipt_count": len(receipts),
                "producer_gaps": all_gaps,
                "language_build_handoff_sha256": accepted["language_build_handoff_sha256"],
                "upstream_manifest": {"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                                      "sha256": upstream_sha},
                "terminal_status": "COMPLETED_WITH_GAPS" if all_gaps else
                                   "SUCCEEDED" if receipts else "NOT_APPLICABLE"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_builds")
        branches = [unit.output("index.catalogs"), unit.output("index.members"),
                    unit.output("index.relationships")]
        current = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
                   for branch in branches for raw in branch["indexes"]]
        prior_path = unit.job.run_root / loaded["upstream_manifest"]["path"]
        prior, _ = load_verified_manifest(unit.job.run_root, prior_path,
                                          loaded["upstream_manifest"]["sha256"])
        prior_values = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
                        for raw in prior["indexes"]]
        identities = [item for item in prior_values if item.name != "artifacts"] + current
        manifest_path = (unit.job.run_root / "data" / "indices" / "manifests" /
                         f"artifact-indexing-{unit.job.attempt_id}.json")
        write_manifest(manifest_path, run_id=unit.job.run_id,
                       target_snapshot=unit.job.source_fingerprint,
                       target_root=unit.job.target_root or unit.job.repository_root,
                       indexes=identities, upstream_manifests=(loaded["upstream_manifest"],))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        gaps = list(dict.fromkeys([*loaded["producer_gaps"],
                                  *(gap for branch in branches for gap in branch["gaps"])]))
        summary = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                   "language_build_handoff_sha256": loaded["language_build_handoff_sha256"],
                   "artifact_shard_count": len(current),
                   "reused_shard_count": sum(int(branch["reused_count"]) for branch in branches),
                   "artifact_count": sum(len(receipt["validated_artifacts"])
                                         for receipt in loaded["receipts"]),
                   "gaps": gaps, "index_manifest": _artifact(unit, manifest_path)}
        summary_path = unit.job.attempt_root / "artifacts" / "artifact-indexing" / "accepted-index.json"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(summary_path, summary)
        return {"schema": SCHEMA, "artifact": _artifact(unit, summary_path),
                "index_manifest": _artifact(unit, manifest_path), "item_count": len(current),
                "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}

    units = (
        Unit("load.accepted_builds", load),
        Unit("index.catalogs", _catalogs, ("load.accepted_builds",)),
        Unit("index.members", _members, ("load.accepted_builds",)),
        Unit("index.relationships", _relationships, ("load.accepted_builds",)),
        Unit("acceptance.publish_handoff", publish,
             ("index.catalogs", "index.members", "index.relationships")),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return Job("job_artifact_indexing", "artifact_indexing", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation,
               units=units)
