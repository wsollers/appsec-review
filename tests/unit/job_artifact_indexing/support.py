"""Canned fixtures for the job_artifact_indexing unit tier.

Everything here is code-level: a unit context stands in for the runner, receipts are dictionaries
the test owns, and the only files written are the produced artifacts and workspace manifests a
receipt points at under a run root the test creates. No runner, no graph, no engine.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.storage import atomic_json, file_sha256

SNAPSHOT = "snapshot-unit"
UNIT = "build-unit-scale"
RUN_ID = "2026-11-12-0001"
WORKSPACE_MANIFEST_SCHEMA = "appsec-review/build-workspace-manifest/1"
RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
SETTINGS = {
    "catalog_parser_identity": "appsec-review/produced-artifact-catalog/1",
    "member_extractor_identity": "appsec-review/accepted-archive-member-manifest/1",
    "member_parser_identity": "appsec-review/archive-member-normalizer/1",
    "relationship_parser_identity": "appsec-review/produced-artifact-relations/2",
    "normalizer_identity": "appsec-review/produced-artifact-normalizer/1",
    "mapping_identity": "appsec-review/receipt-workspace-mapping/1",
}


class CountingList(list):
    """A list that counts complete-iteration passes, to detect per-artifact rescans."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.passes = 0

    def __iter__(self):
        self.passes += 1
        return super().__iter__()


def identity(run_root: Path, path: Path) -> dict[str, Any]:
    """The run-relative artifact reference the job reads and writes."""
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def validated_artifact(path: str, kind: str, content: str, unit: str = UNIT,
                       snapshot: str = SNAPSHOT) -> dict[str, Any]:
    """An artifact as ``load.accepted_builds`` hands it to the index units (already verified)."""
    artifact = {"workspace_path": path, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "size_bytes": len(content), "kind": kind}
    artifact["canonical_identity"] = canonical_artifact_identity(snapshot, unit, artifact).value
    return artifact


def validated_receipt(count: int, *, unit: str = UNIT, link_inputs: int | None = None) -> dict[str, Any]:
    """A validated native receipt: ``count`` objects compiled by ``compile`` and linked into ``build/app``."""
    objects = [validated_artifact(f"build/obj/unit-{index:05d}.o", "object", f"object-{index}", unit)
               for index in range(count)]
    app = validated_artifact("build/app", "executable", "app", unit)
    linked = objects if link_inputs is None else objects[:link_inputs]
    invocations = [{"tool": "cc", "tool_kind": "compiler", "parent_command_id": "compile",
                    "mapping_confidence": 1.0, "origin": f"capture:{index}",
                    "outputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"]}],
                    "inputs": []} for index, item in enumerate(objects)]
    invocations.append({
        "tool": "ld", "tool_kind": "linker", "parent_command_id": "link", "mapping_confidence": 1.0,
        "origin": "capture:link",
        "outputs": [{"workspace_path": app["workspace_path"], "sha256": app["sha256"]}],
        "inputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"],
                    "mapping_confidence": 1.0} for item in linked]})
    return {
        "build_unit_id": unit, "fingerprint": "a" * 64, "family": "native",
        "recipe_identity": "b" * 64, "probe_identity": "c" * 64, "upstream_handoff_sha256": "d" * 64,
        "image": {"image_id": "sha256:" + "e" * 64}, "executor_identity": "executor/1",
        "capture_identity": "capture/1",
        "commands": [{"command_id": "compile", "argv_sha256": "1" * 64, "role": "build",
                      "tool_kind": "compiler-driver"},
                     {"command_id": "link", "argv_sha256": "2" * 64, "role": "build",
                      "tool_kind": "linker-driver"}],
        "tool_invocations": CountingList(invocations),
        "relationships": CountingList({"artifact_sha256": item["sha256"], "command_id": "compile",
                                       "confidence": 0.9, "mapping": "fixture"} for item in objects),
        "validated_artifacts": [*objects, app],
    }


NATIVE_SPEC = (("build/main.o", "object", b"object-one"), ("build/app", "executable", b"\x7fELFapp"))


def recorded_receipt(run_root: Path, *, unit_id: str = "build-unit-00000000000000000001", family: str = "native",
                     ordinal: int = 1, artifacts: tuple[tuple[str, str, bytes], ...] = NATIVE_SPEC,
                     snapshot: str = SNAPSHOT) -> dict[str, Any]:
    """A successful language-build receipt whose workspace, files and manifest exist under ``run_root``.

    This is the shape ``_validate_receipts`` reads: unvalidated, with ``artifacts`` referencing real
    bytes in the workspace and a workspace manifest binding every produced path to its hash.
    """
    workspace = run_root / "data" / "build" / family / unit_id / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    produced = []
    files = {}
    for relative, kind, content in artifacts:
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files[relative] = file_sha256(path)
        produced.append({**identity(run_root, path), "workspace_path": relative, "kind": kind,
                         "build_unit_id": unit_id, "mapping": "exact-workspace-path", "mapping_confidence": 1.0})
    manifest_path = workspace.parent / "workspace-manifest.json"
    atomic_json(manifest_path, {"schema": WORKSPACE_MANIFEST_SCHEMA, "build_unit_id": unit_id, "files": files})
    command_id = f"command-{ordinal}"
    return {
        "schema": RECEIPT_SCHEMA,
        "fingerprint": str(ordinal) * 64,
        "source_fingerprint": snapshot,
        "upstream_handoff_sha256": "a" * 64,
        "build_unit_id": unit_id,
        "family": family,
        "recipe_identity": str(ordinal + 4) * 64,
        "probe_identity": str(ordinal + 5) * 64,
        "image": {"image_id": f"sha256:{str(ordinal + 6) * 64}"},
        "workspace": workspace.relative_to(run_root).as_posix(),
        "workspace_manifest": identity(run_root, manifest_path),
        "commands": [{"command_id": command_id, "argv_sha256": str(ordinal) * 64,
                      "image_id": f"sha256:{str(ordinal + 6) * 64}", "role": "build", "tool_kind": "build-driver"}],
        "tool_invocations": [],
        "artifacts": produced,
        "gaps": [],
        "terminal_status": "SUCCEEDED",
        "executor_identity": f"fixture-{family}-executor/1",
        "capture_identity": f"fixture-{family}-capture/1",
    }


def rewrite_manifest(run_root: Path, receipt: dict[str, Any], files: dict[str, str]) -> None:
    """Replace the receipt's workspace manifest entries and re-bind the receipt to the new bytes."""
    manifest_path = run_root / receipt["workspace_manifest"]["path"]
    atomic_json(manifest_path, {"schema": WORKSPACE_MANIFEST_SCHEMA,
                                "build_unit_id": receipt["build_unit_id"], "files": files})
    receipt["workspace_manifest"] = identity(run_root, manifest_path)


def unit_context(run_root: Path, unit_id: str, outputs: dict[str, Any] | None = None, *,
                 snapshot: str = SNAPSHOT, settings: dict[str, str] = SETTINGS,
                 attempt_id: str = "attempt_0001", target_root: Path | None = None) -> SimpleNamespace:
    """What a handler reads from ``UnitContext``: the job's roots, snapshot, settings and upstream outputs."""
    outputs = dict(outputs or {})
    attempt_root = run_root / "data" / "jobs" / "job_artifact_indexing" / "attempts" / attempt_id
    job = SimpleNamespace(run_root=run_root, run_id=run_root.name, attempt_id=attempt_id, attempt_root=attempt_root,
                          source_fingerprint=snapshot, config=SimpleNamespace(settings=dict(settings)),
                          target_root=target_root, repository_root=run_root)
    return SimpleNamespace(unit_id=unit_id, job=job, outputs=outputs, output=lambda name: outputs[name])


def loaded_output(receipts: list[dict[str, Any]], *, target_artifacts: list[dict[str, Any]] | None = None,
                  producer_gaps: list[str] | None = None, upstream_manifest: dict[str, str] | None = None,
                  catalog_handoff: str | None = None) -> dict[str, Any]:
    """The ``load.accepted_builds`` output the three index units and the publisher consume."""
    return {"receipts": receipts, "receipt_count": len(receipts),
            "target_artifacts": list(target_artifacts or []), "target_catalog_handoff_sha256": catalog_handoff,
            "producer_gaps": list(producer_gaps or []), "language_build_handoff_sha256": "f" * 64,
            "upstream_manifest": upstream_manifest or {"path": "data/indices/manifests/language-build.json",
                                                        "sha256": "0" * 64},
            "terminal_status": "COMPLETED_WITH_GAPS" if producer_gaps else "SUCCEEDED" if receipts else "NOT_APPLICABLE"}
