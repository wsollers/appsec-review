"""job_artifact_indexing: ``_validate_receipts`` binds every accepted language-build receipt and
produced artifact to real bytes, the workspace manifest and the target snapshot before anything is
indexed. The receipts, workspaces and manifests are written by the test; nothing runs a graph.

These cases replace the pre-walk ``test_accepted_reader_rejects_malformed_or_unbound_retained_receipts``
(which drove the same checks through a JobRunner claim) and the two Node validation cases.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_artifact_indexing.job import (
    ArtifactIndexIntegrityError, _load_workspace_manifest, _safe_file, _validate_receipts,
)
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import OBJECTS, put_file
from tests.unit.job_artifact_indexing.support import (
    RUN_ID, SNAPSHOT, WORKSPACE_MANIFEST_SCHEMA, assert_published_gaps, identity, recorded_receipt, rewrite_manifest,
)


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    root = tmp_path / RUN_ID
    root.mkdir()
    return root


# --- the happy paths -------------------------------------------------------------------------------

def test_successful_receipt_yields_verified_artifacts_with_canonical_identities(run_root: Path) -> None:
    receipt = recorded_receipt(run_root)
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert gaps == []
    (result,) = validated
    assert result is not receipt and result["build_unit_id"] == receipt["build_unit_id"], "a copy, not the input"
    assert [item["workspace_path"] for item in result["validated_artifacts"]] == ["build/main.o", "build/app"]
    for artifact in result["validated_artifacts"]:
        assert artifact["canonical_identity"] == canonical_artifact_identity(
            SNAPSHOT, receipt["build_unit_id"], artifact).value
        assert "package_integrity" not in artifact


def test_a_receipt_without_a_source_fingerprint_is_accepted_and_a_retained_object_verifies(run_root: Path) -> None:
    receipt = recorded_receipt(run_root)
    receipt.pop("source_fingerprint")
    artifact = receipt["artifacts"][0]
    artifact.update(put_file(run_root, run_root / artifact["path"]))
    assert artifact["path"] == f"{OBJECTS}/{artifact['sha256']}"
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert gaps == [] and validated[0]["validated_artifacts"][0]["path"] == artifact["path"]


def test_non_successful_receipts_carry_their_gaps_scoped_by_unit_and_publish_no_artifacts(run_root: Path) -> None:
    failed = {**recorded_receipt(run_root, unit_id="build-unit-00000000000000000002", ordinal=2),
              "terminal_status": "FAILED", "artifacts": [],
              "gaps": [{"reason": "image preparation failed"}, "worker failure"]}
    skipped = {**recorded_receipt(run_root, unit_id="build-unit-00000000000000000003", ordinal=3),
               "terminal_status": "SKIPPED_POLICY", "artifacts": [], "gaps": []}
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [failed, skipped])
    assert [item["validated_artifacts"] for item in validated] == [[], []]
    assert gaps == ["build-unit-00000000000000000002: image preparation failed",
                    "build-unit-00000000000000000002: worker failure"]
    assert_published_gaps(run_root, "acceptance.publish_handoff", gaps, [
        "build-unit-00000000000000000002: image preparation failed",
        "build-unit-00000000000000000002: worker failure",
    ])


def test_a_successful_receipt_with_no_artifacts_is_a_named_gap_and_gaps_are_deduplicated(run_root: Path) -> None:
    receipt = recorded_receipt(run_root, artifacts=())
    receipt["gaps"] = ["probe skipped", "probe skipped"]
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert validated[0]["validated_artifacts"] == []
    assert gaps == ["build-unit-00000000000000000001: accepted successful build produced no artifact entries",
                    "build-unit-00000000000000000001: probe skipped"]
    assert_published_gaps(run_root, "acceptance.publish_handoff", gaps, [
        "build-unit-00000000000000000001: accepted successful build produced no artifact entries",
        "build-unit-00000000000000000001: probe skipped",
    ])


def test_an_empty_receipt_list_validates_to_nothing(run_root: Path) -> None:
    assert _validate_receipts(run_root, SNAPSHOT, []) == ([], [])


# --- rejections: the receipt ------------------------------------------------------------------------

def _mutate(run_root: Path, receipts: list[dict], mutation: str, tmp_path: Path) -> None:
    receipt = receipts[0]
    artifact = receipt["artifacts"][0]
    original = run_root / artifact["path"]
    artifact.update(put_file(run_root, original))
    blob = run_root / artifact["path"]
    if mutation == "missing-schema":
        receipt.pop("schema")
    elif mutation == "invalid-schema":
        receipt["schema"] = "appsec-review/language-build-receipt/unknown"
    elif mutation == "wasm-schema-ok":
        receipt["schema"] = "appsec-review/wasm-build-receipt/1"
    elif mutation == "duplicate-unit":
        receipts.append(dict(receipt))
    elif mutation == "empty-unit":
        receipt["build_unit_id"] = ""
    elif mutation == "wrong-snapshot":
        receipt["source_fingerprint"] = "0" * 64
    elif mutation == "invalid-artifacts":
        receipt["artifacts"] = {}
    elif mutation == "invalid-artifact":
        receipt["artifacts"] = ["not-a-mapping"]
    elif mutation == "failed-artifacts":
        receipt["terminal_status"] = "FAILED"
    elif mutation == "missing-manifest":
        receipt.pop("workspace_manifest")
    elif mutation == "missing-manifest-entry":
        files = json.loads((run_root / receipt["workspace_manifest"]["path"]).read_bytes())["files"]
        del files[artifact["workspace_path"]]
        rewrite_manifest(run_root, receipt, files)
    elif mutation == "wrong-manifest-entry":
        files = json.loads((run_root / receipt["workspace_manifest"]["path"]).read_bytes())["files"]
        files[artifact["workspace_path"]] = "0" * 64
        rewrite_manifest(run_root, receipt, files)
    elif mutation == "stale-manifest-reference":
        receipt["workspace_manifest"]["sha256"] = "0" * 64
    elif mutation == "hash":
        blob.write_bytes(b"tampered")
    elif mutation == "size":
        artifact["size_bytes"] += 1
    elif mutation == "missing-size":
        artifact.pop("size_bytes")
    elif mutation in {"arbitrary-path", "wrong-object-name"}:
        copy = run_root / ("data/arbitrary-output" if mutation == "arbitrary-path" else f"{OBJECTS}/" + "0" * 64)
        shutil.copyfile(blob, copy)
        artifact["path"] = copy.relative_to(run_root).as_posix()
    elif mutation == "noncanonical-path":
        artifact["path"] = artifact["path"].replace("/objects/", "//objects/")
    elif mutation == "outside-run":
        outside = tmp_path / "outside-output"
        shutil.copyfile(blob, outside)
        artifact["path"] = str(outside.resolve())
    elif mutation == "symlink-file":
        blob.unlink()
        blob.symlink_to(original)
    elif mutation == "symlink-parent":
        objects = blob.parent
        moved = objects.with_name("moved-objects")
        objects.rename(moved)
        objects.symlink_to(moved, target_is_directory=True)
    elif mutation == "symlink-outside":
        outside = tmp_path / "outside-output"
        shutil.copyfile(blob, outside)
        blob.unlink()
        blob.symlink_to(outside)
    elif mutation == "duplicate-artifact":
        receipt["artifacts"].append(dict(artifact))
    else:
        raise AssertionError(mutation)


REJECTIONS = {
    "missing-schema": "receipt schema is invalid",
    "invalid-schema": "receipt schema is invalid",
    "duplicate-unit": "duplicate build-unit identity",
    "empty-unit": "duplicate build-unit identity",
    "wrong-snapshot": "target snapshot changed",
    "invalid-artifacts": "artifact list is invalid",
    "invalid-artifact": "artifact identity is invalid",
    "failed-artifacts": "non-successful build receipt publishes artifacts",
    "missing-manifest": "has no workspace manifest",
    "missing-manifest-entry": "not bound to its workspace manifest",
    "wrong-manifest-entry": "not bound to its workspace manifest",
    "stale-manifest-reference": "workspace manifest hash mismatch",
    "hash": "produced artifact hash mismatch",
    "size": "produced artifact size mismatch",
    "missing-size": "size is invalid",
    "arbitrary-path": "not bound to its workspace manifest",
    "wrong-object-name": "not bound to its workspace manifest",
    "noncanonical-path": "not bound to its workspace manifest",
    "outside-run": "produced artifact path is invalid",
    "symlink-file": "retained produced artifact integrity is invalid",
    "symlink-parent": "retained produced artifact integrity is invalid",
    "symlink-outside": "produced artifact path is invalid",
    "duplicate-artifact": "duplicate canonical produced-artifact identity",
}


@pytest.mark.parametrize("mutation", sorted(REJECTIONS))
def test_malformed_or_unbound_retained_receipts_are_rejected_by_name(run_root: Path, tmp_path: Path, mutation: str) -> None:
    receipts = [recorded_receipt(run_root)]
    _mutate(run_root, receipts, mutation, tmp_path)
    with pytest.raises(ArtifactIndexIntegrityError, match=REJECTIONS[mutation]):
        _validate_receipts(run_root, SNAPSHOT, receipts)


def test_the_wasm_receipt_schema_is_accepted(run_root: Path, tmp_path: Path) -> None:
    receipts = [recorded_receipt(run_root)]
    _mutate(run_root, receipts, "wasm-schema-ok", tmp_path)
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, receipts)
    assert gaps == [] and len(validated[0]["validated_artifacts"]) == 2


# --- rejections: node receipts ---------------------------------------------------------------------

def _node(run_root: Path) -> dict:
    receipt = recorded_receipt(run_root)
    receipt["family"] = "node"
    for artifact in receipt["artifacts"]:
        artifact["artifact_origin"] = "build-output"
    return receipt


def test_node_artifact_validation_rejects_weakened_origin_mapping_or_workspace_identity(run_root: Path) -> None:
    receipt = _node(run_root)
    receipt["artifacts"][0]["artifact_origin"] = "untrusted-discovery"
    with pytest.raises(ArtifactIndexIntegrityError, match="origin is invalid"):
        _validate_receipts(run_root, SNAPSHOT, [receipt])
    receipt["artifacts"][0]["artifact_origin"] = "accepted-input"
    receipt["artifacts"][0]["build_unit_id"] = "other-unit"
    with pytest.raises(ArtifactIndexIntegrityError, match="build-unit identity changed"):
        _validate_receipts(run_root, SNAPSHOT, [receipt])
    receipt["artifacts"][0]["build_unit_id"] = receipt["build_unit_id"]
    receipt["artifacts"][0]["mapping_confidence"] = 0.9
    with pytest.raises(ArtifactIndexIntegrityError, match="workspace mapping is not exact"):
        _validate_receipts(run_root, SNAPSHOT, [receipt])
    receipt["artifacts"][0]["mapping_confidence"] = 1.0
    validated, _ = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert validated[0]["validated_artifacts"][0]["artifact_origin"] == "accepted-input"


def test_node_package_integrity_is_bound_to_the_workspace_artifact_and_normalized(run_root: Path) -> None:
    receipt = _node(run_root)
    artifact = receipt["artifacts"][1]
    artifact.update(kind="package")
    receipt["artifacts"] = [artifact]
    receipt["tool_invocations"] = [{"package_integrity": [{
        "workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"],
        "integrity": "sha512-fixture", "shasum": "A" * 40, "size": 12, "unpackedSize": 40, "totalFiles": 3,
    }]}]
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert not gaps
    assert validated[0]["validated_artifacts"][0]["package_integrity"] == {
        "workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"],
        "integrity": "sha512-fixture", "shasum": "a" * 40, "size": 12, "unpackedSize": 40, "totalFiles": 3}


NODE_INTEGRITY = {
    "not-a-mapping": ("not-a-row", "integrity metadata is invalid"),
    "unmanifested-path": ({"workspace_path": "build/other", "sha256": "a" * 64, "integrity": "sha512-x"},
                          "integrity identity changed"),
    "hash-differs": ({"workspace_path": "build/app", "sha256": "a" * 64, "integrity": "sha512-x"}, "integrity identity changed"),
    "sri-with-space": ({"workspace_path": "build/app", "integrity": "sha512 x"}, "integrity value is invalid"),
    "sri-empty": ({"workspace_path": "build/app", "integrity": ""}, "integrity value is invalid"),
    "sri-long": ({"workspace_path": "build/app", "integrity": "s" * 1025}, "integrity value is invalid"),
    "sri-number": ({"workspace_path": "build/app", "integrity": 1}, "integrity value is invalid"),
    "shasum-short": ({"workspace_path": "build/app", "shasum": "abc"}, "shasum is invalid"),
    "shasum-number": ({"workspace_path": "build/app", "shasum": 1}, "shasum is invalid"),
    "nothing": ({"workspace_path": "build/app"}, "integrity value is unavailable"),
    "size-negative": ({"workspace_path": "build/app", "integrity": "sha512-x", "size": -1}, "integrity size is invalid"),
    "size-bool": ({"workspace_path": "build/app", "integrity": "sha512-x", "totalFiles": True}, "integrity size is invalid"),
    "size-large": ({"workspace_path": "build/app", "integrity": "sha512-x", "size": 2**63}, "integrity size is invalid"),
}


@pytest.mark.parametrize("case", sorted(NODE_INTEGRITY))
def test_node_package_integrity_rows_are_rejected_by_name(run_root: Path, case: str) -> None:
    receipt = _node(run_root)
    artifact = receipt["artifacts"][1]
    artifact.update(kind="package")
    row, message = NODE_INTEGRITY[case]
    if isinstance(row, dict) and "sha256" not in row:
        row = {**row, "sha256": artifact["sha256"]}
    receipt["tool_invocations"] = [{"package_integrity": [row]}]
    with pytest.raises(ArtifactIndexIntegrityError, match=message):
        _validate_receipts(run_root, SNAPSHOT, [receipt])


def test_duplicate_node_package_integrity_paths_are_rejected(run_root: Path) -> None:
    receipt = _node(run_root)
    artifact = receipt["artifacts"][1]
    row = {"workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"], "integrity": "sha512-x"}
    receipt["tool_invocations"] = [{"package_integrity": [row, dict(row)]}]
    with pytest.raises(ArtifactIndexIntegrityError, match="integrity identity changed"):
        _validate_receipts(run_root, SNAPSHOT, [receipt])


def test_package_integrity_only_attaches_to_package_artifacts(run_root: Path) -> None:
    receipt = _node(run_root)
    artifact = receipt["artifacts"][1]  # kind executable
    receipt["tool_invocations"] = [{"package_integrity": [
        {"workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"], "integrity": "sha512-x"}]}]
    validated, _ = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert all("package_integrity" not in item for item in validated[0]["validated_artifacts"])


def test_node_integrity_accepts_exact_bounds_and_ignores_non_mapping_invocations(run_root: Path) -> None:
    receipt = _node(run_root)
    artifact = receipt["artifacts"][1]
    artifact["kind"] = "package"
    receipt["tool_invocations"] = [None, {"package_integrity": [{
        "workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"],
        "integrity": "s" * 1024, "size": 0, "unpackedSize": 2**63 - 1, "totalFiles": 0,
    }]}]
    validated, gaps = _validate_receipts(run_root, SNAPSHOT, [receipt])
    assert gaps == []
    assert validated[0]["validated_artifacts"][1]["package_integrity"] == {
        "workspace_path": artifact["workspace_path"], "sha256": artifact["sha256"],
        "integrity": "s" * 1024, "size": 0, "unpackedSize": 2**63 - 1, "totalFiles": 0,
    }


# --- the workspace manifest and the safe file reader --------------------------------------------------

def test_workspace_manifest_is_bound_by_schema_unit_and_canonical_unique_entries(run_root: Path) -> None:
    receipt = recorded_receipt(run_root)
    files = _load_workspace_manifest(run_root, receipt)
    assert set(files) == {"build/main.o", "build/app"} and all(len(value) == 64 for value in files.values())
    manifest_path = run_root / receipt["workspace_manifest"]["path"]
    for document, message in (
            ({"schema": "other", "build_unit_id": receipt["build_unit_id"], "files": {}}, "schema or build-unit identity"),
            ({"schema": WORKSPACE_MANIFEST_SCHEMA, "build_unit_id": "other", "files": {}}, "schema or build-unit identity"),
            ({"schema": WORKSPACE_MANIFEST_SCHEMA, "build_unit_id": receipt["build_unit_id"], "files": []},
             "schema or build-unit identity"),
            ({"schema": WORKSPACE_MANIFEST_SCHEMA, "build_unit_id": receipt["build_unit_id"],
              "files": {"a/b": "1" * 64, "a//b": "2" * 64}}, "duplicate or invalid identity"),
            ({"schema": WORKSPACE_MANIFEST_SCHEMA, "build_unit_id": receipt["build_unit_id"],
              "files": {"a/b": "short"}}, "duplicate or invalid identity")):
        atomic_json(manifest_path, document)
        receipt["workspace_manifest"] = identity(run_root, manifest_path)
        with pytest.raises(ArtifactIndexIntegrityError, match=message):
            _load_workspace_manifest(run_root, receipt)
    with pytest.raises(ArtifactIndexIntegrityError, match="has no workspace manifest"):
        _load_workspace_manifest(run_root, {**receipt, "workspace_manifest": "data/x.json"})


def test_safe_file_requires_a_regular_file_inside_the_run_with_matching_hash_and_optional_size(run_root: Path) -> None:
    path = run_root / "data" / "file.bin"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"bytes")
    reference = identity(run_root, path)
    assert _safe_file(run_root, reference, "label") == path.resolve()
    assert _safe_file(run_root, {"path": reference["path"], "sha256": reference["sha256"]}, "label") == path.resolve()
    for broken, message in (({**reference, "path": "data"}, "label path is invalid"),
                            ({**reference, "path": "../file.bin"}, "label path is invalid"),
                            ({**reference, "sha256": "0" * 64}, "label hash mismatch"),
                            ({**reference, "sha256": "nope"}, "label hash mismatch"),
                            ({**reference, "size_bytes": 4}, "label size mismatch"),
                            ({**reference, "size_bytes": "5"}, "label size mismatch")):
        with pytest.raises(ArtifactIndexIntegrityError, match=message):
            _safe_file(run_root, broken, "label")
    assert file_sha256(path) == reference["sha256"]
