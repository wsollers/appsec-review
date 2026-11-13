"""job_artifact_indexing: ``_target_artifacts`` admits the target catalog's prebuilt artifact
intake only with exact provenance, never reading the intake handoff the job does not declare.

The accepted-upstream check and the catalog loader are faked at their module boundary; the object
store under the run root is real, so payload verification runs against bytes the test wrote.
The provenance rejections come from the pre-walk ``tests/test_target_artifact_intake.py``.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import SCOPE_VERSION, ScopeRole
from appsec_review.jobs.job_artifact_indexing.job import (
    ArtifactIndexIntegrityError, _target_artifacts, canonical_target_artifact_identity,
)
from appsec_review.jobs.job_evidence_collection import job as evidence
from appsec_review.runtime import consume
from appsec_review.storage import shared
from tests.unit.job_artifact_indexing.support import SNAPSHOT, unit_context

HANDOFF = "b" * 64


def _intake(run_root: Path, path: str = "module.wasm", content: bytes = b"\0asm\x01\0\0\0") -> dict:
    digest = hashlib.sha256(content).hexdigest()
    store = run_root / shared.OBJECTS / digest
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_bytes(content)
    return {"path": f"{shared.OBJECTS}/{digest}", "sha256": digest, "size_bytes": len(content),
            "schema": "appsec-review/target-artifact-intake/1", "kind": "wasm-module",
            "workspace_path": path, "target_relative_path": path, "artifact_origin": "target-intake",
            "scope_version": SCOPE_VERSION, "scope_role": ScopeRole.UNKNOWN.value,
            "source_fingerprint": SNAPSHOT, "delivery_status": "unknown",
            "mapping": "exact-target-path", "mapping_confidence": 1.0}


def _catalog(*artifacts: dict, available: bool = True, gaps: tuple[str, ...] = (), snapshot: str = SNAPSHOT):
    return SimpleNamespace(source_fingerprint=snapshot, handoff_sha256=HANDOFF,
                           target_artifact_inventory_available=available, target_artifact_gaps=gaps,
                           target_artifacts=tuple(artifacts))


@pytest.fixture
def accepted(monkeypatch):
    """The catalog the faked loader returns; the test sets ``.value`` before calling."""
    holder = SimpleNamespace(value=None, calls=[])
    monkeypatch.setattr(consume, "has_accepted_upstream", lambda root, job_id: job_id == "job_target_catalog")

    def load_catalog_without_intake(_root, *, intake_target_root):
        # Artifact indexing declares no job_review_intake input, so it must not ask for that read.
        holder.calls.append(intake_target_root)
        assert intake_target_root is False
        return holder.value

    monkeypatch.setattr(evidence, "load_target_catalog", load_catalog_without_intake)
    return holder


def test_valid_intake_is_returned_with_canonical_identity_producer_and_a_delivery_gap(tmp_path: Path, accepted) -> None:
    raw = _intake(tmp_path)
    accepted.value = _catalog(raw, gaps=("vendor/blob.bin: inventory_bound_reached",))
    artifacts, gaps, handoff = _target_artifacts(unit_context(tmp_path, "load.accepted_builds"))
    assert handoff == HANDOFF and accepted.calls == [False]
    (artifact,) = artifacts
    assert artifact is not raw and {key: artifact[key] for key in raw} == raw
    assert artifact["canonical_identity"] == canonical_target_artifact_identity(SNAPSHOT, raw).value
    assert artifact["producer"] == {"job_id": "job_target_catalog", "handoff_sha256": HANDOFF,
                                    "source_fingerprint": SNAPSHOT}
    assert gaps == ["vendor/blob.bin: inventory_bound_reached", "module.wasm: target artifact delivery status is unknown"]


def test_without_an_accepted_catalog_the_intake_is_a_named_gap_and_nothing_is_read(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(consume, "has_accepted_upstream", lambda root, job_id: False)
    monkeypatch.setattr(evidence, "load_target_catalog",
                        lambda *args, **kwargs: pytest.fail("catalog read without an accepted upstream"))
    assert _target_artifacts(unit_context(tmp_path, "load.accepted_builds")) == (
        [], ["accepted target artifact intake is unavailable"], None)


def test_a_legacy_catalog_without_an_inventory_is_a_gap_bound_to_its_handoff(tmp_path: Path, accepted) -> None:
    accepted.value = _catalog(available=False)
    assert _target_artifacts(unit_context(tmp_path, "load.accepted_builds")) == (
        [], ["legacy target catalog has no target artifact inventory"], HANDOFF)


def test_a_catalog_of_another_target_is_refused_before_any_entry_is_read(tmp_path: Path, accepted) -> None:
    accepted.value = _catalog(_intake(tmp_path), snapshot="other")
    with pytest.raises(ArtifactIndexIntegrityError, match="belongs to a different target"):
        _target_artifacts(unit_context(tmp_path, "load.accepted_builds"))


CORRUPTIONS = {
    "platform_role": ("scope_role", ScopeRole.PLATFORM.value),
    "different_target": ("source_fingerprint", "different"),
    "outside_object_store": ("path", "data/codeql/scopes/unit/export/pack/supplied"),
    "wrong_schema": ("schema", "appsec-review/target-artifact-intake/0"),
    "wrong_origin": ("artifact_origin", "build-output"),
    "wrong_scope_version": ("scope_version", "appsec-review/delivered-scope/1"),
    "path_mismatch": ("target_relative_path", "other.wasm"),
    "delivered": ("delivery_status", "delivered"),
    "heuristic_mapping": ("mapping_confidence", 0.9),
    "other_mapping": ("mapping", "heuristic"),
}


@pytest.mark.parametrize("corrupt", sorted(CORRUPTIONS))
def test_invalid_target_artifact_provenance_is_rejected_before_payload_access(tmp_path: Path, monkeypatch, accepted,
                                                                             corrupt: str) -> None:
    raw = _intake(tmp_path)
    key, value = CORRUPTIONS[corrupt]
    raw[key] = value
    accepted.value = _catalog(raw)
    monkeypatch.setattr(shared, "verify_reference",
                        lambda *args: pytest.fail("invalid provenance reached payload verification"))
    with pytest.raises(ArtifactIndexIntegrityError, match="provenance is invalid"):
        _target_artifacts(unit_context(tmp_path, "load.accepted_builds"))


def test_repeated_target_paths_invalid_entries_and_weak_identities_are_rejected(tmp_path: Path, accepted) -> None:
    unit = unit_context(tmp_path, "load.accepted_builds")
    first = _intake(tmp_path)
    accepted.value = _catalog(first, dict(first))
    with pytest.raises(ArtifactIndexIntegrityError, match="repeats a target path"):
        _target_artifacts(unit)
    accepted.value = _catalog("not-a-mapping")
    with pytest.raises(ArtifactIndexIntegrityError, match="entry is invalid"):
        _target_artifacts(unit)
    accepted.value = _catalog({**first, "sha256": "short"})
    with pytest.raises(ArtifactIndexIntegrityError, match="canonical path, hash, and format"):
        _target_artifacts(unit)


def test_payload_bytes_are_verified_against_the_declared_hash_and_size(tmp_path: Path, accepted) -> None:
    unit = unit_context(tmp_path, "load.accepted_builds")
    accepted.value = _catalog({**_intake(tmp_path), "size_bytes": 3})
    with pytest.raises(ValueError, match="shared artifact integrity mismatch"):
        _target_artifacts(unit)
    missing = _intake(tmp_path, path="gone.wasm", content=b"gone")
    (tmp_path / missing["path"]).unlink()
    accepted.value = _catalog(missing)
    with pytest.raises(ValueError, match="shared artifact integrity mismatch"):
        _target_artifacts(unit)
