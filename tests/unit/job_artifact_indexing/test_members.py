"""job_artifact_indexing: the ``index.members`` unit indexes the members of produced package
archives as entities contained by their parent package, one batched shard per build unit."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_artifact_indexing import canonical_archive_member_identity
from appsec_review.jobs.job_artifact_indexing.job import ArtifactIndexIntegrityError, _member_rows, _members
from appsec_review.retrieval import EntityKind, LogicalIdentity, RelationKind
from tests.unit.job_artifact_indexing.support import (
    SETTINGS, SNAPSHOT, UNIT, assert_published_gaps, loaded_output, unit_context, validated_artifact, validated_receipt,
)


def _package_receipt(members: list[dict] | None = None, unit: str = UNIT) -> dict:
    receipt = validated_receipt(1, unit=unit)
    receipt["validated_artifacts"].append(validated_artifact("dist/sample.whl", "wheel", "PK-wheel", unit))
    if members is not None:
        receipt["package_members"] = members
    return receipt


def _unit(run_root: Path, receipts: list[dict]):
    return unit_context(run_root, "index.members", {"load.accepted_builds": loaded_output(receipts)})


def _rows(run_root: Path, index: dict, query: str) -> list:
    with sqlite3.connect(f"file:{(run_root / index['relative_path']).as_posix()}?mode=ro", uri=True) as database:
        return database.execute(query).fetchall()


def test_members_become_entities_contained_by_their_package_in_member_order(tmp_path: Path) -> None:
    receipt = _package_receipt([
        {"package_path": "dist/sample.whl", "member": "sample-1.0.dist-info/METADATA", "size_bytes": 24},
        {"package_path": "./dist//sample.whl", "member": "sample/__init__.py", "size_bytes": 12, "sha256": "3" * 64},
    ])
    package = receipt["validated_artifacts"][-1]
    result = _members(_unit(tmp_path, [receipt]))
    (index,) = result["indexes"]
    assert index["shard_id"] == f"members-{UNIT}-0000"
    assert index["producer"] == {"job": "job_artifact_indexing", "unit": "index.members", "family": "members",
                                 "build_unit_id": UNIT, "batch": 0, "batch_count": 1}
    assert (result["shard_count"], result["reused_count"], result["gaps"], result["terminal_status"]) == (1, 0, [], "SUCCEEDED")
    parent = LogicalIdentity.parse(package["canonical_identity"])
    expected = [canonical_archive_member_identity(SNAPSHOT, parent, row) for row in sorted(
        receipt["package_members"], key=lambda item: item["member"])]
    entities = _rows(tmp_path, index, "SELECT identity, kind, native_id, name, payload_json FROM entities ORDER BY native_id")
    assert [(identity, kind, native_id, name) for identity, kind, native_id, name, _ in entities] == [
        (expected[0].value, "archive_member", "sample-1.0.dist-info/METADATA", "METADATA"),
        (expected[1].value, "archive_member", "sample/__init__.py", "__init__.py")]
    assert json.loads(entities[1][4]) == {"member_path": "sample/__init__.py", "size_bytes": 12, "sha256": "3" * 64,
                                          "parent_artifact": parent.value,
                                          "extractor_identity": SETTINGS["member_extractor_identity"]}
    assert json.loads(entities[0][4])["sha256"] is None
    relations = _rows(tmp_path, index, "SELECT kind, source_id, target_id, exact, confidence FROM relations ORDER BY target_id")
    assert relations == sorted([("CONTAINS", parent.value, member.value, 1, 1.0) for member in expected], key=lambda row: row[2])
    assert _rows(tmp_path, index, "SELECT area, status, gap FROM coverage") == [("dist/sample.whl", "complete", None)]


def test_a_package_without_a_member_manifest_is_a_partial_shard_with_a_named_gap(tmp_path: Path) -> None:
    result = _members(_unit(tmp_path, [_package_receipt()]))
    (index,) = result["indexes"]
    assert result["gaps"] == list(index["gaps"]) == ["dist/sample.whl: archive member manifest unavailable"]
    assert_published_gaps(tmp_path, "index.members", result["gaps"],
                          ["dist/sample.whl: archive member manifest unavailable"])
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert _rows(tmp_path, index, "SELECT area, status, gap FROM coverage") == [
        ("dist/sample.whl", "partial", "dist/sample.whl: archive member manifest unavailable")]
    assert _rows(tmp_path, index, "SELECT count(*) FROM entities") == [(0,)]


def test_receipts_without_packages_build_no_shard_and_are_not_applicable(tmp_path: Path) -> None:
    result = _members(_unit(tmp_path, [validated_receipt(2), {**validated_receipt(0), "validated_artifacts": []}]))
    assert result == {"indexes": [], "shard_count": 0, "reused_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}


def test_each_build_unit_gets_its_own_member_batches_and_a_rerun_reuses_them(tmp_path: Path) -> None:
    receipts = [_package_receipt([{"package_path": "dist/sample.whl", "member": "a", "size_bytes": 1}]),
                _package_receipt([{"package_path": "dist/sample.whl", "member": "b", "size_bytes": 1}], unit="build-unit-two")]
    first = _members(_unit(tmp_path, receipts))
    assert [item["shard_id"] for item in first["indexes"]] == [f"members-{UNIT}-0000", "members-build-unit-two-0000"]
    assert len({item["fingerprint"] for item in first["indexes"]}) == 2
    second = _members(_unit(tmp_path, receipts))
    assert second["reused_count"] == 2 and [item["sha256"] for item in second["indexes"]] == [
        item["sha256"] for item in first["indexes"]]


def test_invalid_or_duplicate_member_rows_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ArtifactIndexIntegrityError, match="manifest row is invalid"):
        _members(_unit(tmp_path, [_package_receipt(["not-a-row"])]))
    duplicate = [{"package_path": "dist/sample.whl", "member": "a", "size_bytes": 1},
                 {"package_path": "dist/sample.whl", "member": "a", "size_bytes": 1}]
    with pytest.raises(ArtifactIndexIntegrityError, match="duplicate identity"):
        _members(_unit(tmp_path, [_package_receipt(duplicate)]))
    with pytest.raises(ArtifactIndexIntegrityError, match="non-canonical"):
        _members(_unit(tmp_path, [_package_receipt([{"package_path": "dist/sample.whl", "member": "../x", "size_bytes": 1}])]))


def test_member_rows_are_pure_rows_of_the_artifact_sorted_by_member_path(tmp_path: Path) -> None:
    receipt = _package_receipt()
    package = receipt["validated_artifacts"][-1]
    rows = [{"member": "z", "size_bytes": 1}, {"member": "a/b", "size_bytes": 2}]
    item = _member_rows(unit_context(tmp_path, "index.members"), package, rows)
    assert item.artifact is package and item.gaps == [] and item.size == 4
    assert [entity.native_id for entity in item.entities] == ["a/b", "z"]
    assert all(entity.identity.kind is EntityKind.ARCHIVE_MEMBER for entity in item.entities)
    assert [(relation.kind, relation.source_id, relation.exact, relation.confidence) for relation in item.relations] == [
        (RelationKind.CONTAINS, package["canonical_identity"], True, 1.0)] * 2
    empty = _member_rows(unit_context(tmp_path, "index.members"), package, [])
    assert empty.gaps == ["dist/sample.whl: archive member manifest unavailable"] and empty.size == 0
    assert_published_gaps(tmp_path, "index.members", empty.gaps,
                          ["dist/sample.whl: archive member manifest unavailable"])
