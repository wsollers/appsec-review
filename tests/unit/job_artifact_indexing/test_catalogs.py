"""job_artifact_indexing: the ``index.catalogs`` unit writes one immutable shard per build unit and
artifact family (plus one for target-intake artifacts), with the payload fields consumers query.

The handler is called with a unit context over a run root the test owns; the shards it writes are
opened read-only to assert rows. Replaces the catalog claims of the pre-walk graph tests
(``test_node_catalog_payload_preserves_source_identity...``, the catalog half of the mixed-language
partition test).
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_artifact_indexing import artifact_index_fingerprint, canonical_artifact_identity
from appsec_review.jobs.job_artifact_indexing.job import _catalogs, _manifest_entries, canonical_target_artifact_identity
from appsec_review.retrieval import INDEX_SCHEMA, index_fingerprint
from tests.unit.job_artifact_indexing.support import (
    SETTINGS, SNAPSHOT, UNIT, assert_published_gaps, loaded_output, unit_context, validated_artifact, validated_receipt,
)


def _rows(run_root: Path, index: dict, query: str, *parameters) -> list:
    with sqlite3.connect(f"file:{(run_root / index['relative_path']).as_posix()}?mode=ro", uri=True) as database:
        return database.execute(query, parameters).fetchall()


def _unit(run_root: Path, receipts: list[dict], **loaded):
    return unit_context(run_root, "index.catalogs", {"load.accepted_builds": loaded_output(receipts, **loaded)})


def test_one_shard_per_build_unit_and_family_in_family_order_with_bound_fingerprints(tmp_path: Path) -> None:
    receipt = validated_receipt(2)
    receipt["validated_artifacts"] += [validated_artifact("dist/sample.whl", "wheel", "PK"),
                                       validated_artifact("bin/Sample.dll", "managed-assembly", "MZ")]
    result = _catalogs(_unit(tmp_path, [receipt]))
    assert [item["shard_id"] for item in result["indexes"]] == [
        f"catalog-{UNIT}-executable", f"catalog-{UNIT}-managed_assembly", f"catalog-{UNIT}-object_file",
        f"catalog-{UNIT}-package"]
    assert (result["shard_count"], result["reused_count"], result["gaps"], result["terminal_status"]) == (4, 0, [], "SUCCEEDED")
    by_family = {}
    for artifact in receipt["validated_artifacts"]:
        by_family.setdefault({"object": "object_file", "executable": "executable", "wheel": "package",
                              "managed-assembly": "managed_assembly"}[artifact["kind"]], []).append(artifact)
    for index in result["indexes"]:
        family = index["shard_id"].rsplit("-", 1)[1]
        assert index["producer"] == {"job": "job_artifact_indexing", "unit": "index.catalogs", "family": family}
        assert index["name"] == "artifacts" and index["schema"] == INDEX_SCHEMA and index["gaps"] == ()
        assert index["relative_path"] == f"data/indices/artifacts/{index['fingerprint']}.sqlite"
        dependencies = artifact_index_fingerprint(
            name="artifacts", target_snapshot=SNAPSHOT, receipt=receipt, artifacts=by_family[family],
            upstream_manifests=_manifest_entries(receipt, by_family[family]), extractor_identity="none",
            parser_identity=SETTINGS["catalog_parser_identity"], normalizer_identity=SETTINGS["normalizer_identity"],
            mapping_identity=SETTINGS["mapping_identity"])
        assert index["fingerprint"] != dependencies, "the dependency fingerprint alone does not bind emitted content"
        assert _rows(tmp_path, index, "SELECT value FROM metadata WHERE key='fingerprint'") == [(index["fingerprint"],)]
        assert _rows(tmp_path, index, "SELECT area, status, gap FROM coverage") == [(f"{UNIT}:{family}", "complete", None)]
        assert _rows(tmp_path, index, "SELECT count(*) FROM entities") == [(len(by_family[family]),)]


def test_catalog_entities_carry_the_queryable_payload_native_id_name_and_text(tmp_path: Path) -> None:
    receipt = validated_receipt(1)
    artifact = receipt["validated_artifacts"][1]
    artifact.update({"artifact_origin": "build-output", "mapping": "exact-workspace-path", "mapping_confidence": 1.0,
                     "source_map": {"sources": ["../src/index.ts"], "source_identities": [{
                         "declared_path": "../src/index.ts", "workspace_path": "src/index.ts", "sha256": "f" * 64,
                         "size_bytes": 12, "mapping": "source-map", "mapping_confidence": 1.0}]},
                     "unlisted_key": "dropped"})
    receipt["family"] = "node"
    result = _catalogs(_unit(tmp_path, [receipt]))
    index = next(item for item in result["indexes"] if item["shard_id"].endswith("-executable"))
    (identity, kind, native_id, name, text, payload_json), = _rows(
        tmp_path, index, "SELECT identity, kind, native_id, name, text, payload_json FROM entities")
    assert identity == artifact["canonical_identity"] == canonical_artifact_identity(SNAPSHOT, UNIT, artifact).value
    assert (kind, native_id, name, text) == ("executable", artifact["sha256"], "app", "executable build/app")
    payload = json.loads(payload_json)
    assert payload["artifact_family"] == "executable" and payload["producer_family"] == "node"
    assert (payload["workspace_path"], payload["sha256"], payload["size_bytes"], payload["kind"]) == (
        "build/app", artifact["sha256"], 3, "executable")
    assert payload["artifact_origin"] == "build-output" and payload["mapping_confidence"] == 1.0
    assert payload["source_map"]["source_identities"][0]["workspace_path"] == "src/index.ts"
    assert "unlisted_key" not in payload and payload["package_integrity"] is None
    assert "canonical_identity" not in payload


def test_rerun_reuses_every_completed_shard_and_producer_gaps_drive_the_terminal_status(tmp_path: Path) -> None:
    receipts = [validated_receipt(2), validated_receipt(1, unit="build-unit-other")]
    first = _catalogs(_unit(tmp_path, receipts, producer_gaps=["build-unit-x: probe skipped"]))
    assert first["shard_count"] == 4 and first["reused_count"] == 0
    assert first["gaps"] == ["build-unit-x: probe skipped"] and first["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert_published_gaps(tmp_path, "index.catalogs", first["gaps"], ["build-unit-x: probe skipped"])
    second = _catalogs(_unit(tmp_path, receipts, producer_gaps=["build-unit-x: probe skipped"]))
    assert second["reused_count"] == second["shard_count"] == 4
    assert [(item["shard_id"], item["sha256"], item["fingerprint"]) for item in second["indexes"]] == [
        (item["shard_id"], item["sha256"], item["fingerprint"]) for item in first["indexes"]]


@pytest.mark.parametrize("field,before,after", [
    ("delivery_status", "unknown", "delivered"),
    ("source_map", {"sources": ["old.ts"]}, {"sources": ["new.ts"]}),
    ("package_metadata", {"version": "1"}, {"version": "2"}),
], ids=["delivery", "source-map", "package-metadata"])
def test_retry_indexes_changed_catalog_payload_without_replacing_old_bytes(
        tmp_path: Path, field: str, before, after) -> None:
    receipt = validated_receipt(0)
    artifact = receipt["validated_artifacts"][0]
    artifact[field] = before
    unit = _unit(tmp_path, [receipt])
    first, = _catalogs(unit)["indexes"]
    old_bytes = (tmp_path / first["relative_path"]).read_bytes()
    artifact[field] = after
    result = _catalogs(unit)
    second, = result["indexes"]
    assert result["reused_count"] == 0
    assert first["fingerprint"] != second["fingerprint"]
    for index, value in ((first, before), (second, after)):
        identity, payload = _rows(tmp_path, index, "SELECT identity, payload_json FROM entities")[0]
        assert identity == artifact["canonical_identity"]
        assert json.loads(payload)[field] == value
    assert (tmp_path / first["relative_path"]).read_bytes() == old_bytes
    retry = _catalogs(unit)
    assert retry["reused_count"] == 1 and retry["indexes"] == result["indexes"]


def test_retry_binds_the_bounded_payload_actually_written_not_only_sorted_raw_keys(tmp_path: Path) -> None:
    receipt = validated_receipt(0)
    artifact = receipt["validated_artifacts"][0]
    metadata = {f"field-{index:03d}": index for index in range(201)}
    artifact["package_metadata"] = metadata
    unit = _unit(tmp_path, [receipt])
    first, = _catalogs(unit)["indexes"]
    artifact["package_metadata"] = dict(reversed(list(metadata.items())))
    result = _catalogs(unit)
    second, = result["indexes"]
    assert result["reused_count"] == 0 and first["fingerprint"] != second["fingerprint"]
    payloads = [json.loads(_rows(tmp_path, index, "SELECT payload_json FROM entities")[0][0])["package_metadata"]
                for index in (first, second)]
    assert len(payloads[0]) == len(payloads[1]) == 200
    assert "field-000" in payloads[0] and "field-200" not in payloads[0]
    assert "field-200" in payloads[1] and "field-000" not in payloads[1]


def test_no_receipts_and_no_target_artifacts_is_not_applicable(tmp_path: Path) -> None:
    assert _catalogs(_unit(tmp_path, [])) == {"indexes": [], "shard_count": 0, "reused_count": 0, "gaps": [],
                                               "terminal_status": "NOT_APPLICABLE"}
    failed = {**validated_receipt(0), "validated_artifacts": []}
    assert _catalogs(_unit(tmp_path, [failed]))["indexes"] == []


def test_target_intake_artifacts_get_their_own_partial_shard_with_delivery_gaps(tmp_path: Path) -> None:
    raw = {"path": "data/shared/objects/" + "a" * 64, "sha256": "a" * 64, "size_bytes": 8, "kind": "wasm-module",
           "target_relative_path": "prebuilt/module.wasm", "workspace_path": "prebuilt/module.wasm",
           "artifact_origin": "target-intake", "delivery_status": "unknown"}
    target = {**raw, "canonical_identity": canonical_target_artifact_identity(SNAPSHOT, raw).value,
              "producer": {"job_id": "job_target_catalog", "handoff_sha256": "b" * 64, "source_fingerprint": SNAPSHOT}}
    result = _catalogs(_unit(tmp_path, [], target_artifacts=[target], catalog_handoff="b" * 64))
    (index,) = result["indexes"]
    assert index["shard_id"] == "catalog-target-intake"
    assert index["producer"] == {"job": "job_artifact_indexing", "unit": "index.catalogs", "family": "target-intake"}
    assert index["gaps"] == ("prebuilt/module.wasm: target artifact delivery status is unknown",)
    assert_published_gaps(tmp_path, "index.catalogs", index["gaps"],
                          ["prebuilt/module.wasm: target artifact delivery status is unknown"])
    dependencies = index_fingerprint(
        name="artifacts", target_snapshot=SNAPSHOT, producer_artifacts=[target], tool_identity={"producer": "target-intake"},
        parser_identity=SETTINGS["catalog_parser_identity"], normalizer_identity=SETTINGS["normalizer_identity"],
        mapping_identity="exact-target-path/1")
    assert index["fingerprint"] != dependencies
    assert _rows(tmp_path, index, "SELECT value FROM metadata WHERE key='fingerprint'") == [(index["fingerprint"],)]
    assert _rows(tmp_path, index, "SELECT area, status, gap FROM coverage") == [
        ("target-artifact-intake", "partial", "prebuilt/module.wasm: target artifact delivery status is unknown")]
    (identity, native_id, name, text, payload_json), = _rows(
        tmp_path, index, "SELECT identity, native_id, name, text, payload_json FROM entities")
    assert identity == target["canonical_identity"]
    assert (native_id, name, text) == ("prebuilt/module.wasm", "module.wasm", "target artifact prebuilt/module.wasm")
    payload = json.loads(payload_json)
    assert payload["artifact_family"] == "wasm_module" and payload["producer_family"] == "target-intake"
    assert payload["producer"]["job_id"] == "job_target_catalog"
    # the unit's own gaps come from the load output, not from the intake shard
    assert result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED" and result["shard_count"] == 1
