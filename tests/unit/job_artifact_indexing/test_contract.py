"""job_artifact_indexing: the declared inputs and outputs are the job's contract.

The job consumes the accepted language-build handoff (its receipt set and index manifest are the
two REQUIRED/REJECT inputs) and, optionally, the target catalog's artifact intake; it publishes
three indexed ``artifacts`` dataset families, distinguished by shard-id prefix, and an
artifact-only acceptance summary with its shard locks. These tests pin every input and output
declaration, that each input names a dataset its producer really declares with the same schema,
the files the handlers read and write under the run root, and that the published summary and the
shards land inside their declared claims with the declared schema ids.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_artifact_indexing.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_artifact_indexing import job as indexing
from appsec_review.jobs.job_artifact_indexing.job import (
    _TOPOLOGY, SCHEMA, _batch_shard_id, _catalogs, _members, _relationships, build_job,
)
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.indexing.inventory import compile_glob
from appsec_review.retrieval import INDEX_SCHEMA, write_manifest
from appsec_review.runtime.contracts import (
    Availability, CoveragePolicy, DispatchClass, EvidenceAuthority, InputChannel, MissingPolicy, TargetAccess,
)
from appsec_review.runtime.datasets import METADATA_ROUTE
from appsec_review.runtime import consume
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import put_file
from tests.unit.job_artifact_indexing.support import (
    RUN_ID, SNAPSHOT, assert_published_gaps, loaded_output, recorded_receipt, unit_context,
    validated_artifact, validated_receipt,
)

HANDOFF = "appsec-review/job-handoff/2"
INDEX = "appsec-review/retrieval-index/2"
EXPECTED_INPUTS = (
    ("job_language_build", "handoff", HANDOFF, Availability.REQUIRED, MissingPolicy.REJECT),
    ("job_language_build", "topology_refinement_inputs", "appsec-review/build-topology-refinement/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "build_actions", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "jvm_build_actions", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "language_build_receipts", "appsec-review/language-build-handoff/2",
     Availability.REQUIRED, MissingPolicy.REJECT),
    ("job_language_build", "build_workspaces", "application/octet-stream", Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "handoff", HANDOFF, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "source_files", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "declaration_symbols", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "components", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "target_documents", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "build_units", INDEX, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1", Availability.OPTIONAL, MissingPolicy.GAP),
)


def _declared() -> dict[str, object]:
    return {item.output_kind: item for item in DATASETS}


def _claimed(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS
            if any(compile_glob(pattern).fullmatch(path) for pattern in item.artifacts)]


def _shard_claims(shard_id: str) -> list[str]:
    return [item.output_kind for item in DATASETS if "artifacts" in item.indexes
            and any(shard_id.startswith(prefix) for prefix in item.shard_prefixes)]


# --- inputs ----------------------------------------------------------------------------------------

def test_inputs_are_pinned_with_their_producer_dataset_schema_availability_and_missing_policy() -> None:
    assert [(item.producer, item.output_kind, item.schema, item.availability, item.missing)
            for item in CONTRACT.inputs] == list(EXPECTED_INPUTS)
    for item in CONTRACT.inputs:
        assert item.channel is InputChannel.HANDOFF, item.output_kind
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE, item.output_kind
        assert item.coverage is CoveragePolicy.ALLOW_PARTIAL, item.output_kind
        assert set(asdict(item)) == {
            "producer", "output_kind", "schema", "availability", "missing", "channel", "authority", "coverage",
        }
    required = [(item.producer, item.output_kind) for item in CONTRACT.inputs
                if item.availability is Availability.REQUIRED or item.missing is MissingPolicy.REJECT]
    assert required == [("job_language_build", "handoff"), ("job_language_build", "language_build_receipts")]


def test_every_dataset_input_names_a_declaration_its_producer_makes_with_the_same_schema() -> None:
    producers = {"job_language_build": {item.output_kind: item for item in LANGUAGE_DATASETS},
                 "job_target_catalog": {item.output_kind: item for item in CATALOG_DATASETS}}
    for item in CONTRACT.inputs:
        if item.output_kind == "handoff":
            continue
        declaration = producers[item.producer].get(item.output_kind)
        assert declaration is not None, f"{item.producer} does not declare {item.output_kind}"
        assert declaration.schema == item.schema, item.output_kind
        assert declaration.authority is item.authority, item.output_kind
    # every dataset the two producers declare is consumed: a new upstream output needs a decision here
    for producer, declarations in producers.items():
        consumed = {item.output_kind for item in CONTRACT.inputs if item.producer == producer}
        assert consumed == set(declarations) | {"handoff"}, producer


def test_the_job_is_a_review_graph_producer_scheduled_after_the_language_build() -> None:
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ("job_language_build",)
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True
    assert CONTRACT.consumes == CONSUMES == ("job_language_build", "job_target_catalog")


# --- outputs ---------------------------------------------------------------------------------------

def test_outputs_are_three_indexed_artifact_families_and_one_artifact_only_summary() -> None:
    declared = _declared()
    assert [(k, v.step, v.family, v.disposition, v.schema) for k, v in declared.items()] == [
        ("artifact_catalog", "index", "artifacts", "indexed", INDEX_SCHEMA),
        ("archive_members", "index", "artifacts", "indexed", INDEX_SCHEMA),
        ("artifact_relationships", "index", "artifacts", "indexed", INDEX_SCHEMA),
        ("artifact_index_summary", "acceptance", "artifacts", "artifact_only", SCHEMA),
    ]
    assert INDEX_SCHEMA == INDEX
    for kind in ("artifact_catalog", "archive_members", "artifact_relationships"):
        item = declared[kind]
        assert item.indexes == ("artifacts",) and item.artifacts == () and item.store == "retrieval", kind
        assert item.query_route and item.sensitivity == "internal" and item.required is False, kind
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE, kind
    assert declared["artifact_catalog"].shard_prefixes == ("catalog-",)
    assert declared["archive_members"].shard_prefixes == ("members-",)
    assert declared["artifact_relationships"].shard_prefixes == ("relations-",)
    assert "query_artifacts" in declared["artifact_catalog"].query_route
    assert "kind=archive_member" in declared["archive_members"].query_route
    assert "GENERATED_FROM,LINKS_INTO" in declared["artifact_relationships"].query_route
    summary = declared["artifact_index_summary"]
    assert summary.indexes == () and summary.query_route == METADATA_ROUTE
    assert summary.artifacts == ("data/jobs/job_artifact_indexing/attempts/*/artifacts/artifact-indexing/*.json",
                                 "data/indices/artifacts/*.lock")
    assert "already published by the artifacts index" in summary.reason
    common = {
        "family": "artifacts", "sensitivity": "internal", "required": False,
        "store": "retrieval", "authority": EvidenceAuthority.PRODUCER_EVIDENCE,
        "shard_suffixes": (),
    }
    indexed = {**common, "step": "index", "schema": INDEX, "disposition": "indexed",
               "indexes": ("artifacts",), "artifacts": (), "reason": None}
    assert [asdict(item) for item in DATASETS] == [
        {**indexed, "output_kind": "artifact_catalog", "shard_prefixes": ("catalog-",),
         "description": "Produced artifacts and target-intake artifacts with exact hashes and distinct provenance.",
         "query_route": "query_artifacts; query_precomputed query_set=artifact_inventory"},
        {**indexed, "output_kind": "archive_members", "shard_prefixes": ("members-",),
         "description": "Members of produced package archives.",
         "query_route": "query_artifacts kind=archive_member"},
        {**indexed, "output_kind": "artifact_relationships", "shard_prefixes": ("relations-",),
         "description": "Producing-action and link relationships for produced artifacts.",
         "query_route": "trace relations=GENERATED_FROM,LINKS_INTO; query_artifacts producing_build_action"},
        {**common, "output_kind": "artifact_index_summary", "step": "acceptance", "schema": SCHEMA,
         "disposition": "artifact_only", "description": "Accepted artifact-index summary and shard locks.",
         "indexes": (), "shard_prefixes": (), "query_route": METADATA_ROUTE,
         "artifacts": ("data/jobs/job_artifact_indexing/attempts/*/artifacts/artifact-indexing/*.json",
                       "data/indices/artifacts/*.lock"),
         "reason": "counts and shard identities already published by the artifacts index"},
    ]
    steps = {unit.unit_id.split(".")[0] for unit in build_job().units}
    assert {item.step for item in DATASETS} == {"index", "acceptance"} < steps == set(_TOPOLOGY)


def test_summary_and_shard_lock_paths_are_claimed_and_the_attempt_tree_and_shards_are_not() -> None:
    assert _claimed("data/jobs/job_artifact_indexing/attempts/attempt_0001/artifacts/artifact-indexing/"
                    "accepted-index.json") == ["artifact_index_summary"]
    assert _claimed(f"data/indices/artifacts/{'a' * 64}.sqlite.lock") == ["artifact_index_summary"]
    assert _claimed(f"data/indices/artifacts/{'a' * 64}.sqlite") == [], "shards are claimed by index name and prefix"
    assert _claimed("data/jobs/job_artifact_indexing/attempts/attempt_0001/result.json") == []
    assert _claimed("data/jobs/job_artifact_indexing/attempts/attempt_0001/artifacts/"
                    "artifact-indexing/nested/accepted-index.json") == []
    assert _claimed("data/indices/manifests/artifact-indexing-attempt_0001.json") == [], \
        "the merged manifest is handed off by reference, not claimed as a dataset"
    for shard_id, kind in (("catalog-build-unit-1-object_file", "artifact_catalog"),
                           ("catalog-target-intake", "artifact_catalog"),
                           (_batch_shard_id("members", "build-unit-1", 0), "archive_members"),
                           (_batch_shard_id("relations", "build-unit-1", 3), "artifact_relationships")):
        assert _shard_claims(shard_id) == [kind], shard_id
    assert _shard_claims("build-unit-1") == []


def test_every_shard_the_index_units_build_is_claimed_by_exactly_one_declared_prefix(tmp_path: Path) -> None:
    receipt = validated_receipt(2)
    receipt["validated_artifacts"].append(validated_artifact("dist/sample.whl", "wheel", "PK-wheel"))
    receipt["package_members"] = [{"package_path": "dist/sample.whl", "member": "sample/__init__.py", "size_bytes": 12}]
    loaded = loaded_output([receipt])
    results = {"artifact_catalog": _catalogs(unit_context(tmp_path, "index.catalogs", {"load.accepted_builds": loaded})),
               "archive_members": _members(unit_context(tmp_path, "index.members", {"load.accepted_builds": loaded})),
               "artifact_relationships": _relationships(
                   unit_context(tmp_path, "index.relationships", {"load.accepted_builds": loaded}))}
    for kind, result in results.items():
        assert result["indexes"], kind
        for index in result["indexes"]:
            assert index["name"] == "artifacts" and index["schema"] == INDEX_SCHEMA, kind
            assert _shard_claims(index["shard_id"]) == [kind], index["shard_id"]
            assert index["relative_path"].startswith("data/indices/artifacts/") and index["relative_path"].endswith(".sqlite")
            assert (tmp_path / index["relative_path"]).is_file()
            assert index["producer"]["job"] == "job_artifact_indexing"


# --- the files the handlers read and write ---------------------------------------------------------

def test_load_reads_the_admitted_manifest_workspace_manifest_and_workspace_or_retained_payloads(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / RUN_ID
    receipt = recorded_receipt(root)
    retained = receipt["artifacts"][1]
    retained.update(put_file(root, root / retained["path"]))
    manifest_path = root / "data/indices/manifests/language-build.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=tmp_path, indexes=[])
    reference = {"path": "data/indices/manifests/language-build.json", "sha256": file_sha256(manifest_path)}
    handoff = {"outputs": {"acceptance.publish_handoff": {"index_manifest": reference}}, "artifacts": [reference]}
    monkeypatch.setattr(consume, "accepted_upstream", lambda run, job: SimpleNamespace(handoff=handoff))
    monkeypatch.setattr(indexing, "load_accepted_language_build", lambda run: {
        "source_fingerprint": SNAPSHOT, "receipts": [receipt], "gaps": [], "language_build_handoff_sha256": "f" * 64,
    })
    monkeypatch.setattr(indexing, "_target_artifacts", lambda unit: ([], [], None))
    reads = []
    safe_file = indexing._safe_file

    def tracked(run, identity, label):
        reads.append((run, identity["path"], label))
        return safe_file(run, identity, label)

    monkeypatch.setattr(indexing, "_safe_file", tracked)
    result = build_job().units[0].handler(unit_context(root, "load.accepted_builds"))
    assert reads == [
        (root, "data/indices/manifests/language-build.json", "language-build index manifest"),
        (root, "data/build/native/build-unit-00000000000000000001/workspace-manifest.json", "workspace manifest"),
        (root, "data/build/native/build-unit-00000000000000000001/workspace/build/main.o", "produced artifact"),
        (root, f"data/shared/objects/{retained['sha256']}", "produced artifact"),
    ]
    assert result["upstream_manifest"] == reference and result["producer_gaps"] == []
    assert result["receipt_count"] == 1 and len(result["receipts"][0]["validated_artifacts"]) == 2
    assert not (root / "data/jobs/job_artifact_indexing").exists(), "load does not write job artifacts"


def test_publish_writes_the_summary_inside_its_glob_with_the_declared_schema_and_a_merged_manifest(
        tmp_path: Path) -> None:
    run_root = tmp_path / RUN_ID
    target = tmp_path / "target"
    target.mkdir()
    prior = run_root / "data/indices/manifests/language-build.json"
    prior_document = write_manifest(prior, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=[])
    loaded = loaded_output([], producer_gaps=["accepted language-build handoff contained no receipts"],
                           upstream_manifest={"path": "data/indices/manifests/language-build.json",
                                              "sha256": file_sha256(prior)}, catalog_handoff="c" * 64)
    empty = {"indexes": [], "shard_count": 0, "reused_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}
    unit = unit_context(run_root, "acceptance.publish_handoff", {
        "load.accepted_builds": loaded, "index.catalogs": empty, "index.members": empty,
        "index.relationships": {**empty, "gaps": ["build/app: producing action mapping is ambiguous"]}},
        target_root=target)
    publish = {item.unit_id: item.handler for item in build_job().units}["acceptance.publish_handoff"]
    result = publish(unit)
    assert result["schema"] == SCHEMA and result["item_count"] == 0
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["gaps"] == ["accepted language-build handoff contained no receipts",
                              "build/app: producing action mapping is ambiguous"]
    assert_published_gaps(tmp_path, unit.unit_id, result["gaps"], [
        "accepted language-build handoff contained no receipts", "build/app: producing action mapping is ambiguous",
    ])
    summary_path = result["artifact"]["path"]
    assert summary_path == "data/jobs/job_artifact_indexing/attempts/attempt_0001/artifacts/artifact-indexing/accepted-index.json"
    assert _claimed(summary_path) == ["artifact_index_summary"]
    document = json.loads((run_root / summary_path).read_bytes())
    assert document["schema"] == SCHEMA == _declared()["artifact_index_summary"].schema
    assert (document["source_fingerprint"], document["language_build_handoff_sha256"],
            document["target_catalog_handoff_sha256"]) == (SNAPSHOT, "f" * 64, "c" * 64)
    assert (document["artifact_shard_count"], document["reused_shard_count"], document["artifact_count"]) == (0, 0, 0)
    assert document["gaps"] == result["gaps"] and document["index_manifest"] == result["index_manifest"]
    assert file_sha256(run_root / summary_path) == result["artifact"]["sha256"]
    manifest_path = result["index_manifest"]["path"]
    assert manifest_path == "data/indices/manifests/artifact-indexing-attempt_0001.json"
    manifest = json.loads((run_root / manifest_path).read_bytes())
    assert manifest["schema"] == "appsec-review/index-manifest/1"
    assert manifest["upstream_manifests"] == [loaded["upstream_manifest"]]
    assert manifest["indexes"] == prior_document["indexes"] == []
    assert manifest["target_snapshot"] == SNAPSHOT and manifest["run_id"] == RUN_ID


def test_publish_refuses_an_upstream_manifest_whose_bytes_moved(tmp_path: Path) -> None:
    run_root = tmp_path / RUN_ID
    prior = run_root / "data/indices/manifests/language-build.json"
    write_manifest(prior, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=tmp_path, indexes=[])
    loaded = loaded_output([], upstream_manifest={"path": "data/indices/manifests/language-build.json", "sha256": "0" * 64})
    empty = {"indexes": [], "shard_count": 0, "reused_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}
    unit = unit_context(run_root, "acceptance.publish_handoff", {
        "load.accepted_builds": loaded, "index.catalogs": empty, "index.members": empty, "index.relationships": empty})
    publish = {item.unit_id: item.handler for item in build_job().units}["acceptance.publish_handoff"]
    with pytest.raises(ValueError, match="integrity mismatch"):
        publish(unit)
    assert not (run_root / "data/jobs").exists(), "nothing is published after a failed verification"


def test_the_job_carries_the_contract_and_declarations_it_was_built_from() -> None:
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes
    assert (job.job_id, job.name, job.schema_identity) == ("job_artifact_indexing", "artifact_indexing", SCHEMA)
    assert job.always_execute is False and job.propagate_handoff is True
    assert [unit.unit_id for unit in job.units] == [
        "load.accepted_builds", "index.catalogs", "index.members", "index.relationships", "acceptance.publish_handoff"]
