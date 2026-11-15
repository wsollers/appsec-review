"""job_profile_data: declared inputs, dataset outputs, admission, and published schema/glob parity."""

from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatch
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import PROFILE_DATA_HANDOFF_SCHEMA
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.jobs.job_profile_data import job as job_module
from appsec_review.jobs.job_profile_data.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_profile_data.job import TOPOLOGY, ProfileIntegrityError, build_job
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.retrieval import INDEX_SCHEMA, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import UpstreamIntegrityError, upstream_scope
from appsec_review.runtime.contracts import (
    Availability,
    CoveragePolicy,
    DispatchClass,
    EvidenceAuthority,
    InputChannel,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import admit_inputs
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


HANDOFF = "appsec-review/job-handoff/2"
EXPECTED_INPUTS = (
    ("job_target_catalog", "handoff", HANDOFF, Availability.REQUIRED, MissingPolicy.REJECT),
    ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "source_files", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "declaration_symbols", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "components", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "target_documents", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "build_units", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "handoff", HANDOFF, Availability.WHEN_ENABLED, MissingPolicy.REJECT),
    ("job_language_build", "topology_refinement_inputs", "appsec-review/build-topology-refinement/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "build_actions", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "jvm_build_actions", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "language_build_receipts", "appsec-review/language-build-handoff/2",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_language_build", "build_workspaces", "application/octet-stream",
     Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_artifact_indexing", "handoff", HANDOFF, Availability.WHEN_ENABLED, MissingPolicy.REJECT),
    ("job_artifact_indexing", "artifact_catalog", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_artifact_indexing", "archive_members", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_artifact_indexing", "artifact_relationships", INDEX_SCHEMA, Availability.OPTIONAL, MissingPolicy.GAP),
    ("job_artifact_indexing", "artifact_index_summary", "appsec-review/artifact-indexing/1",
     Availability.OPTIONAL, MissingPolicy.GAP),
)


def _claimed(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS if any(fnmatch(path, pattern) for pattern in item.artifacts)]


def _shard_claims(shard_id: str) -> list[str]:
    return [
        item.output_kind for item in DATASETS
        if "analysis" in item.indexes and any(shard_id.startswith(prefix) for prefix in item.shard_prefixes)
    ]


def _ref(run_root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _seed_catalog_handoff(run_root: Path, snapshot: str) -> str:
    manifest_path = run_root / "data/indices/manifests/catalog-attempt_0001.json"
    write_manifest(manifest_path, run_id=run_root.name, target_snapshot=snapshot, target_root=run_root, indexes=())
    catalog_path = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog.json"
    manifest_ref = _ref(run_root, manifest_path)
    atomic_json(
        catalog_path,
        {"schema": "appsec-review/target-catalog/1", "source_fingerprint": snapshot, "artifacts": {}},
    )
    catalog_ref = _ref(run_root, catalog_path)
    handoff_path = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json"
    atomic_json(
        handoff_path.parent / "claim.json",
        {
            "dataset_contract": dataset_contract(
                "job_target_catalog",
                sorted({item.step for item in CATALOG_DATASETS}),
                tuple(replace(item, required=False) for item in CATALOG_DATASETS),
            )
        },
    )
    write_fixture_handoff(
        run_root,
        handoff_path,
        {
            "run_id": run_root.name,
            "job_id": "job_target_catalog",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "source_fingerprint": snapshot,
            "outputs": {
                "publish_catalog.publish_handoff": {
                    "artifact": catalog_ref,
                    "index_manifest": manifest_ref,
                }
            },
            "artifacts": [catalog_ref, manifest_ref],
        },
    )
    sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data/jobs/job_target_catalog/latest.json",
        {"handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": sha},
    )
    return sha


def test_inputs_are_pinned_with_producer_schema_and_availability_policies() -> None:
    actual = tuple(
        (item.producer, item.output_kind, item.schema, item.availability, item.missing)
        for item in CONTRACT.inputs
    )
    assert actual == EXPECTED_INPUTS
    for item in CONTRACT.inputs:
        assert item.channel is InputChannel.HANDOFF
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE
        assert item.coverage is CoveragePolicy.ALLOW_PARTIAL


def test_every_dataset_input_matches_its_upstream_producer_declaration() -> None:
    upstream = {
        "job_target_catalog": {item.output_kind: item for item in CATALOG_DATASETS},
        "job_language_build": {item.output_kind: item for item in LANGUAGE_DATASETS},
        "job_artifact_indexing": {item.output_kind: item for item in ARTIFACT_DATASETS},
    }
    for item in CONTRACT.inputs:
        if item.output_kind == "handoff":
            assert item.schema == HANDOFF
            continue
        declared = upstream[item.producer][item.output_kind]
        assert item.schema == declared.schema
        assert item.authority is declared.authority


def test_contract_topology_and_dataset_declarations_match_bounded_workflow() -> None:
    job = build_job()
    assert job.job_id == "job_profile_data"
    assert job.name == "profile_data"
    assert job.schema_identity == PROFILE_DATA_HANDOFF_SCHEMA
    assert job.contract == CONTRACT
    assert job.consumes == CONSUMES == (
        "job_artifact_indexing",
        "job_language_build",
        "job_target_catalog",
    )
    assert CONTRACT.schedule_after == ("job_artifact_indexing",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert [unit.unit_id for unit in job.units] == [
        "load.accepted_inputs",
        "normalize.profile_data",
        "index.profile_data",
        "acceptance.publish_handoff",
    ]
    assert tuple(TOPOLOGY) == ("load", "normalize", "index", "acceptance")

    by_kind = {item.output_kind: item for item in DATASETS}
    assert set(by_kind) == {"profile_data", "profile_data_handoff"}
    assert by_kind["profile_data"].step == "index"
    assert by_kind["profile_data"].indexes == ("analysis",)
    assert by_kind["profile_data"].shard_prefixes == ("profile-data-",)
    assert by_kind["profile_data"].query_route == "query_precomputed query_set=profile_data"
    assert by_kind["profile_data_handoff"].step == "acceptance"
    assert by_kind["profile_data_handoff"].schema == PROFILE_DATA_HANDOFF_SCHEMA


def test_missing_load_prerequisites_are_rejected_at_admission_and_handler(tmp_path: Path) -> None:
    job = build_job()
    context = SimpleNamespace(
        run_root=tmp_path,
        contract=job.contract,
        upstream_handoffs={},
        evidence_target_snapshot="profile-fixture",
        external_input_selection=None,
    )
    with pytest.raises(
        ValueError,
        match=r"required input unavailable: job_(artifact_indexing|language_build|target_catalog)/handoff",
    ):
        admit_inputs(context, enabled=set(context.contract.consumes))

    load = next(unit for unit in job.units if unit.unit_id == "load.accepted_inputs")
    with upstream_scope(tmp_path, job.job_id, {}, contract=context.contract):
        with pytest.raises(ProfileIntegrityError) as failure:
            load.handler(SimpleNamespace(job=context))
    assert str(failure.value) == (
        "accepted job_target_catalog handoff is required: "
        "accepted job_target_catalog handoff is required"
    )
    assert isinstance(failure.value.__cause__, UpstreamIntegrityError)
    assert list(tmp_path.iterdir()) == []

    catalog_sha = _seed_catalog_handoff(tmp_path, "profile-fixture")
    context.upstream_handoffs = {"job_target_catalog": catalog_sha}
    with pytest.raises(ValueError, match="required input unavailable: job_language_build/handoff"):
        admit_inputs(context, enabled={"job_target_catalog", "job_language_build"})
    admitted = admit_inputs(context, enabled={"job_target_catalog"})
    by_pair = {(row["producer"], row["output_kind"]): row["status"] for row in admitted["requirements"]}
    assert by_pair[("job_target_catalog", "handoff")] == "supplied"
    assert by_pair[("job_language_build", "handoff")] == "gap"
    assert by_pair[("job_artifact_indexing", "handoff")] == "gap"


def test_published_handoff_and_shard_match_declared_globs_and_schemas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = "a" * 64
    catalog_sha = _seed_catalog_handoff(tmp_path, snapshot)
    profile = tmp_path / "data/build/u1/profile/app.folded"
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_bytes(b"root;hot 9\nroot;cold 1\n")
    profile_ref = {
        **_ref(tmp_path, profile),
        "workspace_path": "profile/app.folded",
        "kind": "execution-profile",
        "artifact_origin": "build-output",
    }
    art_manifest_path = tmp_path / "data/indices/manifests/artifact-index-attempt_0001.json"
    write_manifest(art_manifest_path, run_id=tmp_path.name, target_snapshot=snapshot, target_root=tmp_path, indexes=())
    art_manifest_ref = _ref(tmp_path, art_manifest_path)

    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, _p: True)
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _root: {
            "source_fingerprint": snapshot,
            "language_build_handoff_sha256": "b" * 64,
            "receipts": [
                {
                    "build_unit_id": "u1",
                    "family": "native",
                    "root": ".",
                    "terminal_status": "SUCCEEDED",
                    "artifacts": [profile_ref],
                }
            ],
        },
    )
    monkeypatch.setattr(
        job_module,
        "load_accepted_artifact_index",
        lambda _root: {
            "source_fingerprint": snapshot,
            "handoff_sha256": "c" * 64,
            "index_manifest": art_manifest_ref,
        },
    )

    config = load_config("appsec-review.toml").job("job_profile_data")
    attempt_root = tmp_path / "data/jobs/job_profile_data/attempts/attempt_0001"
    job_ctx = SimpleNamespace(
        run_root=tmp_path,
        run_id=tmp_path.name,
        attempt_id="attempt_0001",
        attempt_root=attempt_root,
        source_fingerprint=snapshot,
        target_root=tmp_path,
        repository_root=tmp_path,
        config=config,
        input_manifest_path=None,
        input_manifest_sha256=None,
    )
    job = build_job()
    outputs: dict[str, object] = {}
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": catalog_sha}, contract=job.contract):
        for unit in job.units:
            step_id, task_id = unit.unit_id.split(".", 1)
            unit_root = attempt_root / "steps" / step_id / "tasks" / task_id
            outputs[unit.unit_id] = unit.handler(
                UnitContext(job_ctx, unit.unit_id, step_id, task_id, unit_root, outputs)
            )

    published = outputs["acceptance.publish_handoff"]
    assert published["terminal_status"] == "SUCCEEDED"
    assert published["item_count"] == 3
    handoff_rel = published["artifact"]["path"]
    assert _claimed(handoff_rel) == ["profile_data_handoff"]
    payload = json.loads((tmp_path / handoff_rel).read_text(encoding="utf-8"))
    assert payload["schema"] == PROFILE_DATA_HANDOFF_SCHEMA
    assert payload["semantics"] == "context_only"
    assert payload["upstream_handoff_sha256"] == {
        "job_target_catalog": catalog_sha,
        "job_language_build": "b" * 64,
        "job_artifact_indexing": "c" * 64,
    }
    shards = outputs["index.profile_data"]["indexes"]
    assert len(shards) == 1
    assert _shard_claims(shards[0]["shard_id"]) == ["profile_data"]
