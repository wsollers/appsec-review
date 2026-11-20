"""job_test_coverage: declared inputs, dataset outputs, admission, and published schema/glob parity."""

from __future__ import annotations

from dataclasses import replace
from fnmatch import fnmatch
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import TEST_COVERAGE_HANDOFF_SCHEMA
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.jobs.job_test_coverage import job as job_module
from appsec_review.jobs.job_test_coverage.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_test_coverage.job import TOPOLOGY, CoverageIntegrityError, build_job
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
from appsec_review.runtime.datasets import METADATA_ROUTE, dataset_contract
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


def _seed_catalog_handoff(run_root: Path, snapshot: str, files: list[dict[str, str]]) -> str:
    manifest_path = run_root / "data/indices/manifests/catalog-attempt_0001.json"
    write_manifest(manifest_path, run_id=run_root.name, target_snapshot=snapshot, target_root=run_root, indexes=())
    partition_path = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/partition.json"
    atomic_json(partition_path, {"files": files})
    catalog_path = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog.json"
    manifest_ref = _ref(run_root, manifest_path)
    partition_ref = _ref(run_root, partition_path)
    atomic_json(
        catalog_path,
        {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": snapshot,
            "artifacts": {"repository_discovery.partition_repository": partition_ref},
        },
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
            "artifacts": [catalog_ref, manifest_ref, partition_ref],
        },
    )
    sha = file_sha256(handoff_path)
    atomic_json(
        run_root / "data/jobs/job_target_catalog/latest.json",
        {"handoff_path": handoff_path.relative_to(run_root).as_posix(), "handoff_sha256": sha},
    )
    return sha


def test_inputs_are_pinned_with_producer_schema_and_availability_policies() -> None:
    actual = [
        (item.producer, item.output_kind, item.schema, item.availability, item.missing)
        for item in CONTRACT.inputs
    ]
    assert actual == list(EXPECTED_INPUTS)
    for item in CONTRACT.inputs:
        assert item.coverage is CoveragePolicy.ALLOW_PARTIAL, item.output_kind
        assert item.channel is InputChannel.HANDOFF, item.output_kind
        assert item.authority is EvidenceAuthority.PRODUCER_EVIDENCE, item.output_kind


def test_every_dataset_input_matches_its_upstream_producer_declaration() -> None:
    producers = {
        "job_target_catalog": {item.output_kind: item for item in CATALOG_DATASETS},
        "job_language_build": {item.output_kind: item for item in LANGUAGE_DATASETS},
        "job_artifact_indexing": {item.output_kind: item for item in ARTIFACT_DATASETS},
    }
    for item in CONTRACT.inputs:
        if item.output_kind == "handoff":
            continue
        declared = producers[item.producer].get(item.output_kind)
        assert declared is not None, f"{item.producer} missing {item.output_kind}"
        assert declared.schema == item.schema, item.output_kind
        assert declared.authority is item.authority, item.output_kind
    for producer, declarations in producers.items():
        consumed = {item.output_kind for item in CONTRACT.inputs if item.producer == producer}
        assert consumed == set(declarations) | {"handoff"}, producer


def test_contract_topology_and_dataset_declarations_match_bounded_workflow() -> None:
    job = build_job()
    assert job.job_id == "job_test_coverage" and job.name == "test_coverage"
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ("job_artifact_indexing",)
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True
    assert CONTRACT.consumes == CONSUMES == (
        "job_artifact_indexing",
        "job_language_build",
        "job_target_catalog",
    )
    assert [unit.unit_id for unit in job.units] == [
        "load.accepted_inputs",
        "normalize.coverage",
        "index.coverage",
        "acceptance.publish_handoff",
    ]
    declared = {item.output_kind: item for item in DATASETS}
    assert [(k, v.step, v.family, v.disposition, v.schema, v.sensitivity) for k, v in declared.items()] == [
        ("test_coverage", "index", "build", "indexed", INDEX_SCHEMA, "internal"),
        ("test_coverage_handoff", "acceptance", "build", "artifact_only", TEST_COVERAGE_HANDOFF_SCHEMA, "internal"),
    ]
    assert declared["test_coverage"].indexes == ("analysis",)
    assert declared["test_coverage"].shard_prefixes == ("test-coverage-",)
    assert declared["test_coverage"].query_route == "query_engineering_signals signal_family=test_coverage"
    assert declared["test_coverage_handoff"].query_route == METADATA_ROUTE
    assert declared["test_coverage_handoff"].artifacts == (
        "data/jobs/job_test_coverage/attempts/*/artifacts/test-coverage/*.json",
    )
    assert _shard_claims("test-coverage-native") == ["test_coverage"]
    assert _shard_claims("profile-data-native") == []
    assert set(TOPOLOGY).issuperset({item.step for item in DATASETS})


def test_missing_load_prerequisites_are_rejected_at_admission_and_handler(tmp_path: Path) -> None:
    job = build_job()
    context = SimpleNamespace(
        run_root=tmp_path,
        contract=job.contract,
        upstream_handoffs={},
        evidence_target_snapshot="coverage-fixture",
        external_input_selection=None,
    )
    with pytest.raises(
        ValueError,
        match=r"required input unavailable: job_(artifact_indexing|language_build|target_catalog)/handoff",
    ):
        admit_inputs(context, enabled=set(context.contract.consumes))

    load = next(unit for unit in job.units if unit.unit_id == "load.accepted_inputs")
    with upstream_scope(tmp_path, job.job_id, {}, contract=context.contract):
        with pytest.raises(CoverageIntegrityError) as failure:
            load.handler(SimpleNamespace(job=context))
    assert str(failure.value) == (
        "accepted job_target_catalog handoff is required: "
        "accepted job_target_catalog handoff is required"
    )
    assert isinstance(failure.value.__cause__, UpstreamIntegrityError)
    assert list(tmp_path.iterdir()) == []

    catalog_sha = _seed_catalog_handoff(tmp_path, "coverage-fixture", [{"path": "src/a.c", "sha256": "1" * 64}])
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
    catalog_sha = _seed_catalog_handoff(tmp_path, snapshot, [{"path": "src/a.c", "sha256": "1" * 64}])
    report = tmp_path / "data/build/u1/coverage/lcov.info"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(b"SF:src/a.c\nDA:1,2\nDA:2,0\nend_of_record\n")
    report_ref = {
        **_ref(tmp_path, report),
        "workspace_path": "coverage/lcov.info",
        "kind": "test-coverage",
        "artifact_origin": "build-output",
    }
    manifest_path = tmp_path / "data/indices/manifests/artifact-attempt_0001.json"
    write_manifest(manifest_path, run_id=tmp_path.name, target_snapshot=snapshot, target_root=tmp_path, indexes=())
    manifest_ref = _ref(tmp_path, manifest_path)

    monkeypatch.setattr(
        "appsec_review.runtime.consume.has_accepted_upstream",
        lambda _root, producer: producer in {"job_language_build", "job_artifact_indexing"},
    )
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _root: {
            "source_fingerprint": snapshot,
            "language_build_handoff_sha256": "2" * 64,
            "receipts": [
                {
                    "build_unit_id": "u1",
                    "family": "native",
                    "root": ".",
                    "terminal_status": "SUCCEEDED",
                    "artifacts": [report_ref],
                }
            ],
        },
    )
    monkeypatch.setattr(
        job_module,
        "load_accepted_artifact_index",
        lambda _root: {
            "source_fingerprint": snapshot,
            "handoff_sha256": "3" * 64,
            "index_manifest": manifest_ref,
        },
    )

    config = load_config("appsec-review.toml").job("job_test_coverage")
    attempt_root = tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0001"
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
    by_id = {unit.unit_id: unit.handler for unit in job.units}
    outputs: dict[str, object] = {}
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": catalog_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.coverage", "index.coverage", "acceptance.publish_handoff"):
            step_id, task_id = uid.split(".", 1)
            outputs[uid] = by_id[uid](
                UnitContext(
                    job=job_ctx,
                    unit_id=uid,
                    step_id=step_id,
                    task_id=task_id,
                    unit_root=attempt_root / "steps" / step_id / "tasks" / task_id,
                    outputs=dict(outputs),
                )
            )

    published = outputs["acceptance.publish_handoff"]
    assert published["terminal_status"] == "SUCCEEDED"
    assert _claimed(published["artifact"]["path"]) == ["test_coverage_handoff"]
    doc = json.loads((tmp_path / published["artifact"]["path"]).read_text(encoding="utf-8"))
    assert doc["schema"] == TEST_COVERAGE_HANDOFF_SCHEMA
    assert doc["totals"]["lines_total"] == 2 and doc["totals"]["lines_covered"] == 1
    (shard,) = outputs["index.coverage"]["indexes"]
    assert shard["schema"] == INDEX_SCHEMA
    assert _shard_claims(shard["shard_id"]) == ["test_coverage"]
    assert (tmp_path / shard["relative_path"]).is_file()
