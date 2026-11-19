"""Handler, shared-checkpoint reuse, handoff verification, and output-validation unit tests."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from appsec_review.config import ToolCapabilityConfig, load_config
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.document_issues import verify_document_issue_ledger
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.indexing.target_documents import collect_target_documents
from appsec_review.jobs.job_document_issue_analysis import job as job_module
from appsec_review.jobs.job_document_issue_analysis.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_document_issue_analysis.job import (
    JOB_ID,
    SCHEMA,
    UNADJUDICATED_GAP,
    _validate_output,
    build_job,
)
from appsec_review.observability import EventLog
from appsec_review.retrieval import (
    EntityKind,
    EntityRecord,
    IndexBuilder,
    IndexIdentity,
    LogicalIdentity,
    RetrievalCore,
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.review_packages import publish_review_packages
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import verify_receipt
from tests.handoff_fixture import write_fixture_handoff


REPO_ROOT = Path(__file__).resolve().parents[3]


def _seed_document_hunt_run(tmp_path: Path) -> tuple[Path, Path, str, Path, str, Path, str]:
    """Create a minimal accepted run with source, documents, document_context, and review packages."""
    run_id = "2026-10-15-0039"
    run_root = tmp_path / "runs" / run_id
    target = tmp_path / "target"

    src_rel = "backend/orders.ts"
    src_path = target / src_rel
    src_path.parent.mkdir(parents=True, exist_ok=True)
    src_bytes = (
        b"app.get('/api/orders/:id', (req, res) => {\n"
        b"  return res.json({ id: req.params.id });\n"
        b"});\n"
    )
    src_path.write_bytes(src_bytes)
    src_sha = hashlib.sha256(src_bytes).hexdigest()

    doc_rel = "api/openapi.yaml"
    doc_path = target / doc_rel
    doc_path.parent.mkdir(parents=True, exist_ok=True)
    doc_bytes = (b"openapi: 3.0.3\npaths:\n  /api/orders/{id}:\n    get:\n"
                 b"      summary: Order lookup\n      security:\n        - bearerAuth: []\n")
    doc_path.write_bytes(doc_bytes)
    doc_sha = hashlib.sha256(doc_bytes).hexdigest()

    snapshot = "target-sha256:" + "9" * 64
    document = collect_target_documents(
        target, snapshot, [{"path": doc_rel, "sha256": doc_sha, "kind": "openapi"}]).records[0]
    src_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": src_rel})
    doc_id = LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, snapshot, {"path": doc_rel, "op": "GET /api/orders/{id}"})
    route_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "document_context", "k": "route"})
    boundary_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "document_context", "k": "boundary"})

    src_loc = SourceLocation(snapshot, src_rel, src_sha, 0, len(src_bytes), 1, 3, 1, 1, {}, "exact", 1.0)
    doc_loc = SourceLocation(snapshot, doc_rel, doc_sha, 0, len(doc_bytes),
                             document["line"], document["end_line"], 1, 1, {}, "exact", 1.0)
    shards: list[IndexIdentity] = []

    def add_shard(name: str, shard_id: str, entities: list[EntityRecord], producer: dict[str, str]) -> None:
        fp = index_fingerprint(
            name=name,
            target_snapshot=snapshot,
            producer_artifacts=[{"shard": shard_id}],
            tool_identity={"job": producer["job"]},
            parser_identity="u/1",
            normalizer_identity="u/1",
            mapping_identity="u/1",
        )
        s_path = run_root / "data" / "indices" / name / shard_id / f"{fp}.sqlite"
        builder = IndexBuilder(s_path, name=name, fingerprint=fp, target_snapshot=snapshot, shard_id=shard_id)
        for ent in entities:
            builder.add_entity(ent)
        builder.add_coverage(f"{name}:{shard_id}", "complete", None)
        sha = builder.build()
        shards.append(
            IndexIdentity(
                name,
                "appsec-review/retrieval-index/2",
                sha,
                fp,
                s_path.relative_to(run_root).as_posix(),
                producer,
                (),
                shard_id,
            )
        )

    add_shard(
        "source",
        "source-files",
        [EntityRecord(src_id, src_rel, "orders.ts", src_rel, {"language": "TypeScript"}, src_loc)],
        {"job": "job_target_catalog", "unit": "catalog.scan"},
    )
    add_shard(
        "documents",
        "target-docs",
        [EntityRecord(doc_id, document["id"], document["text"], document["text"],
                      {"record_type": "target_document", "document_kind": document["kind"],
                       "subtype": document["subtype"], "authority": document["authority"],
                       "fields": document["fields"]}, doc_loc)],
        {"job": "job_target_catalog", "unit": "retrieval_indexes.build_target_documents"},
    )
    add_shard(
        "precomputed",
        "qs-document-context",
        [
            EntityRecord(
                route_fact_id,
                "fact-route",
                "GET /api/orders/{id}",
                "route context",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "document_context",
                    "fact_type": "route_context",
                    "subject_identity": doc_id.value,
                    "gaps": ["declared auth guard not verified"],
                    "result": {
                        "subject_type": "route",
                        "key": "GET /api/orders/{id}",
                        "members": {"openapi": [doc_id.value]},
                    },
                },
            ),
            EntityRecord(
                boundary_fact_id,
                "fact-boundary",
                "public-api",
                "boundary context",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "document_context",
                    "fact_type": "boundary_context",
                    "subject_identity": doc_id.value,
                    "gaps": [],
                    "result": {
                        "subject_type": "boundary",
                        "key": "public-api",
                        "members": {"openapi": [doc_id.value]},
                    },
                },
            ),
        ],
        {"job": "job_review_data_indexing", "query_set": "document_context"},
    )

    manifest_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(
        manifest_path,
        run_id=run_id,
        target_snapshot=snapshot,
        target_root=target,
        indexes=shards,
    )
    manifest_sha = file_sha256(manifest_path)

    core = RetrievalCore(run_root.parent, run_id, manifest_sha256=manifest_sha, manifest_path=manifest_path)
    pkg_dir = publish_review_packages(core)
    pkg_manifest_path = pkg_dir / "manifest.json"
    pkg_manifest = json.loads(pkg_manifest_path.read_text(encoding="utf-8"))
    pkg_artifacts = [
        {
            "path": path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(pkg_dir.iterdir())
    ]

    pkg_handoff_path = (
        run_root / "data" / "jobs" / "job_review_package_assembly" / "attempts" / "attempt_0001" / "handoff.json"
    )
    write_fixture_handoff(
        run_root,
        pkg_handoff_path,
        {
            "job_id": "job_review_package_assembly",
            "attempt_id": "attempt_0001",
            "completion_status": "COMPLETED_WITH_GAPS",
            "target_snapshot": snapshot,
            "source_fingerprint": snapshot,
            "artifacts": pkg_artifacts,
            "outputs": {
                "publication.publish_packages": {
                    "schema": pkg_manifest["schema"],
                    "package_directory": pkg_dir.relative_to(run_root).as_posix(),
                    "manifest": {
                        "path": pkg_manifest_path.relative_to(run_root).as_posix(),
                        "sha256": file_sha256(pkg_manifest_path),
                    },
                    "accepted_manifest_sha256": manifest_sha,
                    "counts": pkg_manifest["counts"],
                    "gaps": [gap["gap_id"] for gap in pkg_manifest["coverage_gaps"]],
                    "terminal_status": "COMPLETED_WITH_GAPS",
                }
            },
        },
        target_snapshot=snapshot,
    )
    pkg_handoff_sha = file_sha256(pkg_handoff_path)
    atomic_json(
        run_root / "data" / "jobs" / "job_review_package_assembly" / "latest.json",
        {
            "handoff_path": pkg_handoff_path.relative_to(run_root).as_posix(),
            "handoff_sha256": pkg_handoff_sha,
        },
    )
    return run_root, target, snapshot, manifest_path, manifest_sha, pkg_dir, pkg_handoff_sha


def _make_job_context(
    run_root: Path,
    target: Path,
    *,
    source_fingerprint: str,
    manifest_path: Path,
    manifest_sha: str,
    attempt_id: str = "attempt_0001",
    releases: dict[str, str] | None = None,
    max_source_files: int = 20000,
    max_source_file_bytes: int = 1048576,
) -> JobContext:
    base_cfg = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    job_cfg = replace(
        base_cfg,
        settings=MappingProxyType(
            {"max_source_files": max_source_files, "max_source_file_bytes": max_source_file_bytes}
        ),
    )
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    orchestration = {"system": "dagster", "run_id": f"doc-{attempt_id}"}
    atomic_json(
        attempt_root / "claim.json",
        {
            "schema": "appsec-review/attempt-claim/1",
            "run_id": run_root.name,
            "job_id": JOB_ID,
            "attempt_id": attempt_id,
            "attempt_path": attempt_root.relative_to(run_root).as_posix(),
            "source_fingerprint": source_fingerprint,
            "orchestration": orchestration,
            "dataset_contract": dataset_contract(
                JOB_ID, ("analysis",), DATASETS, job_contract=CONTRACT.document()
            ),
        },
    )
    return JobContext(
        run_id=run_root.name,
        attempt_id=attempt_id,
        trigger="unit",
        repository_root=REPO_ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=run_root.parent / "metadata",
        orchestration=orchestration,
        config=job_cfg,
        events=EventLog(attempt_root / "logs" / "events.jsonl"),
        tools=ToolCapabilityConfig(),
        target_root=target,
        source_fingerprint=source_fingerprint,
        input_manifest_path=manifest_path,
        input_manifest_sha256=manifest_sha,
        review_policy=ReviewPolicy(releases=ComponentReleases(releases or {})),
        contract=CONTRACT,
    )


def _make_unit_context(ctx: JobContext) -> UnitContext:
    unit_dir = ctx.attempt_root / "steps" / "analysis" / "tasks" / "map_and_adjudicate"
    unit_dir.mkdir(parents=True, exist_ok=True)
    return UnitContext(
        job=ctx,
        unit_id="analysis.map_and_adjudicate",
        step_id="analysis",
        task_id="map_and_adjudicate",
        unit_root=unit_dir,
        outputs=MappingProxyType({}),
    )


@pytest.mark.parametrize(
    ("releases", "expected_reusable"),
    [
        ({"job_document_issue_analysis": "doc-rel-1", "validation": "val-rel-1"}, True),
        ({"platform": "plat-rel-1", "validation": "val-rel-1"}, True),
        ({}, False),
    ],
    ids=["job-release", "platform-fallback", "missing-releases"],
)
def test_analyze_handler_computes_and_reuses_private_candidate_ledger(
    tmp_path: Path,
    releases: dict[str, str],
    expected_reusable: bool,
) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, _pkg_dir, pkg_handoff_sha = _seed_document_hunt_run(
        tmp_path
    )
    job = build_job()
    pins = {"job_review_package_assembly": pkg_handoff_sha}

    ctx1 = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_0001",
        releases=releases,
    )
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        res1 = job.handler(ctx1)

    assert res1["status"] == "COMPLETED_WITH_GAPS"
    out1 = res1["outputs"]["analysis.map_and_adjudicate"]
    assert out1["schema"] == SCHEMA
    assert out1["reused"] is False
    assert out1["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert out1["gaps"][0] == UNADJUDICATED_GAP
    assert len(out1["gaps"]) > 1
    assert out1["counts"] == {"candidates": 2, "supported": 0, "unmapped": 1, "ambiguous": 0}
    assert out1["artifacts"] == [out1["artifact"], out1["drift_artifact"]]
    drift1 = json.loads((run_root / out1["drift_artifact"]["path"]).read_text())
    assert out1["drift_counts"] == {"specs_parsed": 1, "handlers_scanned": 1, "mismatches": 1}
    assert drift1["mismatches"][0]["drift_kind"] == "missing_auth_middleware"
    assert drift1["mismatches"][0]["spec_source_id"].startswith("asr:document_record:")

    receipt1 = verify_receipt(run_root, out1["shared_receipt"])
    assert receipt1["mode"] == "computed"
    core = RetrievalCore(run_root.parent, run_root.name, manifest_sha256=manifest_sha, manifest_path=manifest_path)
    ledger = verify_document_issue_ledger(core, run_root / out1["artifact"]["path"])
    assert ledger["findings"] == ledger["scoring_inputs"] == []

    events1 = [
        json.loads(line)
        for line in (ctx1.attempt_root / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    missed = next(ev for ev in events1 if ev["event"] == "CHECKPOINT_MISSED")
    assert missed["reason"] == ("missing" if expected_reusable else "missing_release_identity")
    published = next(ev for ev in events1 if ev["event"] == "DOCUMENT_ISSUES_PUBLISHED")
    assert published["candidates"] == 2

    ctx2 = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_0002",
        releases=releases,
    )
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        res2 = job.handler(ctx2)

    out2 = res2["outputs"]["analysis.map_and_adjudicate"]
    assert out2["reused"] is expected_reusable
    assert out2["artifact"] == out1["artifact"]
    assert out2["drift_artifact"]["path"] != out1["drift_artifact"]["path"]
    assert json.loads((run_root / out2["drift_artifact"]["path"]).read_text()) == drift1
    receipt2 = verify_receipt(run_root, out2["shared_receipt"])
    assert receipt2["mode"] == ("reused" if expected_reusable else "computed")
    events2 = [
        json.loads(line)
        for line in (ctx2.attempt_root / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    expected_event = "CHECKPOINT_REUSED" if expected_reusable else "CHECKPOINT_MISSED"
    checkpoint_ev = next(ev for ev in events2 if ev["event"] == expected_event)
    assert checkpoint_ev["reason"] == (None if expected_reusable else "missing_release_identity")


def test_validate_output_enforces_ledger_integrity_and_counts(tmp_path: Path) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, _pkg_dir, pkg_handoff_sha = _seed_document_hunt_run(
        tmp_path
    )
    ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
    )
    with upstream_scope(run_root, JOB_ID, {"job_review_package_assembly": pkg_handoff_sha}, contract=CONTRACT):
        out = build_job().handler(ctx)["outputs"]["analysis.map_and_adjudicate"]
    unit = _make_unit_context(ctx)

    _validate_output(unit, out)

    with pytest.raises(ValueError, match="document issue ledger is unavailable"):
        _validate_output(unit, None)

    escaped = {**out, "artifact": {**out["artifact"], "path": "../../escaped.json"}}
    with pytest.raises(ValueError, match="document issue ledger receipt failed verification"):
        _validate_output(unit, escaped)

    bad_hash = {**out, "artifact": {**out["artifact"], "sha256": "0" * 64}}
    with pytest.raises(ValueError, match="document issue ledger receipt failed verification"):
        _validate_output(unit, bad_hash)

    bad_counts = {**out, "counts": {**out["counts"], "unmapped": 99}}
    with pytest.raises(ValueError, match="document issue ledger counts differ from receipt"):
        _validate_output(unit, bad_counts)


def test_analyze_handler_rejects_snapshot_and_handoff_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, pkg_dir, _pkg_handoff_sha = _seed_document_hunt_run(
        tmp_path
    )
    analyze_unit = build_job().units[0]

    # 1. Target snapshot mismatch
    bad_snap_ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint="target-sha256:" + "0" * 64,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_snap",
    )
    with pytest.raises(ValueError, match="document issue analysis target snapshot changed"):
        analyze_unit.handler(_make_unit_context(bad_snap_ctx))

    ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_tamper",
    )
    unit = _make_unit_context(ctx)

    # 2. Missing accepted handoff
    monkeypatch.setattr(job_module, "accepted_handoff", lambda *_args, **_kwargs: None)
    with pytest.raises(ValueError, match="accepted review package handoff is unavailable"):
        analyze_unit.handler(unit)

    def _mock_handoff(result_rel: str, artifacts: list[dict[str, Any]]) -> None:
        fake = AcceptedHandoff(
            job_id="job_review_package_assembly",
            handoff={"resolving_paths": {"result": result_rel}, "artifacts": artifacts},
            sha256="a" * 64,
            path="data/jobs/job_review_package_assembly/attempts/attempt_0001/handoff.json",
        )
        monkeypatch.setattr(job_module, "accepted_handoff", lambda *_args, **_kwargs: fake)

    # 3. Result path escapes run_root or hash missing in handoff artifacts
    _mock_handoff("../../escape.json", [])
    with pytest.raises(ValueError, match="accepted review package result failed verification"):
        analyze_unit.handler(unit)

    custom_result = run_root / "data" / "custom_result.json"
    atomic_json(
        custom_result,
        {
            "outputs": {
                "publication.publish_packages": {
                    "package_directory": "../../escape_dir",
                    "accepted_manifest_sha256": manifest_sha,
                }
            }
        },
    )
    result_rel = custom_result.relative_to(run_root).as_posix()
    _mock_handoff(result_rel, [{"path": result_rel, "sha256": "0" * 64}])
    with pytest.raises(ValueError, match="accepted review package result failed verification"):
        analyze_unit.handler(unit)

    # 4. Package directory escapes run_root
    result_ref = {"path": result_rel, "sha256": file_sha256(custom_result)}
    _mock_handoff(result_rel, [result_ref])
    with pytest.raises(ValueError, match="review package path escapes run"):
        analyze_unit.handler(unit)

    # 5. Accepted manifest SHA mismatch
    atomic_json(
        custom_result,
        {
            "outputs": {
                "publication.publish_packages": {
                    "package_directory": pkg_dir.relative_to(run_root).as_posix(),
                    "accepted_manifest_sha256": "f" * 64,
                }
            }
        },
    )
    result_ref = {"path": result_rel, "sha256": file_sha256(custom_result)}
    _mock_handoff(result_rel, [result_ref])
    with pytest.raises(ValueError, match="review package manifest is not the accepted index set"):
        analyze_unit.handler(unit)

    # 6. Package manifest not bound to accepted handoff artifacts
    atomic_json(
        custom_result,
        {
            "outputs": {
                "publication.publish_packages": {
                    "package_directory": pkg_dir.relative_to(run_root).as_posix(),
                    "accepted_manifest_sha256": manifest_sha,
                }
            }
        },
    )
    result_ref = {"path": result_rel, "sha256": file_sha256(custom_result)}
    _mock_handoff(result_rel, [result_ref])
    with pytest.raises(ValueError, match="review package manifest is not bound to its accepted handoff"):
        analyze_unit.handler(unit)
