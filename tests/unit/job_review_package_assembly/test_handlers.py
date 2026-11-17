"""Handler, core-caching, lineage, and output-validation unit tests for job_review_package_assembly."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from appsec_review.config import ToolCapabilityConfig, load_config
from appsec_review.config.assurance import ReviewPolicy
from appsec_review.jobs.job_review_package_assembly.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_review_package_assembly.job import (
    JOB_ID,
    SCHEMA,
    TOPOLOGY,
    _core,
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
    SourceLocation,
    index_fingerprint,
    write_manifest,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.review_packages import verify_review_packages
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.validation import validation_scope
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.handoff_fixture import write_fixture_handoff


REPO_ROOT = Path(__file__).resolve().parents[3]


def _make_job_context(
    run_root: Path,
    target: Path,
    *,
    source_fingerprint: str,
    manifest_path: Path,
    manifest_sha: str,
    attempt_id: str = "attempt_0001",
    max_page_size: int = 20,
) -> JobContext:
    base_cfg = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    job_cfg = replace(base_cfg, settings=MappingProxyType({"max_page_size": max_page_size}))
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / attempt_id
    orchestration = {"system": "unit", "run_id": f"pkg-{attempt_id}"}
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
            "dataset_contract": dataset_contract(JOB_ID, tuple(TOPOLOGY), DATASETS),
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
        review_policy=ReviewPolicy(),
        contract=CONTRACT,
    )


def _make_unit_context(ctx: JobContext) -> UnitContext:
    unit_dir = ctx.attempt_root / "steps" / "publication" / "tasks" / "publish_packages"
    unit_dir.mkdir(parents=True, exist_ok=True)
    return UnitContext(
        job=ctx,
        unit_id="publication.publish_packages",
        step_id="publication",
        task_id="publish_packages",
        unit_root=unit_dir,
        outputs=MappingProxyType({}),
    )


def _seed_zero_gap_run(tmp_path: Path) -> tuple[Path, Path, str, Path, str, list[IndexIdentity]]:
    """Create a compact accepted run where package assembly completes with zero coverage gaps."""
    run_id = "2026-10-15-0038"
    run_root = tmp_path / "runs" / run_id
    target = tmp_path / "target"
    src_rel = "svc/app.py"
    src_path = target / src_rel
    src_path.parent.mkdir(parents=True, exist_ok=True)
    src_bytes = b"def handle(req):\n    return eval(req)\n"
    src_path.write_bytes(src_bytes)
    src_sha = hashlib.sha256(src_bytes).hexdigest()
    snapshot = "target-sha256:" + "8" * 64

    src_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": src_rel})
    fn_id = LogicalIdentity.derive(EntityKind.PRIORITY_ITEM, snapshot, {"path": src_rel, "fn": "handle"})
    obs_id = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"rule": "py.eval", "line": 2})
    act_id = LogicalIdentity.derive(EntityKind.BUILD_ACTION, snapshot, {"action": "act-1"})
    tag_id = LogicalIdentity.derive(EntityKind.TAG_ASSIGNMENT, snapshot, {"path": src_rel, "tag": "input.http"})
    hist_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "history_context", "p": src_rel})
    build_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "build_provenance", "p": src_rel})
    lead_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "scanner_correlation", "k": "lead"})
    menu_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "scanner_correlation", "k": "menu"})
    audit_fact_id = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"qs": "scanner_correlation", "k": "audit"})

    loc = SourceLocation(snapshot, src_rel, src_sha, 0, len(src_bytes), 1, 2, 1, 1, {}, "exact", 1.0)
    shards: list[IndexIdentity] = []

    def add_shard(name: str, shard_id: str, entities: list[EntityRecord], producer_extra: dict[str, str] | None = None) -> None:
        fp = index_fingerprint(
            name=name,
            target_snapshot=snapshot,
            producer_artifacts=[{"shard": shard_id}],
            tool_identity={"job": "job_review_data_indexing"},
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
                {"job": "job_review_data_indexing", "unit": "precompute.scanner_correlation", **(producer_extra or {})},
                (),
                shard_id,
            )
        )

    add_shard(
        "source",
        "source-files",
        [EntityRecord(src_id, src_rel, "app.py", "svc/app.py", {"language": "Python"}, loc)],
    )
    add_shard(
        "priority",
        "priority-items",
        [EntityRecord(fn_id, "handle", "handle", "function handle", {"scope": "function", "score": 90}, loc)],
    )
    add_shard(
        "tags",
        "tag-assignments",
        [
            EntityRecord(
                tag_id,
                "tag-1",
                "input.http",
                "HTTP input tag",
                {
                    "tag": "input.http",
                    "basis": "ast",
                    "family": "input",
                    "subject": {"kind": "source_file", "path": src_rel, "logical_id": src_id.value},
                },
                loc,
            )
        ],
    )
    add_shard(
        "precomputed",
        "qs-history-context",
        [
            EntityRecord(
                hist_fact_id,
                "hist-1",
                "metric_vector",
                "history metrics",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "history_context",
                    "fact_type": "metric_vector",
                    "subject_path": src_rel,
                    "subject_identity": fn_id.value,
                    "result": {
                        "scope": "file",
                        "metrics": [
                            {
                                "name": "commits_90d",
                                "scope_id": fn_id.value,
                                "value": 3,
                                "status": "available",
                                "producer": "job_source_history_analysis",
                                "algorithm_version": "1",
                            }
                        ],
                    },
                },
                None,
            )
        ],
        producer_extra={"query_set": "history_context"},
    )
    add_shard(
        "precomputed",
        "qs-build-provenance",
        [
            EntityRecord(
                build_fact_id,
                "build-1",
                "build_action",
                "build action",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "build_provenance",
                    "fact_type": "build_action",
                    "result": {
                        "build_action_id": act_id.value,
                        "source_inputs": [f"relative:{src_rel}"],
                        "produced_artifact_ids": [],
                        "command_facts": [
                            {
                                "build_action_id": act_id.value,
                                "tool_id": "python",
                                "ordered_tokens": [
                                    {
                                        "ordinal": 0,
                                        "kind": "source_input",
                                        "safe_value": f"relative:{src_rel}",
                                        "redacted": False,
                                    }
                                ],
                                "exact_artifact_sha256": "2" * 64,
                                "normalization_rule": "command/1",
                            }
                        ],
                        "environment_facts": [],
                    },
                },
                None,
            )
        ],
        producer_extra={"query_set": "build_provenance"},
    )
    add_shard(
        "precomputed",
        "qs-scanner-correlation",
        [
            EntityRecord(
                lead_fact_id,
                "lead-1",
                "lead",
                "eval lead",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "scanner_correlation",
                    "fact_type": "lead",
                    "result": {
                        "observation_id": obs_id.value,
                        "scanner": "semgrep",
                        "rule_id": "py.eval",
                        "category": "code-injection",
                        "native_severity": "ERROR",
                        "normalized_reported_severity": "high",
                        "severity_rule": "semgrep/1",
                        "component_id": "comp-1",
                        "suppression_status": "not_suppressed",
                        "duplicate_of": None,
                        "location": {
                            "exact": True,
                            "mapping_method": "accepted_source_path",
                            "source_path": src_rel,
                            "file_sha256": src_sha,
                            "start_line": 2,
                            "end_line": 2,
                        },
                        "flow_ids": [],
                    },
                },
                None,
            ),
            EntityRecord(
                menu_fact_id,
                "menu-1",
                "menu",
                "high_critical menu",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "scanner_correlation",
                    "fact_type": "menu",
                    "result": {
                        "menu": "high_critical",
                        "component_id": "comp-1",
                        "partition": 0,
                        "next_partition": None,
                        "members": [{"observation_id": obs_id.value}],
                    },
                },
                None,
            ),
            EntityRecord(
                audit_fact_id,
                "audit-1",
                "audit",
                "membership audit",
                {
                    "schema": FACT_SCHEMA,
                    "query_set": "scanner_correlation",
                    "fact_type": "audit",
                    "result": {
                        "status": "passed",
                        "counts": {
                            "source_sast_observations": 1,
                            "high_critical": 1,
                            "unknown_severity": 0,
                        },
                    },
                },
                None,
            ),
        ],
        producer_extra={"query_set": "scanner_correlation"},
    )

    manifest_path = run_root / "data" / "indices" / "manifests" / "review-data-indexing-0001.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=shards)
    manifest_sha = file_sha256(manifest_path)
    manifest_ref = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": manifest_sha}

    idx_att = run_root / "data" / "jobs" / "job_review_data_indexing" / "attempts" / "attempt_0001"
    idx_handoff = idx_att / "handoff.json"
    write_fixture_handoff(
        run_root,
        idx_handoff,
        {
            "job_id": "job_review_data_indexing",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "completion_status": "SUCCEEDED",
            "source_fingerprint": snapshot,
            "artifacts": [manifest_ref, *({"path": s.relative_path, "sha256": s.sha256} for s in shards)],
            "outputs": {
                "publish.inventory_index": {
                    "index_manifest": manifest_ref,
                    "index_identity": asdict(shards[0]),
                    "terminal_status": "SUCCEEDED",
                }
            },
        },
    )
    idx_handoff_sha = file_sha256(idx_handoff)
    atomic_json(
        idx_att.parent.parent / "latest.json",
        {
            "schema": "appsec-review/latest-handoff/1",
            "attempt_id": "attempt_0001",
            "handoff_path": idx_handoff.relative_to(run_root).as_posix(),
            "handoff_sha256": idx_handoff_sha,
        },
    )
    atomic_json(
        run_root / "data" / "indices" / "accepted.json",
        {
            "schema": "appsec-review/accepted-index-set/1",
            "run_id": run_id,
            "handoff_path": idx_handoff.relative_to(run_root).as_posix(),
            "handoff_sha256": idx_handoff_sha,
            "manifest_path": manifest_ref["path"],
            "manifest_sha256": manifest_sha,
        },
    )
    return run_root, target, snapshot, manifest_path, manifest_sha, shards


def test_core_caches_within_validation_scope_and_works_without_scope(tmp_path: Path) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, _ = _seed_zero_gap_run(tmp_path)
    ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
    )
    unit = _make_unit_context(ctx)

    # Outside validation_scope: current_validation(run_root) is None -> constructs uncached core
    core_a, path_a, sha_a = _core(unit)
    core_b, path_b, sha_b = _core(unit)
    assert core_a is not core_b
    assert path_a == path_b == manifest_path.resolve()
    assert sha_a == sha_b == manifest_sha

    # Inside validation_scope: caches on first call and returns exact same instance on second call
    with validation_scope(run_root) as validation:
        cached_1, _, _ = _core(unit)
        cached_2, _, _ = _core(unit)
        assert cached_1 is cached_2
        assert ("package-core", str(manifest_path.resolve()), manifest_sha) in validation.records


def test_publish_handler_executes_with_gaps_and_lineage_manifest(tmp_path: Path) -> None:
    fixture = build_accepted_index_set(tmp_path, publish_v1_packages=False)
    indexing_pointer = json.loads(
        (fixture.run_root / "data" / "jobs" / "job_review_data_indexing" / "latest.json").read_text(encoding="utf-8")
    )
    indexing_handoff = json.loads((fixture.run_root / indexing_pointer["handoff_path"]).read_text(encoding="utf-8"))
    upstream_manifest_ref = next(
        item for item in indexing_handoff["artifacts"] if str(item["path"]).startswith("data/indices/manifests/")
    )
    upstream_manifest = json.loads((fixture.run_root / upstream_manifest_ref["path"]).read_text(encoding="utf-8"))
    upstream_shards = [
        IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
        for raw in upstream_manifest["indexes"]
    ]

    # Create a distinct attempt-pinned input manifest that cites the indexing manifest via upstream_manifests
    attempt_manifest_path = (
        fixture.run_root
        / "data"
        / "jobs"
        / JOB_ID
        / "attempts"
        / "attempt_0001"
        / "inputs"
        / "input-manifest.json"
    )
    write_manifest(
        attempt_manifest_path,
        run_id=fixture.run_id,
        target_snapshot=fixture.snapshot,
        target_root=fixture.target,
        indexes=upstream_shards,
        upstream_manifests=[upstream_manifest_ref],
    )
    attempt_manifest_sha = file_sha256(attempt_manifest_path)

    ctx = _make_job_context(
        fixture.run_root,
        fixture.target,
        source_fingerprint=fixture.snapshot,
        manifest_path=attempt_manifest_path,
        manifest_sha=attempt_manifest_sha,
    )
    job = build_job()
    with validation_scope(fixture.run_root):
        outcome = job.handler(ctx)

    pub = outcome["outputs"]["publication.publish_packages"]
    assert pub["schema"] == SCHEMA
    assert pub["accepted_manifest_sha256"] == attempt_manifest_sha
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert pub["coverage_gap_count"] > 0
    assert len(pub["gaps"]) == pub["coverage_gap_count"]
    # Opaque gap ids are not a cause: every gap is a producer-gap/1 record naming the manifest's reason.
    manifest = json.loads((fixture.run_root / pub["package_directory"] / "manifest.json").read_text(encoding="utf-8"))
    by_manifest_id = {item["gap_id"]: item for item in manifest["coverage_gaps"]}
    assert len(by_manifest_id) == pub["coverage_gap_count"]
    for gap in pub["gaps"]:
        assert gap["schema"] == "appsec-review/producer-gap/1" and gap["code"] == "producer_reported_gap"
        assert gap["unit_id"] == "publication.publish_packages"
        source = next(item for item in by_manifest_id.values() if f"[{item['gap_id']}]" in gap["reason"])
        assert source["reason"] in gap["reason"] and source["producer"] in gap["reason"]
        assert gap["scope_id"] == source["scope"]
    assert len({gap["gap_id"] for gap in pub["gaps"]}) == pub["coverage_gap_count"]
    assert pub["package_count"] > 0
    assert pub["artifacts"]

    core, _, _ = _core(_make_unit_context(ctx))
    verified = verify_review_packages(core, fixture.run_root / pub["package_directory"])
    assert verified["content_sha256"] == pub["content_sha256"]
    assert verified["counts"] == pub["counts"]

    events = [
        json.loads(line)
        for line in (ctx.attempt_root / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    published_events = [ev for ev in events if ev["event"] == "REVIEW_PACKAGES_PUBLISHED"]
    assert len(published_events) == 1
    assert published_events[0]["package_count"] == pub["package_count"]


def test_publish_handler_succeeds_without_gaps_and_validate_output_checks_receipt(tmp_path: Path) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, _ = _seed_zero_gap_run(tmp_path)
    ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
    )
    job = build_job()
    outcome = job.handler(ctx)
    pub = outcome["outputs"]["publication.publish_packages"]
    assert pub["terminal_status"] == "SUCCEEDED"
    assert pub["coverage_gap_count"] == 0
    assert pub["gaps"] == []
    assert pub["counts"]["finding_lead"] == 1
    assert pub["counts"]["hunt"] == 1

    unit = _make_unit_context(ctx)
    _validate_output(unit, pub)

    with pytest.raises(ValueError, match="result is unavailable"):
        _validate_output(unit, None)

    with pytest.raises(ValueError, match="different input manifest"):
        _validate_output(unit, {**pub, "accepted_manifest_sha256": "0" * 64})

    for mutated in (
        {**pub, "content_sha256": "0" * 64},
        {**pub, "manifest_sha256": "0" * 64},
        {**pub, "counts": {**pub["counts"], "finding_lead": 99}},
        {**pub, "coverage_gap_count": 99},
    ):
        with pytest.raises(ValueError, match="receipt differs from verified output"):
            _validate_output(unit, mutated)


def test_publish_handler_rejects_snapshot_mismatch_missing_handoff_and_unbound_manifest(tmp_path: Path) -> None:
    run_root, target, snapshot, manifest_path, manifest_sha, shards = _seed_zero_gap_run(tmp_path)
    job = build_job()
    unit_def = job.units[0]

    # 1. Target snapshot mismatch
    bad_snapshot_ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint="target-sha256:" + "f" * 64,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_0002",
    )
    with pytest.raises(ValueError, match="target snapshot differs from the graph target"):
        unit_def.handler(_make_unit_context(bad_snapshot_ctx))

    # 2. Unbound input manifest (handoff exists, but artifacts do not bind this manifest or its lineage)
    other_manifest_path = run_root / "data" / "indices" / "manifests" / "other-upstream.json"
    write_manifest(other_manifest_path, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=shards)
    other_ref = {"path": other_manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(other_manifest_path)}

    unbound_path = run_root / "data" / "indices" / "manifests" / "unbound.json"
    write_manifest(
        unbound_path,
        run_id=run_root.name,
        target_snapshot=snapshot,
        target_root=target,
        indexes=shards,
        upstream_manifests=[other_ref],
    )
    unbound_sha = file_sha256(unbound_path)
    unbound_ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=unbound_path,
        manifest_sha=unbound_sha,
        attempt_id="attempt_0003",
    )
    with pytest.raises(ValueError, match="require the accepted review-data-indexing manifest"):
        unit_def.handler(_make_unit_context(unbound_ctx))

    # 3. Missing job_review_data_indexing handoff
    (run_root / "data" / "jobs" / "job_review_data_indexing" / "latest.json").unlink()
    missing_handoff_ctx = _make_job_context(
        run_root,
        target,
        source_fingerprint=snapshot,
        manifest_path=manifest_path,
        manifest_sha=manifest_sha,
        attempt_id="attempt_0004",
    )
    with pytest.raises(ValueError, match="require the accepted review-data-indexing manifest"):
        unit_def.handler(_make_unit_context(missing_handoff_ctx))
