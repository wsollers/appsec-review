"""Contract, dataset, topology, registry, and artifact-glob ownership pins for job_evidence_collection."""

from __future__ import annotations

from dataclasses import asdict
from fnmatch import fnmatchcase
import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.job_evidence_collection import (
    __all__ as public_exports,
    build_job,
    load_target_catalog,
    plan_applicability,
)
from appsec_review.jobs.job_evidence_collection.adapters import ADAPTERS, ScanCatalog
from appsec_review.jobs.job_evidence_collection.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_evidence_collection.job import CAPABILITIES, TOPOLOGY
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.runtime.registry import builtin_registry

from .support import FakeExecutor, ROOT, attempt_scope, make_unit_context, write_osv_feed


JOB = "job_evidence_collection"


def test_every_input_requirement_field_and_dispatch_policy_is_pinned() -> None:
    assert set(public_exports) == {
        "CAPABILITIES",
        "TOPOLOGY",
        "build_job",
        "load_target_catalog",
        "plan_applicability",
    }
    assert callable(load_target_catalog) and callable(plan_applicability)
    rows = [
        ("job_build_environment_analysis", "handoff", "appsec-review/job-handoff/2", "operational", "handoff"),
        ("job_build_environment_analysis", "build_environment", "appsec-review/build-environment-analysis/1", "operational", "handoff"),
        ("job_review_intake", "handoff", "appsec-review/job-handoff/2", "producer_evidence", "handoff"),
        ("job_review_intake", "model_preflight", "appsec-review/model-preflight/1", "producer_evidence", "handoff"),
        ("job_review_intake", "binary_evidence", "appsec-review/binary-evidence-intake/1", "producer_evidence", "handoff"),
        ("job_review_intake", "review_intake", "appsec-review/review-intake/1", "producer_evidence", "handoff"),
        ("job_target_analysis_plan", "handoff", "appsec-review/job-handoff/2", "producer_evidence", "handoff"),
        ("job_target_analysis_plan", "planning_feedback_cache", "appsec-review/target-analysis-proposal/3", "producer_evidence", "handoff"),
        ("job_target_analysis_plan", "analysis_plan", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_analysis_plan", "analysis_plan_documents", "appsec-review/target-analysis-plan/1", "producer_evidence", "handoff"),
        ("job_target_catalog", "handoff", "appsec-review/job-handoff/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1", "producer_evidence", "handoff"),
        ("job_target_catalog", "source_files", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "declaration_symbols", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "components", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "target_documents", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "build_units", "appsec-review/retrieval-index/2", "producer_evidence", "handoff"),
        ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1", "producer_evidence", "handoff"),
        ("job_third_party_data_sync", "feed_snapshot", "appsec-review/public-feed-use/1", "reference", "external"),
    ]
    expected = [
        {
            "producer": producer,
            "output_kind": kind,
            "schema": schema,
            "authority": authority,
            "availability": "optional",
            "missing": "gap",
            "coverage": "allow_partial",
            "channel": channel,
        }
        for producer, kind, schema, authority, channel in rows
    ]
    assert [asdict(item) for item in CONTRACT.inputs] == expected
    assert {key: value for key, value in asdict(CONTRACT).items() if key != "inputs"} == {
        "schedule_after": ("job_target_analysis_plan",),
        "dispatch": "review_graph",
        "target_access": "checkout",
        "always_execute": False,
        "propagate_handoff": True,
    }
    assert CONTRACT.consumes == CONSUMES == (
        "job_build_environment_analysis",
        "job_review_intake",
        "job_target_analysis_plan",
        "job_target_catalog",
    )


def test_every_dataset_field_and_topology_registration_is_pinned() -> None:
    attempt = "data/jobs/job_evidence_collection/attempts/*"
    assert [asdict(item) for item in DATASETS] == [
        {
            "output_kind": "static_tool_observations",
            "step": "evidence_publication",
            "family": "scanner_findings",
            "schema": "appsec-review/retrieval-index/2",
            "sensitivity": "internal",
            "disposition": "indexed",
            "description": (
                "Normalized static-tool observations, one shard per tool, including software inventory and "
                "vulnerability matches."
            ),
            "indexes": ("observations",),
            "shard_prefixes": (),
            "shard_suffixes": (),
            "artifacts": (),
            "query_route": "find/search index=observations; query_precomputed query_set=scanner_correlation",
            "reason": None,
            "required": False,
            "store": "retrieval",
            "authority": "producer_evidence",
        },
        {
            "output_kind": "static_tool_evidence",
            "step": "evidence_publication",
            "family": "scanner_findings",
            "schema": "appsec-review/static-tool-evidence/2",
            "sensitivity": "internal",
            "disposition": "artifact_only",
            "description": "Normalized per-tool evidence documents, checkpoints and the evidence handoff.",
            "indexes": (),
            "shard_prefixes": (),
            "shard_suffixes": (),
            "artifacts": (
                f"{attempt}/steps/*/tasks/*/evidence.json",
                f"{attempt}/steps/*/tasks/*/handoff.json",
                "data/task-checkpoints/job_evidence_collection/**",
            ),
            "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
            "reason": "same normalized records as the per-tool observation shards",
            "required": False,
            "store": "retrieval",
            "authority": "producer_evidence",
        },
        {
            "output_kind": "static_tool_io",
            "step": "source_sast",
            "family": "scanner_findings",
            "schema": "appsec-review/container-execution/1",
            "sensitivity": "sensitive",
            "disposition": "protected",
            "description": "Raw scanner output, staged inputs, SBOMs and execution streams.",
            "indexes": (),
            "shard_prefixes": (),
            "shard_suffixes": (),
            "artifacts": (
                f"{attempt}/steps/*/tasks/*/scratch/**",
                f"{attempt}/steps/*/tasks/*/inputs/**",
                f"{attempt}/steps/vulnerability_matching/tasks/osv_scanner_scan/osv-scanner-merged.json",
            ),
            "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
            "reason": "raw scanner output can contain secret matches and unbounded target content",
            "required": False,
            "store": "retrieval",
            "authority": "producer_evidence",
        },
    ]

    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs.keys(), surface="test")
    deps = wave1_dependencies(set(config.jobs))
    assert deps is not None
    assert deps[JOB] == ("job_target_analysis_plan",)


def test_graph_units_dependencies_and_external_feed_identity_are_explicit() -> None:
    built = build_job()
    assert (built.job_id, built.name, built.schema_identity) == (
        JOB,
        "evidence_collection",
        "appsec-review/evidence-collection-job/1",
    )
    assert built.contract is CONTRACT and built.datasets is DATASETS
    assert built.consumes == CONTRACT.consumes and built.strict_gaps is False
    assert built.external_input_identity is feed_input_identity
    assert len(built.input_validators) == 1 and built.output_validators == ()
    assert built.result_transform is None

    expected_units: list[tuple[str, tuple[str, ...]]] = []
    index_ids: list[str] = []
    for capability, tools in CAPABILITIES.items():
        for tool_id in tools:
            stem = tool_id.removeprefix("tool-").replace("-", "_")
            scan_id = f"{capability}.{stem}_scan"
            norm_id = f"{capability}.{stem}_normalize"
            idx_id = f"{capability}.{stem}_index"
            expected_units.append((scan_id, ("software_inventory.syft_scan",) if tool_id == "tool-grype" else ()))
            expected_units.append((norm_id, (scan_id,)))
            expected_units.append((idx_id, (norm_id,)))
            index_ids.append(idx_id)
    expected_units.append(("evidence_publication.assemble_manifest", tuple(index_ids)))
    expected_units.append(("evidence_publication.publish_handoff", ("evidence_publication.assemble_manifest",)))

    assert len(built.units) == 62
    assert [(u.unit_id, u.dependencies) for u in built.units] == expected_units
    assert [u.unit_id for u in built.units] == [
        f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks
    ]


def _matches_dataset_glob(rel_path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        prefix = pattern[:-3] + "/"
        return rel_path.startswith(prefix) or fnmatchcase(rel_path, prefix + "*")
    # Collapse ** segments by checking prefix/suffix parts
    if "/**/scratch/**" in pattern or "/scratch/**" in pattern:
        head = pattern.split("/scratch/**")[0]
        parts = rel_path.split("/scratch/", 1)
        return len(parts) == 2 and fnmatchcase(parts[0], head)
    if "/inputs/**" in pattern:
        head = pattern.split("/inputs/**")[0]
        parts = rel_path.split("/inputs/", 1)
        return len(parts) == 2 and fnmatchcase(parts[0], head)
    return fnmatchcase(rel_path, pattern)


def test_published_evidence_checkpoints_io_and_shards_match_declared_globs_and_schemas(tmp_path: Path) -> None:
    from appsec_review.jobs.job_evidence_collection.job import (
        _build_producer_shard,
        _execute_tool,
        _normalize_tool,
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    write_osv_feed(repo, ("npm",))
    unit, catalog, _ = make_unit_context(
        tmp_path,
        unit_id="vulnerability_matching.osv_scanner_scan",
        repository_root=repo,
        target_files={
            "web/package-lock.json": '{"lockfileVersion":3,"packages":{}}',
            "api/package-lock.json": '{"lockfileVersion":3,"packages":{}}',
        },
    )
    catalog = ScanCatalog(
        catalog.source_fingerprint,
        catalog.handoff_sha256,
        catalog.files,
        ({"root": "web"}, {"root": "api"}),
        target_root=catalog.target_root,
    )
    calls: list[str] = []

    class OsvExecutor(FakeExecutor):
        def __init__(self, r_root: Path, c: list[str]):
            super().__init__(ROOT, r_root, c)

        def execute(self, request):
            res = super().execute(request)
            (request.scratch_root / "output.json").write_text(
                json.dumps({
                    "results": [{
                        "source": {"path": "/target/web/package-lock.json"},
                        "packages": [{
                            "package": {"name": "left-pad"},
                            "vulnerabilities": [{"id": "GHSA-test-0001", "summary": "vuln"}],
                        }],
                    }]
                }),
                encoding="utf-8",
            )
            return res

    adapter = ADAPTERS["tool-osv-scanner"]
    with attempt_scope(unit):
        scan_out = _execute_tool(unit, adapter, catalog, lambda u: OsvExecutor(u.job.run_root, calls), None)
    assert scan_out["terminal_status"] == "SUCCEEDED"

    norm_unit, _, _ = make_unit_context(
        tmp_path,
        unit_id="vulnerability_matching.osv_scanner_normalize",
        repository_root=repo,
        outputs={"vulnerability_matching.osv_scanner_scan": scan_out},
    )
    norm_unit.job.target_root = unit.job.target_root
    norm_out = _normalize_tool(norm_unit, "vulnerability_matching.osv_scanner_scan")

    idx_unit, _, _ = make_unit_context(
        tmp_path,
        unit_id="vulnerability_matching.osv_scanner_index",
        repository_root=repo,
        outputs={"vulnerability_matching.osv_scanner_normalize": norm_out},
    )
    idx_unit.job.target_root = unit.job.target_root
    idx_out = _build_producer_shard(idx_unit, "vulnerability_matching.osv_scanner_normalize")

    pub_job = build_job()
    publish_unit_def = next(u for u in pub_job.units if u.unit_id == "evidence_publication.publish_handoff")
    pub_ctx, _, _ = make_unit_context(
        tmp_path,
        unit_id="evidence_publication.publish_handoff",
        repository_root=repo,
        outputs={
            "evidence_publication.assemble_manifest": {
                "index_manifest": {"path": "data/indices/manifests/evidence-attempt_0001.json", "sha256": "d" * 64},
                "shards": [idx_out["index_identity"]],
                "item_count": idx_out["record_count"],
                "dispositions": [{
                    "tool_id": "tool-osv-scanner",
                    "terminal_status": "SUCCEEDED",
                    "checkpoint_reused": False,
                    "record_count": idx_out["record_count"],
                    "index_reused": False,
                    "shard_id": "osv_scanner",
                    "gaps": [],
                    "not_applicable_input_count": 0,
                }],
                "gaps": [],
                "not_applicable_inputs": {"count": 0, "items": []},
                "unsupported_coverage": {"kind": "unsupported-language", "count": 0},
            }
        },
    )
    pub_out = publish_unit_def.handler(pub_ctx)

    evidence_ds = next(d for d in DATASETS if d.output_kind == "static_tool_evidence")
    io_ds = next(d for d in DATASETS if d.output_kind == "static_tool_io")
    obs_ds = next(d for d in DATASETS if d.output_kind == "static_tool_observations")

    evidence_doc = json.loads((unit.job.run_root / scan_out["artifact"]["path"]).read_text(encoding="utf-8"))
    assert evidence_doc["schema"] == evidence_ds.schema
    assert any(_matches_dataset_glob(scan_out["artifact"]["path"], pat) for pat in evidence_ds.artifacts)
    assert any(_matches_dataset_glob(scan_out["checkpoint"]["path"], pat) for pat in evidence_ds.artifacts)
    assert any(_matches_dataset_glob(pub_out["artifact"]["path"], pat) for pat in evidence_ds.artifacts)

    merged_rel = scan_out["scanner_output"]
    assert merged_rel is not None
    assert any(_matches_dataset_glob(merged_rel, pat) for pat in io_ds.artifacts)
    exec_rel = scan_out["invocations"][0]["execution"]["path"]
    assert any(_matches_dataset_glob(exec_rel, pat) for pat in io_ds.artifacts)

    assert idx_out["index_identity"]["name"] in obs_ds.indexes
    assert idx_out["index_identity"]["schema"] == obs_ds.schema
