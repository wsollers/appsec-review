from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import BuildEnvironmentSettings, load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units
from appsec_review.jobs.job_build_environment_analysis.datasets import DATASETS as ENV_DATASETS
from appsec_review.jobs.job_build_environment_analysis.job import (
    RULES,
    SCHEMA as ENV_SCHEMA,
    planning_environment_inputs,
)
from appsec_review.jobs.job_review_intake.datasets import DATASETS as INTAKE_DATASETS
from appsec_review.jobs.job_target_analysis_plan import build_job, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA, PROPOSAL_SCHEMA, summarize_catalog
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.runtime import JobRunner
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


ROOT = Path(__file__).resolve().parents[3]
ENVIRONMENT = "job_build_environment_analysis"


def _write_ref(root: Path, rel_path: str, payload: dict) -> dict:
    path = root / rel_path
    atomic_json(path, payload)
    return {"path": rel_path, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _canned_upstream(run_root: Path, target: Path, files_map: dict[str, str], *, source: str, config=None) -> dict[str, str]:
    target.mkdir(parents=True, exist_ok=True)
    if config is not None:
        JobRunner(config)._bind_configuration(run_root)
    file_entries = []
    for rel_path, content in sorted(files_map.items()):
        full = target / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
        raw = content.encode("utf-8")
        file_entries.append({
            "path": rel_path,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "language": "C" if rel_path.endswith(".c") else None,
        })
    units = discover_build_units(file_entries)
    for unit in units:
        unit["descriptor_package"] = descriptor_package(target, unit, file_entries)

    # 1. job_review_intake
    intake_attempt = run_root / "data/jobs/job_review_intake/attempts/attempt_0001"
    intake_decls = tuple(replace(d, required=False) for d in INTAKE_DATASETS)
    atomic_json(intake_attempt / "claim.json", {
        "dataset_contract": dataset_contract(
            "job_review_intake",
            sorted({d.step for d in intake_decls}),
            intake_decls,
        ),
    })
    intake_doc = _write_ref(
        run_root,
        "data/jobs/job_review_intake/attempts/attempt_0001/artifacts/intake.json",
        {"schema": "appsec-review/review-intake/1", "source_fingerprint": source},
    )
    intake_handoff = write_fixture_handoff(run_root, intake_attempt / "handoff.json", {
        "job_id": "job_review_intake",
        "source_fingerprint": source,
        "outputs": {"intake_publication.publish_handoff": {"artifact": intake_doc}},
    })
    intake_sha = file_sha256(intake_handoff)
    atomic_json(intake_attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": intake_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": intake_sha,
    })

    # 2. job_target_catalog (including real empty retrieval shard + manifest)
    cat_attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    cat_decls = tuple(replace(d, required=False) for d in CATALOG_DATASETS)
    atomic_json(cat_attempt / "claim.json", {
        "dataset_contract": dataset_contract(
            "job_target_catalog",
            sorted({d.step for d in cat_decls}),
            cat_decls,
        ),
    })
    part = _write_ref(run_root, "data/jobs/job_target_catalog/partition.json", {
        "schema": "appsec-review/repository-partition/1",
        "source_fingerprint": source,
        "files": file_entries,
        "gaps": [],
    })
    proj = _write_ref(run_root, "data/jobs/job_target_catalog/projects.json", {
        "schema": "appsec-review/project-catalog/1",
        "projects": [{"root": ".", "kind": "cmake", "manifest": "CMakeLists.txt"}] if "CMakeLists.txt" in files_map else [],
        "gaps": [],
    })
    comp = _write_ref(run_root, "data/jobs/job_target_catalog/components.json", {
        "schema": "appsec-review/component-catalog/1",
        "components": [
            {"component_id": "component:0001", "root": ".", "manifest": "CMakeLists.txt" if "CMakeLists.txt" in files_map else None},
            {"component_id": "component:0002", "root": "docs", "manifest": None},
        ],
        "gaps": [],
    })
    builds = _write_ref(run_root, "data/jobs/job_target_catalog/builds.json", {
        "schema": "appsec-review/build-systems/4",
        "systems": [{"path": "CMakeLists.txt", "systems": ["cmake"]}] if "CMakeLists.txt" in files_map else [],
        "source_only_scopes": [],
        "gaps": [],
    })
    comp_db = _write_ref(run_root, "data/jobs/job_target_catalog/compile-db.json", {
        "schema": "appsec-review/compile-commands/1",
        "files": [],
        "gaps": [],
    })
    targets_ref = _write_ref(run_root, "data/jobs/job_target_catalog/targets.json", {
        "schema": "appsec-review/build-targets/2",
        "targets": units,
        "gaps": [],
    })
    cat_doc_path = "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog/target-catalog.json"
    cat_ref = _write_ref(run_root, cat_doc_path, {
        "schema": "appsec-review/target-catalog/1",
        "source_fingerprint": source,
        "artifacts": {
            "repository_discovery.partition_repository": part,
            "repository_discovery.discover_projects": proj,
            "component_discovery.catalog_components": comp,
            "build_discovery.discover_build_systems": builds,
            "build_discovery.discover_compile_commands": comp_db,
            "build_discovery.catalog_build_targets": targets_ref,
        },
    })
    sqlite_path = run_root / "data/indices/source/target-catalog-fixture.sqlite"
    builder = IndexBuilder(sqlite_path, name="source", fingerprint="f" * 64, target_snapshot=source, shard_id="target-catalog-files")
    for entry in file_entries:
        sid = LogicalIdentity.derive(EntityKind.SOURCE_FILE, source, {"path": entry["path"], "sha256": entry["sha256"]})
        builder.add_entity(EntityRecord(sid, entry["path"], "source_file", entry["path"], entry))
    builder.add_coverage("catalog", "complete", None)
    sqlite_sha = builder.build()
    shard_id = IndexIdentity(
        "source", "appsec-review/retrieval-index/2", sqlite_sha, "f" * 64,
        sqlite_path.relative_to(run_root).as_posix(), {"job": "job_target_catalog"}, (), "target-catalog-files",
    )
    manifest_path = run_root / "data/indices/manifests/target-catalog.json"
    write_manifest(manifest_path, run_id=run_root.name, target_snapshot=source, target_root=target, indexes=[shard_id])
    manifest_ref = {
        "path": manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest_path),
        "size_bytes": manifest_path.stat().st_size,
    }
    sqlite_ref = {
        "path": sqlite_path.relative_to(run_root).as_posix(),
        "sha256": sqlite_sha,
        "size_bytes": sqlite_path.stat().st_size,
    }
    cat_handoff = write_fixture_handoff(run_root, cat_attempt / "handoff.json", {
        "job_id": "job_target_catalog",
        "source_fingerprint": source,
        "upstream_handoff_sha256": {"job_review_intake": intake_sha},
        "artifacts": [part, proj, comp, builds, comp_db, targets_ref, cat_ref, manifest_ref, sqlite_ref],
        "outputs": {"publish_catalog.publish_handoff": {"artifact": cat_ref, "index_manifest": manifest_ref}},
    })
    cat_sha = file_sha256(cat_handoff)
    atomic_json(cat_attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": cat_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_sha,
    })
    atomic_json(run_root / "data/indices/accepted.json", {
        "schema": "appsec-review/accepted-index-set/1",
        "run_id": run_root.name,
        "handoff_path": cat_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_sha,
        "manifest_path": manifest_path.relative_to(run_root).as_posix(),
        "manifest_sha256": manifest_ref["sha256"],
    })
    return {"job_review_intake": intake_sha, "job_target_catalog": cat_sha}


def _isolated_config(tmp_path: Path, *, summary_max_items: int | None = None):
    cfg_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if summary_max_items is not None:
        base = load_config(ROOT / "appsec-review.toml")
        cur = base.job("job_target_analysis_plan").settings["summary_max_items"]
        cur_sample = base.job("job_target_analysis_plan").settings["summary_sample_per_prefix"]
        text = text.replace(f"summary_max_items = {cur}", f"summary_max_items = {summary_max_items}")
        text = text.replace(
            f"summary_sample_per_prefix = {cur_sample}",
            f"summary_sample_per_prefix = {min(cur_sample, summary_max_items)}",
        )
    cfg_path.write_text(text, encoding="utf-8")
    cfg = load_config(cfg_path)
    return replace(cfg, runtime=replace(cfg.runtime, repository_root=ROOT, runs_dir=tmp_path / "runs"))


def test_fail_task_injection_and_deterministic_environment_gap_branches() -> None:
    failing_job = build_job(fail_task="catalog_summary.summarize_components")
    summarize_unit = next(u for u in failing_job.units if u.unit_id == "catalog_summary.summarize_components")
    with pytest.raises(RuntimeError, match="injected bounded failure: catalog_summary.summarize_components"):
        summarize_unit.handler(SimpleNamespace(unit_id="catalog_summary.summarize_components"))

    det = next(u for u in build_job().units if u.unit_id == "analysis_decisions.apply_deterministic_rules")
    events = []
    empty_cat = {
        "source_fingerprint": "s" * 64,
        "catalog_handoff_sha256": "c" * 64,
        "files": (),
        "components": (),
        "projects": (),
        "build_files": (),
        "compile_databases": (),
        "accepted_artifacts": (),
        "build_units": (),
        "gaps": (),
    }
    outputs = {
        "catalog_summary.load_accepted_catalog": {
            "catalog": empty_cat,
            "history": None,
            "environment": {
                "mode": "OPTIONAL_PRIOR",
                "availability": "UNAVAILABLE",
                "reason": "source_mismatch",
                "evidence": {"gaps": ["env_probe_gap"]},
            },
        },
        "catalog_summary.summarize_components": {
            "summary": summarize_catalog(empty_cat, max_items=50, max_bytes=16384, sample_per_prefix=5),
        },
    }
    res = det.handler(SimpleNamespace(
        unit_id="analysis_decisions.apply_deterministic_rules",
        output=outputs.__getitem__,
        job=SimpleNamespace(
            tools=SimpleNamespace(enable_swift=False),
            events=SimpleNamespace(write=lambda ev, **kw: events.append((ev, kw))),
        ),
    ))
    assert "build environment: env_probe_gap" in res["plan"]["coverage_gaps"]
    assert "build environment: source_mismatch" in res["plan"]["coverage_gaps"]
    assert events[0][0] == "ANALYSIS_PLAN_DETERMINISTIC_DECISIONS"


def test_job_runner_executes_isolated_planner_succeeded_and_index_attest_reuse(tmp_path: Path) -> None:
    config = _isolated_config(tmp_path)
    run_id = "2026-11-15-0001"
    run_root = config.runtime.runs_dir / run_id
    source = "1" * 64
    target = tmp_path / "target"
    upstream = _canned_upstream(run_root, target, {
        "CMakeLists.txt": "project(app)\nadd_executable(app main.c)\n",
        "main.c": "int main(void) { return 0; }\n",
        "docs/Dockerfile": "FROM ubuntu:24.04\n",
    }, source=source, config=config)
    launch, _ = planning_environment_inputs(config, run_root, source, {}, upstream)

    def infer(request, *, timeout_seconds):
        unit = request.summary["build_units"][0]
        return ModelResult({
            "schema": PROPOSAL_SCHEMA,
            "action": "final",
            "component_proposals": [],
            "build_recipes": [{
                "schema": "appsec-review/build-recipe/1",
                "build_unit_id": unit["build_unit_id"],
                "image_profile": "native",
                "source_dir": ".",
                "build_dir": "build",
                "system_packages": [],
                "environment": {},
                "dependency_files": ["CMakeLists.txt"],
                "configure_commands": [["cmake", "-S", ".", "-B", "build"]],
                "build_commands": [["cmake", "--build", "build"]],
                "expected_outputs": ["build"],
                "network_required": False,
                "reason": "accepted cmake recipe",
            }],
            "hints": [],
            "abstentions": [],
        }, input_tokens=15, output_tokens=10)

    outcome = JobRunner(config).run(
        build_job(infer=infer),
        run_id=run_id,
        target_root=target,
        source_fingerprint=source,
        upstream_handoffs=upstream,
        orchestration={"build_environment_contract": json.dumps(launch)},
    )
    assert outcome["handoff"]["completion_status"] == "SUCCEEDED"
    accepted = load_accepted_plan(run_root)
    assert accepted["schema"] == PLAN_SCHEMA
    assert accepted["model"]["status"] == "ACCEPTED"

    # Exercise index_plan reused=True branch calling IndexBuilder(...).attest_existing() (a3d4831c0)
    index_unit = next(u for u in build_job(infer=infer).units if u.unit_id == "plan_acceptance.index_plan")
    validated_plan = accepted
    reused_outputs = {
        "plan_acceptance.validate_plan": {
            "plan": validated_plan,
            "artifact": outcome["result"]["outputs"]["plan_acceptance.publish_handoff"]["artifact"],
        },
    }
    reused_ctx = SimpleNamespace(
        unit_id="plan_acceptance.index_plan",
        output=reused_outputs.__getitem__,
        job=SimpleNamespace(
            run_root=run_root,
            run_id=run_id,
            attempt_id="attempt_0002",
            source_fingerprint=source,
            target_root=target,
            upstream_handoffs=upstream,
        ),
    )
    reused_res = index_unit.handler(reused_ctx)
    assert reused_res["index_reused"] is True


def test_job_runner_normalizes_legacy_gaps_under_registered_non_strict_contract(tmp_path: Path) -> None:
    config = _isolated_config(tmp_path, summary_max_items=8)
    run_id = "2026-11-15-0002"
    run_root = config.runtime.runs_dir / run_id
    source = "2" * 64
    target = tmp_path / "target-gaps"
    files = {f"pkg-{idx:02d}/main.c": "int f(void) { return 0; }\n" for idx in range(25)}
    files["CMakeLists.txt"] = "project(app)\nadd_executable(app pkg-00/main.c)\n"
    upstream = _canned_upstream(run_root, target, files, source=source, config=config)

    # Supply an EXPECTED_CURRENT environment with a named gap
    env_attempt = run_root / "data/jobs" / ENVIRONMENT / "attempts/attempt_0001"
    atomic_json(env_attempt / "claim.json", {
        "dataset_contract": dataset_contract(ENVIRONMENT, ("environment_analysis",), ENV_DATASETS),
    })
    env_doc = {
        "schema": ENV_SCHEMA,
        "source_fingerprint": source,
        "catalog_handoff_sha256": upstream["job_target_catalog"],
        "rules": RULES,
        "availability": "AVAILABLE",
        "coverage": "partial",
        "declarations": [],
        "gaps": ["toolchain probe skipped"],
        "bounds": {**asdict(BuildEnvironmentSettings()), "inspected_scripts": 0,
                   "inventory_scope": "accepted inventory only; no whole-target absence claim"},
    }
    env_path = env_attempt / "steps/environment_analysis/tasks/publish_handoff/build-environment.json"
    atomic_json(env_path, env_doc)
    env_ref = {"path": env_path.relative_to(run_root).as_posix(), "sha256": file_sha256(env_path), "size_bytes": env_path.stat().st_size}
    env_handoff = write_fixture_handoff(run_root, env_attempt / "handoff.json", {
        "job_id": ENVIRONMENT,
        "source_fingerprint": source,
        "schema_identity": ENV_SCHEMA,
        "upstream_handoff_sha256": {"job_target_catalog": upstream["job_target_catalog"]},
        "outputs": {"environment_analysis.publish_handoff": {
            "schema": ENV_SCHEMA,
            "artifact": env_ref,
            "gaps": ["toolchain probe skipped"],
            "terminal_status": "COMPLETED_WITH_GAPS",
        }},
    })
    env_sha = file_sha256(env_handoff)
    atomic_json(env_attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": "attempt_0001",
        "handoff_path": env_handoff.relative_to(run_root).as_posix(),
        "handoff_sha256": env_sha,
    })
    full_upstream = {**upstream, ENVIRONMENT: env_sha}
    launch, _ = planning_environment_inputs(config, run_root, source, {"workflow": "wave1_review"}, full_upstream)

    outcome = JobRunner(config).run(
        build_job(infer=None),
        run_id=run_id,
        target_root=target,
        source_fingerprint=source,
        upstream_handoffs=full_upstream,
        orchestration={"build_environment_contract": json.dumps(launch)},
    )
    handoff = outcome["handoff"]
    assert handoff["completion_status"] == "COMPLETED_WITH_GAPS"
    pub = handoff["outputs"]["plan_acceptance.publish_handoff"]
    assert any("model is unavailable" in str(g) for g in pub["gaps"])
    assert any("toolchain probe skipped" in str(g) for g in pub["gaps"])
