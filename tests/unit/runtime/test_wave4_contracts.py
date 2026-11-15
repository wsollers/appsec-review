"""Wave 4 optional-prior handoff admission, read observation, and lineage separation."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis import build_job as build_env
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID as ENV_JOB_ID,
    environment_contract,
    load_environment,
)
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_planner
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import JobRunner
from appsec_review.runtime.checkpoints import input_key
from appsec_review.runtime.consume import accepted_upstream, current_pins, upstream_scope
from appsec_review.runtime.inputs import (
    INPUT_ADMISSION_SCHEMA,
    admit_inputs,
    input_read_scope,
    resolve_job_inputs,
)
from appsec_review.observability import EventLog, PipelineLog
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.repair import _planning_repair_context
from appsec_review.storage import RunStore
from tests.release_support import write_release

ROOT = Path(__file__).resolve().parents[3]


def _seed_env_run(tmp_path: Path, *, mode: str = "strict"):
    from dataclasses import replace as dc_replace
    import hashlib
    from appsec_review.jobs.job_review_intake.datasets import DATASETS as INTAKE_DATASETS
    from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
    from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
    from appsec_review.runtime.datasets import dataset_contract
    from appsec_review.storage import atomic_json, file_sha256
    from tests.handoff_fixture import write_fixture_handoff

    config_path = tmp_path / "appsec-review.toml"
    target = tmp_path / "target"
    target.mkdir()
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    policy = '[review_policy]\nmode = "strict"\napproved_first_party_projects = []'
    text = text.replace(
        policy,
        f'[review_policy]\nmode = "{mode}"\nproject_id = "wave4-unit"\n'
        'approved_first_party_projects = ["wave4-unit"]\n'
        f"target_root = {json.dumps(str(target))}\ncustody = \"application_private_v1\"",
    )
    write_release(
        tmp_path,
        ("job_review_intake", "job_target_catalog", ENV_JOB_ID, "job_target_analysis_plan"),
    )
    config_path.write_bytes(text.encode("utf-8"))
    config = load_config(config_path)
    setup_bytes = b"SDK_ROOT=tools/sdk\n"
    (target / "setup.sh").write_bytes(setup_bytes)
    fp = source_fingerprint(target)
    runner = JobRunner(config)
    run_id, run_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    runner._bind_configuration(run_root)

    def _ref(rel: str, payload: dict) -> dict:
        p = run_root / rel
        atomic_json(p, payload)
        return {"path": rel, "sha256": file_sha256(p), "size_bytes": p.stat().st_size}

    intake_att = run_root / "data/jobs/job_review_intake/attempts/attempt_0001"
    intake_decls = tuple(dc_replace(d, required=False) for d in INTAKE_DATASETS)
    atomic_json(intake_att / "claim.json", {
        "dataset_contract": dataset_contract("job_review_intake", sorted({d.step for d in intake_decls}), intake_decls),
    })
    intake_doc = _ref("data/jobs/job_review_intake/attempts/attempt_0001/artifacts/intake.json", {
        "schema": "appsec-review/review-intake/1", "source_fingerprint": fp,
    })
    intake_hp = write_fixture_handoff(run_root, intake_att / "handoff.json", {
        "job_id": "job_review_intake", "source_fingerprint": fp,
        "outputs": {"intake_publication.publish_handoff": {"artifact": intake_doc}},
    })
    intake_sha = file_sha256(intake_hp)
    atomic_json(intake_att.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
        "handoff_path": intake_hp.relative_to(run_root).as_posix(), "handoff_sha256": intake_sha,
    })
    intake = {"handoff_sha256": intake_sha, "handoff": json.loads(intake_hp.read_bytes())}

    cat_att = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    cat_decls = tuple(dc_replace(d, required=False) for d in CATALOG_DATASETS)
    atomic_json(cat_att / "claim.json", {
        "dataset_contract": dataset_contract("job_target_catalog", sorted({d.step for d in cat_decls}), cat_decls),
    })
    part = _ref("data/jobs/job_target_catalog/partition.json", {
        "schema": "appsec-review/repository-partition/1", "source_fingerprint": fp,
        "files": [{"path": "setup.sh", "sha256": hashlib.sha256(setup_bytes).hexdigest(), "size_bytes": len(setup_bytes), "language": "Shell"}],
        "gaps": [],
    })
    proj = _ref("data/jobs/job_target_catalog/projects.json", {"schema": "appsec-review/project-catalog/1", "projects": [], "gaps": []})
    comp = _ref("data/jobs/job_target_catalog/components.json", {
        "schema": "appsec-review/component-catalog/1",
        "components": [{"component_id": "component:0001", "root": ".", "manifest": None}], "gaps": [],
    })
    builds = _ref("data/jobs/job_target_catalog/builds.json", {"schema": "appsec-review/build-systems/4", "systems": [], "source_only_scopes": [], "gaps": []})
    comp_db = _ref("data/jobs/job_target_catalog/compile-db.json", {"schema": "appsec-review/compile-commands/1", "files": [], "gaps": []})
    targets_ref = _ref("data/jobs/job_target_catalog/targets.json", {"schema": "appsec-review/build-targets/2", "targets": [], "gaps": []})
    cat_ref = _ref("data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog/target-catalog.json", {
        "schema": "appsec-review/target-catalog/1", "source_fingerprint": fp,
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
    builder = IndexBuilder(sqlite_path, name="source", fingerprint="e" * 64, target_snapshot=fp, shard_id="target-catalog-files")
    setup_entry = {"path": "setup.sh", "sha256": hashlib.sha256(setup_bytes).hexdigest(), "size_bytes": len(setup_bytes), "language": "Shell"}
    sid = LogicalIdentity.derive(EntityKind.SOURCE_FILE, fp, {"path": setup_entry["path"], "sha256": setup_entry["sha256"]})
    builder.add_entity(EntityRecord(sid, setup_entry["path"], "source_file", setup_entry["path"], setup_entry))
    builder.add_coverage("catalog", "complete", None)
    sqlite_sha = builder.build()
    shard_id = IndexIdentity("source", "appsec-review/retrieval-index/2", sqlite_sha, "e" * 64,
                             sqlite_path.relative_to(run_root).as_posix(), {"job": "job_target_catalog"}, (), "target-catalog-files")
    manifest_path = run_root / "data/indices/manifests/target-catalog.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=fp, target_root=target, indexes=[shard_id])
    manifest_ref = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    sqlite_ref = {"path": sqlite_path.relative_to(run_root).as_posix(), "sha256": sqlite_sha, "size_bytes": sqlite_path.stat().st_size}
    cat_hp = write_fixture_handoff(run_root, cat_att / "handoff.json", {
        "job_id": "job_target_catalog", "source_fingerprint": fp,
        "upstream_handoff_sha256": {"job_review_intake": intake_sha},
        "artifacts": [part, proj, comp, builds, comp_db, targets_ref, cat_ref, manifest_ref, sqlite_ref],
        "outputs": {"publish_catalog.publish_handoff": {"artifact": cat_ref, "index_manifest": manifest_ref}},
    })
    cat_sha = file_sha256(cat_hp)
    atomic_json(cat_att.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
        "handoff_path": cat_hp.relative_to(run_root).as_posix(), "handoff_sha256": cat_sha,
    })
    atomic_json(run_root / "data/indices/accepted.json", {
        "schema": "appsec-review/accepted-index-set/1",
        "run_id": run_id,
        "handoff_path": cat_hp.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_sha,
        "manifest_path": manifest_path.relative_to(run_root).as_posix(),
        "manifest_sha256": manifest_ref["sha256"],
    })
    catalog = {"handoff_sha256": cat_sha, "handoff": json.loads(cat_hp.read_bytes())}

    env_out = runner.run(
        build_env(),
        run_id=run_id,
        target_root=target,
        source_fingerprint=fp,
        upstream_handoffs={"job_target_catalog": cat_sha},
    )
    return config, runner, run_id, run_root, target, fp, intake, catalog, env_out


def _make_context(
    config,
    run_root: Path,
    target: Path,
    fp: str,
    job_id: str,
    *,
    upstream: dict[str, str],
    optional_prior: dict[str, str] | None = None,
) -> JobContext:
    job = builtin_registry().build(job_id)
    attempt_root = run_root / "data/jobs" / job_id / "attempts" / "attempt_9999"
    (attempt_root / "logs").mkdir(parents=True, exist_ok=True)
    events = EventLog(
        attempt_root / "logs" / "events.jsonl",
        PipelineLog(run_root),
        {"run_id": run_root.name, "job_id": job_id, "attempt_id": "attempt_9999", "trigger": "unit"},
    )
    return JobContext(
        run_id=run_root.name,
        attempt_id="attempt_9999",
        trigger="unit",
        repository_root=config.runtime.repository_root,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=config.runtime.metadata_dir,
        orchestration=MappingProxyType({}),
        config=config.job(job_id),
        events=events,
        tools=config.tools,
        review_policy=config.review_policy,
        evidence_target_snapshot=fp,
        upstream_handoffs=MappingProxyType(dict(upstream)),
        optional_prior_handoffs=MappingProxyType(dict(optional_prior or {})),
        contract=job.contract,
        target_root=target,
        source_fingerprint=fp,
    )


def test_checkpoints_input_key_distinguishes_optional_prior_without_changing_empty_digest() -> None:
    base = {
        "job_id": "job_target_analysis_plan",
        "source_fingerprint": "fp-1",
        "evidence_target_snapshot": "fp-1",
        "resolved_config_sha256": "a" * 64,
        "dataset_contract": {"sha256": "b" * 64},
        "upstream_handoffs": {"job_target_catalog": "c" * 64},
    }
    assert input_key(base) == input_key({**base, "optional_prior_handoffs": {}})

    with_prior_a = input_key(
        {
            **base,
            "optional_prior_handoffs": {
                ENV_JOB_ID: "d" * 64,
                "job_review_intake": "e" * 64,
            },
        }
    )
    with_prior_b = input_key(
        {
            **base,
            "optional_prior_handoffs": {
                "job_review_intake": "e" * 64,
                ENV_JOB_ID: "d" * 64,
            },
        }
    )
    assert with_prior_a == with_prior_b
    assert with_prior_a != input_key(base)
    assert with_prior_a != input_key({**base, "optional_prior_handoffs": {ENV_JOB_ID: "f" * 64}})


def test_upstream_scope_separates_current_and_optional_prior_and_rejects_overlap(tmp_path: Path) -> None:
    planner_contract = builtin_registry().build("job_target_analysis_plan").contract
    cat_pin = "1" * 64
    env_pin = "2" * 64

    with upstream_scope(
        tmp_path,
        "job_target_analysis_plan",
        {"job_target_catalog": cat_pin},
        contract=planner_contract,
        optional_prior_handoffs={ENV_JOB_ID: env_pin},
    ):
        assert current_pins(tmp_path) == {"job_target_catalog": cat_pin}
        assert accepted_upstream(tmp_path, ENV_JOB_ID, required=False) is None
        with pytest.raises(ValueError, match="handoff is required|not supplied by the attempt claim"):
            accepted_upstream(tmp_path, ENV_JOB_ID)

    with pytest.raises(ValueError, match="conflicting current and optional-prior input lineages"):
        with upstream_scope(
            tmp_path,
            "job_target_analysis_plan",
            {ENV_JOB_ID: env_pin},
            contract=planner_contract,
            optional_prior_handoffs={ENV_JOB_ID: env_pin},
        ):
            pass

    with pytest.raises(ValueError, match="pinned optional-prior digest"):
        with upstream_scope(
            tmp_path,
            "job_target_analysis_plan",
            {},
            contract=planner_contract,
            optional_prior_handoffs={ENV_JOB_ID: "short"},
        ):
            pass

    with pytest.raises(ValueError, match="invalid pinned optional-prior job identity"):
        with upstream_scope(
            tmp_path,
            "job_target_analysis_plan",
            {},
            contract=planner_contract,
            optional_prior_handoffs={"bad-id": env_pin},
        ):
            pass


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_optional_prior_read_records_handoff_and_output_receipts_for_current_and_stale(
    tmp_path: Path, mode: str
) -> None:
    from dataclasses import replace

    config, _runner, _run_id, run_root, target, fp, intake, catalog, env_out = _seed_env_run(
        tmp_path, mode=mode
    )
    env_sha = env_out["handoff_sha256"]
    enabled = set(config.jobs)

    no_prior_ctx = _make_context(
        config,
        run_root,
        target,
        fp,
        "job_target_analysis_plan",
        upstream={"job_review_intake": intake["handoff_sha256"], "job_target_catalog": catalog["handoff_sha256"]},
    )
    no_prior_doc = admit_inputs(no_prior_ctx, enabled)
    assert no_prior_doc["schema"] == INPUT_ADMISSION_SCHEMA
    assert "optional_priors" not in no_prior_doc

    current_ctx = _make_context(
        config,
        run_root,
        target,
        fp,
        "job_target_analysis_plan",
        upstream={"job_review_intake": intake["handoff_sha256"], "job_target_catalog": catalog["handoff_sha256"]},
        optional_prior={ENV_JOB_ID: env_sha},
    )
    current_doc = admit_inputs(current_ctx, enabled)
    assert {(row["producer"], row["output_kind"]) for row in current_doc["optional_priors"]} == {
        (ENV_JOB_ID, "handoff"),
        (ENV_JOB_ID, "build_environment"),
    }
    contract_opt = environment_contract(
        config, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": env_sha}, {}
    )
    with input_read_scope(current_ctx) as current_reads:
        assert current_reads is not None
        assert accepted_upstream(run_root, ENV_JOB_ID, required=False) is None
        loaded_current = load_environment(run_root, fp, contract_opt)
        receipts_current = current_reads.document()
    assert loaded_current["availability"] == "AVAILABLE"
    assert loaded_current["artifact"] is not None and loaded_current["evidence"] is not None
    assert {(r["producer"], r["output_kind"], r["handoff_sha256"], r["target_snapshot"]) for r in receipts_current["reads"]} == {
        (ENV_JOB_ID, "handoff", env_sha, fp),
        (ENV_JOB_ID, "build_environment", env_sha, fp),
    }

    stale_fp = "9" * 64
    env_only_contract = replace(
        current_ctx.contract,
        inputs=tuple(item for item in current_ctx.contract.inputs if item.producer == ENV_JOB_ID),
    )
    stale_ctx = replace(
        _make_context(
            config,
            run_root,
            target,
            stale_fp,
            "job_target_analysis_plan",
            upstream={},
            optional_prior={ENV_JOB_ID: env_sha},
        ),
        contract=env_only_contract,
    )
    stale_doc = admit_inputs(stale_ctx, enabled)
    assert all(row["target_snapshot"] == fp for row in stale_doc["optional_priors"])
    with input_read_scope(stale_ctx) as stale_reads:
        assert stale_reads is not None
        loaded_stale = load_environment(run_root, stale_fp, contract_opt)
        receipts_stale = stale_reads.document()
    assert loaded_stale["availability"] == "UNAVAILABLE"
    assert loaded_stale["artifact"] is None and loaded_stale["evidence"] is None
    assert loaded_stale["reason"] == "STALE optional prior source"
    assert {(r["producer"], r["output_kind"], r["handoff_sha256"], r["target_snapshot"]) for r in receipts_stale["reads"]} == {
        (ENV_JOB_ID, "handoff", env_sha, fp),
        (ENV_JOB_ID, "build_environment", env_sha, fp),
    }


def test_optional_prior_refuses_unpinned_tampered_foreign_and_expected_current_laundering(
    tmp_path: Path,
) -> None:
    config, _runner, _run_id, run_root, target, fp, intake, catalog, env_out = _seed_env_run(tmp_path)
    env_sha = env_out["handoff_sha256"]
    enabled = set(config.jobs)
    base_upstream = {
        "job_review_intake": intake["handoff_sha256"],
        "job_target_catalog": catalog["handoff_sha256"],
    }

    unpinned_ctx = _make_context(
        config, run_root, target, fp, "job_target_analysis_plan", upstream=base_upstream
    )
    contract_opt = environment_contract(
        config, {"environment_mode": "OPTIONAL_PRIOR", "environment_reference": env_sha}, {}
    )
    with pytest.raises(ValueError, match="consumed handoff is not the supplied immutable input"):
        with input_read_scope(unpinned_ctx):
            load_environment(run_root, fp, contract_opt)

    prior_only_ctx = _make_context(
        config,
        run_root,
        target,
        fp,
        "job_target_analysis_plan",
        upstream=base_upstream,
        optional_prior={ENV_JOB_ID: env_sha},
    )
    contract_cur = environment_contract(config, {"workflow": "wave1_review"}, {ENV_JOB_ID: env_sha})
    with pytest.raises(ValueError, match="consumed handoff is not the supplied immutable input"):
        with input_read_scope(prior_only_ctx):
            load_environment(run_root, fp, contract_cur)

    conflict_ctx = _make_context(
        config,
        run_root,
        target,
        fp,
        "job_target_analysis_plan",
        upstream={**base_upstream, ENV_JOB_ID: env_sha},
        optional_prior={ENV_JOB_ID: env_sha},
    )
    with pytest.raises(ValueError, match="conflicting current and optional-prior input lineages"):
        admit_inputs(conflict_ctx, enabled)

    undeclared_ctx = _make_context(
        config,
        run_root,
        target,
        fp,
        "job_target_catalog",
        upstream={"job_review_intake": intake["handoff_sha256"]},
        optional_prior={ENV_JOB_ID: env_sha},
    )
    with pytest.raises(ValueError, match="undeclared optional-prior producer"):
        admit_inputs(undeclared_ctx, enabled)

    _, foreign_root = RunStore(config.runtime.runs_dir).create(datetime.now(timezone.utc))
    foreign_ctx = _make_context(
        config,
        foreign_root,
        target,
        fp,
        "job_target_analysis_plan",
        upstream={},
        optional_prior={ENV_JOB_ID: env_sha},
    )
    with pytest.raises(ValueError, match="expected exactly one accepted handoff"):
        admit_inputs(foreign_ctx, enabled)

    artifact_rel = env_out["handoff"]["outputs"]["environment_analysis.publish_handoff"]["artifact"]["path"]
    artifact_path = run_root / artifact_rel
    artifact_path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="identity mismatch|artifact digest mismatch|changed"):
        with input_read_scope(prior_only_ctx):
            load_environment(run_root, fp, contract_opt)


def test_resolve_job_inputs_and_repair_context_preserve_optional_prior_lineage(
    tmp_path: Path,
) -> None:
    config, runner, run_id, run_root, target, fp, intake, catalog, env_out = _seed_env_run(tmp_path)
    env_sha = env_out["handoff_sha256"]
    enabled = set(config.jobs)

    planner = build_planner(infer=lambda *_a, **_kw: pytest.fail("no model call expected"))
    upstream_with_prior_env = {
        "job_review_intake": intake["handoff_sha256"],
        "job_target_catalog": catalog["handoff_sha256"],
        ENV_JOB_ID: env_sha,
    }
    orchestration = {"workflow": "standalone", "environment_mode": "OPTIONAL_PRIOR"}
    planner_out = runner.run(
        planner,
        run_id=run_id,
        target_root=target,
        source_fingerprint=fp,
        upstream_handoffs=upstream_with_prior_env,
        orchestration=orchestration,
    )
    plan_sha = planner_out["handoff_sha256"]

    recovered = _planning_repair_context(config, run_root, [planner])
    assert recovered == {
        "workflow": "standalone",
        "environment_mode": "OPTIONAL_PRIOR",
        "environment_reference": env_sha,
    }

    evidence_job = builtin_registry().build("job_evidence_collection")
    current, optional_prior, env_meta, _candidate = resolve_job_inputs(
        config,
        evidence_job,
        run_root,
        fp,
        {},
        {"job_target_catalog": catalog["handoff_sha256"], "job_target_analysis_plan": plan_sha},
        enabled=enabled,
    )
    assert ENV_JOB_ID not in current
    assert optional_prior == {ENV_JOB_ID: env_sha}
    assert env_meta is None

    with pytest.raises(ValueError, match="conflicting current and optional-prior input lineages"):
        resolve_job_inputs(
            config,
            evidence_job,
            run_root,
            fp,
            {},
            {
                "job_target_catalog": catalog["handoff_sha256"],
                "job_target_analysis_plan": plan_sha,
                ENV_JOB_ID: env_sha,
            },
            enabled=enabled,
        )
