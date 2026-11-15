"""Wave 3 contract admission and disabled-producer unavailable paths."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import accepted_handoff, handoff_manifests, shard_key
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS
from appsec_review.jobs.job_build_iteration import build_job as build_iteration
from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
from appsec_review.jobs.job_profile_data import build_job as build_profile_data, load_accepted_profile_data
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_test_coverage import build_job as build_test_coverage, load_accepted_test_coverage
from appsec_review.retrieval import write_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.contracts import Availability, InputChannel, JobContract, MissingPolicy
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import RunStore, atomic_json, file_sha256
from appsec_review.storage.validation import validation_scope
from tests.artifact_input_support import recorded_job
from tests.release_support import declare_releases, write_release

ROOT = Path(__file__).resolve().parents[3]


def _wave3_runner(tmp_path: Path, job_ids: tuple[str, ...], *,
                  disabled_jobs: tuple[str, ...] = ()) -> JobRunner:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    if not (root / "containers").exists():
        (root / "containers").symlink_to(ROOT / "containers")
    if not (root / "rules").exists():
        (root / "rules").mkdir(parents=True, exist_ok=True)
        (root / "rules" / "semgrep").symlink_to(ROOT / "rules" / "semgrep")
    components = ("platform", "validation", *(adapter.tool_id for adapter in ADAPTERS.values()))
    text = declare_releases((ROOT / "appsec-review.toml").read_text(encoding="utf-8"),
                            **{key: "fixture/1" for key in components})
    for disabled_id in disabled_jobs:
        header = f"[jobs.{disabled_id}.settings]\n"
        if header not in text:
            raise AssertionError(f"missing settings header for {disabled_id}")
        text = text.replace(header, f"{header}enabled = false\n", 1)
    config_path = root / "appsec-review.toml"
    config_path.write_text(text, encoding="utf-8")
    write_release(root, tuple(dict.fromkeys(job_ids)))
    base = load_config(config_path)
    config = replace(
        base,
        runtime=replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                        metadata_dir=tmp_path / "metadata"),
        review_policy=replace(base.review_policy, releases=ComponentReleases({
            **base.review_policy.releases.values, "platform": "fixture/1", "validation": "fixture/1",
        })),
    )
    return JobRunner(config)


def _seed_catalog_run(tmp_path: Path, extra_job_ids: tuple[str, ...], *,
                      disabled_jobs: tuple[str, ...] = ()):
    job_ids = ("job_review_intake", "job_target_catalog", *extra_job_ids)
    runner = _wave3_runner(tmp_path, job_ids, disabled_jobs=disabled_jobs)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "main.c").write_text("int hot(void) { return 1; }\nint main(void) { return hot(); }\n",
                                           encoding="utf-8")
    snapshot = source_fingerprint(target)
    run_id, run_root = RunStore(runner.config.runtime.runs_dir).create(datetime.now(timezone.utc))
    intake_out = runner.run(build_intake(), run_id=run_id, target_root=target, source_fingerprint=snapshot)
    catalog_out = runner.run(
        build_catalog(), run_id=run_id, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"]},
    )
    return runner, run_id, run_root, target, snapshot, catalog_out


def _recorded_catalog_run(tmp_path: Path, extra_job_ids: tuple[str, ...], *,
                          disabled_jobs: tuple[str, ...] = ()):
    job_ids = ("job_target_catalog", *extra_job_ids)
    runner = _wave3_runner(tmp_path, job_ids, disabled_jobs=disabled_jobs)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    main_c = target / "src" / "main.c"
    main_c.write_text("int hot(void) { return 1; }\nint main(void) { return hot(); }\n", encoding="utf-8")
    snapshot = source_fingerprint(target)
    run_id, run_root = RunStore(runner.config.runtime.runs_dir).create(datetime.now(timezone.utc))
    builtin_cat = builtin_registry().build("job_target_catalog")

    def publish_catalog(unit) -> dict[str, Any]:
        cat_dir = unit.job.attempt_root / "artifacts" / "catalog"
        partition_path = cat_dir / "partition.json"
        atomic_json(partition_path, {"files": [{"path": "src/main.c", "sha256": file_sha256(main_c)}]})
        manifest_path = run_root / "data" / "indices" / "manifests" / "catalog-fixture.json"
        write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=[])
        catalog_path = cat_dir / "target-catalog.json"
        atomic_json(catalog_path, {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": snapshot,
            "artifacts": {"repository_discovery.partition_repository": artifact_ref(run_root, partition_path)},
        })
        cat_ref = artifact_ref(run_root, catalog_path)
        part_ref = artifact_ref(run_root, partition_path)
        mf_ref = artifact_ref(run_root, manifest_path)
        return {
            "artifact": cat_ref,
            "index_manifest": mf_ref,
            "artifacts": [cat_ref, part_ref, mf_ref],
            "gaps": [],
            "terminal_status": "SUCCEEDED",
        }

    cat_job = Job(
        "job_target_catalog", builtin_cat.name, lambda _: {},
        units=(Unit("publish_catalog.publish_handoff", publish_catalog),),
        datasets=tuple(replace(d, required=False) for d in builtin_cat.datasets),
        contract=JobContract(inputs=()),
        schema_identity=builtin_cat.schema_identity, input_identity=lambda _: snapshot,
    )
    catalog_out = runner.run(cat_job, run_id=run_id, target_root=target, source_fingerprint=snapshot)
    return runner, run_id, run_root, target, snapshot, catalog_out


def test_wave3_contract_input_policies_match_confirmed_decisions() -> None:
    registry = builtin_registry()

    bi_contract = registry.build("job_build_iteration").contract
    bi_required = [
        (item.producer, item.output_kind, item.channel)
        for item in bi_contract.inputs
        if item.availability is not Availability.OPTIONAL or item.missing is not MissingPolicy.GAP
    ]
    assert bi_required == [
        ("job_project_build", "handoff", InputChannel.HANDOFF),
        ("build_controller", "iteration_request", InputChannel.TRANSACTION),
    ]
    for item in bi_contract.inputs:
        if (item.producer, item.output_kind) in {
            ("job_project_build", "handoff"),
            ("build_controller", "iteration_request"),
        }:
            assert item.availability is Availability.REQUIRED and item.missing is MissingPolicy.REJECT

    cc_contract = registry.build("job_change_context_analysis").contract
    cc_non_optional = {
        (item.producer, item.output_kind): (item.availability, item.missing)
        for item in cc_contract.inputs
        if item.availability is not Availability.OPTIONAL or item.missing is not MissingPolicy.GAP
    }
    assert cc_non_optional == {
        ("job_target_catalog", "handoff"): (Availability.REQUIRED, MissingPolicy.REJECT),
        ("job_source_history_analysis", "handoff"): (Availability.WHEN_ENABLED, MissingPolicy.REJECT),
    }

    for job_id in ("job_test_coverage", "job_profile_data"):
        contract = registry.build(job_id).contract
        non_optional = {
            (item.producer, item.output_kind): (item.availability, item.missing)
            for item in contract.inputs
            if item.availability is not Availability.OPTIONAL or item.missing is not MissingPolicy.GAP
        }
        assert non_optional == {
            ("job_target_catalog", "handoff"): (Availability.REQUIRED, MissingPolicy.REJECT),
            ("job_language_build", "handoff"): (Availability.WHEN_ENABLED, MissingPolicy.REJECT),
            ("job_artifact_indexing", "handoff"): (Availability.WHEN_ENABLED, MissingPolicy.REJECT),
        }


def test_wave3_admission_rejects_missing_required_and_enabled_conditional_handoffs(tmp_path: Path) -> None:
    runner, run_id, _run_root, target, snapshot, catalog_out = _recorded_catalog_run(
        tmp_path / "all_enabled",
        (
            "job_project_build", "job_build_iteration",
            "job_source_history_analysis", "job_change_context_analysis",
            "job_language_build", "job_artifact_indexing",
            "job_test_coverage", "job_profile_data",
        ),
    )
    catalog_sha = catalog_out["handoff_sha256"]

    with pytest.raises(ValueError, match="required input unavailable: job_project_build/handoff"):
        runner.begin_attempt(
            build_iteration(), run_id=run_id, target_root=target, source_fingerprint=snapshot,
            upstream_handoffs={},
        )

    for job in (build_change_context(), build_test_coverage(), build_profile_data()):
        with pytest.raises(ValueError, match="required input unavailable: job_target_catalog/handoff"):
            runner.begin_attempt(job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
                                 upstream_handoffs={})

    with pytest.raises(ValueError, match="required input unavailable: job_source_history_analysis/handoff"):
        runner.begin_attempt(
            build_change_context(), run_id=run_id, target_root=target, source_fingerprint=snapshot,
            upstream_handoffs={"job_target_catalog": catalog_sha},
        )

    for job in (build_test_coverage(), build_profile_data()):
        with pytest.raises(ValueError, match="required input unavailable: job_language_build/handoff"):
            runner.begin_attempt(
                job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
                upstream_handoffs={"job_target_catalog": catalog_sha},
            )


def test_wave3_admission_rejects_missing_artifact_indexing_when_language_build_disabled(tmp_path: Path) -> None:
    ai_only_runner, ai_run_id, _ai_root, ai_target, ai_snap, ai_catalog = _recorded_catalog_run(
        tmp_path / "artifact_enabled",
        ("job_artifact_indexing", "job_test_coverage", "job_profile_data"),
        disabled_jobs=("job_language_build",),
    )
    for job in (build_test_coverage(), build_profile_data()):
        with pytest.raises(ValueError, match="required input unavailable: job_artifact_indexing/handoff"):
            ai_only_runner.begin_attempt(
                job, run_id=ai_run_id, target_root=ai_target, source_fingerprint=ai_snap,
                upstream_handoffs={"job_target_catalog": ai_catalog["handoff_sha256"]},
            )


def test_change_context_analysis_publishes_unavailable_handoff_when_source_history_disabled(
    tmp_path: Path,
) -> None:
    runner, run_id, run_root, target, snapshot, catalog_out = _seed_catalog_run(
        tmp_path, ("job_change_context_analysis",),
        disabled_jobs=("job_source_history_analysis",),
    )
    cc_job = build_change_context()
    out = runner.run(
        cc_job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_target_catalog": catalog_out["handoff_sha256"]},
    )
    claim = json.loads((Path(out["attempt_root"]) / "claim.json").read_text(encoding="utf-8"))
    by_key = {(row["producer"], row["output_kind"]): row for row in claim["input_admission"]["requirements"]}
    assert by_key[("job_target_catalog", "handoff")]["status"] == "supplied"
    assert by_key[("job_source_history_analysis", "handoff")]["status"] == "gap"

    loaded = out["result"]["outputs"]["load.accepted_history"]
    assert loaded["available"] is False
    assert loaded["reason"] == "source_history_unavailable"
    assert loaded["terminal_status"] == "SKIPPED_NA"

    published = out["result"]["outputs"]["publish.publish_handoff"]
    assert published["terminal_status"] == "SKIPPED_NA"
    assert "git_history_unavailable:source_history_unavailable" in published["gaps"]
    cc_doc = json.loads((run_root / published["artifact"]["path"]).read_text(encoding="utf-8"))
    assert cc_doc["history_handoff_sha256"] is None
    assert cc_doc["history_identity"] is None
    manifest_ref = published["index_manifest"]
    manifest, _ = load_verified_manifest(run_root, run_root / manifest_ref["path"], manifest_ref["sha256"])
    assert any(item["producer"]["job"] == "job_change_context_analysis" for item in manifest["indexes"])

    all_jobs = (build_intake(), build_catalog(), cc_job)
    accepted_by_job = {item.job_id: accepted_handoff(run_root, item.job_id) for item in all_jobs}
    shards_by_key = {
        shard_key(shard): shard
        for acc in accepted_by_job.values()
        if acc is not None
        for mf in handoff_manifests(run_root, acc.handoff)
        for shard in mf["document"].get("indexes", ())
    }
    statuses = {
        "job_review_intake": {},
        "job_target_catalog": {
            key: val.get("terminal_status", "SUCCEEDED")
            if isinstance(val, dict) else "SUCCEEDED"
            for key, val in catalog_out["result"]["outputs"].items()
        },
        cc_job.job_id: {
            key: val.get("terminal_status", "SUCCEEDED")
            if isinstance(val, dict) else "SUCCEEDED"
            for key, val in out["result"]["outputs"].items()
        },
    }
    inventory = build_inventory(InventoryInputs(
        run_root, run_id, snapshot,
        {item.job_id: tuple(runner.config.job(item.job_id).steps) for item in all_jobs},
        {item.job_id: item.datasets for item in all_jobs}, {},
        accepted_by_job, statuses, list(shards_by_key.values()),
    ))
    assert inventory["audit"]["status"] == "PASSED", inventory["audit"]["violations"]


@pytest.mark.parametrize("consumer", ("coverage", "profile"))
def test_coverage_and_profile_publish_unavailable_gaps_when_build_and_artifact_indexing_disabled(
    tmp_path: Path, consumer: str,
) -> None:
    job = build_test_coverage() if consumer == "coverage" else build_profile_data()
    loader = load_accepted_test_coverage if consumer == "coverage" else load_accepted_profile_data
    runner, run_id, run_root, target, snapshot, catalog_out = _recorded_catalog_run(
        tmp_path, (job.job_id,),
        disabled_jobs=("job_language_build", "job_artifact_indexing"),
    )
    catalog_sha = catalog_out["handoff_sha256"]

    out = runner.run(
        job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_target_catalog": catalog_sha},
    )
    assert out["result"]["outputs"]["acceptance.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"

    with validation_scope(run_root):
        doc = loader(run_root)

    expected_gaps = [
        "language_build_unavailable: job_language_build producer disabled",
        "artifact_indexing_unavailable: job_artifact_indexing producer disabled",
    ]
    assert doc["gaps"] == expected_gaps
    assert doc["upstream_handoff_sha256"] == {"job_target_catalog": catalog_sha}
    assert doc["build_units"] == []


@pytest.mark.parametrize("consumer", ("coverage", "profile"))
def test_coverage_and_profile_ingest_language_receipts_when_only_artifact_indexing_disabled(
    tmp_path: Path, consumer: str,
) -> None:
    job = build_test_coverage() if consumer == "coverage" else build_profile_data()
    runner, run_id, run_root, target, snapshot, catalog_out = _recorded_catalog_run(
        tmp_path, ("job_language_build", job.job_id),
        disabled_jobs=("job_artifact_indexing",),
    )
    catalog_sha = catalog_out["handoff_sha256"]

    lcov_path = run_root / "data" / "build" / "u1" / "coverage" / "lcov.info"
    lcov_path.parent.mkdir(parents=True, exist_ok=True)
    lcov_path.write_bytes(b"SF:src/main.c\nDA:1,1\nDA:2,0\nend_of_record\n")
    folded_path = run_root / "data" / "build" / "u1" / "profiles" / "hot.folded"
    folded_path.parent.mkdir(parents=True, exist_ok=True)
    folded_path.write_bytes(b"main;hot 9\nmain;cold 1\n")

    lang_manifest = run_root / "data" / "indices" / "manifests" / "language-fixture.json"
    write_manifest(lang_manifest, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=[])
    seeds = run_root / "data" / "inputs" / "artifact-fixture"
    atomic_json(seeds / "job_language_build.json", {
        "document": {
            "schema": "appsec-review/language-build-handoff/2",
            "source_fingerprint": snapshot,
            "upstream_project_build_handoff_sha256": "c" * 64,
            "gaps": [],
            "receipts": [{
                "build_unit_id": "build-unit-u1",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "fingerprint": "d" * 64,
                "executor_identity": "fixture",
                "capture_identity": "fixture",
                "artifacts": [
                    {
                        "path": lcov_path.relative_to(run_root).as_posix(),
                        "workspace_path": "coverage/lcov.info",
                        "sha256": file_sha256(lcov_path),
                        "size_bytes": lcov_path.stat().st_size,
                        "kind": "test-coverage",
                        "artifact_origin": "build-output",
                    },
                    {
                        "path": folded_path.relative_to(run_root).as_posix(),
                        "workspace_path": "profiles/hot.folded",
                        "sha256": file_sha256(folded_path),
                        "size_bytes": folded_path.stat().st_size,
                        "kind": "execution-profile",
                        "artifact_origin": "build-output",
                    },
                ],
            }],
        },
        "manifest": {"path": lang_manifest.relative_to(run_root).as_posix(),
                     "sha256": file_sha256(lang_manifest)},
    })
    lang_out = runner.run(recorded_job(run_root, "job_language_build"), run_id=run_id,
                          target_root=target, source_fingerprint=snapshot)
    supplied = {"job_target_catalog": catalog_sha, "job_language_build": lang_out["handoff_sha256"]}

    runner.run(job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
               upstream_handoffs=supplied)

    with validation_scope(run_root):
        if consumer == "coverage":
            cov_doc = load_accepted_test_coverage(run_root)
            assert cov_doc["totals"]["lines_total"] == 2 and cov_doc["totals"]["lines_covered"] == 1
            assert "artifact_indexing_unavailable: job_artifact_indexing producer disabled" in cov_doc["gaps"]
            assert not any("language_build_unavailable" in gap for gap in cov_doc["gaps"])
        else:
            prof_doc = load_accepted_profile_data(run_root)
            assert len(prof_doc["build_units"]) == 1 and len(prof_doc["build_units"][0]["rows"]) == 3
            assert "artifact_indexing_unavailable: job_artifact_indexing producer disabled" in prof_doc["gaps"]
            assert not any("language_build_unavailable" in gap for gap in prof_doc["gaps"])


def test_language_build_enabled_setting_rejects_non_boolean(tmp_path: Path) -> None:
    runner = _wave3_runner(tmp_path, ("job_language_build",), disabled_jobs=("job_language_build",))
    assert runner.config.job("job_language_build").settings["enabled"] is False
    bad_toml = tmp_path / "repo" / "appsec-review.toml"
    bad_toml.write_text(
        bad_toml.read_text(encoding="utf-8").replace(
            "[jobs.job_language_build.settings]\nenabled = false",
            '[jobs.job_language_build.settings]\nenabled = "no"',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="jobs.job_language_build.settings.enabled must be a boolean"):
        load_config(bad_toml)
