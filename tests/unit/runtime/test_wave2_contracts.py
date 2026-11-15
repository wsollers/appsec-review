"""Real publication, inventory ownership, and B1 schema parity for Wave 2 producer splits."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime import load_catalog
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.indexing.inventory import InventoryInputs, build_inventory, compile_glob
from appsec_review.indexing.store import accepted_handoff, handoff_manifests, shard_key
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_security_analysis import build_job as build_asa
from appsec_review.jobs.job_artifact_security_analysis.datasets import DATASETS as ASA_DATASETS
from appsec_review.jobs.job_artifact_security_analysis.scanners import ADAPTERS
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job as build_tree_sitter
from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS as TS_DATASETS
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.index import INDEX_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.datasets import read_dataset_contract, validate_declarations
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import RunStore, atomic_json, file_sha256
from tests.artifact_input_support import recorded_job
from tests.container_fixture import copy_containers
from tests.release_support import declare_releases, write_release


ROOT = Path(__file__).resolve().parents[3]
ASA_SCHEMA = "appsec-review/artifact-security-analysis/1"
ASA_OBSERVATION_SCHEMA = "appsec-review/artifact-security-observation/1"
TS_SCHEMA = "appsec-review/tree-sitter-ast/1"
_TS_IMAGE_ID = load_catalog(ROOT).tool("tool-tree-sitter").expected_image_id
_TS_LOCK = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text(encoding="utf-8"))
_BASE_DECLARED_TOML = declare_releases(
    (ROOT / "appsec-review.toml").read_text(encoding="utf-8"),
    **{key: "fixture/1" for key in ("platform", "validation", *(adapter.tool_id for adapter in ADAPTERS.values()))},
)


def owners(datasets, relative: str):
    return [item for item in datasets
            if any(compile_glob(pattern).fullmatch(relative) for pattern in item.artifacts)]


def configured_runner(tmp_path: Path, job_ids: tuple[str, ...], *, extra_jobs: tuple[Any, ...] = (),
                      disabled_jobs: tuple[str, ...] = ()) -> JobRunner:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    if not (root / "containers").exists():
        copy_containers(ROOT, root)
    if not (root / "rules").exists():
        (root / "rules").mkdir(parents=True, exist_ok=True)
        (root / "rules" / "semgrep").symlink_to(ROOT / "rules" / "semgrep")
    text = _BASE_DECLARED_TOML
    for disabled_id in disabled_jobs:
        header = f"[jobs.{disabled_id}.settings]\n"
        if header not in text:
            raise AssertionError(f"missing settings header for {disabled_id}")
        text = text.replace(header, f"{header}enabled = false\n", 1)
    for extra in extra_jobs:
        if f"[jobs.{extra.job_id}]" not in text:
            text += f'\n[jobs.{extra.job_id}]\nname="{extra.name}"\nworkers=1\n'
            for unit in extra.units:
                step, task = unit.unit_id.split(".")
                text += f"[jobs.{extra.job_id}.steps.{step}.tasks.{task}]\nworkers=1\n"
    config_path = root / "appsec-review.toml"
    config_path.write_text(text, encoding="utf-8")
    all_ids = tuple(dict.fromkeys([*job_ids, *(extra.job_id for extra in extra_jobs)]))
    write_release(root, all_ids)
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


def run_asa_publication(tmp_path: Path, *, datasets_override=None, extra_jobs: tuple[Any, ...] = (),
                        extra_job_ids: tuple[str, ...] = ()):
    job_ids = ("job_language_build", "job_artifact_indexing", "job_artifact_security_analysis", *extra_job_ids)
    runner = configured_runner(tmp_path, job_ids, extra_jobs=extra_jobs)
    run_id, run_root = RunStore(runner.config.runtime.runs_dir).create(datetime.now(timezone.utc))
    target = tmp_path / "target"
    target.mkdir(parents=True, exist_ok=True)
    snapshot = "a" * 64
    wasm = run_root / "data" / "build" / "wasm" / "module.wasm"
    wasm.parent.mkdir(parents=True, exist_ok=True)
    wasm.write_bytes(b"\0asm\x01\0\0\0")
    artifact = {
        "path": wasm.relative_to(run_root).as_posix(), "workspace_path": "build/module.wasm",
        "sha256": file_sha256(wasm), "size_bytes": wasm.stat().st_size, "kind": "wasm-module",
        "build_unit_id": "build-unit-fixture", "mapping": "exact-workspace-path", "mapping_confidence": 1.0,
    }
    index_path = run_root / "data" / "indices" / "artifacts" / "catalog-fixture.sqlite"
    index_sha = IndexBuilder(index_path, name="artifacts", fingerprint="b" * 64,
                             target_snapshot=snapshot, shard_id="catalog-fixture").build()
    index_identity = IndexIdentity(
        "artifacts", INDEX_SCHEMA, index_sha, "b" * 64, index_path.relative_to(run_root).as_posix(),
        {"job": "job_artifact_indexing", "unit": "index.fixture"}, (), "catalog-fixture",
    )
    manifest_path = run_root / "data" / "indices" / "manifests" / "artifact-fixture.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target,
                   indexes=[index_identity])
    manifest = {"path": manifest_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
    lang_manifest = manifest_path.with_name("language-fixture.json")
    write_manifest(lang_manifest, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=[])
    seeds = run_root / "data/inputs/artifact-fixture"
    atomic_json(seeds / "job_language_build.json", {
        "document": {"schema": "appsec-review/language-build-handoff/2", "source_fingerprint": snapshot,
                     "upstream_project_build_handoff_sha256": "c" * 64, "gaps": [],
                     "receipts": [{"build_unit_id": "build-unit-fixture", "family": "wasm",
                                   "fingerprint": "d" * 64, "executor_identity": "fixture",
                                   "capture_identity": "fixture", "artifacts": [artifact]}]},
        "manifest": {"path": lang_manifest.relative_to(run_root).as_posix(),
                     "sha256": file_sha256(lang_manifest)},
    })
    atomic_json(seeds / "job_artifact_indexing.json", {
        "document": {"schema": "appsec-review/artifact-indexing/1", "source_fingerprint": snapshot,
                     "artifact_shard_count": 1, "reused_shard_count": 0, "artifact_count": 1,
                     "gaps": [], "index_manifest": manifest},
        "manifest": manifest,
    })
    lang_out = runner.run(recorded_job(run_root, "job_language_build"), run_id=run_id,
                          target_root=target, source_fingerprint=snapshot)
    idx_out = runner.run(recorded_job(run_root, "job_artifact_indexing"), run_id=run_id,
                         target_root=target, source_fingerprint=snapshot,
                         upstream_handoffs={"job_language_build": lang_out["handoff_sha256"]})

    def scanner(capability, _path, _artifact, _timeout, _limit):
        return {"stdout": b"", "stderr": b"", "exit_code": 0, "observation": {},
                "tool_identity": {"scanner": capability, "image": "fixture", "rules": "fixture"}}

    job = build_asa(scanner_runner=scanner)
    if datasets_override is not None:
        job = replace(job, datasets=datasets_override)
    asa_out = runner.run(
        job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_language_build": lang_out["handoff_sha256"],
                           "job_artifact_indexing": idx_out["handoff_sha256"]},
    )
    return runner, run_root, target, snapshot, job, asa_out


class FakeTreeSitterExecutor:
    def __init__(self, fail_languages: frozenset[str] = frozenset()) -> None:
        self.fail_languages = fail_languages
        self.image_id = _TS_IMAGE_ID
        self.lock = _TS_LOCK

    def resolve_image(self, _tool) -> str:
        return self.image_id

    def execute(self, request) -> ExecutionResult:
        payload = json.loads((request.scratch_root / "request.json").read_text(encoding="utf-8"))
        now = "2026-10-10T00:00:00+00:00"
        if payload["language"] in self.fail_languages:
            return ExecutionResult(
                "appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
                self.image_id, self.image_id, "fake", (), {}, now, now, 2, False, False, False, False,
                "", "", "",
            )
        grammar_by_lang = {item["language"]: item["grammar"] for item in self.lock["grammars"]}
        records: list[dict[str, Any]] = []
        for item in payload["files"]:
            source = (request.target_root / item["path"]).read_bytes()
            lines = source.splitlines()
            end_col = len(lines[-1]) if lines else 0
            nodes = [
                {"ordinal_path": [], "field": None, "type": "program", "named": True,
                 "error": False, "missing": False, "extra": False, "has_error": False,
                 "start_byte": 0, "end_byte": len(source), "start_point": [0, 0],
                 "end_point": [max(0, len(lines) - 1), end_col]},
                {"ordinal_path": [0], "field": None, "type": "function_declaration", "named": True,
                 "error": False, "missing": False, "extra": False, "has_error": False,
                 "start_byte": 0, "end_byte": len(source), "start_point": [0, 0],
                 "end_point": [max(0, len(lines) - 1), end_col]},
                {"ordinal_path": [0, 0], "field": "name", "type": "identifier", "named": True,
                 "error": False, "missing": False, "extra": False, "has_error": False,
                 "start_byte": 9, "end_byte": 14, "start_point": [0, 9],
                 "end_point": [0, 14]},
            ]
            records.append({
                "kind": "file", "path": item["path"], "status": "SUCCEEDED", "sha256": item["sha256"],
                "bytes": len(source), "grammar": grammar_by_lang[payload["language"]],
                "root_has_error": False, "node_count": len(nodes), "truncated": False, "nodes": nodes,
            })
        output = {
            "schema": "appsec-review/tree-sitter-container-output/1",
            "tool": {"id": "tool-tree-sitter", "version": self.lock["tool_version"],
                     "tree_sitter": self.lock["tree_sitter"]["version"],
                     "language_pack": self.lock["language_pack"]["version"],
                     "normalizer_schema": self.lock["normalizer_schema"], "architecture": "x86_64"},
            "scope_id": payload["scope_id"], "language": payload["language"], "records": records,
        }
        (request.scratch_root / "output.json").write_text(json.dumps(output), encoding="utf-8")
        return ExecutionResult(
            "appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
            self.image_id, self.image_id, "fake", (), {}, now, now, 0, False, False, False, False,
            "", "", "",
        )


def _fast_intake_and_catalog(runner: JobRunner, target: Path, snapshot: str):
    real_intake = build_intake()
    real_catalog = build_catalog()

    def publish_intake(unit) -> dict[str, Any]:
        doc_path = unit.unit_root / "review-intake.json"
        atomic_json(doc_path, {"schema": "appsec-review/review-intake/1", "fingerprint": {"sha256": snapshot}})
        ref = {"path": doc_path.relative_to(unit.job.run_root).as_posix(),
               "sha256": file_sha256(doc_path), "size_bytes": doc_path.stat().st_size}
        return {"schema": "appsec-review/review-intake/1", "artifact": ref, "artifacts": [ref],
                "gaps": [], "terminal_status": "SUCCEEDED"}

    intake_units = (Unit("publish_intake.publish_handoff", publish_intake),)
    intake = Job(
        "job_review_intake", real_intake.name, UnitExecutor(intake_units).execute,
        units=intake_units,
        datasets=tuple(replace(d, required=False) for d in real_intake.datasets),
        contract=real_intake.contract,
        schema_identity=real_intake.schema_identity,
        input_identity=lambda _: snapshot,
    )
    intake_out = runner.run(intake, target_root=target, source_fingerprint=snapshot)
    run_id = intake_out["status"]["run_id"]
    run_root = runner.runs.resolve(run_id)

    def publish_catalog(unit) -> dict[str, Any]:
        art_dir = unit.job.attempt_root / "artifacts" / "catalog"
        files = []
        for path in sorted(p for p in target.rglob("*") if p.is_file()):
            rel = path.relative_to(target).as_posix()
            lang = "Ruby" if path.suffix == ".rb" else "JavaScript"
            files.append({
                "path": rel, "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                "language": lang, "generated": False, "delivery_role": "production",
                "first_party": True, "vendored": False,
            })
        part_path = art_dir / "partition.json"
        comp_path = art_dir / "components.json"
        build_path = art_dir / "build-targets.json"
        atomic_json(part_path, {"files": files, "gaps": []})
        atomic_json(comp_path, {"components": [{"component_id": "comp:root", "root": "."}]})
        atomic_json(build_path, {"targets": []})
        manifest_path = run_root / "data" / "indices" / "manifests" / "catalog-fast.json"
        write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=[])

        def ref(p: Path) -> dict[str, Any]:
            return {"path": p.relative_to(run_root).as_posix(), "sha256": file_sha256(p), "size_bytes": p.stat().st_size}

        part_ref, comp_ref, build_ref, mf_ref = ref(part_path), ref(comp_path), ref(build_path), ref(manifest_path)
        cat_path = art_dir / "target-catalog.json"
        atomic_json(cat_path, {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": snapshot,
            "artifacts": {
                "repository_discovery.partition_repository": part_ref,
                "component_discovery.catalog_components": comp_ref,
                "build_discovery.catalog_build_targets": build_ref,
            },
        })
        cat_ref = ref(cat_path)
        return {
            "schema": "appsec-review/target-catalog/1",
            "artifact": cat_ref,
            "index_manifest": mf_ref,
            "artifacts": [cat_ref, part_ref, comp_ref, build_ref, mf_ref],
            "gaps": [],
            "terminal_status": "SUCCEEDED",
        }

    cat_units = (Unit("publish_catalog.publish_handoff", publish_catalog),)
    catalog = Job(
        "job_target_catalog", real_catalog.name, UnitExecutor(cat_units).execute,
        units=cat_units,
        datasets=tuple(replace(d, required=False) for d in real_catalog.datasets),
        contract=real_catalog.contract,
        schema_identity=real_catalog.schema_identity,
        input_identity=lambda _: snapshot,
    )
    catalog_out = runner.run(catalog, run_id=run_id, target_root=target, source_fingerprint=snapshot,
                             upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"]})
    return run_id, run_root, intake_out, catalog_out


def run_tree_sitter_publication(tmp_path: Path, *, fail_languages: frozenset[str] = frozenset(),
                                datasets_override=None, extra_jobs: tuple[Any, ...] = (),
                                extra_job_ids: tuple[str, ...] = (),
                                disabled_jobs: tuple[str, ...] = (),
                                recorded_upstream: bool = True):
    job_ids = ("job_review_intake", "job_target_catalog", "job_tree_sitter_ast", *extra_job_ids)
    runner = configured_runner(tmp_path, job_ids, extra_jobs=extra_jobs, disabled_jobs=disabled_jobs)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True, exist_ok=True)
    (target / "src" / "app.js").write_text("function check(x) {\n  return x + 1;\n}\n", encoding="utf-8")
    if "Ruby" in fail_languages:
        (target / "web").mkdir(parents=True, exist_ok=True)
        (target / "web" / "broken.rb").write_text("def bad\n  1\nend\n", encoding="utf-8")
    snapshot = source_fingerprint(target)
    if recorded_upstream:
        run_id, run_root, intake_out, catalog_out = _fast_intake_and_catalog(runner, target, snapshot)
    else:
        intake = build_intake()
        catalog = build_catalog()
        intake_out = runner.run(intake, target_root=target, source_fingerprint=snapshot)
        run_id = intake_out["status"]["run_id"]
        run_root = runner.runs.resolve(run_id)
        catalog_out = runner.run(catalog, run_id=run_id, target_root=target, source_fingerprint=snapshot,
                                 upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"]})
    ts_job = build_tree_sitter(executor_factory=lambda _unit: FakeTreeSitterExecutor(fail_languages))
    if datasets_override is not None:
        ts_job = replace(ts_job, datasets=datasets_override)
    ts_out = runner.run(
        ts_job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
        upstream_handoffs={"job_review_intake": intake_out["handoff_sha256"],
                           "job_target_catalog": catalog_out["handoff_sha256"]},
    )
    return runner, run_root, target, snapshot, ts_job, intake_out, catalog_out, ts_out


def test_artifact_security_declarations_and_real_publication_ownership(tmp_path: Path) -> None:
    validate_declarations("job_artifact_security_analysis", ASA_DATASETS)
    declared = {item.output_kind: item for item in ASA_DATASETS}
    assert set(declared) == {
        "artifact_security_observations", "artifact_security_results",
        "artifact_security_acceptance", "artifact_scanner_io",
    }
    assert declared["artifact_security_results"].schema == ASA_OBSERVATION_SCHEMA
    assert declared["artifact_security_results"].artifacts == ("data/artifact-security/shards/*/*/result.json",)
    assert declared["artifact_security_acceptance"].schema == ASA_SCHEMA
    assert declared["artifact_security_acceptance"].step == "acceptance"

    runner, run_root, target, snapshot, job, asa_out = run_asa_publication(tmp_path)
    shards = sorted(run_root.glob("data/artifact-security/shards/*/*/result.json"))
    assert shards, "expected real per-shard observation JSON"
    for shard in shards:
        rel = shard.relative_to(run_root).as_posix()
        assert owners(job.datasets, rel) == [declared["artifact_security_results"]]
        assert json.loads(shard.read_text(encoding="utf-8"))["schema"] == ASA_OBSERVATION_SCHEMA

    accepted_ref = asa_out["result"]["outputs"]["acceptance.publish_handoff"]["artifact"]
    assert owners(job.datasets, accepted_ref["path"]) == [declared["artifact_security_acceptance"]]
    accepted_doc = json.loads((run_root / accepted_ref["path"]).read_text(encoding="utf-8"))
    assert accepted_doc["schema"] == ASA_SCHEMA

    claim = json.loads((Path(asa_out["attempt_root"]) / "claim.json").read_text(encoding="utf-8"))
    assert read_dataset_contract(claim["dataset_contract"], job.job_id)[1] == job.datasets

    from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as IDX_DATASETS
    from appsec_review.jobs.job_language_build.datasets import DATASETS as LANG_DATASETS

    all_datasets = {
        "job_language_build": LANG_DATASETS,
        "job_artifact_indexing": IDX_DATASETS,
        job.job_id: job.datasets,
    }
    all_steps = {jid: tuple(runner.config.job(jid).steps) for jid in all_datasets}
    all_accepted = {jid: accepted_handoff(run_root, jid) for jid in all_datasets}
    all_statuses = {
        "job_language_build": {},
        "job_artifact_indexing": {},
        job.job_id: {
            key: val.get("terminal_status", "SUCCEEDED")
            for key, val in asa_out["result"]["outputs"].items()
        },
    }
    inventory = build_inventory(InventoryInputs(
        run_root, run_root.name, snapshot, all_steps, all_datasets, {}, all_accepted, all_statuses, (),
    ))
    unsatisfied = [v for v in inventory["audit"]["violations"]
                   if not str(v.get("subject", "")).startswith("data/inputs/")
                   and not (v.get("job_id") in {"job_language_build", "job_artifact_indexing"}
                            and v.get("code") == "missing_required_dataset")]
    assert unsatisfied == []
    rows = {row["output_kind"]: row for row in inventory["rows"] if row["job_id"] == job.job_id}
    assert {"artifact_security_results", "artifact_security_acceptance"} <= rows.keys()
    assert rows["artifact_security_results"]["disposition"] == "artifact_only"
    assert rows["artifact_security_acceptance"]["disposition"] == "artifact_only"

    altered = replace(job, datasets=tuple(item for item in job.datasets
                                          if item.output_kind != "artifact_security_acceptance"))
    planner = ResumePlanner(runner.config, run_root, (altered,), snapshot, target_root=target)
    reasons, _ = planner.accepted(altered, asa_out["handoff"]["upstream_handoff_sha256"])
    assert "dataset contract identity changed" in reasons


def test_tree_sitter_declarations_failed_scope_schema_and_inventory_ownership(tmp_path: Path) -> None:
    validate_declarations("job_tree_sitter_ast", TS_DATASETS)
    declared = {item.output_kind: item for item in TS_DATASETS}
    assert set(declared) == {
        "tree_sitter_ast", "tree_sitter_coverage", "tree_sitter_node_shards",
        "tree_sitter_scope_results", "tree_sitter_acceptance",
        "generated_source_backing", "tree_sitter_tool_io",
    }
    assert declared["tree_sitter_node_shards"].schema == NORMALIZER_SCHEMA
    assert declared["tree_sitter_node_shards"].artifacts == ("data/treesitter/shards/*.jsonl",)
    assert declared["tree_sitter_scope_results"].schema == TS_SCHEMA
    assert declared["tree_sitter_acceptance"].schema == TS_SCHEMA
    assert declared["tree_sitter_acceptance"].step == "acceptance"

    runner, run_root, target, snapshot, ts_job, intake_out, catalog_out, ts_out = run_tree_sitter_publication(
        tmp_path, fail_languages=frozenset({"Ruby"}),
    )
    jsonl_shards = sorted(run_root.glob("data/treesitter/shards/*.jsonl"))
    assert len(jsonl_shards) == 1
    for shard in jsonl_shards:
        rel = shard.relative_to(run_root).as_posix()
        assert owners(ts_job.datasets, rel) == [declared["tree_sitter_node_shards"]]
        rows = [json.loads(line) for line in shard.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert rows and all(row["schema"] == NORMALIZER_SCHEMA for row in rows)

    scope_meta = sorted(run_root.glob("data/treesitter/shards/*.json"))
    assert len(scope_meta) == 1, "FAILED scope must not write reusable shard metadata"
    meta_rel = scope_meta[0].relative_to(run_root).as_posix()
    assert owners(ts_job.datasets, meta_rel) == [declared["tree_sitter_scope_results"]]
    assert json.loads(scope_meta[0].read_text(encoding="utf-8"))["schema"] == TS_SCHEMA

    dispositions = ts_out["result"]["outputs"]["parse.dynamic_scopes"]["dispositions"]
    assert len(dispositions) == 2
    dynamic_root = Path(ts_out["attempt_root"]) / "steps/parse/tasks/dynamic_scopes/dynamic"
    dynamic_root.mkdir(parents=True, exist_ok=True)
    for disp in dispositions:
        atomic_json(dynamic_root / f"{disp['scope_id']}.json", disp)
    dynamic_files = sorted(dynamic_root.glob("*.json"))
    assert len(dynamic_files) == 2
    by_status: dict[str, dict[str, Any]] = {}
    for dyn in dynamic_files:
        rel = dyn.relative_to(run_root).as_posix()
        assert owners(ts_job.datasets, rel) == [declared["tree_sitter_scope_results"]]
        doc = json.loads(dyn.read_text(encoding="utf-8"))
        assert doc["schema"] == TS_SCHEMA
        by_status[doc["terminal_status"]] = doc
    assert set(by_status) == {"SUCCEEDED", "FAILED"}
    failed_fp = by_status["FAILED"]["fingerprint"]
    assert not (run_root / "data" / "treesitter" / "shards" / f"{failed_fp}.json").exists()

    accepted_ref = ts_out["result"]["outputs"]["acceptance.publish_handoff"]["artifact"]
    assert owners(ts_job.datasets, accepted_ref["path"]) == [declared["tree_sitter_acceptance"]]
    accepted_doc = json.loads((run_root / accepted_ref["path"]).read_text(encoding="utf-8"))
    assert accepted_doc["schema"] == TS_SCHEMA

    all_jobs = (
        replace(build_intake(), datasets=tuple(replace(d, required=False) for d in build_intake().datasets)),
        replace(build_catalog(), datasets=tuple(replace(d, required=False) for d in build_catalog().datasets)),
        ts_job,
    )
    outs_by_job = {
        "job_review_intake": intake_out,
        "job_target_catalog": catalog_out,
        ts_job.job_id: ts_out,
    }
    statuses = {
        item.job_id: {
            key: val.get("terminal_status", "SUCCEEDED")
            for key, val in outs_by_job[item.job_id]["result"]["outputs"].items()
        }
        for item in all_jobs
    }
    accepted_by_job = {item.job_id: accepted_handoff(run_root, item.job_id) for item in all_jobs}
    shards_by_key = {
        shard_key(shard): shard
        for acc in accepted_by_job.values()
        if acc is not None
        for manifest in handoff_manifests(run_root, acc.handoff)
        for shard in manifest["document"].get("indexes", ())
    }
    inventory = build_inventory(InventoryInputs(
        run_root, run_root.name, snapshot,
        {item.job_id: tuple(runner.config.job(item.job_id).steps) for item in all_jobs},
        {item.job_id: item.datasets for item in all_jobs}, {},
        accepted_by_job, statuses, list(shards_by_key.values()),
    ))
    assert inventory["audit"]["status"] == "PASSED", inventory["audit"]["violations"]
    rows = {row["output_kind"]: row for row in inventory["rows"] if row["job_id"] == ts_job.job_id}
    assert {"tree_sitter_node_shards", "tree_sitter_scope_results", "tree_sitter_acceptance"} <= rows.keys()

    stale = replace(ts_job, datasets=tuple(
        replace(item, schema=TS_SCHEMA) if item.output_kind == "tree_sitter_node_shards" else item
        for item in ts_job.datasets
    ))
    planner = ResumePlanner(runner.config, run_root, (stale,), snapshot, target_root=target)
    reasons, _ = planner.accepted(stale, ts_out["handoff"]["upstream_handoff_sha256"])
    assert "dataset contract identity changed" in reasons
