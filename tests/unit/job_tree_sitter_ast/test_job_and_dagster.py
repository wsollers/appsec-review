"""Unit tests for job.py handlers, isolated JobRunner execution, and dagster.py op adapter."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

from dagster import DagsterRun
import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime import ExecutionResult, load_catalog
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import handoff_manifests
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job as build_tree_sitter
from appsec_review.jobs.job_tree_sitter_ast.dagster import build_dagster_job
from appsec_review.jobs.job_tree_sitter_ast.job import _load_inputs
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.container_fixture import copy_containers
from tests.handoff_fixture import write_fixture_handoff
from tests.release_support import declare_releases, write_release

ROOT = Path(__file__).resolve().parents[3]


class _FakeTreeSitterExecutor:
    def __init__(self, fail_languages: frozenset[str] = frozenset()) -> None:
        self.fail_languages = fail_languages
        self.image_id = load_catalog(ROOT).tool("tool-tree-sitter").expected_image_id
        self.lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text())
        self.calls = 0

    def resolve_image(self, _tool: Any) -> str:
        return self.image_id

    def execute(self, request: Any) -> ExecutionResult:
        self.calls += 1
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
                {
                    "ordinal_path": [], "field": None, "type": "program", "named": True,
                    "error": False, "missing": False, "extra": False, "has_error": False,
                    "start_byte": 0, "end_byte": len(source), "start_point": [0, 0],
                    "end_point": [max(0, len(lines) - 1), end_col],
                },
                {
                    "ordinal_path": [0], "field": None, "type": "function_declaration", "named": True,
                    "error": False, "missing": False, "extra": False, "has_error": False,
                    "start_byte": 0, "end_byte": len(source), "start_point": [0, 0],
                    "end_point": [max(0, len(lines) - 1), end_col],
                },
            ]
            records.append({
                "kind": "file", "path": item["path"], "status": "SUCCEEDED", "sha256": item["sha256"],
                "bytes": len(source), "grammar": grammar_by_lang[payload["language"]],
                "root_has_error": False, "node_count": len(nodes), "truncated": False, "nodes": nodes,
            })
        output = {
            "schema": "appsec-review/tree-sitter-container-output/1",
            "tool": {
                "id": "tool-tree-sitter",
                "version": self.lock["tool_version"],
                "tree_sitter": self.lock["tree_sitter"]["version"],
                "language_pack": self.lock["language_pack"]["version"],
                "normalizer_schema": self.lock["normalizer_schema"],
                "architecture": "x86_64",
            },
            "scope_id": payload["scope_id"],
            "language": payload["language"],
            "records": records,
        }
        (request.scratch_root / "output.json").write_text(json.dumps(output), encoding="utf-8")
        return ExecutionResult(
            "appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
            self.image_id, self.image_id, "fake", (), {}, now, now, 0, False, False, False, False,
            "", "", "",
        )


def _configured_runner(tmp_path: Path) -> JobRunner:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    if not (repo / "containers").exists():
        copy_containers(ROOT, repo)
    if not (repo / "rules").exists():
        (repo / "rules").mkdir(parents=True, exist_ok=True)
        (repo / "rules" / "semgrep").symlink_to(ROOT / "rules" / "semgrep")
    text = declare_releases(
        (ROOT / "appsec-review.toml").read_text(encoding="utf-8"),
        platform="fixture/1",
        validation="fixture/1",
    )
    config_path = repo / "appsec-review.toml"
    config_path.write_text(text, encoding="utf-8")
    job_ids = ("job_review_intake", "job_target_catalog", "job_tree_sitter_ast")
    write_release(repo, job_ids)
    base = load_config(config_path)
    config = replace(
        base,
        runtime=replace(
            base.runtime,
            runs_dir=tmp_path / "runs",
            data_dir=tmp_path / "data",
            metadata_dir=tmp_path / "metadata",
        ),
        review_policy=replace(
            base.review_policy,
            releases=ComponentReleases({
                **base.review_policy.releases.values,
                "platform": "fixture/1",
                "validation": "fixture/1",
            }),
        ),
    )
    return JobRunner(config)


def _seed_upstream_run(
    runner: JobRunner,
    target: Path,
    *,
    files: list[dict[str, Any]],
    gaps: list[dict[str, Any]] | None = None,
    build_targets: list[dict[str, Any]] | None = None,
) -> tuple[str, Path, str, dict[str, str]]:
    from datetime import UTC, datetime
    snapshot = source_fingerprint(target)
    run_id, run_root = runner.runs.create(datetime(2026, 10, 10, tzinfo=UTC))
    runner._bind_configuration(run_root)

    def _ref(rel: str, doc: Any) -> dict[str, Any]:
        p = run_root / rel
        atomic_json(p, doc)
        return {"path": rel, "sha256": file_sha256(p), "size_bytes": p.stat().st_size}

    from dataclasses import replace
    from appsec_review.runtime.datasets import dataset_contract

    in_job = build_intake()
    in_base = "data/jobs/job_review_intake/attempts/attempt_0001"
    atomic_json(run_root / f"{in_base}/claim.json", {
        "dataset_contract": dataset_contract(
            in_job.job_id,
            tuple(runner.config.job(in_job.job_id).steps),
            in_job.datasets,
        ),
    })
    in_ref = _ref(
        f"{in_base}/steps/publish_intake/tasks/publish_handoff/review-intake.json",
        {"schema": "appsec-review/review-intake/1", "fingerprint": {"sha256": snapshot}},
    )
    in_h = write_fixture_handoff(
        run_root,
        run_root / f"{in_base}/handoff.json",
        {
            "source_fingerprint": snapshot,
            "status": "ACCEPTED",
            "job_id": "job_review_intake",
            "outputs": {"publish_intake.publish_handoff": {"artifact": in_ref}},
            "artifacts": [in_ref],
        },
    )
    in_sha = file_sha256(in_h)
    _ref("data/jobs/job_review_intake/latest.json", {
        "handoff_path": in_h.relative_to(run_root).as_posix(),
        "handoff_sha256": in_sha,
    })

    cat_job = build_catalog()
    cat_base = "data/jobs/job_target_catalog/attempts/attempt_0001"
    atomic_json(run_root / f"{cat_base}/claim.json", {
        "dataset_contract": dataset_contract(
            cat_job.job_id,
            tuple(runner.config.job(cat_job.job_id).steps),
            tuple(replace(d, required=False) for d in cat_job.datasets),
        ),
    })
    part = _ref(f"{cat_base}/artifacts/catalog/partition.json", {"files": files, "gaps": gaps or []})
    comp = _ref(f"{cat_base}/artifacts/catalog/components.json", {"components": [{"component_id": "component:0001", "root": "."}]})
    blds = _ref(f"{cat_base}/artifacts/catalog/builds.json", {"targets": build_targets or []})
    cat_ref = _ref(f"{cat_base}/artifacts/catalog/catalog.json", {
        "schema": "appsec-review/target-catalog/1",
        "source_fingerprint": snapshot,
        "artifacts": {
            "repository_discovery.partition_repository": part,
            "component_discovery.catalog_components": comp,
            "build_discovery.catalog_build_targets": blds,
        },
    })
    from appsec_review.retrieval.index import write_manifest

    cat_manifest_path = run_root / "data" / "indices" / "manifests" / "catalog-attempt_0001.json"
    write_manifest(
        cat_manifest_path,
        run_id=run_root.name,
        target_snapshot=snapshot,
        target_root=target,
        indexes=[],
        upstream_manifests=(),
    )
    cat_manifest_ref = {
        "path": cat_manifest_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(cat_manifest_path),
        "size_bytes": cat_manifest_path.stat().st_size,
    }
    cat_h = write_fixture_handoff(
        run_root,
        run_root / f"{cat_base}/handoff.json",
        {
            "source_fingerprint": snapshot,
            "status": "ACCEPTED",
            "job_id": "job_target_catalog",
            "outputs": {
                "publish_catalog.publish_handoff": {
                    "artifact": cat_ref,
                    "index_manifest": cat_manifest_ref,
                }
            },
            "artifacts": [cat_ref, part, comp, blds, cat_manifest_ref],
        },
    )
    cat_sha = file_sha256(cat_h)
    _ref("data/jobs/job_target_catalog/latest.json", {
        "handoff_path": cat_h.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_sha,
    })
    _ref("data/indices/accepted.json", {
        "schema": "appsec-review/accepted-index-set/1",
        "run_id": run_root.name,
        "handoff_path": cat_h.relative_to(run_root).as_posix(),
        "handoff_sha256": cat_sha,
        "manifest_path": cat_manifest_ref["path"],
        "manifest_sha256": cat_manifest_ref["sha256"],
    })
    return run_id, run_root, snapshot, {
        "job_review_intake": in_sha,
        "job_target_catalog": cat_sha,
    }


def test_job_runner_end_to_end_handles_swift_policy_exclusions_and_inventory_audit(tmp_path: Path) -> None:
    runner = _configured_runner(tmp_path)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "ios").mkdir(parents=True)
    js_path = target / "src" / "app.js"
    swift_path = target / "ios" / "App.swift"
    js_path.write_text("function check(x) {\n  return x + 1;\n}\n", encoding="utf-8")
    swift_path.write_text("struct App {}\n", encoding="utf-8")

    run_id, run_root, snapshot, upstream = _seed_upstream_run(
        runner,
        target,
        files=[
            {"path": "src/app.js", "sha256": file_sha256(js_path), "size_bytes": js_path.stat().st_size, "language": "JavaScript"},
            {"path": "ios/App.swift", "sha256": file_sha256(swift_path), "size_bytes": swift_path.stat().st_size, "language": "Swift"},
        ],
        gaps=[{"path": "orphan/node_modules", "reason": "excluded_directory"}],
        build_targets=[{"language": "TypeScript", "root": "src"}],
    )

    fake_exec = _FakeTreeSitterExecutor()
    ts_job = build_tree_sitter(executor_factory=lambda _u: fake_exec)  # type: ignore[arg-type]

    # Direct unit handler check: load.accepted_inputs rejects mismatched unit.job.source_fingerprint
    bad_unit = SimpleNamespace(
        job=SimpleNamespace(
            run_root=run_root,
            config=runner.config.job(ts_job.job_id),
            source_fingerprint="f" * 64,
        )
    )
    from appsec_review.runtime.consume import upstream_scope
    with upstream_scope(
        run_root,
        ts_job.job_id,
        upstream,
        contract=ts_job.contract,
    ), pytest.raises(ValueError, match="does not match accepted inputs"):
        ts_job.units[0].handler(bad_unit)  # type: ignore[arg-type]

    ts_out = runner.run(
        ts_job,
        run_id=run_id,
        target_root=target,
        source_fingerprint=snapshot,
        upstream_handoffs=upstream,
    )
    assert ts_out["status"]["status"] in {"SUCCEEDED", "PARTIAL", "COMPLETED_WITH_GAPS"}
    assert fake_exec.calls == 1  # JS parsed; Swift filtered by policy gap
    routed_gaps = {g["scope_id"] for g in ts_out["result"]["outputs"]["plan.route_scopes"]["gaps"]}
    assert "generated-source-lane" in routed_gaps
    assert "catalog-exclusions" in routed_gaps

    from appsec_review.indexing.inventory import shard_key
    from appsec_review.indexing.store import accepted_handoff as load_accepted_handoff
    acc = load_accepted_handoff(run_root, ts_job.job_id)
    assert acc is not None
    shards = [
        shard
        for manifest in handoff_manifests(run_root, acc.handoff)
        for shard in manifest["document"].get("indexes", ())
    ]
    inventory = build_inventory(
        InventoryInputs(
            run_root,
            run_id,
            snapshot,
            {ts_job.job_id: tuple(runner.config.job(ts_job.job_id).steps)},
            {ts_job.job_id: ts_job.datasets},
            {},
            {ts_job.job_id: acc},
            {
                ts_job.job_id: {
                    key: val.get("terminal_status", "SUCCEEDED")
                    for key, val in ts_out["result"]["outputs"].items()
                    if isinstance(val, dict)
                }
            },
            list({shard_key(s): s for s in shards}.values()),
        )
    )
    ts_violations = [
        v for v in inventory["audit"]["violations"]
        if v.get("job_id") == ts_job.job_id
        or str(v.get("subject", "")).startswith(("data/treesitter/", "data/jobs/job_tree_sitter_ast/"))
    ]
    assert ts_violations == []
    rows = {row["output_kind"]: row for row in inventory["rows"] if row["job_id"] == ts_job.job_id}
    assert {"tree_sitter_node_shards", "tree_sitter_scope_results", "tree_sitter_acceptance"} <= rows.keys()


def test_load_inputs_rejects_bad_schemas_snapshot_mismatch_and_generated_collision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.job._accepted_handoff",
        lambda r, j: (
            json.loads((r / json.loads((r / f"data/jobs/{j}/latest.json").read_text())["handoff_path"]).read_text()),
            json.loads((r / f"data/jobs/{j}/latest.json").read_text())["handoff_sha256"],
        ),
    )

    def _ref(run: Path, rel: str, doc: Any) -> dict[str, Any]:
        p = run / rel
        atomic_json(p, doc)
        return {"path": rel, "sha256": file_sha256(p), "size_bytes": p.stat().st_size}

    def _seed(name: str, intake_doc: dict[str, Any], catalog_doc: dict[str, Any]) -> Path:
        run = tmp_path / name
        run.mkdir()
        in_ref = _ref(run, "fixture/intake.json", intake_doc)
        in_out = {"publish_intake.publish_handoff": {"artifact": in_ref}}
        in_h = write_fixture_handoff(run, run / "data/jobs/job_review_intake/attempts/f/handoff.json", {
            "source_fingerprint": "a" * 64, "status": "ACCEPTED", "job_id": "job_review_intake",
            "outputs": in_out, "artifacts": [in_ref],
        })
        _ref(run, "data/jobs/job_review_intake/latest.json", {
            "handoff_path": in_h.relative_to(run).as_posix(), "handoff_sha256": file_sha256(in_h),
        })
        cat_ref = _ref(run, "fixture/catalog.json", catalog_doc)
        cat_out = {"publish_catalog.publish_handoff": {"artifact": cat_ref}}
        cat_h = write_fixture_handoff(run, run / "data/jobs/job_target_catalog/attempts/f/handoff.json", {
            "source_fingerprint": "a" * 64, "status": "ACCEPTED", "job_id": "job_target_catalog",
            "outputs": cat_out, "artifacts": [cat_ref],
        })
        _ref(run, "data/jobs/job_target_catalog/latest.json", {
            "handoff_path": cat_h.relative_to(run).as_posix(), "handoff_sha256": file_sha256(cat_h),
        })
        return run

    run1 = _seed("run-schema", {"schema": "wrong/1"}, {"schema": "appsec-review/target-catalog/1"})
    with pytest.raises(ValueError, match="unsupported schemas"):
        _load_inputs(run1)

    def _seed_with_artifacts(name: str, in_fp: str) -> Path:
        run = tmp_path / name
        run.mkdir()
        part = _ref(run, "fixture/part.json", {"files": [{"path": "a.js", "sha256": "1" * 64}], "gaps": []})
        comp = _ref(run, "fixture/comp.json", {"components": []})
        blds = _ref(run, "fixture/blds.json", {"targets": []})
        in_ref = _ref(run, "fixture/intake.json", {"schema": "appsec-review/review-intake/1", "fingerprint": {"sha256": in_fp}})
        in_out = {"publish_intake.publish_handoff": {"artifact": in_ref}}
        in_h = write_fixture_handoff(run, run / "data/jobs/job_review_intake/attempts/f/handoff.json", {
            "source_fingerprint": "a" * 64, "status": "ACCEPTED", "job_id": "job_review_intake",
            "outputs": in_out, "artifacts": [in_ref],
        })
        _ref(run, "data/jobs/job_review_intake/latest.json", {
            "handoff_path": in_h.relative_to(run).as_posix(), "handoff_sha256": file_sha256(in_h),
        })
        cat_doc = {
            "schema": "appsec-review/target-catalog/1",
            "source_fingerprint": "a" * 64,
            "artifacts": {
                "repository_discovery.partition_repository": part,
                "component_discovery.catalog_components": comp,
                "build_discovery.catalog_build_targets": blds,
            },
        }
        cat_ref = _ref(run, "fixture/catalog.json", cat_doc)
        cat_out = {"publish_catalog.publish_handoff": {"artifact": cat_ref}}
        cat_h = write_fixture_handoff(run, run / "data/jobs/job_target_catalog/attempts/f/handoff.json", {
            "source_fingerprint": "a" * 64, "status": "ACCEPTED", "job_id": "job_target_catalog",
            "outputs": cat_out, "artifacts": [cat_ref, part, comp, blds],
        })
        _ref(run, "data/jobs/job_target_catalog/latest.json", {
            "handoff_path": cat_h.relative_to(run).as_posix(), "handoff_sha256": file_sha256(cat_h),
        })
        return run

    run2 = _seed_with_artifacts("run-fp", "b" * 64)
    with pytest.raises(ValueError, match="identities disagree"):
        _load_inputs(run2)

    run3 = _seed_with_artifacts("run-col", "a" * 64)
    monkeypatch.setattr(
        "appsec_review.jobs.job_tree_sitter_ast.job.load_generated_sources",
        lambda *_a, **_kw: ([{"path": "a.js", "sha256": "2" * 64}], [], None),
    )
    with pytest.raises(ValueError, match="collides with an accepted source"):
        _load_inputs(run3)


def test_dagster_job_ops_drive_dynamic_scope_fanout_and_finalize_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _configured_runner(tmp_path)
    target = runner.config.runtime.repository_root / runner.config.target_acquisition.targets_dir / "fixture-target"
    js_path = target / "src" / "app.js"
    (target / "src").mkdir(parents=True)
    js_path.write_text("function check(x) {\n  return x + 1;\n}\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))

    run_id, _run_root, _snapshot, upstream = _seed_upstream_run(
        runner,
        target,
        files=[{
            "path": "src/app.js",
            "sha256": file_sha256(js_path),
            "size_bytes": js_path.stat().st_size,
            "language": "JavaScript",
        }],
    )

    fake_exec = _FakeTreeSitterExecutor()
    monkeypatch.setattr("appsec_review.jobs.job_tree_sitter_ast.job.ContainerExecutor", lambda *_a, **_kw: fake_exec)
    monkeypatch.setattr("appsec_review.jobs.job_tree_sitter_ast.scope_execution.ContainerExecutor", lambda *_a, **_kw: fake_exec)

    job_def = build_dagster_job(runner.config, runner_factory=lambda _cfg: runner)
    graph = job_def.graph
    dagster_run = DagsterRun(
        job_name=job_def.name,
        tags={
            "appsec/application_run_id": run_id,
            "appsec/upstream_handoffs": json.dumps(upstream),
        },
    )

    def _ctx(node_name: str) -> SimpleNamespace:
        op_def = graph.node_named(node_name).definition
        return SimpleNamespace(
            dagster_run=dagster_run,
            run_id="dagster-run-1",
            op=op_def,
            instance=SimpleNamespace(add_run_tags=Mock()),
            add_output_metadata=Mock(),
        )

    begin_ctx = _ctx("standalone__tree_sitter_ast__begin")
    claim = begin_ctx.op.compute_fn.decorated_fn(begin_ctx)
    assert claim["run_id"] == run_id
    begin_ctx.instance.add_run_tags.assert_called_once()

    load_ctx = _ctx("standalone__tree_sitter_ast__load__accepted_inputs")
    loaded = load_ctx.op.compute_fn.decorated_fn(load_ctx, claim)
    assert loaded["image_id"] == fake_exec.image_id

    route_ctx = _ctx("standalone__tree_sitter_ast__plan__route_scopes")
    dyn_scopes = list(route_ctx.op.compute_fn.decorated_fn(route_ctx, claim, loaded))
    assert len(dyn_scopes) == 1

    parse_ctx = _ctx("standalone__tree_sitter_ast__parse__scope")
    scope_res = parse_ctx.op.compute_fn.decorated_fn(parse_ctx, dyn_scopes[0].value, claim)
    assert scope_res["terminal_status"] == "SUCCEEDED"
    assert fake_exec.calls == 1

    # Collect hits the pre-populated dynamic/*.json fast-path without re-running the container!
    collect_ctx = _ctx("standalone__tree_sitter_ast__parse__dynamic_scopes")
    collect_ctx.op.compute_fn.decorated_fn(collect_ctx, [scope_res], claim)
    assert fake_exec.calls == 1

    pub_ctx = _ctx("standalone__tree_sitter_ast__acceptance__publish_handoff")
    pub_ctx.op.compute_fn.decorated_fn(pub_ctx, claim)

    fin_ctx = _ctx("standalone__tree_sitter_ast__finalize")
    final = fin_ctx.op.compute_fn.decorated_fn(fin_ctx, claim)
    assert final["run_id"] == run_id
    assert final["completion_status"] == "SUCCEEDED"
    fin_ctx.instance.add_run_tags.assert_called_once()

    run_root = runner.runs.resolve(run_id)
    assert (run_root / "data" / "telemetry" / "summary.json").is_file()
