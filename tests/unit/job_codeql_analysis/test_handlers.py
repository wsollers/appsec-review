"""Focused unit tests for CodeQL job helpers and unit handlers (plan, execute_scopes, publish)."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.codeql.runtime import CodeQLImage, EXPORT_MANIFEST_NAME, GraphExportIntegrityError, load_asset_lock
from appsec_review.config import load_config
from appsec_review.config.assurance import (
    AssuranceMode,
    ComponentReleases,
    PredecessorDatabases,
    ReviewPolicy,
    StoreAuthorization,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_codeql_analysis import job as mod
from appsec_review.jobs.job_codeql_analysis.datasets import DATASETS
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference
from appsec_review.jobs.job_codeql_analysis.job import (
    DATABASE_CHECKPOINT_SCHEMA,
    FrameworkIntegrityError,
    QUERY_CHECKPOINT_SCHEMA,
    _accepted_handoff_identity,
    _accepted_index_manifests,
    _accepted_replay,
    _artifact,
    _checkpoint,
    _copy_clean_target,
    _database_isolated,
    _export_isolated,
    _export_scopes,
    _import_predecessor_databases,
    _json_artifact,
    _location,
    _normalize_one,
    _optional_accepted_handoff_identity,
    _query_metrics,
    _query_one,
    _receipt_map,
    _safe_json,
    _scope_image_value,
    _settings,
    _stage_manifest_workspace,
    _stage_workspace,
    _verify_export_manifest,
    _verify_export_sources,
    _verify_scope_sources,
    _verify_workspace_scope,
    _workspace_manifest_files,
    build_job,
)
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLPlan, CodeQLScope, PLAN_SCHEMA, SCOPE_SCHEMA
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


REPO_ROOT = Path(__file__).resolve().parents[3]
IMAGE_ID = "sha256:" + "2" * 64


class _DummyEvents:
    def __init__(self) -> None:
        self.items: list[tuple[str, dict[str, Any]]] = []

    def write(self, event_type: str, **payload: Any) -> None:
        self.items.append((event_type, payload))


def _shipped_settings():
    return load_config(REPO_ROOT / "appsec-review.toml").job("job_codeql_analysis").typed_settings


def _make_unit(
    tmp_path: Path,
    *,
    settings: Any = None,
    policy: ReviewPolicy | None = None,
    outputs: dict[str, Any] | None = None,
    target_root: Path | None = None,
    fp: str = "snap-1",
):
    run_root = tmp_path / "run-1"
    attempt_root = run_root / "data" / "jobs" / "job_codeql_analysis" / "attempts" / "attempt_0001"
    unit_root = attempt_root / "steps" / "plan" / "tasks" / "inventory"
    metadata_root = tmp_path / "meta"
    target = target_root or (tmp_path / "target")
    for p in (run_root, attempt_root, unit_root, metadata_root, target):
        p.mkdir(parents=True, exist_ok=True)
    cfg = load_config(REPO_ROOT / "appsec-review.toml")
    typed = cfg.job("job_codeql_analysis").typed_settings if settings is None else settings
    stored = dict(outputs or {})
    job_ctx = SimpleNamespace(
        run_id="run-1",
        attempt_id="attempt_0001",
        run_root=run_root,
        attempt_root=attempt_root,
        repository_root=REPO_ROOT,
        metadata_root=metadata_root,
        target_root=target,
        source_fingerprint=fp,
        config=SimpleNamespace(typed_settings=typed),
        review_policy=policy or cfg.review_policy,
        events=_DummyEvents(),
        tools=SimpleNamespace(enable_swift=False),
    )
    return SimpleNamespace(
        unit_id="plan.inventory",
        unit_root=unit_root,
        job=job_ctx,
        output=lambda uid: stored[uid],
        _stored=stored,
    )


def _write_accepted_handoff(
    run_root: Path,
    job_id: str,
    *,
    outputs: dict[str, Any] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    snapshot: str = "snap-1",
) -> dict[str, str]:
    attempt_dir = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    handoff_path = attempt_dir / "handoff.json"
    write_fixture_handoff(
        run_root,
        handoff_path,
        {
            "job_id": job_id,
            "attempt_id": "attempt_0001",
            "outputs": outputs or {"work.only": {"terminal_status": "SUCCEEDED", "gaps": []}},
            "artifacts": artifacts or [],
        },
        target_snapshot=snapshot,
    )
    rel = handoff_path.relative_to(run_root).as_posix()
    sha = file_sha256(handoff_path)
    latest_dir = run_root / "data" / "jobs" / job_id
    atomic_json(
        latest_dir / "latest.json",
        {
            "job_id": job_id,
            "attempt_id": "attempt_0001",
            "handoff_path": rel,
            "handoff_sha256": sha,
        },
    )
    return {"path": rel, "sha256": sha}


def test_settings_artifact_safe_json_and_handoff_manifest_helpers(tmp_path: Path) -> None:
    bad_unit = _make_unit(tmp_path, settings="not-settings")
    with pytest.raises(ValueError, match="typed CodeQL analysis settings are required"):
        _settings(bad_unit)

    unit = _make_unit(tmp_path)
    outside = tmp_path / "outside.json"
    atomic_json(outside, {"x": 1})
    with pytest.raises(FrameworkIntegrityError, match="escaped the run"):
        _artifact(unit.job.run_root, outside)

    inside = unit.job.run_root / "data" / "doc.json"
    ident = _json_artifact(unit.job.run_root, inside, {"ok": True})
    assert _safe_json(unit.job.run_root, ident) == {"ok": True}

    with pytest.raises(FrameworkIntegrityError, match="unavailable or escaped"):
        _safe_json(unit.job.run_root, {"path": "../outside.json", "sha256": "0" * 64})
    with pytest.raises(FrameworkIntegrityError, match="identity changed"):
        _safe_json(unit.job.run_root, {**ident, "sha256": "f" * 64})

    # Pin attempt inputs so accepted_upstream allows reading job_target_catalog & optional job_cpg_analysis.
    idx_path = unit.job.run_root / "data" / "indices" / "observations" / "dummy.sqlite"
    Builder = IndexBuilder(idx_path, name="observations", fingerprint="f" * 64, target_snapshot="snap-1", shard_id="s1")
    idx_sha = Builder.build()
    manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / "cat.json"
    write_manifest(
        manifest_path,
        run_id="run-1",
        target_snapshot="snap-1",
        target_root=unit.job.target_root,
        indexes=[
            IndexIdentity(
                "observations",
                "appsec-review/retrieval-index/2",
                idx_sha,
                "f" * 64,
                idx_path.relative_to(unit.job.run_root).as_posix(),
                {"job": "job_target_catalog"},
                (),
                "s1",
            )
        ],
    )
    manifest_ref = _artifact(unit.job.run_root, manifest_path)
    cat_id = _write_accepted_handoff(
        unit.job.run_root,
        "job_target_catalog",
        outputs={
            "publish.catalog": {"terminal_status": "SUCCEEDED", "index_manifest": manifest_ref, "gaps": []},
            "other.unit": {"terminal_status": "SUCCEEDED", "plain": 1, "gaps": []},
        },
        snapshot="snap-1",
    )
    with upstream_scope(
        unit.job.run_root, "job_codeql_analysis", {"job_target_catalog": cat_id["sha256"]}, contract=mod.CONTRACT
    ):
        assert _accepted_handoff_identity(unit.job.run_root, "job_target_catalog")["sha256"] == cat_id["sha256"]
        assert _optional_accepted_handoff_identity(unit.job.run_root, "job_cpg_analysis") is None
        manifests = _accepted_index_manifests(unit.job.run_root, cat_id)
        assert len(manifests) == 1 and manifests[0]["sha256"] == manifest_ref["sha256"]

        with pytest.raises(FrameworkIntegrityError, match="handoff is required"):
            _accepted_handoff_identity(unit.job.run_root, "job_language_build")

    bad_handoff = _json_artifact(
        unit.job.run_root,
        unit.job.run_root / "data" / "bad-handoff.json",
        {"outputs": {"x": {"index_manifest": {"path": "../outside.json", "sha256": "0" * 64}}}},
    )
    with pytest.raises(FrameworkIntegrityError, match="escaped the run"):
        _accepted_index_manifests(unit.job.run_root, bad_handoff)


def test_receipt_map_and_accepted_replay_validation_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = _make_unit(tmp_path, fp="snap-expected")

    monkeypatch.setattr(mod, "load_accepted_language_build", lambda _r: {"source_fingerprint": "wrong"})
    with pytest.raises(FrameworkIntegrityError, match="snapshot identity changed"):
        _receipt_map(unit)

    monkeypatch.setattr(
        mod,
        "load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": "snap-expected",
            "receipts": [{"build_unit_id": "u1"}, {"build_unit_id": "u1"}],
        },
    )
    with pytest.raises(FrameworkIntegrityError, match="duplicate units"):
        _receipt_map(unit)

    with pytest.raises(FrameworkIntegrityError, match="recipe or image is unavailable"):
        _accepted_replay(unit, {})

    base_receipt = {
        "recipe_identity": "r1",
        "image": {"image_id": IMAGE_ID, "dependency_hashes": {"lock": "1"}},
        "recipe": {"configure_commands": [], "build_commands": [["make"]]},
    }
    with pytest.raises(FrameworkIntegrityError, match="command set is incomplete"):
        _accepted_replay(unit, {**base_receipt, "commands": []})

    with pytest.raises(FrameworkIntegrityError, match="lacks protected argv"):
        _accepted_replay(unit, {**base_receipt, "commands": [{"role": "build"}]})

    bad_cmd_doc = _json_artifact(
        unit.job.run_root,
        unit.job.run_root / "data" / "cmd-bad.json",
        {"schema": "wrong", "argv": [], "environment": {}},
    )
    with pytest.raises(FrameworkIntegrityError, match="protected build command is invalid"):
        _accepted_replay(unit, {**base_receipt, "commands": [{"role": "build", "protected_argv": bad_cmd_doc}]})

    argv = ["make", "-j2"]
    argv_sha = hashlib.sha256(canonical_json(argv)).hexdigest()
    good_cmd_doc = _json_artifact(
        unit.job.run_root,
        unit.job.run_root / "data" / "cmd-ok.json",
        {
            "schema": "appsec-review/protected-build-command/2",
            "argv": argv,
            "working_directory": "/workspace",
            "environment": {"CC": "clang"},
        },
    )
    with pytest.raises(FrameworkIntegrityError, match="command identity mismatch"):
        _accepted_replay(
            unit,
            {
                **base_receipt,
                "commands": [
                    {
                        "role": "build",
                        "protected_argv": good_cmd_doc,
                        "argv_sha256": argv_sha,
                        "working_directory": "/wrong",
                        "image_id": IMAGE_ID,
                    }
                ],
            },
        )

    replay = _accepted_replay(
        unit,
        {
            **base_receipt,
            "commands": [
                {
                    "role": "build",
                    "protected_argv": good_cmd_doc,
                    "argv_sha256": argv_sha,
                    "working_directory": "/workspace",
                    "image_id": IMAGE_ID,
                }
            ],
        },
    )
    assert replay["schema"] == "appsec-review/codeql-build-replay/1"
    assert replay["commands"][0]["argv"] == argv


def test_workspace_source_and_symlink_custody_guards(tmp_path: Path) -> None:
    unit = _make_unit(tmp_path)
    src = unit.job.target_root / "app.py"
    src.write_text("print(1)\n", encoding="utf-8")
    sha = file_sha256(src)

    def _scope(files):
        return CodeQLScope(
            SCOPE_SCHEMA, "s-py", "python", ("Python",), "none", ".", files, None, None, "e" * 64, False
        )

    with pytest.raises(FrameworkIntegrityError, match="source mapping is invalid"):
        _verify_scope_sources(unit, _scope(({"path": "../app.py", "sha256": sha},)))

    outside_src = tmp_path / "outside.py"
    outside_src.write_text("print(2)\n", encoding="utf-8")
    link = unit.job.target_root / "sym.py"
    link.symlink_to(outside_src)
    with pytest.raises(FrameworkIntegrityError, match="escaped the target"):
        _verify_scope_sources(unit, _scope(({"path": "sym.py", "sha256": sha},)))
    link.unlink()

    with pytest.raises(FrameworkIntegrityError, match="source identity changed"):
        _verify_scope_sources(unit, _scope(({"path": "app.py", "sha256": "0" * 64},)))

    # _copy_clean_target skips .git and rejects symlinks.
    git_dir = unit.job.target_root / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    ws = tmp_path / "clean-ws"
    ws.mkdir()
    (ws / "stale.txt").write_text("old", encoding="utf-8")
    _copy_clean_target(unit, ws)
    assert (ws / "app.py").is_file() and not (ws / ".git").exists() and not (ws / "stale.txt").exists()

    link.symlink_to(src)
    with pytest.raises(FrameworkIntegrityError, match="unsupported symlink"):
        _copy_clean_target(unit, ws)
    link.unlink()

    # _verify_workspace_scope missing and tampered checks.
    valid_scope = _scope(({"path": "app.py", "sha256": sha},))
    (ws / "app.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(FrameworkIntegrityError, match="scope source identity changed"):
        _verify_workspace_scope(ws, valid_scope)
    (ws / "app.py").unlink()
    with pytest.raises(FrameworkIntegrityError, match="missing accepted source"):
        _verify_workspace_scope(ws, valid_scope)

    # _workspace_manifest_files & _stage_manifest_workspace error paths.
    env_src = unit.job.run_root / "data" / "env"
    env_src.mkdir(parents=True)
    (env_src / "app.py").write_text("print(1)\n", encoding="utf-8")
    manifest = {"schema": "appsec-review/build-workspace-manifest/1", "files": {"app.py": sha}}
    with pytest.raises(FrameworkIntegrityError, match="manifest is invalid"):
        _workspace_manifest_files(env_src, {"schema": "bad"}, file_limit=10)
    extra_file = env_src / "extra.py"
    extra_file.write_text("print(2)\n", encoding="utf-8")
    with pytest.raises(FrameworkIntegrityError, match="exceeds its file bound"):
        _workspace_manifest_files(env_src, manifest, file_limit=1)
    extra_file.unlink()

    # Symlink checks inside materialized workspace.
    abs_link = env_src / "abs_link"
    abs_link.symlink_to("/etc/hosts")
    with pytest.raises(FrameworkIntegrityError, match="contains a symlink"):
        _workspace_manifest_files(env_src, manifest, file_limit=10, allow_manifest_backed_symlinks=False)
    with pytest.raises(FrameworkIntegrityError, match="unsafe symlink"):
        _workspace_manifest_files(env_src, manifest, file_limit=10, allow_manifest_backed_symlinks=True)
    abs_link.unlink()

    broken = env_src / "broken_link"
    broken.symlink_to("missing_target.py")
    with pytest.raises(FrameworkIntegrityError, match="invalid symlink"):
        _workspace_manifest_files(env_src, manifest, file_limit=10, allow_manifest_backed_symlinks=True)
    broken.unlink()

    unpinned_file = env_src / "extra.py"
    unpinned_file.write_text("x", encoding="utf-8")
    rel_link = env_src / "rel_link.py"
    rel_link.symlink_to("extra.py")
    with pytest.raises(FrameworkIntegrityError, match="unpinned symlink"):
        _workspace_manifest_files(env_src, manifest, file_limit=10, allow_manifest_backed_symlinks=True)
    rel_link.unlink()
    unpinned_file.unlink()

    empty_dir = env_src / "pkg_empty"
    empty_dir.mkdir()
    dir_link = env_src / "alias_pkg"
    dir_link.symlink_to("pkg_empty")
    with pytest.raises(FrameworkIntegrityError, match="unpinned symlink"):
        _workspace_manifest_files(env_src, manifest, file_limit=10, allow_manifest_backed_symlinks=True)
    dir_link.unlink()

    # _stage_workspace error paths for materialized source scope (mode == "none").
    source_scope = CodeQLScope(
        SCOPE_SCHEMA, "s-py", "python", ("Python",), "none", ".", ({"path": "app.py", "sha256": sha},), "u1", "fp", "e" * 64, False
    )
    with pytest.raises(FrameworkIntegrityError, match="materialized environment identity is unavailable"):
        _stage_workspace(unit, source_scope, {"workspace": "data/env"}, tmp_path / "staged")

    manifest_art = _json_artifact(unit.job.run_root, unit.job.run_root / "data" / "ws-manifest.json", manifest)
    with pytest.raises(FrameworkIntegrityError, match="escaped the run"):
        _stage_workspace(unit, source_scope, {"workspace": "../target", "workspace_manifest": manifest_art}, tmp_path / "staged")

    # Happy-path _stage_workspace over an existing staged directory exercises _stage_manifest_workspace.
    staged_ok = tmp_path / "staged-ok"
    staged_ok.mkdir()
    (staged_ok / "old.txt").write_text("stale", encoding="utf-8")
    empty_dir.rmdir()
    (env_src / "app.py").write_bytes((unit.job.target_root / "app.py").read_bytes())
    _stage_workspace(unit, source_scope, {"workspace": "data/env", "workspace_manifest": manifest_art}, staged_ok)
    assert (staged_ok / "app.py").is_file() and not (staged_ok / "old.txt").exists()

    assert _checkpoint(tmp_path / "nonexistent.json", "id", "schema") is None
    bad_cp = tmp_path / "cp.json"
    atomic_json(bad_cp, {"schema": "s", "identity": "id", "terminal_status": "FAILED"})
    assert _checkpoint(bad_cp, "id", "s") is None


def test_database_query_export_and_normalize_edge_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = _make_unit(tmp_path)
    src = unit.job.target_root / "app.py"
    src.write_text("x = 1\n", encoding="utf-8")
    sha = file_sha256(src)
    scope = CodeQLScope(
        SCOPE_SCHEMA, "s-py", "python", ("Python",), "none", ".", ({"path": "app.py", "sha256": sha},), None, None, "e" * 64, False
    )

    # _query_metrics fallback gap on OSError/ValueError.
    monkeypatch.setattr(mod.execution_metrics, "write_query_metrics", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad")))
    qm = _query_metrics(unit.job.run_root, tmp_path, {})
    assert "query_metrics_gap" in qm

    # _scope_image_value missing build unit & invalid image.
    go_scope_id = "codeql-unit-" + "a" * 24
    manual_scope = CodeQLScope(
        SCOPE_SCHEMA, go_scope_id, "go", ("Go",), "manual", ".", ({"path": "app.py", "sha256": sha},), "u-go", "fp", "e" * 64, True
    )
    with pytest.raises(FrameworkIntegrityError, match="planned build unit disappeared"):
        _scope_image_value(manual_scope, {}, _settings(unit))
    with pytest.raises(FrameworkIntegrityError, match="image identity is unavailable"):
        _scope_image_value(manual_scope, {"u-go": {"image": "not-a-dict"}}, _settings(unit))

    # _import_predecessor_databases error paths.
    sel = PredecessorDatabases(
        run_id="2026-11-15-0001",
        handoff_sha256="1" * 64,
        scope_ids=(go_scope_id,),
        metadata_bytes_limit=1024,
    )
    store_auth = StoreAuthorization(tenant_id="tenant-1", runs_root=str((tmp_path / "runs").resolve()))
    unit_no_rel = _make_unit(
        tmp_path / "pred1",
        policy=ReviewPolicy(
            mode=AssuranceMode.STRICT,
            project_id="proj-1",
            approved_first_party_projects=("proj-1",),
            store_authorization=store_auth,
            predecessor_databases=sel,
            releases=ComponentReleases({}),
        ),
    )
    with pytest.raises(FrameworkIntegrityError, match="lacks required release declarations"):
        _import_predecessor_databases(unit_no_rel, (manual_scope,), {}, _settings(unit_no_rel))

    full_releases = ComponentReleases(
        values={k: "rel1" for k in ("platform", "build_toolchain", "codeql", "codeql_runner", "extractor_go")},
    )
    pred2_target = (tmp_path / "pred2" / "target").resolve()
    pred2_target.mkdir(parents=True, exist_ok=True)
    unit_pred = _make_unit(
        tmp_path / "pred2",
        target_root=pred2_target,
        policy=ReviewPolicy(
            mode=AssuranceMode.FIRST_PARTY_MANAGED,
            project_id="proj-1",
            approved_first_party_projects=("proj-1",),
            target_root=str(pred2_target),
            custody="application_private_v1",
            store_authorization=store_auth,
            predecessor_databases=sel,
            releases=full_releases,
        ),
    )
    with pytest.raises(FrameworkIntegrityError, match="lacks its accepted build unit"):
        _import_predecessor_databases(unit_pred, (manual_scope,), {}, _settings(unit_pred))
    with pytest.raises(FrameworkIntegrityError, match="lacks its environment image"):
        _import_predecessor_databases(unit_pred, (manual_scope,), {"u-go": {"image": "bad"}}, _settings(unit_pred))

    # _database_isolated catches RuntimeError and emits CODEQL_ACTION_FAILED.
    monkeypatch.setattr(mod, "_database_one", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("docker down")))
    db_failed = _database_isolated(unit, scope, {})
    assert db_failed["terminal_status"] == "FAILED"
    assert any("database producer failed (RuntimeError)" in g for g in db_failed["gaps"])

    # _query_one skips when database failed.
    q_skipped = _query_one(unit, db_failed, {"query_id": "default", "kind": "default"})
    assert q_skipped["query_identity"] is None
    assert "CodeQL query skipped because database creation failed" in q_skipped["gaps"]

    # _export_isolated catches TimeoutError; _export_scopes produces graph-exports.json.
    monkeypatch.setattr(mod, "_export_one", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("slow")))
    exp_failed = _export_isolated(unit, {"scope": asdict(scope), "database_identity": "db1"})
    assert exp_failed["export_status"] == "FAILED"

    unit._stored["database.scopes"] = {"databases": [db_failed]}
    exp_summary = _export_scopes(unit)
    assert exp_summary["terminal_status"] == "COMPLETED_WITH_GAPS"

    # _verify_export_sources and _verify_export_manifest error branches.
    cpp_profile = asdict(_settings(unit).languages["cpp"].export_queries[0])
    with pytest.raises(FrameworkIntegrityError, match="asset configuration is unavailable"):
        _verify_export_sources(tmp_path / "empty-repo", cpp_profile, _settings(unit))

    exp_dir = tmp_path / "bad-export"
    exp_dir.mkdir()
    atomic_json(exp_dir / EXPORT_MANIFEST_NAME, {"language": "wrong"})
    cpp_scope = CodeQLScope(SCOPE_SCHEMA, "s-cpp", "cpp", ("C",), "manual", ".", (), "u1", "fp", "e" * 64, True)
    with pytest.raises(GraphExportIntegrityError, match="differs from the configured pack"):
        _verify_export_manifest(exp_dir, cpp_scope, cpp_profile, _settings(unit))

    # _location & _normalize_one edge cases (unlocated, changed source sha, oversized failed SARIF).
    assert _location(unit, {"path": None, "file_sha256": None}) is None
    with pytest.raises(FrameworkIntegrityError, match="normalized source identity changed"):
        _location(unit, {"path": "app.py", "file_sha256": "0" * 64, "start_line": 1, "end_line": 1, "start_column": 1, "end_column": 1})

    oversized_sarif = unit.job.run_root / "data" / "big.sarif"
    oversized_sarif.write_bytes(b"x" * 32)
    small_settings = replace(_settings(unit), sarif_bytes_limit=8)
    unit_small = _make_unit(tmp_path / "norm-small", settings=small_settings)
    oversized_in_small = unit_small.job.run_root / "data" / "big.sarif"
    oversized_in_small.parent.mkdir(parents=True, exist_ok=True)
    oversized_in_small.write_bytes(b"x" * 32)
    with pytest.raises(FrameworkIntegrityError, match="exceeded its retained byte bound"):
        _normalize_one(
            unit_small,
            {
                "scope": asdict(scope),
                "terminal_status": "FAILED",
                "sarif": _artifact(unit_small.job.run_root, oversized_in_small),
                "gaps": ["query failed"],
            },
        )


def test_build_job_plan_execute_scopes_and_publish_handlers_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir(parents=True)
    app_py = target / "app.py"
    app_py.write_text("user_input = input()\neval(user_input)\n", encoding="utf-8")
    app_sha = file_sha256(app_py)
    helper_py = target / "helper.py"
    helper_py.write_text("def taint(x):\n    return x\n", encoding="utf-8")
    helper_sha = file_sha256(helper_py)
    fp = source_fingerprint(target)

    unit = _make_unit(tmp_path, target_root=target, fp=fp)
    unit.job.review_policy = replace(
        unit.job.review_policy,
        releases=ComponentReleases(
            {
                **unit.job.review_policy.releases.values,
                "platform": "p1",
                "build_toolchain": "b1",
                "extractor_python": "py1",
                "query_python_default": "qpy1",
                "query_python_custom": "qpyc1",
            }
        ),
    )
    run_root = unit.job.run_root
    cfg_dir = run_root / "data" / "configuration"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "resolved-config.json").write_text('{"ok": true}\n', encoding="utf-8")

    # Prepare upstream context manifest + required upstream handoffs.
    seed_idx = run_root / "data" / "indices" / "observations" / "seed.sqlite"
    seed_sha = IndexBuilder(seed_idx, name="observations", fingerprint="1" * 64, target_snapshot=fp, shard_id="seed").build()
    ctx_manifest = run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(
        ctx_manifest,
        run_id="run-1",
        target_snapshot=fp,
        target_root=target,
        indexes=[
            IndexIdentity(
                "observations",
                "appsec-review/retrieval-index/2",
                seed_sha,
                "1" * 64,
                seed_idx.relative_to(run_root).as_posix(),
                {"job": "job_target_catalog"},
                (),
                "seed",
            )
        ],
    )
    ctx_ref = _artifact(run_root, ctx_manifest)

    pinned: dict[str, str] = {}
    for req_job in (
        "job_target_catalog",
        "job_language_build",
        "job_artifact_indexing",
        "job_cpp_compiled_analysis",
        "job_evidence_collection",
    ):
        pinned[req_job] = _write_accepted_handoff(
            run_root,
            req_job,
            outputs={"publish.main": {"terminal_status": "SUCCEEDED", "index_manifest": ctx_ref, "gaps": []}},
            snapshot=fp,
        )["sha256"]

    catalog = SimpleNamespace(
        source_fingerprint=fp,
        files=(
            {"path": "app.py", "sha256": app_sha, "size_bytes": app_py.stat().st_size},
            {"path": "helper.py", "sha256": helper_sha, "size_bytes": helper_py.stat().st_size},
        ),
        projects=({"root": "."},),
    )
    monkeypatch.setattr(mod, "load_target_catalog", lambda _r: catalog)
    monkeypatch.setattr(mod, "load_accepted_language_build", lambda _r: {"source_fingerprint": fp, "receipts": []})
    monkeypatch.setattr(mod, "resolve_context_manifest", lambda _job: (ctx_manifest, ctx_ref["sha256"]))

    fake_image = CodeQLImage(
        schema="appsec-review/codeql-runtime-image/2",
        identity="img-ident-1",
        source_image_id=_settings(unit).source_image_id,
        build_image_id=_settings(unit).source_image_id,
        build_image_tag="src:1",
        image_id=IMAGE_ID,
        image_tag="codeql-test:1",
        runtime_user="10001:10001",
        component_release_id=None,
        runner_release_id=None,
        reused=True,
        manifest_path="manifest.json",
    )
    monkeypatch.setattr(mod, "_resolve_image", lambda *_a, **_k: (fake_image, b"", b""))
    monkeypatch.setattr(mod, "_make_workspace_accessible", lambda *_a, **_k: None)

    class _FakeExec:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        def execute(self, action: str, argv: tuple[str, ...], *, scratch_root: Path):
            exec_dir = scratch_root / "executions" / action
            exec_dir.mkdir(parents=True, exist_ok=True)
            atomic_json(
                exec_dir / "receipt.json",
                {
                    "schema": "appsec-review/container-execution/1",
                    "action": action,
                    "exit_code": 0,
                    "timed_out": False,
                    "duration_ms": 5,
                },
            )
            if action == "inventory":
                atomic_json(
                    scratch_root / "extractor-inventory.json",
                    {
                        "schema": "appsec-review/codeql-extractor-inventory/1",
                        "languages": ["python"],
                        "roots": {},
                        "extractors": {},
                        "query_packs": {},
                        "prerequisites": {},
                    },
                )
            elif action == "database":
                db_dir = scratch_root / "database"
                db_dir.mkdir(parents=True, exist_ok=True)
                (db_dir / "codeql-database.yml").write_text("primaryLanguage: python\n", encoding="utf-8")
            elif action == "query":
                sarif_dir = scratch_root / "sarif"
                sarif_dir.mkdir(parents=True, exist_ok=True)
                atomic_json(
                    sarif_dir / "results.sarif",
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "py/code-injection"}]}},
                                "results": [
                                    {
                                        "ruleId": "py/code-injection",
                                        "level": "error",
                                        "message": {"text": "Code injection"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 2, "startColumn": 1},
                                                }
                                            }
                                        ],
                                        "codeFlows": [
                                            {
                                                "threadFlows": [
                                                    {
                                                        "locations": [
                                                            {
                                                                "location": {
                                                                    "message": {"text": "unlocated step"},
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "message": {"text": "helper hop"},
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "helper.py"},
                                                                        "region": {"startLine": 2, "startColumn": 5},
                                                                    },
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "message": {"text": "source"},
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "app.py"},
                                                                        "region": {"startLine": 1, "startColumn": 1},
                                                                    },
                                                                }
                                                            },
                                                        ]
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    },
                )
            return SimpleNamespace(
                exit_code=0,
                timed_out=False,
                duration_ms=5,
                stdout_truncated=False,
                stderr_truncated=False,
            )

    monkeypatch.setattr(mod, "CodeQLExecutor", _FakeExec)

    job = build_job()
    plan_fn, exec_fn, pub_fn = (u.handler for u in job.units)

    actor = {
        "run_id": unit.job.run_id,
        "job_id": "job_codeql_analysis",
        "attempt_id": unit.job.attempt_id,
        "orchestration": {"system": "fixture"},
    }
    atomic_json(
        unit.job.attempt_root / "claim.json",
        {
            **actor,
            "attempt_path": unit.job.attempt_root.relative_to(run_root).as_posix(),
            "dataset_contract": dataset_contract(
                "job_codeql_analysis", ("plan", "execution", "acceptance"), DATASETS
            ),
        },
    )
    owner = SharedArtifacts(
        run_root, unit.job.attempt_root, {**actor, "claim": reference(run_root, unit.job.attempt_root / "claim.json")}
    )

    with (
        upstream_scope(run_root, "job_codeql_analysis", pinned, contract=mod.CONTRACT),
        publication_scope_for_owner(owner),
    ):
        plan_out = plan_fn(unit)
        assert plan_out["scope_count"] == 1
        assert "job_evidence_collection" in plan_out["upstream_handoffs"]
        unit._stored["plan.inventory"] = plan_out

        exec_out = exec_fn(unit)
        assert exec_out["terminal_status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
        assert exec_out["observation_count"] == 1
        assert exec_out["scopes"][0]["support_count"] == 2
        unit._stored["execution.scopes"] = exec_out

        # Second invocation exercises checkpoint reuse for both database and query artifacts.
        reused_exec_out = exec_fn(unit)
        assert reused_exec_out["observation_count"] == 1
        assert reused_exec_out["databases"][0]["database_reused"] is True
        assert reused_exec_out["queries"][0]["query_reused"] is True

        # Strip query_execution from checkpoint to exercise fallback provenance lookup on reuse.
        for qcp in (run_root / "data" / "codeql" / "scopes").rglob("query-checkpoint.json"):
            doc = json.loads(qcp.read_text(encoding="utf-8"))
            doc.pop("query_execution", None)
            atomic_json(qcp, doc)
        reused_no_exec = exec_fn(unit)
        assert reused_no_exec["queries"][0]["query_reused"] is True
        assert any("provenance_unavailable" in g for g in reused_no_exec["gaps"])

        pub_out = pub_fn(unit)
        assert pub_out["terminal_status"] == exec_out["terminal_status"]
        assert pub_out["item_count"] == 1
        assert pub_out["scope_count"] == 1


def test_build_job_plan_runtime_failure_and_admitted_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir(parents=True)
    app_py = target / "app.py"
    app_py.write_text("print('hi')\n", encoding="utf-8")
    app_sha = file_sha256(app_py)
    fp = source_fingerprint(target)

    unit = _make_unit(tmp_path, target_root=target, fp=fp)
    run_root = unit.job.run_root
    cfg_dir = run_root / "data" / "configuration"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "resolved-config.json").write_text('{"ok": true}\n', encoding="utf-8")

    seed_idx = run_root / "data" / "indices" / "observations" / "seed.sqlite"
    seed_sha = IndexBuilder(seed_idx, name="observations", fingerprint="1" * 64, target_snapshot=fp, shard_id="seed").build()
    ctx_manifest = run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(ctx_manifest, run_id="run-1", target_snapshot=fp, target_root=target, indexes=[])
    ctx_ref = _artifact(run_root, ctx_manifest)

    pinned = {
        req_job: _write_accepted_handoff(run_root, req_job, snapshot=fp)["sha256"]
        for req_job in ("job_target_catalog", "job_language_build", "job_artifact_indexing", "job_cpp_compiled_analysis")
    }

    catalog = SimpleNamespace(
        source_fingerprint=fp,
        files=({"path": "app.py", "sha256": app_sha, "size_bytes": app_py.stat().st_size},),
        projects=({"root": "."},),
    )
    monkeypatch.setattr(mod, "load_target_catalog", lambda _r: catalog)
    monkeypatch.setattr(mod, "load_accepted_language_build", lambda _r: {"source_fingerprint": fp, "receipts": []})
    monkeypatch.setattr(mod, "resolve_context_manifest", lambda _job: (ctx_manifest, ctx_ref["sha256"]))
    monkeypatch.setattr(mod, "_resolve_image", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("daemon unreachable")))

    job = build_job()
    plan_fn, exec_fn, pub_fn = (u.handler for u in job.units)

    with upstream_scope(run_root, "job_codeql_analysis", pinned, contract=mod.CONTRACT):
        # Runtime failure in plan records a named gap instead of crashing.
        plan_out = plan_fn(unit)
        assert any("CodeQL runtime dependency is unavailable (RuntimeError)" in g for g in plan_out["gaps"])

        # Capability validation failure (exit_code != 0), invalid inventory schema, and export lock mismatch.
        fake_image = CodeQLImage(
            "appsec-review/codeql-runtime-image/2", "id", _settings(unit).source_image_id,
            _settings(unit).source_image_id, "src:1", IMAGE_ID, "tag:1", "10001:10001", None, None, True, "m.json",
        )
        monkeypatch.setattr(mod, "_resolve_image", lambda *_a, **_k: (fake_image, b"", b""))

        class _ExitFailExec:
            def __init__(self, **_k: Any) -> None:
                pass

            def execute(self, *_a: Any, **_k: Any):
                return SimpleNamespace(exit_code=1, timed_out=False)

        monkeypatch.setattr(mod, "CodeQLExecutor", _ExitFailExec)
        with pytest.raises(FrameworkIntegrityError, match="capability validation failed"):
            plan_fn(unit)

        class _BadSchemaExec:
            def __init__(self, **_k: Any) -> None:
                pass

            def execute(self, _action: str, _argv: Any, *, scratch_root: Path):
                atomic_json(scratch_root / "extractor-inventory.json", {"schema": "wrong"})
                return SimpleNamespace(exit_code=0, timed_out=False)

        monkeypatch.setattr(mod, "CodeQLExecutor", _BadSchemaExec)
        with pytest.raises(FrameworkIntegrityError, match="extractor inventory is invalid"):
            plan_fn(unit)

        monkeypatch.setattr(mod, "_resolve_image", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("daemon unreachable")))
        orig_mismatches = mod.export_lock_mismatches
        monkeypatch.setattr(mod, "export_lock_mismatches", lambda *_a, **_k: ["cpp:export_nodes"])
        with pytest.raises(FrameworkIntegrityError, match="graph export query assets differ from the lock"):
            plan_fn(unit)
        monkeypatch.setattr(mod, "export_lock_mismatches", orig_mismatches)

        # Snapshot mismatch in plan raises FrameworkIntegrityError.
        bad_unit = _make_unit(tmp_path / "bad-snap", target_root=target, fp="wrong-fp")
        with pytest.raises(FrameworkIntegrityError, match="accepted target snapshot changed"):
            plan_fn(bad_unit)

        # Admitted operational failure recovery in execute_scopes when ResourceAdmission.reserve raises TimeoutError.
        py_scope = CodeQLScope(
            SCOPE_SCHEMA, "s-py", "python", ("Python",), "none", ".", ({"path": "app.py", "sha256": app_sha},), None, None, "e" * 64, False
        )
        synthetic_plan = CodeQLPlan(PLAN_SCHEMA, fp, ("python",), (py_scope,), (), (), ())
        plan_art = _json_artifact(run_root, unit.job.attempt_root / "artifacts" / "codeql" / "plan2.json", synthetic_plan.as_dict())
        unit._stored["plan.inventory"] = {**plan_out, "plan": plan_art}

        monkeypatch.setattr(
            mod.ResourceAdmission,
            "reserve",
            lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("resource lease timed out")),
        )
        exec_failed = exec_fn(unit)
        assert exec_failed["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert any("operational failure (TimeoutError)" in g for g in exec_failed["gaps"])

        # Publish rejects missing index_identity without an explicit failure gap.
        unit._stored["execution.scopes"] = {
            **exec_failed,
            "scopes": [{"scope": asdict(py_scope), "terminal_status": "SUCCEEDED", "gaps": []}],
        }
        with pytest.raises(FrameworkIntegrityError, match="omitted its index without an explicit failure gap"):
            pub_fn(unit)
