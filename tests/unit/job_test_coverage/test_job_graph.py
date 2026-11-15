"""Unit tests for job_test_coverage config validation, handlers, shard reuse, and accepted loader."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import TEST_COVERAGE_HANDOFF_SCHEMA
from appsec_review.jobs.job_test_coverage import build_job, load_accepted_test_coverage
from appsec_review.jobs.job_test_coverage import job as job_module
from appsec_review.jobs.job_test_coverage.job import (
    CoverageIntegrityError,
    _fallback_upstream_manifest,
    _load_catalog_files,
    _settings,
    _validate_config,
)
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


def _identity(run_root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _uctx(job_ctx: object, uid: str, outputs: dict[str, object]) -> UnitContext:
    step_id, task_id = uid.split(".", 1)
    return UnitContext(
        job=job_ctx,
        unit_id=uid,
        step_id=step_id,
        task_id=task_id,
        unit_root=job_ctx.attempt_root / "steps" / step_id / "tasks" / task_id,
        outputs=dict(outputs),
    )


def _write_catalog(
    run_root: Path,
    *,
    snapshot: str = "snap",
    schema: str = "appsec-review/target-catalog/1",
    files: object = None,
    include_partition: bool = True,
    include_manifest: bool = True,
) -> tuple[str, dict[str, object] | None]:
    if files is None:
        files = [{"path": "src/a.c", "sha256": "1" * 64}]
    manifest_ref = None
    artifacts_list: list[dict[str, object]] = []
    if include_manifest:
        mpath = run_root / "data/indices/manifests/cat.json"
        write_manifest(mpath, run_id=run_root.name, target_snapshot=snapshot, target_root=run_root, indexes=())
        manifest_ref = _identity(run_root, mpath)
        artifacts_list.append(manifest_ref)
    cat_artifacts: dict[str, object] = {}
    if include_partition:
        ppath = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/part.json"
        atomic_json(ppath, {"files": files})
        pref = _identity(run_root, ppath)
        cat_artifacts["repository_discovery.partition_repository"] = pref
        artifacts_list.append(pref)
    cpath = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/artifacts/catalog.json"
    atomic_json(cpath, {"schema": schema, "source_fingerprint": snapshot, "artifacts": cat_artifacts})
    cref = _identity(run_root, cpath)
    artifacts_list.append(cref)
    pub: dict[str, object] = {"artifact": cref}
    if manifest_ref is not None:
        pub["index_manifest"] = manifest_ref
    hpath = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json"
    write_fixture_handoff(
        run_root,
        hpath,
        {
            "run_id": run_root.name,
            "job_id": "job_target_catalog",
            "attempt_id": "attempt_0001",
            "status": "ACCEPTED",
            "source_fingerprint": snapshot,
            "outputs": {"publish_catalog.publish_handoff": pub},
            "artifacts": artifacts_list,
        },
        target_snapshot=snapshot,
    )
    sha = file_sha256(hpath)
    atomic_json(
        run_root / "data/jobs/job_target_catalog/latest.json",
        {"handoff_path": hpath.relative_to(run_root).as_posix(), "handoff_sha256": sha},
    )
    return sha, manifest_ref


def test_validate_config_and_settings_accept_central_config_and_reject_drift() -> None:
    central = load_config("appsec-review.toml").job("job_test_coverage")
    _validate_config(SimpleNamespace(config=central), None)
    bounds, families = _settings(SimpleNamespace(job=SimpleNamespace(config=central)))
    assert bounds.max_artifacts == 10000 and "native" in families

    bad_steps = SimpleNamespace(config=SimpleNamespace(steps={"load": None}, settings=central.settings))
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(bad_steps, None)

    bad_task = SimpleNamespace(
        config=SimpleNamespace(
            steps=central.steps,
            step=lambda name: SimpleNamespace(tasks=("wrong",) if name == "load" else central.step(name).tasks),
            settings=central.settings,
        )
    )
    with pytest.raises(ValueError, match="task order mismatch: load"):
        _validate_config(bad_task, None)

    for patch, match in (
        ({"bounds": None}, "bounds are required"),
        ({"parser_identity": "wrong"}, "parser_identity is invalid"),
        ({"normalizer_identity": "wrong"}, "normalizer_identity is invalid"),
        ({"mapping_identity": "wrong"}, "mapping_identity is invalid"),
    ):
        mutated = deepcopy(dict(central.settings))
        mutated.update(patch)
        ctx = SimpleNamespace(
            config=SimpleNamespace(steps=central.steps, step=central.step, settings=mutated)
        )
        with pytest.raises(ValueError, match=match):
            _validate_config(ctx, None)

    with pytest.raises(ValueError, match="bounds are invalid"):
        _settings(SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(settings={"bounds": "bad"}))))
    for bad_families in ("native", [""], ["native", "native"]):
        with pytest.raises(ValueError, match="applicable families are invalid"):
            _settings(
                SimpleNamespace(
                    job=SimpleNamespace(
                        config=SimpleNamespace(settings={"bounds": {}, "applicable_families": bad_families})
                    )
                )
            )


@pytest.mark.parametrize(("kwargs", "match"), [
    ({"schema": "wrong/1"}, "schema is unsupported"),
    ({"include_partition": False}, "source inventory is unavailable"),
    ({"files": "not-a-list"}, "source inventory is invalid"),
    ({"files": [{"path": "a.c", "sha256": "short"}]}, "invalid row"),
    ({"files": [{"path": "a.c", "sha256": "1" * 64}, {"path": "a.c", "sha256": "2" * 64}]}, "duplicate path"),
])
def test_load_catalog_files_rejects_unbound_or_malformed_catalog(
    tmp_path: Path, kwargs: dict[str, object], match: str,
) -> None:
    job = build_job()
    sha, _ = _write_catalog(tmp_path, **kwargs)
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": sha}, contract=job.contract):
        with pytest.raises(CoverageIntegrityError, match=match):
            _load_catalog_files(tmp_path)


def test_load_catalog_files_rejects_missing_or_unbound_artifact_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: ({"outputs": {"publish_catalog.publish_handoff": {}}, "artifacts": []}, "h"),
    )
    with pytest.raises(CoverageIntegrityError, match="publication is unavailable"):
        _load_catalog_files(tmp_path)

    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: (
            {
                "outputs": {"publish_catalog.publish_handoff": {"artifact": {"path": "a.json", "sha256": "1" * 64}}},
                "artifacts": [],
            },
            "h",
        ),
    )
    with pytest.raises(CoverageIntegrityError, match="not bound to its handoff"):
        _load_catalog_files(tmp_path)


def test_fallback_upstream_manifest_uses_attempt_input_or_catalog_manifest_and_refuses_missing(
    tmp_path: Path,
) -> None:
    mpath = tmp_path / "data/indices/manifests/input.json"
    write_manifest(mpath, run_id=tmp_path.name, target_snapshot="snap", target_root=tmp_path, indexes=())
    msha = file_sha256(mpath)
    unit = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, input_manifest_path=mpath, input_manifest_sha256=msha)
    )
    resolved = _fallback_upstream_manifest(unit, None)
    assert resolved["sha256"] == msha and resolved["size_bytes"] == mpath.stat().st_size

    no_input = SimpleNamespace(
        job=SimpleNamespace(run_root=tmp_path, input_manifest_path=None, input_manifest_sha256=None)
    )
    with pytest.raises(CoverageIntegrityError, match="upstream index manifest is unavailable"):
        _fallback_upstream_manifest(no_input, None)


def test_handlers_handle_disabled_upstreams_snapshot_mismatch_shard_reuse_and_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = "snap-1"
    cat_sha, _ = _write_catalog(tmp_path, snapshot=snapshot)
    config = load_config("appsec-review.toml").job("job_test_coverage")
    job = build_job()
    by_id = {u.unit_id: u.handler for u in job.units}

    # Snapshot mismatch from catalog is rejected.
    wrong_ctx = SimpleNamespace(
        run_root=tmp_path,
        run_id=tmp_path.name,
        attempt_id="attempt_0001",
        attempt_root=tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0001",
        source_fingerprint="other-snap",
        target_root=tmp_path,
        repository_root=tmp_path,
        config=config,
        input_manifest_path=None,
        input_manifest_sha256=None,
    )
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        with pytest.raises(CoverageIntegrityError, match="disagree with the accepted target snapshot"):
            by_id["load.accepted_inputs"](_uctx(wrong_ctx, "load.accepted_inputs", {}))

    # Disabled language_build and artifact_indexing record explicit gaps and fall back to catalog manifest.
    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, _p: False)
    ctx = SimpleNamespace(**{**wrong_ctx.__dict__, "source_fingerprint": snapshot})
    outputs: dict[str, object] = {}
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.coverage", "index.coverage", "acceptance.publish_handoff"):
            outputs[uid] = by_id[uid](_uctx(ctx, uid, outputs))
    pub = outputs["acceptance.publish_handoff"]
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("language_build_unavailable" in gap for gap in pub["gaps"])
    assert any("artifact_indexing_unavailable" in gap for gap in pub["gaps"])

    # Enabled upstreams with mismatched language_build snapshot fail closed.
    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, p: p == "job_language_build")
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _r: {"source_fingerprint": "wrong", "language_build_handoff_sha256": "2" * 64, "receipts": ()},
    )
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        with pytest.raises(CoverageIntegrityError, match="disagree with the accepted target snapshot"):
            by_id["load.accepted_inputs"](_uctx(ctx, "load.accepted_inputs", {}))

    # NOT_APPLICABLE when enabled upstreams produce zero receipts and zero gaps.
    prior_shard = tmp_path / "data/indices/analysis/prior.sqlite"
    stale_cov = IndexBuilder(
        prior_shard, name="analysis", fingerprint="e" * 64, target_snapshot=snapshot, shard_id="test-coverage-old"
    )
    stale_cov.add_coverage("test-coverage:old", "complete")
    keep_path = tmp_path / "data/indices/inventory/keep.sqlite"
    keep_builder = IndexBuilder(
        keep_path, name="inventory", fingerprint="d" * 64, target_snapshot=snapshot, shard_id="catalog-1"
    )
    keep_builder.add_coverage("catalog:1", "complete")
    art_manifest = tmp_path / "data/indices/manifests/art.json"
    write_manifest(
        art_manifest,
        run_id=tmp_path.name,
        target_snapshot=snapshot,
        target_root=tmp_path,
        indexes=(
            IndexIdentity("analysis", "appsec-review/retrieval-index/2", stale_cov.build(), "e" * 64,
                          prior_shard.relative_to(tmp_path).as_posix(), {"job": "job_test_coverage"}, (), "test-coverage-old"),
            IndexIdentity("inventory", "appsec-review/retrieval-index/2", keep_builder.build(), "d" * 64,
                          keep_path.relative_to(tmp_path).as_posix(), {"job": "job_target_catalog"}, (), "catalog-1"),
        ),
    )
    art_ref = _identity(tmp_path, art_manifest)
    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, _p: True)
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _r: {"source_fingerprint": snapshot, "language_build_handoff_sha256": "2" * 64, "receipts": ()},
    )
    monkeypatch.setattr(
        job_module,
        "load_accepted_artifact_index",
        lambda _r: {"source_fingerprint": snapshot, "handoff_sha256": "3" * 64, "index_manifest": art_ref},
    )
    clean_out: dict[str, object] = {}
    ctx2 = SimpleNamespace(**{**ctx.__dict__, "attempt_id": "attempt_0002",
                              "attempt_root": tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0002"})
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.coverage", "index.coverage", "acceptance.publish_handoff"):
            clean_out[uid] = by_id[uid](_uctx(ctx2, uid, clean_out))
    assert clean_out["acceptance.publish_handoff"]["terminal_status"] == "NOT_APPLICABLE"
    written_manifest = json.loads((tmp_path / clean_out["index.coverage"]["index_manifest"]["path"]).read_text())
    assert [idx["shard_id"] for idx in written_manifest["indexes"]] == ["catalog-1"]

    # Shard reuse (path.exists() -> attest_existing) produces identical shard identity on second index run.
    lcov = tmp_path / "data/build/u1/cov.info"
    lcov.parent.mkdir(parents=True, exist_ok=True)
    lcov.write_bytes(b"SF:src/a.c\nDA:1,1\nend_of_record\n")
    lcov_ref = {**_identity(tmp_path, lcov), "workspace_path": "cov.info", "kind": "test-coverage"}
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": snapshot,
            "language_build_handoff_sha256": "2" * 64,
            "receipts": [{"build_unit_id": "u1", "family": "native", "root": ".", "terminal_status": "SUCCEEDED",
                          "artifacts": [lcov_ref]}],
        },
    )
    first_out: dict[str, object] = {}
    ctx3 = SimpleNamespace(**{**ctx.__dict__, "attempt_id": "attempt_0003",
                              "attempt_root": tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0003"})
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.coverage", "index.coverage"):
            first_out[uid] = by_id[uid](_uctx(ctx3, uid, first_out))
        ctx4 = SimpleNamespace(**{**ctx3.__dict__, "attempt_id": "attempt_0004",
                                  "attempt_root": tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0004"})
        reused = by_id["index.coverage"](_uctx(ctx4, "index.coverage", first_out))
    assert reused["indexes"] == first_out["index.coverage"]["indexes"]


def test_accepted_publication_verifies_handoff_artifact_and_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = "snapshot"
    shard = tmp_path / "data/indices/analysis/coverage.sqlite"
    builder = IndexBuilder(shard, name="analysis", fingerprint="f" * 64,
                           target_snapshot=snapshot, shard_id="test-coverage-u")
    builder.add_coverage("test-coverage:u", "complete")
    index = IndexIdentity(
        "analysis",
        "appsec-review/retrieval-index/2",
        builder.build(),
        "f" * 64,
        shard.relative_to(tmp_path).as_posix(),
        {"job": "job_test_coverage"},
        (),
        "test-coverage-u",
    )
    manifest = tmp_path / "data/indices/manifests/coverage.json"
    write_manifest(manifest, run_id=tmp_path.name, target_snapshot=snapshot, target_root=tmp_path, indexes=(index,))
    attempt = tmp_path / "data/jobs/job_test_coverage/attempts/attempt_0001"
    summary = attempt / "artifacts/test-coverage/accepted-test-coverage.json"
    summary.parent.mkdir(parents=True)
    atomic_json(
        summary,
        {
            "schema": TEST_COVERAGE_HANDOFF_SCHEMA,
            "source_fingerprint": snapshot,
            "build_units": [],
            "totals": {},
            "gaps": [],
            "index_manifest": _identity(tmp_path, manifest),
        },
    )
    summary_identity, manifest_identity = _identity(tmp_path, summary), _identity(tmp_path, manifest)
    handoff = attempt / "handoff.json"
    write_fixture_handoff(
        tmp_path,
        handoff,
        {
            "source_fingerprint": snapshot,
            "status": "ACCEPTED",
            "job_id": "job_test_coverage",
            "attempt_id": "attempt_0001",
            "outputs": {"acceptance.publish_handoff": {"artifact": summary_identity, "index_manifest": manifest_identity}},
            "artifacts": [summary_identity, manifest_identity],
        },
        target_snapshot=snapshot,
    )
    latest = tmp_path / "data/jobs/job_test_coverage/latest.json"
    atomic_json(
        latest,
        {"handoff_path": handoff.relative_to(tmp_path).as_posix(), "handoff_sha256": file_sha256(handoff)},
    )
    assert load_accepted_test_coverage(tmp_path)["handoff_sha256"] == file_sha256(handoff)

    # Tampered summary bytes after publication are rejected.
    summary.write_text("{}", encoding="utf-8")
    with pytest.raises(CoverageIntegrityError, match="identity changed"):
        load_accepted_test_coverage(tmp_path)

    # Missing outputs, unbound artifacts, and unsupported schema are rejected.
    monkeypatch.setattr(
        job_module, "_accepted_handoff", lambda _r, _j: ({"outputs": {"acceptance.publish_handoff": {}}}, "h")
    )
    with pytest.raises(CoverageIntegrityError, match="publication is unavailable"):
        load_accepted_test_coverage(tmp_path)

    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: (
            {
                "outputs": {"acceptance.publish_handoff": {"artifact": summary_identity, "index_manifest": manifest_identity}},
                "artifacts": [manifest_identity],
            },
            "h",
        ),
    )
    with pytest.raises(CoverageIntegrityError, match="not bound to its handoff"):
        load_accepted_test_coverage(tmp_path)

    bad_summary = attempt / "artifacts/test-coverage/bad.json"
    atomic_json(bad_summary, {"schema": "wrong/1"})
    bad_id = _identity(tmp_path, bad_summary)
    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: (
            {
                "outputs": {"acceptance.publish_handoff": {"artifact": bad_id, "index_manifest": manifest_identity}},
                "artifacts": [bad_id, manifest_identity],
            },
            "h",
        ),
    )
    with pytest.raises(CoverageIntegrityError, match="schema is unsupported"):
        load_accepted_test_coverage(tmp_path)
