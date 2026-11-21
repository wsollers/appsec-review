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



def _index_report_fixture(tmp_path: Path, *, duplicate: bool = False,
                          report_name: str = "lcov.info", report_payload: bytes | None = None):
    from appsec_review.jobs.job_test_coverage import ingest_coverage_artifacts

    run_root = tmp_path / "runs" / "2026-11-20-0001"
    run_root.mkdir(parents=True, mode=0o700)
    manifest = run_root / "data/indices/manifests/input.json"
    write_manifest(manifest, run_id=run_root.name, target_snapshot="snapshot",
                   target_root=run_root, indexes=())
    artifacts = []
    for name in (("original", "copy") if duplicate else ("original",)):
        path = run_root / f"data/build/u1/{name}/{report_name}"
        path.parent.mkdir(parents=True)
        path.write_bytes(report_payload if report_payload is not None else
            b"SF:src/a.c\nDA:1,1\nend_of_record\n"
            b"SF:src/b.c\nDA:1,0\nend_of_record\n"
            b"SF:missing.c\nDA:1,0\nend_of_record\n"
        )
        artifacts.append({**_identity(run_root, path), "kind": "test-coverage",
                          "workspace_path": f"{name}/{report_name}", "artifact_origin": "accepted-input"})
    normalized = ingest_coverage_artifacts(
        run_root, [{"build_unit_id": "u1", "family": "native", "root": ".",
                    "terminal_status": "SUCCEEDED", "artifacts": artifacts}],
        {"src/a.c": "1" * 64, "src/b.c": "2" * 64})
    config = load_config("appsec-review.toml").job("job_test_coverage")
    ctx = SimpleNamespace(
        run_root=run_root, run_id=run_root.name, source_fingerprint="snapshot",
        target_root=run_root, repository_root=run_root, config=config,
        attempt_id="attempt_0001",
        attempt_root=run_root / "data/jobs/job_test_coverage/attempts/attempt_0001")
    index = next(unit for unit in build_job().units if unit.unit_id == "index.coverage")
    output = index.handler(_uctx(ctx, "index.coverage", {
        "load.accepted_inputs": {"upstream_manifest": _identity(run_root, manifest)},
        "normalize.coverage": normalized}))
    return run_root, normalized, output


def test_identical_report_copies_keep_distinct_index_provenance(tmp_path: Path) -> None:
    from appsec_review.indexing.store import ShardSet

    run_root, normalized, output = _index_report_fixture(tmp_path, duplicate=True)
    assert normalized["units"][0]["coverage_state"] == "partial"
    assert any("overlapping_coverage_reports" in gap for gap in normalized["gaps"])
    store = ShardSet(run_root, output["indexes"])
    cells = list(store.entities(store.shards, kinds=("coverage_cell",)))
    files = [row for row in cells if "producer_path" in row["payload"]]
    assert len(files) == len({row["identity"] for row in files}) == 6
    copies = [row["payload"] for row in files if row["payload"]["path"] == "src/a.c"]
    assert len({row["artifact_path"] for row in copies}) == 2
    assert len({row["artifact_sha256"] for row in copies}) == 1
    assert {row["file_sha256"] for row in copies} == {"1" * 64}
    assert {row["artifact_origin"] for row in copies} == {"accepted-input"}


def test_advertised_route_retrieves_real_coverage_cells(tmp_path: Path) -> None:
    from appsec_review.jobs.job_test_coverage.datasets import DATASETS
    from appsec_review.retrieval.core import RetrievalCore

    run_root, _, output = _index_report_fixture(tmp_path)
    ref = output["index_manifest"]
    core = RetrievalCore(run_root.parent, run_root.name, manifest_path=run_root / ref["path"],
                         manifest_sha256=ref["sha256"])
    route, argument = DATASETS[0].query_route.split()
    key, value = argument.split("=")
    response = getattr(core, route)(**{key: value, "path": "src/a.c"})
    assert len(response["results"]) == 1
    cell = response["results"][0]
    assert cell["payload"]["file_sha256"] == "1" * 64
    assert cell["payload"]["totals"]["lines_rate"] == 1.0
    assert cell["signal_family"] == "test_coverage"
    assert core.query_engineering_signals(signal_family="test_coverage", path="src/absent.c")["results"] == []
    with pytest.raises(ValueError, match="signal_family"):
        core.query_engineering_signals(signal_family="unregistered")


def test_review_context_excludes_other_files_and_unresolved_cells_from_build(tmp_path: Path) -> None:
    from appsec_review.indexing.store import ShardSet
    from appsec_review.review.units import _engineering_context

    run_root, _, output = _index_report_fixture(tmp_path)
    store = ShardSet(run_root, output["indexes"])
    # Only accepted-scope selection is substituted; rows come from the real coverage producer.
    scope = SimpleNamespace(
        store=store, shard_sha256=lambda shard: shard["sha256"],
        producer=lambda name: SimpleNamespace(shards=store.shards if name == "test_coverage" else ()))
    by_path, by_build, dependencies = _engineering_context(scope)
    rows = list(store.entities(store.shards, kinds=("coverage_cell",)))
    aggregates = {row["identity"] for row in rows if "producer_path" not in row["payload"]}
    assert len(by_build["u1"]) == 1
    assert {entry.id for entry in by_build["u1"]} == aggregates
    assert set(by_path) == {"src/a.c", "src/b.c"}
    for path in sorted(by_path):
        expected = {row["identity"] for row in rows if row["payload"].get("path") == path}
        assert {entry.id for entry in by_path[path]} == expected
        assert expected.isdisjoint(aggregates)
    assert dependencies == []


def _runtime_coverage_fixture(tmp_path, report_name, payload):
    from tests.artifact_input_support import recorded_job
    from tests.unit.runtime.test_wave3_contracts import _recorded_catalog_run

    job = build_job()
    runner, run_id, run_root, target, snapshot, catalog_out, _ = _recorded_catalog_run(
        tmp_path, ("job_language_build", job.job_id), disabled_jobs=("job_artifact_indexing",))
    report = run_root / f"data/build/u1/coverage/{report_name}"
    report.parent.mkdir(parents=True)
    report.write_bytes(payload)
    manifest = run_root / "data/indices/manifests/language-fixture.json"
    write_manifest(manifest, run_id=run_id, target_snapshot=snapshot, target_root=target, indexes=())
    atomic_json(run_root / "data/inputs/artifact-fixture/job_language_build.json", {
        "document": {
            "schema": "appsec-review/language-build-handoff/2", "source_fingerprint": snapshot,
            "upstream_project_build_handoff_sha256": "c" * 64, "gaps": [],
            "receipts": [{"build_unit_id": "build-unit-u1", "family": "native", "root": ".",
                          "terminal_status": "SUCCEEDED", "fingerprint": "d" * 64,
                          "executor_identity": "fixture", "capture_identity": "fixture",
                          "artifacts": [{**_identity(run_root, report), "workspace_path": f"coverage/{report_name}",
                                         "kind": "test-coverage", "artifact_origin": "accepted-input"}]}]},
        "manifest": _identity(run_root, manifest)})
    language_out = runner.run(recorded_job(run_root, "job_language_build"), run_id=run_id,
                              target_root=target, source_fingerprint=snapshot)
    result = runner.run(job, run_id=run_id, target_root=target, source_fingerprint=snapshot,
                        upstream_handoffs={"job_target_catalog": catalog_out["handoff_sha256"],
                                           "job_language_build": language_out["handoff_sha256"]})
    return run_root, target, snapshot, result, report


def test_prioritization_reads_runtime_published_coverage_status_and_receipts(tmp_path: Path) -> None:
    from appsec_review.jobs.job_review_prioritization.composite import _load_test_coverage
    from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT
    from appsec_review.runtime.inputs import input_read_scope
    from appsec_review.storage.validation import validation_scope

    run_root, _, snapshot, result, _ = _runtime_coverage_fixture(
        tmp_path, "lcov.info", b"SF:src/main.c\nDA:1,1\nDA:2,0\nend_of_record\n")
    context = SimpleNamespace(
        run_root=run_root, config=SimpleNamespace(job_id="job_review_prioritization"),
        contract=CONTRACT, upstream_handoffs={"job_test_coverage": result["handoff_sha256"]})
    with validation_scope(run_root), input_read_scope(context) as reads:
        status, files = _load_test_coverage(run_root, True)
    assert reads is not None
    receipts = reads.document()["reads"]
    assert len(receipts) == 1
    assert receipts[0]["producer"] == "job_test_coverage"
    assert receipts[0]["handoff_sha256"] == result["handoff_sha256"]
    assert receipts[0]["target_snapshot"] == snapshot
    assert receipts[0]["read"] is True and receipts[0]["cited"] is None
    assert status == "COMPLETED_WITH_GAPS"
    assert (files["src/main.c"]["lines_total"], files["src/main.c"]["lines_covered"]) == (2, 1)
    assert _load_test_coverage(run_root, False) == ("DISABLED", {})
    with validation_scope(run_root), upstream_scope(
        run_root, "job_review_prioritization", {}, contract=CONTRACT,
    ):
        assert _load_test_coverage(run_root, True) == ("UNAVAILABLE", {})
    handoff_path = run_root / "data/jobs/job_test_coverage/attempts/attempt_0001/handoff.json"
    handoff = json.loads(handoff_path.read_text())
    assert handoff["completion_status"] == status
    summary = run_root / handoff["outputs"]["acceptance.publish_handoff"]["artifact"]["path"]
    summary.write_text("{}", encoding="utf-8")
    with validation_scope(run_root), pytest.raises(ValueError, match="identity changed"):
        with input_read_scope(context):
            _load_test_coverage(run_root, True)



@pytest.mark.parametrize(("other_class", "first", "second", "total"), [
    ("B", "0% (0/2)", "100% (2/2)", 4),
    ("A", "0% (0/2)", "100% (2/2)", 2),
    ("B", "50% (1/2)", "50% (1/2)", 4),
], ids=["independent-classes", "duplicate-class-identity", "independent-partial-classes"])
def test_cobertura_class_branch_identity_survives_ingestion_and_context(
    tmp_path, other_class, first, second, total,
):
    from appsec_review.indexing.store import ShardSet
    from appsec_review.review.units import _engineering_context

    def cls(name, fraction):
        line = f'<line number="1" hits="1" branch="true" condition-coverage="{fraction}"/>'
        return (f'<class name="{name}" filename="src/a.c"><methods><method name="f">'
                f'<lines>{line}</lines></method></methods><lines>{line}</lines></class>')

    payload = ("<coverage>" + cls("A", first) + cls(other_class, second) + "</coverage>").encode()
    run_root, normalized, output = _index_report_fixture(
        tmp_path, report_name="coverage.xml", report_payload=payload)
    unit = normalized["units"][0]
    assert unit["coverage_state"] == "complete" and unit["gaps"] == []
    assert unit["totals"]["lines_total"] == unit["totals"]["lines_covered"] == 1
    assert (unit["totals"]["branches_total"], unit["totals"]["branches_covered"]) == (total, 2)
    store = ShardSet(run_root, output["indexes"])
    scope = SimpleNamespace(
        store=store, shard_sha256=lambda shard: shard["sha256"],
        producer=lambda name: SimpleNamespace(shards=store.shards if name == "test_coverage" else ()))
    by_path, by_build, _ = _engineering_context(scope)
    assert len(by_path["src/a.c"]) == len(by_build["u1"]) == 1
    cells = {row["identity"]: row["payload"] for row in store.entities(store.shards, kinds=("coverage_cell",))}
    file_cell = cells[by_path["src/a.c"][0].id]
    aggregate = cells[by_build["u1"][0].id]
    assert file_cell["totals"] == aggregate["totals"] == unit["totals"]
    assert file_cell["file_sha256"] == "1" * 64
    assert file_sha256(run_root / file_cell["artifact_path"]) == file_cell["artifact_sha256"]
    assert (run_root / file_cell["artifact_path"]).read_bytes() == payload


def test_standard_jacoco_header_preserves_accepted_report_and_source_identity(tmp_path):
    from appsec_review.jobs.job_review_prioritization.composite import _load_test_coverage
    from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT
    from appsec_review.runtime.inputs import input_read_scope
    from appsec_review.storage.validation import validation_scope

    payload = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">'
        b'<report name="unit-fixture"><package name="src"><sourcefile name="main.c">'
        b'<counter type="LINE" missed="1" covered="1"/></sourcefile></package></report>')
    run_root, target, snapshot, result, report = _runtime_coverage_fixture(tmp_path, "jacoco.xml", payload)
    context = SimpleNamespace(
        run_root=run_root, config=SimpleNamespace(job_id="job_review_prioritization"),
        contract=CONTRACT, upstream_handoffs={"job_test_coverage": result["handoff_sha256"]})
    with validation_scope(run_root), input_read_scope(context) as reads:
        doc = load_accepted_test_coverage(run_root)
        status, files = _load_test_coverage(run_root, True)
    assert status == "COMPLETED_WITH_GAPS"  # The fixture intentionally disables artifact indexing.
    assert (files["src/main.c"]["lines_total"], files["src/main.c"]["lines_covered"]) == (2, 1)
    row = doc["build_units"][0]["files"][0]
    assert row["format"] == "jacoco" and row["artifact_origin"] == "accepted-input"
    assert row["artifact_sha256"] == file_sha256(report)
    assert report.read_bytes() == payload
    assert row["file_sha256"] == file_sha256(target / "src/main.c")
    assert doc["source_fingerprint"] == snapshot
    assert not any("malformed_coverage" in gap for gap in doc["gaps"])
    assert reads.document()["reads"][0]["handoff_sha256"] == result["handoff_sha256"]
