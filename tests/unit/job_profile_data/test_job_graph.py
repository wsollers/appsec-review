"""job_profile_data: validators, settings, step handlers, shard reuse, and accepted loader."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import PROFILE_DATA_HANDOFF_SCHEMA
from appsec_review.jobs.job_profile_data import (
    ProfileIntegrityError,
    build_job,
    job as job_module,
    load_accepted_profile_data,
)
from appsec_review.jobs.job_profile_data.job import (
    _fallback_upstream_manifest,
    _load_catalog_identity,
    _settings,
    _validate_config,
)
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff


def _identity(run_root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def _uctx(job_ctx: object, unit_id: str, outputs: dict[str, object]) -> UnitContext:
    step_id, task_id = unit_id.split(".", 1)
    unit_root = job_ctx.attempt_root / "steps" / step_id / "tasks" / task_id
    return UnitContext(job_ctx, unit_id, step_id, task_id, unit_root, outputs)


def _write_catalog(
    run_root: Path,
    *,
    snapshot: str = "snap-1",
    schema: str = "appsec-review/target-catalog/1",
    include_manifest: bool = True,
) -> tuple[str, dict[str, object] | None]:
    attempt = run_root / "data/jobs/job_target_catalog/attempts/attempt_0001"
    manifest_ref = None
    artifacts: list[dict[str, object]] = []
    if include_manifest:
        manifest_path = run_root / "data/indices/manifests/catalog.json"
        write_manifest(manifest_path, run_id=run_root.name, target_snapshot=snapshot, target_root=run_root, indexes=())
        manifest_ref = _identity(run_root, manifest_path)
        artifacts.append(manifest_ref)
    catalog_path = attempt / "artifacts/catalog.json"
    atomic_json(catalog_path, {"schema": schema, "source_fingerprint": snapshot, "artifacts": {}})
    catalog_ref = _identity(run_root, catalog_path)
    artifacts.append(catalog_ref)
    pub_out: dict[str, object] = {"artifact": catalog_ref}
    if manifest_ref is not None:
        pub_out["index_manifest"] = manifest_ref
    handoff = attempt / "handoff.json"
    atomic_json(
        attempt / "claim.json",
        {
            "dataset_contract": dataset_contract(
                "job_target_catalog",
                sorted({item.step for item in CATALOG_DATASETS}),
                tuple(replace(item, required=False) for item in CATALOG_DATASETS),
            )
        },
    )
    write_fixture_handoff(
        run_root,
        handoff,
        {
            "run_id": run_root.name,
            "source_fingerprint": snapshot,
            "status": "ACCEPTED",
            "job_id": "job_target_catalog",
            "attempt_id": "attempt_0001",
            "outputs": {"publish_catalog.publish_handoff": pub_out},
            "artifacts": artifacts,
        },
    )
    sha = file_sha256(handoff)
    atomic_json(
        run_root / "data/jobs/job_target_catalog/latest.json",
        {"handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": sha},
    )
    return sha, manifest_ref


def test_validate_config_and_settings_accept_central_config_and_reject_drift() -> None:
    central = load_config("appsec-review.toml").job("job_profile_data")
    _validate_config(SimpleNamespace(config=central), None)
    bounds = _settings(SimpleNamespace(job=SimpleNamespace(config=central)))
    assert bounds.max_artifacts == 256 and bounds.max_frames_per_sample == 256

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
        ctx = SimpleNamespace(config=SimpleNamespace(steps=central.steps, step=central.step, settings=mutated))
        with pytest.raises(ValueError, match=match):
            _validate_config(ctx, None)

    with pytest.raises(ValueError, match="bounds are invalid"):
        _settings(SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(settings={"bounds": "bad"}))))


def test_load_catalog_identity_and_fallback_manifest_enforce_integrity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = build_job()
    bad_sha, _ = _write_catalog(tmp_path, schema="wrong/1")
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": bad_sha}, contract=job.contract):
        with pytest.raises(ProfileIntegrityError, match="schema is unsupported"):
            _load_catalog_identity(tmp_path)

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
    with pytest.raises(ProfileIntegrityError, match="not bound to its handoff"):
        _load_catalog_identity(tmp_path)

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
    with pytest.raises(ProfileIntegrityError, match="upstream index manifest is unavailable"):
        _fallback_upstream_manifest(no_input, None)


def test_handlers_handle_disabled_upstreams_snapshot_mismatch_shard_reuse_and_not_applicable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = "snap-1"
    cat_sha, _ = _write_catalog(tmp_path, snapshot=snapshot)
    config = load_config("appsec-review.toml").job("job_profile_data")
    job = build_job()
    by_id = {u.unit_id: u.handler for u in job.units}

    wrong_ctx = SimpleNamespace(
        run_root=tmp_path,
        run_id=tmp_path.name,
        attempt_id="attempt_0001",
        attempt_root=tmp_path / "data/jobs/job_profile_data/attempts/attempt_0001",
        source_fingerprint="other-snap",
        target_root=tmp_path,
        repository_root=tmp_path,
        config=config,
        input_manifest_path=None,
        input_manifest_sha256=None,
    )
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        with pytest.raises(ProfileIntegrityError, match="differs from the accepted target snapshot"):
            by_id["load.accepted_inputs"](_uctx(wrong_ctx, "load.accepted_inputs", {}))

    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, _p: False)
    ctx = SimpleNamespace(**{**wrong_ctx.__dict__, "source_fingerprint": snapshot})
    outputs: dict[str, object] = {}
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.profile_data", "index.profile_data", "acceptance.publish_handoff"):
            outputs[uid] = by_id[uid](_uctx(ctx, uid, outputs))
    pub = outputs["acceptance.publish_handoff"]
    assert pub["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("language_build_unavailable" in gap for gap in pub["gaps"])
    assert any("artifact_indexing_unavailable" in gap for gap in pub["gaps"])

    monkeypatch.setattr("appsec_review.runtime.consume.has_accepted_upstream", lambda _r, p: p == "job_language_build")
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _r: {"source_fingerprint": "wrong", "language_build_handoff_sha256": "2" * 64, "receipts": ()},
    )
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        with pytest.raises(ProfileIntegrityError, match="differs from the accepted target snapshot"):
            by_id["load.accepted_inputs"](_uctx(ctx, "load.accepted_inputs", {}))

    prior_shard = tmp_path / "data/indices/analysis/prior.sqlite"
    stale_prof = IndexBuilder(
        prior_shard, name="analysis", fingerprint="e" * 64, target_snapshot=snapshot, shard_id="profile-data-old"
    )
    stale_prof.add_coverage("profile-data:old", "complete")
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
            IndexIdentity("analysis", "appsec-review/retrieval-index/2", stale_prof.build(), "e" * 64,
                          prior_shard.relative_to(tmp_path).as_posix(), {"job": "job_profile_data"}, (), "profile-data-old"),
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
                              "attempt_root": tmp_path / "data/jobs/job_profile_data/attempts/attempt_0002"})
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.profile_data", "index.profile_data", "acceptance.publish_handoff"):
            clean_out[uid] = by_id[uid](_uctx(ctx2, uid, clean_out))
    assert clean_out["acceptance.publish_handoff"]["terminal_status"] == "NOT_APPLICABLE"
    written_manifest = json.loads((tmp_path / clean_out["index.profile_data"]["index_manifest"]["path"]).read_text())
    assert [idx["shard_id"] for idx in written_manifest["indexes"]] == ["catalog-1"]

    folded = tmp_path / "data/build/u1/hot.folded"
    folded.parent.mkdir(parents=True, exist_ok=True)
    folded.write_bytes(b"main;hot 5\n")
    folded_ref = {**_identity(tmp_path, folded), "workspace_path": "hot.folded", "kind": "execution-profile"}
    monkeypatch.setattr(
        job_module,
        "load_accepted_language_build",
        lambda _r: {
            "source_fingerprint": snapshot,
            "language_build_handoff_sha256": "2" * 64,
            "receipts": [{"build_unit_id": "u1", "family": "native", "root": ".", "terminal_status": "SUCCEEDED",
                          "artifacts": [folded_ref]}],
        },
    )
    first_out: dict[str, object] = {}
    ctx3 = SimpleNamespace(**{**ctx.__dict__, "attempt_id": "attempt_0003",
                              "attempt_root": tmp_path / "data/jobs/job_profile_data/attempts/attempt_0003"})
    with upstream_scope(tmp_path, job.job_id, {"job_target_catalog": cat_sha}, contract=job.contract):
        for uid in ("load.accepted_inputs", "normalize.profile_data", "index.profile_data"):
            first_out[uid] = by_id[uid](_uctx(ctx3, uid, first_out))
        ctx4 = SimpleNamespace(**{**ctx3.__dict__, "attempt_id": "attempt_0004",
                                  "attempt_root": tmp_path / "data/jobs/job_profile_data/attempts/attempt_0004"})
        second_out: dict[str, object] = {}
        for uid in ("load.accepted_inputs", "normalize.profile_data", "index.profile_data"):
            second_out[uid] = by_id[uid](_uctx(ctx4, uid, second_out))
    assert first_out["index.profile_data"]["indexes"][0]["sha256"] == (
        second_out["index.profile_data"]["indexes"][0]["sha256"]
    )


def test_accepted_publication_verifies_handoff_artifact_manifest_and_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = "snapshot"
    shard = tmp_path / "data/indices/analysis/profile.sqlite"
    builder = IndexBuilder(shard, name="analysis", fingerprint="f" * 64, target_snapshot=snapshot, shard_id="profile-data-u")
    builder.add_coverage("profile-data:u", "complete")
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", builder.build(), "f" * 64,
                          shard.relative_to(tmp_path).as_posix(), {"job": "job_profile_data"}, (), "profile-data-u")
    manifest = tmp_path / "data/indices/manifests/profile.json"
    write_manifest(manifest, run_id=tmp_path.name, target_snapshot=snapshot, target_root=tmp_path, indexes=(index,))
    attempt = tmp_path / "data/jobs/job_profile_data/attempts/attempt_0001"
    summary = attempt / "artifacts/profile-data/accepted-profile-data.json"
    summary.parent.mkdir(parents=True)
    atomic_json(
        summary,
        {
            "schema": PROFILE_DATA_HANDOFF_SCHEMA,
            "source_fingerprint": snapshot,
            "semantics": "context_only",
            "build_units": [],
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
            "run_id": tmp_path.name,
            "source_fingerprint": snapshot,
            "status": "ACCEPTED",
            "job_id": "job_profile_data",
            "attempt_id": "attempt_0001",
            "outputs": {"acceptance.publish_handoff": {"artifact": summary_identity, "index_manifest": manifest_identity}},
            "artifacts": [summary_identity, manifest_identity],
        },
    )
    latest = tmp_path / "data/jobs/job_profile_data/latest.json"
    atomic_json(latest, {"handoff_path": handoff.relative_to(tmp_path).as_posix(), "handoff_sha256": file_sha256(handoff)})
    assert load_accepted_profile_data(tmp_path)["handoff_sha256"] == file_sha256(handoff)

    atomic_json(
        summary,
        {
            "schema": PROFILE_DATA_HANDOFF_SCHEMA,
            "source_fingerprint": snapshot,
            "semantics": "finding_probability",
            "build_units": [],
            "gaps": [],
            "index_manifest": _identity(tmp_path, manifest),
        },
    )
    new_summary_identity = _identity(tmp_path, summary)
    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: (
            {
                "outputs": {"acceptance.publish_handoff": {"artifact": new_summary_identity, "index_manifest": manifest_identity}},
                "artifacts": [new_summary_identity, manifest_identity],
            },
            "h",
        ),
    )
    with pytest.raises(ProfileIntegrityError, match="schema or semantics is unsupported"):
        load_accepted_profile_data(tmp_path)

    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: ({"outputs": {"acceptance.publish_handoff": {}}, "artifacts": []}, "h"),
    )
    with pytest.raises(ProfileIntegrityError, match="publication is unavailable"):
        load_accepted_profile_data(tmp_path)

    monkeypatch.setattr(
        job_module,
        "_accepted_handoff",
        lambda _r, _j: (
            {
                "outputs": {"acceptance.publish_handoff": {"artifact": new_summary_identity, "index_manifest": manifest_identity}},
                "artifacts": [new_summary_identity],
            },
            "h",
        ),
    )
    with pytest.raises(ProfileIntegrityError, match="not bound to its handoff"):
        load_accepted_profile_data(tmp_path)

    monkeypatch.undo()
    with pytest.raises(ProfileIntegrityError, match="identity changed"):
        load_accepted_profile_data(tmp_path)
