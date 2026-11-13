"""job_artifact_indexing: the unit graph, the configuration validator, the ``load`` handler's
wiring and the two accepted-handoff readers, with the upstream consumers faked at the module
boundary (``accepted_upstream``, the language-build loader, the intake reader)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import (
    _TOPOLOGY, SCHEMA, ArtifactIndexIntegrityError, _accepted_language_manifest, _validate_config, build_job,
    load_accepted_artifact_index,
)
from appsec_review.retrieval import write_manifest
from appsec_review.runtime import consume
from appsec_review.storage import atomic_json, file_sha256
from tests.unit.job_artifact_indexing.support import RUN_ID, SETTINGS, SNAPSHOT, identity, recorded_receipt, unit_context

ROOT = Path(__file__).resolve().parents[3]


# --- graph shape -----------------------------------------------------------------------------------

def test_graph_is_load_then_three_index_branches_joined_by_publication() -> None:
    job = build_job()
    units = {unit.unit_id: unit for unit in job.units}
    assert {unit_id: unit.dependencies for unit_id, unit in units.items()} == {
        "load.accepted_builds": (), "index.catalogs": ("load.accepted_builds",),
        "index.members": ("load.accepted_builds",), "index.relationships": ("load.accepted_builds",),
        "acceptance.publish_handoff": ("index.catalogs", "index.members", "index.relationships")}
    assert all(unit.input_validators == () and unit.output_validators == () for unit in units.values())
    assert _TOPOLOGY == {"load": ("accepted_builds",), "index": ("catalogs", "members", "relationships"),
                         "acceptance": ("publish_handoff",)}
    assert job.input_validators == (_validate_config,) and job.output_validators == ()
    assert (job.job_id, job.name, job.schema_identity) == ("job_artifact_indexing", "artifact_indexing", SCHEMA)
    assert job.implementation_identity is None and job.validation_identity is None
    assert units["index.catalogs"].handler is job_module._catalogs
    assert units["index.members"].handler is job_module._members
    assert units["index.relationships"].handler is job_module._relationships


# --- _validate_config --------------------------------------------------------------------------------

def _job_config(steps: dict[str, tuple[str, ...]], settings: dict[str, object]) -> SimpleNamespace:
    configured = {step: SimpleNamespace(tasks={task: None for task in tasks}) for step, tasks in steps.items()}
    return SimpleNamespace(config=SimpleNamespace(steps=configured, settings=settings, step=lambda name: configured[name]))


def test_shipped_configuration_passes_validation_and_names_the_six_identities() -> None:
    job = load_config(ROOT / "appsec-review.toml").job("job_artifact_indexing")
    _validate_config(SimpleNamespace(config=job), None)
    assert set(job.settings) == set(SETTINGS)
    assert tuple(job.steps) == ("load", "index", "acceptance")


def test_validation_refuses_a_changed_topology_task_order_or_identity_set() -> None:
    good = {"load": ("accepted_builds",), "index": ("catalogs", "members", "relationships"), "acceptance": ("publish_handoff",)}
    _validate_config(_job_config(good, SETTINGS), None)
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(_job_config({"index": good["index"], "load": good["load"], "acceptance": good["acceptance"]}, SETTINGS), None)
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(_job_config({**good, "extra": ("x",)}, SETTINGS), None)
    with pytest.raises(ValueError, match="task order mismatch: index"):
        _validate_config(_job_config({**good, "index": ("members", "catalogs", "relationships")}, SETTINGS), None)
    with pytest.raises(ValueError, match="task order mismatch: acceptance"):
        _validate_config(_job_config({**good, "acceptance": ("publish_handoff", "extra")}, SETTINGS), None)
    for settings in ({key: value for key, value in SETTINGS.items() if key != "mapping_identity"},
                     {**SETTINGS, "extra_identity": "x/1"}, {**SETTINGS, "normalizer_identity": ""},
                     {**SETTINGS, "catalog_parser_identity": 1}):
        with pytest.raises(ValueError, match="identities are invalid"):
            _validate_config(_job_config(good, settings), None)


# --- the load handler --------------------------------------------------------------------------------

def _load():
    return {unit.unit_id: unit.handler for unit in build_job().units}["load.accepted_builds"]


@pytest.fixture
def upstream(monkeypatch, tmp_path: Path):
    """Fake the three upstream readers; the receipt validation itself runs for real."""
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    state = SimpleNamespace(run_root=run_root, accepted=None,
                            manifest={"path": "data/indices/manifests/language-build.json", "sha256": "0" * 64},
                            intake=([], ["accepted target artifact intake is unavailable"], None), calls=[])
    monkeypatch.setattr(job_module, "load_accepted_language_build",
                        lambda root: state.calls.append(("language", root)) or state.accepted)
    monkeypatch.setattr(job_module, "_accepted_language_manifest",
                        lambda root: state.calls.append(("manifest", root)) or state.manifest)
    monkeypatch.setattr(job_module, "_target_artifacts", lambda unit: state.calls.append(("intake", unit)) or state.intake)
    return state


def test_load_validates_receipts_merges_gaps_in_order_and_binds_the_upstream_manifest(upstream) -> None:
    receipt = recorded_receipt(upstream.run_root)
    upstream.accepted = {"source_fingerprint": SNAPSHOT, "receipts": [receipt], "gaps": [{"reason": "plan gap"}, "plan gap"],
                         "language_build_handoff_sha256": "f" * 64}
    unit = unit_context(upstream.run_root, "load.accepted_builds")
    result = _load()(unit)
    assert [kind for kind, _ in upstream.calls] == ["language", "manifest", "intake"]
    assert upstream.calls[0][1] == upstream.run_root and upstream.calls[2][1] is unit
    assert result["receipt_count"] == 1 and [item["workspace_path"] for item in result["receipts"][0]["validated_artifacts"]] == [
        "build/main.o", "build/app"]
    assert result["producer_gaps"] == ["plan gap", "accepted target artifact intake is unavailable"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert (result["target_artifacts"], result["target_catalog_handoff_sha256"]) == ([], None)
    assert result["language_build_handoff_sha256"] == "f" * 64
    assert result["upstream_manifest"] == upstream.manifest


def test_load_succeeds_without_gaps_when_the_intake_is_present_and_names_an_empty_receipt_set(upstream) -> None:
    upstream.accepted = {"source_fingerprint": SNAPSHOT, "receipts": [recorded_receipt(upstream.run_root)], "gaps": [],
                         "language_build_handoff_sha256": "f" * 64}
    upstream.intake = ([{"target_relative_path": "x.wasm"}], [], "c" * 64)
    result = _load()(unit_context(upstream.run_root, "load.accepted_builds"))
    assert result["terminal_status"] == "SUCCEEDED" and result["producer_gaps"] == []
    assert result["target_artifacts"] == [{"target_relative_path": "x.wasm"}] and result["target_catalog_handoff_sha256"] == "c" * 64
    upstream.accepted["receipts"] = []
    result = _load()(unit_context(upstream.run_root, "load.accepted_builds"))
    assert result["receipt_count"] == 0 and result["receipts"] == []
    assert result["producer_gaps"] == ["accepted language-build handoff contained no receipts"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_load_refuses_a_language_build_of_another_snapshot_before_reading_anything_else(upstream) -> None:
    upstream.accepted = {"source_fingerprint": "other", "receipts": [], "gaps": [], "language_build_handoff_sha256": "f" * 64}
    with pytest.raises(ArtifactIndexIntegrityError, match="target snapshot differs from language-build"):
        _load()(unit_context(upstream.run_root, "load.accepted_builds"))
    assert [kind for kind, _ in upstream.calls] == ["language"]


def test_load_propagates_receipt_rejections(upstream) -> None:
    receipt = recorded_receipt(upstream.run_root)
    receipt["source_fingerprint"] = "0" * 64
    upstream.accepted = {"source_fingerprint": SNAPSHOT, "receipts": [receipt], "gaps": [], "language_build_handoff_sha256": "f" * 64}
    with pytest.raises(ArtifactIndexIntegrityError, match="target snapshot changed"):
        _load()(unit_context(upstream.run_root, "load.accepted_builds"))


# --- the accepted-handoff readers --------------------------------------------------------------------

def _fake_upstream(monkeypatch, run_root: Path, handoff: dict | None, *, digest: str = "e" * 64, raising: str | None = None):
    def accepted_upstream(root, job_id, **_):
        assert Path(root) == run_root
        if raising:
            raise ValueError(raising)
        return SimpleNamespace(handoff=handoff, sha256=digest, job_id=job_id)
    monkeypatch.setattr(consume, "accepted_upstream", accepted_upstream)


def _manifest(run_root: Path, name: str = "language-build.json") -> tuple[Path, dict]:
    path = run_root / "data/indices/manifests" / name
    write_manifest(path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=run_root.parent, indexes=[])
    return path, identity(run_root, path)


def test_accepted_language_manifest_requires_a_bound_verified_index_manifest(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    path, reference = _manifest(run_root)
    handoff = {"outputs": {"acceptance.publish_handoff": {"index_manifest": reference}}, "artifacts": [reference]}
    _fake_upstream(monkeypatch, run_root, handoff)
    assert _accepted_language_manifest(run_root) == {"path": reference["path"], "sha256": reference["sha256"]}
    _fake_upstream(monkeypatch, run_root, {**handoff, "artifacts": []})
    with pytest.raises(ArtifactIndexIntegrityError, match="not bound to its accepted handoff"):
        _accepted_language_manifest(run_root)
    _fake_upstream(monkeypatch, run_root, {**handoff, "outputs": {"acceptance.publish_handoff": {}}})
    with pytest.raises(ArtifactIndexIntegrityError, match="index manifest is required"):
        _accepted_language_manifest(run_root)
    _fake_upstream(monkeypatch, run_root, {**handoff, "outputs": {
        "acceptance.publish_handoff": {"index_manifest": {**reference, "sha256": "0" * 64}}}})
    with pytest.raises(ArtifactIndexIntegrityError, match="index manifest hash mismatch"):
        _accepted_language_manifest(run_root)
    _fake_upstream(monkeypatch, run_root, None, raising="undeclared consumption")
    with pytest.raises(ArtifactIndexIntegrityError, match="handoff is required: undeclared consumption"):
        _accepted_language_manifest(run_root)
    path.write_text(json.dumps({"schema": "appsec-review/index-manifest/1", "indexes": []}), encoding="utf-8")
    _fake_upstream(monkeypatch, run_root, handoff)
    with pytest.raises(ValueError, match="mismatch"):
        _accepted_language_manifest(run_root)


def test_load_accepted_artifact_index_returns_the_summary_bound_to_the_accepted_handoff(tmp_path: Path, monkeypatch) -> None:
    run_root = tmp_path / RUN_ID
    run_root.mkdir()
    _, manifest = _manifest(run_root, "artifact-indexing-attempt_0001.json")
    summary_path = run_root / "data/jobs/job_artifact_indexing/attempts/attempt_0001/artifacts/artifact-indexing/accepted-index.json"
    document = {"schema": SCHEMA, "source_fingerprint": SNAPSHOT, "artifact_count": 2, "artifact_shard_count": 3,
                "gaps": ["g"], "index_manifest": manifest}
    atomic_json(summary_path, document)
    summary = identity(run_root, summary_path)
    handoff = {"outputs": {"acceptance.publish_handoff": {"artifact": summary, "index_manifest": manifest}},
               "artifacts": [summary, manifest]}
    _fake_upstream(monkeypatch, run_root, handoff, digest="e" * 64)
    assert load_accepted_artifact_index(run_root) == {**document, "handoff_sha256": "e" * 64}
    _fake_upstream(monkeypatch, run_root, {**handoff, "artifacts": [manifest]})
    with pytest.raises(ArtifactIndexIntegrityError, match="summary is not bound to its accepted handoff"):
        load_accepted_artifact_index(run_root)
    _fake_upstream(monkeypatch, run_root, {**handoff, "outputs": {"acceptance.publish_handoff": {"artifact": summary}}})
    with pytest.raises(ValueError, match="publication is unavailable"):
        load_accepted_artifact_index(run_root)
    _fake_upstream(monkeypatch, run_root, {**handoff, "outputs": {}})
    with pytest.raises(ValueError, match="publication is unavailable"):
        load_accepted_artifact_index(run_root)
    atomic_json(summary_path, {**document, "schema": "appsec-review/artifact-indexing/0"})
    rebound = identity(run_root, summary_path)
    _fake_upstream(monkeypatch, run_root, {"outputs": {"acceptance.publish_handoff": {"artifact": rebound, "index_manifest": manifest}},
                                           "artifacts": [rebound, manifest]})
    with pytest.raises(ValueError, match="schema is unsupported"):
        load_accepted_artifact_index(run_root)
    summary_path.write_bytes(summary_path.read_bytes() + b"\n")
    _fake_upstream(monkeypatch, run_root, handoff)
    with pytest.raises(ArtifactIndexIntegrityError, match="summary hash mismatch"):
        load_accepted_artifact_index(run_root)
    assert file_sha256(summary_path) != summary["sha256"]
