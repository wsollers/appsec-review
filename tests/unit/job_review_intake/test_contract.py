"""Pin intake's external inputs, complete dataset declarations, graph and file interface."""
from __future__ import annotations

from dataclasses import asdict
from fnmatch import fnmatch
import hashlib
from pathlib import Path
import tomllib

import pytest

from appsec_review.jobs.job_review_intake import build_job
from appsec_review.jobs.job_review_intake import job as intake
from appsec_review.jobs.job_review_intake.datasets import CONSUMES, CONTRACT, DATASETS
from tests.unit.job_review_intake.support import ROOT, artifact, configuration, context, dump, handler, publish_context


def test_every_input_requirement_field_and_dispatch_policy_is_pinned():
    common = {"availability": "optional", "missing": "gap", "coverage": "allow_partial", "channel": "external"}
    assert [asdict(item) for item in CONTRACT.inputs] == [
        {**common, "producer": "job_target_acquisition", "output_kind": "target_acquisition",
         "schema": "appsec-review/target-acquisition/1", "authority": "operational"},
        {**common, "producer": "job_target_acquisition", "output_kind": "system_acquisition",
         "schema": "appsec-review/target-system-acquisition/1", "authority": "operational"},
        {**common, "producer": "binary_publication", "output_kind": "decompilation",
         "schema": "appsec-review/binary-decompilation/1", "authority": "producer_evidence"},
    ]
    assert CONTRACT.schedule_after == ("job_target_acquisition",)
    assert CONTRACT.dispatch == "review_graph" and CONTRACT.target_access == "checkout"
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True
    assert CONSUMES == CONTRACT.consumes == ()


def test_every_dataset_field_is_pinned():
    prefix = "data/jobs/job_review_intake/attempts/*/steps/"
    common = {
        "family": "configuration", "sensitivity": "internal", "disposition": "artifact_only",
        "indexes": (), "shard_prefixes": (), "shard_suffixes": (),
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "required": False, "store": "retrieval", "authority": "producer_evidence",
    }
    assert [asdict(item) for item in DATASETS] == [
        {**common, "output_kind": "model_preflight", "step": "model_preflight",
         "schema": "appsec-review/model-preflight/1",
         "description": "Provider and model availability report for configured model settings.",
         "artifacts": (prefix + "model_preflight/tasks/verify_models/model-preflight.json",),
         "reason": "provider status only; enabled lanes are reported through the dataset inventory"},
        {**common, "output_kind": "binary_evidence", "step": "binary_evidence",
         "schema": "appsec-review/binary-evidence-intake/1",
         "description": "Identity and manifest hash of each configured binary's verified decompilation publication, "
                        "or a binary_decompilation_unavailable gap.",
         "artifacts": (prefix + "binary_evidence/tasks/resolve_publications/binary-evidence.json",),
         "reason": "run binding record with host paths; job_binary_evidence_indexing indexes the publications"},
        {**common, "output_kind": "review_intake", "step": "publish_intake",
         "schema": "appsec-review/review-intake/1",
         "description": "Bound configuration, target identity and source fingerprint for the run.",
         "artifacts": (prefix + "publish_intake/tasks/publish_handoff/review-intake.json",),
         "reason": "run binding record with host paths; its snapshot and hashes are inventory metadata"},
    ]


def test_unit_graph_dependencies_validators_and_schema_match_central_configuration():
    job = build_job()
    expected = {
        "model_preflight.resolve_models": (),
        "model_preflight.verify_models": ("model_preflight.resolve_models",),
        "resolve_configuration.fetch_config": (),
        "resolve_configuration.resolve_layers": ("resolve_configuration.fetch_config",),
        "resolve_configuration.freeze_config": ("resolve_configuration.resolve_layers",),
        "prepare_target.resolve_target": (),
        "prepare_target.validate_target": ("prepare_target.resolve_target",),
        "prepare_target.fingerprint_target": ("prepare_target.validate_target",),
        "binary_evidence.resolve_publications": (),
        "publish_intake.publish_handoff": (
            "model_preflight.verify_models", "resolve_configuration.freeze_config",
            "prepare_target.fingerprint_target", "binary_evidence.resolve_publications"),
    }
    assert {unit.unit_id: unit.dependencies for unit in job.units} == expected
    assert [unit.unit_id for unit in job.units] == list(expected)
    assert [(unit.unit_id, unit.output_validators) for unit in job.units] == [(key, ()) for key in expected]
    assert [unit.handler.__name__ for unit in job.units] == [key.split(".")[1] for key in expected]
    assert (job.job_id, job.name, job.schema_identity) == (
        "job_review_intake", "review_intake", "appsec-review/review-intake-job/3")
    assert job.strict_gaps is True and job.always_execute is False and job.propagate_handoff is True
    assert job.datasets is DATASETS and job.contract is CONTRACT and job.consumes == ()
    assert job.external_input_identity is intake.external_input_identity
    assert job.implementation_identity is None and job.validation_identity is None
    assert [validator.__name__ for validator in job.input_validators] == ["validate"]
    # Intake has no job/unit output validator or custom result transform; pin that absence.
    assert job.output_validators == () and job.result_transform is None
    original = {"schema": "appsec-review/job-result/1", "outputs": {"fixture": 2}}
    assert job.finalize_result(None, original) is original
    raw = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["jobs"][job.job_id]
    assert tuple(raw["steps"]) == tuple(intake.TOPOLOGY)
    assert {step: tuple(value["tasks"]) for step, value in raw["steps"].items()} == intake.TOPOLOGY


@pytest.mark.parametrize(("kind", "unit_id", "filename"), [
    ("model_preflight", "model_preflight.verify_models", "model-preflight.json"),
    ("binary_evidence", "binary_evidence.resolve_publications", "binary-evidence.json"),
    ("review_intake", "publish_intake.publish_handoff", "review-intake.json"),
], ids=["models", "binaries", "intake"])
def test_handler_publication_file_schema_and_glob_are_declared(tmp_path, kind, unit_id, filename):
    kwargs = {}
    if kind == "review_intake":
        unit = publish_context(tmp_path)
    else:
        unit = context(tmp_path, unit_id, {
            "model_preflight.resolve_models": {"required": [], "not_required": []}})
        configuration(unit.job.run_root)
        kwargs["check_models"] = lambda *a, **k: pytest.fail("no models should be checked")
    result = handler(unit_id, **kwargs)(unit)
    document = artifact(unit, result)
    declaration = next(item for item in DATASETS if item.output_kind == kind)
    assert result["schema"] == document["schema"] == declaration.schema
    assert list(unit.unit_root.iterdir()) == [unit.unit_root / filename]
    relative = result["artifact"]["path"]
    assert any(fnmatch(relative, pattern) for pattern in declaration.artifacts)
    assert not any(fnmatch(relative.replace("job_review_intake", "job_other"), pattern)
                   for pattern in declaration.artifacts)


@pytest.mark.parametrize(("unit_id", "read_names"), [
    ("model_preflight.resolve_models", ["manifest.json", "resolved.json"]),
    ("resolve_configuration.fetch_config", ["manifest.json"]),
    ("resolve_configuration.resolve_layers", ["host-pins.toml", "manifest.json", "resolved.json"]),
    ("resolve_configuration.freeze_config", ["appsec-review.toml"]),
    ("binary_evidence.resolve_publications", ["manifest.json", "resolved.json"]),
], ids=["models", "fetch", "layers", "freeze", "binaries"])
def test_handler_configuration_file_reads_are_exact(tmp_path, monkeypatch, unit_id, read_names):
    unit = context(tmp_path, unit_id)
    _, manifest = configuration(unit.job.run_root)
    unit.outputs.update({
        "resolve_configuration.fetch_config": manifest["sources"][0],
        "resolve_configuration.resolve_layers": {"layers": manifest["sources"], "profile": "dev"}})
    original = Path.open
    observed = set()
    directory = unit.job.run_root / "data/configuration"

    def traced(path, mode="r", *args, **kwargs):
        if path.parent == directory and mode.startswith("r"):
            observed.add(path.name)
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", traced)
    result = handler(unit_id)(unit)
    assert sorted(observed) == read_names
    assert isinstance(result, dict)


def track_reads(monkeypatch):
    observed = set()
    original = Path.open

    def traced(path, mode="r", *args, **kwargs):
        if mode.startswith("r"):
            observed.add(path)
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", traced)
    return observed


@pytest.mark.parametrize("task", ["resolve_target", "validate_target", "fingerprint_target"],
                         ids=["resolve", "validate", "fingerprint"])
def test_target_handler_file_interface_is_bounded_to_target_and_frozen_configuration(tmp_path, monkeypatch, task):
    from appsec_review.target_acquisition import acquire
    unit = context(tmp_path, f"prepare_target.{task}", {"prepare_target.validate_target": {"file_count": 1}})
    path = unit.job.target_root / "main.py"
    path.write_text("answer = 42\n", encoding="utf-8")
    configuration(unit.job.run_root)
    unit.job.source_fingerprint = intake.source_fingerprint(unit.job.target_root)
    monkeypatch.setattr(acquire, "intake_record", lambda **kwargs: None)
    observed = track_reads(monkeypatch)
    result = handler(unit.unit_id)(unit)
    expected = set() if task == "resolve_target" else {path}
    if task == "fingerprint_target":
        expected.update(unit.job.run_root / f"data/configuration/{name}" for name in ("manifest.json", "resolved.json"))
        assert result["sha256"] == unit.job.source_fingerprint and result["acquisition"] is None
    elif task == "validate_target":
        assert result["file_count"] == 1 and result["total_bytes"] == 12
    else:
        assert result == {"path": str(unit.job.target_root), "kind": "directory"}
    assert observed == expected
    assert list(unit.unit_root.iterdir()) == []


def test_binary_handler_reads_verified_publication_manifest_and_records_only_its_declared_output(tmp_path, monkeypatch):
    from appsec_review import binary_decompilation
    from appsec_review.runtime import inputs
    unit = context(tmp_path, "binary_evidence.resolve_publications")
    document = {"runtime": {"data_dir": "data"}, "binary_decompilation": {"binaries": [{
        "id": "vendor", "path": "fixture.so", "sha256": "b" * 64, "authorization": "synthetic fixture"}]}}
    configuration(unit.job.run_root, document)
    store = binary_decompilation.store_root(tmp_path / "data")
    manifest_path = store / "fixture/manifest.json"
    dump(manifest_path, {"request": {}, "program": {"language": "fixture"}})
    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    monkeypatch.setattr(binary_decompilation, "resolve_current", lambda *args: {
        "path": str(manifest_path.parent), "identity": "fixture", "manifest_sha256": manifest_sha,
        "coverage": {}, "gaps": []})
    receipts = []
    monkeypatch.setattr(inputs, "observe_external", lambda *args: receipts.append(args))
    observed = track_reads(monkeypatch)
    result = handler(unit.unit_id)(unit)
    assert observed == {
        unit.job.run_root / "data/configuration/manifest.json",
        unit.job.run_root / "data/configuration/resolved.json",
        manifest_path, unit.unit_root / "binary-evidence.json"}
    assert list(unit.unit_root.iterdir()) == [unit.unit_root / "binary-evidence.json"]
    assert result["binaries"][0]["manifest_sha256"] == manifest_sha
    assert receipts == [(unit.job.run_root, "binary_publication", "decompilation",
                         "appsec-review/binary-decompilation/1", {
                             "binary_id": "vendor", "binary_sha256": "b" * 64, "manifest_sha256": manifest_sha})]


def test_acquisition_copy_is_a_hashed_external_input_not_an_undeclared_dataset(tmp_path, monkeypatch):
    from appsec_review.runtime import inputs
    from appsec_review.target_acquisition import acquire
    unit = context(tmp_path, "prepare_target.fingerprint_target", {"prepare_target.validate_target": {"file_count": 1}})
    path = unit.job.target_root / "main.py"
    path.write_text("answer = 42\n", encoding="utf-8")
    configuration(unit.job.run_root)
    unit.job.source_fingerprint = intake.source_fingerprint(unit.job.target_root)
    schema = "appsec-review/target-acquisition/1"
    destination = unit.unit_root / "target-acquisition.json"
    receipts = []

    def copy_record(**kwargs):
        assert kwargs["destination"] == destination
        dump(destination, {"schema": schema, "fixture": "copied-input"})
        return {"schema": schema, "manifest": "target-acquisition.json", "gaps": []}

    monkeypatch.setattr(acquire, "intake_record", copy_record)
    monkeypatch.setattr(inputs, "observe_external", lambda *args: receipts.append(args))
    observed = track_reads(monkeypatch)
    result = handler(unit.unit_id)(unit)
    assert observed == {
        path, unit.job.run_root / "data/configuration/manifest.json",
        unit.job.run_root / "data/configuration/resolved.json", destination}
    relative = destination.relative_to(unit.job.run_root).as_posix()
    assert list(unit.unit_root.iterdir()) == [destination]
    assert result["acquisition"] == {"schema": schema, "manifest": relative, "gaps": []}
    assert receipts == [(unit.job.run_root, "job_target_acquisition", "target_acquisition", schema,
                         {"path": relative, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})]
    assert not any(fnmatch(relative, pattern) for declaration in DATASETS for pattern in declaration.artifacts)
