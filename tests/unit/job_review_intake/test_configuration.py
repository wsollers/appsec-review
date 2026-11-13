"""Configuration topology, bounded preflight settings, frozen hashes and layer allowlists."""
from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_review_intake import job as intake
from tests.unit.job_review_intake.support import configuration, context, dump, handler


@pytest.mark.parametrize("timeout", [1, 120, 600], ids=["lower", "default", "upper"])
def test_input_validator_accepts_exact_topology_and_inclusive_timeout_bounds(tmp_path, timeout):
    unit = context(tmp_path, "resolve_configuration.fetch_config")
    unit.job.config.settings["model_preflight"]["timeout_seconds"] = timeout
    validator, = intake.build_job().input_validators
    assert validator(unit.job, None) is None


@pytest.mark.parametrize("settings", [
    None, [], {}, {"timeout_seconds": 1, "extra": 0}, {"timeout_seconds": True},
    {"timeout_seconds": 0}, {"timeout_seconds": 601}, {"timeout_seconds": "1"}, {"timeout_seconds": 1.0},
], ids=["absent", "list", "empty", "extra", "boolean", "below", "above", "string", "float"])
def test_input_validator_rejects_malformed_preflight_settings(tmp_path, settings):
    unit = context(tmp_path, "resolve_configuration.fetch_config")
    unit.job.config.settings["model_preflight"] = settings
    with pytest.raises(ValueError, match="review intake model preflight settings are invalid"):
        intake.build_job().input_validators[0](unit.job, None)


@pytest.mark.parametrize("change", ["step-order", "step-missing", "task-order"])
def test_input_validator_refuses_configuration_topology_drift(tmp_path, change):
    unit = context(tmp_path, "resolve_configuration.fetch_config")
    if change == "step-order":
        unit.job.config.steps = dict(reversed(list(unit.job.config.steps.items())))
    elif change == "step-missing":
        unit.job.config.steps.pop("binary_evidence")
    else:
        unit.job.config.steps["model_preflight"] = SimpleNamespace(tasks=("verify_models", "resolve_models"))
    message = ("task order mismatch: model_preflight" if change == "task-order"
               else "topology does not match configuration")
    with pytest.raises(ValueError, match=message):
        intake.build_job().input_validators[0](unit.job, None)


def test_resolved_configuration_checks_exact_bytes_against_manifest(tmp_path):
    document, _ = configuration(tmp_path)
    assert intake.resolved_configuration(tmp_path) == document
    (tmp_path / "data/configuration/resolved.json").write_text('{"jobs": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="run-owned resolved configuration hash mismatch"):
        intake.resolved_configuration(tmp_path)


@pytest.mark.parametrize("failure", ["manifest-missing", "manifest-json", "resolved-missing", "resolved-json"])
def test_resolved_configuration_propagates_scoped_file_and_json_errors(tmp_path, failure):
    _, manifest = configuration(tmp_path)
    directory = tmp_path / "data/configuration"
    if failure == "manifest-missing":
        (directory / "manifest.json").unlink()
    elif failure == "manifest-json":
        (directory / "manifest.json").write_text("{", encoding="utf-8")
    elif failure == "resolved-missing":
        (directory / "resolved.json").unlink()
    else:
        (directory / "resolved.json").write_text("{", encoding="utf-8")
        manifest["resolved_sha256"] = hashlib.sha256(b"{").hexdigest()
        dump(directory / "manifest.json", manifest)
    expected = FileNotFoundError if failure.endswith("missing") else json.JSONDecodeError
    with pytest.raises(expected) as error:
        intake.resolved_configuration(tmp_path)
    if failure.endswith("missing"):
        assert error.value.filename.endswith(f"{failure.split('-')[0]}.json")
    else:
        assert error.value.doc == "{"


def test_fetch_config_reads_first_manifest_source_and_freeze_hashes_exact_toml(tmp_path):
    unit = context(tmp_path, "resolve_configuration.fetch_config")
    _, manifest = configuration(unit.job.run_root)
    assert handler(unit.unit_id)(unit) == manifest["sources"][0]
    frozen = context(tmp_path, "resolve_configuration.freeze_config", {
        "resolve_configuration.resolve_layers": {"layers": manifest["sources"], "profile": "dev"}})
    result = handler(frozen.unit_id)(frozen)
    assert result == {
        "path": "data/configuration/appsec-review.toml",
        "sha256": hashlib.sha256((unit.job.run_root / "data/configuration/appsec-review.toml").read_bytes()).hexdigest(),
        "layers": manifest["sources"], "profile": "dev",
    }


def layers_fixture(tmp_path, *, profile=False, overlay=False):
    unit = context(tmp_path, "resolve_configuration.resolve_layers")
    document, manifest = configuration(unit.job.run_root)
    sources = manifest["sources"]
    if profile:
        record = {"name": "copilot-dev", "path": "fixture/profile.toml", "sha256": "c" * 64,
                  "document": {"jobs": {"job_project_build": {"settings": {"model": {"model": "fixture-model"}}}}},
                  "keys": ["jobs.job_project_build.settings.model.model"]}
        document["configuration_profile"] = record
        sources.insert(-1, {key: record[key] for key in ("path", "sha256")} | {"layer": "runtime_profile"})
    if overlay:
        record = {"path": "fixture/capacity.toml", "sha256": "d" * 64,
                  "document": {"orchestration": {"dagster": {"pools": {"inference_teams": 1}}}},
                  "keys": ["orchestration.dagster.pools.inference_teams"]}
        document["configuration_overlay"] = record
        sources.insert(-1, {key: record[key] for key in ("path", "sha256")} | {"layer": "capacity_overlay"})
    configuration(unit.job.run_root, document, sources=sources)
    unit.outputs["resolve_configuration.fetch_config"] = sources[0]
    return unit, document, sources


@pytest.mark.parametrize(("profile", "overlay", "strategy"), [
    (False, False, "explicit-or-repository-default-with-host-pins"),
    (False, True, "explicit-or-repository-default-with-capacity-overlay-with-host-pins"),
    (True, False, "explicit-or-repository-default-with-profile-with-host-pins"),
    (True, True, "explicit-or-repository-default-with-profile-and-capacity-overlay-with-host-pins"),
], ids=["base", "overlay", "profile", "both"])
def test_layers_verify_host_profile_overlay_and_preserve_order(tmp_path, profile, overlay, strategy):
    unit, document, sources = layers_fixture(tmp_path, profile=profile, overlay=overlay)
    expected = {"strategy": strategy, "layers": sources, "profile": "copilot-dev" if profile else "dev"}
    if profile:
        expected["profile_keys"] = document["configuration_profile"]["keys"]
    if overlay:
        expected["capacity_keys"] = document["configuration_overlay"]["keys"]
    assert handler(unit.unit_id)(unit) == expected


@pytest.mark.parametrize(("fault", "message"), [
    ("absent", "no host-pins layer"),
    ("wrong-layer", "no host-pins layer"),
    ("record-type", "host-pins layer does not match"),
    ("layer-hash", "host-pins layer does not match"),
    ("record-hash", "host-pins layer does not match"),
    ("record-document", "host-pins layer does not match"),
], ids=["absent", "wrong-layer", "record-type", "layer-hash", "record-hash", "record-document"])
def test_layers_refuse_missing_or_mismatched_frozen_host_binding(tmp_path, fault, message):
    unit, document, sources = layers_fixture(tmp_path)
    if fault == "absent":
        sources.pop()
    elif fault == "wrong-layer":
        sources[-1]["layer"] = "unknown"
    elif fault == "record-type":
        document["configuration_host_pins"] = []
    elif fault == "layer-hash":
        sources[-1]["sha256"] = "0" * 64
    elif fault == "record-hash":
        document["configuration_host_pins"]["sha256"] = "0" * 64
    else:
        document["configuration_host_pins"]["document"]["images"] = {}
    configuration(unit.job.run_root, document, sources=sources)
    with pytest.raises(ValueError, match=message):
        handler(unit.unit_id)(unit)


@pytest.mark.parametrize(("fault", "message"), [
    ("profile-absent", "does not record its runtime profile"),
    ("name-absent", "does not record its runtime profile"),
    ("path-absent", "profile has no layer"),
    ("layer-absent", "profile layer does not match"),
    ("wrong-layer", "profile layer does not match"),
    ("sha", "profile layer does not match"),
    ("path", "profile layer does not match"),
    ("keys", "profile keys do not match"),
    ("allowlist", "configuration profile.*rejected: runtime"),
], ids=["profile-absent", "name-absent", "path-absent", "layer-absent", "wrong-layer",
        "sha", "path", "keys", "allowlist"])
def test_layers_refuse_profile_identity_key_and_allowlist_drift(tmp_path, fault, message):
    unit, document, sources = layers_fixture(tmp_path, profile=True)
    record = document["configuration_profile"]
    if fault == "profile-absent":
        document.pop("configuration_profile")
    elif fault == "name-absent":
        record.pop("name")
    elif fault == "path-absent":
        record.pop("path")
    elif fault == "layer-absent":
        sources.pop(1)
    elif fault == "wrong-layer":
        sources[1]["layer"] = "capacity_overlay"
    elif fault in {"sha", "path"}:
        record["sha256" if fault == "sha" else "path"] = "different"
    elif fault == "keys":
        record["keys"] = []
    else:
        record["document"] = {"runtime": {"data_dir": "elsewhere"}}
    configuration(unit.job.run_root, document, sources=sources)
    with pytest.raises(ValueError, match=message):
        handler(unit.unit_id)(unit)


@pytest.mark.parametrize(("fault", "message"), [
    ("record-absent", "overlay layer does not match"),
    ("layer-absent", "overlay layer does not match"),
    ("extra-layer", "overlay layer does not match"),
    ("wrong-layer", "overlay layer does not match"),
    ("sha", "overlay layer does not match"),
    ("path", "overlay layer does not match"),
    ("keys", "overlay capacity keys do not match"),
    ("allowlist", "configuration overlay.*rejected: runtime"),
], ids=["record-absent", "layer-absent", "extra-layer", "wrong-layer", "sha", "path", "keys", "allowlist"])
def test_layers_refuse_overlay_identity_key_and_allowlist_drift(tmp_path, fault, message):
    unit, document, sources = layers_fixture(tmp_path, overlay=True)
    record = document["configuration_overlay"]
    if fault == "record-absent":
        document.pop("configuration_overlay")
    elif fault == "layer-absent":
        sources.pop(1)
    elif fault == "extra-layer":
        sources.insert(1, dict(sources[1]))
    elif fault == "wrong-layer":
        sources[1]["layer"] = "runtime_profile"
    elif fault in {"sha", "path"}:
        record["sha256" if fault == "sha" else "path"] = "different"
    elif fault == "keys":
        record["keys"] = []
    else:
        record["document"] = {"runtime": {"data_dir": "elsewhere"}}
    configuration(unit.job.run_root, document, sources=sources)
    with pytest.raises(ValueError, match=message):
        handler(unit.unit_id)(unit)
