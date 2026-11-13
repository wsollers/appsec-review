"""The run-frozen execution plan and resume identity: the managed reader image binding comes from
the run's frozen host pins and resolved configuration, never from the mutable host."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.config.host_pins import HOST_PINS_ENV, serialize_host_pins
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.debug_symbols.execution import SymbolIntegrityError, execution_plan
from appsec_review.jobs.job_debug_symbol_indexing import build_job
from appsec_review.runtime import JobRunner
from appsec_review.storage.atomic import canonical_json
from tests.host_pins_support import fixture_bindings, fixture_preinstalled, write_host_pins


ROOT = Path(__file__).resolve().parents[3]


def _freeze(tmp_path, *, images=None, releases=None):
    pins = write_host_pins(tmp_path / "host-pins.toml", images=images,
                           runtimes=fixture_preinstalled())
    config = load_config(ROOT / "appsec-review.toml", host_pins=pins)
    if releases is not None:
        policy = replace(config.review_policy, releases=ComponentReleases(releases))
        document = json.loads(config.resolved_json)
        document["review_policy"] = policy.view()
        content = canonical_json(document)
        config = replace(config, review_policy=policy, resolved_json=content,
                         resolved_sha256=hashlib.sha256(content).hexdigest())
    config = replace(config, runtime=replace(
        config.runtime, runs_dir=tmp_path, metadata_dir=tmp_path / "metadata"))
    run_root = tmp_path / "2026-11-10-0001"
    run_root.mkdir()
    JobRunner(config)._bind_configuration(run_root)
    return config, run_root


@pytest.fixture
def frozen_run(tmp_path):
    return _freeze(tmp_path)


def test_repair_identity_uses_run_frozen_reader_binding(frozen_run):
    config, run_root = frozen_run
    identity = build_job().probe_input_identity(None, run_root, repository_root=ROOT)
    assert isinstance(identity, str) and len(identity) == 64
    plan = execution_plan(ROOT, run_root)
    document = json.loads(config.resolved_json)
    recipe = load_catalog(ROOT).tool("tool-native-cpp")
    assert recipe.expected_image_id is None
    assert plan["fallback"] == {
        "image_id": document["configuration_host_pins"]["document"]["images"][recipe.tag],
        "user": recipe.user,
    }
    assert plan["release_id"] == config.review_policy.releases.values["job_debug_symbol_indexing"]
    assert plan["schema"] == "appsec-review/debug-symbol-execution-plan/2"
    assert plan["reuse_allowed"]
    assert not any(key.endswith("sha256") for key in plan)
    assert not (run_root / "data/jobs/job_debug_symbol_indexing").exists()


@pytest.mark.parametrize("defect,message", [
    ("missing_record", "no frozen host image bindings"),
    ("missing_binding", "no binding for catalog image tool-native-cpp"),
    ("invalid_binding", "invalid expected image id: tool-native-cpp"),
])
def test_catalog_binding_is_required_and_validated(frozen_run, defect, message):
    config, _ = frozen_run
    document = json.loads(config.resolved_json)
    tag = load_catalog(ROOT).tool("tool-native-cpp").tag
    if defect == "missing_record":
        del document["configuration_host_pins"]
    elif defect == "missing_binding":
        del document["configuration_host_pins"]["document"]["images"][tag]
    else:
        document["configuration_host_pins"]["document"]["images"][tag] = "mutable:tag"
    with pytest.raises(ValueError, match=message):
        load_catalog(ROOT, resolved_config=document)


@pytest.mark.parametrize("name,error,message", [
    ("host-pins.toml", ValueError, "host pins are missing"),
    ("resolved.json", FileNotFoundError, "resolved.json"),
])
def test_missing_frozen_inputs_never_fall_back_to_host(frozen_run, name, error, message):
    _, run_root = frozen_run
    (run_root / "data/configuration" / name).unlink()
    with pytest.raises(error, match=message):
        build_job().probe_input_identity(None, run_root, repository_root=ROOT)


def test_frozen_host_file_must_match_resolved_binding(frozen_run):
    config, run_root = frozen_run
    document = config.host_pins.document
    document["images"][load_catalog(ROOT).tool("tool-native-cpp").tag] = "sha256:" + "f" * 64
    (run_root / "data/configuration/host-pins.toml").write_bytes(
        serialize_host_pins(document["images"], document["preinstalled_runtimes"]))
    with pytest.raises(SymbolIntegrityError, match="host-pins identity mismatch"):
        build_job().probe_input_identity(None, run_root, repository_root=ROOT)


def test_resolved_configuration_must_match_frozen_manifest(frozen_run):
    config, run_root = frozen_run
    document = json.loads(config.resolved_json)
    document["configuration_host_pins"]["document"]["images"][
        load_catalog(ROOT).tool("tool-native-cpp").tag] = "sha256:" + "f" * 64
    (run_root / "data/configuration/resolved.json").write_bytes(canonical_json(document))
    with pytest.raises(ValueError, match="resolved configuration hash mismatch"):
        build_job().probe_input_identity(None, run_root, repository_root=ROOT)


def test_frozen_pin_does_not_authorize_an_unapproved_reader(frozen_run, tmp_path):
    _, run_root = frozen_run
    catalog = load_catalog(ROOT)
    tool = catalog.tool("tool-native-cpp")
    root = tmp_path / "recipe"
    (root / "containers").mkdir(parents=True)
    (root / "policy.toml").write_bytes(catalog.runtime_policy.read_bytes())
    manifest = tool.manifest_path.read_text().replace(
        'additional_executables = ["/usr/bin/python3"]', "additional_executables = []")
    (root / "tool.toml").write_text(manifest)
    (root / "containers/catalog.toml").write_text(
        'schema = "appsec-review/container-catalog/1"\nruntime_policy = "policy.toml"\n'
        '[[images]]\nid = "tool-native-cpp"\nkind = "tool"\nstate = "enabled"\n'
        f'tag = {json.dumps(tool.tag)}\nversion = {json.dumps(tool.version)}\n'
        'tool_manifest = "tool.toml"\n')
    with pytest.raises(SymbolIntegrityError, match="not pinned or approved"):
        execution_plan(root, run_root)


def test_mutable_host_changes_cannot_change_frozen_plan_or_reuse(frozen_run, monkeypatch, tmp_path):
    config, run_root = frozen_run
    job = build_job()
    before = job.probe_input_identity(None, run_root)
    plan = execution_plan(ROOT, run_root)
    frozen = run_root / "data/configuration"
    original = {name: (frozen / name).read_bytes() for name in (
        "resolved.json", "manifest.json", "host-pins.toml")}
    document = config.host_pins.document
    document["images"][load_catalog(ROOT).tool("tool-native-cpp").tag] = "sha256:" + "f" * 64
    config.host_pins.path.write_bytes(
        serialize_host_pins(document["images"], document["preinstalled_runtimes"]))
    monkeypatch.setenv(HOST_PINS_ENV, str(tmp_path / "missing-host-pins.toml"))
    assert execution_plan(ROOT, run_root) == plan
    assert job.probe_input_identity(None, run_root) == before
    assert original == {name: (frozen / name).read_bytes() for name in original}
    assert job.probe_input_identity(None) is None


def test_resume_identity_changes_when_managed_reader_image_changes(frozen_run, tmp_path):
    _, run_root = frozen_run
    images = fixture_bindings()
    images[load_catalog(ROOT).tool("tool-native-cpp").tag] = "sha256:" + "f" * 64
    _, other_root = _freeze(tmp_path / "other", images=images)
    job = build_job()
    before = job.probe_input_identity(None, run_root)
    assert job.probe_input_identity(None, other_root) != before
    assert execution_plan(ROOT, other_root)["fallback"]["image_id"] == "sha256:" + "f" * 64
    assert job.probe_input_identity(None, run_root) == before


@pytest.mark.parametrize("releases,expected", [
    ({}, None),
    ({"platform": "platform-1"}, "platform-1"),
    ({"platform": "platform-1", "job_debug_symbol_indexing": "readers-3"}, "readers-3"),
])
def test_managed_image_and_declared_release_are_resume_inputs(tmp_path, releases, expected):
    _, run_root = _freeze(tmp_path / "first", releases=releases)
    plan = execution_plan(ROOT, run_root)
    assert plan["release_id"] == expected
    assert plan["reuse_allowed"] is (expected is not None)
    assert plan["reuse_unavailable_reason"] == (
        None if expected is not None else "missing_release_identity")
    _, other_root = _freeze(
        tmp_path / "other", releases={"job_debug_symbol_indexing": "readers-4"})
    assert execution_plan(ROOT, other_root) != plan
    job = build_job()
    assert job.probe_input_identity(None, other_root) != job.probe_input_identity(None, run_root)
