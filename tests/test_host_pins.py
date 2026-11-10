"""The host binding is a typed, frozen input, not a mutable run-time fallback."""

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.config.host_pins import HOST_PINS_PATH, parse_host_pins, serialize_host_pins
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_image_pin_verification import build_job
from appsec_review.runtime import GraphRunner
from tests.host_pins_support import ROOT, fixture_bindings, write_host_pins
from tests.telemetry_support import assert_job_lifecycle, job_events
from tests.test_image_pin_update import runner


def fixture(tmp_path):
    config = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config)
    catalog = tmp_path / "containers/catalog.toml"
    catalog.parent.mkdir()
    shutil.copyfile(ROOT / "containers/catalog.toml", catalog)
    host = write_host_pins(tmp_path / HOST_PINS_PATH)
    target = tmp_path / "target"
    target.mkdir()
    (target / "sample.py").write_text("print('fixture')\n")
    return config, host, target


def test_missing_host_file_is_an_explicit_configuration_failure(tmp_path):
    with pytest.raises(ValueError, match="host pins are missing.*update-image-pins"):
        load_config(ROOT / "appsec-review.toml", host_pins=tmp_path / "missing.toml")


def test_signing_bootstrap_reads_policy_without_requiring_host_inventory(tmp_path, monkeypatch):
    from appsec_review.config.host_pins import HOST_PINS_ENV
    from appsec_review.signing.cli import load_signing_config
    monkeypatch.setenv(HOST_PINS_ENV, str(tmp_path / "missing.toml"))
    signing = load_signing_config(ROOT / "appsec-review.toml")
    assert signing.runtime.repository_root == ROOT
    assert signing.signing.image_enforcement == "disabled"


@pytest.mark.parametrize("change", ["unknown", "schema", "image", "runtime"], ids=str)
def test_host_schema_is_closed_and_validates_ids_and_declarations(change):
    content = serialize_host_pins(fixture_bindings(), [])
    if change == "unknown":
        content = b"unexpected = true\n" + content
    elif change == "schema":
        content = content.replace(b"host-pins/1", b"host-pins/0")
    elif change == "image":
        content = content.replace(b"sha256:", b"tag:", 1)
    else:
        content = content.replace(b"preinstalled_runtimes = []", b'preinstalled_runtimes = [{}]')
    with pytest.raises(ValueError):
        parse_host_pins(content)


def test_missing_declared_tag_is_not_filled_from_another_host(tmp_path):
    config, host, _ = fixture(tmp_path)
    images = fixture_bindings()
    del images["audit-codeql:custom-2.27.0"]
    write_host_pins(host, images=images)
    with pytest.raises(ValueError, match="no binding.*source_image_id"):
        load_config(config, host_pins=host)


def test_runner_freezes_host_bytes_and_gate_verifies_exact_bindings(tmp_path):
    config_path, host, target = fixture(tmp_path)
    config = load_config(config_path, host_pins=host)
    docker = runner(fixture_bindings())
    graph = GraphRunner(config, [build_job(runner=docker)])
    outcome = graph.run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED"
    root = config.runtime.runs_dir / outcome["run_id"]
    assert (root / "data/configuration/host-pins.toml").read_bytes() == host.read_bytes()
    attempt = root / "data/jobs/job_image_pin_verification/attempts/attempt_0001"
    plan = json.loads((attempt / "steps/selection/tasks/resolve_pins/image-pin-plan.json").read_text())
    verification = json.loads((attempt / "steps/verification/tasks/inspect_images/image-pin-verification.json").read_text())
    assert plan["host_pins"]["sha256"] == config.host_pins.sha256
    assert plan["configuration"]["sha256"] == config.resolved_sha256
    assert len(verification["pins"]) == len(plan["pins"]) > 40
    assert {row["status"] for row in verification["pins"]} == {"matched"}
    assert verification["gaps"] == []
    assert_job_lifecycle(root, "job_image_pin_verification", terminal="SUCCEEDED")
    [completed] = job_events(root, "job_image_pin_verification", "IMAGE_PIN_VERIFICATION_COMPLETED")
    assert completed["pin_count"] == len(plan["pins"])


def test_host_change_changes_identity_without_rewriting_frozen_run(tmp_path):
    config_path, host, target = fixture(tmp_path)
    config = load_config(config_path, host_pins=host)
    result = GraphRunner(config, [build_job(runner=runner(fixture_bindings()))]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    frozen = config.runtime.runs_dir / result["run_id"] / "data/configuration/host-pins.toml"
    before = frozen.read_bytes()
    images = fixture_bindings()
    images["audit-codeql:custom-2.27.0"] = "sha256:" + "f" * 64
    write_host_pins(host, images=images)
    changed = load_config(config_path, host_pins=host)
    assert changed.resolved_sha256 != config.resolved_sha256
    with pytest.raises(ValueError, match="different configuration"):
        GraphRunner(changed, [build_job(runner=runner(images))]).run(
            run_id=result["run_id"], target_root=target, source_fingerprint=source_fingerprint(target))
    assert frozen.read_bytes() == before
