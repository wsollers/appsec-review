"""Pre-walk suite pending replacement: typed host bindings and whole-graph freezing."""

import json
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_image_pin_verification import build_job
from appsec_review.runtime import GraphRunner
from tests.host_pins_support import fixture_bindings, write_host_pins
from tests.telemetry_support import assert_job_lifecycle, job_events
from tests.unit.job_image_pin_verification.test_host_pins import fixture
from tests.unit.job_image_pin_verification.test_image_pin_update import runner


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

