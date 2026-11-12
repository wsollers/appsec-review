"""Real preinstalled cve-bin-tool builder; never build or pull an image during a test."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess

import pytest

from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.reference_feeds import nvd_vulnerability, publish_nvd

from .support import assert_work_contract, work_path


def test_real_cve_builder_matches_synthetic_unit_database_contract(tmp_path, cve_settings):
    settings, verifier = cve_settings
    root = publish_nvd(tmp_path / "feeds/nvd", [nvd_vulnerability("CVE-2026-0001")])
    resolved = database.resolve_nvd_snapshot(root, json.loads((root / "current.json").read_bytes()))

    def runner(settings, source, output):
        return database._docker_builder(settings, source, output, image_verifier=verifier)

    built = database.build(settings, resolved, work_path(tmp_path, "cve_bin_tool_db_build.build"), runner)
    assert_work_contract(tmp_path, "cve_bin_tool_db_build.build", built)
    assert built["cve_count"] == built["layer_records"] == 1
    output = Path(built["directory"])
    record = json.loads((output / "build.json").read_bytes())
    assert record["sources"] == ["NVD"] and record["tool_version"] == settings.tool_version
    pointer = database.publish(settings, built)
    verified = database.verify(settings, resolved)
    assert pointer["snapshot_id"] == verified["snapshot_id"]
    assert verified["nvd_snapshot_id"] == resolved["snapshot_id"]
    manifest = json.loads((Path(verified["directory"]) / "manifest.json").read_bytes())
    assert set(manifest["files"]) == {"cve.db", "version_map.db", "build.json"}
    assert manifest["schema"] == "appsec-review/cve-bin-tool-snapshot/1"
    atomic_json(output / "build.json.provenance.json", {
        "tool_id": "tool-cve-bin-tool", "image_id": built["tool"]["image_id"],
        "tool_version": settings.tool_version, "input_sha256": resolved["layers"][0]["sha256"],
        "output_sha256": file_sha256(output / "build.json"),
    })


def test_real_cve_builder_timeout_removes_its_container(tmp_path, monkeypatch, cve_settings):
    settings, verifier = cve_settings
    if not hasattr(os, "mkfifo"):
        pytest.skip("missing POSIX FIFO support for the blocked-input timeout probe")
    source, output = tmp_path / "input", tmp_path / "output"
    (source / "layers").mkdir(parents=True)
    output.mkdir()
    os.mkfifo(source / "layers/000000.json.gz", mode=0o644)
    commands = []
    real_run = subprocess.run

    def observe(command, **kwargs):
        commands.append(command)
        return real_run(command, **kwargs)

    monkeypatch.setattr(database.subprocess, "run", observe)
    with pytest.raises(subprocess.TimeoutExpired):
        database._docker_builder(replace(settings, run_timeout_seconds=2), source, output,
                                 image_verifier=verifier)
    launched, = [command for command in commands if command[:2] == ["docker", "run"]]
    name = launched[launched.index("--name") + 1]
    assert ["docker", "rm", "--force", name] in commands
    inspected = real_run(["docker", "container", "inspect", name], capture_output=True, check=False, timeout=10)
    assert inspected.returncode != 0 and b"No such" in inspected.stderr
    assert "--read-only" in launched and launched[launched.index("--network") + 1] == "none"
    assert not (settings.feed_root / "current.json").exists()
