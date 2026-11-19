"""The manual transaction reads its immutable request, not the default checkout."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review import cli
from appsec_review.jobs.build_iterations import retain
from appsec_review.jobs.job_build_iteration import job as iteration_job
from appsec_review.runtime import launch as runtime_launch
from appsec_review.storage import atomic_json
from tests.test_build_topology_refinement import accepted_native


def _config(runner):
    from appsec_review.config import load_config
    config = load_config(Path(__file__).resolve().parents[3] / "appsec-review.toml")
    return replace(config, runtime=replace(config.runtime, runs_dir=runner.config.runtime.runs_dir))


@pytest.mark.parametrize("target_option", [False, True])
def test_manual_iteration_uses_request_without_inspecting_unrelated_checkout(tmp_path, monkeypatch, target_option):
    runner, root, _, _ = accepted_native(tmp_path)
    config = _config(runner)
    target = tmp_path / "request-target"
    target.mkdir()
    request = retain(root, "requests", {"display_label": "build_cpp", "target": str(target)})
    atomic_json(root / "data/configuration/manifest.json", {"resolved_sha256": config.resolved_sha256})
    monkeypatch.setattr(cli, "load_config", lambda *_, **__: config)
    monkeypatch.setattr(runtime_launch, "configured_target", lambda *_: tmp_path / "absent-default")
    seen = []

    def invoke(run_root, reference, label):
        seen.append((run_root, reference, label))
        return {"terminal_status": "SUCCEEDED"}

    monkeypatch.setattr(iteration_job, "invoke_registered_iteration", invoke)
    arguments = ["run", "job_build_iteration", "--run-id", root.name,
                 "--iteration-request", json.dumps(request)]
    if target_option:
        arguments.extend(["--target", str(tmp_path / "absent-explicit")])
    assert cli.main(arguments) == 0
    assert seen == [(root, request, "build_cpp")]


def test_manual_iteration_refuses_changed_request_before_invocation(tmp_path, monkeypatch):
    runner, root, _, _ = accepted_native(tmp_path)
    config = _config(runner)
    request = retain(root, "requests", {"display_label": "build_cpp"})
    (root / request["path"]).chmod(0o600)
    (root / request["path"]).write_text("{}")
    monkeypatch.setattr(cli, "load_config", lambda *_, **__: config)
    monkeypatch.setattr(runtime_launch, "configured_target", lambda *_: tmp_path / "absent-default")
    monkeypatch.setattr(iteration_job, "invoke_registered_iteration",
                        lambda *_: pytest.fail("changed request must not execute"))
    with pytest.raises(ValueError, match="integrity mismatch"):
        cli.main(["run", "job_build_iteration", "--run-id", root.name,
                  "--iteration-request", json.dumps(request)])
