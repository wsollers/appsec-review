from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.orchestration.topology import accepted_upstream_handoffs
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.launch import TARGET_JOBS, LaunchInputs, launch, launch_inputs, unit_order
from appsec_review.runtime.registry import builtin_registry
from tests.test_job_runtime import write_config


def _job(calls: list[str], *, fail: str | None = None) -> Job:
    def unit(name: str):
        def handler(context):
            calls.append(name)
            if name == fail:
                raise RuntimeError(f"{name} failed")
            return {"unit": name, "terminal_status": "SUCCEEDED"}
        return handler

    def pre(context, result):
        calls.append("pre")

    def post(context, result):
        calls.append("post")

    # Declared out of dependency order: the launcher must run collect.all before report.final.
    return Job("job_fixture", "fixture", lambda context: {}, (pre,), (post,), units=(
        Unit("report.final", unit("report"), ("collect.all",)),
        Unit("collect.all", unit("collect")),
    ))


def test_launch_claims_runs_units_in_dependency_order_and_publishes(tmp_path: Path) -> None:
    calls: list[str] = []
    runner = JobRunner(load_config(write_config(tmp_path)))
    outcome = launch(runner, _job(calls), LaunchInputs(None, "none"), run_id=None)

    assert calls == ["pre", "collect", "report", "post"]
    attempt = Path(outcome["attempt_root"])
    claim = json.loads((attempt / "claim.json").read_text(encoding="utf-8"))
    assert claim["orchestration"] == {"system": "local"}
    assert outcome["status"]["status"] == "SUCCEEDED"
    assert outcome["handoff"]["status"] == "ACCEPTED"
    latest = json.loads((attempt.parent.parent / "latest.json").read_text(encoding="utf-8"))
    assert latest["handoff_sha256"] == outcome["handoff_sha256"]


def test_job_runner_run_uses_the_same_lifecycle(tmp_path: Path) -> None:
    launched_calls: list[str] = []
    run_calls: list[str] = []
    runner = JobRunner(load_config(write_config(tmp_path)))
    launched = launch(runner, _job(launched_calls), LaunchInputs(None, "none"), run_id=None)
    ran = runner.run(_job(run_calls), run_id=launched["status"]["run_id"])

    assert run_calls == launched_calls
    assert (Path(ran["attempt_root"]) / "claim.json").is_file()
    assert ran["result"]["outputs"] == launched["result"]["outputs"]
    assert ran["result"]["status"] == launched["result"]["status"]
    assert ran["handoff"]["outputs"] == launched["handoff"]["outputs"]


def test_a_failed_unit_marks_the_attempt_failed(tmp_path: Path) -> None:
    calls: list[str] = []
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(RuntimeError, match="report failed"):
        launch(runner, _job(calls, fail="report"), LaunchInputs(None, "none"), run_id=None)

    attempt = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/attempt_0001"))
    assert json.loads((attempt / "status.json").read_text(encoding="utf-8"))["status"] == "FAILED"
    assert not (attempt.parent.parent / "latest.json").exists()


def test_unit_order_rejects_cycles_and_unknown_dependencies() -> None:
    handler = lambda context: {}  # noqa: E731
    cyclic = Job("job_fixture", "fixture", handler, units=(
        Unit("a.one", handler, ("b.two",)), Unit("b.two", handler, ("a.one",))))
    with pytest.raises(ValueError, match="cycle"):
        unit_order(cyclic)
    dangling = Job("job_fixture", "fixture", handler, units=(Unit("a.one", handler, ("z.none",)),))
    with pytest.raises(ValueError, match="unknown dependency"):
        unit_order(dangling)


def test_launch_inputs_give_a_target_only_to_target_reading_jobs(tmp_path: Path) -> None:
    handler = lambda context: {}  # noqa: E731
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    gate = launch_inputs(Job("job_model_connectivity", "gate", handler), target=target,
                         upstream_handoffs={"job_x": "0" * 64})
    reader = launch_inputs(Job("job_target_catalog", "catalog", handler), target=target, upstream_handoffs={})

    assert (gate.target_root, gate.source_fingerprint, dict(gate.upstream_handoffs)) == (
        None, "none", {"job_x": "0" * 64})
    assert reader.target_root == target.resolve()
    assert reader.source_fingerprint not in {"", "none"}


def test_every_registered_job_outside_the_target_set_is_named() -> None:
    # A newly registered job must be placed deliberately: it either reads the target or it does not.
    assert set(builtin_registry().job_ids()) - TARGET_JOBS == {
        "job_model_connectivity", "job_image_pin_verification", "job_third_party_data_sync",
        "job_inference_security_review", "job_final_publication_gate", "job_final_report_publication"}


def test_accepted_upstream_handoffs_requires_and_verifies_each_pointer(tmp_path: Path) -> None:
    runner = JobRunner(load_config(write_config(tmp_path)))
    outcome = launch(runner, _job([]), LaunchInputs(None, "none"), run_id=None)
    run_root = tmp_path / "runs" / outcome["status"]["run_id"]

    assert accepted_upstream_handoffs(run_root, ["job_fixture"]) == {"job_fixture": outcome["handoff_sha256"]}
    with pytest.raises(ValueError, match="no accepted handoff"):
        accepted_upstream_handoffs(run_root, ["job_missing"])
