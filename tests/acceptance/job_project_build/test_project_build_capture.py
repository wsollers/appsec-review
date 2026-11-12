"""T-113: pre-walk graph/target cases retained as acceptance, not bounded integration.

Case bodies are preserved. Shared helpers stay at their existing import paths so the
other machine's unit tier and other jobs do not require edits. Not run by this walk.
"""

from __future__ import annotations
import json
from copy import deepcopy
import os
from types import SimpleNamespace
from uuid import UUID
import pytest
from appsec_review.acceptance.project_build import project_build_content_problems
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.storage import file_sha256
from tests.telemetry_support import assert_job_lifecycle, job_events

from tests.integration.job_project_build.test_project_build_capture import (
    CASE,
    _run,
    _setup,
)

@pytest.mark.parametrize("scenario,reason", [
    ("cmake", None), ("direct", None), ("mixed", "mixed_targets_in_capture"),
    ("outside", "unknown_compiler_in_capture"), ("empty", "capture_empty"),
    ("cross", "cross_target_not_permitted"),
    ("artifact-target", "cross_target_not_permitted"),
])
def test_native_target_is_proven_only_by_captured_execution(tmp_path, scenario, reason):
    run, result, document, calls, image_calls = _run(tmp_path, scenario)
    receipt, = document["probe_receipts"]
    proof, = receipt["enforcement"]
    assert proof["proof_kind"] == "captured_invocation"
    assert len(calls) == 2 and image_calls
    if scenario == "cmake":
        assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in calls[0]
        assert calls[0][calls[0].index("-G") + 1] == "Ninja"
    expected = "SUCCEEDED" if reason is None else "COMPLETED_WITH_GAPS"
    assert_job_lifecycle(run, "job_project_build", terminal=expected)
    assert receipt["terminal_status"] == expected
    if reason is None:
        assert any(item["kind"] == "executable" for item in receipt["artifacts"])
        assert proof["status"] == "proven"
        assert proof["proven_axes"]["os"] == "linux" and proof["proven_axes"]["isa"] == "x86_64"
        assert proof["closure_manifest"]["translation_units"] == [f"/workspace/{CASE}/main.cpp"]
        assert receipt["gaps"] == []
        assert receipt["native_compile_database"]["entry_count"] > 0
        from appsec_review.jobs.job_project_build.enforcement import validate_enforcement
        from appsec_review.jobs.build_topology import _digest
        foreign = deepcopy(proof)
        foreign["build_unit_id"] = "build-unit-" + "0" * 20
        foreign["enforcement_id"] = _digest({key: value for key, value in foreign.items()
                                            if key != "enforcement_id"})
        with pytest.raises(ValueError, match="different build"):
            validate_enforcement(foreign, dispatch=receipt)
    else:
        assert receipt["artifacts"] == []
        assert any(item["kind"] == "executable" for item in receipt["rejected_artifacts"])
        assert proof["status"] != "proven"
        assert any(gap["schema"] == "appsec-review/producer-gap/1"
                   and gap["code"] == "producer_reported_gap" and gap["reason"] == reason
                   and gap["scope_id"] == receipt["build_unit_id"] for gap in receipt["gaps"])
    events = job_events(run, "job_project_build", "LANGUAGE_BUILD_COMPLETED")
    assert len(events) == 1 and events[0]["command_count"] == 2
    attempt = run / "data/jobs/job_project_build/attempts/attempt_0001"
    problems = project_build_content_problems(run, attempt)
    assert (not problems) is (reason is None or scenario == "direct"), problems


@pytest.mark.parametrize("scenario,reason", [
    ("wrapped", None), ("wrappers-only", "capture_empty"),
    ("unmatched-wrapper", "unknown_compiler_in_capture"),
    ("unknown-python", "unknown_compiler_in_capture"),
    ("unknown-shell", "unknown_compiler_in_capture"),
])
def test_capture_intermediaries_require_correlated_real_compiler_execution(tmp_path, scenario, reason):
    run, _, document, _, _ = _run(tmp_path, scenario)
    receipt, = document["probe_receipts"]
    proof, = receipt["enforcement"]
    assert_job_lifecycle(run, "job_project_build",
                         terminal="SUCCEEDED" if reason is None else "COMPLETED_WITH_GAPS")
    if reason is None:
        assert proof["status"] == "proven" and receipt["gaps"] == []
        assert len(proof["closure_manifest"]["observed_axes"]) == 1
        assert all(item["trusted"] and item["executable"] == "/usr/bin/clang++"
                   for item in proof["closure_manifest"]["compilers"])
        assert proof["proven_axes"]["os"] == "linux" and proof["proven_axes"]["isa"] == "x86_64"
        assert proof["proven_axes"]["abi"] == "gnu"
        assert receipt["native_compile_database"]["entry_count"] == 1
        assert any(item["kind"] == "executable" for item in receipt["artifacts"])
    else:
        assert proof["status"] == "unknown" and not receipt["artifacts"]
        assert any(item["code"] == "producer_reported_gap" and item["reason"] == reason
                   and item["scope_id"] == receipt["build_unit_id"] for item in receipt["gaps"])
        if scenario == "wrappers-only":
            assert proof["closure_manifest"]["translation_units"] == []
            assert receipt["native_compile_database"]["entry_count"] == 0


@pytest.mark.parametrize("scenario", ["dynamic", "path", "cc", "network", "missing", "invalid", "unknown"])
def test_untrustworthy_native_recipe_is_refused_before_execution(tmp_path, scenario):
    run, _, document, calls, image_calls = _run(tmp_path, scenario)
    assert not calls and not image_calls
    assert not document["build_dispatches"]
    assert document["gaps"]
    assert_job_lifecycle(run, "job_project_build", terminal="COMPLETED_WITH_GAPS")


def test_capture_integrity_failure_retains_typed_evidence_and_resumes(tmp_path):
    control = ["corrupt"]
    config, target, graph, calls, _ = _setup(tmp_path, "cmake", native_only=True, control=control)
    fingerprint = source_fingerprint(target)
    with pytest.raises(RuntimeError, match="capture"):
        graph.run(target_root=target, source_fingerprint=fingerprint)
    run, = sorted(config.runtime.runs_dir.glob("20*-*-*-*"))
    job = run / "data/jobs/job_project_build"
    assert not (job / "latest.json").exists()
    failure, = (job / "attempts/attempt_0001/steps/probe/tasks/native").glob("*/failure.json")
    evidence = json.loads(failure.read_bytes())
    assert evidence["gaps"][0]["code"] == "producer_failed"
    assert_job_lifecycle(run, "job_project_build", terminal="FAILED")
    assert job_events(run, "job_project_build", "PROJECT_NATIVE_BUILD_FAILED")[0]["error_type"]
    control[0] = "cmake"
    graph.run(target_root=target, source_fingerprint=fingerprint,
              run_id=run.name, force_from="job_project_build")
    assert (job / "latest.json").is_file()
    assert_job_lifecycle(run, "job_project_build", terminal="SUCCEEDED", attempts=2)
    assert len(calls) == 3


@pytest.mark.parametrize("scenario", ["cmake", "mixed"])
def test_language_job_consumes_the_authoritative_project_capture(tmp_path, scenario):
    run, _, document, calls, _ = _run(tmp_path, scenario, consume=True)
    accepted = json.loads((run / "data/jobs/job_language_build/attempts/attempt_0001/"
                          "steps/execute/tasks/native/result.json").read_bytes())
    assert len(calls) == 2
    assert accepted["receipts"] == document["probe_receipts"]
    if scenario == "cmake":
        assert all("delivery_fact_unavailable" in gap for gap in accepted["gaps"])
    else:
        assert any(isinstance(gap, dict) and gap["reason"] == "mixed_targets_in_capture"
                   for gap in accepted["gaps"])
    from appsec_review.jobs.job_artifact_indexing.job import _validate_receipts
    _, gaps = _validate_receipts(run, document["source_fingerprint"], accepted["receipts"])
    assert any("mixed_targets_in_capture" in gap for gap in gaps) is (scenario == "mixed")
    from appsec_review.jobs.job_cpp_compiled_analysis.job import native_analysis_actions, _terminal_gap
    from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
    from appsec_review.runtime.consume import accepted_upstream
    actions = native_analysis_actions({
        **accepted, "language_build_handoff_sha256": accepted_upstream(run, "job_language_build").sha256,
    }, tmp_path / "target")
    assert actions[0]["receipt"] == accepted["receipts"][0]
    if scenario == "cmake":
        assert actions[0]["compile_database_origin"] == "captured-native-components"
    else:
        assert _terminal_gap(actions[0]["receipt"]) == "mixed_targets_in_capture"
    plan = build_codeql_plan(
        source_fingerprint=document["source_fingerprint"],
        files=[{"path": CASE + "/main.cpp", "language": "C++",
                "sha256": file_sha256(tmp_path / "target" / CASE / "main.cpp")}],
        receipts=accepted["receipts"], supported_extractors=["cpp"],
        source_image_id=accepted["receipts"][0]["image"]["image_id"])
    assert any("mixed_targets_in_capture" in gap for gap in plan.gaps) is (scenario == "mixed")
    assert bool(plan.scopes) is (scenario == "cmake")
    assert_job_lifecycle(run, "job_language_build", terminal="COMPLETED_WITH_GAPS")


@pytest.mark.parametrize("scenario", ["cmake", "no-binary", "empty", "database-target"])
def test_stepwise_check_and_accept_enforce_scoped_build_content(tmp_path, monkeypatch, scenario):
    from appsec_review.acceptance.state import StateError, StepwiseState
    from tests.test_stepwise_rewind import stepwise
    config, target, graph, _, _ = _setup(tmp_path, scenario)
    dispatch = str(UUID(int=10))
    result = graph.run(target_root=target, source_fingerprint=source_fingerprint(target),
                       orchestration={"system": "dagster", "run_id": dispatch})
    deployment = tmp_path / "deploy/dagster"
    deployment.mkdir(parents=True)
    (deployment / ".env").write_text(f"APPSEC_UID={os.getuid()}\nAPPSEC_GID={os.getgid()}\n")
    for key, value in {
        "ROOT": tmp_path, "CONTAINER_ROOT": str(tmp_path), "DEPLOYMENT": deployment,
        "STATE_ROOT": tmp_path / "runs/metadata/stepwise", "SEED_STORE": tmp_path / "data/acceptance-seeds",
        "ACCEPTANCE_ROOT": tmp_path / "test/acceptance",
    }.items():
        monkeypatch.setattr(stepwise, key, value)
    monkeypatch.setattr(stepwise, "get_run", lambda *_: {"status": "SUCCESS"})
    topology = {"graph": "wave1_review", "jobs": [{
        "job_id": "job_project_build", "name": "project_build", "dependencies": [],
        "upstream_handoffs": [], "propagate_handoff": True}]}
    state = StepwiseState.create(result["run_id"], target=str(target), topology=topology)
    state.record_launch("job_project_build", dispatch)
    path = stepwise.STATE_ROOT / result["run_id"] / "state.json"
    state.save(path)
    args = SimpleNamespace(app_run=result["run_id"], job="job_project_build",
                           tag="fresh-scoped-fixture", url="offline", show=3)
    if scenario == "cmake":
        assert stepwise.command_check(args) == 0
    else:
        with pytest.raises(StateError, match="fails its check"):
            stepwise.command_accept(args)
    report, = path.parent.glob("checks/*.json")
    document = json.loads(report.read_bytes())
    assert bool(document["content_problems"]) is (scenario != "cmake")
    assert not document["audit"], document["audit"]
