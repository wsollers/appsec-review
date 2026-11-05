from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.build_topology import (
    compile_build_topology, refine_build_topology, topology_evidence_bundle,
)
from appsec_review.jobs.build_topology_artifacts import (
    bind_actions, guard_action, guard_build_cache, load_refinement,
)
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference
from tests.test_job_runtime import write_config
from tests.test_native_target_enforcement import _native, _profile


def accepted_native(tmp_path: Path):
    config_path = write_config(tmp_path)
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write("""
[review_policy.releases]
platform = "synthetic-platform/1"
validation = "synthetic-validation/1"
build_toolchain = "synthetic-toolchain/1"

[jobs.job_target_analysis_plan]
name = "synthetic accepted source producer"

[jobs.job_project_build]
name = "synthetic native cache producer"
""")
    config = load_config(config_path)
    runner = JobRunner(config)
    source = _native()
    source["recipe"] = None
    profile = _profile()
    graph = compile_build_topology([source], source_fingerprint="synthetic-source", profiles=profile)
    plan = {
        "schema": PLAN_SCHEMA, "source_fingerprint": "synthetic-source",
        "build_topology": {
            "executable_graph": graph, "build_actions": [source],
            "evidence_bundle": topology_evidence_bundle(
                [source], source_fingerprint="synthetic-source", profiles=profile),
            "planning_refinement": refine_build_topology(graph, [source], profiles=profile),
        },
    }

    def publish(context):
        path = context.job.attempt_root / "source-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(context.job.run_root, path), "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", "synthetic source producer", lambda _: {},
              units=(Unit("plan_acceptance.publish_handoff", publish),))
    outcome = runner.run(job, source_fingerprint="synthetic-source")
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    action = bind_actions(
        root, [_native()], profiles=profile,
        policy=config.job("job_project_build").settings["build_selection"],
        releases=config.review_policy.releases.view())[0]
    action["image"] = {"image_id": profile["image_digest"]}
    return runner, root, graph, action


def native_cache_job(action, calls):
    def output(_):
        calls.append("executed")
        return {"dispatches": [copy.deepcopy(action)], "terminal_status": "SUCCEEDED"}
    return Job("job_project_build", "synthetic native cache", lambda _: {},
               units=(Unit("build.native", output),))


def test_late_recipe_gets_new_accepted_sidecar_without_mutating_source_plan(tmp_path):
    runner, root, graph, first = accepted_native(tmp_path)
    before = graph.copy()
    first_refinement = load_refinement(root, first["topology_refinement"])
    second = copy.deepcopy(first)
    second["recipe"]["build_commands"][0].append("-g")
    with pytest.raises(ValueError, match="matching immutable refinement"):
        guard_action(root, second)
    second = bind_actions(
        root, [second], profiles=_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())[0]
    assert second["topology_refinement"] != first["topology_refinement"]
    assert guard_action(root, first)["recipe_digest"] != guard_action(root, second)["recipe_digest"]
    assert load_refinement(root, first["topology_refinement"]) == first_refinement
    assert graph == before


def test_missing_recipe_cannot_borrow_a_nonnull_accepted_refinement(tmp_path):
    _runner, root, _graph, action = accepted_native(tmp_path)
    guard_action(root, action)
    del action["recipe"]
    with pytest.raises(ValueError, match="exact selected non-null recipe"):
        guard_action(root, action)


def test_direct_resume_planner_reuses_valid_releases_and_rejects_stale_recipe(tmp_path):
    runner, root, _graph, action = accepted_native(tmp_path)
    calls = []
    job = native_cache_job(action, calls)
    accepted = runner.run(job, run_id=root.name, source_fingerprint="synthetic-source")
    planner = ResumePlanner(runner.config, root, [job], "synthetic-source")
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    assert calls == ["executed"]
    stale = copy.deepcopy(action)
    stale["recipe"]["build_commands"][0].append("-m32")
    with pytest.raises(ValueError, match="matching immutable refinement"):
        guard_build_cache(
            root, job.job_id, {"dispatches": [stale]},
            releases=runner.config.review_policy.releases.view())
    index = root / "data/build/topology/accepted-refinements.json"
    pointer = json.loads(index.read_bytes())
    atomic_json(index, {**pointer, "entries": []})
    decision = planner.plan(emit_event=False)[0]
    assert decision.action == "RUN"
    assert any("build topology cache admission failed" in reason for reason in decision.reasons)
    assert not any("missing_release_identity" in reason for reason in decision.reasons)
    atomic_json(index, pointer)
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    assert accepted["handoff"]["status"] == "ACCEPTED"


def test_task_checkpoint_requires_the_same_recipe_refinement_before_reuse(tmp_path):
    runner, root, _graph, action = accepted_native(tmp_path)
    calls = []
    job = native_cache_job(action, calls)
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="synthetic-source")
    first = runner.execute_or_reuse_unit(job, claim, "build.native")
    assert runner.execute_or_reuse_unit(job, claim, "build.native") == first
    assert calls == ["executed"]
    task_path = root / claim["attempt_path"] / "steps/build/tasks/native/result.json"
    result = json.loads(task_path.read_bytes())
    result["dispatches"][0]["recipe"]["build_commands"][0].append("-m32")
    atomic_json(task_path, result)
    status_path = task_path.with_name("status.json")
    status = json.loads(status_path.read_bytes())
    status["result_sha256"] = reference(root, task_path)["sha256"]
    atomic_json(status_path, status)
    assert runner.execute_or_reuse_unit(job, claim, "build.native") == first
    assert calls == ["executed", "executed"]


def test_whole_attempt_publication_retry_refuses_lost_native_acceptance(tmp_path):
    runner, root, _graph, action = accepted_native(tmp_path)
    calls = []
    job = native_cache_job(action, calls)
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="synthetic-source")
    runner.execute_or_reuse_unit(job, claim, "build.native")
    accepted = runner.finalize_attempt(job, claim)
    assert runner.finalize_attempt(job, claim)["reused"] is True
    index = root / "data/build/topology/accepted-refinements.json"
    before = index.read_bytes()
    atomic_json(index, {"schema": "appsec-review/accepted-topology-refinements/1", "entries": []})
    with pytest.raises(ValueError, match="accepted index entry"):
        runner.finalize_attempt(job, claim)
    index.write_bytes(before)
    assert runner.finalize_attempt(job, claim)["handoff_sha256"] == accepted["handoff_sha256"]
    assert calls == ["executed"]


def test_native_image_and_descriptor_identity_are_checked_before_cache_admission(tmp_path):
    runner, root, _graph, action = accepted_native(tmp_path)
    guard_action(root, action)
    other_image = copy.deepcopy(action)
    other_image["image"]["image_id"] = "sha256:" + "c" * 64
    with pytest.raises(ValueError, match="different immutable image"):
        guard_build_cache(root, "job_project_build", {"dispatches": [other_image]},
                          releases=runner.config.review_policy.releases.view())
    changed_source = copy.deepcopy(action)
    changed_source["descriptor_package"]["documents"][0]["content"] += "# substituted source\n"
    with pytest.raises(ValueError, match="declaring documents differ"):
        guard_action(root, changed_source)
    with pytest.raises(ValueError, match="immutable image"):
        guard_action(root, {key: value for key, value in action.items() if key != "image"})


def test_workspace_resume_checks_native_refinement_before_reconstruction(tmp_path):
    from appsec_review.jobs.build_iterations import resume_build_workspace, retain
    from appsec_review.jobs.build_workspace import BuildWorkspace
    _runner, root, _graph, action = accepted_native(tmp_path)
    target = tmp_path / "synthetic-target"
    target.mkdir()
    for document in _native()["descriptor_package"]["documents"]:
        (target / document["path"]).write_text(document["content"], encoding="utf-8")
    workspace = BuildWorkspace(root)
    workspace.materialize(target, "synthetic-source")
    request = retain(root, "requests", {"dispatch": action})
    atomic_json(root / "data/build/iterations/pending.json", {"request": request})
    index = root / "data/build/topology/accepted-refinements.json"
    before = index.read_bytes()
    state_path = root / workspace.state_relative
    state = state_path.read_bytes()
    atomic_json(index, {"schema": "appsec-review/accepted-topology-refinements/1", "entries": []})
    with pytest.raises(ValueError, match="accepted index entry"):
        resume_build_workspace(root)
    assert state_path.read_bytes() == state
    assert (workspace.paths.target / "main.c").read_text() == _native()["descriptor_package"]["documents"][1]["content"]
    index.write_bytes(before)
    resume_build_workspace(root)
    assert json.loads(state_path.read_bytes())["condition"] == "clean"


@pytest.mark.parametrize("worker", ["native", "jvm", "wasm"])
def test_direct_workers_reject_stale_recipe_before_constructing_an_executor(tmp_path, worker):
    from appsec_review.jobs.job_language_build.job import _execute_one
    from appsec_review.jobs.job_language_build.jvm import execute_jvm_one
    from appsec_review.jobs.job_language_build.wasm import _execute_one as execute_wasm
    runner, root, _graph, action = accepted_native(tmp_path)
    guard_action(root, action, releases=runner.config.review_policy.releases.view())
    changed = copy.deepcopy(action)
    changed["recipe"]["build_commands"][0].append("-m32")
    unit = SimpleNamespace(job=SimpleNamespace(
        run_root=root, review_policy=runner.config.review_policy))
    constructed = []

    def factory(*args):
        constructed.append(args)
        raise AssertionError("an inadmissible recipe must not create an executor")

    with pytest.raises(ValueError, match="matching immutable refinement"):
        if worker == "native":
            _execute_one(unit, changed, {}, factory)
        elif worker == "jvm":
            execute_jvm_one(unit, changed, {}, factory)
        else:
            execute_wasm(unit, changed, {}, "rust", {}, factory)
    assert constructed == []
