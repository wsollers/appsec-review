"""Offline regressions for PB-F01/PB-F02; fixtures never execute target commands."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.build_topology import refine_build_topology
from appsec_review.jobs.build_topology_artifacts import guard_action, guard_build_cache
from appsec_review.jobs.job_project_build.job import (
    BUILD_FAMILIES, STATIC_LANES, _deterministic_native_recipe,
    _validate_expected_outputs, build_job,
)
from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference
from tests.release_support import write_release
from tests.test_build_topology_refinement import accepted_native
from tests.test_native_target_enforcement import _native, _profile


@pytest.mark.parametrize("root,build_dir,outputs", [
    (".", "build", ["build/control"]),
    (".", "out", ["out/control", "out/libcontrol.a"]),
    ("component", "component/debug", ["component/debug/bin/control"]),
    (".", "out", ["out/control", "output/control"]),
])
def test_selected_cmake_recipe_is_not_rewritten(tmp_path, root, build_dir, outputs):
    source = tmp_path if root == "." else tmp_path / root
    source.mkdir(parents=True, exist_ok=True)
    marker = "CMakeLists.txt" if root == "." else f"{root}/CMakeLists.txt"
    (source / "CMakeLists.txt").write_text("project(control)\n", encoding="utf-8")
    action = _native()
    action.update(root=root, markers=[{"path": marker}],
                  descriptor_package={"documents": [{"path": marker}]})
    recipe = action["recipe"]
    recipe.update(
        source_dir=root, build_dir=build_dir,
        configure_commands=[["cmake", "-S", ".", "-B", build_dir.removeprefix(root + "/"),
                             "-DCMAKE_BUILD_TYPE=Debug", "-DCONTROL_FEATURE=ON"]],
        build_commands=[["cmake", "--build", build_dir.removeprefix(root + "/"),
                         "--target", "control"]],
        expected_outputs=outputs, dependency_files=[marker], environment={"CFLAGS": "-g"},
        execution_cwd={"configure": root, "build": root},
    )
    assert validate_build_recipe(recipe, action) == []
    before = copy.deepcopy(action)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=tmp_path))
    assert _deterministic_native_recipe(unit, action) is None
    assert action == before
    for relative in outputs:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"inert expected artifact")
    assert _validate_expected_outputs(tmp_path, recipe) == []
    (tmp_path / outputs[0]).unlink()
    assert _validate_expected_outputs(tmp_path, recipe) == [
        f"required build output is missing: {outputs[0]}"]


def test_cmake_fallback_still_validates_absent_recipe_and_output_custody(tmp_path):
    (tmp_path / "CMakeLists.txt").write_text("project(control)\n", encoding="utf-8")
    action = _native()
    action["recipe"] = None
    unit = SimpleNamespace(job=SimpleNamespace(target_root=tmp_path))
    recipe = _deterministic_native_recipe(unit, action)
    assert validate_build_recipe(recipe, action) == []
    assert recipe["build_dir"] == recipe["expected_outputs"][0] == "build"
    (tmp_path / "build").mkdir()
    assert _validate_expected_outputs(tmp_path, recipe, "build")
    (tmp_path / "build" / "control").write_bytes(b"inert")
    assert _validate_expected_outputs(tmp_path, recipe, "build") == []
    recipe["expected_outputs"] = ["../outside"]
    assert validate_build_recipe(recipe, action)
    with pytest.raises(ValueError, match="escaped"):
        _validate_expected_outputs(tmp_path, recipe)


@pytest.mark.parametrize("selected", [False, True], ids=["marker-fallback", "selected-out"])
def test_real_project_plan_keeps_cmake_contract_and_admits_planning_output(tmp_path, selected):
    runner, root, graph, _ = accepted_native(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    action = _native()
    for document in action["descriptor_package"]["documents"]:
        (target / document["path"]).write_text(document["content"])
    recipe = action["recipe"]
    recipe.update(
        build_dir="out",
        configure_commands=[["cmake", "-S", ".", "-B", "out", "-DCONTROL_FEATURE=ON"]],
        build_commands=[["cmake", "--build", "out", "--target", "control"]],
        expected_outputs=["out/control"], environment={"CFLAGS": "-g"},
    )
    assert validate_build_recipe(recipe, action) == []
    if not selected:
        action["recipe"] = None
    plan = copy.deepcopy(load_accepted_plan(root))
    plan["scanner_selections"] = []
    plan["build_topology"]["build_actions"] = [action]
    plan["build_topology"]["planning_refinement"] = refine_build_topology(
        graph, [action], profiles=_profile())

    def publish(unit):
        path = unit.job.attempt_root / "source-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(root, path), "terminal_status": "SUCCEEDED"}

    producer = Job("job_target_analysis_plan", runner.config.job("job_target_analysis_plan").name,
                   lambda _: {}, units=(Unit("plan_acceptance.publish_handoff", publish),))
    runner.run(producer, run_id=root.name, source_fingerprint="synthetic-source")
    plan_unit = next(unit for unit in build_job().units if unit.unit_id == "plan.load_recipes")
    context = SimpleNamespace(
        job=SimpleNamespace(run_root=root, target_root=target, source_fingerprint="synthetic-source",
                            config=runner.config.job("job_project_build"),
                            review_policy=runner.config.review_policy),
        unit_id=plan_unit.unit_id)
    result = plan_unit.handler(context)
    actual = result["actions"][0]["recipe"]
    if selected:
        assert actual == recipe
    else:
        assert actual["expected_outputs"] == [actual["build_dir"]] == ["build"]
    guard_build_cache(root, "job_project_build", result, unit_id=plan_unit.unit_id,
                      source_fingerprint="synthetic-source",
                      configuration={"build_selection": runner.config.job("job_project_build").settings["build_selection"]},
                      releases=runner.config.review_policy.releases.view())


def _planning_job(tmp_path):
    write_release(tmp_path, ("job_target_analysis_plan", "job_project_build"))
    runner, root, graph, dispatch = accepted_native(tmp_path)
    planned = copy.deepcopy(dispatch)
    del planned["image"]
    plan_output = {
        "actions": [planned], "execution_graph": graph, "scanner_selections": [],
        "action_count": 1, "processing_decisions": [], "terminal_status": "SUCCEEDED", "gaps": [],
    }
    calls = []

    def plan(_):
        calls.append("plan")
        return copy.deepcopy(plan_output)

    publisher = next(unit for unit in build_job().units
                     if unit.unit_id == "acceptance.publish_handoff")

    def publish(unit):
        outputs = {"plan.load_recipes": unit.output("plan.load_recipes")}
        for family in BUILD_FAMILIES:
            outputs[f"image.{family}"] = {"entries": [], "gaps": []}
            outputs[f"probe.{family}"] = {"receipts": [], "gaps": []}
            outputs[f"build_dispatch.{family}"] = {"dispatches": [], "gaps": []}
        for lane in STATIC_LANES:
            outputs[f"static_dispatch.{lane}"] = {"dispatches": [], "gaps": []}
        # Prepared fixture image identity only; no fabricated execution receipt.
        outputs["image.native"]["entries"] = [
            {"action": planned, "image": dispatch["image"], "terminal_status": "SUCCEEDED"}]
        outputs["build_dispatch.native"]["dispatches"] = [dispatch]
        return publisher.handler(SimpleNamespace(
            job=unit.job, unit_id=unit.unit_id, output=outputs.__getitem__))

    job = Job("job_project_build", runner.config.job("job_project_build").name, lambda _: {},
              units=(Unit("plan.load_recipes", plan),
                     Unit("acceptance.publish_handoff", publish, ("plan.load_recipes",))))
    return runner, root, job, plan_output, dispatch, calls


def _checkpoint_result(root, claim):
    return root / claim["attempt_path"] / "steps/plan/tasks/load_recipes/result.json"


def _replace_checkpoint(root, path, output):
    atomic_json(path, output)
    status_path = path.with_name("status.json")
    status = json.loads(status_path.read_bytes())
    atomic_json(status_path, {**status, "result_sha256": reference(root, path)["sha256"]})


def test_native_planning_checkpoint_reuses_without_inventing_an_image(tmp_path):
    runner, root, job, planned, _, calls = _planning_job(tmp_path)
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="synthetic-source")
    assert runner.execute_or_reuse_unit(job, claim, "plan.load_recipes") == planned
    assert runner.execute_or_reuse_unit(job, claim, "plan.load_recipes") == planned
    assert calls == ["plan"]
    assert "image" not in planned["actions"][0]


def test_native_aggregate_whole_job_reuse_and_publication_retry(tmp_path):
    runner, root, job, planned, _, calls = _planning_job(tmp_path)
    outcome = runner.run(job, run_id=root.name, source_fingerprint="synthetic-source")
    planner = ResumePlanner(runner.config, root, [job], "synthetic-source")
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    claim = runner.begin_or_reuse_attempt(job, run_id=root.name, source_fingerprint="synthetic-source")
    assert claim["reused"] is True
    assert runner.execute_or_reuse_unit(job, claim, "plan.load_recipes") == planned
    runner.execute_or_reuse_unit(job, claim, "acceptance.publish_handoff")
    reused = runner.finalize_attempt(job, claim)
    assert reused["reused"] is True
    assert reused["handoff_sha256"] == outcome["handoff_sha256"]
    assert calls == ["plan"]
    artifact = reused["result"]["outputs"]["acceptance.publish_handoff"]["artifact"]
    document = json.loads((root / artifact["path"]).read_bytes())
    assert document["execution_actions"] == planned["actions"]
    assert "image" not in document["execution_actions"][0]
    assert document["build_dispatches"][0]["image"]["image_id"].startswith("sha256:")


@pytest.mark.parametrize("change", ["recipe", "source", "descriptor", "graph", "execution"])
def test_planning_checkpoint_refuses_changed_or_execution_shaped_records(tmp_path, change):
    runner, root, job, planned, dispatch, calls = _planning_job(tmp_path)
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="synthetic-source")
    runner.execute_or_reuse_unit(job, claim, "plan.load_recipes")
    changed = copy.deepcopy(planned)
    action = changed["actions"][0]
    if change == "recipe":
        action["recipe"]["build_commands"][0].append("-m32")
    elif change == "source":
        action["source_fingerprint"] = "other-source"
    elif change == "descriptor":
        action["descriptor_package"]["documents"][0]["content"] += "# changed\n"
    elif change == "graph":
        changed["execution_graph"]["source_fingerprint"] = "other-source"
    else:
        action.update(image=dispatch["image"], execution_owner="job_project_build", commands=[])
    _replace_checkpoint(root, _checkpoint_result(root, claim), changed)
    checkpoint = _checkpoint_result(root, claim).with_name("checkpoint.json")
    before = checkpoint.read_bytes()
    with pytest.raises(ValueError, match="immutable shared artifact conflicts"):
        runner.execute_or_reuse_unit(job, claim, "plan.load_recipes")
    assert calls == ["plan", "plan"]
    assert checkpoint.read_bytes() == before


@pytest.mark.parametrize("change", ["tamper", "missing", "rejected", "configuration", "release"])
def test_planning_checkpoint_and_whole_job_refuse_lost_admission(tmp_path, change):
    runner, root, job, planned, _, calls = _planning_job(tmp_path)
    outcome = runner.run(job, run_id=root.name, source_fingerprint="synthetic-source")
    planner = ResumePlanner(runner.config, root, [job], "synthetic-source")
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    claim = json.loads((root / outcome["handoff"]["resolving_paths"]["attempt"] / "claim.json").read_bytes())
    action = planned["actions"][0]
    receipt = root / action["topology_refinement"]["path"]
    kwargs = {"configuration": {"build_selection": runner.config.job("job_project_build").settings["build_selection"]},
              "releases": runner.config.review_policy.releases.view(),
              "source_fingerprint": "synthetic-source", "unit_id": "plan.load_recipes"}
    if change == "tamper":
        receipt.write_bytes(receipt.read_bytes() + b" ")
    elif change == "missing":
        receipt.unlink()
    elif change == "rejected":
        atomic_json(root / "data/build/topology/accepted-refinements.json",
                    {"schema": "appsec-review/accepted-topology-refinements/1", "entries": []})
    elif change == "configuration":
        kwargs["configuration"] = {"build_selection": {"policy_id": "changed"}}
    else:
        kwargs["releases"] = {**kwargs["releases"], "validation": "changed"}
    exception, message = {
        "tamper": (ValueError, "integrity mismatch|digest changed"),
        "missing": (FileNotFoundError, "No such file"),
        "rejected": (ValueError, "no accepted index entry"),
        "configuration": (ValueError, "selection differs"),
        "release": (ValueError, "releases differ"),
    }[change]
    with pytest.raises(exception, match=message):
        guard_build_cache(root, job.job_id, planned, **kwargs)
    if change in {"configuration", "release"}:
        path = runner.config.source_path
        text = path.read_text()
        if change == "configuration":
            text = text.replace('name = "synthetic native cache producer"',
                                'name = "synthetic native cache producer"\nworkers = 2')
        else:
            text = text.replace('validation = "synthetic-validation/1"', 'validation = "changed"')
        path.write_text(text)
        changed_config = load_config(path)
        planner = ResumePlanner(changed_config, root, [job], "synthetic-source")
        runner = JobRunner(changed_config)
    decision = planner.plan(emit_event=False)[0]
    assert decision.action == "RUN"
    expected_reason = ("resolved configuration identity changed" if change in {"configuration", "release"}
                       else "build topology cache admission failed")
    assert any(expected_reason in reason for reason in decision.reasons)
    checkpoint = _checkpoint_result(root, claim).with_name("checkpoint.json")
    before = checkpoint.read_bytes()
    with pytest.raises(ValueError, match="immutable shared artifact conflicts|configuration"):
        runner.execute_or_reuse_unit(job, claim, "plan.load_recipes")
    assert checkpoint.read_bytes() == before
    assert outcome["handoff"]["status"] == "ACCEPTED"
    assert calls == (["plan"] if change in {"configuration", "release"} else ["plan", "plan"])


@pytest.mark.parametrize("location", ["dispatch", "unknown", "flag", "nested-plan"])
def test_only_actual_planning_context_can_omit_native_image(tmp_path, location):
    runner, root, _, planned, _, _ = _planning_job(tmp_path)
    action = copy.deepcopy(planned["actions"][0])
    if location == "dispatch":
        output = {"dispatches": [action]}
    elif location == "unknown":
        output = {"actions": [action]}
    elif location == "flag":
        output = {"dispatches": [{**action, "planning": True}]}
    else:
        output = {"dispatches": [{"outputs": {"plan.load_recipes": planned}}]}
    with pytest.raises(ValueError, match="immutable image"):
        guard_build_cache(root, "job_project_build", output,
                          releases=runner.config.review_policy.releases.view())
    with pytest.raises(ValueError, match="immutable image"):
        guard_action(root, action)


@pytest.mark.parametrize("change", ["recipe", "source", "missing-image", "other-image"])
def test_whole_job_refuses_changed_planning_or_execution_identity(tmp_path, change):
    runner, root, job, planned, dispatch, _ = _planning_job(tmp_path)
    if change == "recipe":
        planned["actions"][0]["recipe"]["build_commands"][0].append("-m32")
    elif change == "source":
        planned["actions"][0]["root"] = "elsewhere"
    elif change == "missing-image":
        del dispatch["image"]["image_id"]
    else:
        dispatch["image"]["image_id"] = "sha256:" + "e" * 64
    result = runner.run(job, run_id=root.name, source_fingerprint="synthetic-source")
    assert result["handoff"]["status"] == "ACCEPTED"
    decision = ResumePlanner(runner.config, root, [job], "synthetic-source").plan(emit_event=False)[0]
    assert decision.action == "RUN"
    assert any("build topology cache admission failed" in reason for reason in decision.reasons)


@pytest.mark.parametrize("extra", [
    {"execution_owner": "job_project_build", "commands": []},
    {"artifacts": [], "terminal_status": "SUCCEEDED"},
    {"planning": True},
])
def test_execution_receipts_cannot_be_relabelled_as_planning_actions(tmp_path, extra):
    runner, root, job, planned, _, _ = _planning_job(tmp_path)
    planned["actions"][0].update(extra)
    with pytest.raises(ValueError, match="execution or unsupported fields"):
        guard_build_cache(root, job.job_id, planned, unit_id="plan.load_recipes",
                          releases=runner.config.review_policy.releases.view())


def test_planning_reuse_requires_the_selected_immutable_recipe_revision(tmp_path):
    from appsec_review.jobs.build_topology_artifacts import selected_cache_actions
    from tests.unit.job_build_iteration.test_continuity import _selected_trial

    runner, root, graph, original, _, _, _ = _selected_trial(tmp_path)
    planned = {key: value for key, value in original.items() if key != "image"}
    output = {"execution_graph": graph, "actions": [planned]}
    kwargs = {"unit_id": "plan.load_recipes", "releases": runner.config.review_policy.releases.view()}
    with pytest.raises(ValueError, match="selected immutable recipe revision"):
        guard_build_cache(root, "job_project_build", output, **kwargs)
    selected = selected_cache_actions(root)[planned["build_unit_id"]]
    planned.update(recipe=selected["recipe"], topology_refinement=selected["topology_refinement"])
    guard_build_cache(root, "job_project_build", output, **kwargs)
    with pytest.raises(ValueError, match="immutable image"):
        guard_action(root, planned)
