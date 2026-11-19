"""Offline regressions for durable iteration reconstruction and repair contexts."""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict

import pytest

from appsec_review.jobs.build_iterations import (
    IterationOutcome, decode_replay_context, failure_context, read_reference,
    select_promotion, selected_revisions,
)
from appsec_review.jobs.build_workspace import BuildWorkspace
from appsec_review.storage.shared import immutable_bytes
from tests.test_build_topology_refinement import accepted_native
from tests.unit.job_build_iteration.test_workspace_resume import (
    _invoke, _iterations, _succeeding_worker,
)


def _failed_context(runner, root, graph, action):
    stderr = immutable_bytes(root, "artifacts/synthetic/stderr", b"synthetic build failure")
    stdout = immutable_bytes(root, "artifacts/synthetic/stdout", b"")

    def fail(request, _run_id):
        return IterationOutcome(
            {"build_unit_id": request["node_id"], "terminal_status": "FAILED",
             "gaps": ["synthetic build failure"], "commands": [
                 {"exit_code": 1, "timed_out": False, "stdout": stdout, "stderr": stderr}]}, (), True)

    assert _iterations(runner, root, graph, action).run(fail, invoke=_invoke)["states"] == {
        action["build_unit_id"]: "FAILED"}
    outcome = _succeeding_worker(root, graph, action)({"node_id": action["build_unit_id"]}, "fixture")
    (BuildWorkspace(root).paths.target / "build/control").unlink()
    # Restore the clean failure generation after constructing only the product specification.
    with BuildWorkspace(root).writer() as writer:
        writer.restore(writer.state()["generation"])
    context = decode_replay_context(read_reference(
        root, failure_context(root, action["build_unit_id"], [asdict(spec) for spec in outcome.products])))
    return context, stderr


def test_changed_admitted_recipe_rebuilds_then_reuses_its_committed_product(tmp_path):
    from appsec_review.jobs.build_topology_artifacts import bind_actions
    from tests.test_native_target_enforcement import _profile

    runner, root, graph, action = accepted_native(tmp_path)
    calls = []

    def execute(request, run_id):
        calls.append(request["binding"]["recipe_identity"])
        return _succeeding_worker(root, graph, action)(request, run_id)

    assert _iterations(runner, root, graph, action).run(execute, invoke=_invoke)["states"] == {
        action["build_unit_id"]: "SUCCEEDED"}
    revised = copy.deepcopy(action)
    revised["recipe"]["build_commands"][0].append("-g")
    revised = bind_actions(
        root, [revised], profiles=_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())[0]
    for _ in range(2):
        result = _iterations(runner, root, graph, revised).run(execute, invoke=_invoke)
        assert result["states"] == {action["build_unit_id"]: "SUCCEEDED"}, result
    assert len(calls) == 2 and calls[0] != calls[1]
    assert result["receipts"][0]["checkpoint_reused"] is True
    assert len(list((root / "artifacts/build/iterations/invalidations").glob("*.json"))) == 1


@pytest.mark.parametrize("tamper", ["receipt", "product", "binding"])
def test_changed_recipe_never_repairs_corrupt_retained_custody(tmp_path, tamper):
    from appsec_review.jobs.build_topology_artifacts import bind_actions
    from appsec_review.storage import atomic_json
    from tests.test_native_target_enforcement import _profile

    runner, root, graph, action = accepted_native(tmp_path)
    controller = _iterations(runner, root, graph, action)
    controller.run(_succeeding_worker(root, graph, action), invoke=_invoke)
    ledger = json.loads(controller.ledger_path.read_bytes())
    entry = ledger["nodes"][action["build_unit_id"]]
    if tamper == "binding":
        entry["binding"]["recipe_identity"] = "changed"
        atomic_json(controller.ledger_path, ledger)
    else:
        path = root / entry[tamper]["path"]
        path.chmod(0o600)
        path.write_bytes(b"{}")
    revised = copy.deepcopy(action)
    revised["recipe"]["build_commands"][0].append("-g")
    revised, = bind_actions(
        root, [revised], profiles=_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())
    state = (root / controller.workspace.state_relative).read_bytes()
    result = _iterations(runner, root, graph, revised).run(
        lambda *_: pytest.fail("corrupt custody must not dispatch"), invoke=_invoke)
    assert result["terminal_status"] == "BLOCKED"
    assert (root / controller.workspace.state_relative).read_bytes() == state


def _accepted_nodes(tmp_path):
    from appsec_review.jobs.build_topology import (
        compile_build_topology, refine_build_topology, topology_evidence_bundle,
    )
    from appsec_review.jobs.build_topology_artifacts import bind_actions
    from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
    from appsec_review.runtime import Job, Unit
    from appsec_review.storage import atomic_json
    from appsec_review.storage.shared import reference
    from tests.test_native_target_enforcement import _native, _profile

    runner, _, _, _ = accepted_native(tmp_path)
    actions = []
    target = tmp_path / "nodes-source"
    target.mkdir()
    for uid in ("a", "b", "c"):
        action = _native()
        action.update(build_unit_id=uid, root=uid)
        documents = action["descriptor_package"]["documents"]
        documents[0]["content"] = f"project({uid})\nadd_executable({uid} main.c)\n"
        if uid == "b":
            documents[0]["content"] += "add_dependencies(b a)\n"
        for document in documents:
            document["path"] = f"{uid}/{document['path']}"
            document["sha256"] = hashlib.sha256(document["content"].encode()).hexdigest()
            document["size_bytes"] = len(document["content"].encode())
            path = target / document["path"]
            path.parent.mkdir(exist_ok=True)
            path.write_text(document["content"])
        action["markers"] = [{key: documents[0][key] for key in ("path", "sha256", "size_bytes")}]
        action["recipe"].update(
            build_unit_id=uid, source_dir=uid, build_dir=f"{uid}/build",
            dependency_files=[document["path"] for document in documents],
            expected_outputs=[f"{uid}/build/main.o"])
        actions.append(action)
    sources = [{**action, "recipe": None} for action in actions]
    graph = compile_build_topology(sources, source_fingerprint="synthetic-source", profiles=_profile())
    plan = {"schema": PLAN_SCHEMA, "source_fingerprint": "synthetic-source", "build_topology": {
        "executable_graph": graph, "build_actions": sources,
        "evidence_bundle": topology_evidence_bundle(
            sources, source_fingerprint="synthetic-source", profiles=_profile()),
        "planning_refinement": refine_build_topology(graph, sources, profiles=_profile()),
    }}

    def publish(context):
        path = context.job.attempt_root / "nodes-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(context.job.run_root, path), "terminal_status": "SUCCEEDED"}

    result = runner.run(
        Job("job_target_analysis_plan", "synthetic accepted source producer", lambda _: {},
            units=(Unit("plan_acceptance.publish_handoff", publish),)),
        source_fingerprint="synthetic-source")
    root = runner.config.runtime.runs_dir / result["status"]["run_id"]
    actions = bind_actions(
        root, actions, profiles=_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())
    for action in actions:
        action["image"] = {"image_id": _profile()["image_digest"]}
    return runner, root, target, graph, actions


@pytest.mark.parametrize("changed", [("a",), ("a", "c")], ids=["closure", "two-changes"])
def test_recipe_changes_rebuild_only_their_dependency_closure(tmp_path, changed):
    from dataclasses import replace
    from appsec_review.config.build_selection import parse_build_selection
    from appsec_review.jobs.build_iterations import BuildIterations
    from appsec_review.jobs.build_topology_artifacts import bind_actions
    from tests.test_native_target_enforcement import _profile

    runner, root, target, graph, actions = _accepted_nodes(tmp_path)
    assert {(edge["producer_build_unit_id"], edge["consumer_build_unit_id"])
            for edge in graph["edges"]} == {("a", "b")}

    def controller(dispatches):
        return BuildIterations(
            root, target, graph, dispatches,
            configuration={"build_selection": parse_build_selection(
                runner.config.job("job_project_build").settings["build_selection"]).view()},
            releases=runner.config.review_policy.releases.view(),
            execution_identity="synthetic-executor/1", output_policy_identity="synthetic-outputs/1")

    calls = []

    def execute(request, run_id):
        uid = request["node_id"]
        calls.append(uid)
        outcome = _succeeding_worker(root, graph, request["dispatch"])(request, run_id)
        old = BuildWorkspace(root).paths.target / "build/control"
        new = BuildWorkspace(root).paths.target / uid / "control"
        old.rename(new)
        old.parent.rmdir()
        return replace(outcome, products=tuple(replace(spec, path=f"target/{uid}/control")
                                               for spec in outcome.products))

    first = controller(actions)
    assert first.run(execute, invoke=_invoke)["states"] == dict.fromkeys(("a", "b", "c"), "SUCCEEDED")
    initial = json.loads(first.ledger_path.read_bytes())
    revised = copy.deepcopy(actions)
    for action in revised:
        if action["build_unit_id"] in changed:
            action["recipe"]["build_commands"][0].append("-g")
    revised = bind_actions(
        root, revised, profiles=_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())
    calls.clear()
    result = controller(revised).run(execute, invoke=_invoke)
    assert result["states"] == dict.fromkeys(("a", "b", "c"), "SUCCEEDED"), result
    assert set(calls) == {"a", "b", *changed}
    if "c" not in changed:
        after = json.loads(first.ledger_path.read_bytes())
        assert after["nodes"]["c"]["product"] == initial["nodes"]["c"]["product"]
        assert after["nodes"]["c"]["completion"] == initial["nodes"]["c"]["completion"]


@pytest.mark.parametrize("older_failure", [False, True])
def test_product_rejection_retains_current_failure_and_original_success_receipt(tmp_path, older_failure):
    runner, root, graph, action = accepted_native(tmp_path)
    old_attempt = None
    if older_failure:
        old_context, _ = _failed_context(runner, root, graph, action)
        old_attempt = old_context.failed_attempt_id
    attempts = []
    products = []

    def missing_product(request, run_id):
        attempts.append(request["attempt_id"])
        outcome = _succeeding_worker(root, graph, action)(request, run_id)
        products.extend(asdict(spec) for spec in outcome.products)
        (BuildWorkspace(root).paths.target / "build/control").unlink()
        return outcome

    result = _iterations(runner, root, graph, action).run(missing_product, invoke=_invoke)
    assert result["states"] == {action["build_unit_id"]: "FAILED"}
    context = decode_replay_context(read_reference(root, failure_context(root, action["build_unit_id"], products)))
    assert context.failed_attempt_id == attempts[0] != old_attempt
    failure = read_reference(root, context.inputs["failure"])
    assert failure["terminal_status"] == "FAILED"
    assert "missing" in failure["transaction_error"].lower()
    assert read_reference(root, failure["receipt"])["terminal_status"] == "SUCCEEDED"
    assert failure["receipt"] in failure["evidence"]
    assert failure["prepared"] in failure["evidence"]
    with BuildWorkspace(root).writer() as writer:
        assert writer.state()["attempt"] is None
        assert writer.committed_generation()["accepted"] == {}
        from appsec_review.jobs.build_recipe_replay import _validate_context
        assert _validate_context(BuildWorkspace(root), context, writer) == graph


def _selected_trial(tmp_path):
    from appsec_review.config import BuildCaptureConfig
    from appsec_review.container_runtime import BuildProfile, CaptureScope
    from appsec_review.jobs.build_recipe_replay import RecipeCandidate, TrialExecution, replay_recipe
    from tests.capture_fakes import minimal_elf, simulated_executor

    runner, root, graph, action = accepted_native(tmp_path)
    action["image"].update(family="native", image_tag="fixture:local", user="1000:1000", dependency_hashes={})
    context, stderr = _failed_context(runner, root, graph, action)
    recipe = copy.deepcopy(context.accepted_recipe)
    recipe["build_commands"] = [
        ["clang", "--target=x86_64-unknown-linux-gnu", "main.c", "-o", "build/control", "-g"]]
    recipe["expected_outputs"] = ["build/control"]
    candidate = RecipeCandidate(recipe, (stderr,), "synthetic missing executable correction")

    def execute(invocation):
        def behavior(argv, target, _cwd, _environment, capture):
            capture.exec("/usr/bin/clang", argv)
            (target / "build/control").write_bytes(minimal_elf())
            return 0, b"", b""

        executor = simulated_executor(
            BuildProfile("native", "fixture:local", action["image"]["image_id"], "1000:1000"), behavior)
        results = []
        for ordinal in range(len(invocation.commands)):
            argv, cwd = invocation.prepare_command(ordinal)
            results.append(executor.execute_captured(
                argv, workspace=invocation.paths.target, install_dir=invocation.paths.install,
                working_directory=cwd, environment={},
                capture_directory=invocation.capture_directory / f"command-{ordinal}",
                capture_config=BuildCaptureConfig("ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100),
                scope=CaptureScope(context.run_id, "job_project_build", invocation.attempt_id,
                                   action["build_unit_id"], "native")))
        return TrialExecution(tuple(results), all(result.cleanup_complete for result in results))

    trial = replay_recipe(BuildWorkspace(root), context, candidate, execute=execute)
    assert read_reference(root, trial)["status"] == "SUCCEEDED"
    promotion = select_promotion(root, context.view(), trial)
    return runner, root, graph, action, context, trial, promotion


def test_selected_recipe_survives_successful_production_but_new_promotion_is_stale(tmp_path):
    from appsec_review.jobs.build_recipe_replay import ReplayRefused, promote_recipe

    runner, root, graph, action, context, trial, _ = _selected_trial(tmp_path)
    selected, dispatches, overrides = selected_revisions(root, {"execution_graph": graph}, [action])
    controller = _iterations(runner, root, selected, dispatches[0])
    controller.product_overrides = overrides
    production = controller.run(_succeeding_worker(root, graph, dispatches[0]), invoke=_invoke)
    assert production["states"] == {action["build_unit_id"]: "SUCCEEDED"}
    assert selected_revisions(root, {"execution_graph": graph}, [action]) == (selected, dispatches, overrides)
    reused = _iterations(runner, root, selected, dispatches[0])
    reused.product_overrides = overrides
    result = reused.run(lambda *_: pytest.fail("accepted production must be reused"), invoke=_invoke)
    assert result["receipts"][0]["checkpoint_reused"] is True
    with pytest.raises(ReplayRefused, match="stale_generation"):
        promote_recipe(BuildWorkspace(root), context, trial)


@pytest.mark.parametrize("tamper", ["trial", "source", "release"])
def test_selected_recipe_still_rejects_changed_immutable_evidence(tmp_path, tamper):
    from dataclasses import replace
    from appsec_review.jobs.build_recipe_replay import load_promoted_revision

    _, root, _, _, context, trial, promotion = _selected_trial(tmp_path)
    if tamper == "release":
        context = replace(context, releases={**context.releases, "validation": "changed"})
    else:
        ref = trial if tamper == "trial" else context.inputs["source"]
        path = root / ref["path"]
        path.chmod(0o600)
        path.write_bytes(b"{}")
    with pytest.raises((ValueError, OSError)):
        load_promoted_revision(BuildWorkspace(root), context, promotion)
