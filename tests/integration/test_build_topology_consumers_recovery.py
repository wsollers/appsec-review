"""I2: accepted refinement -> consumers/cache/recovery. AUTHORED - NOT RUN.

R3/R6/R11 and C1: every consumer needs the chosen immutable recipe proof;
retained products and an old success cannot bypass changed identities.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, replace
import hashlib
import json
import struct
from types import SimpleNamespace

import pytest

from appsec_review.jobs.build_topology import (
    compile_build_topology, refine_build_topology, topology_evidence_bundle,
    verify_product_contract,
)
from appsec_review.jobs.build_topology_artifacts import (
    bind_actions, guard_action, guard_build_cache, load_refinement,
)
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage.shared import reference
from tests.integration.test_build_topology_catalog_planner_publication import (
    isolated_config, offline_reporting,
)


def compiler_profile():
    return {
        "schema": "appsec-review/static-compiler-profile/1", "executable": "clang",
        "driver_semantics": "clang-target/1", "compiler_sha256": "b" * 64,
        "image_digest": "sha256:" + "a" * 64, "wrapper_closure": [],
        "target_axes": {"os": "linux", "isa": "x86_64", "abi": "gnu"},
        "provenance": {"origin": "explicitly-synthetic-ia", "revision": "independent-control/1"},
    }


def native_action():
    documents = []
    for path, text in {
        "CMakeLists.txt": "project(control)\nadd_executable(control main.c)\n",
        "main.c": "int main(void) { return 0; }\n",
    }.items():
        documents.append({"path": path, "content": text,
                          "sha256": hashlib.sha256(text.encode()).hexdigest(),
                          "size_bytes": len(text.encode())})
    return {
        "build_unit_id": "independent-native-control", "root": ".", "family": "native",
        "build_system": "cmake", "markers": [{key: documents[0][key]
                                            for key in ("path", "sha256", "size_bytes")}],
        "descriptor_package": {"documents": documents, "bounds": {}, "gaps": []},
        "build_variant": {"configuration": "Release", "target_arch": None,
                          "execution_role": "target", "linkage": None, "toolchain": None, "abi": None},
        "recipe": {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": "independent-native-control",
            "image_profile": "native", "source_dir": ".", "build_dir": "build",
            "system_packages": [], "environment": {},
            "dependency_files": ["CMakeLists.txt", "main.c"], "configure_commands": [],
            "build_commands": [["clang", "--target=x86_64-unknown-linux-gnu",
                                "-c", "main.c", "-o", "build/main.o"]],
            "expected_outputs": ["build/main.o"], "network_required": False,
            "reason": "synthetic input; compiler boundary is never invoked by this suite",
        },
    }


def accepted_native(tmp_path, *, selected=None):
    config = isolated_config(tmp_path)
    runner = JobRunner(config)
    selected = native_action() if selected is None else copy.deepcopy(selected)
    source = copy.deepcopy(selected)
    source["recipe"] = None
    profile = compiler_profile()
    graph = compile_build_topology([source], source_fingerprint="independent-source", profiles=profile)
    plan = {
        "schema": PLAN_SCHEMA, "source_fingerprint": "independent-source",
        "build_topology": {
            "executable_graph": graph, "build_actions": [source],
            "evidence_bundle": topology_evidence_bundle(
                [source], source_fingerprint="independent-source", profiles=profile),
            "planning_refinement": refine_build_topology(graph, [source], profiles=profile),
        },
    }

    def publish(context):
        path = context.job.attempt_root / "independent-source-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(context.job.run_root, path), "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", "target_analysis_plan", lambda _: {},
              units=(Unit("plan_acceptance.publish_handoff", publish),))
    result = runner.run(job, source_fingerprint="independent-source")
    root = config.runtime.runs_dir / result["status"]["run_id"]
    action, = bind_actions(
        root, [selected], profiles=profile,
        policy=config.job("job_project_build").settings["build_selection"],
        releases=config.review_policy.releases.view())
    action["image"] = {"image_id": profile["image_digest"]}
    return runner, root, action


def cache_job(action, calls):
    def publish(_context):
        calls.append("published-dispatch")
        return {"dispatches": [copy.deepcopy(action)], "terminal_status": "SUCCEEDED"}

    return Job("job_project_build", "project_build", lambda _: {},
               units=(Unit("build.native", publish),))


def test_late_recipe_and_replacement_publish_new_proof_without_mutating_accepted_plan(tmp_path):
    runner, root, action = accepted_native(tmp_path)
    plan_bytes = canonical_json(load_accepted_plan(root))
    first = load_refinement(root, action["topology_refinement"])
    revised = copy.deepcopy(action)
    revised["recipe"]["build_commands"][0].append("-g")
    with pytest.raises(ValueError):
        guard_action(root, revised)
    revised, = bind_actions(
        root, [revised], profiles=compiler_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())
    assert revised["topology_refinement"] != action["topology_refinement"]
    assert guard_action(root, revised)["recipe_digest"] != guard_action(root, action)["recipe_digest"]
    assert load_refinement(root, action["topology_refinement"]) == first
    assert canonical_json(load_accepted_plan(root)) == plan_bytes
    incompatible = copy.deepcopy(revised)
    incompatible["recipe"]["build_commands"][0].append("-m32")
    incompatible, = bind_actions(
        root, [incompatible], profiles=compiler_profile(),
        policy=runner.config.job("job_project_build").settings["build_selection"],
        releases=runner.config.review_policy.releases.view())
    with pytest.raises(ValueError, match="blocked"):
        guard_action(root, incompatible)
    assert canonical_json(load_accepted_plan(root)) == plan_bytes


def test_resume_cache_and_publication_retry_require_the_live_accepted_refinement(tmp_path):
    runner, root, action = accepted_native(tmp_path)
    calls = []
    job = cache_job(action, calls)
    accepted = runner.run(job, run_id=root.name, source_fingerprint="independent-source")
    planner = ResumePlanner(runner.config, root, [job], "independent-source")
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    assert calls == ["published-dispatch"]
    index = root / "data/build/topology/accepted-refinements.json"
    original = index.read_bytes()
    atomic_json(index, {"schema": "appsec-review/accepted-topology-refinements/1", "entries": []})
    decision = planner.plan(emit_event=False)[0]
    assert decision.action == "RUN"
    assert any("topology" in reason for reason in decision.reasons)
    assert not any("missing_release_identity" in reason for reason in decision.reasons)
    with pytest.raises(ValueError):
        guard_build_cache(root, job.job_id, {"dispatches": [action]},
                          releases=runner.config.review_policy.releases.view())
    index.write_bytes(original)
    assert planner.plan(emit_event=False)[0].action == "REUSE"
    assert accepted["handoff"]["status"] == "ACCEPTED" and calls == ["published-dispatch"]


def test_task_checkpoint_with_rehashed_stale_recipe_cannot_bypass_semantic_admission(tmp_path):
    runner, root, action = accepted_native(tmp_path)
    calls = []
    job = cache_job(action, calls)
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="independent-source")
    first = runner.execute_or_reuse_unit(job, claim, "build.native")
    assert runner.execute_or_reuse_unit(job, claim, "build.native") == first
    task_path = root / claim["attempt_path"] / "steps/build/tasks/native/result.json"
    tampered = json.loads(task_path.read_bytes())
    tampered["dispatches"][0]["recipe"]["build_commands"][0].append("-m32")
    atomic_json(task_path, tampered)
    status_path = task_path.with_name("status.json")
    status = json.loads(status_path.read_bytes())
    status["result_sha256"] = reference(root, task_path)["sha256"]
    atomic_json(status_path, status)
    assert runner.execute_or_reuse_unit(job, claim, "build.native") == first
    assert calls == ["published-dispatch", "published-dispatch"]
    accepted = runner.finalize_attempt(job, claim)
    assert accepted["handoff"]["status"] == "ACCEPTED"
    index = root / "data/build/topology/accepted-refinements.json"
    original = index.read_bytes()
    atomic_json(index, {"schema": "appsec-review/accepted-topology-refinements/1", "entries": []})
    with pytest.raises(ValueError):
        runner.finalize_attempt(job, claim)
    index.write_bytes(original)
    assert runner.finalize_attempt(job, claim)["handoff_sha256"] == accepted["handoff_sha256"]


@pytest.mark.parametrize("worker", ["native", "jvm", "wasm"])
def test_stale_dispatch_is_rejected_before_any_worker_executor_is_constructed(tmp_path, worker):
    from appsec_review.jobs.job_language_build.job import _execute_one
    from appsec_review.jobs.job_language_build.jvm import execute_jvm_one
    from appsec_review.jobs.job_language_build.wasm import _execute_one as execute_wasm

    runner, root, action = accepted_native(tmp_path)
    stale = copy.deepcopy(action)
    stale["recipe"]["build_commands"][0].append("-m32")
    context = SimpleNamespace(job=SimpleNamespace(
        run_root=root, review_policy=runner.config.review_policy))
    constructed = []

    def factory(*args):
        constructed.append(args)
        raise AssertionError("an inadmissible recipe must not create an external executor")

    with pytest.raises(ValueError):
        if worker == "native":
            _execute_one(context, stale, {}, factory)
        elif worker == "jvm":
            execute_jvm_one(context, stale, {}, factory)
        else:
            execute_wasm(context, stale, {}, "rust", {}, factory)
    assert constructed == []


def test_workspace_recovery_checks_pending_recipe_before_restoring_or_changing_state(tmp_path):
    from appsec_review.jobs.build_iterations import retain, resume_build_workspace
    from appsec_review.jobs.build_workspace import BuildWorkspace

    _runner, root, action = accepted_native(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    for doc in action["descriptor_package"]["documents"]:
        (source / doc["path"]).write_bytes(doc["content"].encode())
    workspace = BuildWorkspace(root)
    workspace.materialize(source, "independent-source")
    stale = copy.deepcopy(action)
    stale["recipe"]["build_commands"][0].append("-m32")
    request = retain(root, "requests", {"dispatch": stale})
    atomic_json(root / "data/build/iterations/pending.json", {"request": request})
    state_path = root / workspace.state_relative
    state = state_path.read_bytes()
    before_source = (workspace.paths.target / "main.c").read_bytes()
    with pytest.raises(ValueError):
        resume_build_workspace(root)
    assert state_path.read_bytes() == state
    assert (workspace.paths.target / "main.c").read_bytes() == before_source


def test_retained_native_product_must_match_preflight_axes_and_role(tmp_path):
    _runner, root, action = accepted_native(tmp_path)
    bound = guard_action(root, action)
    axes = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None,
            "deployment": None, "device_kind": None, "hardware_generation": None}
    verify_product_contract(bound, [{"role": "native_object", "axes": axes}])
    with pytest.raises(ValueError):
        verify_product_contract(bound, [{"role": "native_object", "axes": {**axes, "isa": "x86"}}])
    with pytest.raises(ValueError):
        verify_product_contract(bound, [{"kind": "object", "path": "build/main.o"}])
    with pytest.raises(ValueError):
        guard_action(root, {**action, "image": {"image_id": "sha256:" + "c" * 64}})


def replay_fixture(tmp_path):
    from appsec_review.jobs.build_iterations import retain
    from appsec_review.jobs.build_recipe_replay import RecipeCandidate, ReplayContext
    from appsec_review.jobs.build_workspace import BuildWorkspace, NodeBinding, ProductSpec
    from appsec_review.storage.atomic import canonical_json_sha256
    from appsec_review.storage.shared import immutable_bytes

    unit = native_action()
    unit["recipe"]["build_commands"] = [
        ["clang", "--target=x86_64-unknown-linux-gnu", "main.c", "-o", "build/control"],
    ]
    unit["recipe"]["expected_outputs"] = ["build/control"]
    runner, root, action = accepted_native(tmp_path, selected=unit)
    plan = load_accepted_plan(root)
    graph = plan["build_topology"]["executable_graph"]
    node, = graph["nodes"]
    source = tmp_path / "source"
    source.mkdir()
    original = {}
    for doc in unit["descriptor_package"]["documents"]:
        original[doc["path"]] = doc["content"].encode()
        (source / doc["path"]).write_bytes(original[doc["path"]])
    workspace = BuildWorkspace(root)
    generation = workspace.materialize(source, "independent-source")
    releases = runner.config.review_policy.releases.view()
    configuration = canonical_json_sha256({"releases": releases})
    binding = NodeBinding(
        node["build_unit_id"], "independent-source", graph["topology_id"], configuration,
        canonical_json_sha256(unit["recipe"]), action["image"]["image_id"],
        "independent-toolchain/1", (), "independent-capture/1", "independent-outputs/1")
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "independent-failed", generation)
        (workspace.paths.target / "failed-only").write_bytes(b"failed attempt dirt must not be replayed")
        writer.fail_attempt("synthetic original compile failure")
    action["image"].update(family="native", image_tag="independent:base",
                           user="1000:1000", dependency_hashes={})
    failure_evidence = immutable_bytes(root, "artifacts/independent-failure/stderr",
                                       b"synthetic original compiler failure")
    failure = retain(root, "failures", {
        "attempt_id": "independent-failed", "binding": binding.view(), "terminal_status": "FAILED",
        "request": retain(root, "requests", {"dispatch": action}), "evidence": [failure_evidence],
    })
    axes = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None,
            "deployment": None, "device_kind": None, "hardware_generation": None}
    context = ReplayContext(
        root.name, "independent-failed", binding, generation, unit, unit["recipe"],
        dict(node["variant"]),
        (ProductSpec("target/build/control", **node["products"][0], role="executable", axes=axes),),
        releases, {
            "failure": failure, "graph": retain(root, "graphs", graph),
            "configuration": retain(root, "configurations", {
                "configuration_identity": configuration, "releases": releases}),
            "source": reference(root, root / "artifacts/build/workspace/input.json"),
        })
    recipe = copy.deepcopy(unit["recipe"])
    recipe["build_commands"][0].append("-g")
    candidate = RecipeCandidate(recipe, (context.inputs["graph"],),
                                "independent synthetic recipe adjustment")
    return SimpleNamespace(runner=runner, root=root, action=action, source=source,
                           original=original, workspace=workspace, context=context, candidate=candidate)


def prepared_resolution(fixture, candidate, *, mutation=None):
    from appsec_review.container_runtime import BuildProfile
    from appsec_review.jobs.build_iterations import retain
    from appsec_review.jobs.build_recipe_replay import ImageResolution
    from appsec_review.storage.atomic import canonical_json_sha256

    image = "sha256:" + "d" * 64
    profile = BuildProfile("native", "independent:prepared", image, "1000:1000",
                           fixture.context.binding.image_identity)
    metadata = {**compiler_profile(), "image_digest": image,
                "image_recipe_digest": canonical_json_sha256(candidate.recipe)}
    if mutation == "image":
        metadata["image_digest"] = fixture.context.binding.image_identity
    elif mutation == "recipe":
        metadata["image_recipe_digest"] = canonical_json_sha256(fixture.context.accepted_recipe)
    elif mutation == "compiler":
        metadata["compiler_sha256"] = None
    elif mutation == "driver":
        metadata["executable"] = "gcc"
    compiler = retain(fixture.root, "compiler-metadata", metadata)
    if mutation == "stale-bytes":
        (fixture.root / compiler["path"]).write_bytes(canonical_json(
            {**metadata, "compiler_sha256": "e" * 64}))
    approval = retain(fixture.root, "image-approvals", {
        "image_id": image, "profile": asdict(profile), "operator_approved": True,
        "recipe_identity": canonical_json_sha256(candidate.recipe), "network": "none", "prepared": True,
        **({} if mutation == "missing" else {"compiler_metadata": compiler}),
    })
    return ImageResolution(profile, approval)


def production_snapshot(fixture):
    state = fixture.root / fixture.workspace.state_relative
    return (state.read_bytes(),
            {path.relative_to(fixture.workspace.paths.target).as_posix(): path.read_bytes()
             for path in fixture.workspace.paths.target.rglob("*") if path.is_file()})


@pytest.mark.parametrize("mutation", ["missing", "stale-bytes", "image", "recipe", "compiler", "driver"])
def test_actual_prepared_image_requires_immutable_exact_compiler_and_recipe_before_reconstruction(
        tmp_path, monkeypatch, mutation):
    from appsec_review.jobs.build_recipe_replay import ReplayRefused, replay_recipe
    from appsec_review.jobs.build_workspace import WorkspaceWriter

    fixture = replay_fixture(tmp_path)
    candidate = replace(fixture.candidate, recipe={
        **fixture.candidate.recipe, "system_packages": ["libssl-dev"]})
    resolution = prepared_resolution(fixture, candidate, mutation=mutation)
    before = production_snapshot(fixture)
    reconstructed, executed = [], []
    real_create = WorkspaceWriter.create_replay

    def observe_create(writer, *args, **kwargs):
        reconstructed.append((args, kwargs))
        return real_create(writer, *args, **kwargs)

    def forbidden_execute(invocation):
        executed.append(invocation)
        raise AssertionError("unadmitted image must not execute")

    monkeypatch.setattr(WorkspaceWriter, "create_replay", observe_create)
    with pytest.raises((ReplayRefused, ValueError)):
        replay_recipe(
            fixture.workspace, fixture.context, candidate, network_offline=True,
            approved_image_builder=lambda *_: resolution, execute=forbidden_execute)
    assert reconstructed == [] and executed == []
    assert production_snapshot(fixture) == before
    assert {path.relative_to(fixture.source).as_posix(): path.read_bytes()
            for path in fixture.source.rglob("*") if path.is_file()} == fixture.original


@pytest.mark.parametrize("mutation", ["missing_refinement", "image", "recipe"])
def test_real_captured_callback_denies_stale_actual_image_or_recipe_before_settings_and_executor(
        tmp_path, monkeypatch, mutation):
    import appsec_review.container_runtime as runtime
    from appsec_review.container_runtime import BuildProfile
    from appsec_review.jobs.build_iterations import captured_replay
    from appsec_review.jobs.build_recipe_replay import ReplayInvocation

    fixture = replay_fixture(tmp_path)
    profile = BuildProfile("native", "independent:base", fixture.context.binding.image_identity, "1000:1000")
    candidate = replace(fixture.candidate, recipe=fixture.context.accepted_recipe)
    if mutation == "image":
        profile = replace(profile, image_id="sha256:" + "e" * 64)
    elif mutation == "recipe":
        candidate = fixture.candidate
    invocation = ReplayInvocation(
        fixture.context, candidate, fixture.workspace.paths,
        fixture.root / "artifacts/never-captured", "never-executed", "none",
        profile.image_id, profile,
        topology_refinement=None if mutation == "missing_refinement" else fixture.action["topology_refinement"])
    settings_read, constructed = [], []

    def settings(_job_id):
        settings_read.append(_job_id)
        raise AssertionError("inadmissible dispatch must fail before reading executor settings")

    def executor(*args, **kwargs):
        constructed.append((args, kwargs))
        raise AssertionError("inadmissible dispatch must not construct an executor")

    monkeypatch.setattr(runtime, "BuildContainerExecutor", executor)
    config = SimpleNamespace(runtime=SimpleNamespace(runs_dir=fixture.root.parent), job=settings)
    before = production_snapshot(fixture)
    with pytest.raises(ValueError):
        captured_replay(config, fixture.context, invocation)
    assert settings_read == [] and constructed == []
    assert production_snapshot(fixture) == before


def test_genuine_accepted_graph1_refuses_real_replay_before_any_reconstruction(tmp_path, monkeypatch):
    from appsec_review.jobs.build_iterations import read_reference, retain
    from appsec_review.jobs.build_recipe_replay import ReplayRefused, replay_recipe
    from appsec_review.jobs.build_topology import _compile_graph1
    from appsec_review.jobs.build_workspace import WorkspaceWriter

    fixture = replay_fixture(tmp_path)
    plan = copy.deepcopy(load_accepted_plan(fixture.root))
    plan["build_topology"] = {
        "executable_graph": _compile_graph1(
            plan["build_topology"]["build_actions"], source_fingerprint=plan["source_fingerprint"]),
        "build_actions": plan["build_topology"]["build_actions"],
    }

    def publish(unit):
        path = unit.job.attempt_root / "historical-source-plan.json"
        atomic_json(path, plan)
        return {"artifact": reference(fixture.root, path), "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", fixture.runner.config.job("job_target_analysis_plan").name,
              lambda _: {}, units=(Unit("plan_acceptance.publish_handoff", publish),))
    outcome = fixture.runner.run(job, run_id=fixture.root.name, source_fingerprint="independent-source")
    assert outcome["handoff"]["status"] == "ACCEPTED"
    assert load_accepted_plan(fixture.root) == plan
    graph = plan["build_topology"]["executable_graph"]
    binding = replace(fixture.context.binding, graph_identity=graph["topology_id"])
    failure = read_reference(fixture.root, fixture.context.inputs["failure"])
    context = replace(fixture.context, binding=binding, inputs={
        **fixture.context.inputs, "graph": retain(fixture.root, "graphs", graph),
        "failure": retain(fixture.root, "failures", {**failure, "binding": binding.view()}),
    })
    reconstructed, executed = [], []
    real_create = WorkspaceWriter.create_replay

    def observe_create(writer, *args, **kwargs):
        reconstructed.append((args, kwargs))
        return real_create(writer, *args, **kwargs)

    def forbidden_execute(invocation):
        executed.append(invocation)
        raise AssertionError("historical accepted graph cannot execute a graph/2 trial")

    monkeypatch.setattr(WorkspaceWriter, "create_replay", observe_create)
    before = production_snapshot(fixture)
    with pytest.raises(ReplayRefused, match="graph/1"):
        replay_recipe(fixture.workspace, context, fixture.candidate, execute=forbidden_execute)
    assert reconstructed == [] and executed == []
    assert production_snapshot(fixture) == before
    assert load_accepted_plan(fixture.root) == plan


def replay_cli_arguments(fixture, candidate, resolution):
    from appsec_review.jobs.build_iterations import retain

    context = retain(fixture.root, "contexts", fixture.context.view())
    candidate_path = fixture.source.parent / "independent-candidate.json"
    candidate_path.write_bytes(canonical_json(candidate.view()))
    return [
        "--config", str(fixture.source.parent / "appsec-review.toml"),
        "replay-build-recipe", "--run-id", fixture.root.name,
        "--context", json.dumps(context), "--candidate", str(candidate_path),
        "--offline", "--prepared-image", json.dumps(resolution.evidence),
    ]


def native_executable():
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    body = b"\xb8\x3c\0\0\0\x31\xff\x0f\x05"
    return (struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000,
                          120 + len(body), 120 + len(body), 4096) + body)


@pytest.mark.parametrize("entrypoint", ["api", "cli"])
def test_actual_prepared_image_and_native_product_close_real_captured_replay_without_mutating_production(
        tmp_path, monkeypatch, capsys, entrypoint):
    import appsec_review.container_runtime as runtime
    from appsec_review import cli
    from appsec_review.jobs.build_iterations import captured_replay, read_reference
    from appsec_review.jobs.build_recipe_replay import (
        load_promoted_revision, promote_recipe, replay_recipe,
    )
    from tests.capture_fakes import simulated_executor

    fixture = replay_fixture(tmp_path)
    candidate = replace(fixture.candidate, recipe={
        **fixture.candidate.recipe, "system_packages": ["libssl-dev"]})
    resolution = prepared_resolution(fixture, candidate)
    before = production_snapshot(fixture)
    plan_before = canonical_json(load_accepted_plan(fixture.root))
    constructed, launched = [], []
    real_executor = runtime.BuildContainerExecutor

    def behavior(argv, target, cwd, environment, recording):
        assert tuple(argv) == tuple(candidate.recipe["build_commands"][0])
        assert cwd == "." and environment["PREFIX"] == "/install"
        assert not (target / "failed-only").exists()
        assert (target / "main.c").read_bytes() == fixture.original["main.c"]
        recording.exec("/usr/bin/clang", argv)
        launched.append(tuple(argv))
        (target / "build/control").write_bytes(native_executable())
        return 0, b"", b""

    def factory(profile, **kwargs):
        constructed.append(profile)
        assert profile == resolution.profile
        assert kwargs["network"] == "none" and kwargs["network_offline"] is True
        boundary = simulated_executor(profile, behavior)
        return real_executor(profile, runner=boundary.runner, **kwargs)

    monkeypatch.setattr(runtime, "BuildContainerExecutor", factory)
    if entrypoint == "cli":
        assert cli.main(replay_cli_arguments(fixture, candidate, resolution)) == 0
        trial_ref = json.loads(capsys.readouterr().out)
    else:
        trial_ref = replay_recipe(
            fixture.workspace, fixture.context, candidate, network_offline=True,
            approved_image_builder=lambda *_: resolution,
            execute=lambda invocation: captured_replay(fixture.runner.config, fixture.context, invocation))
    trial = read_reference(fixture.root, trial_ref)
    assert trial["status"] == "SUCCEEDED" and trial["cleanup_complete"] is True
    assert trial["binding"]["image_identity"] == resolution.profile.image_id
    assert constructed == [resolution.profile]
    assert launched == [tuple(candidate.recipe["build_commands"][0])]
    assert trial["verified_interfaces"]
    assert any(item["role"] == "executable" and item["axes"]["isa"] == "x86_64"
               for item in trial["verified_interfaces"])
    refinement = load_refinement(fixture.root, trial["topology_refinement"])
    assert refinement["profiles"]["image_digest"] == resolution.profile.image_id
    assert refinement["profiles"]["image_recipe_digest"] == hashlib.sha256(
        canonical_json(candidate.recipe)).hexdigest()
    assert refinement["refinement_id"] != load_refinement(
        fixture.root, fixture.action["topology_refinement"])["refinement_id"]
    promotion = promote_recipe(fixture.workspace, fixture.context, trial_ref)
    revision = load_promoted_revision(fixture.workspace, fixture.context, promotion)
    assert revision.recipe == candidate.recipe and revision.profile == resolution.profile
    assert production_snapshot(fixture) == before
    assert canonical_json(load_accepted_plan(fixture.root)) == plan_before
    assert {path.relative_to(fixture.source).as_posix(): path.read_bytes()
            for path in fixture.source.rglob("*") if path.is_file()} == fixture.original
    approval = read_reference(fixture.root, resolution.evidence)
    compiler = fixture.root / approval["compiler_metadata"]["path"]
    compiler.write_bytes(compiler.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        load_promoted_revision(fixture.workspace, fixture.context, promotion)


@pytest.mark.parametrize("mutation", ["missing", "stale-bytes", "image", "recipe"])
def test_real_cli_prepared_metadata_failure_cannot_construct_executor_or_reconstruct(
        tmp_path, monkeypatch, mutation):
    import appsec_review.container_runtime as runtime
    from appsec_review import cli
    from appsec_review.jobs.build_workspace import WorkspaceWriter

    fixture = replay_fixture(tmp_path)
    candidate = replace(fixture.candidate, recipe={
        **fixture.candidate.recipe, "system_packages": ["libssl-dev"]})
    resolution = prepared_resolution(fixture, candidate, mutation=mutation)
    constructed, reconstructed = [], []
    real_create = WorkspaceWriter.create_replay

    def observe_create(writer, *args, **kwargs):
        reconstructed.append((args, kwargs))
        return real_create(writer, *args, **kwargs)

    def factory(*args, **kwargs):
        constructed.append((args, kwargs))
        raise AssertionError("CLI must reject inadmissible metadata before external execution")

    monkeypatch.setattr(WorkspaceWriter, "create_replay", observe_create)
    monkeypatch.setattr(runtime, "BuildContainerExecutor", factory)
    before = production_snapshot(fixture)
    with pytest.raises(ValueError):
        cli.main(replay_cli_arguments(fixture, candidate, resolution))
    assert constructed == [] and reconstructed == []
    assert production_snapshot(fixture) == before
