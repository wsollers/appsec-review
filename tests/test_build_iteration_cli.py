from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from appsec_review import cli
from appsec_review.config import load_config
from appsec_review.interchange import HANDOFF_SCHEMA, handoff_input_projection, input_set_sha256
from appsec_review.jobs.build_iterations import decode_replay_context, read_reference, retain
from appsec_review.jobs.build_recipe_replay import ProducerProduct
from appsec_review.jobs.build_workspace import BuildWorkspace, ProductSpec
from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import immutable_bytes, reference, verify_reference
from tests.test_build_recipe_replay import _executor, build as replay_build


@pytest.fixture
def build(replay_build, tmp_path):
    original = replay_build
    run = tmp_path / "cli-runs/2026-10-12-0001"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    initial = workspace.materialize(original.source, original.context.binding.source_identity)
    graph = read_reference(original.workspace.run_dir, original.context.inputs["graph"])
    producer = next(node for node in graph["nodes"] if node["root"] == "z-library")
    binding_a = original.context.upstreams[0].binding
    with workspace.writer() as writer:
        writer.begin_attempt(binding_a, "A-success", initial)
        for path, content in {
            "lib/libA.a": original.a_bytes, "include/a.h": original.original["shared/a.h"],
            "lib/pkgconfig/a.pc": b"Name: A\nLibs: -L/install/lib -lA\n",
        }.items():
            output = workspace.paths.install / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(content)
        record = writer.commit((
            ProductSpec("install/lib/libA.a", **producer["products"][0]),
            ProductSpec("install/include/a.h", "headers", "include:A", "include:A", original.context.variant),
            ProductSpec("install/lib/pkgconfig/a.pc", "package_metadata", "pkg:A", "pkg:A", original.context.variant),
        ))
        generation = writer.state()["generation"]
        atomic_json(run / "data/test-checkpoints.json",
                    {"a": [binding_a.node_id, initial, generation]})
        binding_b = replace(original.context.binding, upstream_products=(record.identity,))
        writer.begin_attempt(binding_b, "B-failed", generation)
        writer.fail_attempt("fixture compiler exit 2")
    failure = read_reference(original.workspace.run_dir, original.context.inputs["failure"])
    for evidence in failure["evidence"]:
        immutable_bytes(run, evidence["path"], verify_reference(original.workspace.run_dir, evidence).read_bytes())
    inputs = {
        "failure": retain(run, "failures", {**failure, "binding": binding_b.view()}),
        "graph": retain(run, "graphs", graph),
        "configuration": retain(run, "configurations", read_reference(
            original.workspace.run_dir, original.context.inputs["configuration"])),
        "source": reference(run, run / "artifacts/build/workspace/input.json"),
    }
    context = replace(original.context, run_id=run.name, binding=binding_b, generation_identity=generation,
                      inputs=inputs, upstreams=(ProducerProduct(binding_a, record.reference),))
    candidate = replace(original.candidate, evidence=(inputs["graph"],))
    return replace(original, workspace=workspace, context=context, candidate=candidate)


@pytest.fixture
def recovery(build, monkeypatch):
    run = build.workspace.run_dir
    config = load_config(Path(__file__).parents[1] / "appsec-review.toml")
    config = replace(config, runtime=replace(config.runtime, runs_dir=run.parent))
    monkeypatch.setattr(cli, "load_config", lambda *_, **__: config)
    directory = run / "data/configuration"
    directory.mkdir(parents=True)
    (directory / "resolved.json").write_bytes(config.resolved_json)
    atomic_json(directory / "manifest.json", {"resolved_sha256": config.resolved_sha256, "selection": {}})
    request = retain(run, "requests", {
        "attempt_id": build.context.failed_attempt_id, "generation": build.context.generation_identity,
        "node_id": build.context.binding.node_id, "binding": build.context.binding.view(),
        "graph": build.context.inputs["graph"], "configuration": build.context.inputs["configuration"],
        "dispatch": {**build.context.validation_unit, "image": {
            "family": "native", "image_tag": "fixture:base", "image_id": build.context.binding.image_identity,
            "user": "1000:1000", "dependency_hashes": {}}},
        "producers": {item.binding.node_id: item.binding.view() for item in build.context.upstreams},
    })
    failure = retain(run, "failures", {
        **read_reference(run, build.context.inputs["failure"]), "request": request})
    context = replace(build.context, inputs={**build.context.inputs, "failure": failure})
    atomic_json(run / "data/build/iterations/failures" / f"{context.binding.node_id}.json",
                {"failure": failure, "request": request})
    context_ref = retain(run, "contexts", context.view())
    return config, context, context_ref


def _arguments(context_ref, command="replay-build-recipe"):
    return [command, "--run-id", "2026-10-12-0001", "--context", json.dumps(context_ref)]


@pytest.mark.parametrize("status", ["STOPPED", "BLOCKED", "FAILED", "SUCCEEDED"])
def test_replay_cli_uses_real_replay_status_and_promotes_only_a_verified_trial(
        build, recovery, tmp_path, monkeypatch, capsys, status):
    _config, context, context_ref = recovery
    from appsec_review.jobs import build_iterations
    executor = _executor(build, exit_code=2 if status == "FAILED" else 0)
    monkeypatch.setattr(build_iterations, "captured_replay", lambda _config, _context, invocation: executor(invocation))
    recipe = (context.accepted_recipe if status == "STOPPED" else
              {**build.candidate.recipe, **({"system_packages": ["libssl-dev"]} if status == "BLOCKED" else {})})
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(replace(build.candidate, recipe=recipe).view()))
    arguments = [*_arguments(context_ref), "--candidate", str(candidate)]
    if status == "BLOCKED":
        arguments.append("--offline")
    assert cli.main(arguments) == (0 if status == "SUCCEEDED" else 1)
    trial = json.loads(capsys.readouterr().out)
    assert read_reference(build.workspace.run_dir, trial)["status"] == status
    assert executor.call_count == (0 if status in {"STOPPED", "BLOCKED"} else 1)
    if status == "SUCCEEDED":
        assert cli.main([*_arguments(context_ref, "promote-build-recipe"), "--trial", json.dumps(trial)]) == 0
        promotion = json.loads(capsys.readouterr().out)
        assert read_reference(build.workspace.run_dir, promotion)["recipe_identity"]
        assert (build.workspace.run_dir / "data/build/iterations/selection.json").is_file()
        assert not (build.workspace.paths.install / "bin/B").exists()


def test_replay_cli_refuses_changed_configuration_before_execution(build, recovery, tmp_path, monkeypatch):
    config, _context, context_ref = recovery
    monkeypatch.setattr(cli, "load_config", lambda *_, **__: replace(config, resolved_sha256="f" * 64))
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(build.candidate.view()))
    with pytest.raises(ValueError, match="differs from its frozen run"):
        cli.main([*_arguments(context_ref), "--candidate", str(candidate)])


def test_replay_cli_rejects_candidate_schema(build, recovery, tmp_path):
    _config, _context, context_ref = recovery
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps({**build.candidate.view(), "schema": "unregistered/1"}))
    with pytest.raises(ValueError, match="candidate schema is unsupported"):
        cli.main([*_arguments(context_ref), "--candidate", str(candidate)])


def test_replay_cli_consumes_a_pinned_approved_full_profile_without_image_preparation(
        build, recovery, tmp_path, monkeypatch, capsys):
    from appsec_review.container_runtime import BuildProfile
    from appsec_review.jobs import build_iterations
    _config, context, context_ref = recovery
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate.view()))
    profile = BuildProfile("native", "fixture:prepared", "sha256:" + "2" * 64, "1000:1000",
                           context.binding.image_identity)
    evidence = retain(build.workspace.run_dir, "image-approvals", {
        "image_id": profile.image_id, "profile": asdict(profile), "operator_approved": True,
        "recipe_identity": build_iterations.digest(candidate.recipe), "network": "none", "prepared": True})
    executor = _executor(build)

    def captured(_config, _context, invocation):
        assert invocation.profile == profile and invocation.network == "none"
        return executor(invocation)

    monkeypatch.setattr(build_iterations, "captured_replay", captured)
    assert cli.main([*_arguments(context_ref), "--candidate", str(path), "--offline",
                     "--prepared-image", json.dumps(evidence)]) == 0
    assert read_reference(build.workspace.run_dir, json.loads(capsys.readouterr().out))["status"] == "SUCCEEDED"


@pytest.fixture
def accepted_plan(build, recovery):
    config, context, _context_ref = recovery
    run = build.workspace.run_dir
    graph = read_reference(run, context.inputs["graph"])
    plan = retain(run, "accepted-plans", {
        "schema": PLAN_SCHEMA, "source_fingerprint": graph["source_fingerprint"],
        "build_topology": {"executable_graph": graph, "build_actions": [context.validation_unit]}})
    outcomes = retain(run, "outcomes", {"schema": "appsec-review/job-outcomes/1"})
    handoff = {
        "schema": HANDOFF_SCHEMA, "run_id": run.name, "job_id": "job_target_analysis_plan",
        "attempt_id": "plan-accepted", "status": "ACCEPTED", "completion_status": "SUCCEEDED",
        "execution_status": "SUCCEEDED", "outputs": {"plan_acceptance.publish_handoff": {"artifact": plan}},
        "artifacts": [plan, outcomes], "outcomes": outcomes, "upstream_handoff_sha256": {},
        "resolved_config_sha256": config.resolved_sha256, "job_config_sha256": "a" * 64,
        "source_fingerprint": graph["source_fingerprint"], "target_snapshot": graph["source_fingerprint"],
        "implementation_identity": "fixture/1", "schema_identity": "fixture/1",
        "validation_identity": "fixture/1", "tool_identity": {}, "input_identity": {},
        "input_manifest": None, "dataset_contract_sha256": "b" * 64,
        "coverage": {"disposition": "complete", "gap_count": 0, "retry_required": False},
        "resolving_paths": {}, "started_at": "fixture-start", "completed_at": "fixture-end",
    }
    handoff["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff))
    accepted = retain(run, "handoffs", handoff)
    atomic_json(run / "data/jobs/job_target_analysis_plan/latest.json", {
        "handoff_path": accepted["path"], "handoff_sha256": accepted["sha256"]})
    return config, context


def test_failure_context_cli_resolves_actual_accepted_plan_handoff_and_producer_evidence(
        build, accepted_plan, tmp_path, capsys):
    config, context = accepted_plan
    run = build.workspace.run_dir
    products = tmp_path / "products.json"
    products.write_text(json.dumps([asdict(spec) for spec in context.products]))
    assert cli.main(["build-failure-context", "--run-id", run.name, "--node-id", context.binding.node_id,
                     "--products", str(products)]) == 0
    result = json.loads(capsys.readouterr().out)
    decoded = decode_replay_context(read_reference(run, result))
    assert decoded.binding == context.binding
    assert decoded.validation_unit == context.validation_unit
    assert decoded.products == context.products
    assert decoded.upstreams == context.upstreams
    assert decoded.releases == context.releases
    generation = read_reference(run, decoded.inputs["production_generation"])
    assert generation["failure_generation"] == generation["selected_generation"] == context.generation_identity


@pytest.mark.parametrize("change", ["missing", "same-bytes-new-reference", "changed-binding"])
def test_failure_context_refuses_missing_or_changed_original_products(build, accepted_plan, change):
    from appsec_review.jobs.build_iterations import failure_context
    from appsec_review.jobs.build_workspace import WorkspaceError
    _config, context = accepted_plan
    upstream = context.upstreams[0]
    with build.workspace.writer() as writer:
        writer.resume()
        checkpoint = json.loads((build.workspace.run_dir / "data/test-checkpoints.json").read_bytes())["a"]
        writer.invalidate_nodes(
            (upstream.binding.node_id,),
            [checkpoint],
            operation_id="context-negative-" + change, expected_generation=writer.state()["generation"])
        if change != "missing":
            binding = (upstream.binding if change == "same-bytes-new-reference" else
                       replace(upstream.binding, recipe_identity="different-recipe/1"))
            writer.begin_attempt(binding, "A-replacement", writer.state()["generation"])
            library = build.workspace.paths.install / "lib/libA.a"
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_bytes(build.a_bytes)
            writer.commit((ProductSpec("install/lib/libA.a", "library", "replacement", "A", context.variant),))
    with pytest.raises(WorkspaceError, match="failure prerequisites changed"):
        failure_context(build.workspace.run_dir, context.binding.node_id, [asdict(spec) for spec in context.products])


@pytest.mark.parametrize("field", ["graph_identity", "configuration_identity"])
def test_failure_context_refuses_incompatible_retained_binding_even_with_matching_bytes(
        build, accepted_plan, field):
    from appsec_review.jobs.build_iterations import failure_context
    from appsec_review.jobs.build_workspace import WorkspaceError
    _config, context = accepted_plan
    binding = replace(context.upstreams[0].binding, node_id="independent-C", **{field: "different/1"})
    with build.workspace.writer() as writer:
        writer.resume()
        writer.begin_attempt(binding, "C-success", writer.state()["generation"])
        library = build.workspace.paths.install / "lib/libC.a"
        library.write_bytes(build.a_bytes)
        writer.commit((ProductSpec("install/lib/libC.a", "library", "C", "C", context.variant),))
    with pytest.raises(WorkspaceError, match="incompatible retained production inputs"):
        failure_context(build.workspace.run_dir, context.binding.node_id, [asdict(spec) for spec in context.products])


def test_failure_context_source_cannot_change_at_the_public_workspace_boundary(build, accepted_plan):
    from appsec_review.jobs.build_workspace import ReconstructionMiss
    _config, context = accepted_plan
    binding = replace(context.upstreams[0].binding, node_id="independent-C", source_identity="different/1")
    with build.workspace.writer() as writer:
        writer.resume()
        with pytest.raises(ReconstructionMiss, match="pinned source identity changed"):
            writer.begin_attempt(binding, "C-success", writer.state()["generation"])
