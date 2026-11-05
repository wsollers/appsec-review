from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
import struct
from unittest.mock import Mock

import jsonschema
import pytest

from appsec_review.config.build_workspaces import BuildWorkspacePolicy
from appsec_review.container_runtime.build_executor import BuildCommandResult, BuildProfile
from appsec_review.jobs.build_discovery import descriptor_package, discover_build_units, validate_build_recipe
from appsec_review.jobs.build_recipe_replay import (
    ImageResolution, RecipeCandidate, ReplayContext, ReplayInvocation, ReplayRefused, ProducerProduct, TrialExecution,
    load_promoted_recipe, load_promoted_revision, promote_recipe, replay_recipe,
)
from appsec_review.jobs.build_topology import compile_build_topology
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, sweep_workspaces,
)
from appsec_review.storage.atomic import canonical_json, canonical_json_sha256
from appsec_review.storage.lock import FileLock, LockUnavailable
from appsec_review.storage.shared import immutable_bytes, reference, verify_reference
from tests.test_native_target_enforcement import _archive_member, _profile


VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "fixture-toolchain/1", "abi": "gnu"}
TARGET = "--target=x86_64-unknown-linux-gnu"
_ELF_IDENT = b"\x7fELF\x02\x01\x01" + bytes(9)
_EXIT_CODE = b"\xb8\x3c\0\0\0\x31\xff\x0f\x05"
NATIVE_OUTPUT = (
    struct.pack("<16sHHIQQQIHHHHHH", _ELF_IDENT, 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120 + len(_EXIT_CODE), 120 + len(_EXIT_CODE), 4096)
    + _EXIT_CODE)
NATIVE_OBJECT = (
    struct.pack("<16sHHIQQQIHHHHHH", _ELF_IDENT, 1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 1, 0)
    + bytes(64))
NATIVE_AXES = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None,
               "deployment": None, "device_kind": None, "hardware_generation": None}


def _compiler_metadata(image_identity, recipe=None):
    profile = {**_profile(), "image_digest": image_identity}
    if recipe is not None:
        profile["image_recipe_digest"] = canonical_json_sha256(recipe)
    return profile


def _publish_source_plan(run, units, releases, *, config=None, legacy=False):
    from appsec_review.config import load_config
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.jobs.build_topology import refine_build_topology, topology_evidence_bundle
    from appsec_review.jobs.job_target_analysis_plan.planning import PLAN_SCHEMA
    from appsec_review.runtime import Job, JobRunner, Unit

    config = config or load_config(Path(__file__).parents[1] / "appsec-review.toml")
    config = replace(config, runtime=replace(config.runtime, runs_dir=run.parent),
                     review_policy=replace(config.review_policy, releases=ComponentReleases(releases)))
    profile = _compiler_metadata("sha256:" + "1" * 64)
    source_identity = units[0]["source_fingerprint"]
    graph = compile_build_topology(units, source_fingerprint=source_identity, profiles=profile)
    plan = {
        "schema": PLAN_SCHEMA, "source_fingerprint": source_identity,
        "build_topology": {
            "executable_graph": graph, "build_actions": units,
            "evidence_bundle": topology_evidence_bundle(
                units, source_fingerprint=source_identity, profiles=profile),
            "planning_refinement": refine_build_topology(graph, units, profiles=profile),
        },
    }
    if legacy:
        from appsec_review.jobs.build_topology import _compile_graph1
        plan["build_topology"] = {
            "executable_graph": _compile_graph1(units, source_fingerprint=source_identity),
            "build_actions": units,
        }

    def publish(context):
        artifact = immutable_bytes(context.job.run_root,
                                   f"artifacts/source-plans/{canonical_json_sha256(plan)}.json", canonical_json(plan))
        return {"artifact": artifact, "terminal_status": "SUCCEEDED"}

    job = Job("job_target_analysis_plan", config.job("job_target_analysis_plan").name, lambda _: {},
              units=(Unit("plan_acceptance.publish_handoff", publish),))
    result = JobRunner(config).run(job, run_id=run.name, source_fingerprint=source_identity)
    assert result["status"]["status"] == "SUCCEEDED"
    return config, plan


def _accepted_dispatch(run, unit, releases):
    from appsec_review.jobs.build_topology_artifacts import bind_actions
    action = bind_actions(run, [unit], profiles=_compiler_metadata("sha256:" + "1" * 64),
                          releases=releases)[0]
    return {**action, "image": {
        "family": "native", "image_tag": "fixture:base", "image_id": "sha256:" + "1" * 64,
        "user": "1000:1000", "dependency_hashes": {}}}


def _json(run, relative, document):
    return immutable_bytes(run, relative, canonical_json(document))


def _read(run, ref):
    return json.loads(verify_reference(run, ref).read_bytes())


@dataclass
class Fixture:
    workspace: BuildWorkspace
    context: ReplayContext
    candidate: RecipeCandidate
    a_bytes: bytes
    original: dict[str, bytes]
    source: Path


@pytest.fixture
def build(tmp_path, request):
    source = tmp_path / "source"
    original = {
        "z-library/CMakeLists.txt": b"project(A)\nadd_library(A STATIC a.c)\n",
        "z-library/a.c": b"int a(void) { return 1; }\n",
        "a-consumer/CMakeLists.txt": b"project(B)\nadd_executable(B b.c)\ntarget_link_libraries(B PRIVATE A)\n",
        "a-consumer/b.c": b'#include "../shared/a.h"\nint main(void) { return 0; }\n',
        "shared/a.h": b"int a(void);\n",
    }
    files = []
    for relative, content in original.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files.append({"path": relative, "sha256": hashlib.sha256(content).hexdigest(),
                      "size_bytes": len(content)})
    source_identity = canonical_json_sha256(files)
    units = discover_build_units(files)
    for unit in units:
        unit["descriptor_package"] = descriptor_package(source, unit, files)
        captured = {document["path"] for document in unit["descriptor_package"]["documents"]}
        for item in files:
            if item["path"] not in captured and Path(item["path"]).suffix in {".c", ".h"}:
                unit["descriptor_package"]["documents"].append({
                    **item, "content": original[item["path"]].decode()})
        unit["build_variant"] = dict(VARIANT)
        unit["source_fingerprint"] = source_identity
        root = unit["root"]
        translation = "a.c" if root == "z-library" else "b.c"
        unit["recipe"] = {
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": "native", "source_dir": root, "build_dir": root + "/build",
            "system_packages": [], "environment": {},
            "dependency_files": [marker["path"] for marker in unit["markers"]],
            "configure_commands": [], "build_commands": [
                ["clang", TARGET, "-c", translation, "-o", "build/A.o"] if root == "z-library"
                else ["clang", TARGET, translation, "-o", "build/B"]],
            "expected_outputs": [root + "/build"], "network_required": False,
            "reason": "source-backed direct compiler fixture; execution boundary is simulated",
        }
    graph = compile_build_topology(units, source_fingerprint=source_identity,
                                   profiles=_compiler_metadata("sha256:" + "1" * 64))
    producer = next(node for node in graph["nodes"] if node["root"] == "z-library")
    consumer = next(node for node in graph["nodes"] if node["root"] == "a-consumer")
    unit_b = next(unit for unit in units if unit["root"] == "a-consumer")
    run = tmp_path / "runs" / "2026-10-12-0001"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    initial = workspace.materialize(source, source_identity)
    releases = getattr(request, "param", {"platform": "platform/1", "validation": "validation/1"})
    _publish_source_plan(run, units, releases)
    action_b = _accepted_dispatch(run, unit_b, releases)
    configuration = canonical_json_sha256({"releases": releases})
    binding_a = NodeBinding(
        producer["build_unit_id"], source_identity, graph["topology_id"], configuration,
        canonical_json_sha256(next(unit["recipe"] for unit in units if unit["root"] == "z-library")),
        "sha256:" + "1" * 64, VARIANT["toolchain"], (),
        "fixture-capture/1", "fixture-output-policy/1",
    )
    a_bytes = b"!<arch>\n" + _archive_member("a.o/", NATIVE_OBJECT)
    with workspace.writer() as writer:
        writer.begin_attempt(binding_a, "A-success", initial)
        library = writer.paths.install / "lib/libA.a"
        library.parent.mkdir()
        library.write_bytes(a_bytes)
        header = writer.paths.install / "include/a.h"
        header.parent.mkdir()
        header.write_bytes(original["shared/a.h"])
        metadata = writer.paths.install / "lib/pkgconfig"
        metadata.mkdir()
        (metadata / "a.pc").write_bytes(b"Name: A\nLibs: -L/install/lib -lA\n")
        record_a = writer.commit([
            ProductSpec("install/lib/libA.a", **producer["products"][0],
                        role="static_archive", axes=NATIVE_AXES),
            ProductSpec("install/include/a.h", "headers", "include:A", "include:A", VARIANT,
                        role="headers", axes=NATIVE_AXES),
            ProductSpec("install/lib/pkgconfig/a.pc", "package_metadata", "pkg:A", "pkg:A", VARIANT,
                        role="metadata", axes=NATIVE_AXES),
        ])
        generation = writer.state()["generation"]
        binding_b = replace(binding_a, node_id=consumer["build_unit_id"],
                            recipe_identity=canonical_json_sha256(unit_b["recipe"]),
                            upstream_products=(record_a.identity,))
        writer.begin_attempt(binding_b, "B-failed", generation)
        (writer.paths.target / "failed-only").write_bytes(b"failed B dirt must not be replayed")
        library.write_bytes(b"corrupt failed B overwrite")
        header.unlink()
        writer.fail_attempt("original command exit 2; retain all evidence")
    stdout = immutable_bytes(run, "artifacts/failure/stdout", b"original failed B stdout")
    stderr = immutable_bytes(run, "artifacts/failure/stderr", b"missing ../shared/a.h")
    capture = _json(run, "artifacts/failure/capture.json", {"original": "capture"})
    failure = _json(run, "artifacts/failure/failure.json", {
        "attempt_id": "B-failed", "binding": binding_b.view(), "terminal_status": "FAILED",
        "request": _json(run, "artifacts/failure/request.json", {"dispatch": action_b}),
        "evidence": [stdout, stderr, capture],
    })
    inputs = {
        "failure": failure, "graph": _json(run, "artifacts/inputs/graph.json", graph),
        "configuration": _json(run, "artifacts/inputs/configuration.json", {
            "configuration_identity": configuration, "releases": releases}),
        "source": reference(run, run / "artifacts/build/workspace/input.json"),
    }
    context = ReplayContext(
        run.name, "B-failed", binding_b, generation, unit_b, unit_b["recipe"], dict(VARIANT),
        (ProductSpec("install/bin/B", **consumer["products"][0], role="executable",
                     axes=NATIVE_AXES),), releases, inputs,
        (ProducerProduct(binding_a, record_a.reference),),
    )
    recipe = deepcopy(unit_b["recipe"])
    recipe["build_commands"][0] += ["-g"]
    candidate = RecipeCandidate(recipe, (inputs["graph"],), "retry B with an evidenced compiler option")
    yield Fixture(workspace, context, candidate, a_bytes, original, source)
    assert {path.relative_to(source).as_posix(): path.read_bytes()
            for path in source.rglob("*") if path.is_file()} == original


def _capture(invocation, ordinal, argv, *, exit_code=0, gaps=()):
    root = invocation.capture_directory / f"command-{ordinal:03d}"
    root.mkdir(parents=True)
    run = root

    def write(relative, data):
        path = run / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"uri": relative, "sha256": hashlib.sha256(data).hexdigest()}

    events = write("events.jsonl", b"")
    stdout = write("stdout", b"trial stdout")
    stderr = write("stderr", b"" if exit_code == 0 else b"trial compiler failed")
    write("scan/stdout", b"")
    write("scan/stderr", b"")
    findings = write("scan/findings.json", canonical_json({
        "schema": "appsec-review/build-capture-secret-findings/1", "retained": 0, "findings": [],
    }))
    scan = write("scan/execution.json", canonical_json({
        "schema": "appsec-review/build-capture-secret-scan-execution/1",
        "stdout": {"uri": "stdout", "sha256": hashlib.sha256(b"").hexdigest()},
        "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest()},
    }))
    document = {
        "schema": "appsec-review/build-execution-record/1",
        "scope": {"run_id": invocation.context.run_id, "job_id": "job_project_build",
                  "attempt_id": invocation.attempt_id, "build_unit_id": invocation.context.binding.node_id,
                  "family": invocation.context.validation_unit["family"]},
        "collector": {"image_id": invocation.image_identity},
        "command": {"argv": list(argv), "working_directory": invocation.working_directories[ordinal],
                    "exit_code": exit_code, "timed_out": False},
        "coverage": {"complete": not gaps, "gaps": list(gaps)},
        "events": events, "streams": {"stdout": stdout, "stderr": stderr},
        "tool_calls": {"records": []},
        "secret_scan": {"scanner": "tool-gitleaks", "findings": findings, "execution": scan},
    }
    record = root / "record.json"
    record.write_bytes(canonical_json(document))
    return BuildCommandResult(argv, exit_code, b"trial stdout", b"", False,
                              capture_record=record, stdout_file=root / "stdout", stderr_file=root / "stderr")


def _executor(build, *, exit_code=0, capture_gaps=(), cleanup=True, produce=True, before_return=None):
    def execute(invocation):
        assert invocation.paths.target_container == "/workspace"
        assert invocation.paths.install_container == "/install"
        assert (invocation.paths.target / "shared/a.h").read_bytes() == build.original["shared/a.h"]
        assert (invocation.paths.target / "z-library/a.c").is_file()
        assert not (invocation.paths.target / "failed-only").exists()
        assert (invocation.paths.install / "lib/libA.a").read_bytes() == build.a_bytes
        assert (invocation.paths.install / "include/a.h").is_file()
        assert b"-L/install" in (invocation.paths.install / "lib/pkgconfig/a.pc").read_bytes()
        assert {item["path"] for item in invocation.interfaces} == {
            "/install/lib/libA.a", "/install/include/a.h", "/install/lib/pkgconfig/a.pc",
        }
        assert all(item["producer_build_unit_id"] == build.context.upstreams[0].binding.node_id
                   and item["workspace_product"] == build.context.upstreams[0].reference
                   for item in invocation.interfaces)
        replay_key = invocation.paths.target.parent.name
        with pytest.raises(LockUnavailable, match="lock"):
            with FileLock(build.workspace.run_dir / f"data/build/workspace/replays/{replay_key}/writer.lock"):
                pass
        if produce:
            output = invocation.paths.install / "bin/B"
            output.parent.mkdir(exist_ok=True)
            output.write_bytes(NATIVE_OUTPUT)
            directory = invocation.paths.target / "a-consumer/build"
            directory.mkdir(exist_ok=True)
            (directory / "B").write_bytes(NATIVE_OUTPUT)
        results = []
        for index in range(len(invocation.commands)):
            argv, _cwd = invocation.prepare_command(index)
            results.append(_capture(invocation, index, argv, exit_code=exit_code, gaps=capture_gaps))
        if before_return:
            before_return(invocation, results)
        return TrialExecution(tuple(results), cleanup)
    return Mock(side_effect=execute)


def _trial(build, **kwargs):
    return replay_recipe(build.workspace, build.context, build.candidate,
                         execute=_executor(build, **kwargs))


def test_full_context_detached_replay_promotes_recipe_only_then_reexecutes_b_without_rebuilding_a(build):
    production_state = (build.workspace.run_dir / build.workspace.state_relative).read_bytes()
    failed_library = (build.workspace.paths.install / "lib/libA.a").read_bytes()
    failed_streams = {ref["path"]: verify_reference(build.workspace.run_dir, ref).read_bytes()
                      for ref in _read(build.workspace.run_dir, build.context.inputs["failure"])["evidence"]}
    executor = _executor(build)
    ref = replay_recipe(build.workspace, build.context, build.candidate, execute=executor)
    executor.assert_called_once()
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == "SUCCEEDED"
    assert trial["cleanup_complete"] is True
    assert trial["verified_interfaces"][0]["path"] == "/install/bin/B"
    promotion = promote_recipe(build.workspace, build.context, ref)
    promoted = load_promoted_recipe(build.workspace, build.context, promotion)
    assert promoted == build.candidate.recipe
    assert load_promoted_revision(build.workspace, build.context, promotion).profile is None
    assert _read(build.workspace.run_dir, promotion)["production_reexecution_required"] is True
    assert (build.workspace.run_dir / build.workspace.state_relative).read_bytes() == production_state
    assert (build.workspace.paths.install / "lib/libA.a").read_bytes() == failed_library
    assert (build.workspace.paths.target / "failed-only").is_file()
    assert all(verify_reference(build.workspace.run_dir, ref).read_bytes() == failed_streams[ref["path"]]
               for ref in _read(build.workspace.run_dir, build.context.inputs["failure"])["evidence"])
    with build.workspace.writer() as writer:
        writer.restore(build.context.generation_identity)
        writer.verify_product(build.context.upstreams[0].reference, build.context.upstreams[0].binding)
        assert not (writer.paths.install / "bin/B").exists()
        writer.begin_attempt(replace(build.context.binding, recipe_identity=canonical_json_sha256(promoted)),
                             "B-production-reexecution", build.context.generation_identity)
        (writer.paths.install / "bin").mkdir()
        (writer.paths.install / "bin/B").write_bytes(b"production B; not trial bytes")
        writer.commit(build.context.products)
        assert (writer.paths.install / "lib/libA.a").read_bytes() == build.a_bytes
    schema = json.loads((Path(__file__).parents[1] / "docs/schemas/build-recipe-replay.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(trial, schema)


def test_duplicate_and_reason_only_no_op_stop_durably_without_another_executor(build):
    noop = replace(build.candidate, recipe={**build.context.accepted_recipe, "reason": "new explanation"})
    executor = _executor(build)
    first = replay_recipe(build.workspace, build.context, noop, execute=executor)
    assert _read(build.workspace.run_dir, first)["reason"] == "normalized_no_op"
    executor.assert_not_called()
    _trial(build)
    duplicate = replay_recipe(build.workspace, build.context,
                              replace(build.candidate, reason="explanation does not change semantics"),
                              execute=executor)
    assert _read(build.workspace.run_dir, duplicate)["reason"] == "normalized_duplicate"
    executor.assert_not_called()


@pytest.mark.parametrize("options,reason", [
    ({"exit_code": 2}, "command_failed"),
    ({"capture_gaps": ("ptrace events dropped",)}, "ptrace events dropped"),
    ({"produce": False}, "required_output_missing"),
    ({"cleanup": False}, "worker_cleanup_unconfirmed"),
])
def test_failed_capture_output_and_unconfirmed_cleanup_cannot_win(build, options, reason):
    ref = _trial(build, **options)
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == ("UNFINISHED" if options.get("cleanup") is False else "FAILED")
    assert reason in trial["reason"]
    with pytest.raises(ReplayRefused, match="unverified_trial"):
        promote_recipe(build.workspace, build.context, ref)
    replay_id = _read(build.workspace.run_dir, trial["intent"])["replay_id"]
    replay = BuildWorkspace(build.workspace.run_dir, replay_id=replay_id)
    owner = json.loads((build.workspace.run_dir / replay.owner_relative).read_bytes())
    assert (owner["terminal_ns"] is None) == (options.get("cleanup") is False)


@pytest.mark.parametrize("field,value", [
    ("releases", {}), ("variant", {**VARIANT, "abi": None}),
    ("generation_identity", "0" * 64), ("failed_attempt_id", "foreign-attempt"),
])
def test_missing_or_foreign_context_is_explicit_refusal_before_execution(build, field, value):
    executor = _executor(build)
    with pytest.raises((ReplayRefused, RuntimeError), match="release|variant|generation|foreign_failure|metadata"):
        replay_recipe(build.workspace, replace(build.context, **{field: value}), build.candidate, execute=executor)
    executor.assert_not_called()


@pytest.mark.parametrize("releases", [
    {"platform": "platform/1"}, {"validation": "validation/1"}, {"unrelated": "unrelated/1"},
    {"platform": "undeclared", "validation": "validation/1"},
    {"job_project_build": "build/1", "validation": "undeclared"},
])
def test_missing_specific_or_placeholder_releases_are_not_reuse_proof(build, releases):
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="missing_release_identity"):
        replay_recipe(build.workspace, replace(build.context, releases=releases), build.candidate, execute=execute)
    execute.assert_not_called()


def test_approved_image_evidence_must_pin_the_full_execution_and_signature_profile(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    profile = BuildProfile("native", "prepared:fixture", "sha256:" + "2" * 64, "1000:1000",
                           build.context.binding.image_identity)
    receipt = _json(build.workspace.run_dir, "artifacts/prepared/wrong-profile.json", {
        "image_id": profile.image_id, "recipe_identity": canonical_json_sha256(candidate.recipe),
        "profile": {**asdict(profile), "user": "2000:2000"}, "operator_approved": True,
    })
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="unverified_image_preparation"):
        replay_recipe(build.workspace, build.context, candidate, execute=execute,
                      approved_image_builder=Mock(return_value=ImageResolution(profile, receipt)))
    execute.assert_not_called()


@pytest.mark.parametrize("build", [{"job_project_build": "build/1", "validation": "validation/1"}], indirect=True)
def test_job_implementation_override_and_validation_release_are_valid_reuse_proof(build):
    assert _read(build.workspace.run_dir, _trial(build))["status"] == "SUCCEEDED"


def test_malformed_release_identity_has_explicit_refusal_before_execution(build):
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="invalid_release_identity"):
        replay_recipe(build.workspace, replace(build.context, releases={"platform": "release with spaces",
                      "validation": "validation/1"}), build.candidate, execute=execute)
    execute.assert_not_called()


@pytest.mark.parametrize("field,value", [
    ("source_identity", "foreign-source"), ("graph_identity", "foreign-graph"),
    ("configuration_identity", "foreign-config"), ("recipe_identity", "foreign-recipe"),
    ("toolchain_identity", "foreign-toolchain"), ("image_identity", "unversioned:latest"),
    ("upstream_products", ("a" * 64,)), ("execution_identity", "foreign-executor"),
    ("output_policy_identity", "foreign-output-policy"),
])
def test_promotion_refuses_stale_or_foreign_source_node_config_recipe_toolchain_and_products(build, field, value):
    ref = _trial(build)
    context = replace(build.context, binding=replace(build.context.binding, **{field: value}))
    with pytest.raises(ReplayRefused):
        promote_recipe(build.workspace, context, ref)


def test_wrong_producer_binding_or_variant_cannot_supply_a_product_edge(build):
    upstream = build.context.upstreams[0]
    bad = replace(upstream, binding=replace(upstream.binding, node_id=build.context.binding.node_id))
    executor = _executor(build)
    with pytest.raises(ReplayRefused, match="upstream"):
        replay_recipe(build.workspace, replace(build.context, upstreams=(bad,)), build.candidate, execute=executor)
    bad_product = replace(build.context.products[0], variant={**VARIANT, "abi": "foreign-abi"})
    with pytest.raises(ReplayRefused, match="product"):
        replay_recipe(build.workspace, build.context, replace(build.candidate, products=(bad_product,)), execute=executor)
    executor.assert_not_called()


@pytest.mark.parametrize("mutation", [
    {"build_commands": [["cmake", "--help"]]},
    {"configure_commands": [["cmake", "-E", "copy", "../shared/a.h", "b.c"]]},
    {"build_commands": [["sh", "-c", "echo evil"]]},
    {"source_dir": "."},
    {"dependency_files": ["unaccepted-manifest"]},
    {"environment": {"CMAKE_PROJECT_INCLUDE": "/tmp/source-patch.cmake"}},
])
def test_candidate_reuses_accepted_validation_and_cannot_patch_source_or_widen_authority(build, mutation):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, **mutation})
    executor = _executor(build)
    with pytest.raises(ReplayRefused):
        replay_recipe(build.workspace, build.context, candidate, execute=executor)
    executor.assert_not_called()


def test_explicit_network_offline_uses_none_and_refuses_fetch_requirements(build):
    seen = []
    executor = _executor(build, before_return=lambda invocation, _: seen.append(invocation.network))
    ref = replay_recipe(build.workspace, build.context, build.candidate, execute=executor, network_offline=True)
    assert _read(build.workspace.run_dir, ref)["status"] == "SUCCEEDED"
    assert seen == ["none"]
    recipe = {**build.context.accepted_recipe, "network_required": True}
    binding = replace(build.context.binding, recipe_identity=canonical_json_sha256(recipe))
    graph = _read(build.workspace.run_dir, build.context.inputs["graph"])
    next(node for node in graph["nodes"] if node["build_unit_id"] == binding.node_id)["recipe_revision"] = binding.recipe_identity
    failure = _read(build.workspace.run_dir, build.context.inputs["failure"])
    failure["binding"] = binding.view()
    inputs = {**build.context.inputs,
              "failure": _json(build.workspace.run_dir, "artifacts/inputs/network-failure.json", failure),
              "graph": _json(build.workspace.run_dir, "artifacts/inputs/network-graph.json", graph)}
    context = replace(build.context, accepted_recipe=recipe, binding=binding, inputs=inputs)
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "network_required": True},
                        evidence=(inputs["graph"],))
    blocked = replay_recipe(build.workspace, context, candidate, execute=executor, network_offline=True)
    assert _read(build.workspace.run_dir, blocked)["reason"] == "network_offline_requires_prepared_dependencies"
    executor.assert_called_once()


def test_normalized_no_op_includes_reordered_exports_and_empty_image_repair_record(build):
    products = (*build.context.products, ProductSpec("target/shared/a.h", "headers", "include:B", "include:B", VARIANT))
    context = replace(build.context, products=products)
    candidate = replace(build.candidate, recipe={**context.accepted_recipe,
        "image_repairs": {"environment": {}, "package_manager": None, "dependency_restores": []}},
        products=tuple(reversed(products)))
    executor = _executor(build)
    ref = replay_recipe(build.workspace, context, candidate, execute=executor)
    assert _read(build.workspace.run_dir, ref)["reason"] == "normalized_no_op"
    executor.assert_not_called()


def test_missing_approved_image_builder_is_precise_block_without_executor_or_provisioning(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    executor = _executor(build)
    ref = replay_recipe(build.workspace, build.context, candidate, execute=executor)
    assert _read(build.workspace.run_dir, ref)["reason"] == "derived_image_preparation_unavailable"
    executor.assert_not_called()


def test_distinct_failed_candidate_can_be_followed_by_one_genuinely_different_successful_trial(build):
    failed = _trial(build, exit_code=2)
    assert _read(build.workspace.run_dir, failed)["status"] == "FAILED"
    recipe = deepcopy(build.candidate.recipe)
    recipe["build_commands"][0][-1] = "1"
    revised = replace(build.candidate, recipe=recipe)
    executor = _executor(build)
    second = replay_recipe(build.workspace, build.context, revised, execute=executor)
    executor.assert_called_once()
    assert _read(build.workspace.run_dir, second)["status"] == "SUCCEEDED"
    assert _read(build.workspace.run_dir, failed)["commands"][0]["exit_code"] == 2
    promotion = promote_recipe(build.workspace, build.context, second)
    assert load_promoted_recipe(build.workspace, build.context, promotion) == recipe


def test_evidenced_export_path_and_build_directory_revision_uses_same_source_cwd(build):
    recipe = deepcopy(build.candidate.recipe)
    recipe.update(build_dir="a-consumer/rebuilt", expected_outputs=["a-consumer/rebuilt"],
                  configure_commands=[["clang", TARGET, "-c", "b.c", "-o", "rebuilt/preflight.o"]])
    recipe["build_commands"] = [["clang", TARGET, "b.c", "-o", "rebuilt/B"]]
    product = replace(build.context.products[0], path="install/revised/B")
    candidate = replace(build.candidate, recipe=recipe, products=(product,))
    seen = []

    def execute(invocation):
        assert invocation.candidate.recipe["source_dir"] == "a-consumer"
        assert invocation.commands == (("clang", TARGET, "-c", "b.c", "-o", "rebuilt/preflight.o"),
                                       ("clang", TARGET, "b.c", "-o", "rebuilt/B"))
        assert (invocation.paths.target / "shared/a.h").is_file()
        assert (invocation.paths.install / "lib/libA.a").read_bytes() == build.a_bytes
        out = invocation.paths.install / "revised/B"
        out.parent.mkdir()
        out.write_bytes(NATIVE_OUTPUT)
        generated = invocation.paths.target / recipe["build_dir"]
        generated.mkdir(exist_ok=True)
        (generated / "B").write_bytes(NATIVE_OUTPUT)
        seen.append(invocation)
        return TrialExecution(tuple(_capture(invocation, index, invocation.prepare_command(index)[0])
                                    for index in range(len(invocation.commands))), True)

    ref = replay_recipe(build.workspace, build.context, candidate, execute=execute)
    assert len(seen) == 1
    assert _read(build.workspace.run_dir, ref)["verified_interfaces"][0]["path"] == "/install/revised/B"
    promotion = promote_recipe(build.workspace, build.context, ref)
    assert load_promoted_recipe(build.workspace, build.context, promotion) == recipe
    revision = load_promoted_revision(build.workspace, build.context, promotion)
    assert revision.products == (product,)
    assert revision.image_identity == build.context.binding.image_identity


def test_phase_cwd_correction_replays_and_promotes_without_changing_source_root_or_a(build):
    recipe = deepcopy(build.candidate.recipe)
    recipe.update(
        execution_cwd={"configure": "a-consumer", "build": "a-consumer/build"},
        configure_commands=[["clang", TARGET, "-c", "b.c", "-o", "build/preflight.o"]],
        build_commands=[["clang", TARGET, "../b.c", "-o", "B", "-g"]],
    )
    candidate = replace(build.candidate, recipe=recipe)
    observed = []

    def execute(invocation):
        assert invocation.commands == (
            ("clang", TARGET, "-c", "b.c", "-o", "build/preflight.o"),
            ("clang", TARGET, "../b.c", "-o", "B", "-g"))
        assert invocation.working_directories == ("a-consumer", "a-consumer/build")
        results = []
        for ordinal in range(len(invocation.commands)):
            argv, cwd = invocation.prepare_command(ordinal)
            assert (invocation.paths.target / cwd).is_dir()
            observed.append(cwd)
            if ordinal == 1:
                (invocation.paths.target / cwd / "B").write_bytes(NATIVE_OUTPUT)
                output = invocation.paths.install / "bin/B"
                output.parent.mkdir()
                output.write_bytes(NATIVE_OUTPUT)
            results.append(_capture(invocation, ordinal, argv))
        return TrialExecution(tuple(results), True)

    ref = replay_recipe(build.workspace, build.context, candidate, execute=execute)
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == "SUCCEEDED"
    assert [item["working_directory"] for item in trial["commands"]] == observed
    revision = load_promoted_revision(build.workspace, build.context,
                                      promote_recipe(build.workspace, build.context, ref))
    assert revision.recipe["execution_cwd"] == recipe["execution_cwd"]
    assert revision.recipe["source_dir"] == build.context.accepted_recipe["source_dir"] == "a-consumer"
    assert revision.recipe_identity != build.context.binding.recipe_identity
    assert (build.workspace.paths.install / "lib/libA.a").read_bytes() == b"corrupt failed B overwrite"


@pytest.mark.parametrize("explicit_cwd", [False, True])
@pytest.mark.parametrize("argv", [
    ["cmake", "--build", "a-consumer/build", "--target", "a-consumer/custom-target"],
    ["make", "-f", "a-consumer/Makefile", "a-consumer/custom-target"],
])
def test_command_plan_rebases_recognized_path_operands_not_source_prefixed_targets(build, explicit_cwd, argv):
    recipe = {**build.candidate.recipe, "build_commands": [argv]}
    if explicit_cwd:
        recipe["execution_cwd"] = {"build": "a-consumer/build"}
    original_recipe = deepcopy(recipe)
    original_argv = tuple(argv)
    assert validate_build_recipe(recipe, build.context.validation_unit) == []
    invocation = ReplayInvocation(
        build.context, replace(build.candidate, recipe=recipe), build.workspace.paths,
        build.workspace.run_dir / "artifacts/command-plan", "plan-only", "none",
        build.context.binding.image_identity,
    )
    expected_path = "." if explicit_cwd else "build"
    if argv[0] == "make":
        expected_path = "../Makefile" if explicit_cwd else "Makefile"
    assert invocation.commands == ((original_argv[0], original_argv[1], expected_path, *original_argv[3:]),)
    assert invocation.working_directories == (
        "a-consumer/build" if explicit_cwd else "a-consumer",
    )
    assert recipe == original_recipe


def test_shared_command_guard_refuses_wrong_source_before_replay_configure_launch(build):
    recipe = {**build.candidate.recipe,
              "execution_cwd": {"configure": "a-consumer/build", "build": "a-consumer/build"},
              "configure_commands": [["cmake", "-S", ".", "-B", "."]],
              "build_commands": [["cmake", "--build", "."]]}
    execute = Mock(side_effect=AssertionError("wrong-source configure must not launch"))
    with pytest.raises(ValueError, match="(?i)source|descriptor|origin"):
        replay_recipe(build.workspace, build.context, replace(build.candidate, recipe=recipe), execute=execute)
    execute.assert_not_called()


def test_targeted_compiler_allows_parent_source_from_declared_build_cwd(build):
    recipe = {**build.candidate.recipe,
              "execution_cwd": {"configure": "a-consumer/build", "build": "a-consumer/build"},
              "configure_commands": [["clang", TARGET, "-c", "../b.c", "-o", "preflight.o"]],
              "build_commands": [["clang", TARGET, "../b.c", "-o", "B"]]}
    ref = replay_recipe(build.workspace, build.context, replace(build.candidate, recipe=recipe),
                        execute=_executor(build))
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == "SUCCEEDED"
    assert [command["working_directory"] for command in trial["commands"]] == ["a-consumer/build"] * 2
    revision = load_promoted_revision(build.workspace, build.context,
                                      promote_recipe(build.workspace, build.context, ref))
    assert revision.recipe["source_dir"] == "a-consumer"
    assert revision.recipe["configure_commands"] == [["clang", TARGET, "-c", "../b.c", "-o", "preflight.o"]]


def test_targeted_compiler_cannot_bypass_exact_command_capture_matching(build):
    recipe = {**build.candidate.recipe,
              "build_commands": [["clang", TARGET, "b.c", "-o", "build/B", "-g"]]}

    def wrong_target(invocation, results):
        argv = (*results[0].argv[:-1], "-O2")
        results[0] = replace(results[0], argv=argv)
        document = json.loads(results[0].capture_record.read_bytes())
        document["command"]["argv"] = list(argv)
        results[0].capture_record.write_bytes(canonical_json(document))

    with pytest.raises(ReplayRefused, match="command_mismatch"):
        replay_recipe(build.workspace, build.context, replace(build.candidate, recipe=recipe),
                      execute=_executor(build, before_return=wrong_target))


def test_explicit_default_phase_cwds_are_a_normalized_no_op(build):
    candidate = replace(build.candidate, recipe={**build.context.accepted_recipe,
        "execution_cwd": {"configure": "a-consumer", "build": "a-consumer"}})
    executor = _executor(build)
    ref = replay_recipe(build.workspace, build.context, candidate, execute=executor)
    assert _read(build.workspace.run_dir, ref)["reason"] == "normalized_no_op"
    executor.assert_not_called()


def test_cwd_is_revalidated_between_configure_and_build_instead_of_trusting_initial_directory(build):
    recipe = {**build.candidate.recipe, "execution_cwd": {"build": "a-consumer/build"},
              "configure_commands": [["clang", TARGET, "-c", "b.c", "-o", "build/preflight.o"]],
              "build_commands": [["clang", TARGET, "../b.c", "-o", "B"]]}
    candidate = replace(build.candidate, recipe=recipe)
    executed = []

    def execute(invocation):
        argv, cwd = invocation.prepare_command(0)
        executed.append((argv, cwd))
        directory = invocation.paths.target / "a-consumer/build"
        directory.rmdir()
        directory.symlink_to("../", target_is_directory=True)
        invocation.prepare_command(1)
        raise AssertionError("build must not launch through configure-created symlink")

    with pytest.raises(ReplayRefused, match="unsafe_execution_cwd"):
        replay_recipe(build.workspace, build.context, candidate, execute=execute)
    assert len(executed) == 1


@pytest.mark.parametrize("cwd", ["/tmp/host", "../outside", "a-consumer/../shared"])
def test_execution_cwd_never_relaxes_accepted_recipe_path_authority(build, cwd):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "execution_cwd": {"build": cwd}})
    executor = _executor(build)
    with pytest.raises(ReplayRefused, match="invalid_candidate_recipe"):
        replay_recipe(build.workspace, build.context, candidate, execute=executor)
    executor.assert_not_called()


def test_non_build_source_cwd_requires_accepted_descriptor_evidence(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe,
                                                "execution_cwd": {"build": "a-consumer/undocumented"}})
    executor = _executor(build)
    with pytest.raises(ReplayRefused, match="unproven_execution_cwd"):
        replay_recipe(build.workspace, build.context, candidate, execute=executor)
    executor.assert_not_called()


def test_missing_generated_child_cwd_is_not_created_or_treated_as_verified_context(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe,
        "execution_cwd": {"build": "a-consumer/build/not-generated"},
        "build_commands": [["clang", TARGET, "../../b.c", "-o", "B"]]})
    executor = _executor(build)
    with pytest.raises(ReplayRefused, match="unsafe_execution_cwd"):
        replay_recipe(build.workspace, build.context, candidate, execute=executor)
    executor.assert_not_called()


def test_captured_wrong_phase_cwd_cannot_be_a_winner(build):
    recipe = {**build.candidate.recipe, "execution_cwd": {"build": "a-consumer/build"},
              "build_commands": [["clang", TARGET, "../b.c", "-o", "B"]]}
    candidate = replace(build.candidate, recipe=recipe)

    def wrong_cwd(invocation, results):
        record = results[0].capture_record
        document = json.loads(record.read_bytes())
        document["command"]["working_directory"] = recipe["source_dir"]
        record.write_bytes(canonical_json(document))

    with pytest.raises(ReplayRefused, match="capture_command_mismatch"):
        replay_recipe(build.workspace, build.context, candidate,
                      execute=_executor(build, before_return=wrong_cwd))


def test_network_offline_approved_prepared_image_requires_immutable_matching_builder_evidence(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    image = "sha256:" + "2" * 64
    profile = BuildProfile("native", "prepared:fixture", image, "1000:1000", build.context.binding.image_identity)
    receipt = _json(build.workspace.run_dir, "artifacts/prepared/image.json", {
        "image_id": image, "recipe_identity": canonical_json_sha256(candidate.recipe),
        "profile": asdict(profile), "operator_approved": True, "network": "none", "prepared": True,
        "compiler_metadata": _json(build.workspace.run_dir, "artifacts/prepared/compiler.json",
                                   _compiler_metadata(image, candidate.recipe)),
    })
    builder = Mock(return_value=ImageResolution(profile, receipt))
    execute = _executor(build)
    ref = replay_recipe(build.workspace, build.context, candidate, execute=execute,
                        network_offline=True, approved_image_builder=builder)
    builder.assert_called_once_with(build.context, candidate, True)
    assert _read(build.workspace.run_dir, ref)["binding"]["image_identity"] == image
    assert execute.call_args.args[0].profile == profile
    assert execute.call_args.args[0].network == "none"
    promotion = promote_recipe(build.workspace, build.context, ref)
    promoted = load_promoted_revision(build.workspace, build.context, promotion)
    assert promoted.recipe == candidate.recipe
    assert promoted.profile == profile
    assert _read(build.workspace.run_dir, promotion)["image_profile"] == asdict(profile)
    trial = _read(build.workspace.run_dir, ref)
    intent = _read(build.workspace.run_dir, trial["intent"])
    intent["image_profile"]["tag"] = "forged:profile"
    trial["intent"] = _json(build.workspace.run_dir,
                           f"artifacts/build/recipe-replay/intents/{canonical_json_sha256(intent)}.json", intent)
    forged = _json(build.workspace.run_dir,
                   f"artifacts/build/recipe-replay/trials/{canonical_json_sha256(trial)}.json", trial)
    with pytest.raises(ReplayRefused, match="image_mismatch"):
        promote_recipe(build.workspace, build.context, forged)


@pytest.mark.parametrize("mutation", ["missing", "stale-bytes", "image", "recipe", "compiler", "target"])
def test_prepared_actual_image_compiler_admission_precedes_reconstruction_and_execution(build, monkeypatch, mutation):
    from appsec_review.jobs.build_workspace import WorkspaceWriter
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    image = "sha256:" + "2" * 64
    profile = BuildProfile("native", "prepared:fixture", image, "1000:1000")
    metadata = _compiler_metadata(image, candidate.recipe)
    if mutation == "image":
        metadata["image_digest"] = build.context.binding.image_identity
    elif mutation == "recipe":
        metadata["image_recipe_digest"] = canonical_json_sha256(build.context.accepted_recipe)
    elif mutation == "compiler":
        metadata["compiler_sha256"] = None
    elif mutation == "target":
        metadata["executable"] = "gcc"
    compiler = _json(build.workspace.run_dir, "artifacts/prepared/compiler.json", metadata)
    if mutation == "stale-bytes":
        (build.workspace.run_dir / compiler["path"]).write_bytes(canonical_json({**metadata, "compiler_sha256": "f" * 64}))
    approval = _json(build.workspace.run_dir, "artifacts/prepared/approval.json", {
        "image_id": image, "recipe_identity": canonical_json_sha256(candidate.recipe),
        "profile": asdict(profile), "operator_approved": True, "network": "none", "prepared": True,
        **({} if mutation == "missing" else {"compiler_metadata": compiler}),
    })
    reconstruct = Mock(side_effect=AssertionError("unadmitted image must not reconstruct"))
    execute = Mock(side_effect=AssertionError("unadmitted image must not execute"))
    monkeypatch.setattr(WorkspaceWriter, "create_replay", reconstruct)
    with pytest.raises((ReplayRefused, ValueError)):
        replay_recipe(build.workspace, build.context, candidate, execute=execute,
                      approved_image_builder=Mock(return_value=ImageResolution(profile, approval)))
    reconstruct.assert_not_called()
    execute.assert_not_called()


def test_native_cmake_without_compiler_closure_never_reconstructs_or_executes(build, monkeypatch):
    from appsec_review.jobs.build_workspace import WorkspaceWriter
    candidate = replace(build.candidate, recipe={**build.candidate.recipe,
        "build_commands": [["cmake", "--build", "a-consumer/build"]]})
    reconstruct = Mock(side_effect=AssertionError("unknown compiler closure must not reconstruct"))
    execute = Mock(side_effect=AssertionError("unknown compiler closure must not execute"))
    monkeypatch.setattr(WorkspaceWriter, "create_replay", reconstruct)
    with pytest.raises(ReplayRefused, match="candidate_target_unenforced"):
        replay_recipe(build.workspace, build.context, candidate, execute=execute)
    reconstruct.assert_not_called()
    execute.assert_not_called()


@pytest.mark.parametrize("mutation", ["changed-source", "source-symlink", "output-symlink", "output-escape", "cwd-escape"])
def test_direct_compiler_changed_cwd_rechecks_real_source_and_containment_each_launch(build, mutation):
    from appsec_review.jobs.build_recipe_commands import prepare_recipe_command
    workspace = build.workspace.paths.target
    recipe = {**build.candidate.recipe, "execution_cwd": {"build": "a-consumer/build"},
              "build_commands": [["clang", TARGET, "../b.c", "-o", "B"]]}
    argv = recipe["build_commands"][0]
    assert prepare_recipe_command(workspace, build.context.validation_unit, recipe, "build", argv) == (
        tuple(argv), "a-consumer/build")
    source = workspace / "a-consumer/b.c"
    if mutation == "changed-source":
        source.write_bytes(b"int main(void) { return 7; }\n")
    elif mutation == "source-symlink":
        source.unlink()
        source.symlink_to("../z-library/a.c")
    elif mutation == "output-symlink":
        (workspace / "a-consumer/build/B").symlink_to("../../z-library/a.c")
    elif mutation == "output-escape":
        argv[-1] = "../../../outside"
    elif mutation == "cwd-escape":
        recipe["execution_cwd"]["build"] = "../outside"
    with pytest.raises(ValueError):
        prepare_recipe_command(workspace, build.context.validation_unit, recipe, "build", argv)


def test_genuine_accepted_graph1_remains_readable_but_refuses_replay_before_reconstruction(build, monkeypatch):
    from appsec_review.jobs.build_workspace import WorkspaceWriter
    from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
    run = build.workspace.run_dir
    units = load_accepted_plan(run)["build_topology"]["build_actions"]
    _, plan = _publish_source_plan(run, units, build.context.releases, legacy=True)
    graph = plan["build_topology"]["executable_graph"]
    binding = replace(build.context.binding, graph_identity=graph["topology_id"])
    failure = _read(run, build.context.inputs["failure"])
    context = replace(build.context, binding=binding, inputs={
        **build.context.inputs, "graph": _json(run, "artifacts/legacy/graph.json", graph),
        "failure": _json(run, "artifacts/legacy/failure.json", {**failure, "binding": binding.view()})})
    reconstruct = Mock(side_effect=AssertionError("legacy graph cannot reconstruct a graph/2 trial"))
    execute = Mock(side_effect=AssertionError("legacy graph cannot replay"))
    monkeypatch.setattr(WorkspaceWriter, "create_replay", reconstruct)
    with pytest.raises(ReplayRefused, match="graph/1"):
        replay_recipe(build.workspace, context, build.candidate, execute=execute)
    assert load_accepted_plan(run) == plan
    reconstruct.assert_not_called()
    execute.assert_not_called()


def test_network_offline_builder_cannot_hide_a_fetch_or_unapproved_recipe(build):
    candidate = replace(build.candidate, recipe={**build.candidate.recipe, "system_packages": ["libssl-dev"]})
    image = "sha256:" + "2" * 64
    profile = BuildProfile("native", "prepared:fixture", image, "1000:1000")
    receipt = _json(build.workspace.run_dir, "artifacts/prepared/unapproved.json", {
        "image_id": image, "recipe_identity": canonical_json_sha256(candidate.recipe),
        "profile": asdict(profile), "operator_approved": True, "network": "bridge", "prepared": False,
    })
    builder = Mock(return_value=ImageResolution(profile, receipt))
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="unverified_image_preparation"):
        replay_recipe(build.workspace, build.context, candidate, execute=execute,
                      network_offline=True, approved_image_builder=builder)
    execute.assert_not_called()


def test_accepted_descriptor_content_cannot_be_forged_to_widen_command_validation(build):
    unit = deepcopy(build.context.validation_unit)
    unit["descriptor_package"]["documents"][0]["content"] = "unaccepted build authority"
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="descriptor_identity_mismatch"):
        replay_recipe(build.workspace, replace(build.context, validation_unit=unit), build.candidate, execute=execute)
    execute.assert_not_called()


def test_unrelated_durable_artifact_is_not_accepted_build_evidence(build):
    evidence = _json(build.workspace.run_dir, "artifacts/unrelated/model-claim.json", {"claim": "trust me"})
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="foreign_candidate_evidence"):
        replay_recipe(build.workspace, build.context, replace(build.candidate, evidence=(evidence,)), execute=execute)
    execute.assert_not_called()


def test_wrong_run_or_missing_marker_cannot_be_substituted_for_accepted_authority(build):
    execute = _executor(build)
    with pytest.raises(ReplayRefused, match="foreign_run"):
        replay_recipe(build.workspace, replace(build.context, run_id="foreign-run"), build.candidate, execute=execute)
    unit = {**build.context.validation_unit, "markers": []}
    with pytest.raises(ReplayRefused, match="descriptor_identity_mismatch"):
        replay_recipe(build.workspace, replace(build.context, validation_unit=unit), build.candidate, execute=execute)
    execute.assert_not_called()


def test_missing_expected_product_records_a_finished_failure_and_releases_trial_for_retention(build):
    def remove_product(invocation, results):
        (invocation.paths.install / "bin/B").unlink()
    ref = _trial(build, before_return=remove_product)
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == "FAILED"
    assert "product_verification_failed" in trial["reason"]
    replay_id = _read(build.workspace.run_dir, trial["intent"])["replay_id"]
    replay = BuildWorkspace(build.workspace.run_dir, replay_id=replay_id)
    assert json.loads((build.workspace.run_dir / replay.owner_relative).read_bytes())["terminal_ns"] is not None
    assert json.loads((build.workspace.run_dir / replay.state_relative).read_bytes())["attempt"] is None


def test_old_source_bytes_as_exports_cannot_make_an_exit_zero_command_a_winner(build):
    products = (replace(build.context.products[0], path="target/a-consumer/b.c"),)
    candidate = replace(build.candidate, products=products)
    ref = replay_recipe(build.workspace, build.context, candidate, execute=_executor(build))
    trial = _read(build.workspace.run_dir, ref)
    assert trial["status"] == "FAILED"
    assert "no_new_or_changed_build_product" in trial["reason"]


def test_upstream_cas_tampering_blocks_promotion_even_with_untouched_trial_receipt(build):
    ref = _trial(build)
    product = _read(build.workspace.run_dir, build.context.upstreams[0].reference)
    digest = product["entries"]["install/lib/libA.a"]["sha256"]
    (build.workspace.run_dir / f"data/shared/objects/{digest}").write_bytes(b"tampered A")
    with pytest.raises(RuntimeError, match="missing|changed"):
        promote_recipe(build.workspace, build.context, ref)


def test_new_production_generation_invalidates_an_old_successful_trial(build):
    ref = _trial(build)
    with build.workspace.writer() as writer:
        writer.restore(build.context.generation_identity)
        writer.begin_attempt(replace(build.context.binding, node_id="another-node", upstream_products=()),
                             "another-node-success", build.context.generation_identity)
        (writer.paths.install / "other").write_bytes(b"new accepted generation")
        writer.commit([ProductSpec("install/other", "headers", "other", "other", VARIANT)])
    with pytest.raises(ReplayRefused, match="stale_generation"):
        promote_recipe(build.workspace, build.context, ref)


def test_active_or_newer_failed_production_attempt_invalidates_selected_old_failure(build):
    ref = _trial(build)
    with build.workspace.writer() as writer:
        writer.restore(build.context.generation_identity)
        writer.begin_attempt(build.context.binding, "B-new-attempt", build.context.generation_identity)
    with pytest.raises(ReplayRefused, match="active_production_attempt"):
        promote_recipe(build.workspace, build.context, ref)
    with build.workspace.writer() as writer:
        writer.fail_attempt("new failure")
    with pytest.raises(ReplayRefused, match="stale_failure"):
        promote_recipe(build.workspace, build.context, ref)


def test_tampered_capture_or_original_failure_evidence_cannot_be_promoted(build):
    ref = _trial(build)
    trial = _read(build.workspace.run_dir, ref)
    path = verify_reference(build.workspace.run_dir, trial["commands"][0]["stdout"])
    path.write_bytes(b"tampered stream")
    with pytest.raises(ValueError, match="integrity|identity"):
        promote_recipe(build.workspace, build.context, ref)


def test_immutable_trial_reference_cannot_be_replaced_with_edited_success_content(build):
    ref = _trial(build)
    value = _read(build.workspace.run_dir, ref)
    value["binding"]["image_identity"] = "sha256:" + "f" * 64
    path = verify_reference(build.workspace.run_dir, ref)
    path.write_bytes(canonical_json(value))
    with pytest.raises(ValueError, match="integrity|identity"):
        promote_recipe(build.workspace, build.context, ref)


def test_exception_leaves_unfinished_trial_protected_not_success_shaped(build):
    def crash(invocation):
        (invocation.paths.target / "partial").write_bytes(b"partial")
        raise RuntimeError("Docker closure unproven")
    with pytest.raises(RuntimeError, match="closure unproven"):
        replay_recipe(build.workspace, build.context, build.candidate, execute=crash)
    owner = json.loads((build.workspace.run_dir / build.workspace.owner_relative).read_bytes())
    replay = BuildWorkspace(build.workspace.run_dir, replay_id=next(iter(owner["replays"])))
    state = json.loads((build.workspace.run_dir / replay.state_relative).read_bytes())
    assert state["condition"] == "running" and state["attempt"]
    assert json.loads((build.workspace.run_dir / replay.owner_relative).read_bytes())["terminal_ns"] is None


def test_sweep_removes_only_finished_disposable_replay_and_preserves_receipts_and_promotion(build):
    ref = _trial(build)
    promotion = promote_recipe(build.workspace, build.context, ref)
    trial = _read(build.workspace.run_dir, ref)
    replay_id = _read(build.workspace.run_dir, trial["intent"])["replay_id"]
    replay = BuildWorkspace(build.workspace.run_dir, replay_id=replay_id)
    active = sweep_workspaces(build.workspace.run_dir.parent, BuildWorkspacePolicy(1))
    assert active.retained[str(build.workspace.root)] == "active"
    assert replay.root.exists()
    with build.workspace.writer() as writer:
        writer.restore(build.context.generation_identity)
    build.workspace.mark_terminal(workers_stopped=True)
    other_source = build.source.parent / "other-source"
    other_source.mkdir()
    (other_source / "file").write_bytes(b"other")
    other = build.workspace.run_dir.parent / "newer"
    other.mkdir()
    newer = BuildWorkspace(other)
    newer.materialize(other_source, "other-source")
    newer.mark_terminal(workers_stopped=True)
    replay.set_hold("operator-preserve", held=True)
    held = sweep_workspaces(build.workspace.run_dir.parent, BuildWorkspacePolicy(1))
    assert held.retained[str(build.workspace.root)].startswith("active_or_held_replay")
    assert replay.root.exists()
    replay.set_hold("operator-preserve", held=False)
    report = sweep_workspaces(build.workspace.run_dir.parent, BuildWorkspacePolicy(1))
    assert not report.failures
    assert not replay.root.exists()
    assert load_promoted_recipe(build.workspace, build.context, promotion) == build.candidate.recipe
    assert _read(build.workspace.run_dir, ref)["status"] == "SUCCEEDED"
