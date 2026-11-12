from __future__ import annotations

import json
from copy import deepcopy
import os
import shlex
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from appsec_review.acceptance.project_build import project_build_content_problems
from appsec_review.config import load_config
from appsec_review.container_runtime import ProjectImageResolver
from appsec_review.container_runtime import compiler_profiles
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.job_language_build import build_job as language_job
from appsec_review.jobs.job_project_build import build_job, load_accepted_builds
from appsec_review.jobs.job_target_analysis_plan.datasets import DATASETS as PLAN_DATASETS
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PLAN_SCHEMA, PROPOSAL_SCHEMA, deterministic_plan, merge_proposal, summarize_catalog,
)
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime import GraphRunner, Job, Unit
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import reference
from tests.capture_fakes import minimal_elf, simulated_executor
from tests.telemetry_support import assert_job_lifecycle, job_events
from tests.test_compiler_profiles import CPP, _executables
from tests.test_native_target_enforcement import _elf_header


ROOT = Path(__file__).resolve().parents[3]
CASE = "projects/native/case-094"


def _config(tmp_path, scenario):
    text = (ROOT / "appsec-review.toml").read_text()
    text = text.replace("[jobs.job_project_build.settings.model]\nenabled = true",
                        "[jobs.job_project_build.settings.model]\nenabled = false")
    path = tmp_path / "appsec-review.toml"
    path.write_text(text)
    target = tmp_path / "target"
    (target / CASE).mkdir(parents=True)
    (target / CASE / "main.cpp").write_text("int main() { return 0; }\n")
    marker = "Makefile" if scenario in {"direct", "missing", "unknown", "invalid"} else "CMakeLists.txt"
    (target / CASE / marker).write_text(
        "all:\n\tclang++ -c main.cpp -o build/main.o\n" if marker == "Makefile" else
        "cmake_minimum_required(VERSION 3.20)\nproject(case094 LANGUAGES CXX)\n"
        "add_executable(case094 main.cpp)\n")
    if scenario == "multiple":
        for relative, content in {
            "unsupported/legacy.vcproj": '<VisualStudioProject ProjectType="Visual C++"/>\n',
            "unresolved/CMakeLists.txt": "add_library(C STATIC c.c)\n",
            "unresolved/c.c": "int c(void) { return 0; }\n",
        }.items():
            source_path = target / relative
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(content)
    return load_config(path), target


def _recipe_proposal(actions, scenario):
    recipes = []
    for action in actions:
        root = action["root"]
        configure = [["cmake", "-S", root, "-B", root + "/build"]]
        build = [["cmake", "--build", root + "/build"]]
        environment = {}
        if scenario in {"direct", "missing", "unknown", "invalid"}:
            configure = []
            build = [["clang++", "-c", root + "/main.cpp", "-o", root + "/build/main.o"],
                     ["clang++", root + "/build/main.o", "-o", root + "/build/case094"]]
        if scenario == "unknown":
            build = [["clang++", "--version"]]
        if scenario == "invalid":
            build = [["unapproved-compiler", "-c", root + "/main.cpp"]]
        if scenario == "dynamic":
            configure[0].append("-DVALUE=$VALUE")
        if scenario == "path":
            environment = {"PATH": "/workspace/bin"}
        if scenario == "cc":
            environment = {"CC": "/workspace/compiler"}
        recipes.append({
            "schema": "appsec-review/build-recipe/1", "build_unit_id": action["build_unit_id"],
            "image_profile": "native", "source_dir": root, "build_dir": root + "/build",
            "system_packages": [], "environment": environment,
            "dependency_files": [item["path"] for item in action["markers"]],
            "configure_commands": configure, "build_commands": build,
            "expected_outputs": [root + "/build/case094"], "network_required": scenario == "network",
            "reason": "Bounded synthetic upstream recipe input",
        })
        if scenario == "derived":
            recipes[-1]["image_repairs"] = {
                "environment": {}, "package_manager": None, "dependency_restores": []}
    return {"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [],
            "abstentions": [], "component_proposals": [], "build_recipes": recipes}


def _executor(profile, calls, scenario):
    def behavior(argv, workspace, working_directory, environment, container):
        calls.append(tuple(argv))
        container.exec("/usr/bin/" + Path(argv[0]).name, argv)
        if argv[0] == "cmake" and "--build" not in argv:
            container.exec("/usr/bin/clang++", ["clang++", "--version"])
            reply = workspace / CASE / "build/.cmake/api/v1/reply"
            reply.mkdir(parents=True, exist_ok=True)
            (reply / "index-fixture.json").write_text(json.dumps({
                "objects": [{"kind": "codemodel", "jsonFile": "codemodel.json"}]}))
            (reply / "codemodel.json").write_text(json.dumps({
                "paths": {"source": f"/workspace/{CASE}", "build": f"/workspace/{CASE}/build"},
                "configurations": [{"directories": [{"source": ".", "build": "."}],
                                    "projects": [{"name": "case094", "directoryIndexes": [0]}]}],
            }))
            return 0, b"", b""
        build = workspace / CASE / "build"
        build.mkdir(parents=True, exist_ok=True)
        if scenario != "no-binary":
            binary = bytearray(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))
            if scenario == "artifact-target":
                struct.pack_into("<H", binary, 18, 183)
            (build / "case094").write_bytes(binary)
        (build / "main.o").write_bytes(_elf_header("x86_64"))
        flags = ["-m64"] if scenario != "cross" else ["-m32"]
        compile_argv = ["/usr/bin/clang++", *flags, "-o", f"/workspace/{CASE}/build/main.o",
                        "-c", f"/workspace/{CASE}/main.cpp"]
        invocation = [compile_argv[0], "-MD", "-MT", "main.o", "-MF", "main.o.d", *compile_argv[1:]]
        wrapped = scenario in {"wrapped", "wrappers-only", "unmatched-wrapper", "unknown-python", "unknown-shell"}
        link = ["/usr/bin/clang++", f"/workspace/{CASE}/build/main.o", "-o", f"/workspace/{CASE}/build/case094"]
        if wrapped:
            for command, linking in ((invocation, False), (link, True)):
                forwarded = [value if value != "-m64" or scenario != "unmatched-wrapper" else "-m32"
                             for value in command[1:]]
                shell = shlex.join(["/capture/wrappers/clang++", *forwarded])
                container.exec("/bin/sh", ["/bin/sh", "-c", f": && {shell} && :" if linking else shell])
                container.exec("/usr/bin/python3",
                               ["/usr/bin/python3", "/capture/tool-wrapper.py", "clang++", *forwarded])
                container.tool_call("clang++", forwarded, executable="/usr/bin/clang++")
            if scenario != "wrappers-only":
                container.exec("/usr/bin/clang++", link)
            if scenario in {"unknown-python", "unknown-shell"}:
                interpreter, script = (("/usr/bin/python3", "/workspace/compiler.py")
                                       if scenario == "unknown-python" else ("/bin/sh", "/workspace/compiler.sh"))
                container.exec(interpreter, [interpreter, script, *invocation[1:]])
        if scenario not in {"empty", "wrappers-only"}:
            executable = "/workspace/compiler/clang++" if scenario == "outside" else "/usr/bin/clang++"
            container.exec(executable, invocation)
            if scenario == "mixed":
                container.exec(executable, [value if value != "-m64" else "-m32" for value in compile_argv])
        declared_argv = [arg if arg != "-m64" or scenario != "database-target" else "-m32"
                         for arg in compile_argv]
        (build / "compile_commands.json").write_text(json.dumps([{
            "directory": f"/workspace/{CASE}", "file": f"/workspace/{CASE}/main.cpp",
            "arguments": declared_argv,
        }]))
        return 0, b"built", b""

    executor = simulated_executor(profile, behavior)
    transcript = CPP.replace("@@tool gcc", """@@tool clang++
|/usr/bin/clang++
@@link clang++
|/usr/bin/clang++
|../lib/llvm-18/bin/clang
@@real clang++
|/usr/lib/llvm-18/bin/clang
@@tool gcc""")
    records = compiler_profiles.build_profile_records(
        compiler_profiles.parse_probe_transcript(transcript.encode()), image_digest=profile.image_id,
        executables=_executables(["clang", "gcc"]), transcript_sha256="b" * 64,
        image_signature="not-enforced")
    executor.compiler_profiles = lambda **_: compiler_profiles.profile_set(profile.image_id, records)
    if scenario == "corrupt":
        captured = executor.execute_captured
        def corrupt(*args, **kwargs):
            result = captured(*args, **kwargs)
            (result.capture_record.parent / "events.jsonl").write_bytes(b"changed after capture")
            return result
        executor.execute_captured = corrupt
    return executor


def _publish_input_plan(config, target, scenario):
    """Publish this test's upstream input, not a handwritten handoff or a mock of the build."""
    files = [{"path": path.relative_to(target).as_posix(), "sha256": file_sha256(path),
              "size_bytes": path.stat().st_size, "language": "C++"}
             for path in sorted(target.rglob("*")) if path.is_file()]
    units = discover_build_units(files)
    for action in units:
        action["descriptor_package"] = {"documents": [
            {"path": item["path"], "sha256": item["sha256"],
             "content": (target / item["path"]).read_text()} for item in files
            if str(Path(item["path"]).parent) == action["root"]],
            "bounds": {}, "gaps": []}
    fingerprint = source_fingerprint(target)
    catalog = {"source_fingerprint": fingerprint, "catalog_handoff_sha256": "c" * 64,
               "files": files, "components": [], "projects": [], "build_files": [],
               "build_units": units, "gaps": [], "accepted_artifacts": [], "compile_databases": []}
    summary = summarize_catalog(catalog, max_items=100, max_bytes=65536, sample_per_prefix=10)
    plan = deterministic_plan(catalog, summary)
    proposal = _recipe_proposal(units, scenario)
    if scenario != "missing":
        plan = merge_proposal(plan, proposal, catalog)

    def publish(unit):
        path = unit.job.attempt_root / "artifacts/analysis-plan/accepted-plan.json"
        atomic_json(path, plan)
        index = unit.job.run_root / "data/indices/analysis/target-analysis-plan-fixture.sqlite"
        builder = IndexBuilder(index, name="analysis", fingerprint=fingerprint,
                               target_snapshot=fingerprint, shard_id="target-analysis-plan")
        digest = builder.build()
        identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2", digest, fingerprint,
                                 index.relative_to(unit.job.run_root).as_posix(),
                                 {"job": "job_target_analysis_plan", "unit": unit.unit_id},
                                 (), "target-analysis-plan")
        manifest = unit.job.run_root / "data/indices/manifests/target-analysis-plan-fixture.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=fingerprint,
                       target_root=target, indexes=[identity])
        return {"artifact": reference(unit.job.run_root, path),
                "index_manifest": reference(unit.job.run_root, manifest), "terminal_status": "SUCCEEDED"}

    publisher = Job("job_target_analysis_plan", config.job("job_target_analysis_plan").name, lambda _: {},
                    units=(Unit("plan_acceptance.publish_handoff", publish),),
                    schema_identity=PLAN_SCHEMA, datasets=PLAN_DATASETS)
    return publisher


def _setup(tmp_path, scenario, *, consume=False, native_only=False, control=None):
    config, target = _config(tmp_path, scenario)
    calls, image_calls = [], []
    tags = {profile["tag"]: profile["image_id"]
            for profile in config.job("job_project_build").settings["profiles"].values()}

    def docker(argv, timeout):
        image_calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, tags[argv[3]].encode(), b"", False
        pytest.fail("base image must not require a derived-image builder")

    def resolver(unit):
        return ProjectImageResolver(metadata_root=unit.job.metadata_root,
                                    target_root=unit.job.target_root, run_root=unit.job.run_root,
                                    releases=unit.job.review_policy.releases, runner=docker)

    project = build_job(executor_factory=lambda unit, profile: _executor(
                            profile, calls, control[0] if control is not None else scenario),
                        image_resolver_factory=resolver)
    if native_only:
        project = replace(project, units=tuple(unit for unit in project.units if unit.unit_id in {
            "plan.load_recipes", "image.native", "probe.native"}))
    jobs = [_publish_input_plan(config, target, scenario), project]
    if consume:
        consumer = language_job(executor_factory=lambda *_: pytest.fail("native build was repeated"))
        # Exercise the actual native ingestion units, not unrelated family lanes and index publication.
        consumer = replace(consumer, units=tuple(unit for unit in consumer.units if unit.unit_id in {
            "iterations.dispatch", "load.native", "execute.native"}))
        jobs.append(consumer)
    return config, target, GraphRunner(config, jobs), calls, image_calls


def _run(tmp_path, scenario, *, consume=False):
    config, target, graph, calls, image_calls = _setup(tmp_path, scenario, consume=consume)
    result = graph.run(target_root=target, source_fingerprint=source_fingerprint(target))
    run = config.runtime.runs_dir / result["run_id"]
    return run, result, load_accepted_builds(run), calls, image_calls


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
