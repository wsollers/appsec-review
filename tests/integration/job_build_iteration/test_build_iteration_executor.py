"""job_build_iteration: the pre-walk replay-executor suite, moved out of the unit path by T-113.

Both cases drive the real replay callback over the ``build`` fixture of test_build_recipe_replay,
whose setup publishes a synthetic accepted plan through JobRunner and costs 8 to 10 s at four
workers, over the unit budget. They are integration tests pending replacement and run only when
named explicitly (``scripts/run-tests.sh --allow-heavy -- <file>``). At the walk's HEAD (52b3daab)
the three real-replay cases already failed (KeyError: 'topology_refinement').
"""
from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildProfile, CaptureScope
from appsec_review.container_runtime.build_executor import reconcile_build_leases
from appsec_review.jobs.build_workspace import BuildWorkspace, NodeBinding, ProductSpec
from tests.capture_fakes import simulated_executor
from tests.integration.job_build_iteration.test_build_recipe_replay import build
from tests.unit.job_build_iteration.support import NATIVE_OBJECT, NATIVE_OUTPUT, TARGET, _compiler_metadata

VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "fixture/1", "abi": "fixture-abi/1"}


@pytest.mark.parametrize(("prepared", "offline"), [(False, False), (False, True), (True, True)])
def test_real_replay_callback_captures_shared_commands_interfaces_profile_and_explicit_offline(
        build, monkeypatch, prepared, offline):  # noqa: F811
    import appsec_review.container_runtime as runtime
    from appsec_review.jobs.build_iterations import (
        captured_replay, digest, read_reference, retain, select_promotion, selected_revisions,
    )
    from appsec_review.jobs.build_recipe_replay import ImageResolution, load_promoted_revision, replay_recipe
    run = build.workspace.run_dir
    original_image = {
        "family": "native", "image_tag": "fixture:base",
        "image_id": build.context.binding.image_identity, "user": "1000:1000", "dependency_hashes": {},
    }
    failure = read_reference(run, build.context.inputs["failure"])
    original_request = read_reference(run, failure["request"])
    request_ref = retain(run, "requests", {**original_request, "dispatch": {
        **original_request["dispatch"], "image": original_image}})
    context = replace(build.context, inputs={**build.context.inputs, "failure": retain(
        run, "failures", {**failure, "request": request_ref})})
    candidate = replace(build.candidate, recipe={
        **build.candidate.recipe,
        "execution_cwd": {"configure": "a-consumer/build", "build": "a-consumer/build"},
        "configure_commands": [["clang", TARGET, "-c", "../b.c", "-o", "preflight.o"]],
        "build_commands": [["clang", TARGET, "../b.c", "-o", "B", "-g"]],
        **({"system_packages": ["libssl-dev"]} if prepared else {}),
    })
    profile = (BuildProfile("native", "fixture:prepared", "sha256:" + "2" * 64, "1000:1000",
                            context.binding.image_identity) if prepared else
               BuildProfile("native", "fixture:base", context.binding.image_identity, "1000:1000"))
    capture = BuildCaptureConfig("ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100)
    config = SimpleNamespace(
        runtime=SimpleNamespace(runs_dir=run.parent),
        job=lambda _: SimpleNamespace(settings={"command_timeout_seconds": 90, "output_bytes": 4096},
                                      build_capture=capture))
    observed, launched, profiles, mounts = [], [], [], {}
    real_executor = runtime.BuildContainerExecutor

    def behavior(argv, target, cwd, environment, recording):
        assert cwd == "a-consumer/build"
        assert environment["CPATH"] == "/install/include"
        assert environment["LIBRARY_PATH"] == "/install/lib"
        assert environment["PKG_CONFIG_PATH"] == "/install/lib/pkgconfig"
        assert environment["CMAKE_PREFIX_PATH"] == "/install"
        assert (mounts["/install"] / "lib/libA.a").read_bytes() == build.a_bytes
        recording.exec("/usr/bin/clang", argv)
        launched.append(tuple(argv))
        if "-c" not in argv:
            assert tuple(argv) == ("clang", TARGET, "../b.c", "-o", "B", "-g")
            output = mounts["/install"] / "bin/B"
            output.parent.mkdir(exist_ok=True)
            output.write_bytes(NATIVE_OUTPUT)
            (target / "a-consumer/build/B").write_bytes(NATIVE_OUTPUT)
        else:
            assert tuple(argv) == ("clang", TARGET, "-c", "../b.c", "-o", "preflight.o")
            (target / "a-consumer/build/preflight.o").write_bytes(NATIVE_OBJECT)
        return 0, b"", b""

    def factory(actual_profile, **kwargs):
        profiles.append(actual_profile)
        simulated = simulated_executor(actual_profile, behavior)

        def boundary(argv, timeout):
            assert tuple(argv[:2]) in {
                ("docker", "image"), ("docker", "inspect"), ("docker", "run"), ("docker", "rm")}
            observed.append(tuple(argv))
            for index, value in enumerate(argv[:-1]):
                if value == "--mount":
                    fields = dict(item.split("=", 1) for item in argv[index + 1].split(",") if "=" in item)
                    mounts[fields["dst"]] = Path(fields["src"])
            return simulated.runner(argv, timeout)

        return real_executor(actual_profile, runner=boundary, **kwargs)

    monkeypatch.setattr(runtime, "BuildContainerExecutor", factory)
    image_builder = None
    if prepared:
        approval = retain(run, "image-approvals", {
            "image_id": profile.image_id, "profile": asdict(profile), "operator_approved": True,
            "recipe_identity": digest(candidate.recipe),
            "compiler_metadata": retain(run, "compiler-metadata", _compiler_metadata(profile.image_id, candidate.recipe)),
            "network": "none", "prepared": True})
        image_builder = lambda *_: ImageResolution(profile, approval)
    before = (build.workspace.paths.install / "lib/libA.a").read_bytes()
    trial = replay_recipe(
        build.workspace, context, candidate, network_offline=offline, approved_image_builder=image_builder,
        execute=lambda invocation: captured_replay(config, context, invocation))
    assert read_reference(run, trial)["status"] == "SUCCEEDED"
    assert profiles == [profile] and len(launched) == 2
    containers = [argv for argv in observed if argv[:2] == ("docker", "run")]
    assert len(containers) == 4
    for argv in containers:
        assert ("--pull" in argv) is offline
        if offline:
            assert argv[argv.index("--pull") + 1] == "never"
        expected_network = "none" if offline or "--report-path" in argv else "bridge"
        assert argv[argv.index("--network") + 1] == expected_network
    assert (build.workspace.paths.install / "lib/libA.a").read_bytes() == before
    assert not (build.workspace.paths.install / "bin/B").exists()
    promotion = select_promotion(run, context.view(), trial)
    revision = load_promoted_revision(build.workspace, context, promotion)
    assert revision.profile == (profile if prepared else None)
    graph = read_reference(run, context.inputs["graph"])
    dispatch = {**context.validation_unit, "image": original_image}
    selected, dispatches, overrides = selected_revisions(run, {"execution_graph": graph}, [dispatch])
    assert selected["topology_id"] == graph["topology_id"]
    assert selected["coverage_gaps"] == graph["coverage_gaps"]
    assert dispatches[0]["recipe"] == candidate.recipe
    assert dispatches[0]["image"]["image_id"] == profile.image_id
    assert overrides[context.binding.node_id] == [asdict(spec) for spec in context.products]
    if prepared:
        assert dispatches[0]["promoted_profile"] == asdict(profile)


@pytest.mark.parametrize("mutation", ["missing", "image", "recipe"])
def test_captured_replay_admits_actual_refinement_before_executor_construction_or_resolution(build, monkeypatch, mutation):  # noqa: F811
    from unittest.mock import Mock
    import appsec_review.container_runtime as runtime
    from appsec_review.jobs.build_iterations import captured_replay, read_reference
    from appsec_review.jobs.build_recipe_replay import ReplayInvocation
    run = build.workspace.run_dir
    failure = read_reference(run, build.context.inputs["failure"])
    dispatch = read_reference(run, failure["request"])["dispatch"]
    profile = BuildProfile("native", "fixture:base", build.context.binding.image_identity, "1000:1000")
    candidate = replace(build.candidate, recipe=build.context.accepted_recipe)
    if mutation == "image":
        profile = replace(profile, image_id="sha256:" + "2" * 64)
    elif mutation == "recipe":
        candidate = build.candidate
    invocation = ReplayInvocation(
        build.context, candidate, build.workspace.paths, run / "artifacts/never-captured",
        "never-executed", "none", profile.image_id, profile,
        topology_refinement=None if mutation == "missing" else dispatch["topology_refinement"])
    executor = Mock(side_effect=AssertionError("unadmitted replay must not construct an executor"))
    monkeypatch.setattr(runtime, "BuildContainerExecutor", executor)
    config = SimpleNamespace(runtime=SimpleNamespace(runs_dir=run.parent),
                             job=Mock(side_effect=AssertionError("must fail before executor settings")))
    with pytest.raises(ValueError):
        captured_replay(config, build.context, invocation)
    executor.assert_not_called()
    config.job.assert_not_called()
