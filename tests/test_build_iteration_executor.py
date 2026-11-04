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
from tests.test_build_recipe_replay import build

VARIANT = {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
           "linkage": "static", "toolchain": "fixture/1", "abi": "fixture-abi/1"}


def test_captured_shared_mounts_preserve_committed_producer_metadata(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "source.c").write_text("int a;\n")
    run = tmp_path / "runs" / "fixture"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, "source/1")
    binding = NodeBinding("a", "source/1", "graph/1", "config/1", "recipe/1",
                          "sha256:" + "a" * 64, "toolchain/1", (), "execution/1", "outputs/1")
    profile = BuildProfile("native", "fixture:local", "sha256:" + "a" * 64, "1000:1000")

    def behavior(argv, target, cwd, environment, capture):
        assert cwd == "." and environment["PREFIX"] == "/install"
        capture.exec("/usr/bin/cc", argv)
        capture.open("/install/include/a.h")
        (target / "b.o").write_bytes(b"b")
        return 0, b"", b""

    executor = simulated_executor(profile, behavior)
    executor.lease_directory = run / "data/build/iterations/leases/b"
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "a-attempt", writer.state()["generation"])
        header = workspace.paths.install / "include/a.h"
        header.parent.mkdir()
        header.write_bytes(b"int a;")
        header.chmod(0o644)
        producer = writer.commit((ProductSpec("install/include/a.h", "headers", "a-headers",
                                              "include:a", VARIANT),))
        before = (header.stat().st_mode, header.stat().st_mtime_ns, header.read_bytes())
        consumer = replace(binding, node_id="b", upstream_products=(producer.reference["sha256"],))
        writer.begin_attempt(consumer, "b-attempt", writer.state()["generation"])
        result = executor.execute_captured(
            ("cc", "source.c"), workspace=workspace.paths.target, install_dir=workspace.paths.install,
            working_directory=".", environment={"PREFIX": "/install"},
            capture_directory=run / "artifacts/capture/b",
            capture_config=BuildCaptureConfig("ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100),
            scope=CaptureScope("fixture", "job_language_build", "b-attempt", "b", "native"))
        assert result.cleanup_complete
        assert (header.stat().st_mode, header.stat().st_mtime_ns, header.read_bytes()) == before
        writer.commit((ProductSpec("target/b.o", "library", "b-object", "object:b", VARIANT),))
        writer.verify_product(producer.reference, binding)
    outcome = json.loads((run / "artifacts/capture/b/execution-outcome.json").read_bytes())
    assert outcome["cleanup"] == "SUCCEEDED"
    leases = list(executor.lease_directory.glob("*.json"))
    assert len(leases) == 2
    assert all(json.loads(path.read_bytes())["mounts_closed"] is True
               and json.loads(path.read_bytes())["container_closed"] is True for path in leases)
    assert (source / "source.c").read_bytes() == b"int a;\n"


def test_cleanup_failure_cannot_publish_success_and_restores_original_modes(tmp_path: Path):
    source, install = tmp_path / "source", tmp_path / "install"
    source.mkdir()
    install.mkdir()
    product = install / "a.h"
    product.write_bytes(b"A")
    product.chmod(0o644)
    profile = BuildProfile("native", "fixture:local", "sha256:" + "a" * 64, "1000:1000")
    executor = simulated_executor(profile, lambda *_: (0, b"", b""))
    runner = executor.runner
    executor.runner = lambda argv, timeout: ((2, b"", b"daemon unavailable", False)
                                             if tuple(argv[:3]) == ("docker", "rm", "--force")
                                             else runner(argv, timeout))
    with pytest.raises(RuntimeError, match="cleanup is unconfirmed"):
        executor.execute(("true",), workspace=source, install_dir=install,
                         working_directory=".", environment={})
    assert product.stat().st_mode & 0o777 == 0o644


def test_recovery_closes_only_validated_registered_container_names(tmp_path: Path):
    directory = tmp_path / "leases"
    directory.mkdir()
    name = "appsec-review-build-" + "a" * 32
    lease = directory / f"{name}.json"
    lease.write_text(json.dumps({
        "schema": "appsec-review/build-worker-lease/1", "container": name,
        "workspace": str(tmp_path / "target"), "install": str(tmp_path / "install"),
        "container_closed": False, "mounts_closed": False,
    }))
    calls = []

    def runner(argv, timeout):
        calls.append(tuple(argv))
        return 0, b"", b"", False

    reconcile_build_leases(directory, workspace=tmp_path / "target",
                           install=tmp_path / "install", runner=runner)
    assert calls == [("docker", "rm", "--force", name)]
    value = json.loads(lease.read_bytes())
    value["workspace"] = str(tmp_path / "foreign")
    lease.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="invalid build worker lease"):
        reconcile_build_leases(directory, workspace=tmp_path / "target",
                               install=tmp_path / "install", runner=runner)
    assert len(calls) == 1


def test_export_publishes_actual_install_outputs_and_aliases_without_reclaiming_upstreams(tmp_path):
    from appsec_review.jobs.build_iterations import install_inventory, product_specs
    source = tmp_path / "source"
    source.mkdir()
    (source / "source.c").write_bytes(b"int a;\n")
    run = tmp_path / "run"
    run.mkdir()
    workspace = BuildWorkspace(run)
    initial = workspace.materialize(source, "source/1")
    binding = NodeBinding("a", "source/1", "graph/1", "config/1", "recipe/1",
                          "sha256:" + "a" * 64, "toolchain/1", (), "execution/1", "outputs/1")
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "a-attempt", initial)
        library = workspace.paths.install / "lib/libA.a"
        library.parent.mkdir()
        library.write_bytes(b"A")
        producer = writer.commit((ProductSpec("install/lib/libA.a", "library", "a-lib", "A", VARIANT),))
        before = install_inventory(workspace.paths.install)
        consumer = replace(binding, node_id="b", upstream_products=(producer.identity,))
        writer.begin_attempt(consumer, "b-attempt", writer.state()["generation"])
        (library.parent / "libB.so.1").write_bytes(b"B")
        (library.parent / "libB.so").symlink_to("libB.so.1")
        node = {"variant": VARIANT, "products": [
            {"kind": "library", "product_id": "b-lib", "interface": "cmake-target:B", "variant": VARIANT}]}
        specs = product_specs(node, {"artifacts": []}, workspace, install_before=before)
        assert {spec.path for spec in specs} == {"install/lib/libB.so", "install/lib/libB.so.1"}
        assert next(spec for spec in specs if spec.interface == "cmake-target:B").path == "install/lib/libB.so"
        writer.commit(specs)
        writer.verify_product(producer.reference, binding)
    assert library.read_bytes() == b"A"


@pytest.mark.parametrize(("prepared", "offline"), [(False, False), (False, True), (True, True)])
def test_real_replay_callback_captures_shared_commands_interfaces_profile_and_explicit_offline(
        build, monkeypatch, prepared, offline):
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
    request_ref = retain(run, "requests", {"dispatch": {
        "image": original_image, "recipe": build.context.accepted_recipe}})
    failure = read_reference(run, build.context.inputs["failure"])
    context = replace(build.context, inputs={**build.context.inputs, "failure": retain(
        run, "failures", {**failure, "request": request_ref})})
    candidate = replace(build.candidate, recipe={
        **build.candidate.recipe,
        "execution_cwd": {"configure": "a-consumer/build", "build": "a-consumer/build"},
        "configure_commands": [["cmake", "-S", "..", "-B", "."]],
        "build_commands": [["cmake", "--build", "a-consumer/build", "--target",
                            "a-consumer/custom-target", "B", "--config", "a-consumer/Release"]],
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
        recording.exec("/usr/bin/cmake", argv)
        launched.append(tuple(argv))
        if "--build" in argv:
            assert tuple(argv) == ("cmake", "--build", ".", "--target",
                                   "a-consumer/custom-target", "B", "--config", "a-consumer/Release")
            output = mounts["/install"] / "bin/B"
            output.parent.mkdir(exist_ok=True)
            output.write_bytes(b"trial B executable")
            (target / "a-consumer/build/B").write_bytes(b"trial B executable")
        else:
            assert tuple(argv) == ("cmake", "-S", "..", "-B", ".")
            (target / "a-consumer/build/CMakeCache.txt").write_text(
                "CMAKE_HOME_DIRECTORY:INTERNAL=/workspace/a-consumer\n")
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
