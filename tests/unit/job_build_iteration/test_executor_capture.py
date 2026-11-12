"""job_build_iteration: the captured build executor and lease recovery with a simulated container
runner, and the install-output export that turns new workspace files into product specs. The fake
runner answers the docker argv in-process; nothing is started."""
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
from tests.unit.job_build_iteration.support import NATIVE_OBJECT, NATIVE_OUTPUT, TARGET, _compiler_metadata

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
