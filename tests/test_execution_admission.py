from contextvars import copy_context
import json
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.assurance import ComponentReleases, ResourceBudget
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile, ProjectImageResolver
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest
from appsec_review.observability import EventLog
from appsec_review.runtime.resources import (
    Reservation, ResourceAdmission, reserve_execution, review_resource_scope,
)
from tests.test_container_runtime import DIGEST, catalog


@pytest.mark.parametrize("backend", ("scanner", "build"))
@pytest.mark.parametrize("confirmed", (False, True))
def test_review_executor_tracks_container_before_launch_and_quarantines_uncertain_death(
        tmp_path, backend, confirmed):
    metadata = tmp_path / "metadata"
    events = EventLog(tmp_path / "events.jsonl")
    target = tmp_path / "target"
    target.mkdir()
    lease_path = metadata / "resource-admission" / "leases.json"
    launches = []

    def runner(argv, timeout):
        argv = tuple(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            value = (0, DIGEST.encode(), b"", False)
        elif argv[:2] == ("docker", "run"):
            lease = next(iter(json.loads(lease_path.read_text())["leases"].values()))
            name = argv[argv.index("--name") + 1]
            assert name in lease["containers"]
            assert lease["reservation"]["cpu"] == 2
            assert lease["reservation"]["memory_mb"] == (1536 if backend == "scanner" else 4608)
            launches.append(name)
            value = (None, b"", b"client timed out", True)
        elif argv[:2] in (("docker", "kill"), ("docker", "rm")):
            value = (1, b"", b"daemon unavailable", False)
        elif argv[:3] == ("docker", "container", "inspect"):
            value = (0, b"false" if confirmed else b"true", b"", False)
        else:
            raise AssertionError(argv)
        return CommandOutcome(*value) if backend == "scanner" else value

    def execute():
        if backend == "scanner":
            return ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner).execute(
                ExecutionRequest("tool-fixture", ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
        return BuildContainerExecutor(BuildProfile("native", "fixture", DIGEST, "10001:10001"),
                                      timeout_seconds=10, output_bytes=1024, runner=runner).execute(
                                          ("cc", "--version"), workspace=target,
                                          working_directory=".", environment={})

    with review_resource_scope(metadata, ResourceBudget(), events):
        if confirmed:
            assert execute().timed_out
        else:
            with pytest.raises(RuntimeError, match="death is unconfirmed"):
                execute()
    leases = json.loads(lease_path.read_text())["leases"]
    assert len(launches) == 1
    if confirmed:
        assert leases == {}
    else:
        lease = next(iter(leases.values()))
        assert lease["containers"] == launches
        assert lease["owner_finished"]
        assert lease["quarantine"].endswith("container_death_unconfirmed")


def test_nested_execution_cannot_expand_or_outlive_reservation(tmp_path):
    events = EventLog(tmp_path / "events.jsonl")
    with review_resource_scope(tmp_path, ResourceBudget(), events):
        with reserve_execution(cpu="2", memory="1g", action="outer", timeout_seconds=1):
            with pytest.raises(ValueError, match="exceeds"):
                with reserve_execution(cpu="2", memory="4g", action="oversized", timeout_seconds=1):
                    pytest.fail("nested execution expanded the reservation")
            context = copy_context()
    def late():
        with reserve_execution(cpu="1", memory="1m", action="late", timeout_seconds=1):
            pytest.fail("expired lease admitted execution")
    with pytest.raises(RuntimeError, match="outlived"):
        context.run(late)
    assert json.loads((tmp_path / "resource-admission" / "leases.json").read_text())["leases"] == {}


@pytest.mark.parametrize("state", ["removed", "stopped", "running", "wrong-container", "missing-socket", "timeout"])
def test_native_cleanup_requires_exact_removal_and_keeps_unknown_work_reserved(tmp_path, state):
    from appsec_review.runtime.resources import tracked_container

    events = EventLog(tmp_path / "events.jsonl")
    commands = []
    def runner(argv, timeout):
        commands.append(tuple(argv))
        if argv[:2] == ("docker", "rm"):
            return 0, b"", b"", False
        assert argv[:3] == ("docker", "container", "inspect")
        if state in {"stopped", "running"}:
            return 0, b"false" if state == "stopped" else b"true", b"", False
        if state == "timeout":
            return None, b"", b"", True
        message = {
            "removed": b"Error: No such container: owned-fixture",
            "wrong-container": b"Error: No such container: unrelated",
            "missing-socket": b"No such file or directory",
        }[state]
        return 1, b"", message, False

    def execute():
        with review_resource_scope(tmp_path, ResourceBudget(), events, require_container_removal=True):
            with reserve_execution(cpu="1", memory="1m", action="native.fixture", timeout_seconds=1):
                with tracked_container("owned-fixture", runner, label="Native"):
                    pass

    if state == "removed":
        execute()
    else:
        with pytest.raises(RuntimeError, match="removal is unconfirmed"):
            execute()
    assert len(commands) == 2
    path = tmp_path / "resource-admission/leases.json"
    leases = json.loads(path.read_text())["leases"]
    if state == "removed":
        assert leases == {}
    else:
        lease_id, lease = next(iter(leases.items()))
        assert lease["container_cleanup"] == "removed"
        assert lease["containers"] == ["owned-fixture"] and lease["owner_finished"]
        assert lease["quarantine"] == "native_container_removal_unconfirmed"
        admission = ResourceAdmission(tmp_path, ResourceBudget())
        assert admission.reconcile(lambda name: True, confirmed_cleanup=lambda entry: True) == []
        assert admission.reconcile(
            lambda name: True, confirmed_cleanup=lambda entry: True,
            confirmed_removed=lambda name: name == "owned-fixture") == [lease_id]


def test_native_cleanup_cannot_be_weakened_by_a_nested_resource_scope(tmp_path):
    events = EventLog(tmp_path / "events.jsonl")
    with review_resource_scope(tmp_path, ResourceBudget(), events, require_container_removal=True):
        with reserve_execution(cpu="1", memory="1m", action="native.outer", timeout_seconds=1):
            with review_resource_scope(tmp_path, ResourceBudget(), events):
                with pytest.raises(ValueError, match="enclosing resource contract"):
                    with reserve_execution(cpu="1", memory="1m", action="legacy.inner", timeout_seconds=1):
                        pytest.fail("native cleanup was weakened")


def _mixed_worker(metadata, backend, eligible, started, release):
    assert set(os.sched_getaffinity(0)) <= {0, 1, 2, 3}
    root = Path(metadata)
    budget = ResourceBudget(cpu=4, memory_mb=7000, io_slots=2, staging_memory_mb=512)
    events = EventLog(root / f"{backend}.jsonl")
    eligible.set()
    if backend == "codeql":
        with ResourceAdmission(root, budget).reserve(
                Reservation(2, 5000), events=events, action="codeql.fixture", timeout_seconds=10):
            started.set()
            assert release.wait(15)
        return
    work = root / backend
    work.mkdir()
    def runner(argv, timeout):
        argv = tuple(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            value = (0, DIGEST.encode(), b"", False)
        elif argv[:2] == ("docker", "run"):
            leases = json.loads((root / "resource-admission" / "leases.json").read_text())["leases"]
            assert sum(lease["reservation"]["cpu"] for lease in leases.values()) <= 4
            assert sum(lease["reservation"]["memory_mb"] for lease in leases.values()) <= 7000
            started.set()
            assert release.wait(15)
            value = (0, b"", b"", False)
        elif argv[:2] == ("docker", "rm"):
            value = (0, b"", b"", False)
        else:
            raise AssertionError(argv)
        return CommandOutcome(*value) if backend == "scanner" else value
    with review_resource_scope(root, budget, events):
        if backend == "scanner":
            ContainerExecutor(catalog(work), work / "run", runner=runner).execute(
                ExecutionRequest("tool-fixture", ("/bin/fixture",), work, work / "run" / "scratch"))
        else:
            BuildContainerExecutor(BuildProfile("native", "fixture", DIGEST, "10001:10001"),
                                   timeout_seconds=10, output_bytes=1024, runner=runner).execute(
                                       ("cc", "--version"), workspace=work,
                                       working_directory=".", environment={})


def test_mixed_codeql_scanner_build_processes_share_one_budget(tmp_path):
    context = multiprocessing.get_context("spawn")
    signals = {name: (context.Event(), context.Event(), context.Event())
               for name in ("codeql", "scanner", "build")}
    workers = []
    try:
        for name in ("codeql", "scanner", "build"):
            worker = context.Process(target=_mixed_worker, args=(str(tmp_path), name, *signals[name]))
            worker.start()
            workers.append(worker)
            assert signals[name][0].wait(10)
            if name != "build":
                assert signals[name][1].wait(10)
        assert not signals["build"][1].wait(0.1)
        signals["codeql"][2].set()
        assert signals["build"][1].wait(10)
    finally:
        for values in signals.values():
            values[2].set()
        for worker in workers:
            worker.join(20)
            if worker.is_alive():
                worker.terminate()
                worker.join(5)
    assert all(worker.exitcode == 0 for worker in workers)
    assert json.loads((tmp_path / "resource-admission" / "leases.json").read_text())["leases"] == {}


@pytest.mark.parametrize("backend", ("project", "codeql"))
def test_unbounded_derived_image_build_is_named_gap_before_daemon_mutation(tmp_path, backend):
    from appsec_review.codeql.runtime import CodeQLImageResolver
    target = tmp_path / "target"
    target.mkdir()
    calls = []
    def runner(argv, timeout):
        calls.append(argv)
        assert argv[:3] == ("docker", "image", "inspect"), "review mutated an unbounded builder"
        return 0, DIGEST.encode(), b"", False
    releases = ComponentReleases({key: "fixture/1" for key in
                                  ("platform", "build_toolchain", "codeql", "codeql_runner")})
    metadata = tmp_path / "metadata"
    with review_resource_scope(metadata, ResourceBudget(), EventLog(tmp_path / "events.jsonl")):
        with pytest.raises(RuntimeError, match="derived_image_preparation_unavailable"):
            if backend == "project":
                resolver = ProjectImageResolver(metadata_root=metadata, target_root=target,
                                                runner=runner, releases=releases)
                resolver.resolve({"source_dir": ".", "system_packages": ["cmake"]},
                                 BuildProfile("native", "base", DIGEST, "10001:10001"))
            else:
                resolver = CodeQLImageResolver(repository_root=tmp_path, metadata_root=metadata,
                    settings=SimpleNamespace(source_image_tag="source", source_image_id=DIGEST),
                    runner=runner, releases=releases)
                resolver.resolve(build_image_tag="base", build_image_id=DIGEST, runtime_user="10001:10001")
    assert calls
    assert not list(metadata.rglob("Dockerfile"))


def test_review_admission_can_use_declared_prepared_image_without_building(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    builds = []
    def runner(argv, timeout):
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, DIGEST.encode(), b"", False
        assert argv[:3] == ("docker", "buildx", "build")
        builds.append(argv)
        return 0, b"", b"", False
    releases = ComponentReleases({"platform": "fixture/1", "build_toolchain": "fixture/1"})
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target,
                                    runner=runner, releases=releases)
    recipe = {"source_dir": ".", "system_packages": ["cmake"]}
    profile = BuildProfile("native", "base", DIGEST, "10001:10001")
    prepared = resolver.resolve(recipe, profile)[0]
    with review_resource_scope(tmp_path / "metadata", ResourceBudget(), EventLog(tmp_path / "events.jsonl")):
        accepted = resolver.resolve(recipe, profile)[0]
        assert accepted.reused and accepted.image_id == prepared.image_id
        baseline = resolver.resolve({"source_dir": ".", "system_packages": []}, profile)[0]
        assert not baseline.customized and not baseline.reused
    assert len(builds) == 1
