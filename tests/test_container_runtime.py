from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import sys
from types import MappingProxyType

import pytest

from appsec_review.container_runtime.catalog import ContainerCatalog, ToolImage
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest, Mount
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.container_runtime.measurement import (
    COUNTERS, TreeSitterInvocation, capture_resources, supervise,
)


DIGEST = "sha256:" + "a" * 64


def test_application_runtime_user_uses_non_root_process_identity(monkeypatch) -> None:
    monkeypatch.setattr("appsec_review.container_runtime.identity.os.geteuid", lambda: 1234,
                        raising=False)
    monkeypatch.setattr("appsec_review.container_runtime.identity.os.getegid", lambda: 5678,
                        raising=False)
    assert application_runtime_user("10001:10001") == "1234:5678"


def test_application_runtime_user_keeps_non_root_fallback_for_root_process(monkeypatch) -> None:
    monkeypatch.setattr("appsec_review.container_runtime.identity.os.geteuid", lambda: 0,
                        raising=False)
    monkeypatch.setattr("appsec_review.container_runtime.identity.os.getegid", lambda: 0,
                        raising=False)
    assert application_runtime_user("10001:10001") == "10001:10001"


def catalog(tmp_path: Path, *, expected: str | None = DIGEST, additional: tuple[str, ...] = ()) -> ContainerCatalog:
    policy = MappingProxyType({"tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=128m"]})
    tool = ToolImage("tool-fixture", "fixture", "1", "fixture:1", "/bin/fixture",
                     "10001:10001", "none", "1g", "2", 256, 10, 8, expected,
                     tmp_path / "tool.toml", MappingProxyType({}), additional_executables=additional)
    return ContainerCatalog(tmp_path / "catalog.toml", tmp_path / "policy.toml", policy,
                            MappingProxyType({"tool-fixture": tool}))


def test_executor_uses_argv_and_enforces_mounts_policy_digest_and_bounds(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    def runner(argv, timeout):
        calls.append(list(argv))
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        return CommandOutcome(0, b"0123456789", b"abcdefghij")

    target = tmp_path / "target"
    target.mkdir()
    scratch = tmp_path / "run" / "scratch"
    result = ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner).execute(
        ExecutionRequest("tool-fixture", ("/bin/fixture", "--name", "value with spaces"), target, scratch)
    )
    docker = next(call for call in calls if "/bin/fixture" in call)
    assert docker[0:2] == ["docker", "run"]
    assert ["--network", "none"] == docker[docker.index("--network"):docker.index("--network") + 2]
    assert "--read-only" in docker and "ALL" in docker and "no-new-privileges" in docker
    assert "value with spaces" in docker
    assert result.image_id == DIGEST
    assert result.stdout_truncated and result.stderr_truncated
    assert (tmp_path / "run" / result.stdout_path).read_bytes() == b"01234567"
    expected_user = (f"{os.geteuid()}:{os.getegid()}" if hasattr(os, "geteuid") and
                     os.geteuid() > 0 and os.getegid() > 0 else "10001:10001")
    assert docker[docker.index("--user") + 1] == expected_user
    assert len([call for call in calls if call[:2] == ["docker", "run"]]) == 1


def test_execution_receipt_records_environment_identity(tmp_path: Path) -> None:
    def runner(argv, timeout):
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        return CommandOutcome(0, b"", b"")

    target = tmp_path / "target"
    target.mkdir()
    scratch = tmp_path / "run" / "scratch"
    executor = ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner)
    first = executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture",), target, scratch,
                                              environment={"MODE": "a"}))
    receipt = json.loads((scratch / "execution.json").read_text(encoding="utf-8"))
    assert receipt["environment_sha256"] == {"MODE": hashlib.sha256(b"a").hexdigest()}
    second = executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture",), target, scratch,
                                               environment={"MODE": "b"}))
    assert first.environment_sha256 != second.environment_sha256


def test_executor_rejects_digest_mismatch_and_docker_socket_mount(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    socket = tmp_path / "docker.sock"
    socket.write_text("fixture", encoding="utf-8")
    runner = lambda argv, timeout: CommandOutcome(0, ("sha256:" + "b" * 64).encode(), b"")
    executor = ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner)
    with pytest.raises(ValueError, match="Docker socket"):
        executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture",), target,
                         tmp_path / "run" / "scratch", (Mount(socket, "/docker.sock"),)))
    listing = tmp_path / "files.txt"
    listing.write_text("a\n", encoding="utf-8")
    with pytest.raises(ValueError, match="nest inside /scratch"):
        executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture",), target,
                         tmp_path / "run" / "scratch", (Mount(listing, "/scratch/files.txt", True),)))
    with pytest.raises(ValueError, match="digest mismatch"):
        executor.resolve_image(executor.catalog.tool("tool-fixture"))


def test_executor_records_timeout_and_failure_state(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    def runner(argv, timeout):
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        if tuple(argv[:2]) == ("docker", "kill"):
            return CommandOutcome(0, b"", b"")
        if "/usr/bin/find" in argv:
            return CommandOutcome(0, b"", b"")
        return CommandOutcome(None, b"partial", b"timeout", timed_out=True)
    result = ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner).execute(
        ExecutionRequest("tool-fixture", ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
    assert result.timed_out and result.terminal_status == "TIMEOUT" and result.exit_code is None
    assert (tmp_path / "run" / "scratch").stat().st_mode & 0o777 == 0o755


def test_scratch_is_writable_only_while_the_scanner_runs(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    scratch = tmp_path / "run" / "scratch"
    modes: list[int] = []

    def runner(argv, timeout):
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        modes.append(scratch.stat().st_mode & 0o777)
        raise OSError("docker vanished")

    with pytest.raises(OSError):
        ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner).execute(
            ExecutionRequest("tool-fixture", ("/bin/fixture",), target, scratch))
    assert modes == [0o700]
    assert scratch.stat().st_mode & 0o777 == 0o755


def test_a_declared_additional_executable_is_the_entrypoint_and_nothing_else_is_accepted(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def runner(argv, timeout):
        calls.append(list(argv))
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (DIGEST + "\n").encode(), b"")
        return CommandOutcome(0, b"", b"")

    target = tmp_path / "target"
    target.mkdir()
    executor = ContainerExecutor(catalog(tmp_path, additional=("/bin/fixture-export",)), tmp_path / "run", runner=runner)
    executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture-export", "--out", "/scratch/x"), target,
                                      tmp_path / "run" / "scratch"))
    docker = next(call for call in calls if call[:2] == ["docker", "run"])
    assert docker[docker.index("--entrypoint") + 1] == "/bin/fixture-export"
    for other in ("/bin/sh", "fixture-export"):
        with pytest.raises(ValueError, match="cataloged executable"):
            executor.execute(ExecutionRequest("tool-fixture", (other,), target, tmp_path / "run" / "scratch"))
    with pytest.raises(ValueError, match="absolute"):
        catalog(tmp_path, additional=("relative-tool",))


def cgroup_fixture(root: Path, *, oom: int = 0) -> Path:
    root.mkdir()
    for name, value in {
        "cpu.max": "200000 100000", "memory.max": "1073741824", "memory.swap.max": "0", "pids.max": "256",
        "cpu.stat": "usage_usec 120\nuser_usec 100\nsystem_usec 20\n", "memory.peak": "4096",
        "memory.events": f"low 0\nhigh 0\nmax 0\noom {oom}\noom_kill {oom}\n",
        "io.stat": "8:0 rbytes=1024 wbytes=512 rios=2 wios=1\n",
    }.items():
        (root / name).write_text(value)
    return root


def test_resource_capture_distinguishes_zero_from_unavailable(tmp_path: Path) -> None:
    root = cgroup_fixture(tmp_path / "cgroup")
    (root / "memory.swap.max").write_text("1073741824")
    measured = capture_resources(root)
    assert measured["cpu_usage_usec"] == 120 and measured["memory_peak_bytes"] == 4096
    assert measured["io_read_bytes"] == 1024 and measured["oom_kill_events"] == 0
    assert measured["local_limits"]["memory.max"] == "1073741824"
    assert measured["local_limits"]["memory.swap.max"] == "1073741824"
    assert measured["limit_scope"] == "container_cgroup" and not measured["ancestor_limits_visible"]
    assert "effective_limits" not in measured
    assert not measured["unavailable"]
    (root / "io.stat").write_text("")
    (root / "memory.peak").unlink()
    measured = capture_resources(root)
    assert measured["io_read_bytes"] == 0
    assert measured["memory_peak_bytes"] is None and measured["unavailable"]["memory.peak"] == "FileNotFoundError"


def test_supervisor_retains_final_counters_and_parser_exit(tmp_path: Path) -> None:
    root = cgroup_fixture(tmp_path / "cgroup")
    output = tmp_path / "resources.json"
    assert supervise([sys.executable, "-c", "raise SystemExit(7)"], output, cgroup_root=root) == 7
    retained = json.loads(output.read_text())
    assert retained["parser_returncode"] == 7 and retained["final_snapshot"] is True
    assert all(retained[key] is not None for key in COUNTERS)


@pytest.mark.parametrize("escalate", (False, True))
def test_supervisor_forwards_signals_and_bounds_child_cleanup(tmp_path: Path, monkeypatch, escalate: bool) -> None:
    root = cgroup_fixture(tmp_path / "cgroup")
    handlers, signals = {}, []
    clock = iter((1.0, 4.0))
    monkeypatch.setattr(signal, "signal", lambda number, handler: handlers.setdefault(number, handler))
    monkeypatch.setattr(os, "killpg", lambda pid, number: signals.append((pid, number)))
    monkeypatch.setattr("appsec_review.container_runtime.measurement.time.monotonic", lambda: next(clock))

    class Child:
        pid = 12345
        called = False

        def wait(self, timeout):
            if not self.called:
                self.called = True
                handlers[signal.SIGTERM](signal.SIGTERM, None)
                if escalate:
                    raise subprocess.TimeoutExpired("fixture", timeout)
            return -signal.SIGKILL if escalate else -signal.SIGTERM

        def poll(self):
            return -signal.SIGTERM

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Child())
    result = supervise(["fixture"], tmp_path / "resources.json", cgroup_root=root)
    assert result == (137 if escalate else 143)
    assert signals == [(12345, signal.SIGTERM), *([(12345, signal.SIGKILL)] if escalate else [])]
    assert json.loads((tmp_path / "resources.json").read_text())["oom_kill_events"] == 0


@pytest.mark.parametrize("failure", ("success", "oom", "timeout", "canceled", "missing"))
def test_measured_executor_preserves_linkage_resources_and_failed_receipts(tmp_path: Path, failure: str) -> None:
    from appsec_review.runtime.execution_safety import ReviewStopped
    base = catalog(tmp_path)
    tool = replace(base.tool("tool-fixture"), tool_id="tool-tree-sitter", executable="/opt/appsec/parser.py")
    tools = replace(base, tools=MappingProxyType({tool.tool_id: tool}))
    target, run = tmp_path / "target", tmp_path / "run"
    target.mkdir()
    scratch = run / "scratch"
    root = cgroup_fixture(tmp_path / "cgroup", oom=int(failure == "oom"))
    context = TreeSitterInvocation("a" * 32, "run", "job_source_history_analysis", "attempt_0001",
                                   "analyze.symbol_spans", "scope", "C", ({"path": "a.c", "sha256": "b" * 64},))
    calls = []

    def runner(argv, timeout):
        argv = list(argv)
        calls.append(argv)
        if argv[:3] == ["docker", "image", "inspect"]:
            return CommandOutcome(0, DIGEST.encode(), b"")
        if argv[:2] == ["docker", "run"]:
            assert argv[argv.index("--entrypoint") + 1] == "/usr/local/bin/python"
            assert argv[argv.index("--") + 1:] == list(request.argv)
            mount = next(value for value in argv if ",dst=/opt/appsec/measurement.py" in value)
            assert mount.endswith(",readonly")
            source = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
            assert scratch not in source.parents and source.stat().st_mode & 0o222 == 0
            if failure != "missing":
                (scratch / f"resources-{context.invocation_id}.json").write_text(json.dumps(capture_resources(root)))
            if failure == "canceled":
                raise ReviewStopped("fixture cancellation")
            return CommandOutcome(None if failure == "timeout" else 137 if failure == "oom" else 0,
                                  b"output", b"", timed_out=failure == "timeout", oom_killed=failure == "oom")
        if argv[:2] == ["docker", "stop"]:
            assert argv[2:4] == ["--time", "2"] and timeout == 5
            return CommandOutcome(0, b"", b"")
        assert argv[:3] == ["docker", "rm", "--force"]
        return CommandOutcome(0, b"", b"")

    request = ExecutionRequest(tool.tool_id, (tool.executable, "parse", "--request", "/scratch/request.json",
                                              "--output", "/scratch/output.json"), target, scratch, measurement=context)
    executor = ContainerExecutor(tools, run, runner=runner)
    if failure == "canceled":
        with pytest.raises(ReviewStopped, match="fixture cancellation"):
            executor.execute(request)
    else:
        result = executor.execute(request)
        assert result.timed_out is (failure == "timeout")
    receipt = json.loads((scratch / "execution.json").read_text())
    measured = json.loads((run / receipt["metrics_receipt"]["path"]).read_text())
    assert measured["invocation_id"] == context.invocation_id and measured["attempt_id"] == "attempt_0001"
    assert measured["files"] == [{"path": "a.c", "sha256": "b" * 64}]
    assert measured["configured_limits"]["memory"] == "1g"
    assert measured["status"] == {"success": "SUCCEEDED", "oom": "OOM", "timeout": "TIMEOUT",
                                   "canceled": "CANCELED", "missing": "SUCCEEDED"}[failure]
    assert measured["resources"]["memory_peak_bytes"] == (None if failure == "missing" else 4096)
    assert measured["resource_accounting_complete"] is (failure != "missing")
    assert sum(call[:2] == ["docker", "stop"] for call in calls) == int(failure in {"timeout", "canceled"})
    assert len([call for call in calls if call[:2] == ["docker", "run"]]) == 1
