from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.container_runtime.catalog import ContainerCatalog, ToolImage
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest, Mount


DIGEST = "sha256:" + "a" * 64


def catalog(tmp_path: Path, *, expected: str | None = DIGEST) -> ContainerCatalog:
    policy = MappingProxyType({"tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=128m"]})
    tool = ToolImage("tool-fixture", "fixture", "1", "fixture:1", "/bin/fixture",
                     "10001:10001", "none", "1g", "2", 256, 10, 8, expected,
                     tmp_path / "tool.toml", MappingProxyType({}))
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
    docker = calls[-1]
    assert docker[0:2] == ["docker", "run"]
    assert ["--network", "none"] == docker[docker.index("--network"):docker.index("--network") + 2]
    assert "--read-only" in docker and "ALL" in docker and "no-new-privileges" in docker
    assert "value with spaces" in docker
    assert result.image_id == DIGEST
    assert result.stdout_truncated and result.stderr_truncated
    assert (tmp_path / "run" / result.stdout_path).read_bytes() == b"01234567"


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
        return CommandOutcome(None, b"partial", b"timeout", timed_out=True)
    result = ContainerExecutor(catalog(tmp_path), tmp_path / "run", runner=runner).execute(
        ExecutionRequest("tool-fixture", ("/bin/fixture",), target, tmp_path / "run" / "scratch"))
    assert result.timed_out and result.terminal_status == "TIMEOUT" and result.exit_code is None
