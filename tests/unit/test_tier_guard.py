"""The unit-tier guard refuses engines, network and Dagster, and fails tests over ten seconds."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

import pytest

from tests.unit import conftest as guard

REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(("args", "shell", "expected"), [
    (["docker", "run", "x"], False, "docker"),
    (("podman", "ps"), False, "podman"),
    ("docker version", True, "docker"),
    ("/usr/bin/claude -p ok", True, "claude"),
    ([b"gh", b"pr"], False, "gh"),
    (["python", "-c", "pass"], False, None),
    (["/opt/dagster/bin/dagster-daemon"], False, "dagster-daemon"),
    (["docker-compose"], False, None),
    ([], False, None),
], ids=["list", "tuple", "shell", "shell-path", "bytes", "allowed", "path", "near-miss", "empty"])
def test_blocked_executables_are_named_by_basename(args, shell, expected) -> None:
    assert guard.blocked_executable(args, shell, None) == expected


def test_a_fake_under_the_scratch_root_is_allowed_but_the_same_name_elsewhere_is_not(tmp_path: Path) -> None:
    fake = tmp_path / "bin" / "docker"
    assert guard.blocked_executable([str(fake)], False, tmp_path) is None
    assert guard.blocked_executable([str(fake)], False, tmp_path / "other") == "docker"
    assert guard.blocked_executable(["docker"], False, tmp_path) == "docker"  # bare name resolves on PATH


def test_real_docker_is_refused_before_it_starts() -> None:
    with pytest.raises(guard.UnitTierViolation, match="never launch 'docker'"):
        subprocess.run(["docker", "version"], capture_output=True)
    with pytest.raises(guard.UnitTierViolation, match="never launch 'claude'"):
        subprocess.Popen("claude -p ok", shell=True)


@pytest.mark.skipif(os.name == "nt", reason="fake executables are POSIX shell scripts")
def test_a_fake_docker_written_by_the_test_runs(tmp_path: Path) -> None:
    fake = tmp_path / "docker"
    fake.write_text("#!/bin/sh\necho fake-docker \"$@\"\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    completed = subprocess.run([str(fake), "version"], capture_output=True, text=True, check=True)
    assert completed.stdout.strip() == "fake-docker version"


def test_outbound_connections_are_refused_and_loopback_is_allowed() -> None:
    with socket.socket() as client:
        with pytest.raises(guard.UnitTierViolation, match="never open network connections"):
            client.connect(("203.0.113.1", 9))
    assert guard.is_loopback(("127.0.0.1", 80)) and guard.is_loopback(("::1", 80)) and guard.is_loopback("/tmp/sock")
    assert not guard.is_loopback(("example.invalid", 443))
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2) as client:
            assert client.getpeername()[0] == "127.0.0.1"


def test_dagster_execution_is_refused_once_imported() -> None:
    dagster = pytest.importorskip("dagster")
    assert guard.guard_dagster_if_imported()
    with pytest.raises(guard.UnitTierViolation, match="never execute Dagster"):
        dagster.execute_job(None)

    @dagster.op
    def one() -> int:
        return 1

    @dagster.job
    def graph() -> None:
        one()

    with pytest.raises(guard.UnitTierViolation, match="never execute Dagster"):
        graph.execute_in_process()


def test_unit_budget_is_ten_seconds_and_an_overrun_fails(tmp_path: Path) -> None:
    """A copy of the harness runs one unit test that sleeps past a lowered budget."""
    from tests.unit.conftest import LOOPBACK_HOSTS  # noqa: F401  (the guard module must import cleanly)
    from tests import time_budgets

    assert time_budgets.DEFAULT_TIER_BUDGETS["unit"] == 10.0
    assert time_budgets.tier_of(REPOSITORY / "tests" / "unit" / "job_x" / "test_y.py", REPOSITORY / "tests") == "unit"
    assert time_budgets.tier_of(REPOSITORY / "tests" / "test_y.py", REPOSITORY / "tests") is None

    root = tmp_path / "p"
    tests = root / "tests"
    (tests / "unit").mkdir(parents=True)
    for harness in ("conftest.py", "time_budgets.py", "host_pins_support.py"):
        (tests / harness).write_text((REPOSITORY / "tests" / harness).read_text(encoding="utf-8"), encoding="utf-8")
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "unit" / "__init__.py").write_text("", encoding="utf-8")
    (tests / "unit" / "conftest.py").write_text(
        (REPOSITORY / "tests" / "unit" / "conftest.py").read_text(encoding="utf-8"), encoding="utf-8")
    for document in ("appsec-review.toml", "containers/catalog.toml"):
        (root / document).parent.mkdir(parents=True, exist_ok=True)
        (root / document).write_bytes((REPOSITORY / document).read_bytes())
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\naddopts = "--basetemp=test/tmp"\n'
        'cache_dir = "test/tmp/.pytest_cache"\nunit_time_budget_seconds = "0.2"\n', encoding="utf-8")
    (tests / "unit" / "test_slow.py").write_text(
        "import time\n\ndef test_fast():\n    assert True\n\n"
        "def test_slow():\n    time.sleep(0.5)\n", encoding="utf-8")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("APPSEC_")}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/unit/test_slow.py"],
        cwd=root, env={**environment, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "1 failed, 1 passed" in result.stdout, result.stdout
    assert "time budget exceeded" in result.stdout and "unit default unit_time_budget_seconds" in result.stdout
