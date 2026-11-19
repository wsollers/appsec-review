"""Inert subprocess regressions for scanner stream retention; no Docker or native tools."""
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import tracemalloc

import pytest

from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, _default_runner
from appsec_review.runtime import execution_safety as safety
from tests.test_container_runtime import DIGEST, catalog
from tests.test_review_stop_policy import _running


def _scanner(tmp_path, monkeypatch, script):
    popen = subprocess.Popen

    def inert_docker(argv, **kwargs):
        if argv[:2] == ["docker", "run"]:
            code = script
        elif argv[:3] == ["docker", "rm", "--force"]:
            code = "pass"
        else:
            assert argv[:3] == ["docker", "container", "inspect"]
            code = f"import sys; sys.stderr.write('No such container: {argv[3]}'); sys.exit(1)"
        return popen([sys.executable, "-c", code], **kwargs)

    monkeypatch.setattr(subprocess, "Popen", inert_docker)
    monkeypatch.setattr(ContainerExecutor, "resolve_image", lambda self, tool: DIGEST)
    monkeypatch.setattr(ContainerExecutor, "_docker_bind_source", lambda self, path: path)
    target = tmp_path / "target"
    target.mkdir()
    executor = ContainerExecutor(catalog(tmp_path), tmp_path / "run")
    request = ExecutionRequest("tool-fixture", ("/bin/fixture",), target, tmp_path / "run" / "scratch")
    return executor, request


@pytest.mark.parametrize("guarded", [False, True])
def test_scanner_capture_bounds_memory_while_draining_both_streams(tmp_path, monkeypatch, guarded):
    script = (
        "import os; "
        "[(os.write(1, b'o'*65536), os.write(2, b'e'*65536)) for _ in range(128)]"
    )
    executor, request = _scanner(tmp_path, monkeypatch, script)
    with _running(tmp_path / "metadata") if guarded else nullcontext():
        with safety.operation("fixture.streams"):
            tracemalloc.start()
            try:
                result = executor.execute(request)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
    receipt = json.loads((executor.run_root / result.receipt_path).read_text())
    assert result.exit_code == 0 and not result.timed_out
    for stream, expected in (("stdout", b"o" * 8), ("stderr", b"e" * 8)):
        assert (executor.run_root / receipt[f"{stream}_path"]).read_bytes() == expected
        assert receipt[f"{stream}_truncated"] is True
        assert receipt[f"{stream}_sha256"] == hashlib.sha256(expected).hexdigest()
    assert peak < 4 * 1024 * 1024, f"capture materialized discarded output: peak={peak}"


@pytest.mark.parametrize("guarded", [False, True])
@pytest.mark.parametrize("out,err,code", [
    (b"", b"", 0),
    (b"exactly8", b"exactly8", 0),
    (b"overflow9", b"short", 7),
    (b"short", b"overflow9", 0),
], ids=["empty", "exact", "stdout-overflow", "stderr-overflow"])
def test_scanner_receipts_distinguish_complete_and_truncated_streams(
        tmp_path, monkeypatch, guarded, out, err, code):
    executor, request = _scanner(
        tmp_path, monkeypatch,
        f"import os; os.write(1, {out!r}); os.close(1); os.write(2, {err!r}); raise SystemExit({code})")
    request = replace(request, accepted_exit_codes=frozenset({0, 7}))
    with _running(tmp_path / "metadata") if guarded else nullcontext():
        result = executor.execute(request)
    receipt = json.loads((executor.run_root / result.receipt_path).read_text())
    assert result.exit_code == code and not result.timed_out
    for stream, expected in (("stdout", out), ("stderr", err)):
        assert (executor.run_root / receipt[f"{stream}_path"]).read_bytes() == expected[:8]
        assert receipt[f"{stream}_truncated"] is (len(expected) > 8)


def test_safety_failed_scanner_keeps_truncated_evidence_before_stopping(tmp_path, monkeypatch):
    executor, request = _scanner(
        tmp_path, monkeypatch, "import os; os.write(1, b'o'*65536); os.write(2, b'e'*65536); exit(137)")
    with _running(tmp_path / "metadata") as guardian:
        with pytest.raises(safety.ReviewStopped, match="execution failed"):
            executor.execute(request)
        assert guardian.state["first_error"]["action"] == "scanner.tool-fixture"
    receipt = json.loads((request.scratch_root / "execution.json").read_text())
    assert receipt["exit_code"] == 137 and receipt["oom_killed"] is True
    assert receipt["stdout_truncated"] is receipt["stderr_truncated"] is True
    assert (request.scratch_root / "raw" / "stdout.bin").read_bytes() == b"o" * 8
    assert (request.scratch_root / "raw" / "stderr.bin").read_bytes() == b"e" * 8


@pytest.mark.parametrize("guarded", [False, True])
def test_bounded_timeout_kills_process_group_and_keeps_stream_prefixes(tmp_path, guarded):
    script = (
        "import os,subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "os.write(1, b'o'*65536); os.write(2, b'e'*65536); time.sleep(30)"
    )
    started = time.monotonic()
    with _running(tmp_path / "metadata") if guarded else nullcontext():
        with safety.operation("fixture.timeout"):
            outcome = _default_runner([sys.executable, "-c", script], 1, output_bytes=8)
    assert outcome.exit_code is None and outcome.timed_out and not outcome.oom_killed
    assert outcome.stdout == b"o" * 9 and outcome.stderr == b"e" * 9
    assert time.monotonic() - started < 5


def test_safety_cancellation_still_registers_and_reaps_bounded_process(tmp_path):
    ready = tmp_path / "ready"
    script = (
        "import os,time; from pathlib import Path; "
        "os.write(1,b'o'*65536); os.write(2,b'e'*65536); "
        f"Path({str(ready)!r}).touch(); time.sleep(30)"
    )
    with _running(tmp_path / "metadata") as guardian:
        failures = []

        def stop():
            deadline = time.monotonic() + 3
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not ready.exists():
                failures.append("fixture did not start")
            guardian.fail("fixture cancellation", action="sibling")

        stopper = threading.Thread(target=stop)
        stopper.start()
        try:
            with pytest.raises(safety.ReviewStopped):
                with safety.operation("fixture.cancel"):
                    outcome = _default_runner([sys.executable, "-c", script], 5, output_bytes=8)
        finally:
            stopper.join(4)
        assert not stopper.is_alive() and not failures
        assert outcome.timed_out and outcome.exit_code is None
        assert outcome.stdout == b"o" * 9 and outcome.stderr == b"e" * 9
        events = [json.loads(line) for line in guardian.events.read_text().splitlines()]
        process = next(event["process"] for event in events if event["event"] == "PROCESS")
        assert process["process_identity"] and process["process_group"] == process["pid"]
        assert not Path(f"/proc/{process['pid']}").exists()
        assert guardian.state["first_error"]["action"] == "sibling"


@pytest.mark.parametrize("redirect_stderr", [False, True])
def test_safety_file_sinks_remain_complete_and_uncaptured(tmp_path, redirect_stderr):
    script = "import os; os.write(1,b'o'*65536); os.write(2,b'e'*65536)"
    with _running(tmp_path / "metadata"):
        with safety.operation("fixture.files"):
            with (tmp_path / "stdout").open("wb") as out, (tmp_path / "stderr").open("wb") as err:
                result = safety.run_process(
                    [sys.executable, "-c", script], 3, stdout=out,
                    stderr=err if redirect_stderr else None, output_bytes=8)
    assert result == (0, b"", b"" if redirect_stderr else b"e" * 9, False)
    assert (tmp_path / "stdout").read_bytes() == b"o" * 65536
    assert (tmp_path / "stderr").read_bytes() == (b"e" * 65536 if redirect_stderr else b"")


def test_safety_without_a_byte_budget_preserves_complete_caller_output(tmp_path):
    with _running(tmp_path / "metadata"):
        with safety.operation("fixture.complete"):
            result = safety.run_process(
                [sys.executable, "-c", "import os; os.write(1,b'o'*65536); os.write(2,b'e'*65536)"], 3)
    assert result == (0, b"o" * 65536, b"e" * 65536, False)


@pytest.mark.parametrize("guarded", [False, True])
def test_capture_read_failure_is_not_a_success_and_reaps_the_child(tmp_path, monkeypatch, guarded):
    from appsec_review.runtime import _process_capture
    popen, read = subprocess.Popen, _process_capture.os.read
    children = []

    def launch(*args, **kwargs):
        child = popen(*args, **kwargs)
        children.append(child)
        return child

    def broken_pipe(fd, count):
        if children and fd == children[0].stdout.fileno():
            raise OSError("fixture capture read failure")
        return read(fd, count)

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(_process_capture.os, "read", broken_pipe)
    with _running(tmp_path / "metadata") if guarded else nullcontext():
        with pytest.raises(safety.ReviewStopped if guarded else OSError, match="capture read failure"):
            with safety.operation("fixture.read"):
                _default_runner(
                    [sys.executable, "-c", "import time; print('ready',flush=True); time.sleep(30)"],
                    3, output_bytes=8)
    assert len(children) == 1 and children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed


@pytest.mark.parametrize("failure", [False, True])
def test_native_broker_result_or_failure_never_falls_through_to_local_capture(monkeypatch, failure):
    from appsec_review.container_runtime import native_client
    calls = []

    def native(argv, timeout):
        calls.append((argv, timeout))
        if failure:
            raise RuntimeError("native capture is truncated")
        return 7, b"native-out", b"native-err", False

    monkeypatch.setattr(native_client, "native_run", native)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("native fell through"))
    if failure:
        with pytest.raises(RuntimeError, match="native capture is truncated"):
            _default_runner(("docker", "run"), 3, output_bytes=8)
    else:
        result = _default_runner(("docker", "run"), 3, output_bytes=8)
        assert (result.exit_code, result.stdout, result.stderr, result.timed_out) == (
            7, b"native-out", b"native-err", False)
    assert calls == [(("docker", "run"), 3)]


def test_active_safety_still_refuses_uncommissioned_native_cancellation(tmp_path, monkeypatch):
    from appsec_review.config import native_dagster
    from appsec_review.container_runtime import native_client
    monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: True)
    monkeypatch.setattr(native_client, "native_run", lambda *a: pytest.fail("native bypassed safety"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("local bypassed safety"))
    with _running(tmp_path / "metadata"):
        with pytest.raises(safety.ReviewStopped, match="not commissioned"):
            _default_runner(("docker", "run"), 3, output_bytes=8)
