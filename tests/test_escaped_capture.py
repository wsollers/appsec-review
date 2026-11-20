"""Real held-pipe failures, with every pipe writer owned and reaped by this test."""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from appsec_review.container_runtime.executor import ContainerExecutor, ExecutionRequest, _default_runner
from appsec_review.container_runtime.measurement import TreeSitterInvocation
from appsec_review.runtime import execution_safety as safety, resources
from tests.test_container_runtime import DIGEST, catalog
from tests.test_review_stop_policy import _running


@contextmanager
def held_pipes(tmp_path, monkeypatch, *, on_started=lambda: None, err_bytes=b"e" * 16):
    """A separately sessioned, test-owned child holds the CLI's real pipe write ends."""
    popen = subprocess.Popen
    children = []
    state = {}
    ready = tmp_path / "holder-ready"

    def launch(argv, **kwargs):
        command = list(argv)
        if command[:2] == ["docker", "stop"] or command[:3] == ["docker", "rm", "--force"]:
            return popen([sys.executable, "-c", "pass"], **kwargs)
        if command[:3] == ["docker", "container", "inspect"]:
            return popen([sys.executable, "-c",
                          f"import sys; sys.stderr.write('No such container: {command[3]}'); sys.exit(1)"],
                         **kwargs)
        child = popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        children.append(child)
        state["cli"] = child
        # Duplicate only this known child's descriptors. The holder is our direct child, not an
        # orphan: its independent session reproduces an escaped descendant's pipe custody.
        with (os.fdopen(os.open(f"/proc/{child.pid}/fd/1", os.O_WRONLY), "wb") as out,
              os.fdopen(os.open(f"/proc/{child.pid}/fd/2", os.O_WRONLY), "wb") as err):
            holder = popen(
                [sys.executable, "-c",
                 "import os,time; from pathlib import Path; "
                 f"os.write(1,b'o'*16); os.write(2,{err_bytes!r}); "
                 f"Path({str(ready)!r}).write_text(str(os.getpid())); time.sleep(30)"],
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        children.append(holder)
        state["holder"] = holder
        deadline = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert ready.read_text() == str(holder.pid)
        assert os.getsid(holder.pid) == holder.pid != os.getsid(child.pid)
        on_started()
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    try:
        yield state
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            assert not Path(f"/proc/{child.pid}").exists()


def test_failed_post_cancel_drain_retains_prefixes_and_original_timeout(tmp_path, monkeypatch):
    argv = [sys.executable, "-c", "inert fixture CLI"]
    with held_pipes(tmp_path, monkeypatch) as state:
        with pytest.raises(subprocess.TimeoutExpired) as raised:
            _default_runner(argv, 1, output_bytes=8)
        error = raised.value
        assert (error.timeout, error.stdout, error.stderr) == (1, b"o" * 9, b"e" * 9)
        assert error.cmd == state["cli"].args
        assert isinstance(error.__cause__, subprocess.TimeoutExpired)
        assert error.__cause__.timeout == 5
        assert state["holder"].poll() is None
        assert state["cli"].poll() is not None
        assert state["cli"].stdout.closed and state["cli"].stderr.closed


@pytest.mark.parametrize("measured,external_stop", [(False, False), (True, False), (True, True)],
                         ids=["plain", "measured", "measured-cancel"])
def test_scanner_failed_drain_persists_incomplete_diagnostics_before_reraising(
        tmp_path, monkeypatch, measured, external_stop):
    base = catalog(tmp_path)
    tool = replace(base.tool("tool-fixture"), timeout_seconds=1,
                   tool_id="tool-tree-sitter" if measured else "tool-fixture",
                   executable="/opt/appsec/parser.py" if measured else "/bin/fixture")
    tools = replace(base, tools={tool.tool_id: tool})
    target, run = tmp_path / "target", tmp_path / "run"
    target.mkdir()
    context = (TreeSitterInvocation("a" * 32, "run", "job_source_history_analysis", "attempt_0001",
                                  "analyze.symbol_spans", "scope", "C", ()) if measured else None)
    request = ExecutionRequest(tool.tool_id, (tool.executable, "parse"), target, run / "scratch",
                               measurement=context)
    monkeypatch.setattr(ContainerExecutor, "resolve_image", lambda self, tool: DIGEST)
    monkeypatch.setattr(ContainerExecutor, "_docker_bind_source", lambda self, path: path)
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    with _running(tmp_path / "metadata") if external_stop else nullcontext() as guardian:
        def stop_if_requested():
            if external_stop:
                guardian.fail("fixture external cancellation", action="external")

        with held_pipes(tmp_path, monkeypatch, on_started=stop_if_requested, err_bytes=b"err") as state:
            error_type = safety.ReviewStopped if external_stop else subprocess.TimeoutExpired
            with pytest.raises(error_type) as raised:
                ContainerExecutor(tools, run).execute(request)
            assert state["holder"].poll() is None
            receipt = json.loads((request.scratch_root / "execution.json").read_text())
            assert receipt["schema"] == "appsec-review/container-execution-partial/1"
            assert receipt["error_type"] == error_type.__name__
            assert receipt["timed_out"] is (None if external_stop else True)
            if external_stop:
                assert receipt["capture_timeout_seconds"] == 5 and "timeout_seconds" not in receipt
                assert quarantined == ["local_descendant_death_unconfirmed"]
                assert guardian.state["first_error"]["action"] == "external"
            else:
                assert receipt["timeout_seconds"] == raised.value.timeout == 1
            assert receipt["cleanup"] == "UNCONFIRMED" and receipt["capture_complete"] is False
            for stream, expected, truncated in (("stdout", b"o" * 8, True), ("stderr", b"err", False)):
                assert (run / receipt[f"{stream}_path"]).read_bytes() == expected
                assert receipt[f"{stream}_sha256"] == hashlib.sha256(expected).hexdigest()
                assert receipt[f"{stream}_truncated"] is truncated
            if measured:
                metrics = json.loads((run / receipt["metrics_receipt"]["path"]).read_text())
                assert metrics["status"] == ("CANCELED" if external_stop else "FAILED")
                assert metrics["timed_out"] is (None if external_stop else True)
                assert metrics["error_type"] == error_type.__name__
                assert metrics["resource_accounting_complete"] is False


@pytest.mark.parametrize("external_stop", [False, True])
def test_guarded_failed_drain_keeps_quarantine_cancellation_and_error_diagnostics(
        tmp_path, monkeypatch, external_stop):
    quarantined = []
    monkeypatch.setattr(resources, "quarantine_resources", quarantined.append)
    with _running(tmp_path / "metadata") as guardian:
        def stop_if_requested():
            if external_stop:
                guardian.fail("fixture external cancellation", action="external")

        with held_pipes(tmp_path, monkeypatch, on_started=stop_if_requested) as state:
            with pytest.raises(safety.ReviewStopped, match="descendants remain unconfirmed") as raised:
                with safety.operation("fixture.held-pipes"):
                    _default_runner([sys.executable, "-c", "inert fixture CLI"],
                                    30 if external_stop else 1, output_bytes=8)
            assert quarantined == ["local_descendant_death_unconfirmed"]
            assert state["holder"].poll() is None
            cause = raised.value.__cause__
            assert isinstance(cause, subprocess.TimeoutExpired)
            assert cause.timeout == 5
            assert cause.stdout == b"o" * 9 and cause.stderr == b"e" * 9
            if external_stop:
                assert guardian.state["first_error"]["action"] == "external"
                assert guardian.state["first_error"]["reason"] == "fixture external cancellation"
