from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import subprocess
import sys
import time

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.observability import write_run_metrics
from appsec_review.storage import atomic_json


CHECKOUT = Path(__file__).resolve().parents[3]
LINUX = sys.platform == "linux"
MODULE = "tests.fixtures.process_lifecycle.worker"
_DEADLINE = ContextVar("process_acceptance_deadline", default=None)


def remaining(timeout):
    deadline = _DEADLINE.get()
    return timeout if deadline is None else min(timeout, max(0, deadline - time.monotonic()))


def wait_for(predicate, *, timeout=15, description="readiness barrier", bounded=True, child=None):
    deadline = time.monotonic() + (remaining(timeout) if bounded else timeout)
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        if child is not None and child.poll() is not None:
            raise AssertionError(
                f"owned child exited {child.returncode} before {description}\n"
                + child.error_path.read_text(encoding="utf-8")[-10000:])
        time.sleep(0.02)
    raise TimeoutError(f"timed out waiting for {description}")


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def working_directory(root):
    # CreateProcess rejects cwd over MAX_PATH even when Python can access the directory.
    return Path(os.environ.get("APPSEC_ACCEPTANCE_ROOT", root))


@contextmanager
def case(name, *, deadline_seconds=60):
    if type(deadline_seconds) is not int or deadline_seconds not in {60, 120}:
        raise ValueError("process cases require an explicit 60s or 120s budget")
    outer = os.environ.get("APPSEC_ACCEPTANCE_ROOT")
    parent = Path(outer).resolve() if outer else CHECKOUT
    if outer and not parent.is_relative_to(CHECKOUT / "test" / "tmp"):
        raise ValueError("outer acceptance workspace must belong to this checkout's test/tmp")
    workspace = LaneWorkspace.create(parent, "process-lifecycle")
    started = time.monotonic()
    deadline_token = _DEADLINE.set(started + deadline_seconds - 5)
    status = "FAILED"
    workspace.emit("ACCEPTANCE_CASE_STARTED", case=name, deadline_seconds=deadline_seconds)
    try:
        with workspace.span(name):
            yield workspace
        status = "SUCCEEDED"
    finally:
        _DEADLINE.reset(deadline_token)
        elapsed = time.monotonic() - started
        commit = os.environ.get("APPSEC_ACCEPTANCE_TESTED_COMMIT")
        if not outer:
            commit = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=CHECKOUT, capture_output=True, text=True,
                check=True, timeout=5).stdout.strip()
        atomic_json(workspace.root / "measurement.json", {
            "case": name, "status": status, "elapsed_seconds": elapsed,
            "deadline_seconds": deadline_seconds, "tested_commit": commit,
            "supervisor_workspace": outer,
            "commit_unavailable_reason": None if commit else "identity_recorded_by_outer_supervisor",
            "platform": sys.platform, "pid": os.getpid(),
            "fixture_sha256": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(Path(__file__).parent.iterdir())
                if path.suffix in {".py", ".cs", ".ps1"}},
        })
        workspace.emit("ACCEPTANCE_CASE_COMPLETED", case=name, status=status,
                       elapsed_seconds=elapsed)
        write_run_metrics(workspace.driver_root)
        print(f"\n{name}: {elapsed:.3f}s artifacts={workspace.root}", flush=True)
        assert elapsed < deadline_seconds, f"{name} exceeded its {deadline_seconds}s budget including cleanup"


def prepare(workspace, name="checkout"):
    root = workspace.root / name
    root.mkdir()
    source = (CHECKOUT / "appsec-review.toml").read_text(encoding="utf-8")
    source = source.replace('runs_dir = "runs"', f"runs_dir = {json.dumps(str(workspace.runs_dir))}", 1)
    source = source.replace('metadata_dir = "runs/metadata"',
                            f"metadata_dir = {json.dumps(str(workspace.runs_dir / 'metadata'))}", 1)
    # Opaque operator release IDs permit genuine runner reuse without scanning installed payloads.
    source = source.replace("[review_policy.releases]", '[review_policy.releases]\nplatform = "acceptance-v1"\nvalidation = "acceptance-v1"', 1)
    source = source.replace("max_concurrent = 8", "max_concurrent = 2", 1)
    source += """
[jobs.job_fixture]
name = "fixture"
workers = 2
[jobs.job_fixture.steps.work]
workers = 2
[jobs.job_fixture.steps.work.tasks.first]
[jobs.job_fixture.steps.work.tasks.second]
[jobs.job_fixture.steps.work.tasks.third]
"""
    (root / "appsec-review.toml").write_text(source, encoding="utf-8")
    shutil.copytree(CHECKOUT / "profiles", root / "profiles")
    overlay = root / "test" / "acceptance" / "capacity.toml"
    overlay.parent.mkdir(parents=True)
    overlay.write_text(
        "[orchestration.dagster.pools]\napplication = 1\n", encoding="utf-8")
    target = root / "target"
    target.mkdir()
    (target / "main.py").write_text("answer = 42\n", encoding="utf-8")
    return root


class _WindowsJob:
    """Contain the helper before its startup gate opens, including Dagster grandchildren."""

    def __init__(self, process):
        from ctypes import wintypes

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
        self.api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.api.OpenProcess.restype = wintypes.HANDLE
        self.api.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.BOOL)]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t),
                ("maximum", ctypes.c_size_t), ("active_limit", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
                ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]

        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.api.CloseHandle(self.handle)
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.api.CloseHandle(self.handle)
            raise ctypes.WinError(ctypes.get_last_error())

    def active(self):
        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in (
                "user", "kernel", "period_user", "period_kernel")] + [
                (name, ctypes.c_uint32) for name in ("faults", "total", "active", "terminated")]

        info = Accounting()
        if not self.api.QueryInformationJobObject(
                self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return info.active

    def close(self):
        try:
            if self.active():
                if not self.api.TerminateJobObject(self.handle, 137):
                    raise ctypes.WinError(ctypes.get_last_error())
                wait_for(lambda: self.active() == 0, timeout=5, bounded=False,
                         description="owned Windows job death")
        finally:
            self.api.CloseHandle(self.handle)

    def contains(self, pid):
        from ctypes import wintypes
        handle = self.api.OpenProcess(0x1000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            member = wintypes.BOOL()
            if not self.api.IsProcessInJob(handle, self.handle, ctypes.byref(member)):
                raise ctypes.WinError(ctypes.get_last_error())
            return bool(member.value)
        finally:
            self.api.CloseHandle(handle)


def owns(child, pid):
    if os.name == "nt":
        return child._acceptance_job.contains(pid)
    return os.getpgid(pid) == child.pid


def kill_owned(child):
    if os.name == "nt":
        job = child._acceptance_job
        if not job.api.TerminateJobObject(job.handle, 137):
            raise ctypes.WinError(ctypes.get_last_error())
        wait_for(lambda: job.active() == 0, timeout=5, bounded=False,
                 description="owned worker tree death")
    else:
        _linux_cleanup(child)
    subprocess.Popen.wait(child, timeout=5)


class _BoundedProcess(subprocess.Popen):
    def wait(self, timeout=None):
        return super().wait(timeout=remaining(55 if timeout is None else timeout))

    def communicate(self, input=None, timeout=None):
        return super().communicate(input, timeout=remaining(55 if timeout is None else timeout))


def _linux_cleanup(child):
    """Inspect only this helper's descendants and generation-bound fixture registrations."""
    from appsec_review.runtime.resources import process_identity

    owned = {child.pid: child.generation}
    for path in child.fixture_root.glob("*.json"):
        value = read(path)
        if isinstance(value, dict) and value.get("generation") and type(value.get("pid")) is int:
            owned[value["pid"]] = value["generation"]
    pending = list(owned)
    while pending:
        pid = pending.pop()
        if process_identity(pid) != owned[pid]:
            continue
        path = Path(f"/proc/{pid}/task/{pid}/children")
        try:
            children = [int(value) for value in path.read_text().split()]
        except FileNotFoundError:
            continue
        for descendant in children:
            if descendant not in owned:
                owned[descendant] = process_identity(descendant)
                pending.append(descendant)
    descriptors = []
    try:
        for pid, generation in owned.items():
            if generation is None or process_identity(pid) != generation:
                continue
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            if process_identity(pid) != generation:
                os.close(descriptor)
                continue
            descriptors.append(descriptor)
        for descriptor in reversed(descriptors):
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 5
        for descriptor in descriptors:
            assert select.select([descriptor], [], [], max(0, deadline - time.monotonic()))[0], \
                "owned Linux descendant death unconfirmed"
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@contextmanager
def process(root, action, *arguments, environment=None):
    if not LINUX and os.name != "nt":
        raise RuntimeError("lifecycle supervisor requires Windows jobs or Linux pidfds")
    if remaining(55) <= 0:
        raise TimeoutError("acceptance case exhausted its work deadline before process launch")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("APPSEC_", "DAGSTER_")) or key.startswith("APPSEC_ACCEPTANCE_")}
    env.update(PYTHONPATH=os.pathsep.join(filter(None, (
                   str(CHECKOUT / "src"), str(CHECKOUT), os.environ.get("PYTHONPATH")))),
               APPSEC_PROCESS_ROOT=str(root), PYTHONUNBUFFERED="1",
               NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
    env.update(environment or {})
    stdout = (root / f"{action}-{time.time_ns()}.stdout").open("w", encoding="utf-8")
    stderr = stdout.name.replace(".stdout", ".stderr")
    with stdout, open(stderr, "w", encoding="utf-8") as errors:
        child = _BoundedProcess(
            [sys.executable, "-m", MODULE, action, *map(str, arguments)],
            cwd=working_directory(root),
            stdin=subprocess.PIPE, stdout=stdout, stderr=errors, text=True,
            env=env, start_new_session=True)
        job = None
        try:
            child.error_path = Path(stderr)
            child.fixture_root = root
            if LINUX:
                from appsec_review.runtime.resources import process_identity
                child.generation = process_identity(child.pid)
            if os.name == "nt":
                job = _WindowsJob(child)
            child._acceptance_job = job
            child.stdin.write("start\n")
            child.stdin.flush()
            yield child
        finally:
            if job is not None:
                job.close()
            elif LINUX:
                _linux_cleanup(child)
            elif child.poll() is None:
                child.kill()
            subprocess.Popen.wait(child, timeout=5)
            child.stdin.close()
            atomic_json(root / f"cleanup-{child.pid}.json", {
                "pid": child.pid, "returncode": child.returncode,
                "confirmed": child.poll() is not None,
                "containment": "windows-job" if job else "generation-bound-linux-pidfds",
            })


def completed(root, action, *arguments, environment=None, timeout=45):
    with process(root, action, *arguments, environment=environment) as child:
        child.wait(timeout=timeout)
        if child.returncode:
            errors = sorted(root.glob(f"{action}-*.stderr"))[-1].read_text(encoding="utf-8")
            raise AssertionError(f"{action} exited {child.returncode}\n{errors[-10000:]}")
    return read(root / f"{action}.json")
