"""Strict, machine-readable acceptance reporting; loaded only by the owned supervisor."""
from __future__ import annotations

import importlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shlex
import sys
import time

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.storage import atomic_json


_workspace: LaneWorkspace | None = None
_outcome: Path | None = None
_collected: list[str] = []
_collection_errors: list[str] = []
_cases: list[dict] = []
_reports: dict[str, list] = {}
_prerequisites: list[dict] = []


def _guard(workspace: LaneWorkspace) -> None:
    """Catch accidental production access, writes and live transports in hermetic Python tests.

    This is a fail-closed regression guard, not a sandbox for hostile test code. Kernel-owned
    process cleanup and explicit inventory membership remain the execution boundary.
    """
    root = workspace.root.resolve()
    null_device = Path(os.devnull).resolve()
    protected = [workspace.repository / name for name in ("runs", "targets", "data")]
    protected = [path.resolve() for path in protected]

    def path_of(value):
        if isinstance(value, (str, bytes, os.PathLike)):
            return Path(os.fsdecode(value)).resolve()
        return None

    def owned(value) -> bool:
        path = path_of(value)
        return path is None or path.is_relative_to(root)

    def audit(event, args):
        if event == "open":
            path = path_of(args[0])
            if path == null_device:
                return
            if path is not None and any(path.is_relative_to(item) for item in protected):
                raise PermissionError("acceptance forbids production and target access")
            mode = args[1] or ""
            flags = args[2] or 0
            if (any(char in mode for char in "wax+") or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
                    ) and not owned(args[0]):
                raise PermissionError("acceptance writes must stay in the invocation workspace")
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.truncate", "os.utime"}:
            if not owned(args[0]):
                raise PermissionError("acceptance mutation outside invocation workspace")
        elif event in {"os.rename", "os.link", "os.symlink"}:
            if not owned(args[0]) or not owned(args[1]):
                raise PermissionError("acceptance link or rename outside invocation workspace")
        elif event in {"os.listdir", "os.scandir", "os.chdir"}:
            path = path_of(args[0])
            if path and any(path.is_relative_to(item) for item in protected):
                raise PermissionError("acceptance forbids production and target access")
        elif event in {"socket.connect", "socket.bind"}:
            address = args[1]
            if isinstance(address, tuple):
                try:
                    loopback = ipaddress.ip_address(address[0]).is_loopback
                except ValueError:
                    loopback = address[0] == "localhost"
                if not loopback:
                    raise PermissionError("acceptance permits loopback transports only")
            elif isinstance(address, (str, bytes)) and not owned(address):
                raise PermissionError("acceptance socket must be invocation-owned")
        elif event == "subprocess.Popen":
            executable, argv, cwd, _ = args
            if executable is None:
                executable = shlex.split(argv, posix=False)[0].strip('"') if isinstance(argv, str) else argv[0]
            program = Path(os.fsdecode(executable)).resolve()
            local = program.is_relative_to(root)
            python = program == Path(sys.executable).resolve()
            # No production service commands, acquisition CLIs, or external inference.
            if not local and not python:
                raise PermissionError("acceptance executable must be the owned Python or an invocation fixture")
            if cwd is not None and not owned(cwd):
                raise PermissionError("acceptance child working directory must be invocation-owned")
        elif event in {"os.system", "os.exec", "os.posix_spawn"}:
            raise PermissionError("acceptance requires tracked subprocess execution")

    sys.addaudithook(audit)


def pytest_configure(config: pytest.Config) -> None:
    global _workspace, _outcome
    root = Path(os.environ["APPSEC_ACCEPTANCE_ROOT"]).resolve()
    owner = json.loads((root / "owner.json").read_text(encoding="utf-8"))
    _workspace = LaneWorkspace(Path(owner["repository"]), root, owner["lane"], owner["invocation_id"])
    if str(_workspace.runs_dir) != os.environ["APPSEC_ACCEPTANCE_RUNS_DIR"]:
        raise pytest.UsageError("acceptance fixture runs directory is not invocation-owned")
    _outcome = _workspace.require_owned_path(Path(os.environ["APPSEC_ACCEPTANCE_OUTCOME"]))
    _guard(_workspace)
    for requirement in json.loads(os.environ.get("APPSEC_ACCEPTANCE_PREREQUISITES", "[]")):
        if requirement in {"platform:linux", "platform:windows"}:
            available = sys.platform == "linux" if requirement == "platform:linux" else os.name == "nt"
            _prerequisites.append({"name": requirement, "available": available})
            continue
        if not requirement.startswith("python:"):
            _prerequisites.append({"name": requirement, "available": False})
            continue
        try:
            importlib.import_module(requirement.removeprefix("python:"))
            _prerequisites.append({"name": requirement, "available": True})
        except Exception as error:
            _prerequisites.append({"name": requirement, "available": False, "reason": type(error).__name__})
    if any(not item["available"] for item in _prerequisites):
        # Persist an explicit failure even when configuration aborts before sessionfinish.
        atomic_json(_outcome, {"collected": [], "cases": [], "prerequisites": _prerequisites,
                               "collection_errors": ["required_prerequisite_unavailable"], "exit_code": 4})
        raise pytest.UsageError("required acceptance prerequisite unavailable")


def pytest_collectreport(report) -> None:
    if report.failed or report.skipped:
        _collection_errors.append(report.nodeid or "<collection>")


def pytest_collection_finish(session: pytest.Session) -> None:
    _collected.extend(item.nodeid for item in session.items)
    for item in session.items:
        if item.get_closest_marker("requires_target"):
            _collection_errors.append(f"target_checkout_forbidden:{item.nodeid}")


def pytest_runtest_logreport(report) -> None:
    _reports.setdefault(report.nodeid, []).append(report)


def _payload(exit_code: int | None, cases: list[dict]) -> dict:
    return {"schema": "appsec-review/acceptance-pytest/1",
            "collected": _collected, "collection_errors": _collection_errors,
            "prerequisites": _prerequisites, "cases": cases, "exit_code": exit_code,
            "versions": {"python": platform.python_version(), "pytest": pytest.__version__}}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item: pytest.Item):
    assert _workspace is not None
    started = time.monotonic()
    with _workspace.span("acceptance.case") as span:
        _workspace.emit("ACCEPTANCE_CASE_STARTED", node=item.nodeid, span_id=span.span_id)
        atomic_json(_outcome, _payload(None, [*_cases, {
            "node": item.nodeid, "outcome": "running", "span_id": span.span_id,
            "duration_seconds": None, "resources": {
                "cpu_user_seconds": None, "cpu_system_seconds": None,
                "child_cpu_seconds": None, "peak_rss_bytes": None,
                "logical_read_bytes": None, "logical_write_bytes": None,
                "physical_read_bytes": None, "physical_write_bytes": None,
                "unavailable_reason": "interrupted_before_operation_span_completion"},
        }]))
        yield
        reports = _reports.get(item.nodeid, [])
        if any(report.failed for report in reports):
            outcome = "failed"
        elif any(getattr(report, "wasxfail", None) for report in reports):
            outcome = "xpass" if any(report.when == "call" and report.passed for report in reports) else "xfail"
        elif any(report.skipped for report in reports):
            outcome = "skipped"
        elif len(reports) == 3 and all(report.passed for report in reports):
            outcome = "passed"
        else:
            outcome = "incomplete"
        if outcome != "passed":
            span.status = "FAILED"
        record = {"node": item.nodeid, "outcome": outcome, "span_id": span.span_id,
                  "duration_seconds": time.monotonic() - started,
                  "stages": [{"when": report.when, "outcome": report.outcome,
                              "duration_seconds": report.duration} for report in reports]}
        _workspace.emit("ACCEPTANCE_CASE_COMPLETED", **record)
    # These are the production OperationSpan measurements, not inferred zero-valued stand-ins.
    records, torn = _workspace.pipeline.read()
    measurements = [row["details"] for row in records if row["event_type"] == "OPERATION_COMPLETED"
                    and row["details"].get("span_id") == span.span_id]
    record["resources"] = measurements[-1]["resources"] if measurements else {
        "unavailable_reason": "operation_span_measurement_missing"}
    if not measurements:
        record["outcome"] = "incomplete"
    _cases.append(record)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    assert _outcome is not None
    collecting = session.config.option.collectonly
    complete = bool(_collected) and not _collection_errors and len(_collected) == len(set(_collected))
    if not collecting:
        complete = complete and len(_cases) == len(_collected) and all(
            item["outcome"] == "passed" for item in _cases)
    if not complete or exitstatus:
        session.exitstatus = int(exitstatus) or 1
    atomic_json(_outcome, _payload(int(session.exitstatus), _cases))
