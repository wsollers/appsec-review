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

from appsec_review.acceptance.lanes import STATIC_REFERENCE_INPUTS, LaneWorkspace
from appsec_review.acceptance.staging import StageKind, stage_context
from appsec_review.storage import atomic_json, file_sha256


_workspace: LaneWorkspace | None = None
_outcome: Path | None = None
_collected: list[str] = []
_collection_errors: list[str] = []
_cases: list[dict] = []
_reports: dict[str, list] = {}
_prerequisites: list[dict] = []
_preflight: dict | None = None


def _guard(workspace: LaneWorkspace) -> None:
    """Catch accidental production access, writes and live transports in hermetic Python tests.

    This is a fail-closed regression guard, not a sandbox for hostile test code. Kernel-owned
    process cleanup and explicit inventory membership remain the execution boundary.
    """
    root = workspace.root.resolve()
    null_device = Path(os.devnull).resolve()
    protected = [workspace.repository / name for name in ("runs", "targets", "data")]
    protected = [path.resolve() for path in protected]
    pinned = json.loads(os.environ.get("APPSEC_ACCEPTANCE_STATIC_INPUTS", "{}"))
    if not isinstance(pinned, dict) or set(pinned) - set(STATIC_REFERENCE_INPUTS):
        raise pytest.UsageError("acceptance static reference selection is not allowed")
    read_only = set()
    for relative, expected in pinned.items():
        path = workspace.repository / relative
        if path.resolve() != path or not path.is_file() or file_sha256(path) != expected:
            raise pytest.UsageError(f"acceptance static reference identity changed: {relative}")
        read_only.add(path)

    context = stage_context()
    writable = [root]
    immutable = []
    if context is not None:
        from appsec_review.acceptance.custody import CustodyError, ordinary_path, snapshot_tree, verify_inputs, verify_seed

        ordinary_path(context.work_root)
        reporting = Path(os.environ["APPSEC_ACCEPTANCE_OUTCOME"]).parent
        ordinary_path(reporting)
        if reporting.parent not in {root / "processes", root / "p"}:
            raise pytest.UsageError("acceptance stage reporting is not process-owned")
        writable = [context.work_root, reporting, workspace.driver_root]
        if context.kind is StageKind.CONSUMER:
            manifest = verify_seed(context)
            if snapshot_tree(context.work_root) != manifest["tree"]:
                raise CustodyError("custody_consumer_copy_changed_before_execution")
            immutable = [context.seed_root, context.manifest_path]
        else:
            frozen_path = os.environ.get("APPSEC_ACCEPTANCE_FROZEN_INPUTS")
            if frozen_path is not None:
                path = Path(frozen_path)
                ordinary_path(path)
                if (path.parent != reporting
                        or file_sha256(path) != os.environ["APPSEC_ACCEPTANCE_FROZEN_INPUTS_SHA256"]):
                    raise pytest.UsageError("acceptance immutable input receipt changed")
                frozen = json.loads(path.read_text(encoding="utf-8"))
                verify_inputs(context, frozen)
                immutable = [path, *(context.work_root / value for value in frozen["read_only_paths"])]

    def descriptor_path(descriptor):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            import msvcrt

            api = ctypes.WinDLL("kernel32", use_last_error=True)
            api.GetFinalPathNameByHandleW.argtypes = [
                wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            api.GetFinalPathNameByHandleW.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            try:
                count = api.GetFinalPathNameByHandleW(
                    msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
            except OSError:
                return None
            if not count or count >= len(buffer):
                return None
            value = buffer.value
            if value.startswith("\\\\?\\UNC\\"):
                value = "\\\\" + value[8:]
            elif value.startswith("\\\\?\\"):
                value = value[4:]
            return Path(value).resolve()
        try:
            return Path(os.readlink(f"/proc/self/fd/{descriptor}")).resolve()
        except OSError:
            return None

    def path_of(value):
        if isinstance(value, int):
            return descriptor_path(value)
        if isinstance(value, (str, bytes, os.PathLike)):
            return Path(os.fsdecode(value)).resolve()
        return None

    def owned(value) -> bool:
        path = path_of(value)
        return path is not None and path.is_relative_to(root)

    def mutation(value, *, directory_fd=None, structural=False):
        if directory_fd not in (None, -1):
            parent = path_of(directory_fd)
            if parent is None:
                raise PermissionError("acceptance cannot resolve mutation directory descriptor")
            value = parent / os.fsdecode(value)
        path = path_of(value)
        if path == null_device:
            return
        if path is None or not any(path.is_relative_to(item) for item in writable):
            raise PermissionError("acceptance writes must stay in the stage-owned workspace")
        if any(path.is_relative_to(item) or (structural and item.is_relative_to(path))
               for item in immutable):
            raise PermissionError("acceptance sealed and prepared inputs are read-only")

    def audit(event, args):
        if event == "open":
            path = path_of(args[0])
            if path == null_device:
                return
            mode = args[1] or ""
            flags = args[2] or 0
            writing = (any(char in mode for char in "wax+")
                       or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if (path is not None and any(path.is_relative_to(item) for item in protected)
                    and (writing or path not in read_only)):
                raise PermissionError("acceptance forbids production and target access")
            if writing:
                mutation(args[0])
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.chown",
                       "os.truncate", "os.utime", "os.setxattr", "os.removexattr"}:
            directory_fd = None
            if event in {"os.remove", "os.rmdir"}:
                directory_fd = args[1]
            elif event in {"os.mkdir", "os.chmod"}:
                directory_fd = args[2]
            elif event in {"os.chown", "os.utime"}:
                directory_fd = args[3]
            mutation(args[0], directory_fd=directory_fd, structural=event != "os.mkdir")
        elif event in {"os.rename", "os.link", "os.symlink"}:
            if context is not None and event in {"os.link", "os.symlink"}:
                raise PermissionError("acceptance staged fixtures require ordinary independent files")
            mutation(args[0], directory_fd=args[2] if event == "os.rename" else None, structural=True)
            mutation(args[1], directory_fd=args[3] if event == "os.rename" else None, structural=True)
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
    global _workspace, _outcome, _preflight
    root = Path(os.environ["APPSEC_ACCEPTANCE_ROOT"]).resolve()
    owner = json.loads((root / "owner.json").read_text(encoding="utf-8"))
    _workspace = LaneWorkspace(Path(owner["repository"]), root, owner["lane"], owner["invocation_id"])
    if str(_workspace.runs_dir) != os.environ["APPSEC_ACCEPTANCE_RUNS_DIR"]:
        raise pytest.UsageError("acceptance fixture runs directory is not invocation-owned")
    _outcome = _workspace.require_owned_path(Path(os.environ["APPSEC_ACCEPTANCE_OUTCOME"]))
    began = time.monotonic()
    try:
        with _workspace.span("acceptance.preflight") as span:
            _guard(_workspace)
        _preflight = {"span_id": span.span_id, "duration_seconds": time.monotonic() - began}
    except (ValueError, OSError, pytest.UsageError) as error:
        _collection_errors.append(f"acceptance_preflight:{type(error).__name__}:{error}")
        atomic_json(_outcome, _payload(4, []))
        raise pytest.UsageError(f"acceptance preflight failed: {error}") from error
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
            "preflight": _preflight,
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
