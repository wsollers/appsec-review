"""Named pytest suites with a unique base temp, a log file and known-failure accounting."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import signal
import subprocess
import sys
import time


KNOWN_FAILURES = Path("scripts") / "known-failures.txt"
SUMMARY = re.compile(r"(\d+) (failed|passed|skipped|error|errors|xfailed|xpassed|deselected)")
FAILURE_LINE = re.compile(r"^(FAILED|ERROR) (\S+)")

# Suites are lists of pytest arguments, relative to the repository root. A glob that matches nothing
# is dropped, so a suite never names a file this checkout lacks.
OFFLINE_IGNORES = ("--ignore=tests/live", "--ignore-glob=tests/test_live_*.py")
SUITES: dict[str, tuple[str, ...]] = {
    "fast": ("tests", *OFFLINE_IGNORES, "--ignore=tests/integration"),
    "all-offline": ("tests", *OFFLINE_IGNORES),
    "review": ("tests/review",),
    "orchestration": ("tests/orchestration", "tests/test_dagster_*.py", "tests/test_job_runtime.py",
                      "tests/test_runtime_launch.py", "tests/test_wave1_resume.py", "tests/test_job_selection.py",
                      "tests/test_operator_scripts.py"),
    "docs": ("tests/test_documentation.py", "tests/test_repository_hygiene.py", "tests/test_docs_sync.py",
             "tests/test_skill_separation.py"),
    "graph": ("tests/graph", "tests/test_code_graph_index_job.py"),
    "live": ("tests/live", "tests/test_live_*.py", "tests/integration"),
}
LIVE_WARNING = ("WARNING: the live suite needs Docker, the CodeQL/tool images, local target checkouts and model access. "
                "It can take hours, uses real tools and may spend model budget. Do not run it while another session "
                "uses the shared Dagster stack or Docker daemon.")


@dataclass
class Result:
    failures: list[str]
    known: list[str]
    counts: dict[str, int]


def load_known(root: Path) -> dict[str, str]:
    """Node ids and reasons from ``scripts/known-failures.txt`` (``<node id> | <reason>`` per line)."""
    path = root / KNOWN_FAILURES
    known: dict[str, str] = {}
    if not path.is_file():
        return known
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            node, _, reason = line.partition("|")
            known[node.strip()] = reason.strip() or "no reason recorded"
    return known


def suite_arguments(root: Path, suite: str) -> list[str]:
    arguments: list[str] = []
    for item in SUITES[suite]:
        if item.startswith("-"):
            arguments.append(item)
        elif any(char in item for char in "*?["):
            arguments.extend(sorted(str(path.relative_to(root).as_posix()) for path in root.glob(item)))
        elif (root / item).exists():
            arguments.append(item)
    return arguments


def find_python(root: Path) -> tuple[str, dict[str, str]]:
    """The interpreter and extra environment: the checkout's venv, else the main checkout's with PYTHONPATH=src."""
    override = os.environ.get("APPSEC_PYTHON")
    if override:
        return override, {"PYTHONPATH": str(root / "src")}
    candidates = [root / ".venv" / "bin" / "python", root / ".venv" / "Scripts" / "python.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate), {}
    common = subprocess.run(["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            capture_output=True, text=True, check=False).stdout.strip()
    if common:
        main = Path(common).parent
        for candidate in (main / ".venv" / "bin" / "python", main / ".venv" / "Scripts" / "python.exe"):
            if candidate.is_file():
                return str(candidate), {"PYTHONPATH": str(root / "src")}
    return sys.executable, {"PYTHONPATH": str(root / "src")}


def has_xdist(python: str, environment: dict[str, str]) -> bool:
    probe = subprocess.run([python, "-c", "import xdist"], capture_output=True, check=False,
                           env={**os.environ, **environment})
    return probe.returncode == 0


def build_command(root: Path, args: argparse.Namespace, python: str, stamp: str, parallel: bool) -> list[str]:
    name = "custom" if args.extra else args.suite
    command = [python, "-m", "pytest", "-q", "-rfE", f"--basetemp=test/tmp/tests-{name}-{stamp}"]
    if parallel:
        command += ["-n", "auto"]
    command += list(args.extra) if args.extra else suite_arguments(root, args.suite)
    return command


def parse_output(text: str, known: dict[str, str]) -> Result:
    failures, recognized = [], []
    for line in text.splitlines():
        match = FAILURE_LINE.match(line)
        if match and match.group(2) not in failures and match.group(2) not in recognized:
            (recognized if match.group(2) in known else failures).append(match.group(2))
    counts: dict[str, int] = {}
    summary = [line for line in text.splitlines() if re.search(r"\d+ (passed|failed|skipped|error)", line)]
    for number, word in SUMMARY.findall(summary[-1] if summary else ""):
        counts["error" if word == "errors" else word] = int(number)
    return Result(failures, recognized, counts)


def run(args: argparse.Namespace, root: Path) -> int:
    root = root.resolve()
    if getattr(args, "acceptance", None):
        return run_acceptance(args, root)
    if any(getattr(args, name, None) is not None for name in ("workers", "deadline", "case_deadline")):
        print("error: --workers/--deadline/--case-deadline require --acceptance", file=sys.stderr)
        return 2
    if args.extra and args.suite:
        print("error: give a suite name or arguments after --, not both", file=sys.stderr, flush=True)
        return 2
    args.suite = args.suite or "fast"
    if not args.extra and args.suite not in SUITES:
        print(f"error: unknown suite {args.suite!r}; choose from {', '.join(SUITES)} or pass arguments after --", file=sys.stderr, flush=True)
        return 2
    python, environment = find_python(root)
    parallel = False
    if args.parallel:
        parallel = has_xdist(python, environment)
        if not parallel:
            print("warning: pytest-xdist is not installed in that environment; running serially", flush=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = "custom" if args.extra else args.suite
    command = build_command(root, args, python, stamp, parallel)
    log = root / "test" / "tmp" / "logs" / f"tests-{name}-{stamp}.log"
    if args.suite == "live" and not args.extra:
        print(LIVE_WARNING, flush=True)
    print(f"run-tests: suite {name}; python {python}" + (f"; PYTHONPATH={environment['PYTHONPATH']}" if environment else ""), flush=True)
    print("+ " + shlex.join(command), flush=True)
    print(f"log: {log}", flush=True)
    if args.dry_run:
        print("dry run: not executed", flush=True)
        return 0
    log.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **environment}
    if args.background:
        stream = log.open("wb")
        process = subprocess.Popen(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=(os.name != "nt"))
        print(f"started in the background (pid {process.pid}); follow with: tail -f {shlex.quote(str(log))}", flush=True)
        print(f"when it ends, the log's last lines hold pytest's summary; known failures are listed in {KNOWN_FAILURES.as_posix()}",
              flush=True)
        return 0
    with log.open("w", encoding="utf-8", errors="replace") as stream:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, text=True, errors="replace")
        assert process.stdout is not None
        for line in process.stdout:
            stream.write(line)
            sys.stdout.write(line)
            sys.stdout.flush()
        code = process.wait()
    return report(log.read_text(encoding="utf-8", errors="replace"), load_known(root), code, args.strict)


def report(text: str, known: dict[str, str], code: int, strict: bool) -> int:
    result = parse_output(text, known)
    counts = ", ".join(f"{value} {key}" for key, value in result.counts.items()) or "no summary line found"
    print(f"\nresult: {counts}", flush=True)
    print(f"{len(result.failures) + len(result.known)} failures, {len(result.known)} known", flush=True)
    for node in result.known:
        print(f"  known   {node}  ({known[node]})", flush=True)
    for node in result.failures:
        print(f"  NEW     {node}", flush=True)
    if code == 0:
        return 0
    if code == 1 and not result.failures and result.known and not strict:
        print("only known failures remain (use --strict to fail on them too)", flush=True)
        return 0
    return code if code else 1


def register(commands, add, root: Path) -> None:
    sub = add("run-tests", lambda args: run(args, root), "Run a named pytest suite with a unique base temp and a log.",
              dry_run=True, url=False)
    sub.add_argument("suite", nargs="?", metavar="SUITE", help=f"one of {', '.join(SUITES)} (default fast)")
    sub.add_argument("--background", action="store_true", help="start detached; print the log path and how to follow it")
    sub.add_argument("--parallel", action="store_true", help="use pytest-xdist (-n auto) when it is installed")
    sub.add_argument("--strict", action="store_true", help="fail even when only known failures remain")
    sub.add_argument("--acceptance", metavar="PROFILE",
                     help="run an explicit acceptance inventory profile (quick); always strict and isolated")
    sub.add_argument("--workers", type=int, choices=(1, 2), help="acceptance workers (default 1; never -n auto)")
    sub.add_argument("--deadline", type=int, help="lower the acceptance suite hard deadline, including cleanup")
    sub.add_argument("--case-deadline", type=int, help="lower the acceptance per-case hard deadline, including cleanup")
    sub.set_defaults(extra=[])
    sub.epilog += "\nInstead of a suite, pass pytest arguments after --, for example: run-tests.sh -- tests/test_config.py -k overlay"


# The gate keeps the process-group leader alive until the supervisor has inspected and
# terminated its entire group. On Windows the gate is opened only after Job Object assignment.
_GATE = """
import json, os, pathlib, subprocess, sys, time
if sys.platform == "linux":
    import ctypes
    if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError("acceptance child subreaper could not be established")
path = pathlib.Path(sys.argv[1])
path.with_name("gate.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
assert sys.stdin.readline() == "go\\n"
code = subprocess.call([sys.argv[2], "-B", "-m", "pytest", *sys.argv[3:]],
                       stdin=subprocess.DEVNULL)
sys.stdout.flush()
sys.stderr.flush()
path.write_text(json.dumps({"exit_code": int(code)}), encoding="utf-8")
while True:
    time.sleep(3600)
"""
_CLEANUP_SECONDS = 3.0
INVENTORY = Path("tests") / "acceptance_inventory.json"


class _WindowsJob:
    """A private kernel-owned tree; no PID/name lookup can select another session."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [("user", ctypes.c_int64), ("process_user", ctypes.c_int64),
                        ("flags", w.DWORD), ("minimum", ctypes.c_size_t),
                        ("maximum", ctypes.c_size_t), ("active_limit", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
                        ("scheduling", w.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]

        class Limits(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                        ("peak_job", ctypes.c_size_t)]

        class Accounting(ctypes.Structure):
            _fields_ = [(name, ctypes.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")] + [
                (name, w.DWORD) for name in ("faults", "total", "active", "terminated")]

        self.ctypes, self.Accounting = ctypes, Accounting
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.api.CreateJobObjectW.restype = w.HANDLE
        self.api.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.api.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self.api.QueryInformationJobObject.argtypes = [
            w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.c_void_p]
        self.api.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Limits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; breakaway is not allowed.
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process: subprocess.Popen) -> None:
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def count(self) -> int:
        value = self.Accounting()
        if not self.api.QueryInformationJobObject(
                self.handle, 1, self.ctypes.byref(value), self.ctypes.sizeof(value), None):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        return value.active

    def terminate(self) -> None:
        if not self.api.TerminateJobObject(self.handle, 1):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def _linux_descendants(pid: int) -> dict[int, str]:
    from appsec_review.runtime.resources import process_identity

    parents = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            if fields[0] != "Z":
                parents[int(path.parent.name)] = int(fields[1])
        except (FileNotFoundError, ProcessLookupError):
            pass
    descendants = {pid}
    while True:
        expanded = descendants | {child for child, parent in parents.items() if parent in descendants}
        if expanded == descendants:
            break
        descendants = expanded
    return {child: identity for child in descendants
            if child in parents and (identity := process_identity(child)) is not None}


def _stop_linux_tree(process: subprocess.Popen, generation: str, deadline: float) -> tuple[int, int]:
    """Freeze the owned subreaper's tree before killing, including children that called setsid."""
    from appsec_review.runtime.resources import process_identity

    if process_identity(process.pid) != generation:
        raise OSError("owned subreaper identity changed; descendant cleanup cannot be confirmed")
    stopped = {}
    while time.monotonic() < deadline:
        members = _linux_descendants(process.pid)
        new = {pid: token for pid, token in members.items() if pid not in stopped}
        for pid, token in new.items():
            if process_identity(pid) == token:
                try:
                    os.kill(pid, signal.SIGSTOP)
                except ProcessLookupError:
                    pass
        stopped.update(new)
        if not new:
            break
    for pid, token in stopped.items():
        if pid != process.pid and process_identity(pid) == token:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Keep the subreaper alive while checking its adopted children, then kill its verified handle.
    while len(_linux_descendants(process.pid)) > 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    remaining = max(0, len(_linux_descendants(process.pid)) - 1)
    process.kill()
    return len(stopped), remaining


def acceptance_environment(workspace) -> dict[str, str]:
    """Do not inherit deployment selection, credentials, SDK endpoints or pytest overrides."""
    from appsec_review.acceptance.lanes import STATIC_REFERENCE_INPUTS
    from appsec_review.storage import file_sha256

    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE",
               "LANG", "LC_ALL", "TZ", "NUMBER_OF_PROCESSORS"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    home = workspace.root / "home"
    home.mkdir(exist_ok=True)
    temporary = workspace.root / "temporary"
    temporary.mkdir(exist_ok=True)
    dagster = workspace.root / "dagster"
    dagster.mkdir(exist_ok=True)
    environment.update(workspace.environment())
    references = {}
    for relative in STATIC_REFERENCE_INPUTS:
        path = workspace.repository / relative
        if path.resolve() != path or not path.is_file():
            raise ValueError(f"acceptance static reference is missing or redirected: {relative}")
        references[relative] = file_sha256(path)
    environment.update({
        "APPSEC_ACCEPTANCE_STATIC_INPUTS": json.dumps(references, sort_keys=True),
        "HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home),
        "LOCALAPPDATA": str(home), "TEMP": str(temporary), "TMP": str(temporary),
        "TMPDIR": str(temporary), "DAGSTER_HOME": str(dagster),
        "PYTHONPATH": os.pathsep.join((str(workspace.repository / "src"), str(workspace.repository))),
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    return environment


def supervised_pytest(python: str, arguments: list[str], workspace, key: str,
                      *, deadline: float, prerequisites: tuple[str, ...] = (),
                      tested_commit: str | None = None) -> dict:
    """Run collection or exactly one case under a hard wall-clock budget with owned cleanup."""
    from appsec_review.storage import atomic_json
    from appsec_review.runtime.resources import process_identity

    started = time.monotonic()
    directory = workspace.require_owned_path(workspace.root / "processes" / key)
    directory.mkdir(parents=True, exist_ok=False)
    outcome_path = directory / "pytest.json"
    exit_path = directory / "exit.json"
    environment = acceptance_environment(workspace)
    if tested_commit is not None:
        environment["APPSEC_ACCEPTANCE_TESTED_COMMIT"] = tested_commit
    environment["APPSEC_ACCEPTANCE_OUTCOME"] = str(outcome_path)
    environment["APPSEC_ACCEPTANCE_PREREQUISITES"] = json.dumps(prerequisites)
    # Windows venv launchers can spawn their real interpreter before assignment. Bootstrap
    # with the base executable (stdlib only), then open the owned venv worker inside the job.
    bootstrap = sys._base_executable if os.name == "nt" else python
    command = [bootstrap, "-B", "-c", _GATE, str(exit_path), python, "-p", "tests.acceptance_plugin",
               "-q", "--strict-markers", "-o", "addopts=",
               "-o", f"cache_dir={directory / 'cache'}",
               f"--basetemp={directory / 'temporary'}", *arguments]
    result = {"command": command, "log": str(directory / "pytest.log"), "outcome": "error",
              "duration_seconds": 0.0, "cleanup": {"confirmed": True, "started": False},
              "static_input_identities": json.loads(environment["APPSEC_ACCEPTANCE_STATIC_INPUTS"]),
              "pytest": None, "exit_code": None}
    # Reserve cleanup inside both the per-case and suite cap, not after them.
    execution_end = deadline - _CLEANUP_SECONDS
    if time.monotonic() >= execution_end:
        result["outcome"] = "not_executed"
        result["reason"] = "deadline_has_no_execution_budget"
        return result
    process = job = None
    assigned = False
    generation = None
    interpreter_processes = 1
    try:
        with (directory / "pytest.log").open("wb") as stream:
            if os.name == "nt":
                job = _WindowsJob()
            elif sys.platform != "linux":
                raise RuntimeError("owned process-tree supervision requires Windows or Linux")
            process = subprocess.Popen(command, cwd=workspace.repository, env=environment,
                                       stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT,
                                       start_new_session=(os.name != "nt"))
            result["cleanup"] = {"confirmed": False, "started": True, "pid": process.pid,
                                 "boundary": "windows_job" if job else "linux_process_group"}
            if job:
                job.assign(process)
                assigned = True
            else:
                generation = process_identity(process.pid)
                if generation is None or os.getpgid(process.pid) != process.pid:
                    raise RuntimeError("owned process group identity could not be established")
            while not (directory / "gate.json").is_file() and time.monotonic() < execution_end:
                if process.poll() is not None:
                    raise RuntimeError("interpreter gate exited before opening")
                time.sleep(0.01)
            if not (directory / "gate.json").is_file():
                raise TimeoutError("interpreter gate startup exceeded deadline")
            if job and assigned:
                interpreter_processes = job.count()
            result["cleanup"]["interpreter_processes"] = interpreter_processes
            process.stdin.write(b"go\n")
            process.stdin.flush()
            while time.monotonic() < execution_end:
                if exit_path.is_file():
                    try:
                        result["exit_code"] = json.loads(exit_path.read_text(encoding="utf-8"))["exit_code"]
                    except (ValueError, KeyError):
                        time.sleep(0.01)
                        continue
                    result["outcome"] = "completed"
                    break
                if process.poll() is not None:
                    result["reason"] = "worker_exited_without_machine_readable_outcome"
                    break
                time.sleep(min(0.02, max(0, execution_end - time.monotonic())))
            else:
                result.update(outcome="timeout", reason="hard_deadline")
    except Exception as error:
        result.update(outcome="error", reason=f"supervisor_{type(error).__name__}")
    finally:
        if process is not None:
            cleanup_started = time.monotonic()
            try:
                if job:
                    before = job.count()
                    job.terminate()
                    while job.count() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    remaining = job.count()
                elif not job and generation is not None and process_identity(process.pid) == generation:
                    before, remaining = _stop_linux_tree(process, generation, deadline)
                else:
                    # The gate has not opened when ownership setup fails. Kill only its Popen handle.
                    before, remaining = 1, 0
                    if generation is not None:
                        remaining = -1
                        result["cleanup"]["reason"] = "subreaper_identity_lost"
                    if process.poll() is None:
                        process.kill()
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                result["cleanup"].update(confirmed=remaining == 0, remaining_processes=remaining,
                                         observed_processes=before)
                if result["outcome"] == "completed" and before > interpreter_processes:
                    result.update(outcome="error", reason="test_left_descendants_running")
            except (OSError, subprocess.TimeoutExpired):
                result["cleanup"].update(confirmed=False, reason="process_death_unconfirmed")
            finally:
                if process.stdin:
                    process.stdin.close()
                result["cleanup"]["duration_seconds"] = time.monotonic() - cleanup_started
        if job:
            job.close()
    if outcome_path.is_file():
        try:
            result["pytest"] = json.loads(outcome_path.read_text(encoding="utf-8"))
        except ValueError:
            result.update(outcome="error", reason="invalid_pytest_outcome")
    result["duration_seconds"] = time.monotonic() - started
    for case in (result["pytest"] or {}).get("cases", []):
        if case["outcome"] == "running":
            case.update(outcome="interrupted", duration_seconds=result["duration_seconds"],
                        duration_scope="supervised_process_including_setup_and_cleanup")
    if time.monotonic() > deadline:
        result.update(outcome="timeout", reason="deadline_including_cleanup_exceeded")
    atomic_json(directory / "supervisor.json", result)
    return result


def _matches(selection: str, node: str) -> bool:
    return node == selection or node.startswith(selection + "::") or node.startswith(selection + "[")


def run_acceptance(args: argparse.Namespace, root: Path) -> int:
    from appsec_review.acceptance.lanes import LaneSpec, LaneTier, LaneWorkspace
    from appsec_review.storage import atomic_json, file_sha256

    if args.suite or args.extra or args.parallel or args.background:
        print("error: acceptance forbids legacy suites, arbitrary pytest arguments, --parallel and --background",
              file=sys.stderr)
        return 2
    try:
        inventory_bytes = (root / INVENTORY).read_bytes()
        inventory = json.loads(inventory_bytes)
        profile = inventory["profiles"][args.acceptance]
    except (OSError, ValueError, KeyError):
        print(f"error: unknown or invalid acceptance profile {args.acceptance!r}", file=sys.stderr)
        return 2
    selected = profile.get("obligations", [])
    entries = {entry["id"]: entry for entry in inventory["obligations"]}
    try:
        nodes = tuple(node for obligation in selected for node in entries[obligation]["nodes"])
        maximum = profile["deadline_seconds"]
        case_maximum = profile["case_deadline_seconds"]
        total = args.deadline if args.deadline is not None else maximum
        per_case = args.case_deadline if args.case_deadline is not None else min(case_maximum, total)
        if not _CLEANUP_SECONDS < per_case <= case_maximum or not per_case <= total <= maximum:
            raise ValueError("deadlines may only lower profile caps and must leave execution plus cleanup time")
        # Deferred profiles deliberately have no executable selections.
        spec = LaneSpec(args.acceptance, nodes or ("unimplemented",), LaneTier(profile["tier"]),
                        total, per_case, args.workers or 1, tuple(profile.get("prerequisites", ())))
    except (ValueError, KeyError, TypeError) as error:
        print(f"error: invalid acceptance selection: {error}", file=sys.stderr)
        return 2
    if args.dry_run:
        print(json.dumps({"profile": spec.name, "nodes": list(nodes), "workers": spec.workers,
                          "deadline_seconds": total, "case_deadline_seconds": per_case,
                          "strict": True, "implemented": bool(nodes)}, sort_keys=True))
        return 0
    started = time.monotonic()
    suite_end = started + total
    workspace = LaneWorkspace.create(root, spec.name)
    result = {
        "schema": "appsec-review/acceptance-result/1", "profile": spec.name,
        "invocation_id": workspace.invocation_id, "commit": None,
        "artifacts_root": str(workspace.root), "runs_dir": str(workspace.runs_dir),
        "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "versions": {"driver_python": platform.python_version()},
        "source_identities": {},
        "budget": {"suite_seconds": total, "case_seconds": per_case,
                   "cleanup_reserve_seconds": _CLEANUP_SECONDS, "workers": spec.workers},
        "selected_obligations": selected, "executed_obligations": [], "failed_obligations": [],
        "skipped_obligations": [], "unexecuted_obligations": list(selected),
        "selected_nodes": list(nodes), "collected_nodes": [], "cases": [],
        "failures": [], "prerequisites": [], "coverage_status": "unverified",
        "deferred_profiles": {name: item.get("deferral") for name, item in inventory["profiles"].items()
                              if name != spec.name},
        "known_gaps": inventory.get("known_duplicate_definitions", []),
        "metric_paths": {"events": str(workspace.driver_root / "events.jsonl"),
                         "pipeline": str(workspace.pipeline.path)},
    }
    workspace.emit("ACCEPTANCE_SUITE_STARTED", profile=spec.name, budget=result["budget"])
    with workspace.span("acceptance.suite") as suite_span:
        try:
            commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                                    text=True, timeout=min(5, max(0.1, suite_end - time.monotonic())),
                                    check=True, env=acceptance_environment(workspace))
            result["commit"] = commit.stdout.strip()
            status = subprocess.run(
                ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
                capture_output=True, text=True, timeout=min(5, max(0.1, suite_end - time.monotonic())),
                check=True, env=acceptance_environment(workspace))
            result["working_tree_dirty"] = bool(status.stdout.strip())
            for relative in {
                    "appsec-review.toml", "tests/acceptance_plugin.py", "deploy/dagster/bin/ops_tests.py",
                    *json.loads(acceptance_environment(workspace)["APPSEC_ACCEPTANCE_STATIC_INPUTS"]),
                    *(node.split("::", 1)[0] for node in nodes)}:
                path = root / relative
                if path.is_file():
                    result["source_identities"][relative] = file_sha256(path)
            python, _ = find_python(root)
            # Acceptance must not silently borrow another checkout's editable environment.
            if not Path(python).parent.resolve().is_relative_to((root / ".venv").resolve()):
                result["failures"].append("checkout_owned_virtualenv_required")
            if not nodes:
                result["failures"].append("profile_not_implemented")
                result["prerequisites"] = [{"name": requirement, "available": None,
                                            "reason": "profile_not_implemented"}
                                           for requirement in spec.prerequisites]
            if not result["failures"]:
                result["setup_duration_seconds"] = time.monotonic() - started
                collection = supervised_pytest(python, ["--collect-only", *nodes], workspace, "collection",
                                               deadline=min(suite_end, time.monotonic() + per_case),
                                               prerequisites=spec.prerequisites, tested_commit=result["commit"])
                result["collection"] = collection
                collected = (collection["pytest"] or {}).get("collected", [])
                result["prerequisites"] = (collection["pytest"] or {}).get("prerequisites", [])
                if any(not item["available"] for item in result["prerequisites"]):
                    result["failures"].append("required_prerequisite_unavailable")
                result["collected_nodes"] = collected
                if (collection["outcome"] != "completed" or collection["exit_code"] != 0
                        or not collection["cleanup"]["confirmed"] or not collected
                        or len(collected) != len(set(collected))
                        or any(not any(_matches(node, item) for item in collected) for node in nodes)
                        or any(not any(_matches(node, item) for node in nodes) for item in collected)):
                    result["failures"].append("collection_incomplete_or_unexpected")
                else:
                    def execute(node: str) -> dict:
                        key = "case-" + hashlib.sha256(node.encode()).hexdigest()[:16]
                        limits = [entries[obligation].get("case_deadline_seconds", 60)
                                  for obligation in selected if any(
                                      _matches(selection, node) for selection in entries[obligation]["nodes"])]
                        case_seconds = min(per_case, *limits)
                        outcome = supervised_pytest(python, [node], workspace, key,
                                                   deadline=min(suite_end, time.monotonic() + case_seconds),
                                                   tested_commit=result["commit"])
                        record = {"node": node, "budget_seconds": case_seconds, **outcome}
                        payload = outcome["pytest"] or {}
                        cases = payload.get("cases", [])
                        record["passed"] = (outcome["outcome"] == "completed" and outcome["exit_code"] == 0
                                            and outcome["cleanup"]["confirmed"] and len(cases) == 1
                                            and cases[0]["node"] == node and cases[0]["outcome"] == "passed")
                        if any(result["source_identities"].get(path) != expected
                               for path, expected in outcome["static_input_identities"].items()):
                            record.update(passed=False, reason="static_reference_changed_during_suite")
                        return record

                    with ThreadPoolExecutor(max_workers=spec.workers) as executor:
                        result["cases"] = list(executor.map(execute, collected))
            for obligation in selected:
                required = entries[obligation]["nodes"]
                cases = [case for case in result["cases"] if any(_matches(node, case["node"]) for node in required)]
                executed = cases and all(
                    any(_matches(node, case["node"]) and (case["pytest"] or {}).get("cases")
                        for case in cases) for node in required)
                if executed:
                    result["executed_obligations"].append(obligation)
                if not executed or not all(case["passed"] for case in cases):
                    result["failed_obligations"].append(obligation)
                if any(any(item["outcome"] == "skipped" for item in (case["pytest"] or {}).get("cases", []))
                       for case in cases):
                    result["skipped_obligations"].append(obligation)
            result["unexecuted_obligations"] = [
                obligation for obligation in selected if not any(
                    any(_matches(node, case["node"]) for node in entries[obligation]["nodes"])
                    and (case["pytest"] or {}).get("cases") for case in result["cases"])]
            if result["failed_obligations"]:
                result["failures"].append("required_obligations_failed")
        except Exception as error:
            result["failures"].append(f"harness_{type(error).__name__}")
        all_processes = [result.get("collection", {}), *result["cases"]]
        result["cleanup"] = {"confirmed": all(
            item.get("cleanup", {}).get("confirmed", True) for item in all_processes),
            "scope": "owned_process_trees_only", "production_services_touched": False}
        if not result["cleanup"]["confirmed"]:
            result["failures"].append("cleanup_unconfirmed")
        if time.monotonic() > suite_end:
            result["failures"].append("suite_deadline_exceeded")
        result["passed"] = not result["failures"] and bool(result["executed_obligations"])
        if not result["passed"]:
            suite_span.status = "FAILED"
        result["coverage_status"] = "selected_obligations_passed" if result["passed"] else "incomplete"
    result["duration_seconds"] = time.monotonic() - started
    workspace.emit("ACCEPTANCE_SUITE_COMPLETED", passed=result["passed"],
                   duration_ms=result["duration_seconds"] * 1000, cleanup=result["cleanup"])
    atomic_json(workspace.root / "result.json", result)
    print(f"acceptance: {'PASSED' if result['passed'] else 'FAILED'}; "
          f"{len(result['cases'])} cases; {result['duration_seconds']:.3f}s", flush=True)
    print(f"result: {workspace.root / 'result.json'}", flush=True)
    return 0 if result["passed"] else 1
