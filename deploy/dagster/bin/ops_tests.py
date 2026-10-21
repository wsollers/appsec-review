"""Named pytest suites with a unique base temp, a log file and known-failure accounting."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys


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
    sub.set_defaults(extra=[])
    sub.epilog += "\nInstead of a suite, pass pytest arguments after --, for example: run-tests.sh -- tests/test_config.py -k overlay"
