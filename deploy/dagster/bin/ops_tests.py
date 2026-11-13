"""Named pytest suites with a unique base temp, a log file and known-failure accounting."""

from __future__ import annotations

import argparse
import ast
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import keyword
import os
from pathlib import Path
import platform
import random
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
OFFLINE_IGNORES = ("--ignore=tests/live", "--ignore-glob=tests/test_live_*.py",
                   "--ignore=tests/acceptance")
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
    """Use an explicit interpreter or this checkout's own environment; never borrow another checkout."""
    override = os.environ.get("APPSEC_PYTHON")
    if override:
        return override, {"PYTHONPATH": str(root / "src")}
    candidates = [root / ".venv" / "bin" / "python", root / ".venv" / "Scripts" / "python.exe"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate), {}
    return sys.executable, {"PYTHONPATH": str(root / "src")}


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def session_name(args: argparse.Namespace, stamp: str) -> str:
    return f"tests-{'custom' if args.extra else args.suite}-{stamp}"


# Arguments the wrapper owns. Passing them after -- would defeat the bounded base temp, the report or
# the shared-host worker bound; they are refused rather than silently overridden.
def reserved_extra_arguments(extra: list[str]) -> list[str]:
    """The pass-through arguments run-tests refuses: its own base temp and report, and an unbounded worker count."""
    refused = []
    from ops_test_guard import VALUE_OPTIONS
    operand = False
    for index, item in enumerate(extra):
        if operand:
            operand = False
            continue
        if item in VALUE_OPTIONS:
            operand = True
            continue
        if item in {"-n", "--numprocesses"} and index + 1 < len(extra) and extra[index + 1] == "auto":
            refused.append(f"{item} auto")
        elif item in {"-nauto", "-n=auto", "--numprocesses=auto"}:
            refused.append(item)
        elif item.startswith(("--basetemp", "--junitxml", "--junit-xml")):
            refused.append(item)
    return refused


def build_command(root: Path, args: argparse.Namespace, python: str, stamp: str, parallel: bool) -> list[str]:
    name = session_name(args, stamp)
    command = [python, "-m", "pytest", "-q", "-rfE", f"--basetemp=test/tmp/{name}",
               f"--junitxml=test/tmp/{name}.junit.xml", "-o", "junit_family=legacy"]
    if parallel:
        command += ["-n", str(args.test_workers)]
    seed = shuffle_seed(args)
    if seed is not None:
        command.append(f"--shuffle-seed={seed}")
    command += list(args.extra) if args.extra else suite_arguments(root, args.suite)
    return command


def shuffle_seed(args: argparse.Namespace) -> int | None:
    """Named suites other than live run in a shuffled order so order-coupled tests surface."""
    if args.no_shuffle or any(item == "--shuffle-seed" or item.startswith("--shuffle-seed=") for item in args.extra):
        return None
    if args.shuffle_seed is not None:
        return args.shuffle_seed
    if args.extra or args.suite == "live":
        return None
    return random.SystemRandom().randrange(1, 2**31)


# ------------------------------------------------------------------------------- the fixed report

SLOW_SECONDS = 10.0


def _junit_node_id(case) -> str:
    """The pytest node id of a legacy-family junit testcase (file, classname, name)."""
    file = case.get("file") or ""
    classname = case.get("classname") or ""
    name = case.get("name") or ""
    if not file:
        return f"{classname}::{name}" if classname else name
    module = file[:-3].replace("/", ".") if file.endswith(".py") else file.replace("/", ".")
    classes = classname[len(module) + 1:] if classname.startswith(module + ".") else ""
    parts = [file, *(classes.split(".") if classes else []), name]
    return "::".join(part for part in parts if part)


def load_baseline(path: Path) -> set[str]:
    """Node ids of a baseline file: one per line, an optional ``FAILED``/``ERROR`` prefix, ``| reason`` allowed."""
    ids = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("|", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        for prefix in ("FAILED ", "ERROR "):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
        line = line.split(" - ", 1)[0].strip()
        if line:
            ids.add(line)
    return ids


def junit_report(xml_path: Path, text: str, *, slow_seconds: float = SLOW_SECONDS) -> dict:
    """The fixed report of one pytest run, from its junit file and its log.

    Nothing here classifies a failure: the report carries the counts, the elapsed time, every test over
    ``slow_seconds``, every FAILED/ERROR node id verbatim with the ``E`` lines of its report, and the
    paths of the log, the junit file and the timings database. Attribution is the reader's job.
    """
    import xml.etree.ElementTree as ET
    result = parse_output(text, {})
    report: dict = {"counts": result.counts, "elapsed_s": None, "slow": [], "failures": [], "ran": [],
                    "junit": str(xml_path), "junit_present": xml_path.is_file()}
    summary = [line for line in text.splitlines() if re.search(r"\d+ (passed|failed|skipped|error)", line)]
    match = re.search(r"in ([0-9.]+)s", summary[-1]) if summary else None
    if match:
        report["elapsed_s"] = float(match.group(1))
    failures_by_id: dict[str, dict] = {}
    for status, node in (m.groups() for m in map(FAILURE_LINE.match, text.splitlines()) if m):
        failures_by_id.setdefault(node, {"node": node, "status": status, "lines": [], "duration_s": None})
    if xml_path.is_file():
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as error:
            report["junit_error"] = str(error)
            tree = None
        if tree is not None:
            for case in tree.getroot().iter("testcase"):
                node = _junit_node_id(case)
                duration = float(case.get("time") or 0.0)
                report["ran"].append(node)
                if duration >= slow_seconds:
                    report["slow"].append({"node": node, "duration_s": round(duration, 2)})
                failed = case.find("failure")
                errored = case.find("error")
                detail = failed if failed is not None else errored
                if detail is not None:
                    entry = failures_by_id.setdefault(node, {"node": node, "status": "FAILED" if failed is not None else "ERROR",
                                                             "lines": [], "duration_s": None})
                    entry["duration_s"] = round(duration, 2)
                    body = detail.text or detail.get("message") or ""
                    lines = [line.rstrip() for line in body.splitlines() if line.startswith("E ")]
                    entry["lines"] = lines[:40] or [line.rstrip() for line in body.splitlines() if line.strip()][-3:]
    report["slow"].sort(key=lambda item: (-item["duration_s"], item["node"]))
    report["failures"] = [failures_by_id[node] for node in sorted(failures_by_id)]
    report["ran"] = sorted(set(report["ran"]))
    return report


def differential(report: dict, baseline: set[str]) -> dict:
    """New, fixed and unchanged failures against a baseline of node ids; fixed only when the test ran and passed."""
    failing = {item["node"] for item in report["failures"]}
    ran = set(report["ran"])
    return {"new": sorted(failing - baseline), "unchanged": sorted(failing & baseline),
            "fixed": sorted(node for node in baseline if node in ran and node not in failing),
            "not_run": sorted(node for node in baseline if node not in ran and node not in failing)}


def shared_error_groups(report: dict) -> list[dict]:
    """Failures that end in the same ``E`` line, largest group first; groups of one are left out.

    This is a literal grouping, not a classification: the signature is the last ``E`` line of each
    report with whitespace collapsed and memory addresses masked. Many failures with one signature
    usually share one cause, and naming that cause stays the reader's job.
    """
    groups: dict[str, list[str]] = {}
    for item in report["failures"]:
        last = next((line for line in reversed(item["lines"]) if line.startswith("E ")), None)
        if last is None:
            continue
        signature = re.sub(r"0x[0-9a-fA-F]+", "0x…", " ".join(last[1:].split()))
        groups.setdefault(signature, []).append(item["node"])
    return [{"signature": signature, "count": len(nodes), "nodes": sorted(nodes)}
            for signature, nodes in sorted(groups.items(), key=lambda pair: (-len(pair[1]), pair[0])) if len(nodes) > 1]


def coverage_report(path: Path) -> dict:
    """Read counts without making coverage availability or completeness a test verdict."""
    result = {"json": str(path)}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        totals = payload.get("totals") if isinstance(payload, dict) else None
        keys = ("covered_lines", "num_statements", "missing_lines",
                "covered_branches", "num_branches", "missing_branches")
        if not isinstance(totals, dict) or any(type(totals.get(key)) is not int or totals[key] < 0 for key in keys):
            raise ValueError("coverage totals must contain nonnegative integer line and branch counts")
        if (totals["covered_lines"] + totals["missing_lines"] != totals["num_statements"]
                or totals["covered_branches"] + totals["missing_branches"] != totals["num_branches"]):
            raise ValueError("coverage totals have inconsistent covered/missing counts")
        result["totals"] = {key: totals[key] for key in keys}
    except (OSError, UnicodeError, ValueError) as error:
        result["error"] = f"{type(error).__name__}: {error}"
    return result


def render_report(report: dict, *, log: Path, timings: Path, diff: dict | None, baseline: Path | None) -> str:
    counts = ", ".join(f"{report['counts'].get(key, 0)} {key}" for key in ("passed", "failed", "error", "skipped", "xfailed", "xpassed")
                       if report["counts"].get(key)) or "no summary line found"
    lines = [f"counts: {counts}", f"elapsed: {report['elapsed_s']} s" if report["elapsed_s"] is not None else "elapsed: unknown",
             f"log: {log}", f"junit: {report['junit']}" + ("" if report["junit_present"] else " (missing)"), f"timings: {timings}"]
    if "coverage" in report:
        coverage = report["coverage"]
        lines.append(f"coverage JSON: {coverage['json']}")
        if "totals" in coverage:
            totals = coverage["totals"]
            lines.append(f"coverage totals: lines {totals['covered_lines']}/{totals['num_statements']} "
                         f"(missing {totals['missing_lines']}), branches {totals['covered_branches']}/{totals['num_branches']} "
                         f"(missing {totals['missing_branches']})")
        else:
            lines.append(f"coverage totals: unavailable ({coverage['error']})")
    lines.append(f"slower than {SLOW_SECONDS:g}s: " + (", ".join(f"{item['node']} ({item['duration_s']}s)" for item in report["slow"]) or "none"))
    lines.append(f"failures: {len(report['failures'])}")
    for item in report["failures"]:
        lines.append(f"  {item['status']} {item['node']}")
        lines.extend(f"    {line}" for line in item["lines"])
    groups = shared_error_groups(report)
    if groups:
        lines.append(f"shared error text: {len(groups)} group(s)")
        for group in groups:
            lines.append(f"  {group['count']} failures end in: {group['signature']}")
            lines.extend(f"    {node}" for node in group["nodes"][:5])
            if group["count"] > 5:
                lines.append(f"    ... and {group['count'] - 5} more")
    if diff is not None:
        lines.append(f"baseline: {baseline} — {len(diff['new'])} new, {len(diff['fixed'])} fixed, "
                     f"{len(diff['unchanged'])} unchanged, {len(diff['not_run'])} not run")
        lines.extend(f"  NEW     {node}" for node in diff["new"])
        lines.extend(f"  FIXED   {node}" for node in diff["fixed"])
    return "\n".join(lines)


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
    started = time.monotonic()
    root = root.resolve()
    coverage = getattr(args, "coverage", None)
    if coverage is not None and (not re.fullmatch(r"appsec_review(?:\.[A-Za-z_][A-Za-z0-9_]*)*", coverage)
                                 or any(keyword.iskeyword(part) for part in coverage.split("."))):
        print("error: --coverage PACKAGE must be a dotted module name under appsec_review", file=sys.stderr, flush=True)
        return 2
    if getattr(args, "acceptance", None):
        if coverage is not None:
            print("error: --coverage cannot combine with --acceptance", file=sys.stderr, flush=True)
            return 2
        if (any(getattr(args, name, None) is not None for name in
                ("max_tests", "expect_tests", "collection_seconds", "timeout_seconds"))
                or getattr(args, "allow_heavy", False)):
            print("error: focused pytest bounds/--allow-heavy cannot combine with --acceptance; "
                  "use its --deadline/--case-deadline", file=sys.stderr, flush=True)
            return 2
        return run_acceptance(args, root)
    if any(getattr(args, name, None) is not None for name in ("workers", "deadline", "case_deadline")):
        print("error: --workers/--deadline/--case-deadline require --acceptance", file=sys.stderr)
        return 2
    if args.extra and args.suite:
        print("error: give a suite name or arguments after --, not both", file=sys.stderr, flush=True)
        return 2
    refused = reserved_extra_arguments(list(args.extra))
    if refused:
        print("error: run-tests owns these arguments; drop them: " + ", ".join(refused), file=sys.stderr, flush=True)
        return 2
    if getattr(args, "baseline", None) is not None and not Path(args.baseline).is_file():
        print(f"error: baseline file not found: {args.baseline}", file=sys.stderr, flush=True)
        return 2
    from ops_test_guard import CONTROL_ENV, Limits, focused_arguments, supervise

    try:
        defaults = Limits()
        limits = Limits(
            defaults.max_tests if args.max_tests is None else args.max_tests, args.expect_tests,
            defaults.collection_seconds if args.collection_seconds is None else args.collection_seconds,
            defaults.timeout_seconds if args.timeout_seconds is None else args.timeout_seconds)
        if args.background:
            raise ValueError("--background is not supervised; background the entire run-tests command with your host instead")
        if not args.extra and not args.suite:
            raise ValueError("name an explicit suite or pass exact test file/node selectors after --; no default broad run")
        if args.extra:
            args.extra, selectors = focused_arguments(root, list(args.extra), allow_heavy=args.allow_heavy)
        else:
            selectors = []
        if os.environ.get("PYTEST_ADDOPTS"):
            raise ValueError("PYTEST_ADDOPTS can change collection; unset it and pass supported options explicitly")
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr, flush=True)
        return 2
    if not args.extra and args.suite not in SUITES:
        print(f"error: unknown suite {args.suite!r}; choose from {', '.join(SUITES)} or pass arguments after --", file=sys.stderr, flush=True)
        return 2
    if not args.extra and not any(not item.startswith("-") for item in suite_arguments(root, args.suite)):
        print(f"error: suite {args.suite!r} has no existing selectors", file=sys.stderr, flush=True)
        return 2
    python, environment = find_python(root)
    if coverage is not None:
        try:
            probe = subprocess.run([python, "-c", "import pytest_cov"], cwd=root,
                                   env={**os.environ, **environment}, capture_output=True, text=True,
                                   timeout=min(5.0, limits.timeout_seconds), check=False)
            if probe.returncode:
                raise ValueError(f"pytest_cov is not importable with {python}: {probe.stderr.strip()}")
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            print(f"error: --coverage requires importable pytest_cov: {error}", file=sys.stderr, flush=True)
            return 2
    parallel = args.parallel
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + f"-{os.getpid()}"
    name = "custom" if args.extra else args.suite
    session = session_name(args, stamp)
    command = build_command(root, args, python, stamp, parallel)
    # Pin config/root and clear its addopts; only the wrapper may select scope and scratch paths.
    command[3:3] = ["-p", "ops_test_guard", "-c", str(root / "pyproject.toml"),
                    f"--rootdir={root}", "-o", "addopts="]
    collection_command = command.copy()
    if parallel:
        index = collection_command.index("-n")
        del collection_command[index:index + 2]
    collection_command.append("--collect-only")
    coverage_path = Path("test/tmp") / f"{session}.coverage.json"
    if coverage is not None:
        command += [f"--cov={coverage}", "--cov-branch", f"--cov-report=json:{coverage_path.as_posix()}"]
    log = root / "test" / "tmp" / "logs" / f"{session}.log"
    if args.suite == "live" and not args.extra:
        print(LIVE_WARNING, flush=True)
    print(f"run-tests: suite {name}; python {python}" + (f"; PYTHONPATH={environment['PYTHONPATH']}" if environment else ""), flush=True)
    print("+ " + shlex.join(command), flush=True)
    print(f"log: {log}", flush=True)
    print(f"selectors: {json.dumps(selectors) if selectors else 'explicit suite ' + args.suite}; "
          f"max-tests={limits.max_tests}; expect-tests={limits.expect_tests}; "
          f"collection={limits.collection_seconds:g}s; total={limits.timeout_seconds:g}s", flush=True)
    if args.dry_run:
        print("dry run: not executed", flush=True)
        return 0
    log.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **environment}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(Path(__file__).parent), env.get("PYTHONPATH"))))
    process_root = root / "test/tmp" / f"{session}.processes"
    manifest = root / "test/tmp" / f"{session}.collection.json"
    proofs = process_root / "collection-proofs"
    proofs.mkdir(parents=True)
    control = {"root": str(root), "selectors": selectors, "limits": asdict(limits),
               "allow_heavy": args.allow_heavy or args.suite in {"live", "all-offline"},
               "manifest": str(manifest), "proof_directory": str(proofs), "stage": "collect"}
    env[CONTROL_ENV] = json.dumps(control)
    collection_log = log.with_suffix(".collection.log")
    deadline = started + limits.timeout_seconds
    collection_deadline = min(deadline, time.monotonic() + limits.collection_seconds)
    collected = supervise(
        collection_command, root, env, process_root / "collect", collection_log,
        deadline=collection_deadline, cleanup_seconds=min(3.0, limits.collection_seconds / 4, limits.timeout_seconds / 4))
    stages = {"collection": collected}
    code = 124 if collected["outcome"] == "timeout" else 2
    if collected["outcome"] == "completed" and collected["exit_code"] == 0 and manifest.is_file():
        collection = json.loads(manifest.read_text(encoding="utf-8"))
        print(f"collected: {collection['count']}; manifest: {manifest}", flush=True)
        for node in collection["nodes"]:
            print(f"  {node}", flush=True)
        control["stage"] = "execute"
        env[CONTROL_ENV] = json.dumps(control)
        if coverage is not None:
            env["COVERAGE_FILE"] = f"test/tmp/{session}.coverage"
        executed = supervise(command, root, env, process_root / "execute", log, deadline=deadline,
                             cleanup_seconds=min(3.0, limits.timeout_seconds / 4))
        stages["execution"] = executed
        code = (executed["exit_code"] if executed["outcome"] == "completed"
                else 124 if executed["outcome"] == "timeout" else 2)
        collection_proofs = [json.loads(path.read_bytes()) for path in sorted(proofs.glob("*.json"))]
        if code in (0, 1) and (len(collection_proofs) != (args.test_workers if parallel else 1)
                              or any(proof.get("verified") is not True for proof in collection_proofs)):
            code = 2
            executed.update(outcome="error", reason="execution collection proof missing or refused")
        if any(proof.get("verified") is not True for proof in collection_proofs):
            code = 2
            executed.update(outcome="error", reason="execution collection differs from inspected preflight")
            with log.open("a", encoding="utf-8") as stream:
                for proof in collection_proofs:
                    if proof.get("verified") is not True:
                        stream.write(f"\ncollection refused: {proof.get('reason', 'missing verification')}\n")
    else:
        log.write_text("collection refused; no tests executed\n" + collection_log.read_text(
            encoding="utf-8", errors="replace"), encoding="utf-8")
    for phase, result in stages.items():
        print(f"{phase}: {result['outcome']}; cleanup={json.dumps(result['cleanup'])}"
              + (f"; {result['reason']}" if result.get("reason") else ""), flush=True)
    text = log.read_text(encoding="utf-8", errors="replace")
    print(text, end="", flush=True)
    fixed = junit_report(root / "test" / "tmp" / f"{session}.junit.xml", text)
    if coverage is not None:
        fixed["coverage"] = coverage_report(root / coverage_path)
    baseline_path = Path(args.baseline).resolve() if getattr(args, "baseline", None) else None
    diff = differential(fixed, load_baseline(baseline_path)) if baseline_path else None
    timings = root / "test" / "tmp" / f"{session}.timings.sqlite"
    rendered = render_report(fixed, log=log, timings=timings, diff=diff, baseline=baseline_path)
    report_path = root / "test" / "tmp" / "reports" / f"{session}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps({"command": command, "exit_code": code, "log": str(log), "timings": str(timings),
                                       "report": fixed, "baseline": str(baseline_path) if baseline_path else None,
                                       "differential": diff, "selectors": selectors, "limits": asdict(limits),
                                       "collection_log": str(collection_log), "collection_manifest": str(manifest),
                                       "stages": stages, "total_elapsed_s": time.monotonic() - started},
                                      indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("\n" + rendered, flush=True)
    print(f"report: {report_path}", flush=True)
    if getattr(args, "write_baseline", None) and code in (0, 1):
        target = Path(args.write_baseline)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(f"{item['status']} {item['node']}\n" for item in fixed["failures"]), encoding="utf-8")
        print(f"baseline written: {target} ({len(fixed['failures'])} ids)", flush=True)
    if code not in (0, 1):
        return code
    if diff is not None:
        # With a baseline the verdict is the differential, not pytest's exit code: new failures fail.
        return 1 if diff["new"] else (0 if code in (0, 1) else code)
    return report(text, load_known(root), code, args.strict)


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
    sub.add_argument("suite", nargs="?", metavar="SUITE", help=f"explicit suite: {', '.join(SUITES)}")
    sub.add_argument("--background", action="store_true", help="refused: background the supervised wrapper via your host")
    sub.add_argument("--max-tests", type=_positive_int, help="maximum collected tests (default 200)")
    sub.add_argument("--expect-tests", type=_positive_int, help="require exactly this reviewed collection count")
    sub.add_argument("--collection-seconds", type=float, help="collection cap inside total deadline (default 30)")
    sub.add_argument("--timeout-seconds", type=float, help="total collection/execution/cleanup cap (default 300)")
    sub.add_argument("--allow-heavy", action="store_true", help="explicit manual integration/live file selection; not acceptance")
    sub.add_argument("--parallel", action="store_true",
                     help="require pytest-xdist with --test-workers workers; no serial fallback")
    sub.add_argument("--test-workers", type=_positive_int, default=8, metavar="N",
                     help="xdist workers for --parallel (default 8; bounded for shared hosts, never auto)")
    sub.add_argument("--shuffle-seed", type=int, metavar="N",
                     help="reproduce a shuffled order (named suites except live are shuffled by default)")
    sub.add_argument("--no-shuffle", action="store_true", help="keep pytest's deterministic collection order")
    sub.add_argument("--strict", action="store_true", help="fail even when only known failures remain")
    sub.add_argument("--coverage", metavar="PACKAGE",
                     help="branch coverage JSON for appsec_review or one dotted submodule (requires pytest-cov)")
    # Refuse raw --cov even before "--", without changing existing option abbreviations.
    option_tuples = sub._get_option_tuples

    def exact_coverage_option(option_string):
        return [match for match in option_tuples(option_string) if match[1] != "--coverage"]

    sub._get_option_tuples = exact_coverage_option
    sub.add_argument("--baseline", metavar="FILE",
                     help="node ids that fail without this change (one per line; FAILED/ERROR prefixes allowed); "
                          "the verdict becomes the differential: new failures fail, unchanged ones do not")
    sub.add_argument("--write-baseline", metavar="FILE", help="write this run's FAILED/ERROR node ids to FILE")
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
                      tested_commit: str | None = None, stage=None,
                      frozen_inputs: dict | None = None) -> dict:
    """Run collection or exactly one case under a hard wall-clock budget with owned cleanup."""
    from appsec_review.storage import atomic_json
    from appsec_review.runtime.resources import process_identity

    started = time.monotonic()
    directory = workspace.require_owned_path(workspace.root / ("p" if stage is not None else "processes") / key)
    directory.mkdir(parents=True, exist_ok=False)
    outcome_path = directory / "pytest.json"
    exit_path = directory / "exit.json"
    environment = acceptance_environment(workspace)
    if tested_commit is not None:
        environment["APPSEC_ACCEPTANCE_TESTED_COMMIT"] = tested_commit
    environment["APPSEC_ACCEPTANCE_OUTCOME"] = str(outcome_path)
    environment["APPSEC_ACCEPTANCE_PREREQUISITES"] = json.dumps(prerequisites)
    if stage is not None:
        from appsec_review.acceptance.staging import STAGE_ENVIRONMENT

        if "--collect-only" in arguments:
            raise ValueError("stage context is execution-only")
        environment[STAGE_ENVIRONMENT] = json.dumps(stage.record(), sort_keys=True)
        if frozen_inputs is not None:
            from appsec_review.storage import file_sha256

            frozen_path = directory / "frozen-inputs.json"
            atomic_json(frozen_path, frozen_inputs)
            environment["APPSEC_ACCEPTANCE_FROZEN_INPUTS"] = str(frozen_path)
            environment["APPSEC_ACCEPTANCE_FROZEN_INPUTS_SHA256"] = file_sha256(frozen_path)
        # A staged child cannot write another phase's HOME, TEMP, cache, or Dagster state.
        for name, keys in (
                ("h", ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA")),
                ("t", ("TEMP", "TMP", "TMPDIR")),
                ("d", ("DAGSTER_HOME",))):
            path = directory / name
            path.mkdir()
            environment.update({key: str(path) for key in keys})
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
        result["duration_seconds"] = time.monotonic() - started
        atomic_json(directory / "supervisor.json", result)
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


def _stage_graph(entries: dict, selected: list[str]) -> dict:
    """Validate the explicitly selected chain without adding or skipping prerequisites."""
    from appsec_review.acceptance.staging import StageDeclaration, StageKind

    stages = {}
    if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)):
        raise ValueError("obligations must be a unique explicit list")
    for obligation in selected:
        entry = entries[obligation]
        nodes = entry["nodes"]
        if not isinstance(nodes, list) or not nodes or any(
                not isinstance(node, str) or not node.strip() for node in nodes):
            raise ValueError(f"obligation requires explicit nodes: {obligation}")
        if "stage" in entry:
            if not isinstance(entry["stage"], dict):
                raise ValueError(f"stage must be a declaration: {obligation}")
            stage = StageDeclaration.from_mapping(entry["stage"])
            if stage.kind is StageKind.PRODUCER and (
                    len(nodes) != 1 or "::" not in nodes[0]
                    or not nodes[0].endswith(f"[{stage.variant}]")):
                raise ValueError(f"producer requires one literal variant node: {obligation}")
            stages[obligation] = stage
    for obligation, stage in stages.items():
        for dependency in stage.depends_on:
            if dependency not in entries:
                raise ValueError(f"unknown stage prerequisite: {obligation}:{dependency}")
            if dependency not in selected:
                raise ValueError(f"unselected stage prerequisite: {obligation}:{dependency}")
            predecessor = stages.get(dependency)
            if (predecessor is None or predecessor.kind is not StageKind.PRODUCER
                    or predecessor.variant != stage.variant
                    or (stage.kind is StageKind.PRODUCER and predecessor.seals)
                    or (stage.kind is StageKind.CONSUMER and not predecessor.seals)):
                raise ValueError(f"incompatible stage prerequisite: {obligation}:{dependency}")
    visited, active = set(), set()

    def visit(obligation):
        if obligation in active:
            raise ValueError(f"cyclic stage prerequisites: {obligation}")
        if obligation in visited:
            return
        active.add(obligation)
        for dependency in stages[obligation].depends_on:
            visit(dependency)
        active.remove(obligation)
        visited.add(obligation)

    for obligation in stages:
        visit(obligation)
    for variant in {stage.variant for stage in stages.values()}:
        producers = {name: stage for name, stage in stages.items()
                     if stage.variant == variant and stage.kind is StageKind.PRODUCER}
        roots = [name for name, stage in producers.items() if not stage.depends_on]
        children = {name: [child for child, stage in producers.items() if name in stage.depends_on]
                    for name in producers}
        terminals = [name for name, successors in children.items() if not successors]
        if (len(roots) != 1 or len(terminals) != 1
                or any(len(successors) > 1 for successors in children.values())
                or [name for name, stage in producers.items() if stage.seals] != terminals):
            raise ValueError(f"ambiguous or unsealed producer chain: {variant}")
    return stages


def _collected_owners(entries: dict, selected: list[str], collected: list[str], stages: dict) -> dict[str, str]:
    owners = {}
    for node in collected:
        matches = [obligation for obligation in selected
                   if any(_matches(selection, node) for selection in entries[obligation]["nodes"])]
        if len(matches) != 1:
            raise ValueError(f"ambiguous collected obligation: {node}")
        owners[node] = matches[0]
    for obligation in stages:
        from appsec_review.acceptance.staging import StageKind

        if stages[obligation].kind is StageKind.PRODUCER:
            expected = entries[obligation]["nodes"]
            actual = [node for node, owner in owners.items() if owner == obligation]
            if actual != expected:
                raise ValueError(f"producer did not collect its exact literal node: {obligation}")
    return owners


def _source_identities(root: Path, nodes: tuple[str, ...], static_inputs: dict, *, staged=False) -> dict[str, str]:
    from appsec_review.storage import file_sha256

    paths = {
        "appsec-review.toml", "tests/conftest.py", "tests/acceptance_plugin.py",
        "deploy/dagster/bin/ops_tests.py", *static_inputs,
        *(node.split("::", 1)[0] for node in nodes),
        *(path.relative_to(root).as_posix()
          for path in (root / "src" / "appsec_review" / "acceptance").glob("*.py")),
    }
    if staged:
        # JobRunner loads handlers dynamically. Pin its complete code, not just imports
        # visible in the selected fixture. Test helpers use an explicit local import closure.
        paths.update(path.relative_to(root).as_posix() for path in (root / "src").rglob("*.py"))
        for directory in ("docs/schemas", "pipeline"):
            paths.update(path.relative_to(root).as_posix()
                         for path in (root / directory).rglob("*") if path.is_file())
    pending = [name for name in paths if name.endswith(".py")]
    inspected = set()
    while pending:
        relative = pending.pop()
        if relative in inspected:
            continue
        inspected.add(relative)
        path = root / relative
        if not path.is_file():
            raise ValueError(f"missing acceptance source: {relative}")
        module = relative.removesuffix(".py").replace("/", ".")
        if module.endswith(".__init__"):
            module = module.removesuffix(".__init__") + ".__package__"
        for item in ast.walk(ast.parse(path.read_bytes(), filename=relative)):
            imports = []
            if isinstance(item, ast.Import):
                imports = [alias.name for alias in item.names]
            elif isinstance(item, ast.ImportFrom):
                prefix = ".".join(module.split(".")[:-item.level]) if item.level else ""
                base = ".".join(part for part in (prefix, item.module) if part)
                imports = [base, *(base + "." + alias.name for alias in item.names)]
            for name in imports:
                if not name.startswith("tests."):
                    continue
                logical = name.replace(".", "/")
                for candidate in (logical + ".py", logical + "/__init__.py"):
                    if (root / candidate).is_file() and candidate not in paths:
                        paths.add(candidate)
                        pending.append(candidate)
    identities = {}
    for relative in sorted(paths):
        path = root / relative
        if path.resolve() != path or not path.is_file():
            raise ValueError(f"missing or redirected acceptance source: {relative}")
        identities[relative] = file_sha256(path)
    return identities


def _verify_sources(root: Path, identities: dict[str, str]) -> None:
    from appsec_review.acceptance.custody import _check_deadline
    from appsec_review.storage import file_sha256

    for relative, expected in identities.items():
        _check_deadline()
        path = root / relative
        if path.resolve() != path or not path.is_file() or file_sha256(path) != expected:
            raise ValueError(f"acceptance_source_changed:{relative}")
        _check_deadline()


def _execute_acceptance_cases(python, workspace, collected, owners, entries, stages, result,
                              *, suite_end, per_case, workers):
    from appsec_review.acceptance.custody import (
        capture_inputs, checkpoint_seed, copy_receipt_path, custody_deadline, detach_producer_outputs, materialize_seed,
        seal_seed, verify_checkpoint, verify_inputs,
    )
    from appsec_review.acceptance.staging import StageContext, StageKind
    from appsec_review.storage import atomic_json, file_sha256

    states: dict[str, dict] = {}
    records: dict[str, dict] = {}
    by_obligation = {name: [node for node in collected if owners[node] == name]
                     for name in result["selected_obligations"]}
    pending = list(collected)
    running = {}

    def blocked(node, reason, dependency=None):
        return {
            "node": node, "obligation_id": owners[node], "outcome": "blocked" if dependency else "not_executed",
            "reason": reason, "dependency": dependency, "passed": False, "pytest": None,
            "exit_code": None, "duration_seconds": 0.0, "cleanup": {"confirmed": True, "started": False},
        }

    def execute(node):
        obligation = owners[node]
        stage = stages.get(obligation)
        # Invocation-local ordinals are unique without long helper HOME/TEMP paths.
        key = f"case-{collected.index(node):04d}"
        case_seconds = min(per_case, entries[obligation].get("case_deadline_seconds", 60))
        started = time.monotonic()
        deadline = min(suite_end, started + case_seconds)
        record = {"node": node, "obligation_id": obligation, "budget_seconds": case_seconds,
                  "pytest": None, "exit_code": None, "outcome": "error", "passed": False,
                  "cleanup": {"confirmed": True, "started": False}, "staging": []}
        manifest_path = None

        def operation(name, function):
            began = time.monotonic()
            span = None
            try:
                with workspace.span("acceptance.stage." + name) as span:
                    return function()
            finally:
                record["staging"].append({
                    "operation": name, "span_id": span.span_id if span is not None else None,
                    "duration_seconds": time.monotonic() - began,
                    "status": span.status if span is not None else "FAILED"})

        try:
            with custody_deadline(deadline):
                if stage is not None:
                    operation("sources_precheck", lambda: _verify_sources(
                        workspace.repository, result["source_identities"]))
                context = None
                frozen = None
                state = None
                if stage is not None:
                    state = states.setdefault(stage.variant, {})
                    work_root = workspace.root / "stages" / stage.variant
                    common = {
                        "kind": stage.kind, "variant": stage.variant, "obligation_id": obligation,
                        "invocation_id": workspace.invocation_id, "tested_commit": result["commit"],
                        "source_identities": result["stage_source_identities"], "workspace_root": workspace.root,
                        "work_root": work_root,
                    }
                    if stage.kind is StageKind.PRODUCER:
                        context = StageContext(**common)
                        if stage.depends_on:
                            frozen = state["inputs"]
                            if file_sha256(state["inputs_path"]) != state["inputs_sha256"]:
                                raise ValueError("prepared_input_receipt_changed")
                            operation("predecessor_precheck", lambda: verify_checkpoint(
                                context, state["checkpoint_path"], state["checkpoint_sha256"]))
                            operation("inputs_precheck", lambda: verify_inputs(context, frozen))
                        else:
                            operation("prepare_directory", lambda: work_root.mkdir(parents=True, exist_ok=False))
                    else:
                        manifest_path = state["manifest_path"]
                        context = StageContext(**{
                            **common, "work_root": workspace.root / "consumers" / key,
                            "seed_root": work_root, "manifest_path": manifest_path,
                            "manifest_sha256": state["manifest_sha256"],
                        })
                        operation("copy", lambda: materialize_seed(context))
                        copy_receipt = copy_receipt_path(context.work_root)
                        record["materialization_receipt"] = {
                            "path": str(copy_receipt), "sha256": file_sha256(copy_receipt)}
                    record["stage"] = context.record()
                outcome = supervised_pytest(
                    python, [node], workspace, key, deadline=deadline, tested_commit=result["commit"],
                    **({"stage": context, "frozen_inputs": frozen} if context is not None else {}))
                record.update(outcome)
                payload = outcome["pytest"] or {}
                cases = payload.get("cases", [])
                record["passed"] = (
                    outcome["outcome"] == "completed" and outcome["exit_code"] == 0
                    and outcome["cleanup"]["confirmed"] and payload.get("collected") == [node]
                    and not payload.get("collection_errors") and len(cases) == 1
                    and cases[0]["node"] == node and cases[0]["outcome"] == "passed")
                if payload.get("collection_errors"):
                    record["reason"] = ";".join(payload["collection_errors"])
                if any(result["source_identities"].get(path) != expected
                       for path, expected in outcome["static_input_identities"].items()):
                    record.update(passed=False, reason="static_reference_changed_during_suite")
                if stage is not None:
                    operation("sources_postcheck", lambda: _verify_sources(
                        workspace.repository, result["source_identities"]))
                if stage is not None and record["passed"] and stage.kind is StageKind.PRODUCER:
                    detachment_path = workspace.root / "custody" / stage.variant / (key + ".publication.json")
                    record["producer_publication"] = {"path": str(detachment_path)}
                    detachment = operation("producer_publication", lambda: detach_producer_outputs(
                        context, detachment_path, producer_result=outcome, frozen_inputs=frozen))
                    record["producer_publication"].update(
                        sha256=file_sha256(detachment_path), outcome=detachment["outcome"],
                        replaced_files=detachment["replaced_files"],
                        verified_copy_bytes=detachment["verified_copy_bytes"])
                    if frozen is None:
                        frozen = operation("capture_inputs", lambda: capture_inputs(context))
                        inputs_path = workspace.root / "custody" / stage.variant / "immutable-inputs.json"
                        operation("pin_inputs", lambda: atomic_json(inputs_path, frozen))
                        state.update(inputs_path=inputs_path, inputs_sha256=file_sha256(inputs_path))
                    else:
                        operation("inputs_postcheck", lambda: verify_inputs(context, frozen))
                    record["immutable_inputs"] = {
                        "path": str(state["inputs_path"]), "sha256": state["inputs_sha256"]}
                    checkpoint_path = workspace.root / "custody" / stage.variant / (key + ".checkpoint.json")
                    digest = operation("checkpoint", lambda: checkpoint_seed(context, checkpoint_path))
                    update = {"inputs": frozen, "checkpoint_path": checkpoint_path,
                              "checkpoint_sha256": digest}
                    record["checkpoint"] = {"path": str(checkpoint_path), "sha256": digest}
                    if stage.seals:
                        manifest_path = workspace.root / "custody" / stage.variant / "sealed.json"
                        seal_hash = operation("seal", lambda: seal_seed(context, manifest_path))
                        operation("sealed_inputs_postcheck", lambda: verify_inputs(context, frozen))
                        update.update(manifest_path=manifest_path, manifest_sha256=seal_hash)
                        record["seal"] = {"path": str(manifest_path), "sha256": seal_hash}
                    state.update(update)
        except Exception as error:
            record.update(passed=False, reason=f"stage_{type(error).__name__}:{error}", outcome="error")
        record["duration_seconds"] = time.monotonic() - started
        if time.monotonic() > deadline:
            record.update(passed=False, outcome="timeout", reason="deadline_including_staging_exceeded")
        if not record["passed"] and stage is not None and stage.kind is StageKind.PRODUCER:
            state = states.get(stage.variant, {})
            invalid = state.pop("manifest_path", None)
            state.pop("manifest_sha256", None)
            if stage.seals:
                invalid = invalid or (workspace.root / "custody" / stage.variant / "sealed.json")
                if invalid.exists():
                    invalid.unlink()
            record.pop("seal", None)
        return record

    with ThreadPoolExecutor(max_workers=workers) as executor:
        while pending or running:
            changed = True
            while changed:
                changed = False
                for node in pending[:]:
                    stage = stages.get(owners[node])
                    for dependency in stage.depends_on if stage is not None else ():
                        dependencies = by_obligation[dependency]
                        if all(item in records for item in dependencies) and any(
                                not records[item]["passed"] for item in dependencies):
                            records[node] = blocked(node, f"prerequisite_failed_or_incomplete:{dependency}", dependency)
                            pending.remove(node)
                            changed = True
                            break
            for node in pending[:]:
                if len(running) >= workers:
                    break
                stage = stages.get(owners[node])
                dependencies = stage.depends_on if stage is not None else ()
                if not all(all(item in records and records[item]["passed"] for item in by_obligation[dependency])
                           for dependency in dependencies):
                    continue
                if time.monotonic() >= suite_end - _CLEANUP_SECONDS:
                    records[node] = blocked(node, "suite_deadline_has_no_execution_budget")
                else:
                    running[executor.submit(execute, node)] = node
                pending.remove(node)
            if running:
                finished, _ = wait(running, return_when=FIRST_COMPLETED)
                for future in finished:
                    node = running.pop(future)
                    try:
                        records[node] = future.result()
                    except Exception as error:
                        records[node] = blocked(node, f"case_dispatch_{type(error).__name__}:{error}")
            elif pending:
                for node in pending:
                    records[node] = blocked(node, "prerequisite_incomplete", stages[owners[node]].depends_on[0])
                pending.clear()
    return [records[node] for node in collected]


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
    try:
        entries = {entry["id"]: entry for entry in inventory["obligations"]}
        if len(entries) != len(inventory["obligations"]):
            raise ValueError("duplicate acceptance obligation identity")
        # Empty deferred profiles remain explicit failures at execution, not malformed chains.
        stages = _stage_graph(entries, selected) if selected else {}
        nodes = tuple(node for obligation in selected for node in entries[obligation]["nodes"])
        if len(nodes) != len(set(nodes)):
            raise ValueError("duplicate acceptance node selection")
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
            result["source_identities"] = _source_identities(
                root, nodes, json.loads(acceptance_environment(workspace)["APPSEC_ACCEPTANCE_STATIC_INPUTS"]),
                staged=bool(stages))
            source_manifest = workspace.root / "source-identities.json"
            atomic_json(source_manifest, result["source_identities"])
            result["source_manifest"] = {"path": str(source_manifest), "sha256": file_sha256(source_manifest)}
            # Keep the environment bounded on Windows. The exact manifest binds every helper
            # and core module; expose the boundary modules individually as well.
            boundary_sources = {
                "appsec-review.toml", "tests/conftest.py", "tests/acceptance_plugin.py",
                "deploy/dagster/bin/ops_tests.py",
                *(node.split("::", 1)[0] for node in nodes),
                *(path.relative_to(root).as_posix()
                  for path in (root / "src" / "appsec_review" / "acceptance").glob("*.py")),
            }
            result["stage_source_identities"] = {
                "source-manifest": result["source_manifest"]["sha256"],
                **{name: result["source_identities"][name] for name in sorted(boundary_sources)},
            }
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
                    owners = _collected_owners(entries, selected, collected, stages)
                    result["cases"] = _execute_acceptance_cases(
                        python, workspace, collected, owners, entries, stages, result,
                        suite_end=suite_end, per_case=per_case, workers=spec.workers)
            for obligation in selected:
                required = entries[obligation]["nodes"]
                cases = [case for case in result["cases"] if any(_matches(node, case["node"]) for node in required)]
                executed = cases and all(
                    any(_matches(node, case["node"]) and (case["pytest"] or {}).get("cases")
                        for case in cases) for node in required)
                if obligation in stages:
                    executed = bool(cases) and all(
                    any(item["node"] == case["node"] for item in (case["pytest"] or {}).get("cases", []))
                    for case in cases)
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
            _verify_sources(root, result["source_identities"])
            if result["failed_obligations"]:
                result["failures"].append("required_obligations_failed")
        except Exception as error:
            result["failures"].append(f"harness_{type(error).__name__}")
            result["failure_details"] = str(error)
        for obligation in selected:
            if obligation not in result["executed_obligations"] and obligation not in result["failed_obligations"]:
                result["failed_obligations"].append(obligation)
        result["blocked_obligations"] = [
            obligation for obligation in selected if any(
                case.get("obligation_id") == obligation and case["outcome"] == "blocked"
                for case in result["cases"])]
        result["executed_nodes"] = [
            case["node"] for case in result["cases"]
            if any(item["node"] == case["node"] for item in (case["pytest"] or {}).get("cases", []))]
        result["unexecuted_nodes"] = [
            node for node in result["collected_nodes"] if node not in result["executed_nodes"]]
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
