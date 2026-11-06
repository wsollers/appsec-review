from __future__ import annotations

import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys
import time
import tomllib
from uuid import uuid4

from .baseline import Finding, compare, decode_baseline, finding, require_shrink_only
from .boundaries import module_name, scan_boundaries
from .config import Config, GateError, checked_file, strings, table, unit_selector
from .process import run
from .selection import changed_paths, select_tests


def require_tools(root: Path) -> None:
    document = tomllib.loads(checked_file(root, "pyproject.toml").read_text(encoding="utf-8"))
    project = table(document.get("project"), "project")
    extras = table(project.get("optional-dependencies"), "project.optional-dependencies")
    requirements = strings(extras.get("quality"), "quality dependencies")
    pins = dict(item.split("==", 1) for item in requirements if "==" in item)
    for name in ("ruff", "mypy", "bandit", "pytest"):
        if name not in pins:
            raise GateError("configuration", f"quality tool must have an exact version pin: {name}")
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as error:
            raise GateError("missing-tool", f"install the locked quality environment; missing {name}") from error
        if version != pins[name] or importlib.util.find_spec(name) is None:
            raise GateError("tool-version", f"{name}: required {pins[name]}, installed {version}")


def source_files(root: Path, config: Config) -> tuple[str, ...]:
    result = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], root, config.timeout_seconds)
    paths = tuple(sorted({
        path for path in result.stdout.split("\0") if path.endswith(".py")
        and any(path.startswith(prefix + "/") for prefix in config.source_roots)
        and (root / path).exists()
    }))
    for prefix in config.source_roots:
        if not any(path.startswith(prefix + "/") for path in paths):
            raise GateError("missing-input", f"source scope contains no Python modules: {prefix}")
    for path in paths:
        checked_file(root, path)
    missing = (set(config.bootstrap_modules) | set(config.public_contracts)) - {module_name(path) for path in paths}
    if missing:
        raise GateError("missing-input", f"required architecture modules are unavailable: {sorted(missing)}")
    return paths


def diagnostic_path(root: Path, value: object) -> str:
    if not isinstance(value, str):
        raise GateError("tool-output", "diagnostic is missing its source filename")
    path = Path(value)
    if path.is_absolute():
        try:
            value = path.relative_to(root.resolve()).as_posix()
        except ValueError as error:
            raise GateError("tool-output", f"diagnostic escapes the repository: {value}") from error
    else:
        value = path.as_posix()
    checked_file(root, value)
    return value


def diagnostic(root: Path, row: dict[str, object], tool: str) -> Finding:
    path = diagnostic_path(root, row.get("file") if tool == "mypy" else row.get("filename"))
    if tool == "ruff":
        location = table(row.get("location"), "ruff location")
        line, rule, message = location.get("row"), row.get("code"), row.get("message")
        if rule is None:
            rule = "syntax"
    elif tool == "mypy":
        line, rule, message = row.get("line"), row.get("code"), row.get("message")
    else:
        line, rule, message = row.get("line_number"), row.get("test_id"), row.get("issue_text")
    if type(line) is not int or not isinstance(rule, str) or not isinstance(message, str):
        raise GateError("tool-output", f"{tool} produced an incomplete diagnostic")
    return finding(root, path, f"{tool}:{rule}", message, line)


def tool_findings(root: Path, tool: str, stdout: str, returncode: int) -> tuple[Finding, ...]:
    try:
        if tool == "mypy":
            values: object = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        elif tool == "bandit":
            document = table(json.loads(stdout), "bandit report")
            if document.get("errors") != []:
                raise GateError("tool-output", f"Bandit has unscanned/error files: {document.get('errors')}")
            values = document.get("results")
        else:
            values = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise GateError("tool-output", f"{tool} did not return valid JSON: {error}") from error
    if not isinstance(values, list):
        raise GateError("tool-output", f"{tool} report must contain a diagnostic list")
    result: list[Finding] = []
    for value in values:
        row = table(value, f"{tool} diagnostic")
        if tool == "mypy" and row.get("severity") == "note":
            continue
        if tool == "mypy" and row.get("severity") != "error":
            raise GateError("tool-output", "mypy diagnostic has unknown severity")
        result.append(diagnostic(root, row, tool))
    if (returncode == 1) != bool(result):
        raise GateError("tool-output", f"{tool} exit status and findings disagree")
    return tuple(result)


def static_checks(root: Path, config: Config) -> tuple[tuple[Finding, ...], dict[str, float], int]:
    require_tools(root)
    paths = source_files(root, config)
    findings: list[Finding] = []
    elapsed: dict[str, float] = {}
    commands = {
        "ruff": [sys.executable, "-m", "ruff", "check", "--ignore-noqa", "--output-format=json", "--", *paths],
        "mypy": [sys.executable, "-m", "mypy", "--config-file=pyproject.toml",
                 "--output=json", "--no-error-summary", "--no-incremental"],
        "bandit": [sys.executable, "-m", "bandit", "--format=json", "--quiet", "--ignore-nosec",
                   "--tests", ",".join(config.sast_rules), "--", *paths],
    }
    for tool, command in commands.items():
        started = time.monotonic()
        result = run(command, root, config.timeout_seconds, allowed=(0, 1))
        findings.extend(tool_findings(root, tool, result.stdout, result.returncode))
        elapsed[tool] = round(time.monotonic() - started, 3)
    started = time.monotonic()
    findings.extend(scan_boundaries(root, paths, config))
    elapsed["architecture"] = round(time.monotonic() - started, 3)
    return tuple(sorted(findings)), elapsed, len(paths)


def baseline_at_base(root: Path, base: str, config: Config) -> tuple[Finding, ...] | None:
    revision = run(["git", "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}"],
                   root, config.timeout_seconds).stdout.strip()
    previous_project = run(["git", "show", f"{revision}:pyproject.toml"], root, config.timeout_seconds).stdout
    previous_tools = table(tomllib.loads(previous_project).get("tool", {}), "base tool config")
    if "appsec-quality" not in previous_tools:
        return None
    old = table(previous_tools["appsec-quality"], "base quality config")
    if old.get("baseline") != config.baseline:
        raise GateError("baseline-growth", "moving the baseline cannot bypass its ratchet")
    text = run(["git", "show", f"{revision}:{config.baseline}"], root, config.timeout_seconds).stdout
    return decode_baseline(text)


def run_units(root: Path, config: Config, tests: tuple[str, ...]) -> tuple[str, float]:
    if not tests or len(set(tests)) != len(tests):
        raise GateError("no-tests", "unit selection is empty or duplicated")
    for path in tests:
        unit_selector(path)
        checked_file(root, path)
    started = time.monotonic()
    result = run(
        [sys.executable, "-m", "pytest", "-q", "-p", "tools.quality.pytest_guard",
         f"--basetemp=test/tmp/quality-{uuid4().hex}", *tests],
        root, config.timeout_seconds,
        environment={
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "",
            "APPSEC_QUALITY_TEST_FILES": json.dumps(tests),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    return result.stdout, round(time.monotonic() - started, 3)


def check(root: Path, config: Config, *, base: str, full: bool, static_only: bool, units_only: bool) -> dict[str, object]:
    require_tools(root)
    changes = changed_paths(root, base, config.timeout_seconds)
    selection = select_tests(config, changes, full=full)
    report: dict[str, object] = {
        "changes": changes, "selectors": selection.tests, "selection_reasons": selection.reasons,
        "coverage": "bounded offline contracts; not complete job coverage or a live security review",
        "integration_acceptance_live": "NOT RUN",
        "static_checks": "NOT RUN" if units_only else "pending",
        "units": "NOT RUN" if static_only else "pending",
    }
    if not units_only:
        baseline = decode_baseline(checked_file(root, config.baseline).read_text(encoding="utf-8"))
        previous = baseline_at_base(root, base, config)
        if previous is not None:
            require_shrink_only(baseline, previous)
        findings, timing, count = static_checks(root, config)
        differences = compare(findings, baseline)
        report.update(static_checks="FAIL" if differences else "PASS", diagnostics=differences,
                      legacy_findings=len(baseline), modules_scanned=count, static_seconds=timing,
                      baseline_policy="initial adoption; review seed" if previous is None else "shrink-only")
        if differences:
            report["status"] = "FAIL"
            return report
    if not static_only:
        output, duration = run_units(root, config, selection.tests)
        report.update(units="PASS", unit_seconds=duration, unit_output=output)
    report["status"] = "PASS"
    return report
