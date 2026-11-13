"""Coverage is execution-only, bounded to one package, and never a report verdict."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from tests import operator_support  # noqa: F401 (operator module path)
import ops
import ops_test_guard as guard
import ops_tests


PACKAGE = "appsec_review.coverage_sample"
TOTALS = {
    "covered_lines": 8, "num_statements": 10, "missing_lines": 2,
    "covered_branches": 3, "num_branches": 4, "missing_branches": 1,
}


def arguments(*options):
    args = ops.build_parser().parse_args(["run-tests", *options])
    args.extra = ["tests/test_inert.py"]
    return args


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    (root / "tests").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ncache_dir = "test/tmp/.pytest_cache"\n')
    (root / "tests/test_inert.py").write_text(
        "from appsec_review.coverage_sample import choose\n"
        "def test_one(): assert choose(True) == 1\n"
        "def test_two(): assert choose(True) == 1\n")
    package = root / "src/appsec_review"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "coverage_sample.py").write_text(
        "def choose(flag):\n    if flag:\n        return 1\n    return 2\n")
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    monkeypatch.delenv("COVERAGE_FILE", raising=False)
    return root


def receipt(root):
    paths = list((root / "test/tmp/reports").glob("*.json"))
    assert len(paths) == 1
    return json.loads(paths[0].read_bytes())


def unexpected_process(*args, **kwargs):
    pytest.fail("refusal must precede every subprocess, including dependency probes")


@pytest.mark.parametrize("package", [
    "", "other", "appsec_review_extra.job", "appsec_reviewx", ".appsec_review",
    "appsec_review.", "appsec_review..jobs", "appsec_review/jobs", "appsec_review.*",
    "appsec_review.job-name", "appsec_review.1job", "appsec_review.class",
    "appsec_review.jobs;echo bad", "appsec_review.jobs\n", " appsec_review.jobs",
])
def test_invalid_package_never_starts_a_process(checkout, monkeypatch, capsys, package):
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    assert ops_tests.run(arguments("--coverage", package), checkout) == 2
    assert "must be a dotted module name under appsec_review" in capsys.readouterr().err
    assert not (checkout / "test").exists()


@pytest.mark.parametrize("extra", [
    ["--cov"], ["--cov=appsec_review"], ["--cov", PACKAGE], ["--cov-branch"],
    ["--cov-report=json:elsewhere"], ["--cov-fail-under=100"], ["--cov-append"],
    ["--cov-config=elsewhere"], ["-p", "no:cacheprovider"], ["-pno:cacheprovider"],
])
def test_raw_coverage_and_cache_options_remain_refused(checkout, monkeypatch, extra):
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    args = arguments("--coverage", PACKAGE)
    args.extra += extra
    assert ops_tests.run(args, checkout) == 2
    assert not (checkout / "test").exists()


@pytest.mark.parametrize("option", ["--cov", "--cov=appsec_review", "--cov-branch", "--cov-report=json:x",
                                  "--cover", "--coverag", "-p"])
def test_raw_flags_and_coverage_abbreviations_are_not_wrapper_options(monkeypatch, option):
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    with pytest.raises(SystemExit) as error:
        arguments(option, PACKAGE)
    assert error.value.code == 2


def test_no_option_retains_existing_wrapper_abbreviations():
    args = arguments("--para", "--test-w", "2", "--str", "--coll", "15")
    assert args.parallel and args.strict and args.test_workers == 2 and args.collection_seconds == 15
    assert args.coverage is None


def test_coverage_cannot_silently_disappear_in_acceptance(checkout, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    monkeypatch.setattr(ops_tests, "run_acceptance", unexpected_process)
    assert ops_tests.run(arguments("--coverage", PACKAGE, "--acceptance", "quick"), checkout) == 2
    assert "--coverage cannot combine with --acceptance" in capsys.readouterr().err


@pytest.mark.parametrize("failure", ["missing", "os-error", "timeout"])
def test_dependency_failure_refuses_before_collection(checkout, monkeypatch, capsys, failure):
    calls = []

    def probe(command, **kwargs):
        calls.append((command, kwargs))
        if failure == "os-error":
            raise OSError("probe unavailable")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 1, "", "ModuleNotFoundError: pytest_cov")

    monkeypatch.setattr(subprocess, "run", probe)
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    assert ops_tests.run(arguments("--coverage", PACKAGE), checkout) == 2
    assert "--coverage requires importable pytest_cov" in capsys.readouterr().err
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == [sys.executable, "-c", "import pytest_cov"]
    assert kwargs["cwd"] == checkout
    assert kwargs["env"]["PYTHONPATH"] == str(checkout / "src")
    assert not (checkout / "test").exists()


@pytest.mark.parametrize("package", ["appsec_review", "appsec_review.jobs.job_one", "appsec_review._job2"])
def test_valid_package_dry_run_checks_dependency_only(checkout, monkeypatch, capsys, package):
    calls = []

    def probe(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", probe)
    monkeypatch.setattr(subprocess, "Popen", unexpected_process)
    assert ops_tests.run(arguments("--coverage", package, "--dry-run"), checkout) == 0
    output = capsys.readouterr().out
    assert f"--cov={package} --cov-branch --cov-report=json:test/tmp/" in output
    assert calls == [[sys.executable, "-c", "import pytest_cov"]]
    assert not (checkout / "test").exists()


@pytest.mark.parametrize("parallel", [False, True], ids=["serial", "parallel"])
def test_inert_execution_adds_exact_arguments_and_environment_only(checkout, monkeypatch, parallel):
    calls = []
    supervise = guard.supervise

    def record(command, root, environment, *args, **kwargs):
        calls.append((command.copy(), environment.copy()))
        return supervise(command, root, environment, *args, **kwargs)

    monkeypatch.setattr(guard, "supervise", record)
    options = ["--parallel", "--test-workers", "2"] if parallel else []
    args = arguments("--coverage", PACKAGE, "--expect-tests", "2", *options)
    assert ops_tests.run(args, checkout) == 0
    saved = receipt(checkout)
    collection, execution = calls
    command = execution[0]
    base = next(arg.split("=", 1)[1] for arg in command if arg.startswith("--basetemp="))
    assert command[-3:] == [f"--cov={PACKAGE}", "--cov-branch", f"--cov-report=json:{base}.coverage.json"]
    expected_collection = command[:-3]
    if parallel:
        index = expected_collection.index("-n")
        assert expected_collection[index:index + 2] == ["-n", "2"]
        del expected_collection[index:index + 2]
    assert collection[0] == [*expected_collection, "--collect-only"]
    assert "COVERAGE_FILE" not in collection[1]
    assert execution[1]["COVERAGE_FILE"] == base + ".coverage"
    assert {key: value for key, value in execution[1].items() if key not in {"COVERAGE_FILE", guard.CONTROL_ENV}} == {
        key: value for key, value in collection[1].items() if key != guard.CONTROL_ENV}
    assert json.loads(collection[1][guard.CONTROL_ENV])["stage"] == "collect"
    assert json.loads(execution[1][guard.CONTROL_ENV])["stage"] == "execute"
    assert (checkout / (base + ".coverage")).is_file()
    payload = json.loads((checkout / (base + ".coverage.json")).read_bytes())
    assert saved["report"]["coverage"]["totals"] == {
        key: payload["totals"][key] for key in TOTALS}
    assert saved["report"]["coverage"]["totals"]["missing_branches"] == 1
    assert saved["report"]["counts"] == {"passed": 2}
    assert all(stage["cleanup"]["confirmed"] for stage in saved["stages"].values())


@pytest.fixture
def fixed_report():
    return {
        "counts": {"passed": 2}, "elapsed_s": 0.1, "junit": "test/tmp/run.junit.xml",
        "junit_present": True, "slow": [], "failures": [], "ran": [],
    }


def render(report):
    return ops_tests.render_report(
        report, log=Path("test/tmp/run.log"), timings=Path("test/tmp/run.timings.sqlite"),
        diff=None, baseline=None)


def test_report_reads_canned_totals_and_adds_exactly_two_lines(tmp_path, fixed_report):
    path = tmp_path / "session.coverage.json"
    path.write_text(json.dumps({"totals": {**TOTALS, "percent_covered": 73.123}}))
    before = render(fixed_report)
    fixed_report["coverage"] = ops_tests.coverage_report(path)
    assert fixed_report["coverage"] == {"json": str(path), "totals": TOTALS}
    lines = render(fixed_report).splitlines()
    assert lines[5:7] == [
        f"coverage JSON: {path}",
        "coverage totals: lines 8/10 (missing 2), branches 3/4 (missing 1)",
    ]
    assert "\n".join(lines[:5] + lines[7:]) == before


def test_zero_totals_are_reported_without_inventing_coverage(tmp_path, fixed_report):
    path = tmp_path / "session.coverage.json"
    path.write_text(json.dumps({"totals": {key: 0 for key in TOTALS}}))
    fixed_report["coverage"] = ops_tests.coverage_report(path)
    assert "coverage totals: lines 0/0 (missing 0), branches 0/0 (missing 0)" in render(fixed_report)


@pytest.mark.parametrize("payload", [
    b"{", b"\xff", b"[]", b"null", b"{}", b'{"totals": []}',
    json.dumps({"totals": {**TOTALS, "num_branches": "4"}}).encode(),
    json.dumps({"totals": {**TOTALS, "missing_branches": False}}).encode(),
    json.dumps({"totals": {**TOTALS, "missing_lines": -1}}).encode(),
    json.dumps({"totals": {**TOTALS, "covered_lines": 10}}).encode(),
    json.dumps({"totals": {**TOTALS, "covered_branches": 4}}).encode(),
], ids=["json", "encoding", "list", "null", "absent", "totals-list", "string", "bool", "negative",
        "line-sum", "branch-sum"])
def test_malformed_coverage_is_unavailable_not_zero(tmp_path, fixed_report, payload):
    path = tmp_path / "session.coverage.json"
    path.write_bytes(payload)
    fixed_report["coverage"] = ops_tests.coverage_report(path)
    assert "totals" not in fixed_report["coverage"]
    assert f"coverage JSON: {path}\ncoverage totals: unavailable (" in render(fixed_report)


@pytest.mark.parametrize("directory", [False, True], ids=["missing", "unreadable"])
def test_missing_or_unreadable_json_is_named(tmp_path, fixed_report, directory):
    path = tmp_path / "session.coverage.json"
    if directory:
        path.mkdir()
    fixed_report["coverage"] = ops_tests.coverage_report(path)
    error = "IsADirectoryError" if directory else "FileNotFoundError"
    assert f"coverage totals: unavailable ({error}:" in render(fixed_report)


@pytest.mark.parametrize("failure", [False, True], ids=["passed", "failed"])
@pytest.mark.parametrize("damage", ["missing", "malformed"])
def test_report_error_preserves_success_or_failure(checkout, monkeypatch, capsys, failure, damage):
    if failure:
        (checkout / "tests/test_inert.py").write_text("def test_one(): assert False\n")
    supervise = guard.supervise

    def damage_report(command, root, environment, *args, **kwargs):
        result = supervise(command, root, environment, *args, **kwargs)
        if "--collect-only" not in command:
            path = root / next(arg.split("json:", 1)[1] for arg in command if arg.startswith("--cov-report="))
            if damage == "missing":
                path.unlink(missing_ok=True)
            else:
                path.write_text("{")
        return result

    monkeypatch.setattr(guard, "supervise", damage_report)
    assert ops_tests.run(arguments("--coverage", PACKAGE, "--strict"), checkout) == int(failure)
    saved = receipt(checkout)
    output = capsys.readouterr().out
    assert "coverage totals: unavailable (" in output
    assert saved["exit_code"] == int(failure)
    assert len(saved["report"]["failures"]) == int(failure)
    if failure:
        assert "FAILED tests/test_inert.py::test_one" in output
        assert "E " in output


def test_collection_refusal_with_coverage_remains_a_refusal(checkout, capsys):
    assert ops_tests.run(arguments("--coverage", PACKAGE, "--expect-tests", "1"), checkout) == 2
    saved = receipt(checkout)
    assert set(saved["stages"]) == {"collection"}
    assert saved["exit_code"] == 2
    assert saved["report"]["coverage"]["error"].startswith("FileNotFoundError:")
    assert "coverage totals: unavailable (" in capsys.readouterr().out


def test_no_option_command_and_fixed_report_remain_byte_identical(checkout, fixed_report):
    args = arguments("--shuffle-seed", "42", "--test-workers", "2")
    for parallel in (False, True):
        assert ops_tests.build_command(checkout, args, "python", "stamp", parallel) == [
            "python", "-m", "pytest", "-q", "-rfE", "--basetemp=test/tmp/tests-custom-stamp",
            "--junitxml=test/tmp/tests-custom-stamp.junit.xml", "-o", "junit_family=legacy",
            *(["-n", "2"] if parallel else []), "--shuffle-seed=42", "tests/test_inert.py",
        ]
    assert render(fixed_report) == (
        "counts: 2 passed\nelapsed: 0.1 s\nlog: test/tmp/run.log\n"
        "junit: test/tmp/run.junit.xml\ntimings: test/tmp/run.timings.sqlite\n"
        "slower than 10s: none\nfailures: 0")


def test_no_option_never_probes_or_adds_coverage_state(checkout, monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", unexpected_process)
    assert ops_tests.run(arguments(), checkout) == 0
    saved = receipt(checkout)
    assert "coverage" not in saved["report"]
    assert not any(arg.startswith("--cov") for arg in saved["command"])
    assert "coverage JSON:" not in capsys.readouterr().out
    assert not list((checkout / "test/tmp").glob("*.coverage*"))


def test_powershell_declares_coverage_for_shared_argument_translation():
    source = (operator_support.REPOSITORY / "scripts/run-tests.ps1").read_text()
    assert "[string]$Coverage," in source
    assert "Invoke-Ops -Name 'run-tests' -Bound $PSBoundParameters" in source


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh unavailable; PowerShell runtime parity not exercised")
def test_powershell_coverage_reaches_the_python_execution_command():
    root = operator_support.REPOSITORY
    result = subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(root / "scripts/run-tests.ps1"),
         "-Coverage", PACKAGE, "-Parallel", "-TestWorkers", "2", "-DryRun",
         "-Extra", "tests/test_ops_tests_coverage.py"],
        cwd=root, env={**os.environ, "APPSEC_PYTHON": sys.executable, "APPSEC_REPO_ROOT": str(root)},
        capture_output=True, text=True, timeout=8)
    assert result.returncode == 0, result.stdout + result.stderr
    command = shlex.split(next(line[2:] for line in result.stdout.splitlines() if line.startswith("+ ")))
    assert command[-3:-1] == [f"--cov={PACKAGE}", "--cov-branch"]
    assert command[-1].startswith("--cov-report=json:test/tmp/tests-custom-")
    assert command[command.index("-n") + 1] == "2"
