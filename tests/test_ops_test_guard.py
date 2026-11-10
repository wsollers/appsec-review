"""Inert subprocesses exercise the actual selector, collection and deadline guards."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from tests import operator_support  # noqa: F401 (operator module path)
import ops
import ops_test_guard as guard
import ops_tests


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "checkout"
    (root / "tests").mkdir(parents=True)
    (root / "pyproject.toml").write_text("[tool.pytest.ini_options]\n")
    (root / "tests/test_inert.py").write_text("def test_one(): pass\n\ndef test_two(): pass\n")
    return root


def invoke(root, *argv):
    options, extra = argv[:argv.index("--")], argv[argv.index("--") + 1:]
    args = ops.build_parser().parse_args(["run-tests", *options])
    args.extra = list(extra)
    return ops_tests.run(args, root)


def receipt(root):
    paths = sorted((root / "test/tmp/reports").glob("*.json"))
    assert len(paths) == 1
    return json.loads(paths[0].read_bytes())


@pytest.mark.parametrize("selector", [".", "./", "tests", "tests/", "tests/*.py", "tests/test_*.py",
                                      "tests/missing.py", "tests/test_inert.py.", "tests/test_inert.py::",
                                      "tests/test_inert.py::test_one::", "tests/../tests/test_inert.py"])
def test_rejects_nonexact_selectors_before_starting_processes(checkout, selector, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("selector refusal must not start any process")
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    assert invoke(checkout, "--", "tests/test_inert.py", selector) == 2
    assert not (checkout / "test").exists()


def test_resolved_scope_and_node_ids(checkout, tmp_path):
    outside = tmp_path / "test_foreign.py"
    outside.write_text("def test_no(): pass\n")
    (checkout / "tests/test_link.py").symlink_to(outside)
    for selector in (str(outside), str(checkout), "tests/test_link.py"):
        with pytest.raises(ValueError, match="existing, unredirected"):
            guard.focused_arguments(checkout, [selector])
    node = "tests/test_inert.py::test_one[literal.*?]"
    assert guard.focused_arguments(checkout, [node])[1] == [node]


@pytest.mark.parametrize("option,value", [("-k", "."), ("-m", "unit and not slow"), ("--maxfail", "1"),
                                         ("--tb", "short"), ("--shuffle-seed", "42")])
def test_option_operands_are_not_selectors(checkout, option, value):
    expected = ([option, value, "tests/test_inert.py"], ["tests/test_inert.py"])
    assert guard.focused_arguments(checkout, [option, value, "tests/test_inert.py"]) == expected
    assert guard.focused_arguments(checkout, [f"{option}={value}", "tests/test_inert.py"]) == expected


@pytest.mark.parametrize("arguments", [["-k", "x"], ["--pyargs", "tests"], ["-o", "addopts=."],
                                      ["--rootdir=."], ["-p", "no:ops_test_guard"], ["-k"],
                                      ["-n", "4"], ["--"], ["tests/test_inert.py", "tests/test_inert.py"]])
def test_missing_selectors_and_scope_overrides_fail(checkout, arguments):
    with pytest.raises(ValueError):
        guard.focused_arguments(checkout, arguments)


def test_heavy_tiers_require_explicit_manual_selection(checkout):
    for tier in ("integration", "live", "acceptance"):
        directory = checkout / "tests" / tier
        directory.mkdir()
        path = directory / "test_heavy.py"
        path.write_text("raise AssertionError('must not import')\n")
        selector = path.relative_to(checkout).as_posix()
        with pytest.raises(ValueError, match="heavy-tier"):
            guard.focused_arguments(checkout, [selector])
        if tier != "acceptance":
            assert guard.focused_arguments(checkout, [selector], allow_heavy=True)[1] == [selector]
        else:
            with pytest.raises(ValueError, match="--acceptance"):
                guard.focused_arguments(checkout, [selector], allow_heavy=True)


@pytest.mark.parametrize("changes", [{"max_tests": 0}, {"expect_tests": 0}, {"expect_tests": 201},
                                    {"timeout_seconds": float("inf")}, {"collection_seconds": float("nan")},
                                    {"timeout_seconds": -1}])
def test_invalid_budgets_are_refused(changes):
    with pytest.raises(ValueError):
        guard.Limits(**changes)


@pytest.mark.parametrize("parallel", [False, True])
def test_real_preflight_and_execution_match_count_and_scope(checkout, monkeypatch, parallel):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    options = ["--parallel", "--test-workers", "2"] if parallel else []
    assert invoke(checkout, *options, "--expect-tests", "2", "--", "tests/test_inert.py") == 0
    report = receipt(checkout)
    assert report["report"]["counts"] == {"passed": 2}
    assert report["selectors"] == ["tests/test_inert.py"]
    assert report["limits"] == asdict(guard.Limits(expect_tests=2))
    manifest = json.loads(Path(report["collection_manifest"]).read_bytes())
    assert manifest == {"nodes": ["tests/test_inert.py::test_one", "tests/test_inert.py::test_two"], "count": 2}
    assert all(stage["cleanup"]["confirmed"] for stage in report["stages"].values())


@pytest.mark.parametrize("options", [("--expect-tests", "1"), ("--max-tests", "1")])
def test_unexpected_collection_never_executes_or_writes_success_baseline(checkout, monkeypatch, options):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    (checkout / "tests/test_inert.py").write_text("def test_one(): assert False\n\ndef test_two(): assert False\n")
    baseline = checkout / "baseline.txt"
    baseline.write_text("tests/test_inert.py::test_one\n")
    assert invoke(checkout, *options, "--baseline", str(baseline), "--write-baseline", str(baseline),
                  "--", "tests/test_inert.py") == 2
    report = receipt(checkout)
    assert set(report["stages"]) == {"collection"}
    assert "unexpected collection count 2" in Path(report["log"]).read_text()
    assert baseline.read_text() == "tests/test_inert.py::test_one\n"


def test_empty_or_partly_empty_selection_is_refused(checkout, monkeypatch):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    (checkout / "tests/test_empty.py").write_text("")
    assert invoke(checkout, "--", "tests/test_inert.py", "tests/test_empty.py") == 2
    assert "selector collected no tests" in Path(receipt(checkout)["log"]).read_text()


@pytest.mark.parametrize("parallel", [False, True])
def test_execution_collection_drift_is_refused_before_test_body(checkout, monkeypatch, parallel):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    (checkout / "tests/test_inert.py").write_text(
        "import json, os\n"
        f"stage = json.loads(os.environ[{guard.CONTROL_ENV!r}])['stage']\n"
        "def test_one(): raise AssertionError('body must never run')\n"
        "if stage == 'execute':\n"
        "    def test_extra(): raise AssertionError('body must never run')\n")
    options = ["--parallel", "--test-workers", "2"] if parallel else []
    baseline = checkout / "empty-baseline.txt"
    baseline.write_text("")
    assert invoke(checkout, *options, "--baseline", str(baseline), "--", "tests/test_inert.py") == 2
    report = receipt(checkout)
    assert "execution collection differs from inspected preflight" in Path(report["log"]).read_text()
    assert not report["report"]["ran"]


@pytest.mark.parametrize("phase", ["collection", "execution"])
def test_total_deadline_kills_only_owned_tree_and_keeps_diagnostics(checkout, monkeypatch, phase):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    source = "import subprocess, sys, time\n"
    body = ("child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
            "print('owned-child', child.pid, flush=True)\ntime.sleep(60)\n")
    source += body if phase == "collection" else "def test_wait():\n" + "".join("    " + line + "\n" for line in body.splitlines())
    (checkout / "tests/test_inert.py").write_text(source)
    outsider = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        started = time.monotonic()
        assert invoke(checkout, "--timeout-seconds", "2", "--collection-seconds", "2",
                      "--", "tests/test_inert.py", "-s") == 124
        assert time.monotonic() - started < 3
        assert outsider.poll() is None
        report = receipt(checkout)
        stopped = report["stages"][phase]
        assert stopped["outcome"] == "timeout"
        assert stopped["cleanup"]["confirmed"]
        assert stopped["cleanup"]["observed_processes"] >= 3
        assert stopped["cleanup"]["remaining_processes"] == 0
        assert Path(report["collection_log"]).is_file() and Path(report["log"]).is_file()
    finally:
        outsider.terminate()
        outsider.wait(timeout=1)


def test_ambient_scope_and_unsupervised_background_are_refused(checkout, monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", ".")
    assert invoke(checkout, "--", "tests/test_inert.py") == 2
    monkeypatch.delenv("PYTEST_ADDOPTS")
    assert invoke(checkout, "--background", "--", "tests/test_inert.py") == 2
    assert not (checkout / "test").exists()


@pytest.mark.parametrize("failure", ["empty", "import-error"])
def test_empty_collection_and_collection_import_error_never_execute(checkout, monkeypatch, failure):
    monkeypatch.setenv("APPSEC_PYTHON", sys.executable)
    if failure == "import-error":
        (checkout / "tests/test_inert.py").write_text("raise RuntimeError('inert import failure')\n")
    options = ["-k", "absent"] if failure == "empty" else []
    assert invoke(checkout, "--", "tests/test_inert.py", *options) == 2
    assert set(receipt(checkout)["stages"]) == {"collection"}


@pytest.mark.parametrize("option,value", [("--max-tests", "200"), ("--expect-tests", "1"),
                                         ("--collection-seconds", "30"), ("--timeout-seconds", "120")])
def test_focused_controls_cannot_silently_override_acceptance_budget(checkout, monkeypatch, option, value):
    def unexpected(*args, **kwargs):
        pytest.fail("must refuse before entering acceptance supervisor")
    monkeypatch.setattr(ops_tests, "run_acceptance", unexpected)
    assert invoke(checkout, "--acceptance", "quick", option, value, "--") == 2


def test_resolved_collection_scope_is_verified_before_execution(checkout):
    (checkout / "tests/test_other.py").write_text("def test_other(): pass\n")
    with pytest.raises(ValueError, match="outside requested selectors"):
        guard.check_collection(checkout, ["tests/test_other.py::test_other"], ["tests/test_inert.py"],
                               guard.Limits(), allow_heavy=False)
    with pytest.raises(ValueError, match="duplicate"):
        guard.check_collection(checkout, ["tests/test_inert.py::test_one"] * 2, ["tests/test_inert.py"],
                               guard.Limits(), allow_heavy=False)


def test_exhausted_total_budget_retains_refusal_report_without_starting_pytest(checkout, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("exhausted budget must not start pytest")
    monkeypatch.setattr(subprocess, "Popen", unexpected)
    assert invoke(checkout, "--timeout-seconds", "0.000001", "--", "tests/test_inert.py") == 124
    report = receipt(checkout)
    assert report["stages"]["collection"]["outcome"] == "timeout"
    assert "pid" not in report["stages"]["collection"]["cleanup"]
    assert report["stages"]["collection"]["cleanup"]["confirmed"]
    assert Path(report["log"]).is_file()
