from __future__ import annotations

from dataclasses import replace
import importlib.metadata
import json
from pathlib import Path
import subprocess

import pytest

from tools.quality import process, runner
from tools.quality.__main__ import main
from tools.quality.baseline import baseline_json, finding
from tools.quality.config import GateError, load_config
from tests.quality.support import git, repository, write


@pytest.mark.parametrize(("failure", "category"), [
    (FileNotFoundError("absent"), "missing-tool"),
    (subprocess.TimeoutExpired("fixture", 1), "timeout"),
    (PermissionError("denied"), "tool-error"),
])
def test_process_failure_classification(tmp_path: Path, monkeypatch, failure, category: str) -> None:
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(process.subprocess, "run", fail)
    with pytest.raises(GateError) as caught:
        process.run(["fixture"], tmp_path, 1)
    assert caught.value.category == category


def test_nonzero_and_no_tests_exit_are_failures(tmp_path: Path, monkeypatch) -> None:
    for code in (1, 2, 5, -9):
        monkeypatch.setattr(process.subprocess, "run",
                            lambda *args, **kwargs: subprocess.CompletedProcess(args[0], code, "", "failure"))
        with pytest.raises(GateError, match="tool-failure"):
            process.run(["fixture"], tmp_path, 1)


def test_required_tool_missing_or_wrong_version_fails(tmp_path: Path, monkeypatch) -> None:
    root = repository(tmp_path / "repo")
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(runner.importlib.metadata, "version", missing)
    with pytest.raises(GateError, match="missing-tool"):
        runner.require_tools(root)
    monkeypatch.setattr(runner.importlib.metadata, "version", lambda name: "0.0.0")
    with pytest.raises(GateError, match="tool-version"):
        runner.require_tools(root)


@pytest.mark.parametrize(("tool", "output", "code"), [
    ("ruff", "[]", 1), ("ruff", "not json", 0), ("ruff", "{}", 0),
    ("mypy", "", 1), ("mypy", '{"severity": "unexpected"}', 0),
    ("bandit", '{"errors": [{"filename": "unscanned"}], "results": []}', 0),
    ("bandit", '{"results": []}', 0), ("bandit", '{"errors": [], "results": []}', 1),
])
def test_bad_or_incomplete_tool_reports_never_pass(tmp_path: Path, tool: str, output: str, code: int) -> None:
    with pytest.raises(GateError):
        runner.tool_findings(tmp_path, tool, output, code)


@pytest.mark.parametrize("tool", ["ruff", "mypy", "bandit"])
def test_tool_diagnostics_resolve_source_and_reject_contradictory_success(tmp_path: Path, tool: str) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/runtime/contract.py"
    rows = {
        "ruff": {"filename": str(root / path), "location": {"row": 1}, "code": "F821", "message": "fixture"},
        "mypy": {"file": path, "line": 1, "code": "return-value", "message": "fixture", "severity": "error"},
        "bandit": {"filename": path, "line_number": 1, "test_id": "B307", "issue_text": "fixture"},
    }
    output = json.dumps(rows[tool] if tool == "mypy" else (
        {"errors": [], "results": [rows[tool]]} if tool == "bandit" else [rows[tool]]
    ))
    items = runner.tool_findings(root, tool, output, 1)
    assert len(items) == 1 and items[0].path == path and items[0].fingerprint
    with pytest.raises(GateError, match="exit status"):
        runner.tool_findings(root, tool, output, 0)


def test_diagnostic_paths_accept_tool_dot_prefix_but_not_escapes(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    path = "src/appsec_review/runtime/contract.py"
    assert runner.diagnostic_path(root, "./" + path) == path
    with pytest.raises(GateError):
        runner.diagnostic_path(root, "../outside.py")


def test_static_scope_includes_new_code_and_excludes_deleted_and_manual_tests(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    config = load_config(root)
    write(root, "src/appsec_review/new.py", "value = 1\n")
    write(root, "tests/integration/test_manual.py", "raise RuntimeError('never import')\n")
    write(root, "src/appsec_review/obsolete.py", "value = 0\n")
    git(root, "add", "src/appsec_review/obsolete.py")
    (root / "src/appsec_review/obsolete.py").unlink()
    paths = runner.source_files(root, config)
    assert "src/appsec_review/new.py" in paths
    assert "src/appsec_review/obsolete.py" not in paths
    assert not any(path.startswith("tests/") for path in paths)
    with pytest.raises(GateError, match="contains no Python"):
        runner.source_files(root, replace(config, source_roots=("empty",)))
    (root / "src/appsec_review/signing/core.py").unlink()
    with pytest.raises(GateError, match="required architecture modules"):
        runner.source_files(root, config)


def test_baseline_uses_previous_config_and_refuses_path_bypass(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    config = load_config(root)
    assert runner.baseline_at_base(root, "HEAD", config) == ()
    with pytest.raises(GateError, match="moving the baseline"):
        runner.baseline_at_base(root, "HEAD", replace(config, baseline="quality/other.json"))


def test_baseline_growth_fails_before_static_tools(tmp_path: Path, monkeypatch) -> None:
    root = repository(tmp_path / "repo")
    config = load_config(root)
    item = finding(root, "src/appsec_review/runtime/contract.py", "ruff:F821", "fixture", 1)
    write(root, config.baseline, baseline_json((item,), "try to absorb a defect"))
    monkeypatch.setattr(runner, "require_tools", lambda root: None)
    with pytest.raises(GateError, match="baseline-growth"):
        runner.check(root, config, base="HEAD", full=False, static_only=True, units_only=False)


@pytest.mark.parametrize(("body", "passes"), [
    ("def test_ok():\n    assert True\n", True),
    ("value = 1\n", False),
    ("import pytest\n@pytest.mark.skip(reason='unavailable')\ndef test_skip():\n    pass\n", False),
    ("import pytest\n@pytest.mark.xfail(reason='known')\ndef test_xfail():\n    assert False\n", False),
])
def test_pytest_guard_requires_executed_coverage_per_selected_file(tmp_path: Path, body: str, passes: bool) -> None:
    root = repository(tmp_path / "repo", copy_tools=True)
    config = load_config(root)
    write(root, "tests/test_fixture.py", body)
    write(root, "tests/integration/test_never.py", "raise RuntimeError('implicit manual suite')\n")
    write(root, "tests/acceptance/test_never.py", "raise RuntimeError('implicit manual suite')\n")
    write(root, "tests/live/test_never.py", "raise RuntimeError('implicit manual suite')\n")
    if passes:
        output, _ = runner.run_units(root, config, config.unit_tests)
        assert "1 passed" in output
    else:
        with pytest.raises(GateError, match="tool-failure"):
            runner.run_units(root, config, config.unit_tests)


def test_each_selector_must_collect_tests_even_if_another_passes(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo", copy_tools=True)
    config = load_config(root)
    write(root, "tests/test_contract.py", "value = 1\n")
    with pytest.raises(GateError, match="coverage mismatch"):
        runner.run_units(root, config, config.unit_tests + config.contract_tests)


def test_configured_deselection_cannot_pass_partial_file_coverage(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo", copy_tools=True)
    config = load_config(root)
    path = root / "pyproject.toml"
    path.write_text(path.read_text().replace("--basetemp=test/tmp", "--basetemp=test/tmp -k fixture"))
    with pytest.raises(GateError, match="tool-failure"):
        runner.run_units(root, config, config.unit_tests + config.contract_tests)


def test_no_selectors_and_missing_selectors_are_errors(tmp_path: Path) -> None:
    root = repository(tmp_path / "repo")
    config = load_config(root)
    with pytest.raises(GateError, match="no-tests"):
        runner.run_units(root, config, ())
    with pytest.raises(GateError, match="missing-input"):
        runner.run_units(root, config, ("tests/test_absent.py",))


def test_cli_configuration_error_is_structured_nonzero(tmp_path: Path, capsys) -> None:
    write(tmp_path, "pyproject.toml", "broken [")
    assert main(["--root", str(tmp_path), "check"]) == 2
    report = json.loads(capsys.readouterr().err)
    assert report["status"] == "ERROR" and report["category"] == "configuration"


def test_prune_never_initializes_or_absorbs_new_diagnostics(tmp_path: Path, monkeypatch, capsys) -> None:
    root = repository(tmp_path / "repo")
    item = finding(root, "src/appsec_review/runtime/contract.py", "ruff:F821", "new", 1)
    monkeypatch.setattr("tools.quality.__main__.static_checks", lambda root, config: ((item,), {}, 1))
    assert main(["--root", str(root), "baseline", "--initialize", "--reason", "overwrite"]) == 2
    assert main(["--root", str(root), "baseline", "--prune", "--reason", "remove fixed entries"]) == 0
    assert json.loads((root / "quality/baseline.json").read_text())["findings"] == []
