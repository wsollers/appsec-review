from __future__ import annotations

import ast
from pathlib import Path
import re
import tomllib

import yaml

from tools.quality.config import load_config, unit_selector


ROOT = Path(__file__).resolve().parents[2]


def test_ci_is_unprivileged_and_runs_only_the_offline_gate() -> None:
    # BaseLoader preserves YAML 1.2's "on" key instead of coercing it to a YAML 1.1 Boolean.
    workflow = yaml.load((ROOT / ".github/workflows/quality.yml").read_text(), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request", "push"}
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert workflow["permissions"] == {"contents": "read"}
    for job in workflow["jobs"].values():
        assert job["runs-on"] == "ubuntu-24.04"
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"actions/[\w-]+@[0-9a-f]{40}", step["uses"])
            command = step.get("run", "")
            assert not any(value in command for value in ("tests/integration", "tests/acceptance", "tests/live",
                                                          "docker ", "dagster ", "pytest "))
            assert "secrets." not in str(step)
    checkout = workflow["jobs"]["quality"]["steps"][0]["with"]
    assert checkout == {"fetch-depth": "0", "persist-credentials": "false"}
    execution = workflow["jobs"]["quality"]["steps"][-1]
    assert execution["env"]["QUALITY_BASE"]
    assert "python -m tools.quality check" in execution["run"]


def test_repository_config_keeps_enforced_scope_and_explicit_safe_selectors() -> None:
    config = load_config(ROOT)
    document = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert document["tool"]["ruff"]["lint"]["select"] == ["E9", "F811", "F821", "F822", "F823"]
    assert not document["tool"]["ruff"]["lint"].get("ignore")
    assert not document["tool"]["ruff"]["lint"].get("per-file-ignores")
    assert document["tool"]["mypy"]["strict"] is True
    assert document["tool"]["mypy"]["follow_imports"] == "silent"
    assert not document["tool"]["mypy"].get("ignore_missing_imports")
    assert not document["tool"]["mypy"].get("overrides")
    assert not document["tool"]["mypy"].get("exclude")
    assert not document["tool"]["mypy"].get("ignore_errors")
    assert not document["tool"]["mypy"].get("disable_error_code")
    assert set(config.sast_rules) == {"B102", "B301", "B307", "B506", "B602"}
    assert set(config.type_files) >= {
        "src/appsec_review/runtime/job.py", "src/appsec_review/storage/atomic.py",
        "src/appsec_review/inference/request.py", "tools/quality",
    }
    for selector in config.unit_tests + config.contract_tests:
        assert unit_selector(selector) == selector
        tree = ast.parse((ROOT / selector).read_text())
        assert any(isinstance(node, ast.FunctionDef) and node.name.startswith("test_") for node in tree.body)
    assert not any(path.startswith(("tests/integration", "tests/acceptance", "tests/live"))
                   for path in config.unit_tests + config.contract_tests)


def test_pinned_tools_and_transitive_hash_lock_are_checked_in() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    pins = project["optional-dependencies"]["quality"]
    assert all(re.fullmatch(r"[\w-]+==[\d.]+", pin) for pin in pins)
    lock = (ROOT / "requirements/quality.lock").read_text()
    for pin in pins:
        assert pin in lock
    assert "--hash=sha256:" in lock
    assert all(re.match(r"^[a-zA-Z0-9_.-]+==", line)
               for line in lock.splitlines() if line and not line[0].isspace() and not line.startswith("#"))
