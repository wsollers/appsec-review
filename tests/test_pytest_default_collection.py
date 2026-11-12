from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from appsec_review.config.host_pins import HOST_PINS_ENV


@pytest.mark.parametrize(("arguments", "imported", "passed"), [
    ((), (), 1),
    (("-o", "testpaths="), (), 1),
    (("-k", "unit"), (), 1),
    (("tests/test_unit.py",), (), 1),
    (("tests/integration",), ("integration/test_integration_selected.py",), 1),
    (("tests/live/test_provider_selected.py",), ("live/test_provider_selected.py",), 1),
    (("tests/test_live_selected.py::test_selected",), ("test_live_selected.py",), 1),
    (("tests", "--ignore=tests/live", "--ignore-glob=tests/test_live_*.py"),
     ("integration/test_integration_selected.py",), 2),
    (("tests/live", "tests/test_live_selected.py", "tests/integration"),
     ("integration/test_integration_selected.py", "live/test_provider_selected.py", "test_live_selected.py"), 3),
], ids=["default", "fallback", "keyword", "unit-file", "integration-dir", "live-file", "live-node", "offline", "live-suite"])
def test_collection_scope(tmp_path: Path, arguments, imported, passed):
    root = tmp_path / "p"
    tests = root / "tests"
    tests.mkdir(parents=True)
    for harness in ("conftest.py", "time_budgets.py", "host_pins_support.py"):
        (tests / harness).write_text(
            Path(__file__).with_name(harness).read_text(encoding="utf-8"), encoding="utf-8")
    # The harness writes inert unit-test host pins from the project's own configuration and image
    # catalog, so the isolated project carries the real ones.
    repository = Path(__file__).resolve().parents[1]
    for document in ("appsec-review.toml", "containers/catalog.toml"):
        (root / document).parent.mkdir(parents=True, exist_ok=True)
        (root / document).write_bytes((repository / document).read_bytes())
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        'addopts = "--basetemp=test/tmp"\ncache_dir = "test/tmp/.pytest_cache"\n',
        encoding="utf-8")
    (tests / "test_unit.py").write_text("def test_unit(): assert True\n", encoding="utf-8")
    on_demand = ("integration/test_integration_selected.py", "live/test_provider_selected.py", "test_live_selected.py")
    for relative in on_demand:
        path = tests / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "from pathlib import Path\n"
            "Path(__file__).with_suffix('.imported').write_text('imported', encoding='utf-8')\n"
            "def test_selected(): assert True\n", encoding="utf-8")
    # The outer session's fixture host pins live under the outer scratch root; the isolated project
    # is its own session and its harness refuses a binding from outside its own test/tmp.
    environment = {key: value for key, value in os.environ.items() if key != HOST_PINS_ENV}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *arguments],
        cwd=root, env={**environment, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"{passed} passed" in result.stdout, result.stdout
    assert {
        relative for relative in on_demand if (tests / relative).with_suffix(".imported").exists()
    } == set(imported)
