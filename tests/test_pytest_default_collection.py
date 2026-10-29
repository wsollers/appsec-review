from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize(("arguments", "imported", "passed"), [
    ((), (), 1),
    (("-k", "unit"), (), 1),
    (("tests/test_unit.py",), (), 1),
    (("tests/integration",), ("integration/test_integration_selected.py",), 1),
    (("tests/live/test_provider_selected.py",), ("live/test_provider_selected.py",), 1),
    (("tests/test_live_selected.py::test_selected",), ("test_live_selected.py",), 1),
    (("tests", "--ignore=tests/live", "--ignore-glob=tests/test_live_*.py"),
     ("integration/test_integration_selected.py",), 2),
    (("tests/live", "tests/test_live_selected.py", "tests/integration"),
     ("integration/test_integration_selected.py", "live/test_provider_selected.py", "test_live_selected.py"), 3),
], ids=["default", "keyword", "unit-file", "integration-dir", "live-file", "live-node", "offline", "live-suite"])
def test_collection_scope(tmp_path: Path, arguments, imported, passed):
    root = tmp_path / "p"
    tests = root / "tests"
    tests.mkdir(parents=True)
    (tests / "conftest.py").write_text(
        Path(__file__).with_name("conftest.py").read_text(encoding="utf-8"), encoding="utf-8")
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
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *arguments],
        cwd=root, env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"{passed} passed" in result.stdout, result.stdout
    assert {
        relative for relative in on_demand if (tests / relative).with_suffix(".imported").exists()
    } == set(imported)
