"""Manual only: installed quality tools and CLI in a wholly isolated repository."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from tests.quality.support import repository, write


def test_quality_command_runs_end_to_end_without_optional_live_tools(tmp_path: Path) -> None:
    root = repository(tmp_path / "quality", copy_tools=True)
    for suite in ("integration", "acceptance", "live"):
        write(root, f"tests/{suite}/test_forbidden.py", "raise RuntimeError('must not collect')\n")
    binaries = root / "test" / "tmp" / "only-git"
    binaries.mkdir(parents=True)
    git_binary = shutil.which("git")
    assert git_binary is not None
    (binaries / "git").symlink_to(git_binary)
    result = subprocess.run(
        [sys.executable, "-m", "tools.quality", "check", "--full"],
        cwd=root, env={**os.environ, "PATH": str(binaries)}, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "PASS"
    assert report["units"] == report["static_checks"] == "PASS"
    assert report["integration_acceptance_live"] == "NOT RUN"
    assert set(report["selectors"]) == {"tests/test_fixture.py", "tests/test_contract.py"}
    assert report["legacy_findings"] == 0


def test_quality_command_missing_selector_is_an_explicit_error(tmp_path: Path) -> None:
    root = repository(tmp_path / "quality", copy_tools=True)
    (root / "tests/test_fixture.py").unlink()
    result = subprocess.run(
        [sys.executable, "-m", "tools.quality", "check"],
        cwd=root, capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["category"] == "missing-input"
