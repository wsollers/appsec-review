"""Manual only: introduce and remove lint/type/boundary/SAST defects in an isolated repo."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from tests.quality.support import repository, write


@pytest.mark.parametrize(("path", "source", "rule"), [
    ("src/appsec_review/defect.py", "value = undefined_name\n", "ruff:F821"),
    ("src/appsec_review/runtime/contract.py", "def contract(value: int) -> int:\n    return 'wrong'\n", "mypy:return-value"),
    ("src/appsec_review/defect.py", "from appsec_review.storage.atomic import _private\n", "ARCH:private-import"),
    ("src/appsec_review/defect.py", "value = eval('1 + 1')\n", "bandit:B307"),
])
def test_defect_is_rejected_then_clean_scope_passes(tmp_path: Path, path: str, source: str, rule: str) -> None:
    root = repository(tmp_path / "quality", copy_tools=True)
    file = root / path
    before = file.read_bytes() if file.exists() else None
    write(root, path, source)
    command = [sys.executable, "-m", "tools.quality", "check", "--full"]
    failed = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
    assert failed.returncode == 1, failed.stdout + failed.stderr
    assert any(rule in item for item in json.loads(failed.stdout)["diagnostics"])
    if before is None:
        file.unlink()
    else:
        file.write_bytes(before)
    clean = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=120)
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert json.loads(clean.stdout)["status"] == "PASS"
