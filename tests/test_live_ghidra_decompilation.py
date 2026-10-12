"""Real-container efficacy run for the Ghidra path: compile the fixture, decompile it, score it.

Skipped unless Docker and the pinned ``tool-ghidra`` and ``tool-native-cpp`` images are locally
available. Run it explicitly with a short base temp so bind-mount sources stay shallow:

    python -m pytest tests/test_live_ghidra_decompilation.py --basetemp=test/tmp/ghidra-live
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.binary_decompilation import efficacy, load_table, verify_publication
from appsec_review.container_runtime import load_catalog


ROOT = Path(__file__).resolve().parents[1]


def _images_available() -> bool:
    if not shutil.which("docker"):
        return False
    catalog = load_catalog(ROOT)
    for tool_id in ("tool-ghidra", "tool-native-cpp"):
        try:
            probe = subprocess.run(["docker", "image", "inspect", catalog.tool(tool_id).tag],
                                   capture_output=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return False
        if probe.returncode != 0:
            return False
    return True


@pytest.mark.skipif(not _images_available(), reason="pinned Ghidra and native images are not locally available")
def test_fixture_variants_meet_their_expected_efficacy(tmp_path_factory) -> None:
    work = tmp_path_factory.getbasetemp() / "ghidra"
    report = efficacy.run_efficacy(repository_root=ROOT, config_path=ROOT / "appsec-review.toml",
                                   work_root=work, force=True)
    assert report["accepted"], report
    symbols, stripped = report["variants"]["symbols"], report["variants"]["stripped"]
    assert symbols["score"] == stripped["score"] == 1.0 and symbols["gaps"] == stripped["gaps"] == {}
    # Stripping loses both function names; the sink is still found through the import call edge.
    lost = {check["id"] for check in stripped["checks"] if not check["passed"]}
    assert {"lost-function-main", "lost-function-print-label"} <= lost
    assert all(not check["required"] for check in stripped["checks"] if not check["passed"])

    root = Path(symbols["publication"])
    manifest = verify_publication(root)
    assert manifest["tool"]["ghidra_version"] == manifest["tool"]["version"]
    assert manifest["program"]["executable_format"] == "Executable and Linking Format (ELF)"
    assert manifest["execution"]["limits"]["network"] == "none"
    sink = next(row for row in load_table(root, "functions") if row["name"] == "print_label")
    text = (root / sink["pseudo_c"]["path"]).read_text(encoding="utf-8")
    assert "strcpy(label,input);" in text and "char label [32];" in text
