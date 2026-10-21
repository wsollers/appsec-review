"""Render the synthetic run to PDF in the real image and check its structure. Skipped without Docker or the image."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

from .fixture import RUN_ID, build_fixture

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "appsec-review/tool-report-latex:1.0.0"


def _image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None or shutil.which("bash") is None or os.name == "nt":
        return False
    try:
        return subprocess.run([docker, "image", "inspect", IMAGE], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not _image_available(), reason="Docker or the tool-report-latex image is unavailable")


def _render(tmp_path: Path, name: str) -> Path:
    runs = tmp_path / "runs"
    if not runs.exists():
        build_fixture(runs)
    done = subprocess.run(["bash", str(ROOT / "scripts" / "render-report.sh"), "--run", RUN_ID, "--runs-dir", str(runs),
                           "--output-dir", str(tmp_path / name), "--format", "pdf"],
                          capture_output=True, text=True, timeout=600, env={**os.environ, "APPSEC_PYTHON": sys.executable})
    assert done.returncode == 0, done.stderr
    return Path(done.stdout.strip())


def _in_image(pdf: Path, *argv: str) -> str:
    done = subprocess.run(["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--user", "10001:10001",
                           "--mount", f"type=bind,src={pdf.parent},dst=/in,readonly", IMAGE, *argv],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    return done.stdout


def test_pdf_structure_and_content(tmp_path: Path) -> None:
    pdf = _render(tmp_path, "one")
    assert pdf.read_bytes().startswith(b"%PDF-")
    info = _in_image(pdf, "pdfinfo", f"/in/{pdf.name}")
    assert int(re.search(r"Pages:\s+(\d+)", info).group(1)) >= 8
    assert "Title:" in info and RUN_ID in info and "A4" in info
    text = _in_image(pdf, "pdftotext", "-layout", f"/in/{pdf.name}", "-")
    for expected in ("Security review report", RUN_ID, "EVIDENCE", "REQUEST", "MODEL", "RESULT", "FEEDBACK", "CLAIM", "COUNTER",
                     "VERIFIER", "GAP", "PROVENANCE", "Integer truncation after strtol", "forbidden_parameter",
                     "INSUFFICIENT EVIDENCE", "SUPPORTED", "Reading guide", "more rows, sha256", "U+4E2D"):
        assert expected in text, expected
    assert "passwd" in text  # hostile text is shown, escaped, not executed
    assert not (Path("/tmp/pwned")).exists()


def test_pdf_is_reproducible(tmp_path: Path) -> None:
    first = _render(tmp_path, "a")
    second = _render(tmp_path, "b")
    assert hashlib.sha256(first.read_bytes()).hexdigest() == hashlib.sha256(second.read_bytes()).hexdigest()
