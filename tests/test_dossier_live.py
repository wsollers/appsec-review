"""Real XeLaTeX container acceptance, including Windows; never substitutes a mock PDF."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess

import pytest

from appsec_review.jobs.bound_artifacts import resolve_bound
from appsec_review.reporting.dossier_render import render_dossier
from tests.dossier_fixture import ROOT, make_model, settings

IMAGE = "appsec-review/tool-report-latex:1.0.0"


def image_id():
    if shutil.which("docker") is None:
        return None
    try:
        result = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                                capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    identity = result.stdout.decode().strip()
    return identity if result.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", identity) else None


@pytest.mark.parametrize("kind", ["confirmed_finding", "poc"])
def test_real_dossier_pdf_is_readable_complete_and_byte_reproducible(tmp_path, kind):
    identity = image_id()
    if identity is None:
        pytest.skip("Docker/the commissioned LaTeX image is unavailable")
    root = tmp_path / "r"
    model = make_model(root, kind)
    records = [render_dossier(root, root / "data" / name, model, settings=settings(image_id=identity),
                              repository_root=ROOT) for name in ("one", "two")]
    for record in records:
        assert record["status"] == "rendered", record
        for reference in record["files"].values():
            resolve_bound(root, reference)
        directory = root / record["files"]["pdf"]["path"]
        pdf = directory.read_bytes()
        assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
        info = (directory.parent / "report.pdfinfo.txt").read_text(encoding="utf-8")
        assert "A4" in info and int(re.search(r"Pages:\s+(\d+)", info).group(1)) >= 3
        text = (directory.parent / "report.txt").read_text(encoding="utf-8").replace("\uee55", "-")
        flattened = re.sub(r"\s+", " ", text)
        for expected in ("Synthetic document finding", "Finding brief", "Risk dimensions",
                         "Evidence and resolving source", "COMPILE VERIFIED ONLY", "NOT RUNTIME PROOF",
                         "not_performed_by_policy", "Remediation assurance", "static_checked",
                         "Not fixed, resolved, or regression verified", "Resolving provenance", "Seeded",
                         "safe_negative_control", "Enforcement linkage"):
            assert expected in flattened, (expected, flattened)
        assert "PRIVATE_PROMPT" not in text
        receipt = json.loads((directory.parent / "receipt.json").read_text())
        assert receipt["tool"]["image_id"] == identity
        execution = json.loads(resolve_bound(root, receipt["execution"]).read_text())
        for name in ("stdout_path", "stderr_path"):
            assert (root / execution[name]).is_file()
    first, second = [resolve_bound(root, record["files"]["pdf"]).read_bytes() for record in records]
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()
    assert records[0]["files"]["latex"]["sha256"] == records[1]["files"]["latex"]["sha256"]
