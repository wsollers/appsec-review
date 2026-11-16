"""Run 2026-11-15-0005 failed at dossier_publication/dossiers/create: ``template_identity`` hashed the repository's
LaTeX template through ``file_sha256``, whose customer-review guard refuses platform payload under ``src``,
``containers`` and ``rules`` while a run's ``review_scope`` is active. Unit tests never activate that scope, so the
fault reached the live run. Platform files have a hasher of their own; the guard on evidence stays."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from appsec_review.reporting.dossier_render import template_identity
from appsec_review.runtime.scope import review_scope
from appsec_review.storage import file_sha256, platform_file_sha256

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"


def test_template_identity_resolves_inside_an_active_review_scope(tmp_path: Path) -> None:
    run_root = tmp_path / "runs" / "2026-11-15-0005"
    run_root.mkdir(parents=True)
    with review_scope(ROOT, run_root, None):
        identity = template_identity(TEMPLATE)
        with pytest.raises(ValueError, match="excluded from customer review"):
            file_sha256(TEMPLATE / "appsec-report.cls")
    assert [item["name"] for item in identity["files"]] == ["appsec-report.cls", "appsec-palette.tex", "report-skeleton.tex"]
    expected = hashlib.sha256((TEMPLATE / "appsec-report.cls").read_bytes()).hexdigest()
    assert identity["files"][0]["sha256"] == expected == platform_file_sha256(TEMPLATE / "appsec-report.cls")
    assert identity == template_identity(TEMPLATE)


def test_platform_hasher_refuses_missing_or_symbolic_files(tmp_path: Path) -> None:
    target = tmp_path / "policy.toml"
    target.write_text("x = 1\n", encoding="utf-8")
    assert platform_file_sha256(target) == hashlib.sha256(b"x = 1\n").hexdigest()
    with pytest.raises(ValueError, match="missing or symbolic"):
        platform_file_sha256(tmp_path / "absent.toml")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="missing or symbolic"):
        platform_file_sha256(link)
