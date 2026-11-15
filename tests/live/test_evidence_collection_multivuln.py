"""Live target-fixture applicability checks for job_evidence_collection against appsec-multi-vuln."""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.cataloging import inventory, source_fingerprint
from appsec_review.jobs.job_evidence_collection.adapters import ScanCatalog, adapter_registry


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.live
@pytest.mark.requires_target("appsec-multi-vuln")
def test_checkov_multi_vuln_scope_offers_every_admitted_input_and_leaves_recognition_to_checkov() -> None:
    target = ROOT / "targets" / "appsec-multi-vuln"
    snapshot = inventory(target)
    catalog = ScanCatalog(source_fingerprint(target), "a" * 64, tuple(snapshot["files"]), (), (), target)
    adapter = adapter_registry()["tool-checkov"]
    selected = adapter.applicability(catalog)
    assert selected.applicable
    assert any(path.endswith("Dockerfile") for path in selected.files)
    assert {".github/workflows/ci.yml", ".github/workflows/codeql.yml"} <= set(selected.files)
    assert "projects/python/case-078/config.yaml" in selected.files and "README.md" in selected.files
    argv = adapter.argv("/opt/tool/bin/checkov", selected)
    assert "--framework" not in argv


@pytest.mark.live
@pytest.mark.requires_target("appsec-multi-vuln")
def test_real_target_has_bounded_cpp_and_java_applicability() -> None:
    target = ROOT / "targets" / "appsec-multi-vuln"
    snapshot = inventory(target)
    catalog = ScanCatalog(source_fingerprint(target), "a" * 64, tuple(snapshot["files"]), (), (), target)
    cpp = adapter_registry()["tool-cppcheck"].applicability(catalog)
    java = adapter_registry()["tool-pmd"].applicability(catalog)
    assert cpp.applicable and all(
        Path(path).suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}
        for path in cpp.files
    )
    assert java.applicable and all(path.endswith(".java") for path in java.files)
