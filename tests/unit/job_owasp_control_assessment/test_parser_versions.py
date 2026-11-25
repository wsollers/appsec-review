"""D5/D6 (run 2026-11-16-0005): declared parser versions equal the implemented ones; coverage is typed."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tomllib
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_owasp_control_assessment.job import _validate_config, coverage_disposition
from appsec_review.owasp_workbench.versions import implemented_parser_versions

ROOT = Path(__file__).resolve().parents[3]


def declared_versions() -> dict:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    return document["jobs"]["job_owasp_control_assessment"]["settings"]["parser_versions"]


def test_central_toml_declares_exactly_the_implemented_parser_versions() -> None:
    implemented = implemented_parser_versions()
    assert declared_versions() == implemented
    # T-5002: budget the rendered envelope and bind assessment inputs to their obligations.
    assert implemented == {"component_rules": "2", "applicability_rules": "4", "batching_rules": "2",
                           "evidence_binding": "5", "subject_selection": "2", "result_validator": "4"}


@pytest.mark.parametrize("change", [
    {"applicability_rules": "3"}, {"evidence_binding": "3"}, {"component_rules": "1"},
    {"extra_rule": "1"}, "drop",
])
def test_input_validation_refuses_a_stale_or_foreign_declared_version(change) -> None:
    from tests.test_owasp_assessment_job import _base_app_config
    config = _base_app_config().job("job_owasp_control_assessment")
    versions = dict(config.settings["parser_versions"])
    if change == "drop":
        versions.pop("result_validator")
    else:
        versions.update(change)
    stale = replace(config, settings={**config.settings, "parser_versions": versions})
    with pytest.raises(ValueError, match="parser_versions must declare the implemented rule versions"):
        _validate_config(SimpleNamespace(config=stale, repository_root=ROOT), None)
    _validate_config(SimpleNamespace(config=config, repository_root=ROOT), None)


def row(**overrides) -> dict:
    return {"applicability": "not_applicable", "coverage_completeness": "not_applicable",
            "control_status": "not_assessed", **overrides}


def test_coverage_disposition_is_partial_for_unresolved_rows_gaps_or_failures() -> None:
    assert coverage_disposition([row()]) == "complete"
    assert coverage_disposition([row(applicability="applicable", coverage_completeness="complete",
                                     control_status="satisfied")]) == "complete"
    assert coverage_disposition([row(applicability="cannot_determine", coverage_completeness="unresolved")]) == "partial"
    assert coverage_disposition([row(applicability="unsupported_missing_evidence")]) == "partial"
    assert coverage_disposition([row(applicability="applicable", control_status="cannot_verify")]) == "partial"
    assert coverage_disposition([row()], gaps=True) == "partial"
    assert coverage_disposition([row()], failed=True) == "partial"
    assert coverage_disposition([]) == "complete"
