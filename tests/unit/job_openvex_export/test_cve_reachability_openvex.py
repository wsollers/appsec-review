"""Focused unit tests for CVE/OSV + PURL OpenVEX v0.2.0 reachability & coverage honesty."""
from __future__ import annotations

import pytest

from appsec_review.jobs.job_openvex_export import (
    NOT_IN_EXECUTE_PATH,
    classify_cve_reachability,
    construct_purl,
    extract_vulnerability_identity,
    project_dependency_advisories_to_openvex,
    validate_cve_openvex_document,
)


def test_cve_osv_identity_and_purl_binding_validates_against_openvex_v020() -> None:
    primary, iri, aliases, desc = extract_vulnerability_identity({
        "advisory_id": "GHSA-xxxx-yyyy-zzzz",
        "cve_ids": ["CVE-2024-3094"],
        "aliases": ["OSV-2024-111"],
        "summary": "Backdoor in upstream lzma archive",
    })
    assert primary == "CVE-2024-3094"
    assert iri == "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
    assert aliases == ("GHSA-xxxx-yyyy-zzzz", "OSV-2024-111")
    assert "lzma" in desc

    assert construct_purl({"ecosystem": "npm", "package_name": "@babel/traverse", "version": "7.23.0"}) == (
        "pkg:npm/%40babel/traverse@7.23.0"
    )
    assert construct_purl({"ecosystem": "python", "package_name": "cryptography", "version": "41.0.1"}) == (
        "pkg:pypi/cryptography@41.0.1"
    )

    advisories = [
        {
            "cve_id": "CVE-2024-11111",
            "aliases": ["GHSA-1111-2222-3333"],
            "ecosystem": "python",
            "package_name": "jinja2",
            "version": "3.1.2",
            "fixed_version": "3.1.4",
            "reachability": "symbol_reachable",
            "reachable_symbols": ["jinja2.Environment.from_string"],
            "coverage_complete": True,
        },
        {
            "cve_id": "CVE-2024-22222",
            "aliases": ["GHSA-4444-5555-6666"],
            "purl": "pkg:npm/%40babel/traverse@7.23.0",
            "reachability": "unreachable_in_target",
            "coverage_complete": True,
        },
        {
            "cve_id": "CVE-2024-33333",
            "purl": "pkg:cargo/mio@0.8.8",
            "reachability": "unreachable_in_target",
            "coverage_complete": False,
            "gaps": ["rust_mir_extractor_unavailable"],
        },
    ]
    b1 = project_dependency_advisories_to_openvex(
        advisories,
        product_id="https://github.com/example/service",
        timestamp="2026-05-01T12:00:00Z",
    )
    b2 = project_dependency_advisories_to_openvex(
        list(reversed(advisories)),
        product_id="https://github.com/example/service",
        timestamp="2026-05-01T12:00:00Z",
    )
    assert b1.document_bytes == b2.document_bytes
    assert b1.statements_by_status == {
        "affected": 1,
        "not_affected": 1,
        "under_investigation": 1,
    }
    assert b1.telemetry["openvex.cve_statements_by_status"] == b1.statements_by_status
    assert b1.document is not None
    validate_cve_openvex_document(b1.document)

    stmts = {s["vulnerability"]["name"]: s for s in b1.document["statements"]}
    assert stmts["CVE-2024-11111"]["status"] == "affected"
    assert "3.1.4" in stmts["CVE-2024-11111"]["action_statement"]
    assert stmts["CVE-2024-11111"]["vulnerability"]["aliases"] == ["GHSA-1111-2222-3333"]
    assert stmts["CVE-2024-11111"]["products"][0]["subcomponents"][0]["identifiers"]["purl"] == "pkg:pypi/jinja2@3.1.2"

    assert stmts["CVE-2024-22222"]["status"] == "not_affected"
    assert stmts["CVE-2024-22222"]["justification"] == NOT_IN_EXECUTE_PATH

    assert stmts["CVE-2024-33333"]["status"] == "under_investigation"
    assert "justification" not in stmts["CVE-2024-33333"]
    assert len(b1.gaps) == 1
    assert b1.gaps[0]["schema"] == "appsec-review/producer-gap/1"


@pytest.mark.parametrize(
    "incomplete_kwargs",
    [
        {"coverage_complete": False},
        {},  # coverage_complete omitted -> must never assume full coverage!
        {"coverage_complete": True, "has_coverage_gaps": True},
        {"coverage_complete": True, "gaps": ["tree_sitter_timeout"]},
        {"coverage_complete": True, "resolution_tier": "syntactic_fallback"},
        {"coverage_complete": True, "coverage_status": "partial"},
    ],
)
def test_never_claims_not_affected_when_coverage_has_gaps(incomplete_kwargs: dict) -> None:
    record = {
        "cve_id": "CVE-2025-99999",
        "purl": "pkg:golang/golang.org/x/net@v0.17.0",
        "reachability": "unreachable_in_target",
        **incomplete_kwargs,
    }
    decision = classify_cve_reachability(record)
    assert decision.status == "under_investigation"
    assert decision.status != "not_affected"
    assert decision.justification is None
    assert decision.has_coverage_gap is True

    # Also verify run-level coverage gap overrides advisory-level coverage_complete=True
    run_gap_decision = classify_cve_reachability(
        {
            "cve_id": "CVE-2025-99999",
            "purl": "pkg:golang/golang.org/x/net@v0.17.0",
            "reachability": "unreachable_in_target",
            "coverage_complete": True,
        },
        run_has_coverage_gaps=True,
    )
    assert run_gap_decision.status == "under_investigation"
    assert run_gap_decision.justification is None
