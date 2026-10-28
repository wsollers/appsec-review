from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.report import build_report


REFERENCE = {"path": "data/accepted.json", "sha256": "a" * 64}


def report_gate():
    return {
        "run_id": "2026-10-28-0001",
        "review": {
            "status": "COMPLETE", "review_incomplete": False,
            "accepted_manifest_sha256": "1" * 64, "configuration_sha256": "2" * 64,
            "ledger_head_sha256": "3" * 64, "ship_block_policy_sha256": "4" * 64,
        },
        "status": "PUBLISHABLE",
        "packages": [],
        "package_counts": {"total": 0, "publishable": 0, "verification_backlog": 0, "withheld": 0,
                           "exact": True},
        "accounting": {
            "claims_total": 0, "claims_by_state": {}, "gap_ratio": 0.0, "incomplete_gap_ratio": 0.2,
            "gaps_by_class": {},
        },
        "ship_block": {
            "policy": "ship-block-policy/1", "by_status": {"decision_pending": 0},
            "by_lane": {"lead": {}, "hunt": {}},
        },
        "coverage": {}, "limitations": [], "gap_ids": [],
        "inputs": {"review_handoff": dict(REFERENCE)},
    }


def export_view(state):
    available = state in {"available", "no_statements"}
    return {
        "state": state, "reason": f"OpenVEX export is {state}; no target-safety assertion.",
        "handoff": dict(REFERENCE) if available else None,
        "result": dict(REFERENCE) if available else None,
        "manifest": dict(REFERENCE) if available else None,
        "document": dict(REFERENCE) if state == "available" else None,
        "statement_count": 0 if available else None,
        "included_findings": 0 if available else None,
        "excluded_findings": 0 if available else None,
    }


@pytest.mark.parametrize("state", ["not_run", "stale", "no_statements"])
def test_missing_or_empty_export_is_an_explicit_publication_gap_not_a_claim_change(state):
    gate = report_gate()
    original = deepcopy(gate)
    report = build_report(gate, gate_handoff=REFERENCE, gate_document=REFERENCE, openvex=export_view(state))
    assert gate == original
    assert report["openvex_export"]["state"] == state
    assert report["status"]["publication"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert report["status"]["review_complete"] is False
    assert report["limitations"] == [{
        "limitation_id": f"openvex_export_{state}", "kind": "gap",
        "statement": export_view(state)["reason"], "count": 0,
    }]
    assert report["summary"]["package_counts"] == gate["package_counts"]
    assert report["summary"]["ship_block"] == gate["ship_block"]
    assert report["findings"] == report["verification_backlog"] == report["withheld"] == []


@pytest.mark.parametrize("state", ["disabled", "available"])
def test_disabled_and_available_exports_do_not_introduce_a_review_gap(state):
    report = build_report(report_gate(), gate_handoff=REFERENCE, gate_document=REFERENCE,
                          openvex=export_view(state))
    assert report["status"]["publication"] == "PUBLISHABLE"
    assert report["status"]["review_complete"] is True
    assert report["limitations"] == []


def test_historical_report_builder_remains_valid_without_the_optional_export_block():
    report = build_report(report_gate(), gate_handoff=REFERENCE, gate_document=REFERENCE)
    assert "openvex_export" not in report
    assert "## OpenVEX" not in render_markdown(report, evidence_ids=8, gap_ids=16)


def test_markdown_exposes_only_verified_references_and_escapes_text():
    view = export_view("available")
    view["reason"] = "<script>unsafe</script> [link](https://example.test)"
    view["document"] = {"path": "data/`evil`<script>.json", "sha256": "a" * 64}
    report = build_report(report_gate(), gate_handoff=REFERENCE, gate_document=REFERENCE, openvex=view)
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert "## OpenVEX impact statements" in markdown
    assert "\\<script\\>" in markdown
    assert "data/'evil'<script>.json" in markdown
    assert "SHA-256 `" + "a" * 64 + "`" in markdown
    assert "data/`evil`" not in markdown
    assert markdown == render_markdown(report, evidence_ids=8, gap_ids=16)
