from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.report import build_report
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_openvex_export.contracts import json_body
from tests.openvex_support import ROOT, example_bundle, make_verified_inputs


REFERENCE = {"path": "data/accepted.json", "sha256": "a" * 64}


def report_gate(*, empty=False):
    return json_body(make_verified_inputs(() if empty else ("publishable",)).gate)


def export_view(state):
    available = state in {"available", "no_statements"}
    bundle = example_bundle(make_verified_inputs(() if state == "no_statements" else ("publishable",)))
    return {
        "state": state, "reason": f"OpenVEX export is {state}; no target-safety assertion.",
        "handoff": dict(REFERENCE) if available else None,
        "result": bundle.result_ref.reference.to_json() if available else None,
        "manifest": bundle.manifest_ref.reference.to_json() if available else None,
        "document": bundle.document_ref.reference.to_json() if state == "available" else None,
        **{key: bundle.result[key] if available else None
           for key in ("statement_count", "included_findings", "excluded_findings")},
    }


@pytest.mark.parametrize("state", ["not_run", "stale", "no_statements"])
def test_missing_or_empty_export_is_an_explicit_publication_gap_not_a_claim_change(state):
    gate = report_gate(empty=state == "no_statements")
    original = deepcopy(gate)
    report = build_report(gate, gate_handoff=REFERENCE, gate_document=REFERENCE, openvex=export_view(state))
    assert gate == original
    assert report["openvex_export"]["state"] == state
    assert report["status"]["publication"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert report["status"]["review_complete"] is False
    assert report["limitations"] == [*gate["limitations"], {
        "limitation_id": f"openvex_export_{state}", "kind": "gap",
        "statement": export_view(state)["reason"], "count": 0,
    }]
    assert report["summary"]["package_counts"] == gate["package_counts"]
    assert report["summary"]["ship_block"] == gate["ship_block"]
    assert report["findings"] == [item for item in gate["packages"] if item["bucket"] == "publishable"]
    assert report["verification_backlog"] == report["withheld"] == []
    assert SchemaSet(ROOT / "docs" / "schemas" / "final-report").errors("final-report", report) == []


@pytest.mark.parametrize("state", ["disabled", "available"])
def test_disabled_and_available_exports_do_not_introduce_a_review_gap(state):
    gate = report_gate()
    report = build_report(gate, gate_handoff=REFERENCE, gate_document=REFERENCE,
                          openvex=export_view(state))
    assert report["status"]["publication"] == gate["status"]
    assert report["status"]["review_complete"] is True
    assert report["limitations"] == gate["limitations"]
    assert SchemaSet(ROOT / "docs" / "schemas" / "final-report").errors("final-report", report) == []


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
