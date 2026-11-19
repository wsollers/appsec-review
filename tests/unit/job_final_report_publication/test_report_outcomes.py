"""Conservation of certified report inputs, unknown measurements and renderer outcomes."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.job_final_report_publication import JOB_ID, build_job
from appsec_review.jobs.job_final_report_publication.pdf import render_executive_latex, template_dir
from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.report import build_report, report_schema_name
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.observability.completion import completion_metrics
from appsec_review.reporting.dimensions import DOMAIN_IDS, build_radar_tracker, radar_telemetry
from appsec_review.reporting.executive_report import render_executive_html
from appsec_review.reporting.executive_posture import build_named_coverage_gaps
from appsec_review.reporting.latex import escape_latex
from appsec_review.review.identity import sha256_hex
from tests.unit.job_final_report_publication.test_job_units import _setup_run, fake_executor, run_units
from tests.unit.job_final_report_publication.test_report_and_render import _serialized_review, _validator
from tests.unit.review_decision_audit_wiring.helpers import HASH, verified_document

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "docs" / "schemas" / "final-report"
ADMITTED_CHAINS = json.loads((SCHEMAS / "common.schema.json").read_text())[
    "$defs"]["attachments"]["properties"]["attack_chains"]["maxItems"]


def _report(verified):
    gate = gate_classify.gate_document(
        FINAL_PUBLICATION_GATE_SCHEMA, verified, gate_classify.classify(verified))
    schemas = SchemaSet(SCHEMAS)
    schemas.validate("final-publication-gate", gate)
    report = build_report(
        gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": HASH},
        gate_document={"path": "data/gate.json", "sha256": HASH})
    return report, schemas


@pytest.mark.parametrize("with_findings", [False, True])
def test_absent_certified_reachability_is_unknown_not_a_measured_zero(tmp_path, with_findings):
    verified = _serialized_review(tmp_path, (("confirmed", "high"),) if with_findings else ())
    report, schemas = _report(verified)
    posture = report["executive_posture"]
    assert posture["reachable_supply_chain_advisories_count"] is None
    assert posture["reachable_supply_chain_gap_reasons"] == ["certified_reachability_unavailable"]
    schemas.validate(report_schema_name(report), report)
    _validator(report_schema_name(report)).validate(report)
    html = render_executive_html(report, ())
    latex = render_executive_latex(report, (), template_dir(ROOT)).decode()
    markdown = render_markdown(report, evidence_ids=0, gap_ids=0)
    assert "N/A" in html and escape_latex("N/A") in latex
    assert "reachable supply-chain advisories N/A" in markdown
    assert "No gate-certified advisory reachability measurement is available" in html
    assert escape_latex("No gate-certified advisory reachability measurement is available") in latex
    assert ">None<" not in html


@pytest.mark.parametrize("chain_count", [245, 1001, ADMITTED_CHAINS])
def test_every_admitted_active_chain_and_severity_gap_remains_representable(chain_count):
    verified = verified_document()
    members = [row["claim_id"] for row in verified["packages"]]
    verified["attachments"]["attack_chains"] = [
        {"chain_id": f"chain-{sha256_hex(str(index))}", "status": "qualified_supported",
         "component_claim_ids": members,
         "artifact": {"path": f"data/chains/{index}.json", "sha256": HASH},
         "gap_count": 0, "disposition": "assessed"}
        for index in range(chain_count)
    ]
    manifest = {"path": "data/chains.json", "sha256": HASH}
    verified["capabilities"]["attack_chains"] = capability(True, summary=manifest, count=chain_count)
    verified["bindings"].extend([manifest, *(row["artifact"] for row in verified["attachments"]["attack_chains"])])
    report, schemas = _report(verified)
    schemas.validate(report_schema_name(report), report)
    assert len(report["attack_chains"]["items"]) == chain_count
    assert len(report["attack_chain_cards"]) == chain_count
    assert report["attack_chains"]["status_counts"]["qualified_supported"] == chain_count
    gaps = [row for row in report["named_coverage_gaps"] if row["gap_id"].startswith("chain_severity_unrated:")]
    assert len(gaps) == chain_count
    assert {row["affected_scope"] for row in gaps} == {
        row["chain_id"] for row in report["attack_chain_cards"]}
    assert all(row["composed_severity"] == "unrated" for row in report["attack_chain_cards"])
    # Validate the maximum accepted gate limitations as well as the chain/axis gap rows.
    gate_bound = json.loads((SCHEMAS / "final-publication-gate.schema.json").read_text())[
        "properties"]["limitations"]["maxItems"]
    report["limitations"] = [
        {"limitation_id": f"gap_{index}", "kind": "gap", "statement": "A certified coverage gap.", "count": 1}
        for index in range(gate_bound)]
    report["named_coverage_gaps"] = build_named_coverage_gaps(report, report["radar_tracker"])
    schemas.validate(report_schema_name(report), report)
    assert len(report["named_coverage_gaps"]) == chain_count + gate_bound + len(DOMAIN_IDS)


@pytest.mark.parametrize("outcome", ["not_rendered", "render_failed", "rendered"])
def test_actual_report_events_retain_metrics_and_pdf_outcomes(tmp_path, monkeypatch, outcome):
    fx = _setup_run(tmp_path, monkeypatch, render_pdf=outcome != "not_rendered")
    factory = (lambda *_: pytest.fail("disabled renderer must not run")) if outcome == "not_rendered" else (
        fake_executor([], render_status=1, pdf=None) if outcome == "render_failed" else fake_executor([]))
    outputs = run_units(fx, build_job(executor_factory=factory))
    records = [{"job_id": JOB_ID, "event_type": event, "details": details} for event, details in fx.events.rows]
    metrics = completion_metrics(records)
    events = metrics["lanes"]["report_publication"]["events"]
    assembled = events["FINAL_REPORT_ASSEMBLED"]
    actual = fx.events.rows[0][1]
    for field in ("radar_verified_axes", "radar_gap_axes", "chain_elevated_count",
                  "remediation_roadmap_count", "named_gap_count"):
        assert assembled["counters"][field] == actual[field]
    assert assembled["measurements"]["coverage_confidence_score"] == {
        "count": 0, "unavailable": 1, "min": None, "max": None}
    assert assembled["measurements"]["reachable_supply_chain_advisories_count"] == {
        "count": 0, "unavailable": 1, "min": None, "max": None}
    assert assembled["qualifications"][
        "reachable_supply_chain_gap_reasons.certified_reachability_unavailable"] == 1
    for axis, counts in actual["radar_counts_by_axis_and_series"].items():
        for series, value in counts.items():
            assert assembled["measurements"][f"radar_counts_by_axis_and_series.{axis}.{series}"] == {
                "count": int(value is not None), "unavailable": int(value is None),
                "min": value, "max": value}
        for field in ("radar_gap_reasons_by_axis", "radar_metric_gap_reasons_by_axis"):
            for reason in actual[field][axis]:
                assert assembled["qualifications"][f"{field}.{axis}.{reason}"] == 1
    for name, value in actual["funnel_conversion_rates"].items():
        assert assembled["measurements"][f"funnel_conversion_rates.{name}"] == {
            "count": int(value is not None), "unavailable": int(value is None),
            "min": value, "max": value}
        for reason in actual["funnel_gap_reasons"][name]:
            assert assembled["qualifications"][f"funnel_gap_reasons.{name}.{reason}"] == 1
    assert events["FINAL_REPORT_PDF_RENDERED"]["outcomes"] == {outcome: 1}
    assert events["FINAL_REPORT_PUBLISHED"]["outcomes"] == {f"pdf.{outcome}": 1}
    assert outputs["acceptance.publish_handoff"]["pdf"]["state"] == outcome
    if outcome != "rendered":
        assert outputs["report.render_pdf"]["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert outputs["acceptance.publish_handoff"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert metrics["measurement_gap_count"] == 0
    assert completion_metrics(records + records)["lanes"]["report_publication"]["events"][
        "FINAL_REPORT_PDF_RENDERED"]["outcomes"] == {outcome: 2}
    assert json.loads(json.dumps(metrics)) == metrics


def test_snapshot_metrics_keep_measured_zero_and_ranges_not_summed_rates():
    report, _ = _report(verified_document())
    records = []
    for inspected in (0, 1):
        tracker = build_radar_tracker(report, domain_telemetry={
            domain: {"surface_exposure": 2, "inspected_units": inspected, "corroborated_leads": 0}
            for domain in DOMAIN_IDS})
        details = {key.removeprefix("reporting."): value for key, value in radar_telemetry(tracker).items()}
        details["coverage_confidence_score"] = tracker["coverage_confidence"]["confidence_score"]
        details["coverage_confidence_gap_reasons"] = tracker["coverage_confidence"]["gap_reasons"]
        records.append({"job_id": JOB_ID, "event_type": "FINAL_REPORT_ASSEMBLED", "details": details})
    result = completion_metrics(records)
    event = result["lanes"]["report_publication"]["events"]["FINAL_REPORT_ASSEMBLED"]
    assert event["measurements"]["coverage_confidence_score"] == {
        "count": 2, "unavailable": 0, "min": 0, "max": 50}
    assert event["measurements"]["funnel_conversion_rates.exposure_to_coverage_rate"] == {
        "count": 2, "unavailable": 0, "min": 0, "max": 0.5}
    assert event["measurements"]["funnel_conversion_rates.exposure_to_leads_rate"] == {
        "count": 2, "unavailable": 0, "min": 0, "max": 0}
    assert event["measurements"]["funnel_conversion_rates.leads_to_confirmed_rate"] == {
        "count": 0, "unavailable": 2, "min": None, "max": None}
    assert event["qualifications"]["funnel_gap_reasons.leads_to_confirmed_rate.denominator_empty"] == 2
    assert result["measurement_gap_count"] == 0


@pytest.mark.parametrize("field,value", [
    ("coverage_confidence_score", True),
    ("coverage_confidence_score", 101),
    ("reachable_supply_chain_advisories_count", 10**400),
    ("radar_counts_by_axis_and_series", {"untrusted-axis": {"surface_exposure": 0}}),
    ("radar_counts_by_axis_and_series", {"memory_safety_native": {"untrusted-series": 1}}),
    ("radar_counts_by_axis_and_series", {"memory_safety_native": {"surface_exposure": -1}}),
    ("radar_counts_by_axis_and_series", []),
    ("radar_metric_gap_reasons_by_axis", {"memory_safety_native": ["untrusted-reason"]}),
    ("radar_gap_reasons_by_axis", {"memory_safety_native": "surface_exposure_unknown"}),
    ("funnel_conversion_rates", {"exposure_to_coverage_rate": float("nan")}),
    ("funnel_conversion_rates", {"exposure_to_coverage_rate": float("inf")}),
    ("funnel_conversion_rates", {"exposure_to_coverage_rate": "0"}),
    ("funnel_gap_reasons", {"untrusted-rate": ["denominator_empty"]}),
], ids=["bool", "score-bound", "large-int", "axis", "series", "negative", "map-shape",
        "reason", "reason-shape", "nan", "infinity", "string", "rate"])
def test_report_measurement_failures_are_bounded_gaps_not_zero_or_untrusted_labels(field, value):
    result = completion_metrics([{"job_id": JOB_ID, "event_type": "FINAL_REPORT_ASSEMBLED",
                                  "details": {field: value}}])
    assert result["measurement_gap_count"] == 1
    event = result["lanes"]["report_publication"]["events"]["FINAL_REPORT_ASSEMBLED"]
    assert event["measurements"] == event["qualifications"] == {}
    assert "untrusted-" not in json.dumps(result)
