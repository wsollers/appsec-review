from copy import deepcopy
import json

import pytest
from jsonschema import ValidationError

from appsec_review.reporting.dimensions import DOMAIN_IDS, build_radar_tracker, dimension_counts, radar_telemetry
from appsec_review.reporting.executive_report import executive_document, render_executive_html
from appsec_review.reporting.model import RadarChart
from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.pdf import render_executive_latex
from appsec_review.jobs.job_final_report_publication.report import report_schema_name
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.reporting.dossiers import build_dossier
from appsec_review.reporting.executive_posture import (
    build_attack_chain_cards, build_executive_posture, build_remediation_roadmap,
)
from tests.unit.job_final_report_publication.test_report_and_render import (
    ROOT, SCHEMAS, _gate_and_report, _memory_axis, _serialized_review, _validator,
)
from tests.dossier_fixture import seed as dossier_seed
from tests.unit.reporting.test_executive_report import coverage_table


@pytest.mark.parametrize(
    "exposed,inspected,status,score,gaps",
    [
        (4, 0, "unverified_gap", 0.0, {"uninspected_exposed_units"}),
        (4, 2, "partial_coverage_gap", 50.0, {"uninspected_exposed_units"}),
        (4, 4, "verified_no_findings", 100.0, set()),
        (0, 0, "unverified_gap", None, {"no_domain_coverage_bound"}),
    ],
    ids=["not-inspected", "partial", "verified-empty-findings", "no-population"],
)
def test_only_explicit_inspected_population_can_verify_empty_findings(
    tmp_path, exposed, inspected, status, score, gaps,
):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, ()))
    assert _memory_axis(report)["coverage_status"] == "unverified_gap"
    report["radar_tracker"] = build_radar_tracker(
        report, domain_telemetry={"memory_safety_native": {"surface_exposure": exposed, "inspected_units": inspected}},
    )
    _validator(report_schema_name(report)).validate(report)
    axis = _memory_axis(report)
    assert axis["coverage_status"] == status
    assert gaps <= set(axis["gap_reasons"])
    assert axis["series"]["surface_exposure"]["raw_count"] == exposed
    assert axis["series"]["verified_coverage"]["raw_count"] == inspected
    assert axis["series"]["verified_coverage"]["score"] == score


@pytest.mark.parametrize("withheld", [False, True], ids=["unresolved-backlog", "withheld"])
def test_full_inspected_scope_does_not_clear_unresolved_packages(tmp_path, withheld):
    verified = _serialized_review(tmp_path, (("supported", "low"),))
    if withheld:
        verified["packages"][0]["attack_chains"] = ["chain-" + "a" * 64]
    _gate, report = _gate_and_report(verified)
    before = deepcopy(report["withheld"] if withheld else report["verification_backlog"])
    report["radar_tracker"] = build_radar_tracker(
        report, domain_telemetry={"memory_safety_native": {"surface_exposure": 2, "inspected_units": 2}},
    )
    _validator(report_schema_name(report)).validate(report)
    axis = _memory_axis(report)
    assert axis["coverage_status"] == "partial_coverage_gap"
    assert ("withheld_packages" if withheld else "verification_backlog_unconfirmed") in axis["gap_reasons"]
    assert axis["series"]["verified_coverage"]["score"] == 100.0
    assert axis["series"]["verified_coverage"]["is_gap"] is True
    assert axis["series"]["confirmed_high_critical"]["all_confirmed_count"] == 0
    assert before == (report["withheld"] if withheld else report["verification_backlog"])


def test_dossier_chain_hints_do_not_override_certified_report_membership(tmp_path):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, (("confirmed", "low"),)))
    claim_id = report["findings"][0]["claim_id"]
    report["radar_tracker"] = build_radar_tracker(report, {claim_id: {
        "chains": [{"chain_id": "chain-" + "a" * 64, "status": "refuted"}],
    }})
    _validator(report_schema_name(report)).validate(report)
    series = _memory_axis(report)["series"]["confirmed_high_critical"]
    assert series["chain_elevated_count"] == series["raw_count"] == 0
    assert series["unit"] == series["score"] == 0


@pytest.mark.parametrize(
    "telemetry,exposure,inspected,score,gap",
    [
        ({}, None, None, None, "surface_exposure_unknown"),
        ({"inspected_units": 2}, None, 2, None, "surface_exposure_unknown"),
        ({"surface_exposure": 2}, 2, None, None, "inspected_units_unknown"),
        ({"surface_exposure": 2, "inspected_units": 0}, 2, 0, 0.0, "uninspected_exposed_units"),
        ({"surface_exposure": 0, "inspected_units": 0}, 0, 0, None, "no_domain_coverage_bound"),
    ],
    ids=["unknown", "unknown-exposure", "unknown-inspection", "zero-inspected", "zero-exposure"],
)
def test_nullable_metrics_survive_real_schemas_and_renderers(tmp_path, telemetry, exposure, inspected, score, gap):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, ()))
    report["radar_tracker"] = build_radar_tracker(report, domain_telemetry={"memory_safety_native": telemetry})
    report["executive_posture"] = build_executive_posture(report, report["radar_tracker"])
    _validator(report_schema_name(report)).validate(report)
    SchemaSet(SCHEMAS).validate(report_schema_name(report), report)
    axis = _memory_axis(report)
    assert axis["series"]["surface_exposure"]["raw_count"] == exposure
    assert axis["series"]["verified_coverage"]["raw_count"] == inspected
    assert axis["series"]["verified_coverage"]["score"] == score
    assert gap in axis["gap_reasons"]
    assert report["radar_tracker"]["coverage_confidence"]["confidence_score"] is None
    telemetry_out = radar_telemetry(report["radar_tracker"])
    assert telemetry_out["reporting.radar_counts_by_axis_and_series"]["memory_safety_native"]["surface_exposure"] == exposure
    assert telemetry_out["reporting.funnel_conversion_rates"]["exposure_to_coverage_rate"] is None
    assert "denominator_unknown" in telemetry_out["reporting.funnel_gap_reasons"]["exposure_to_coverage_rate"]
    assert telemetry_out["reporting.funnel_conversion_rates"]["leads_to_confirmed_rate"] is None
    assert telemetry_out["reporting.funnel_gap_reasons"]["leads_to_confirmed_rate"] == ["denominator_unknown"]
    document = executive_document(report, ())
    row = coverage_table(document).rows[3]
    assert row[1].text == ("N/A" if exposure is None else str(exposure))
    assert row[2].text == ("N/A" if score is None else f"{score:g}%")
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16)
    html = render_executive_html(report)
    latex = render_executive_latex(report, (), ROOT / "containers" / "report" / "latex" / "template").decode()
    latex = latex.replace(r"\allowbreak{}", "")
    assert "N/A" in markdown and "N/A" in html and "N/A" in latex
    assert gap in markdown and gap in html and gap.replace("_", r"\_") in latex
    if score == 0:
        assert row[2].text == "0%" and "uninspected_exposed_units" in row[5].text
        assert "| 0% |" in markdown


def test_known_population_does_not_inflate_exposure_to_number_of_claims(tmp_path):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, (("confirmed", "low"),) * 3))
    telemetry = {domain: {"surface_exposure": 1, "inspected_units": 1} for domain in DOMAIN_IDS}
    report["radar_tracker"] = build_radar_tracker(report, domain_telemetry=telemetry)
    report["executive_posture"] = build_executive_posture(report, report["radar_tracker"])
    _validator(report_schema_name(report)).validate(report)
    axis = _memory_axis(report)
    assert axis["coverage_status"] == "verified_findings"
    assert axis["series"]["surface_exposure"]["raw_count"] == 1
    assert axis["series"]["corroborated_leads"]["raw_count"] is None
    assert axis["package_counts"] == {"publishable": 3, "verification_backlog": 0, "withheld": 0}
    assert axis["series"]["confirmed_high_critical"]["all_confirmed_count"] == 3
    assert axis["series"]["confirmed_high_critical"]["raw_count"] == 0
    assert report["radar_tracker"]["coverage_confidence"]["confidence_score"] == 100
    counts, _ = dimension_counts(report)
    memory = next(row for row in counts if row.key == "Mem")
    assert memory.surface_exposure_raw == 1 and memory.verified_coverage_pct == 100
    assert radar_telemetry(report["radar_tracker"])["reporting.funnel_conversion_rates"]["exposure_to_coverage_rate"] == 1


@pytest.mark.parametrize("measured_leads", [None, 0, 2], ids=["unknown", "measured-zero", "measured-two"])
def test_corroboration_requires_measurement_not_publication_packages(tmp_path, measured_leads):
    verified = _serialized_review(tmp_path, (("confirmed", "low"), ("supported", "low"), ("supported", "low")))
    verified["packages"][2]["attack_chains"] = ["chain-" + "a" * 64]
    gate, report = _gate_and_report(verified)
    if measured_leads is not None:
        report["radar_tracker"] = build_radar_tracker(
            report, domain_telemetry={"memory_safety_native": {"corroborated_leads": measured_leads}},
        )
    axis = _memory_axis(report)
    assert axis["package_counts"] == {"publishable": 1, "verification_backlog": 1, "withheld": 1}
    assert gate["package_counts"]["total"] == 3
    metric = axis["series"]["corroborated_leads"]
    assert metric["raw_count"] == measured_leads
    expected_gaps = ["corroborated_leads_unknown"] if measured_leads is None else []
    assert metric["gap_reasons"] == expected_gaps
    assert metric["unit"] == (None if measured_leads is None else 0 if measured_leads == 0 else 1)
    assert axis["coverage_status"] == "unverified_gap"
    assert axis["series"]["verified_coverage"]["score"] is None
    assert axis["series"]["surface_exposure"]["raw_count"] is None
    counts, _ = dimension_counts(report)
    memory = next(row for row in counts if row.key == "Mem")
    assert memory.claims == 3 and memory.corroborated_leads == measured_leads
    _validator(report_schema_name(report)).validate(report)
    SchemaSet(SCHEMAS).validate(report_schema_name(report), report)
    exported = radar_telemetry(report["radar_tracker"])
    assert exported["reporting.radar_counts_by_axis_and_series"]["memory_safety_native"]["corroborated_leads"] == measured_leads
    assert exported["reporting.radar_metric_gap_reasons_by_axis"]["memory_safety_native"] == expected_gaps
    document = executive_document(report, ())
    row = coverage_table(document).rows[3]
    assert row[3].text == ("N/A" if measured_leads is None else str(measured_leads))
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16)
    html = render_executive_html(report)
    latex = render_executive_latex(report, (), ROOT / "containers" / "report" / "latex" / "template").decode()
    if measured_leads is None:
        assert "corroborated_leads_unknown" in markdown and "corroborated_leads_unknown" in html
        assert "corroborated\\_leads\\_unknown" in latex.replace(r"\allowbreak{}", "")
        assert 'data-series="Corroborated leads"' not in html
    else:
        memory_row = next(line for line in markdown.splitlines() if line.startswith("| Mem |"))
        assert f"| {measured_leads} |" in memory_row


def test_missing_optional_corroboration_does_not_change_measured_coverage(tmp_path):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, ()))
    measured = {domain: {"surface_exposure": 2, "inspected_units": 2} for domain in DOMAIN_IDS}
    unknown = build_radar_tracker(report, domain_telemetry=measured)
    known_zero = build_radar_tracker(
        report, domain_telemetry={domain: {**values, "corroborated_leads": 0} for domain, values in measured.items()},
    )
    for tracker in (unknown, known_zero):
        _validator("security-radar-tracker-v2").validate(tracker)
        SchemaSet(SCHEMAS).validate("security-radar-tracker-v2", tracker)
    assert unknown["coverage_confidence"] == known_zero["coverage_confidence"]
    assert unknown["coverage_confidence"]["confidence_score"] == 100
    for unknown_axis, known_axis in zip(unknown["axes"], known_zero["axes"], strict=True):
        assert unknown_axis["coverage_status"] == known_axis["coverage_status"] == "verified_no_findings"
        assert unknown_axis["gap_reasons"] == known_axis["gap_reasons"] == []
        assert unknown_axis["series"]["verified_coverage"] == known_axis["series"]["verified_coverage"]
        assert unknown_axis["series"]["corroborated_leads"]["raw_count"] is None
        assert unknown_axis["series"]["corroborated_leads"]["gap_reasons"] == ["corroborated_leads_unknown"]
        assert known_axis["series"]["corroborated_leads"]["raw_count"] == 0
    unknown_export = radar_telemetry(unknown)
    assert unknown_export["reporting.funnel_conversion_rates"]["leads_to_confirmed_rate"] is None
    assert unknown_export["reporting.funnel_gap_reasons"]["leads_to_confirmed_rate"] == ["denominator_unknown"]
    zero_export = radar_telemetry(known_zero)
    assert zero_export["reporting.funnel_conversion_rates"]["exposure_to_leads_rate"] == 0
    assert zero_export["reporting.funnel_gap_reasons"]["leads_to_confirmed_rate"] == ["denominator_empty"]


@pytest.mark.parametrize("version", [2, 3])
def test_legacy_report_validation_and_rendering_preserve_original_bytes(tmp_path, version):
    _gate, legacy = _gate_and_report(_serialized_review(tmp_path, ()))
    legacy["radar_tracker"] = build_radar_tracker(
        legacy, domain_telemetry={domain: {"surface_exposure": 1, "inspected_units": 0, "corroborated_leads": 0}
                                 for domain in DOMAIN_IDS},
    )
    legacy["executive_posture"] = build_executive_posture(legacy, legacy["radar_tracker"])
    legacy["schema"] = f"appsec-review/final-report/{version}"
    legacy["executive_posture"]["reachable_supply_chain_advisories_count"] = 0
    del legacy["executive_posture"]["reachable_supply_chain_gap_reasons"]
    if version == 2:
        legacy["radar_tracker"]["schema"] = "appsec-review/security-radar-tracker/1"
        for axis in legacy["radar_tracker"]["axes"]:
            del axis["package_counts"]
            del axis["series"]["corroborated_leads"]["gap_reasons"]
        del legacy["radar_tracker"]["coverage_confidence"]["gap_reasons"]
        del legacy["executive_posture"]["coverage_confidence_index"]["gap_reasons"]
    original = json.dumps(legacy, sort_keys=True).encode()
    schemas = SchemaSet(SCHEMAS)
    schemas.validate(report_schema_name(legacy), legacy)
    _validator(report_schema_name(legacy)).validate(legacy)
    assert schemas.errors("final-report-v4", legacy)
    assert ("Legacy radar /1 estimates" in render_markdown(legacy, evidence_ids=8, gap_ids=16)) == (version == 2)
    assert ("Legacy radar /1 estimates" in render_executive_html(legacy)) == (version == 2)
    assert "reachable supply-chain advisories 0" in render_markdown(legacy, evidence_ids=8, gap_ids=16)
    assert "No gate-certified advisory reachability measurement is available" not in render_executive_html(legacy)
    legacy_tex = render_executive_latex(legacy, (), ROOT / "containers" / "report" / "latex" / "template").decode()
    assert ("legacy package{-}count estimates, not measured corroboration" in legacy_tex) == (version == 2)
    assert json.dumps(legacy, sort_keys=True).encode() == original
    _memory_axis(legacy)["series"]["surface_exposure"]["raw_count"] = None
    assert schemas.errors(report_schema_name(legacy), legacy)
    with pytest.raises(ValidationError):
        _validator(report_schema_name(legacy)).validate(legacy)
    with pytest.raises(ValueError, match="unsupported"):
        report_schema_name({"schema": "appsec-review/final-report/999"})


@pytest.mark.parametrize("corruption", ["missing-gap", "false-clean", "invented-zero", "missing-corroboration-gap"], ids=str)
def test_new_schema_rejects_unknown_metrics_without_gap_semantics(tmp_path, corruption):
    _gate, report = _gate_and_report(_serialized_review(tmp_path, ()))
    axis = _memory_axis(report)
    if corruption == "missing-gap":
        axis["gap_reasons"] = []
    elif corruption == "false-clean":
        axis["coverage_status"] = "verified_no_findings"
        axis["series"]["verified_coverage"]["is_gap"] = False
    elif corruption == "invented-zero":
        axis["series"]["surface_exposure"].update(score=0, unit=0)
    else:
        axis["series"]["corroborated_leads"]["gap_reasons"] = []
    assert SchemaSet(SCHEMAS).errors(report_schema_name(report), report)
    with pytest.raises(ValidationError):
        _validator(report_schema_name(report)).validate(report)


def test_ship_block_decision_not_severity_or_chain_membership_controls_banner():
    report = {
        "findings": [{"claim_id": "c", "ship_block": {"technical_severity": "critical"}}],
        "attack_chains": {"items": [{"chain_id": "chain", "status": "confirmed", "component_claim_ids": ["c"]}]},
        "status": {"review_complete": True}, "summary": {"ship_block": {"by_status": {"not_ship_blocking": 1}}},
    }
    radar = {"coverage_confidence": {"gap_axes": 0, "verified_axes": 12, "confidence_score": 100,
                                     "summary_statement": "Recorded coverage"}, "axes": []}
    assert build_executive_posture(report, radar)["release_readiness"] == "READY_WITH_RESIDUAL_ACCEPTANCE"
    report["summary"]["ship_block"]["by_status"] = {"ship_blocking": 1}
    report["findings"][0]["ship_block"]["technical_severity"] = "low"
    assert build_executive_posture(report, radar)["release_readiness"] == "BLOCK_RELEASE"


def test_chain_rating_only_comes_from_the_manifest_and_proposals_are_not_verified():
    report = {
        "findings": [{"finding_package_id": "f", "claim_id": "c", "ship_block": {"technical_severity": "critical"}}],
        "attack_chains": {"items": [{"chain_id": "chain", "status": "confirmed", "component_claim_ids": ["c", "other"]}]},
        "remediation_planning": {"items": [{"finding": {"finding_package_id": "f"},
                                          "status": "proposal_generated", "plan": {"patch": "proposed"}}]},
    }
    card = build_attack_chain_cards(report)[0]
    assert (card["composed_severity"], card["severity_gap"], card["gap_count"]) == (
        "unrated", "chain_severity_unrated", 1)
    card = build_attack_chain_cards(report, manifest_items=[{"chain_id": "chain", "composed_severity": "low"}])[0]
    assert (card["composed_severity"], card["severity_gap"]) == ("low", None)
    assert build_remediation_roadmap(report)[0]["validation_status"] == "proposal_only"
    report["remediation_validation"] = {"items": [{"finding": {"finding_package_id": "f"}, "status": "static_checked"}]}
    assert build_remediation_roadmap(report)[0]["validation_status"] == "static_checked"


def test_adjudication_confirmation_does_not_imply_reachability(tmp_path):
    source = dossier_seed(tmp_path / "run")
    assert source["finding"]["state"] == "confirmed"
    assert "reachability" not in source["claim"]
    dossier = build_dossier(kind="confirmed_finding", **source)
    assert dossier["state"] == "confirmed"
    assert dossier["classification_badge"]["reachability_badge"] == "unknown"
