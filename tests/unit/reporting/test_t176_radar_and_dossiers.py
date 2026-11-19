"""Focused unit tests for T-176: 12-axis 4-series radar, executive report, and dossiers."""
from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from appsec_review.jobs.accepted_review import project_finding
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_report_publication.render import render_markdown
from appsec_review.jobs.job_final_report_publication.report import build_report
from appsec_review.reporting.dimensions import (
    DIMENSIONS,
    RADAR_SERIES_IDS,
    SECURITY_RADAR_TRACKER_SCHEMA,
    build_radar_tracker,
    domain_id_of_package,
    owasp_of_cwe_or_domain,
    radar_telemetry,
)
from appsec_review.reporting.dossier_render import (
    render_dossier_html,
    render_dossier_markdown,
)
from appsec_review.reporting.dossiers import build_dossier, dossier_document
from appsec_review.reporting.executive_posture import (
    build_attack_chain_cards,
    build_executive_posture,
    build_named_coverage_gaps,
    build_remediation_roadmap,
)
from appsec_review.reporting.executive_report import (
    executive_document,
    render_executive_html,
)
from appsec_review.reporting.latex import escape_latex, render_latex
from appsec_review.review.identity import sha256_hex
from tests.dossier_fixture import seed
from tests.unit.review_decision_audit_wiring.helpers import verified_document
from tests.unit.review_decision_audit_consumers.helpers import Fixture

ROOT = Path(__file__).resolve().parents[3]
RADAR_SCHEMA_PATH = ROOT / "docs" / "schemas" / "final-report" / "security-radar-tracker-v2.schema.json"
DOSSIER_SCHEMA_PATH = ROOT / "docs" / "schemas" / "dossier" / "finding-dossier.schema.json"
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"

EXPECTED_DOMAIN_IDS = (
    "authentication_session",
    "authorization_access_control",
    "injection_interpreters",
    "memory_safety_native",
    "parsing_deserialization",
    "cryptography_secrets",
    "network_api_surface",
    "filesystem_path_resources",
    "business_logic_state",
    "supply_chain_dependencies",
    "ci_cd_build_integrity",
    "container_deployment_hardening",
)


def test_twelve_domains_and_four_series_validate_against_schema() -> None:
    assert tuple(dim.domain_id for dim in DIMENSIONS) == EXPECTED_DOMAIN_IDS
    assert RADAR_SERIES_IDS == (
        "surface_exposure",
        "verified_coverage",
        "corroborated_leads",
        "confirmed_high_critical",
    )
    report_in = {
        "status": {"review": "DEGRADED", "review_complete": False, "review_incomplete": True},
        "findings": [
            {
                "claim_id": "c1",
                "finding_package_id": "f1",
                "security_predicate": "sql_injection",
                "ship_block": {"technical_severity": "critical"},
            },
            {
                "claim_id": "c2",
                "finding_package_id": "f2",
                "security_predicate": "supply_chain_compromise",
                "ship_block": {"technical_severity": "high"},
            },
            {
                "claim_id": "c3",
                "finding_package_id": "f3",
                "observation_class": "ci_cd_workflow",
                "ship_block": {"technical_severity": "medium"},
            },
        ],
        "verification_backlog": [
            {
                "claim_id": "c4",
                "finding_package_id": "b1",
                "security_predicate": "memory_corruption",
                "ship_block": {"technical_severity": "high"},
            },
        ],
        "withheld": [],
        "limitations": [
            {"kind": "gap", "limitation_id": "gap-cpp", "statement": "C++ compile database unavailable"},
        ],
    }
    tracker = build_radar_tracker(report_in)
    assert tracker["schema"] == SECURITY_RADAR_TRACKER_SCHEMA == "appsec-review/security-radar-tracker/2"
    assert len(tracker["axes"]) == 12
    schema = json.loads(RADAR_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    documents = [json.loads(path.read_text(encoding="utf-8"))
                 for path in sorted(RADAR_SCHEMA_PATH.parent.glob("*.schema.json"))]
    registry = Registry().with_resources((row["$id"], Resource.from_contents(row)) for row in documents)
    Draft202012Validator(schema, registry=registry).validate(tracker)

    assert json.dumps(tracker, sort_keys=True) == json.dumps(build_radar_tracker(report_in), sort_keys=True)
    tel = radar_telemetry(tracker)
    assert len(tel["reporting.radar_counts_by_axis_and_series"]) == 12
    assert set(tel["reporting.funnel_conversion_rates"]) == {
        "exposure_to_coverage_rate",
        "exposure_to_leads_rate",
        "leads_to_confirmed_rate",
    }


def test_radar_coverage_gaps_never_conflated_with_clean_domains() -> None:
    empty_unverified_report = {
        "status": {"review": "DEGRADED", "review_complete": False, "review_incomplete": True},
        "findings": [],
        "verification_backlog": [],
        "withheld": [],
        "limitations": [
            {"kind": "gap", "limitation_id": "gap-all", "statement": "All static and dynamic lanes skipped"},
        ],
    }
    tracker = build_radar_tracker(empty_unverified_report)
    for axis in tracker["axes"]:
        assert axis["coverage_status"] in {"unverified_gap", "partial_coverage_gap"}
        assert axis["coverage_status"] not in {"verified_no_findings", "clean"}
        assert axis["series"]["verified_coverage"]["is_gap"] is True
    assert tracker["coverage_confidence"]["gap_axes"] == 12
    assert tracker["coverage_confidence"]["verified_axes"] == 0
    assert "never treated as clean" in tracker["coverage_confidence"]["summary_statement"]


def test_domain_and_owasp_mapping_covers_all_twelve_axes() -> None:
    assert domain_id_of_package({"cwe_id": 287}) == "authentication_session"
    assert domain_id_of_package({"cwe_id": 862}) == "authorization_access_control"
    assert domain_id_of_package({"cwe_id": 89}) == "injection_interpreters"
    assert domain_id_of_package({"cwe_id": 787}) == "memory_safety_native"
    assert domain_id_of_package({"cwe_id": 502}) == "parsing_deserialization"
    assert domain_id_of_package({"cwe_id": 327}) == "cryptography_secrets"
    assert domain_id_of_package({"cwe_id": 918}) == "network_api_surface"
    assert domain_id_of_package({"cwe_id": 22}) == "filesystem_path_resources"
    assert domain_id_of_package({"cwe_id": 362}) == "business_logic_state"
    assert domain_id_of_package({"security_predicate": "supply_chain_compromise"}) == "supply_chain_dependencies"
    assert domain_id_of_package({"observation_class": "ci_cd_workflow"}) == "ci_cd_build_integrity"
    assert domain_id_of_package({"security_predicate": "insecure_configuration"}) == "container_deployment_hardening"
    assert owasp_of_cwe_or_domain(89, "injection_interpreters") == "A05:2025"
    assert owasp_of_cwe_or_domain(None, "supply_chain_dependencies") == "A03:2025"


def test_executive_report_posture_chains_roadmap_and_multi_format_rendering() -> None:
    verified = verified_document()
    gate = gate_classify.gate_document(
        FINAL_PUBLICATION_GATE_SCHEMA, verified, gate_classify.classify(verified),
    )
    report = build_report(
        gate,
        gate_handoff={"path": "data/gate-handoff.json", "sha256": sha256_hex("h")},
        gate_document={"path": "data/gate.json", "sha256": sha256_hex("g")},
    )
    assert len(report["radar_tracker"]["axes"]) == 12
    assert "executive_posture" in report
    assert "attack_chain_cards" in report
    assert "remediation_roadmap" in report
    assert "named_coverage_gaps" in report

    synthetic_report = {
        "status": {"review": "DEGRADED", "review_complete": False},
        "summary": {"ship_block": {"by_status": {"ship_blocking": 1}}},
        "findings": [
            {
                "finding_package_id": "low-cfg",
                "claim_id": "claim-low",
                "title": "Container missing read-only rootfs",
                "security_predicate": "insecure_configuration",
                "ship_block": {"technical_severity": "low"},
            },
            {
                "finding_package_id": "crit-sqli",
                "claim_id": "claim-crit",
                "title": "SQL Injection in Checkout",
                "security_predicate": "sql_injection",
                "ship_block": {"technical_severity": "critical"},
            },
            {
                "finding_package_id": "high-dep",
                "claim_id": "claim-dep",
                "title": "Reachable CVE-2024-9999 in parser library",
                "security_predicate": "supply_chain_compromise",
                "ship_block": {"technical_severity": "high"},
            },
        ],
        "attack_chains": {
            "items": [
                {
                    "chain_id": "chain-1",
                    "status": "confirmed",
                    "component_claim_ids": ["claim-dep", "claim-crit"],
                }
            ]
        },
        "remediation_validation": {
            "items": [
                {"finding": {"finding_package_id": "crit-sqli"}, "status": "build_checked"},
            ]
        },
        "poc_outcomes": {
            "items": [
                {"finding_package_id": "crit-sqli", "status": "compile_verified"},
            ]
        },
        "limitations": [
            {"kind": "gap", "limitation_id": "gap-syntactic", "statement": "Rust module used syntactic_fallback"},
        ],
    }
    syn_radar = build_radar_tracker(synthetic_report)
    roadmap = build_remediation_roadmap(synthetic_report)
    assert [r["finding_package_id"] for r in roadmap] == ["crit-sqli", "high-dep", "low-cfg"]
    assert roadmap[0]["validation_status"] == "build_checked"
    assert roadmap[0]["poc_posture"] == {"status": "compile_only_verified", "generated_code_execution": "not_performed_by_policy"}

    chains = build_attack_chain_cards(synthetic_report)
    assert len(chains) == 1
    assert chains[0]["composed_severity"] == "unrated"
    assert chains[0]["severity_gap"] == "chain_severity_unrated"
    assert [s["role"] for s in chains[0]["steps"]] == ["entry", "sink"]

    gaps = build_named_coverage_gaps(synthetic_report, syn_radar)
    assert any(g.get("gap_id") == "gap-syntactic" or "syntactic" in str(g) for g in gaps)

    posture = build_executive_posture(synthetic_report, syn_radar)
    assert posture["release_readiness"] == "BLOCK_RELEASE"
    assert posture["confirmed_by_severity"]["critical"] == 1
    assert posture["reachable_supply_chain_advisories_count"] is None
    assert posture["reachable_supply_chain_gap_reasons"] == ["certified_reachability_unavailable"]
    assert posture["chain_elevated_findings_count"] == 2

    md = render_markdown(report, evidence_ids=True, gap_ids=True)
    html = render_executive_html(report)
    tex = render_latex(executive_document(report, ()), TEMPLATE)
    assert md == render_markdown(report, evidence_ids=True, gap_ids=True)
    assert html == render_executive_html(report)
    assert tex == render_latex(executive_document(report, ()), TEMPLATE)
    assert "<svg" in html
    svg_start = html.index("<svg")
    svg_end = html.index("</svg>") + len("</svg>")
    ET.fromstring(html[svg_start:svg_end])
    assert html.count('data-series=') == 1
    assert 'data-series="Surface exposure"' not in html
    assert 'data-series="Verified coverage"' not in html
    assert 'data-series="Corroborated leads"' not in html
    assert "N/A" in html and "N/A" in md


def test_redesigned_dossier_sections_and_deterministic_latex_escaping(tmp_path: Path) -> None:
    special = r"a_b % & # $ { } ~ ^ \ end"
    escaped = escape_latex(special)
    assert escaped == escape_latex(special)
    for raw_tok in ("_", "%", "&", "#", "$", "{", "}"):
        assert f"\\{raw_tok}" in escaped
    assert r"\textbackslash{}" in escaped
    assert r"\textasciitilde{}" in escaped
    assert r"\textasciicircum{}" in escaped

    source = seed(tmp_path / "run")
    model = build_dossier(kind="poc", **source)
    for key in (
        "classification_badge",
        "taint_path_timeline",
        "adjudication_summary",
        "poc_harness_summary",
        "remediation_guide",
    ):
        assert key in model, f"missing {key}"

    assert model["poc_harness_summary"]["generated_code_execution"] == "not_performed_by_policy"
    assert isinstance(model["remediation_guide"]["verification_checklist"], list)
    assert len(model["remediation_guide"]["verification_checklist"]) >= 1

    dossier_schema = json.loads(DOSSIER_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(dossier_schema)
    Draft202012Validator(dossier_schema).validate(model)

    md = render_dossier_markdown(model)
    html = render_dossier_html(model)
    tex = render_latex(dossier_document(model))
    assert md == render_dossier_markdown(model)
    assert html == render_dossier_html(model)
    assert tex == render_latex(dossier_document(model))
    assert "not_performed_by_policy" in md
    assert "not_performed_by_policy" in html


@pytest.mark.parametrize("independent", [None, False, True], ids=["absent", "failed", "passed"])
def test_accepted_finding_does_not_invent_path_guard_or_independence(tmp_path, independent):
    source = seed(tmp_path / "run")
    finding = source["finding"]
    package = {
        **finding, "label": "confirmed", "gaps": [], "poc": None, "judge_verdict": None,
        "verification_review_id": None,
        "independence": {} if independent is None else {"independent": independent},
        "ship_block": {
            "policy": "ship-block-policy/1", "policy_sha256": "1" * 64,
            "status": "not_ship_blocking", "reasons": [], "missing_factors": [],
            "conditions": {"distinct_verification_required": False, "verifier_model_distinct": False},
            "inputs": {"technical_severity": {
                "rating": "medium", "score_id": None, "severity_floor": None, "severity_ceiling": None,
                "missing_factors": []}},
        },
    }
    source["finding"] = project_finding(
        {"path": finding["path"], "sha256": finding["sha256"]}, package, finding["scores"])
    model = build_dossier(kind="confirmed_finding", **source)
    assert model["taint_path_timeline"] == []
    assert model["classification_badge"]["corroborating_scanners"] == []
    expected = "not_recorded" if independent is None else (
        "independence_passed" if independent else "independence_failed")
    assert model["adjudication_summary"]["verifier_posture"] == expected
    for rendered in (json.dumps(model), render_dossier_markdown(model), render_dossier_html(model)):
        assert "confirmed_independent" not in rendered
        assert "verified_unblocked_citation" not in rendered
        assert "candidate guards did not" not in rendered
        assert "Guard analysis is not recorded" in rendered


@pytest.mark.parametrize("format", ["markdown", "html", "latex"])
def test_dossier_formats_preserve_audited_counterevidence_risk_and_provenance(tmp_path, format):
    fixture = Fixture(tmp_path)
    source = fixture.dossier()
    source["finding"]["scores"] = [{
        "score_id": "score-1", "sha256": "a" * 64, "provider": {"id": "risk-provider"},
        "technical_severity": {"rating": "medium", "scale": "ordinal", "value": 2},
        "missing_factors": ["deployment-unknown"],
    }]
    source["chains"] = [{"chain_id": "chain-1", "status": "qualified_supported",
                         "objective": "Qualified chain", "qualifications": ["UNIQUE_CHAIN_LIMITATION"]}]
    source["excerpts"] = [{"identity": "entity-dissent", "location": {"path": "example/dissent.c"},
                           "excerpt": "counterevidence excerpt", "excerpt_start_line": 1, "excerpt_end_line": 1}]
    model = build_dossier(**source, decision_audit=fixture.load())
    render = {"markdown": render_dossier_markdown, "html": render_dossier_html,
              "latex": lambda value: render_latex(dossier_document(value))}[format]
    rendered = render(model)
    for marker in ("Protected decision basis", "dissent", "qualification", "nondeciding",
                   "UNIQUE_CHAIN_LIMITATION", "risk-provider", "deployment-unknown", "review handoff"):
        expected = (escape_latex(marker) if format == "latex" else
                    marker.replace("_", "\\_") if format == "markdown" else marker)
        assert expected in rendered
    assert model["taint_path_timeline"] == []
    assert model["decision_basis"]["verification"]["existing_r6_passed"]["value"] is False
    assert model["adjudication_summary"]["verifier_posture"] != "confirmed_independent"
    assert "literal-secret" not in rendered
    assert "DO_NOT_COPY_PRIVATE_WORKER_DICTIONARY" not in rendered


def test_common_markdown_keeps_untrusted_markup_and_code_inert(tmp_path):
    source = seed(tmp_path / "run")
    source["claim"]["statement"] = '<script>alert(1)</script> [link](https://invalid.example)'
    source["poc_source"] = "```\n# not a heading\n<script>inert code</script>"
    model = build_dossier(kind="poc", **source)
    markdown = render_dossier_markdown(model)
    assert "<script>alert(1)</script>" not in markdown
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markdown
    assert "\\[link\\](https://invalid.example)" in markdown
    assert "````text\n```\n# not a heading\n<script>inert code</script>\n````" in markdown
