"""Report assembly, schema validation, decision_pending projection, and Markdown rendering unit tests."""
from __future__ import annotations

from copy import deepcopy
from collections import Counter
from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import pytest
from referencing import Registry, Resource

from appsec_review.config.loader import PROFILES
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA, FINAL_REPORT_SCHEMA
from appsec_review.jobs.accepted_review import project_finding
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.job_final_report_publication.render import code, plain, render_markdown
from appsec_review.jobs.job_final_report_publication.report import (
    HTML_RENDERER, NOTICES, PDF_REASON, POC_REASON, RENDERER, build_report, report_schema_name,
)
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.reporting.executive_report import executive_document, render_executive_html
from appsec_review.reporting.latex import escape_latex, render_latex
from appsec_review.review import ship_block
from appsec_review.review.claims import normalize_claim
from appsec_review.review.identity import sha256_hex
from appsec_review.review.ledger import ClaimView, Projection
from appsec_review.review.models import ClaimState, Lane
from tests.unit.review_decision_audit_wiring.helpers import HASH, verified_document

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "docs" / "schemas" / "final-report"
def _validator(name: str) -> Draft202012Validator:
    documents = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(SCHEMAS.glob("*.schema.json"))]
    registry = Registry().with_resources((item["$id"], Resource.from_contents(item)) for item in documents)
    return Draft202012Validator(
        json.loads((SCHEMAS / f"{name}.schema.json").read_text(encoding="utf-8")),
        registry=registry,
    )


def _gate_and_report(
    verified: dict[str, Any],
    *,
    configuration_profile: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    classification = gate_classify.classify(verified)
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
    _validator("final-publication-gate").validate(gate)
    assert SchemaSet(SCHEMAS).errors("final-publication-gate", gate) == []
    report = build_report(
        gate,
        gate_handoff={"path": "data/gate-handoff.json", "sha256": sha256_hex("gate-handoff")},
        gate_document={"path": "data/gate.json", "sha256": sha256_hex("gate-doc")},
        configuration_profile=configuration_profile,
    )
    _validator(report_schema_name(report)).validate(report)
    assert SchemaSet(SCHEMAS).errors(report_schema_name(report), report) == []
    return gate, report


def _serialized_review(tmp_path: Path, states: tuple[tuple[str, str], ...], *,
                       independent: bool = True, distinct: bool = True) -> dict[str, Any]:
    """Tiny accepted claims cross the real finding serializer and accepted-field projection."""
    verified = verified_document()
    packages = []
    schemas = SchemaSet(ROOT / SCHEMA_DIRECTORY)
    for index, (state, severity) in enumerate(states):
        claim = normalize_claim(
            lane=Lane.HUNT, package_id=f"package-{index}",
            affected_entities=(f"asr:source_span:{sha256_hex(str(index))}",),
            weakness_cwe="CWE-787", security_predicate="memory_corruption",
            preconditions=(), statement="Synthetic bounded memory finding",
            accepted_cwe_ids={"CWE-787"},
        ).claim
        claim = replace(claim, state=ClaimState(state))
        projection = Projection(HASH, {claim.claim_id: ClaimView(claim, (), ())}, {}, (), {})
        score_id = f"score-{sha256_hex(str(index))}"
        score = {
            "claim_id": claim.claim_id, "score_id": score_id, "provider": ship_block.SEVERITY_PROVIDER,
            "technical_severity": severity,
            "severity_assessment": {"severity_floor": severity, "severity_ceiling": severity,
                                    "unresolved_factors": []},
        }
        entries = stages.finding_packages(
            projection,
            [{"claim_id": claim.claim_id, "state": state,
              "adjudication_id": f"adjudication-{sha256_hex(str(index))}", "predicates": [], "gap_ids": []}],
            {"independence": {claim.claim_id: [{
                "independent": independent, "provider_distinct": distinct, "verifier_model_distinct": distinct,
                "review_id": f"review-{sha256_hex(str(index))}",
            }]}}, [score], manifest_sha256=HASH, out_dir=tmp_path, schemas=schemas,
        )
        entry, = entries
        package = json.loads((tmp_path / entry["file"]).read_bytes())
        schemas.validate("finding-package", package)
        packages.append(project_finding(
            {"path": f"data/findings/{entry['file']}", "sha256": entry["sha256"]}, package, []
        ))
    verified["packages"] = packages
    verified["partition"] = {
        state: [row["finding_package_id"] for row in packages if row["state"] == state]
        for state in ("confirmed", "supported")
    }
    verified["accounting"].update(claims_total=len(packages),
                                  claims_by_state=dict(Counter(row["state"] for row in packages)))
    verified["ship_block"] = {
        "policy": "ship-block-policy/1",
        "policy_sha256": ship_block.policy_sha256(ship_block.ShipBlockSettings(), True),
        **ship_block.summarize({"lane": row["lane"], "status": row["ship_block"]["status"]} for row in packages),
    }
    return verified


def _memory_axis(report: dict[str, Any]) -> dict[str, Any]:
    return next(axis for axis in report["radar_tracker"]["axes"] if axis["key"] == "Mem")


@pytest.mark.parametrize("state,independent,distinct", [
    ("confirmed", False, False), ("confirmed", True, False), ("confirmed", True, True),
    ("supported", False, False),
], ids=["conditional-not-independent", "same-model-independent", "distinct-independent", "backlog"])
def test_executive_verification_preserves_serialized_independence(
    tmp_path: Path, state: str, independent: bool, distinct: bool,
) -> None:
    # The contradictory confirmed/false case is schema-supported, not a claim of R5 reachability.
    verified = _serialized_review(tmp_path, ((state, "high"),), independent=independent, distinct=distinct)
    gate, report = _gate_and_report(verified)
    original = deepcopy(report)
    package = (report["findings"] or report["verification_backlog"])[0]
    assert package["state"] == state and package["independence"]["independent"] is independent
    assert package == gate["packages"][0]
    html = render_executive_html(report, ())
    latex = render_latex(executive_document(report, ()), ROOT / "containers" / "report" / "latex" / "template")
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16)
    if state == "confirmed" and not independent:
        expected = "No: the accepted finding is confirmed, but its independence record explicitly says no."
        assert expected in html and escape_latex(expected) in latex
        assert "Yes: an independent verifier confirmed this finding" not in html + latex
        assert "Confirmed means an independent verifier" not in html + latex
        assert "independent verifier no" in markdown
    elif state == "confirmed":
        expected = ("Yes: an independent verifier confirmed this finding "
                    f"(separate provider: {'yes' if distinct else 'no'}; "
                    f"distinct verifier model: {'yes' if distinct else 'no'}).")
        assert expected in html and escape_latex(expected) in latex
        assert "independent verifier yes" in markdown
    else:
        assert not report["findings"] and len(report["verification_backlog"]) == 1
        assert "Yes: an independent verifier confirmed this finding" not in html + latex
    assert report == original


@pytest.mark.parametrize("state", ["confirmed", "supported"])
def test_withheld_only_serialized_finding_never_certifies_clean_coverage(tmp_path: Path, state: str) -> None:
    verified = _serialized_review(tmp_path, ((state, "low"),))
    verified["packages"][0]["attack_chains"] = [f"chain-{sha256_hex('unavailable')}"]
    gate, report = _gate_and_report(verified)
    assert gate["package_counts"]["withheld"] == 1
    assert report["findings"] == report["verification_backlog"] == []
    assert report["withheld"][0]["state"] == state
    axis = _memory_axis(report)
    assert axis["package_counts"] == {"publishable": 0, "verification_backlog": 0, "withheld": 1}
    assert axis["coverage_status"] == "unverified_gap"
    assert "withheld_packages" in axis["gap_reasons"]
    assert "surface_exposure_unknown" in axis["gap_reasons"]
    assert axis["series"]["verified_coverage"]["is_gap"] is True
    assert axis["series"]["surface_exposure"] == {"raw_count": None, "score": None, "unit": None}
    assert axis["series"]["verified_coverage"]["raw_count"] is None
    assert axis["series"]["verified_coverage"]["score"] is None
    assert axis["series"]["confirmed_high_critical"]["all_confirmed_count"] == 0


@pytest.mark.parametrize("state", ["supported", "confirmed"])
def test_serialized_package_count_is_not_domain_inspection_or_exposure(tmp_path: Path, state: str) -> None:
    _gate, report = _gate_and_report(_serialized_review(tmp_path, ((state, "high"),)))
    axis = _memory_axis(report)
    assert axis["coverage_status"] == "unverified_gap"
    assert {"surface_exposure_unknown", "inspected_units_unknown"} <= set(axis["gap_reasons"])
    assert ("verification_backlog_unconfirmed" in axis["gap_reasons"]) is (state == "supported")
    assert axis["series"]["corroborated_leads"]["raw_count"] is None
    assert axis["package_counts"] == {"publishable": int(state == "confirmed"),
                                     "verification_backlog": int(state == "supported"), "withheld": 0}
    assert axis["series"]["confirmed_high_critical"]["all_confirmed_count"] == (state == "confirmed")


@pytest.mark.parametrize("status", ["confirmed", "qualified_supported", "refuted", "insufficient_evidence"])
def test_certified_chain_components_elevate_each_publishable_finding_once(tmp_path: Path, status: str) -> None:
    verified = _serialized_review(tmp_path, (("confirmed", "low"), ("confirmed", "high"),
                                            ("confirmed", "medium")))
    members = [row["claim_id"] for row in verified["packages"][:2]]
    verified["attachments"]["attack_chains"] = [
        {"chain_id": f"chain-{sha256_hex(str(index))}", "status": status, "component_claim_ids": members,
         "artifact": {"path": f"data/chain-{index}.json", "sha256": HASH}, "gap_count": 0, "disposition": "assessed"}
        for index in range(2)
    ]
    manifest = {"path": "data/chains.json", "sha256": HASH}
    verified["capabilities"]["attack_chains"] = capability(True, summary=manifest, count=2)
    verified["bindings"].extend([manifest, *(row["artifact"] for row in verified["attachments"]["attack_chains"])])
    _gate, report = _gate_and_report(verified)
    active = status in {"confirmed", "qualified_supported"}
    series = _memory_axis(report)["series"]["confirmed_high_critical"]
    assert series["all_confirmed_count"] == 3
    assert series["chain_elevated_count"] == (2 if active else 0)
    assert series["raw_count"] == (2 if active else 1)
    assert report["executive_posture"]["chain_elevated_findings_count"] == series["chain_elevated_count"]
    assert [row["ship_block"]["technical_severity"] for row in report["findings"]].count("high") == 1


def test_clean_and_incomplete_reports_are_schema_valid_and_track_completeness() -> None:
    clean_verified = verified_document()
    gate, report = _gate_and_report(clean_verified)
    assert report["schema"] == FINAL_REPORT_SCHEMA
    assert report["status"] == {
        "review": "COMPLETE",
        "review_incomplete": False,
        "publication": "PUBLISHABLE",
        "review_complete": True,
    }
    assert "configuration_profile" not in report["provenance"]
    assert "poc_handoff" not in report["provenance"]
    assert report["renderers"] == {
        "markdown": {"file": "final-report.md", "renderer": RENDERER},
        "html": {"file": "final-report.html", "renderer": HTML_RENDERER},
        "sarif": {"file": "findings.sarif", "receipt": "sarif-export-result.json", "version": "2.1.0"},
        "pdf": {"state": "not_rendered", "reason": PDF_REASON},
    }
    assert report["notices"] == list(NOTICES)
    assert len(report["findings"]) == 1 and len(report["verification_backlog"]) == 1
    assert report["withheld"] == []

    md = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert "review presented as complete: **yes**" in md
    assert "This review is not complete" not in md
    assert "runtime profile" not in md
    assert "No finding package is withheld." in md

    # Incomplete review cannot be presented as complete even if status were COMPLETE.
    incomplete = verified_document()
    incomplete["review"]["status"] = "DEGRADED"
    incomplete["review"]["review_incomplete"] = True
    incomplete["accounting"]["outcome"] = "DEGRADED"
    incomplete["accounting"]["review_incomplete"] = True
    _gate2, report2 = _gate_and_report(
        incomplete, configuration_profile={"name": "prod", "sha256": sha256_hex("prod-layer")}
    )
    assert report2["status"]["review_complete"] is False
    assert report2["status"]["publication"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert report2["provenance"]["configuration_profile"] == {
        "name": "prod",
        "sha256": sha256_hex("prod-layer"),
    }
    md2 = render_markdown(report2, evidence_ids=8, gap_ids=16)
    assert "review presented as complete: **no**" in md2
    assert "> This review is not complete." in md2
    assert "- runtime profile `prod`" in md2


@pytest.mark.parametrize("profile_name", sorted(PROFILES))
def test_report_preserves_supported_runtime_profile(profile_name: str) -> None:
    profile = {
        "name": profile_name,
        "sha256": None if profile_name == "dev" else sha256_hex(profile_name),
    }
    _gate, report = _gate_and_report(verified_document(), configuration_profile=profile)
    assert report["provenance"]["configuration_profile"] == profile
    assert f"- runtime profile `{profile_name}`" in render_markdown(report, evidence_ids=8, gap_ids=16)


@pytest.mark.parametrize("profile", [
    {"name": "unknown-profile", "sha256": HASH},
    {"name": "copilot-dev-astra-6.2", "sha256": "not-a-digest"},
], ids=["unknown-profile", "invalid-profile-digest"])
def test_report_rejects_invalid_runtime_profile_identity(profile: dict[str, Any]) -> None:
    _gate, report = _gate_and_report(verified_document())
    report["provenance"]["configuration_profile"] = profile
    assert list(_validator(report_schema_name(report)).iter_errors(report))
    assert SchemaSet(SCHEMAS).errors(report_schema_name(report), report)


def test_long_gap_inventory_keeps_every_id_without_exceeding_tex_line_buffer() -> None:
    _gate, report = _gate_and_report(verified_document())
    report["gap_ids"] = [f"gap-{index:064x}" for index in range(1600)]
    rendered = render_latex(executive_document(report, ()), ROOT / "containers" / "report" / "latex" / "template")
    assert max(len(line.encode("utf-8")) for line in rendered.splitlines()) < 200000
    flattened = rendered.replace("%\n", "").replace("\n", " ")
    for identity in report["gap_ids"]:
        assert escape_latex(identity) in flattened


def test_decision_pending_with_and_without_bounds_projected_verbatim_and_never_hidden() -> None:
    # Replacement for test_decision_pending_is_a_named_gap_projected_verbatim_and_never_hidden
    bounded = verified_document()
    pkg = bounded["packages"][0]
    undecided_id = pkg["finding_package_id"]
    pkg["ship_block"] = {
        **pkg["ship_block"],
        "status": "decision_pending",
        "technical_severity": None,
        "technical_severity_score_id": None,
        "reasons": ["technical_severity_unrated", "missing_factor_attacker_control", "missing_factor_taint_path"],
        "technical_severity_floor": "medium",
        "technical_severity_ceiling": "high",
        "missing_factors": ["attacker_control", "taint_path"],
    }
    pkg["scores"][0]["technical_severity"] = {"scale": "fixture/1", "rating": None, "value": None}
    pkg["scores"][0]["missing_factors"] = ["attacker_control", "taint_path"]
    pkg["scores"][0]["severity_assessment"] = {
        "assessment": "unrated",
        "severity_floor": "medium",
        "severity_ceiling": "high",
        "unresolved_factors": ["attacker_control", "taint_path"],
    }
    bounded["ship_block"]["by_status"]["ship_blocking"] = 0
    bounded["ship_block"]["by_status"]["decision_pending"] = 1
    bounded["ship_block"]["by_lane"]["hunt"]["ship_blocking"] = 0
    bounded["ship_block"]["by_lane"]["hunt"]["decision_pending"] = 1

    gate, report = _gate_and_report(bounded)
    limitation = next(item for item in gate["limitations"] if item["limitation_id"] == "decision_pending")
    assert limitation["kind"] == "gap" and limitation["count"] == 1
    assert "not a release decision" in limitation["statement"]
    assert report["status"]["publication"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert report["status"]["review_complete"] is False
    assert report["summary"]["ship_block"]["by_status"]["decision_pending"] == 1
    projected = next(item for item in report["findings"] if item["finding_package_id"] == undecided_id)
    assert projected["ship_block"]["status"] == "decision_pending"
    assert projected["ship_block"]["missing_factors"] == ["attacker_control", "taint_path"]

    text = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert (
        "**decision pending: severity not yet rated; what is missing: `attacker_control`, `taint_path`; "
        "the missing factors leave the severity between `medium` and `high`**"
    ) in text
    assert "neither ship-blocking nor cleared" in text
    assert "does not block" not in text
    assert text.count("decision pending: severity not yet rated") == 1
    assert "severity assessment: `unrated`, severity between `medium` and `high`" in text
    assert "missing factors: `attacker_control`, `taint_path`" in text
    assert "Technical severity: unrated on scale `fixture/1`" in text

    # Replacement for test_decision_pending_without_bounds_names_the_unrated_severity_itself
    unbounded = deepcopy(bounded)
    unbounded["packages"][0]["ship_block"].update(
        technical_severity_floor=None,
        technical_severity_ceiling=None,
        missing_factors=[],
    )
    unbounded["packages"][0]["scores"] = []
    _gate_u, report_u = _gate_and_report(unbounded)
    text_u = render_markdown(report_u, evidence_ids=8, gap_ids=16)
    assert "what is missing: the technical severity rating itself**" in text_u
    assert "- scores: none (a gap)" in text_u


def test_attachments_filtering_poc_handoff_withheld_and_rendering_branches() -> None:
    verified = verified_document()
    confirmed_pkg, supported_pkg = verified["packages"]
    # Exercise judge_verdict, independence flags, native rating, missing predicates, and ID truncation.
    confirmed_pkg["independence"] = {
        "independent": False,
        "provider_distinct": False,
        "verifier_model_distinct": False,
        "judge_model_distinct": True,
    }
    confirmed_pkg["judge_verdict"] = {
        "verdict": "red_correct",
        "disagrees_with_state": True,
        "verdict_ids": [f"judge-{sha256_hex('j1')}"],
    }
    confirmed_pkg["direct_evidence"] = [f"evrel-{sha256_hex(f'e{i}')}" for i in range(3)]
    confirmed_pkg["analyst_assessed_evidence"] = [f"evrel-{sha256_hex('a1')}"]
    confirmed_pkg["missing_predicates"] = ["missing_or_ineffective_guard"]
    confirmed_pkg["gap_ids"] = [f"gap-{sha256_hex(f'g{i}')}" for i in range(3)]
    confirmed_pkg["scores"][0]["native"] = {"nomenclature": "CVSS:3.1", "rating": "HIGH", "score": 8.2}

    supported_pkg["independence"]["judge_model_distinct"] = False
    supported_pkg["judge_verdict"] = {
        "verdict": "partly",
        "disagrees_with_state": False,
        "verdict_ids": [f"judge-{sha256_hex('j2')}"],
    }
    # Force supported_pkg into withheld bucket by referencing an unavailable chain id.
    supported_pkg["attack_chains"] = [f"chain-{sha256_hex('missing-chain')}"]
    verified["gap_ids"] = [f"gap-{sha256_hex(f'rg{i}')}" for i in range(3)]

    gate, _initial = _gate_and_report(verified)
    assert len(gate["buckets"]["withheld"]) == 1

    # Populate attack_chains (both kept and filtered-out statuses), poc_generation, planning, validation, dossiers.
    ref = {"path": "data/artifact.json", "sha256": HASH}
    poc_handoff = {"path": "data/poc-handoff.json", "sha256": sha256_hex("poc-handoff")}
    gate["capabilities"]["poc_generation"].update(
        enabled=True, disposition="SUCCEEDED", handoff=poc_handoff, item_count=2
    )
    gate["capabilities"]["attack_chains"].update(enabled=True, disposition="SUCCEEDED", item_count=2)
    gate["capabilities"]["remediation_planning"].update(enabled=True, disposition="SUCCEEDED", item_count=2)
    gate["capabilities"]["remediation_validation"].update(enabled=True, disposition="SUCCEEDED", item_count=2)
    gate["capabilities"]["dossiers"].update(enabled=True, disposition="SUCCEEDED", item_count=2)

    claim_a = confirmed_pkg["claim_id"]
    claim_b = supported_pkg["claim_id"]
    binding_a = {
        "claim_id": claim_a,
        "finding_package_id": confirmed_pkg["finding_package_id"],
        "sha256": confirmed_pkg["sha256"],
    }
    binding_b = {
        "claim_id": claim_b,
        "finding_package_id": supported_pkg["finding_package_id"],
        "sha256": supported_pkg["sha256"],
    }
    gate["attachments"]["attack_chains"] = [
        {
            "chain_id": f"chain-{sha256_hex('c1')}",
            "status": "confirmed",
            "component_claim_ids": [claim_a, claim_b],
            "artifact": ref,
            "gap_count": 0,
            "disposition": "assessed",
        },
        {
            "chain_id": f"chain-{sha256_hex('c2')}",
            "status": "refuted",
            "component_claim_ids": [claim_a, claim_b],
            "artifact": ref,
            "gap_count": 0,
            "disposition": "assessed",
        },
    ]
    gate["attachments"]["poc_generation"] = [
        {
            "finding_package_id": confirmed_pkg["finding_package_id"],
            "claim_id": claim_a,
            "status": "compile_verified",
            "description": "Compile-checked trigger",
            "functions": {"test_function": "poc_trigger", "negative_control": "poc_control"},
            "files": {"source": ref, "compile": ref, "readme": ref, "provenance": ref},
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
        {
            "finding_package_id": supported_pkg["finding_package_id"],
            "claim_id": claim_b,
            "status": "policy_denied",
            "description": "Skipped by policy",
            "functions": None,
            "files": None,
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
    ]
    gate["attachments"]["remediation_planning"] = [
        {
            "finding": binding_a,
            "status": "proposal_generated",
            "plan": ref,
            "gap_ids": [],
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
        {
            "finding": binding_b,
            "status": "manual_design_required",
            "plan": None,
            "gap_ids": [],
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
    ]
    gate["attachments"]["remediation_validation"] = [
        {
            "finding": binding_a,
            "status": "build_checked",
            "validation": ref,
            "gap_ids": [],
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
        {
            "finding": binding_b,
            "status": "manual_validation_required",
            "validation": None,
            "gap_ids": [],
            "execution": "not_performed_by_policy",
            "runtime_verified": False,
            "result_id": None,
        },
    ]
    gate["attachments"]["dossiers"] = [
        {
            "dossier_id": f"dossier-{sha256_hex('d1')}",
            "kind": "confirmed_finding",
            "finding": binding_a,
            "status": "rendered",
            "files": {"json": ref, "latex": ref, "pdf": ref, "receipt": ref},
            "gap_ids": [],
        },
        {
            "dossier_id": f"dossier-{sha256_hex('d2')}",
            "kind": "poc",
            "finding": binding_a,
            "status": "render_failed",
            "files": {"json": ref, "latex": ref, "pdf": None, "receipt": ref},
            "gap_ids": [],
        },
    ]

    report = build_report(
        gate,
        gate_handoff={"path": "data/gate-handoff.json", "sha256": HASH},
        gate_document={"path": "data/gate.json", "sha256": HASH},
    )
    _validator(report_schema_name(report)).validate(report)
    assert SchemaSet(SCHEMAS).errors(report_schema_name(report), report) == []

    # Only confirmed / qualified_supported chains survive into report["attack_chains"].
    assert report["attack_chains"]["status"] == "available"
    assert [row["status"] for row in report["attack_chains"]["items"]] == ["confirmed"]
    assert report["poc_outcomes"]["status"] == "available"
    assert report["poc_outcomes"]["reason"] == POC_REASON
    assert report["poc_outcomes"]["poc_handoff"] == poc_handoff
    assert report["provenance"]["poc_handoff"] == poc_handoff

    # Render with bounded IDs (1) and zero IDs (0) to cover all _ids / section branches.
    md_bounded = render_markdown(report, evidence_ids=1, gap_ids=1)
    assert "and 2 more (see final-report.json)" in md_bounded
    assert "native rating `HIGH`" in md_bounded
    assert "the judge disagrees with this finding's state; judge model distinct yes" in md_bounded
    assert "missing predicates: `missing_or_ineffective_guard`" in md_bounded
    assert "test function `poc_trigger`, negative control `poc_control`" in md_bounded
    assert "no artifact available" in md_bounded
    assert "The verification backlog is empty." in md_bounded
    assert "withheld because: `attack_chain_unavailable`" in md_bounded

    md_zero = render_markdown(report, evidence_ids=0, gap_ids=0)
    assert "3 (not listed here; see final-report.json)" in md_zero

    # Also cover empty findings section and PoC outcome without claim_id + hostile markup neutralization.
    empty_findings_report = deepcopy(report)
    empty_findings_report["findings"] = []
    empty_findings_report["verification_backlog"] = [deepcopy(supported_pkg)]
    empty_findings_report["poc_outcomes"]["items"].append(
        {"finding_package_id": confirmed_pkg["finding_package_id"], "status": "not_applicable"}
    )
    separator = chr(0x2028)
    hostile = "```\n<script>alert(1)</script> | [x](http://evil) " + separator + "\n# injected"
    empty_findings_report["verification_backlog"][0]["title"] = hostile
    empty_findings_report["limitations"][0]["statement"] = hostile
    md_hostile = render_markdown(empty_findings_report, evidence_ids=8, gap_ids=16)
    assert "No confirmed finding packages are publishable." in md_hostile
    assert "judge model distinct no" in md_hostile
    assert separator not in md_hostile and "\n```" not in md_hostile
    hostile_lines = md_hostile.splitlines()
    first_lim_id = empty_findings_report["limitations"][0]["limitation_id"]
    statement_line = next(line for line in hostile_lines if line.startswith(f"- `{first_lim_id}`"))
    assert "<script>" not in statement_line and "\\<script\\>" in statement_line
    title_line = next(line for line in hostile_lines if line.startswith("### 1. "))
    assert title_line.startswith("### 1. `") and title_line.endswith("`") and title_line.count("`") == 2
    assert not any(line.startswith("# injected") for line in hostile_lines)
    assert code("a`b\x00\nc") == "`a'b c`"
    assert plain("*x* <b> #h") == "\\*x\\* \\<b\\> \\#h"

    # Cover attack_chains filtering to empty when only refuted chains exist.
    only_refuted_gate = deepcopy(gate)
    only_refuted_gate["attachments"]["attack_chains"] = [gate["attachments"]["attack_chains"][1]]
    only_refuted_report = build_report(
        only_refuted_gate,
        gate_handoff={"path": "data/gate-handoff.json", "sha256": HASH},
        gate_document={"path": "data/gate.json", "sha256": HASH},
    )
    assert only_refuted_report["attack_chains"]["status"] == "none_available"
    assert only_refuted_report["attack_chains"]["items"] == []
    # "none available" is explained: the refuted candidate is counted, and the gate's accounting is relayed.
    assert only_refuted_report["attack_chains"]["status_counts"] == {
        "admitted": 1, "confirmed": 0, "qualified_supported": 0, "refuted": 1, "insufficient_evidence": 0}
    assert only_refuted_report["attack_chains"]["reason"].startswith(
        "1 candidate chain(s) proposed, 1 admitted: 0 confirmed, 0 qualified_supported, 1 refuted, "
        "0 insufficient_evidence. Only confirmed and qualified_supported chains are listed. ")
    counted_gate = deepcopy(only_refuted_gate)
    counted_gate["capabilities"]["attack_chains"]["status_counts"] = {
        "proposed": 4, "admitted": 1, "assessed": 1, "capped": 0, "rejected": 2, "deduplicated": 1,
        "confirmed": 0, "qualified_supported": 0, "refuted": 1, "insufficient_evidence": 0}
    counted = build_report(counted_gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": HASH},
                           gate_document={"path": "data/gate.json", "sha256": HASH})
    _validator(report_schema_name(counted)).validate(counted)
    assert counted["attack_chains"]["reason"].startswith(
        "4 candidate chain(s) proposed, 1 admitted: 0 confirmed, 0 qualified_supported, 1 refuted, "
        "0 insufficient_evidence; 2 rejected, 1 deduplicated, 0 capped by max_attack_chains. ")
    assert counted["attack_chains"]["status_counts"]["proposed"] == 4
    empty_gate = deepcopy(only_refuted_gate)
    empty_gate["attachments"]["attack_chains"] = []
    empty = build_report(empty_gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": HASH},
                         gate_document={"path": "data/gate.json", "sha256": HASH})
    assert empty["attack_chains"]["reason"].startswith("No candidate attack chain was proposed")


def test_unverified_link_trust_boundary_renders_domain_transition_and_preserves_v2_v4_schemas(
    tmp_path: Path,
) -> None:
    verified = _serialized_review(tmp_path, (("confirmed", "high"), ("confirmed", "medium")))
    members = [row["claim_id"] for row in verified["packages"][:2]]
    chain_id = f"chain-{sha256_hex('unverified-boundary')}"
    chain_ref = {"path": "data/chain-unverified.json", "sha256": HASH}
    manifest = {"path": "data/chains.json", "sha256": HASH}
    verified["attachments"]["attack_chains"] = [
        {
            "chain_id": chain_id,
            "status": "confirmed",
            "component_claim_ids": members,
            "artifact": chain_ref,
            "gap_count": 0,
            "disposition": "assessed",
        }
    ]
    verified["capabilities"]["attack_chains"] = capability(True, summary=manifest, count=1)
    verified["bindings"].extend([manifest, chain_ref])

    _gate, report = _gate_and_report(verified)
    assert report_schema_name(report) == "final-report-v4"
    assert report["attack_chain_cards"][0]["trust_boundary_crossed"] == "[unverified link]"

    md_unverified = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert "reported domain transition (not a source-resolved boundary)" in md_unverified
    assert "source-resolved boundary `[unverified link]`" not in md_unverified

    resolved_card_report = deepcopy(report)
    resolved_card_report["attack_chain_cards"][0]["trust_boundary_crossed"] = "edge_gateway -> auth_db"
    md_resolved = render_markdown(resolved_card_report, evidence_ids=8, gap_ids=16)
    assert "source-resolved boundary `edge_gateway -> auth_db`" in md_resolved
    assert "reported domain transition (not a source-resolved boundary)" not in md_resolved

    # final-report-v4 rejects non-'[unverified link]' trust_boundary_crossed, while historical final-report (v2) keeps its contract.
    assert SchemaSet(SCHEMAS).errors("final-report-v4", resolved_card_report) != []
    v2_schema = json.loads((SCHEMAS / "final-report.schema.json").read_text(encoding="utf-8"))
    v2_card_def = v2_schema["$defs"]["attack_chain_card"]
    assert v2_card_def["properties"]["trust_boundary_crossed"] == {"type": "string", "minLength": 1}
    assert v2_card_def["properties"]["steps"]["items"]["properties"]["role"]["enum"] == ["entry", "hop", "sink"]
    v4_schema = json.loads((SCHEMAS / "final-report-v4.schema.json").read_text(encoding="utf-8"))
    v4_card_def = v4_schema["$defs"]["attack_chain_card"]
    assert v4_card_def["properties"]["trust_boundary_crossed"] == {"const": "[unverified link]"}
    assert "component" in v4_card_def["properties"]["steps"]["items"]["properties"]["role"]["enum"]


def _candidate_job_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    render_pdf: bool = True,
) -> tuple[Any, dict[str, Any]]:
    from types import SimpleNamespace
    from appsec_review.config import JobConfig
    from appsec_review.indexing.store import AcceptedHandoff
    from appsec_review.jobs.bound_artifacts import artifact_ref
    from appsec_review.jobs.completion_contracts import DOSSIER_PUBLICATION_SCHEMA
    from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
    from appsec_review.jobs.job_final_publication_gate import verify as gate_verify
    from appsec_review.jobs.job_final_publication_gate.attachments import _dossiers
    from appsec_review.jobs.job_final_report_publication import JOB_ID
    from appsec_review.reporting.dossier_render import render_dossier
    from appsec_review.reporting.dossiers import build_dossier
    from appsec_review.runtime import JobContext, UnitContext
    from appsec_review.storage import atomic_json
    from tests.dossier_fixture import settings as dossier_settings
    from tests.unit.review_decision_audit_wiring.helpers import events, put

    gate_job = "job_final_publication_gate"
    attempt = f"data/jobs/{JOB_ID}/attempts/attempt_0001"
    image_tag = "appsec-review/tool-report-latex:1.0.0"
    image_id = "sha256:" + "ab" * 32
    raw_excerpt = "SECRET_SOURCE_EXCERPT_strcpy(stack_buf, user_hdr);"

    root = tmp_path / "run-exec-candidates"
    verified = verified_document()
    verified["run_id"] = root.name
    for name in verified["inputs"]:
        verified["inputs"][name] = put(root, f"data/{name}.json", {"input": name})
    verified["bindings"] = list(verified["inputs"].values())

    finding = verified["packages"][0]
    dossier_doc = build_dossier(
        run_id=root.name,
        kind="confirmed_finding",
        finding=finding,
        claim={
            "claim_id": finding["claim_id"],
            "state": finding["state"],
            "statement": "Untrusted frame header length reaches fixed buffer copy without validation.",
            "weakness_cwe": "CWE-120",
            "security_predicate": "memory_corruption",
            "preconditions": [],
        },
        relations=[
            {
                "relation_id": key,
                "claim_id": finding["claim_id"],
                "kind": "supports",
                "admissibility": "direct",
                "complete": True,
            }
            for key in finding["direct_evidence"] + finding["analyst_assessed_evidence"]
        ],
        excerpts=[
            {
                "identity": "asr:source_file:" + "f" * 64,
                "location": {
                    "path": "src/parser.c",
                    "source_id": "s",
                    "file_sha256": "f" * 64,
                    "target_snapshot": "synthetic-snapshot",
                    "mapping_method": "exact",
                    "ambiguous": False,
                },
                "excerpt_start_line": 40,
                "excerpt_end_line": 52,
                "excerpt": raw_excerpt,
            }
        ],
        provenance={},
    )
    dossier_base = "data/jobs/job_dossier_publication/attempts/attempt_0001/steps/dossiers/tasks/create/d1"
    item = render_dossier(
        root,
        root / dossier_base,
        dossier_doc,
        settings=dossier_settings(render_pdf=False),
        repository_root=ROOT,
        executor_factory=lambda *_: pytest.fail("dossier PDF disabled"),
    )
    publication = {
        "schema": DOSSIER_PUBLICATION_SCHEMA,
        "run_id": root.name,
        "items": [item],
        "omitted": [],
        "counts": {
            "admitted": 1,
            "items": 1,
            "omitted": 0,
            "by_kind": {"confirmed_finding": 1, "poc": 0},
            "by_status": {"rendered": 0, "render_failed": 0, "latex_only": 1},
        },
        "caps": {"max_dossiers": 1},
    }
    verified["attachments"]["dossiers"] = _dossiers(
        root,
        publication,
        {row["finding_package_id"]: row for row in verified["packages"]},
        [],
        verified["bindings"],
    )
    d_handoff = put(root, "data/jobs/job_dossier_publication/attempts/attempt_0001/handoff.json", {"job": "dossiers"})
    d_summary = put(root, "data/jobs/job_dossier_publication/attempts/attempt_0001/summary.json", publication)
    verified["capabilities"]["dossiers"] = capability(True, handoff=d_handoff, summary=d_summary, count=1)
    verified["bindings"] += [d_handoff, d_summary]
    verified["bindings"] = [
        {"path": p, "sha256": d}
        for p, d in sorted({(row["path"], row["sha256"]) for row in verified["bindings"]})
    ]

    config_ref = put(root, "data/configuration/resolved.json", {"jobs": {JOB_ID: {"settings": {"render_timeout_seconds": 600}}}})
    put(root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
    verified["bindings"].append(config_ref)

    classification = gate_classify.classify(verified)
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
    gate_path = root / "data/jobs/job_final_publication_gate/attempts/attempt_0001/steps/acceptance/tasks/publish_handoff/final-publication-gate.json"
    atomic_json(gate_path, gate)
    gate_ref = artifact_ref(root, gate_path)
    handoff_payload = {
        "job_id": gate_job,
        "outputs": {
            "acceptance.publish_handoff": {
                "schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
                "artifact": gate_ref,
                "item_count": gate["package_counts"]["total"],
            }
        },
    }
    handoff_ref = put(root, "data/jobs/job_final_publication_gate/attempts/attempt_0001/handoff.json", handoff_payload)
    accepted = AcceptedHandoff(gate_job, handoff_payload, handoff_ref["sha256"], handoff_ref["path"])
    monkeypatch.setattr(
        gate_verify,
        "accepted_handoff",
        lambda _run_root, jid: accepted if jid == gate_job else None,
    )
    settings = {
        "enabled": True,
        "markdown_evidence_ids": 8,
        "markdown_gap_ids": 16,
        "render_pdf": render_pdf,
        "image_tag": image_tag,
        "image_id": image_id,
        "render_timeout_seconds": 600,
        "max_pdf_bytes": 16777216,
    }
    cfg = JobConfig(JOB_ID, "final_report_publication", 1, None, settings, {})
    job_ctx = JobContext(
        root.name,
        "attempt_0001",
        "unit-fixture",
        ROOT,
        root,
        root / attempt,
        root / "metadata",
        {},
        cfg,
        events(),
        upstream_handoffs={gate_job: accepted.sha256},
    )

    def mk_unit(unit_id: str, outputs: dict[str, Any] | None = None) -> UnitContext:
        step, task = unit_id.split(".")
        return UnitContext(
            job_ctx,
            unit_id,
            step,
            task,
            root / attempt / "steps" / step / "tasks" / task,
            outputs or {},
        )

    fx = SimpleNamespace(
        root=root,
        attempt=attempt,
        image_id=image_id,
        raw_excerpt=raw_excerpt,
        unit=mk_unit,
    )
    return fx, dossier_doc


def _candidate_executor(*, fail_on_run_index: int | None = None):
    from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor

    image_id = "sha256:" + "ab" * 32
    pdf_bytes = b"%PDF-1.5\n" + b"streamlined candidate pdf " * 4 + b"\n%%EOF\n"
    run_counter = {"count": 0}

    class FixtureExecutor(ContainerExecutor):
        def _docker_bind_source(self, path):
            return path

    def factory(catalog, root):
        def runner(argv, timeout):
            if argv[1:3] == ("image", "inspect"):
                return CommandOutcome(0, image_id.encode(), b"")
            if "run" in argv:
                idx = run_counter["count"]
                run_counter["count"] += 1
                mounts = [argv[i + 1] for i, val in enumerate(argv) if val == "--mount"]
                spec = next(item for item in mounts if "dst=/scratch" in item)
                scratch = Path(spec.split("src=", 1)[1].split(",dst=")[0])
                (scratch / "report.log").write_bytes(b"xelatex log\n")
                (scratch / "report.pdfinfo.txt").write_bytes(b"Pages: 5\n")
                if fail_on_run_index is not None and idx == fail_on_run_index:
                    return CommandOutcome(1, b"candidate xelatex failure", b"error")
                (scratch / "report.pdf").write_bytes(pdf_bytes)
                return CommandOutcome(0, b"ok", b"")
            return CommandOutcome(0, b"", b"")

        return FixtureExecutor(catalog, root, runner=runner)

    return factory


def test_final_report_job_publishes_executive_candidates_and_claims_all_datasets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
    from appsec_review.jobs.bound_artifacts import read_bound, read_bound_json
    from appsec_review.jobs.job_final_report_publication import JOB_ID, build_job
    from appsec_review.jobs.job_final_report_publication.datasets import DATASETS
    from appsec_review.reporting.executive_candidates import CANDIDATE_IDS, CANDIDATE_LABELS, CANDIDATE_TITLES

    fx, _dossier = _candidate_job_fixture(tmp_path, monkeypatch, render_pdf=True)
    built = build_job(executor_factory=_candidate_executor())
    outputs: dict[str, Any] = {}
    for unit in built.units:
        outputs[unit.unit_id] = unit.handler(fx.unit(unit.unit_id, outputs))

    rendered = outputs["report.render"]
    pdf_out = outputs["report.render_pdf"]
    published = outputs["acceptance.publish_handoff"]
    assert published["terminal_status"] == "SUCCEEDED"
    assert set(rendered["executive_candidates"]) == set(CANDIDATE_IDS)
    assert set(pdf_out["executive_candidates"]) == set(CANDIDATE_IDS)
    assert set(published["executive_candidates"]) == set(CANDIDATE_IDS)

    render_dir = fx.root / fx.attempt / "steps/report/tasks/render"
    pdf_dir = fx.root / fx.attempt / "steps/report/tasks/render_pdf"
    assert (render_dir / "final-report.md").is_file()
    assert (render_dir / "final-report.html").is_file()
    assert (pdf_dir / "final-report.tex").is_file()
    assert (pdf_dir / "final-report.pdf").is_file()
    assert (pdf_dir / "receipt.json").is_file()

    for cid in CANDIDATE_IDS:
        entry = published["executive_candidates"][cid]
        assert entry["label"] == CANDIDATE_LABELS[cid]
        assert entry["title"] == CANDIDATE_TITLES[cid]
        assert entry["markdown"]["path"].endswith(f"steps/report/tasks/render/executive-report-candidate-{cid}.md")
        assert entry["html"]["path"].endswith(f"steps/report/tasks/render/executive-report-candidate-{cid}.html")
        assert entry["pdf"]["state"] == "rendered"
        assert entry["pdf"]["latex"]["path"].endswith(f"steps/report/tasks/render_pdf/executive-report-candidate-{cid}.tex")
        assert entry["pdf"]["file"]["path"].endswith(f"steps/report/tasks/render_pdf/executive-report-candidate-{cid}.pdf")
        assert entry["pdf"]["receipt"]["path"].endswith(f"steps/report/tasks/render_pdf/receipt-candidate-{cid}.json")
        receipt = read_bound_json(fx.root, entry["pdf"]["receipt"])
        _validator("final-report-pdf-receipt").validate(receipt)
        for ref in (entry["markdown"], entry["html"], entry["pdf"]["latex"]):
            body = read_bound(fx.root, ref).decode("utf-8")
            assert fx.raw_excerpt not in body
            assert "SECRET_SOURCE_EXCERPT" not in body
            assert "<redacted:" not in body.lower()

    claims = runtime_claims({JOB_ID: ("load", "report", "acceptance")}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(fx.root, FileClaims(claims), max_files=10_000)
    unaccounted = [p for p in tree.unaccounted if p.startswith(f"data/jobs/{JOB_ID}")]
    assert unaccounted == []


def test_final_report_executive_candidate_pdf_failure_and_tamper_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from appsec_review.jobs.bound_artifacts import artifact_ref
    from appsec_review.jobs.job_final_report_publication import build_job
    from appsec_review.review.models import IntegrityError
    from appsec_review.storage import atomic_bytes

    # Run index 0 = final-report.pdf (succeeds); run index 2 = Candidate B PDF (fails)
    fx, _dossier = _candidate_job_fixture(tmp_path, monkeypatch, render_pdf=True)
    built = build_job(executor_factory=_candidate_executor(fail_on_run_index=2))
    outputs: dict[str, Any] = {}
    for unit in built.units:
        outputs[unit.unit_id] = unit.handler(fx.unit(unit.unit_id, outputs))

    pdf_out = outputs["report.render_pdf"]
    published = outputs["acceptance.publish_handoff"]
    assert pdf_out["status"] == "rendered"
    assert pdf_out["executive_candidates"]["a"]["status"] == "rendered"
    assert pdf_out["executive_candidates"]["b"]["status"] == "render_failed"
    assert pdf_out["executive_candidates"]["b"]["files"]["pdf"] is None
    assert (fx.root / pdf_out["executive_candidates"]["b"]["files"]["latex"]["path"]).is_file()
    assert pdf_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any(gap["scope_id"] == "executive_candidate_b_pdf" for gap in pdf_out["gaps"])
    assert any(gap["scope_id"] == "executive_candidate_b_pdf" for gap in published["gaps"])

    # Tampering with Candidate A Markdown after render fails closed in publish_handoff:
    cand_a_md = fx.root / outputs["report.render"]["executive_candidates"]["a"]["markdown"]["path"]
    original_bytes = cand_a_md.read_bytes()
    atomic_bytes(cand_a_md, b"# tampered candidate markdown\n")
    forged_render = deepcopy(outputs["report.render"])
    forged_render["executive_candidates"]["a"]["markdown"] = artifact_ref(fx.root, cand_a_md)
    with pytest.raises(IntegrityError, match="executive-report-candidate-a.md"):
        built.units[-1].handler(
            fx.unit("acceptance.publish_handoff", {**outputs, "report.render": forged_render})
        )
    atomic_bytes(cand_a_md, original_bytes)
