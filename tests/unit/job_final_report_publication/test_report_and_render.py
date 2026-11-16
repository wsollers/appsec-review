"""Report assembly, schema validation, decision_pending projection, and Markdown rendering unit tests."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA, FINAL_REPORT_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_report_publication.render import code, plain, render_markdown
from appsec_review.jobs.job_final_report_publication.report import (
    NOTICES, PDF_REASON, POC_REASON, RENDERER, build_report,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.identity import sha256_hex
from tests.unit.review_decision_audit_wiring.helpers import HASH, verified_document

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "docs" / "schemas" / "final-report"
NAMES = ("common", "final-publication-gate", "final-report")


def _validator(name: str) -> Draft202012Validator:
    documents = [json.loads((SCHEMAS / f"{item}.schema.json").read_text(encoding="utf-8")) for item in NAMES]
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
    _validator("final-report").validate(report)
    assert SchemaSet(SCHEMAS).errors("final-report", report) == []
    return gate, report


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
    _validator("final-report").validate(report)
    assert SchemaSet(SCHEMAS).errors("final-report", report) == []

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
