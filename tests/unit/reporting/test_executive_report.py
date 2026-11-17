"""The executive report document: plain-language findings, honest empty sections, no excerpts, deterministic."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from appsec_review.jobs.completion_contracts import DOSSIER_SCHEMA
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_report_publication.report import build_report
from appsec_review.reporting.executive_report import (
    NOT_CLEAN, POLICY_STATEMENT, RENDERER, BoundDossier, executive_document, words,
)
from appsec_review.reporting.dimensions import DIMENSIONS, dimension_counts
from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.model import Box, Document, Heading, RadarChart
from appsec_review.review.identity import sha256_hex
from tests.unit.review_decision_audit_wiring.helpers import verified_document

ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = ROOT / "containers" / "report" / "latex" / "template"
EXCERPT = "SECRET_EXCERPT_memcpy(buf, input, length);"


def report_document(verified: dict[str, Any] | None = None) -> dict[str, Any]:
    verified = verified or verified_document()
    gate = gate_classify.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, gate_classify.classify(verified))
    return build_report(gate, gate_handoff={"path": "data/gate-handoff.json", "sha256": sha256_hex("handoff")},
                        gate_document={"path": "data/gate.json", "sha256": sha256_hex("gate")})


def dossier_for(finding: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    binding = {key: finding[key] for key in ("claim_id", "finding_package_id", "sha256")}
    document = {
        "schema": DOSSIER_SCHEMA, "dossier_id": "dossier-" + sha256_hex(finding["claim_id"]), "run_id": "run-wiring",
        "kind": "confirmed_finding", "finding": binding, "visibility": "protected_developer",
        "title": finding["title"], "state": finding["state"], "lane": finding["lane"],
        "statement": "An attacker-controlled length reaches a fixed-size copy without a bound check.",
        "weakness_cwe": "CWE-120", "security_predicate": "memory_corruption",
        "preconditions": ["network access to the parser endpoint"],
        "ship_block": {"policy": "ship-block-policy/1", "status": "ship_blocking", "technical_severity": "high"},
        "missing_predicates": [], "evidence": [], "scores": [], "chains": [
            {"chain_id": "chain-" + sha256_hex("c"), "status": "qualified_supported", "objective": "reach the parser"}],
        "sources": [{"entity_id": "asr:x:" + "0" * 64, "path": "src/parser.c", "source_id": "s", "file_sha256": "0" * 64,
                     "mapping_method": "exact", "mapping_confidence": 1, "mapping_ambiguous": False,
                     "target_snapshot": "t", "start_line": 40, "end_line": 52, "excerpt": EXCERPT,
                     "upstream_truncated": False}],
        "poc": None,
        "remediation": [{"stage": "proposal", "status": "proposal_generated", "reason": "bound the copy length",
                         "corrected_invariant": "length never exceeds the buffer size", "violated_invariant": "x",
                         "artifact": None}],
        "notices": [], "gaps": [], "truncations": [], "provenance": {},
    }
    document.update(overrides)
    return document


def bound(document: dict[str, Any]) -> BoundDossier:
    return BoundDossier(document["dossier_id"], document["kind"], document["finding"], document)


def tex_of(report: dict[str, Any], dossiers: tuple[BoundDossier, ...] = ()) -> str:
    return render_latex(executive_document(report, dossiers), TEMPLATE)


def test_confirmed_finding_is_explained_in_plain_language_from_its_dossier() -> None:
    report = report_document()
    finding = report["findings"][0]
    dossier = dossier_for(finding)
    document = executive_document(report, (bound(dossier),))
    assert isinstance(document, Document) and document.renderer == RENDERER
    assert document.status_badge == "COMPLETE" and document.named_gaps == ()
    tex = tex_of(report, (bound(dossier),))
    # What, where, why it is bad, severity, verification and shipment, in words.
    assert "1. Synthetic finding 0" in tex
    assert "attacker{-}controlled length reaches a fixed{-}size copy" in tex
    assert "src/\\allowbreak{}parser.c, lines 40{-}52" in tex
    assert "memory corruption" in tex and "network access to the parser endpoint" in tex
    assert "CWE{-}120" in tex
    assert "High: a serious weakness that an attacker could turn into real damage" in tex
    assert "Blocks shipping: under the policy this must be fixed before a release" in tex
    assert "Yes: an independent verifier confirmed this finding" in tex
    assert "bound the copy length" in tex and "not a verified fix" in tex
    assert "qualified supported; reach the parser" in tex
    # The verification backlog is listed as unconfirmed, never as a finding.
    assert "supported but not independently confirmed" in tex and "Synthetic finding 1" in tex
    # The executive summary and the policy statement.
    assert "It may be presented as complete." in tex
    assert "1 finding: Blocks shipping" in tex and "1 finding: Needs verification" in tex
    assert "compiled only and never executed" in POLICY_STATEMENT and "compiled only and never executed" in tex


def test_excerpts_prompts_and_payloads_never_reach_the_document() -> None:
    report = report_document()
    dossier = dossier_for(report["findings"][0])
    dossier["poc"] = {"status": "compile_verified", "reason": "compiled", "description": "PAYLOAD_TEXT",
                      "source": "int main(){ EXPLOIT_CODE }"}
    dossier["evidence"] = [{"relation_id": "r", "locator": "PROMPT_TEXT retrieve the sink"}]
    tex = tex_of(report, (bound(dossier),))
    for forbidden in (EXCERPT, "SECRET_EXCERPT", "EXPLOIT_CODE", "PAYLOAD_TEXT", "PROMPT_TEXT", "codebox"):
        assert forbidden not in tex
    assert "lines 40{-}52" in tex


def test_none_available_sections_name_their_reason_and_never_read_as_clean() -> None:
    report = report_document()
    for key in ("attack_chains", "poc_outcomes", "remediation_planning", "remediation_validation"):
        assert report[key]["status"] == "none_available"
    document = executive_document(report, ())
    boxes = [block for block in document.blocks if isinstance(block, Box)]
    for title in ("Connected attack chains", "Proof-of-concept outcomes (compile only)", "Remediation proposals",
                  "Remediation validation"):
        box = next(block for block in boxes if block.title == title)
        assert box.kind.value == "gap"
        texts = " ".join(item.text for item in box.items if hasattr(item, "text"))
        assert "None available." in texts and NOT_CLEAN in texts
        assert "frozen configuration" in texts
    tex = tex_of(report)
    assert tex.count(NOT_CLEAN.replace("-", "{-}")) >= 5
    headings = [block.text for block in document.blocks if isinstance(block, Heading)]
    assert headings == ["Executive summary", "Review coverage by security dimension",
                        "Prioritized remediation roadmap", "Confirmed findings",
                        "Attack chains", "Proof-of-trigger outcomes",
                        "Remediation", "Verification backlog and withheld packages", "Limitations and coverage",
                        "Appendix: provenance"]


def test_incomplete_review_says_why_and_lists_gaps_by_kind() -> None:
    verified = verified_document()
    verified["review"]["status"] = "DEGRADED"
    verified["accounting"]["outcome"] = "DEGRADED"
    report = report_document(verified)
    assert report["status"]["review_complete"] is False
    tex = tex_of(report)
    assert "It may not be presented as complete" in tex
    assert "Why the review is not complete" in tex and "review degraded" in tex
    assert "Gaps (" in tex and "Notices (" in tex and "Stages not run (" in tex
    assert "compile only nonexecution" in tex
    assert report["provenance"]["ledger_head_sha256"][:14] in tex.replace("\\allowbreak{}", "")


def test_missing_or_mismatched_dossier_is_a_named_gap_not_a_silent_omission() -> None:
    report = report_document()
    finding = report["findings"][0]
    gap = BoundDossier("dossier-" + sha256_hex("x"), "confirmed_finding",
                       {key: finding[key] for key in ("claim_id", "finding_package_id", "sha256")}, None,
                       "executive_dossier_unavailable: run-owned artifact changed after acceptance")
    document = executive_document(report, (gap,))
    assert document.named_gaps == (gap.gap,)
    tex = tex_of(report, (gap,))
    assert "dossier was not available to this report" in tex
    assert "0 of 1 gate{-}certified dossier documents" in tex
    assert "changed after acceptance" in tex
    with pytest.raises(ValueError, match="unsupported dossier model"):
        executive_document(report, (bound(dossier_for(finding, schema="appsec-review/other/1")),))


def test_rendering_is_deterministic_and_order_independent_of_dossier_input() -> None:
    report = report_document()
    dossier = dossier_for(report["findings"][0])
    first = tex_of(deepcopy(report), (bound(deepcopy(dossier)),))
    second = tex_of(report, (bound(dossier),))
    assert first == second
    assert executive_document(report, (bound(dossier),)) == executive_document(report, (bound(dossier),))
    assert words("ship_blocking_pending_distinct_verification") == "ship blocking pending distinct verification"


def test_consequence_classes_are_explained_in_business_terms_and_locations_deduplicated() -> None:
    from appsec_review.reporting import executive_report as E
    from appsec_review.review.models import SecurityPredicate
    # Every value of the closed vocabulary has a plain-language meaning, except "other".
    assert {p.value for p in SecurityPredicate} - {"other"} <= set(E.CONSEQUENCES)
    dossier = {"security_predicate": "command_injection", "preconditions": [],
               "sources": [{"path": "src/a.cpp", "start_line": 3, "end_line": 5},
                           {"path": "src/a.cpp", "start_line": 3, "end_line": 5},
                           {"path": "src/a.cpp", "start_line": 9, "end_line": 9}]}
    assert "operating-system commands" in E._attacker_gain(dossier, {})
    assert E._locations(dossier) == ["src/a.cpp, lines 3-5", "src/a.cpp, line 9"]


def test_connected_line_ranges_of_one_file_collapse_to_their_union() -> None:
    """Owner's rule: references to connected code collapse; [5,10] and [6,12] read as [5,12]."""
    from appsec_review.reporting import executive_report as E
    assert E.merge_spans([(5, 10), (6, 12)]) == [(5, 12)]
    assert E.merge_spans([(6, 12), (5, 10), (11, 12), (20, 22), (23, 23)]) == [(5, 12), (20, 23)]   # touching joins
    assert E.merge_spans([(5, 10), (12, 14)]) == [(5, 10), (12, 14)]                                # a gap stays
    assert E.merge_spans([(10, 5)]) == [(5, 10)]                                                    # order-insensitive
    dossier = {"sources": [{"path": "src/request.cpp", "start_line": 77, "end_line": 81},
                           {"path": "src/request.cpp", "start_line": 74, "end_line": 78},
                           {"path": "src/request.cpp", "start_line": 26, "end_line": 30},
                           {"path": "src/request.cpp", "start_line": 65, "end_line": 83},
                           {"path": "src/other.cpp", "start_line": 4, "end_line": None}]}
    assert E._locations(dossier) == ["src/request.cpp, lines 26-30", "src/request.cpp, lines 65-83",
                                     "src/other.cpp, line range not recorded"]


def dimension_report() -> dict[str, Any]:
    """The wiring fixture with pipeline-shaped titles: one confirmed command injection, one backlog use after free."""
    report = report_document()
    report["findings"][0]["title"] = "command_injection (CWE-78)"
    report["verification_backlog"][0]["title"] = "use_after_free (CWE-416)"
    return report


def _chart_of(document: Document) -> RadarChart:
    return next(block for block in document.blocks if isinstance(block, RadarChart))


def _by_axis(chart: RadarChart, series_index: int) -> dict[str, float]:
    return dict(zip((axis.key for axis in chart.axes), chart.series[series_index].values))


def test_coverage_by_dimension_counts_findings_and_claims_per_axis_and_agrees_with_markdown() -> None:
    from appsec_review.jobs.job_final_report_publication.render import render_markdown
    from appsec_review.review.models import SecurityPredicate
    report = dimension_report()
    finding = report["findings"][0]
    dossier = dossier_for(finding, security_predicate="command_injection", weakness_cwe="CWE-78", title=finding["title"])
    document = executive_document(report, (bound(dossier),))
    chart = _chart_of(document)
    assert len(DIMENSIONS) == 12
    assert [axis.key for axis in chart.axes] == [
        "Auth", "AzZ", "Inj", "Mem", "Pars", "Cryp", "API", "Path", "Logi", "Deps", "CICD", "Hard"
    ]
    assert [series.label for series in chart.series] == [
        "Surface exposure", "Verified coverage", "Corroborated leads", "Confirmed High/Critical"
    ]
    surface, verified_cov, leads, confirmed_hc = (_by_axis(chart, idx) for idx in range(4))
    assert confirmed_hc["Inj"] == 1.0 and sum(confirmed_hc.values()) == 1.0
    assert leads["Inj"] == 1.0 and leads["Mem"] == 1.0 and sum(leads.values()) == 2.0
    assert surface["Inj"] == 1.0 and surface["Mem"] == 1.0
    assert verified_cov["Inj"] > 0.0 and chart.clamped == 0
    headings = [block.text for block in document.blocks if isinstance(block, Heading)]
    assert headings[:4] == [
        "Executive summary",
        "Review coverage by security dimension",
        "Prioritized remediation roadmap",
        "Confirmed findings",
    ]
    tex = tex_of(report, (bound(dossier),))
    assert r"\radarkeyrow{Inj}{Injection \& Command/\allowbreak{}SQL/\allowbreak{}Template}" in tex
    assert r"\draw[verdict-contradicted,radarline,densely dashdotted]" in tex
    assert "NEVER evidence that a security domain is clean" in tex
    assert "Uncovered: no claim was examined here." in tex and "1 claim examined, none confirmed. Not a clearance." in tex
    assert r"1 confirmed finding (1 high/\allowbreak{}critical) of 1 claim examined." in tex
    assert "Every accepted package names a member of the vocabulary" in tex
    # Markdown parity: 12-axis security radar & verification funnel agrees with dimension_counts.
    markdown = render_markdown(report, evidence_ids=8, gap_ids=16)
    assert "## Coverage by security dimension" in markdown
    assert "| Inj | Injection & Command/SQL/Template |" in markdown
    assert "| Mem | Memory & Native Safety |" in markdown
    rows, unclassified = dimension_counts(report)
    assert unclassified == 0 and [(row.key, row.findings, row.claims) for row in rows if row.claims] == [("Inj", 1, 1), ("Mem", 0, 1)]
    # Every member of the closed vocabulary except "other" lies in exactly one dimension.
    members = [predicate for dimension in DIMENSIONS for predicate in dimension.predicates]
    assert sorted(members) == sorted({predicate.value for predicate in SecurityPredicate} - {"other"})


def test_dossier_predicate_is_used_and_unparseable_titles_are_unclassified_never_guessed() -> None:
    report = report_document()                     # titles "Synthetic finding n" name no predicate
    dossier = dossier_for(report["findings"][0])   # the dossier says memory_corruption
    document = executive_document(report, (bound(dossier),))
    assert _by_axis(_chart_of(document), 3)["Mem"] == 1.0 and _by_axis(_chart_of(document), 2)["Mem"] == 1.0
    tex = tex_of(report, (bound(dossier),))
    assert "1 package named no member of the vocabulary and is counted in no dimension" in tex
    # Without the dossier nothing is classified: the chart says so instead of drawing a guess.
    tex = tex_of(report)
    assert r"\chartempty{No data}" in tex
    assert "2 packages named no member of the vocabulary and are counted in no dimension" in tex


def test_dimension_section_with_nothing_bound_reads_as_uncovered_not_clean() -> None:
    from appsec_review.reporting import executive_report as E
    blocks = E._dimension_blocks({"findings": [], "verification_backlog": [], "withheld": []}, ())
    chart = blocks[1]
    assert isinstance(chart, RadarChart) and all(value == 0 for series in chart.series for value in series.values)
    document = Document(title="x", run_id="r", subtitle="", status_badge="EMPTY", status_tone="unresolved",
                        source_date_epoch=0, ledger_head="ab" * 32, blocks=tuple(blocks))
    tex = render_latex(document, TEMPLATE)
    assert r"\chartempty{No data}" in tex and tex.count("Uncovered: no claim was examined here.") == len(DIMENSIONS)
    assert NOT_CLEAN.replace("-", "{-}") in tex
