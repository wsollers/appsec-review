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
from appsec_review.reporting.executive_latex import _chunks, render_latex, template_identity
from appsec_review.reporting.model import Box, Document, Heading, Table
from appsec_review.reporting.technical_evidence import citations, source_location, standards
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
    # Accepted narrative and evidence remain; release recommendations and inferred impact do not.
    assert "F01 — Synthetic finding 0" in tex
    assert "attacker{-}controlled length reaches a fixed{-}size copy" in tex
    assert "src/\\allowbreak{}parser.c, lines 40{-}52" in tex
    assert "memory corruption" in tex and "network access to the parser endpoint" in tex
    assert "CWE{-}120" in tex
    assert r"\technicalfield{Technical severity}{high}" in tex
    assert "Blocks shipping" not in tex and "Release readiness" not in tex
    assert "Yes: an independent verifier confirmed this finding" in tex
    assert "bound the copy length" in tex and "not a verified fix" in tex
    assert "Attack path: entry to vulnerable function" in tex
    assert "not established in accepted evidence" in tex
    # The verification backlog is listed as unconfirmed, never as a finding.
    assert "Supported but not independently confirmed" in tex and "Synthetic finding 1" in tex
    # The executive summary and the policy statement.
    assert "It may be presented as complete." in tex
    assert tex.count("An attacker{-}controlled length reaches a fixed{-}size copy") == 1
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
    for title in ("Proof-of-concept outcomes (compile only)", "Remediation proposals",
                  "Remediation validation"):
        box = next(block for block in boxes if block.title == title)
        assert box.kind.value == "gap"
        texts = " ".join(item.text for item in box.items if hasattr(item, "text"))
        assert "None available." in texts and NOT_CLEAN in texts
        assert "frozen configuration" in texts
    tex = tex_of(report)
    assert NOT_CLEAN.replace("-", "{-}") in tex
    headings = [block.text for block in document.blocks if isinstance(block, Heading)]
    assert headings == ["Scope and summary", "Technical findings", "F01 — Synthetic finding 0",
                        "Verification backlog and withheld packages", "Related analysis and validation",
                        "Coverage and limitations", "References and provenance"]
    assert r"\makecover" not in tex and r"\begin{longtable}" in tex


def test_incomplete_review_says_why_and_lists_gaps_by_kind() -> None:
    verified = verified_document()
    verified["review"]["status"] = "DEGRADED"
    verified["accounting"]["outcome"] = "DEGRADED"
    report = report_document(verified)
    assert report["status"]["review_complete"] is False
    tex = tex_of(report)
    assert "It may not be presented as complete" in tex
    assert "review\\_degraded" in tex.replace(r"\allowbreak{}", "")
    assert "Coverage and limitations" in tex
    assert "compile\\_only\\_nonexecution" in tex.replace(r"\allowbreak{}", "")
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


def test_consequence_category_does_not_invent_attacker_gain_or_a_source_identity() -> None:
    report = report_document()
    dossier = dossier_for(report["findings"][0], security_predicate="command_injection", statement="")
    tex = tex_of(report, (bound(dossier),))
    assert "command injection" in tex and "gain beyond the accepted statement is not established" in tex
    assert "run operating{-}system commands" not in tex
    assert "Source span not established" in source_location({"path": "invented.c", "start_line": 3, "end_line": 5})


def test_connected_line_ranges_of_one_file_collapse_to_their_union() -> None:
    """Owner's rule: references to connected code collapse; [5,10] and [6,12] read as [5,12]."""
    from appsec_review.reporting import executive_report as E
    assert E.merge_spans([(5, 10), (6, 12)]) == [(5, 12)]
    assert E.merge_spans([(6, 12), (5, 10), (11, 12), (20, 22), (23, 23)]) == [(5, 12), (20, 23)]   # touching joins
    assert E.merge_spans([(5, 10), (12, 14)]) == [(5, 10), (12, 14)]                                # a gap stays
    assert E.merge_spans([(10, 5)]) == [(5, 10)]                                                    # order-insensitive
    # Evidence register does not merge spans across snapshots merely because their paths agree.
    source = dossier_for(report_document()["findings"][0])["sources"][0]
    assert "snapshot t" in source_location(source)
    assert "snapshot other" in source_location({**source, "target_snapshot": "other"})


def dimension_report() -> dict[str, Any]:
    """The wiring fixture with pipeline-shaped titles: one confirmed command injection, one backlog use after free."""
    verified = verified_document()
    verified["packages"][0]["title"] = "command_injection (CWE-78)"
    verified["packages"][1]["title"] = "use_after_free (CWE-416)"
    return report_document(verified)


def coverage_table(document: Document) -> Table:
    return next(item for block in document.blocks if isinstance(block, Box) for item in block.items
                if isinstance(item, Table) and item.headers[0] == "Domain")


def test_coverage_by_dimension_counts_findings_and_claims_per_axis_and_agrees_with_markdown() -> None:
    from appsec_review.jobs.job_final_report_publication.render import render_markdown
    from appsec_review.review.models import SecurityPredicate
    report = dimension_report()
    finding = report["findings"][0]
    dossier = dossier_for(finding, security_predicate="command_injection", weakness_cwe="CWE-78", title=finding["title"])
    document = executive_document(report, (bound(dossier),))
    table = coverage_table(document)
    assert len(DIMENSIONS) == 12
    assert [axis["key"] for axis in report["radar_tracker"]["axes"]] == [
        "Auth", "AzZ", "Inj", "Mem", "Pars", "Cryp", "API", "Path", "Logi", "Deps", "CICD", "Hard"
    ]
    assert len(table.rows) == 12
    assert table.rows[2][4].text == "1"
    assert all(row[1].text == row[2].text == row[3].text == "N/A" for row in table.rows)
    headings = [block.text for block in document.blocks if isinstance(block, Heading)]
    assert headings[:2] == ["Scope and summary", "Technical findings"]
    tex = tex_of(report, (bound(dossier),))
    assert r"Injection \& Command/\allowbreak{}SQL/\allowbreak{}Template" in tex
    assert "Package counts do not establish exposure" in tex
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


def test_certified_radar_is_not_reclassified_by_format_specific_dossiers() -> None:
    report = report_document()                     # titles "Synthetic finding n" name no predicate
    dossier = dossier_for(report["findings"][0])   # the dossier says memory_corruption
    document = executive_document(report, (bound(dossier),))
    table = coverage_table(document)
    assert table.rows[3][4].text == "0" and table.rows[3][3].text == "N/A"
    tex = tex_of(report, (bound(dossier),))
    assert "2 packages are unclassified by the accepted domain vocabulary" in tex
    # Without the dossier nothing is reclassified by this presentation.
    tex = tex_of(report)
    assert "2 packages are unclassified by the accepted domain vocabulary" in tex


def test_dimension_section_with_nothing_bound_reads_as_uncovered_not_clean() -> None:
    from appsec_review.reporting import executive_report as E
    report = report_document()
    report["findings"] = report["verification_backlog"] = report["withheld"] = []
    del report["radar_tracker"]
    blocks = E._coverage_blocks(report, ())
    document = Document(title="x", run_id="r", subtitle="", status_badge="EMPTY", status_tone="unresolved",
                        source_date_epoch=0, ledger_head="ab" * 32, blocks=tuple(blocks))
    tex = render_latex(document, TEMPLATE)
    table = coverage_table(document)
    assert all(row[1].text == row[2].text == row[3].text == "N/A" for row in table.rows)
    assert all(row[4].text == "0" for row in table.rows)
    assert NOT_CLEAN.replace("-", "{-}") in tex


@pytest.mark.parametrize("count", [0, 1, 70], ids=["empty", "single", "many"])
def test_real_projection_keeps_every_finding_and_complete_long_text(count: int) -> None:
    report = report_document()
    seed = report["findings"][0]
    report["findings"] = [{**seed, "claim_id": f"claim-{n}", "finding_package_id": f"package-{n}",
                           "title": ("Long & title_%#{} " * 90) + f"END-TITLE-{n}"} for n in range(count)]
    dossiers = tuple(bound(dossier_for(row, statement=("Accepted mechanism & details. " * 100)
                                      + f"END-NARRATIVE-{n}"))
                     for n, row in enumerate(report["findings"]))
    tex = tex_of(report, dossiers)
    for n in range(count):
        assert tex.count(f"END{{-}}NARRATIVE{{-}}{n}" + "}") == 1
        assert f"END{{-}}TITLE{{-}}{n}" in tex
    assert tex.count(r"\technicalnote{Attack path: entry to vulnerable function}") == count
    assert "more characters" not in tex and r"\resizebox" not in tex and r"\begin{minipage}" not in tex
    assert "".join(_chunks("longword" * 1000, 111)) == "longword" * 1000


@pytest.mark.parametrize("ambiguous", [False, True])
def test_evidence_attribution_and_unknown_transitions_survive_projection(ambiguous: bool) -> None:
    report = report_document()
    dossier = dossier_for(report["findings"][0])
    source = dossier["sources"][0]
    source["mapping_ambiguous"] = ambiguous
    dossier["evidence"] = [
        {"relation_id": "r-input", "entity_id": source["entity_id"], "predicate": "attacker_input_control",
         "kind": "supports", "strength": "counted_direct", "complete": True, "admissibility": "direct",
         "content_sha256": "a" * 64, "retrieval_receipt_sha256": "b" * 64, "locator": "PRIVATE_RAW_LOCATOR"},
        {"relation_id": "r-sink", "entity_id": source["entity_id"], "predicate": "source_to_sink_reachability",
         "kind": "supports", "strength": "analyst_assessed_not_counted", "complete": False,
         "admissibility": "analyst_assessed"},
    ]
    dossier["taint_path_timeline"] = [{"symbol": "fabricatedOrderedFunction", "step_index": 1}]
    tex = tex_of(report, (bound(dossier),))
    assert "PRIVATE" not in tex and "fabricatedOrderedFunction" not in tex
    assert "Analyst{-}assessed, not counted" in tex and "Cited, counted direct" in tex
    assert "conditional CBMC witness" in tex and "not established in accepted evidence" in tex
    assert ("lines 40{-}52" in tex) is not ambiguous
    assert "a" * 14 in tex and "b" * 14 in tex
    assert citations(dossier)[0].relation_id == "r-input"


def test_scores_and_advisory_patterns_are_not_upgraded_to_official_scores() -> None:
    report = report_document()
    report["findings"][0]["title"] = "Unverified title references: " + " ".join(
        f"CVE-2026-{index:05}" for index in range(100))
    dossier = dossier_for(report["findings"][0])
    dossier.update(cvss={"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": 9.8},
                   epss={"probability": .9}, cves=["CVE-2021-44228"])
    dossier["scores"] = [{"score_id": "score-one", "sha256": "a" * 64, "provider": "accepted-provider",
                          "technical_severity": {"scale": "vendor-scale", "rating": "high", "value": "8.7"},
                          "missing_factors": ["configuration"]}]
    tex = tex_of(report, (bound(dossier),))
    assert "accepted{-}provider" in tex and "vendor{-}scale" in tex and "8.7" in tex
    assert "CVE{-}2021" not in tex and "9.8" not in tex
    assert "CVE{-}2026{-}00099" in tex
    assert dict(standards(dossier))["CVSS"].startswith("N/A")
    assert dict(standards(dossier))["EPSS"].startswith("N/A")
    assert "taxonomy name not supplied" in tex


def test_actual_template_identity_binds_executive_not_telemetry_skeleton(tmp_path: Path) -> None:
    import shutil
    from appsec_review.review.models import IntegrityError
    for name in ("appsec-report.cls", "appsec-palette.tex", "technical-report-skeleton.tex"):
        shutil.copyfile(TEMPLATE / name, tmp_path / name)
    before = template_identity(tmp_path)
    path = tmp_path / "technical-report-skeleton.tex"
    path.write_text(path.read_text() + "% layout change\n")
    assert template_identity(tmp_path)["sha256"] != before["sha256"]
    path.unlink()
    with pytest.raises(IntegrityError, match="missing or symbolic"):
        template_identity(tmp_path)
