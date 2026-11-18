"""Build ``final-report.json`` from the accepted final publication gate document.

The report only projects the gate: it selects the packages the gate placed in each bucket, carries
the gate's limitations, and computes the deterministic 12-axis / 4-series security radar tracker,
executive risk posture, attack-chain cards, prioritized remediation roadmap, and explicit named
coverage gaps. It does not look at the target, a model or any artifact the gate does not bind.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from appsec_review.jobs.engineering_contracts import FINAL_REPORT_SCHEMA
from appsec_review.reporting.dimensions import build_radar_tracker
from appsec_review.reporting.executive_posture import (
    build_attack_chain_cards,
    build_executive_posture,
    build_named_coverage_gaps,
    build_remediation_roadmap,
)

RENDERER = "final-report-markdown/2"
HTML_RENDERER = "appsec-review/executive-report/1"
PDF_REASON = ("The executive PDF (final-report.pdf) is rendered after this document is assembled, by "
              "report.render_pdf, from this JSON and the gate-bound dossier JSON; its outcome, file and receipt "
              "are reported in the publish handoff's pdf field. Protected finding and PoC dossier PDFs are "
              "produced separately when configured; this report publishes only their certified references.")
NOTICES = (
    "This report is a deterministic projection of the accepted inference security review. It reinterprets "
    "no claim state and no ship-block-policy/1 status.",
    "Only confirmed findings are listed as findings. Supported findings are listed separately as an "
    "unconfirmed verification backlog and are not independently confirmed.",
    "Score dimensions are independent and are never combined or averaged. A missing dimension is a gap, "
    "not a low value.",
    "A finding whose ship-block status is decision_pending has no technical severity yet because scoring "
    "factors are missing. It is neither ship-blocking nor cleared; the missing factors are listed with it.",
    "The report holds identifiers, hashes and accepted summaries only. It contains no exploit code, proof "
    "payloads, queries or prompts.",
    "A named limitation is a limit of the review or of the pipeline, never evidence that the target is clean.",
)

POC_REASON = ("Compile-only PoC generation outcomes for accepted review candidates. Each status distinguishes "
              "successful compilation, failures, policy refusals and unavailable work. Nothing was linked or run. "
              "A failed or unavailable PoC does not contradict its finding.")

CHAIN_STATUSES = ("confirmed", "qualified_supported", "refuted", "insufficient_evidence")


def chain_status_counts(record: Mapping[str, Any], items: Mapping[str, Any] | list) -> dict[str, int]:
    """Per-status chain counts from the gate's attachments, plus the gate's candidate accounting when present."""
    by_status = Counter(row["status"] for row in items)
    counts = {status: by_status.get(status, 0) for status in CHAIN_STATUSES}
    extra = record.get("status_counts")
    if isinstance(extra, Mapping):
        counts.update({key: int(value) for key, value in extra.items() if key not in CHAIN_STATUSES})
    counts.setdefault("admitted", len(items))
    return counts


def chain_reason(record: Mapping[str, Any], counts: Mapping[str, int]) -> str:
    """Why the listed chains are all there is: every proposed candidate is accounted for by status."""
    admitted = counts.get("admitted", 0)
    proposed = counts.get("proposed", admitted)
    if not proposed and not admitted:
        lead = "No candidate attack chain was proposed by the accepted review"
    else:
        lead = (f"{proposed} candidate chain(s) proposed, {admitted} admitted: {counts['confirmed']} confirmed, "
                f"{counts['qualified_supported']} qualified_supported, {counts['refuted']} refuted, "
                f"{counts['insufficient_evidence']} insufficient_evidence")
        if "rejected" in counts:
            lead += (f"; {counts['rejected']} rejected, {counts['deduplicated']} deduplicated, "
                     f"{counts['capped']} capped by max_attack_chains")
    return f"{lead}. Only confirmed and qualified_supported chains are listed. {record['reason']}"


def build_report(gate: Mapping[str, Any], *, gate_handoff: Mapping[str, str],
                 gate_document: Mapping[str, str], configuration_profile: Mapping[str, Any] | None = None,
                 chain_manifest_items: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    packages = gate["packages"]

    def bucket(name: str) -> list[Any]:
        return [item for item in packages if item["bucket"] == name]

    limitations = list(gate["limitations"])
    review = gate["review"]
    complete = (review["status"] == "COMPLETE" and not review["review_incomplete"]
                and not any(item["kind"] == "gap" for item in limitations))

    def section(name: str) -> dict[str, Any]:
        record = gate["capabilities"][name]
        items = gate["attachments"][name]
        result = {"status": "available" if items else "none_available", "reason": record["reason"], "items": items}
        if name == "attack_chains":
            listed = [row for row in items if row["status"] in {"confirmed", "qualified_supported"}]
            counts = chain_status_counts(record, items)
            result.update(status="available" if listed else "none_available", items=listed,
                          reason=chain_reason(record, counts), status_counts=counts)
        return result

    outcomes = section("poc_generation")
    if outcomes["items"]:
        outcomes["reason"] = POC_REASON
    poc_reference = gate["capabilities"]["poc_generation"]["handoff"]
    if poc_reference is not None:
        outcomes["poc_handoff"] = poc_reference
    provenance: dict[str, Any] = {
        **({"configuration_profile": dict(configuration_profile)} if configuration_profile else {}),
        "gate_handoff": dict(gate_handoff), "gate_document": dict(gate_document),
        "review_handoff": dict(gate["inputs"]["review_handoff"]),
        "accepted_manifest_sha256": review["accepted_manifest_sha256"],
        "configuration_sha256": review["configuration_sha256"],
        "ledger_head_sha256": review["ledger_head_sha256"],
        "ship_block_policy_sha256": review["ship_block_policy_sha256"]}
    if poc_reference is not None:
        provenance["poc_handoff"] = poc_reference

    report: dict[str, Any] = {
        "schema": FINAL_REPORT_SCHEMA, "run_id": gate["run_id"],
        "provenance": provenance,
        "status": {"review": review["status"], "review_incomplete": review["review_incomplete"],
                   "publication": gate["status"], "review_complete": complete},
        "summary": {"accounting": gate["accounting"], "package_counts": gate["package_counts"],
                    "ship_block": gate["ship_block"], "coverage": gate["coverage"]},
        "findings": bucket("publishable"),
        "attack_chains": section("attack_chains"),
        "poc_outcomes": outcomes,
        "remediation_planning": section("remediation_planning"),
        "remediation_validation": section("remediation_validation"),
        "dossiers": section("dossiers"),
        "capabilities": gate["capabilities"],
        "verification_backlog": bucket("verification_backlog"),
        "withheld": bucket("withheld"),
        "limitations": limitations,
        "gap_ids": list(gate["gap_ids"]),
        "renderers": {"markdown": {"file": "final-report.md", "renderer": RENDERER},
                      "html": {"file": "final-report.html", "renderer": HTML_RENDERER},
                      "sarif": {"file": "findings.sarif", "receipt": "sarif-export-result.json",
                                "version": "2.1.0"},
                      "pdf": {"state": "not_rendered", "reason": PDF_REASON}},
        "notices": list(NOTICES),
    }
    radar = build_radar_tracker(report)
    report["radar_tracker"] = radar
    report["executive_posture"] = build_executive_posture(report, radar)
    report["attack_chain_cards"] = build_attack_chain_cards(report, manifest_items=chain_manifest_items)
    report["remediation_roadmap"] = build_remediation_roadmap(report)
    report["named_coverage_gaps"] = build_named_coverage_gaps(report, radar)
    return report


__all__ = [
    "CHAIN_STATUSES",
    "HTML_RENDERER",
    "NOTICES",
    "PDF_REASON",
    "POC_REASON",
    "RENDERER",
    "build_attack_chain_cards",
    "build_executive_posture",
    "build_named_coverage_gaps",
    "build_remediation_roadmap",
    "build_report",
    "chain_reason",
    "chain_status_counts",
]
