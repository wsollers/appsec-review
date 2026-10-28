"""Build ``final-report.json`` from the accepted final publication gate document.

The report only projects the gate: it selects the packages the gate placed in each bucket and carries
the gate's limitations. It does not look at the target, a model or any artifact the gate does not bind.
"""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.jobs.engineering_contracts import FINAL_REPORT_SCHEMA

RENDERER = "final-report-markdown/2"
PDF_REASON = ("A consolidated public-report PDF is not rendered. Protected finding and PoC dossier PDFs "
              "are produced separately when configured; this report publishes only their certified references.")
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


def build_report(gate: Mapping[str, Any], *, gate_handoff: Mapping[str, str],
                 gate_document: Mapping[str, str], configuration_profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
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
        if name == "attack_chains":
            items = [row for row in items if row["status"] in {"confirmed", "qualified_supported"}]
        return {"status": "available" if items else "none_available", "reason": record["reason"], "items": items}

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
    return {
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
                      "pdf": {"state": "not_rendered", "reason": PDF_REASON}},
        "notices": list(NOTICES),
    }
