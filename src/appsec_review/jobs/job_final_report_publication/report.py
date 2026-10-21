"""Build ``final-report.json`` from the accepted final publication gate document.

The report only projects the gate: it selects the packages the gate placed in each bucket and carries
the gate's limitations. It does not look at the target, a model or any artifact the gate does not bind.
"""
from __future__ import annotations

from typing import Any, Mapping

from appsec_review.jobs.engineering_contracts import FINAL_REPORT_SCHEMA

from appsec_review.jobs.job_final_publication_gate.verify import ATTACK_CHAIN_UNAVAILABLE, POC_UNAVAILABLE

RENDERER = "final-report-markdown/1"
PDF_REASON = ("LaTeX/PDF report rendering is a later step; containers/report/latex is not enabled, so only "
              "final-report.json and final-report.md are produced.")
NOTICES = (
    "This report is a deterministic projection of the accepted inference security review. It reinterprets "
    "no claim state and no ship-block-policy/1 status.",
    "Only confirmed findings are listed as findings. Supported findings are listed separately as an "
    "unconfirmed verification backlog and are not independently confirmed.",
    "Score dimensions are independent and are never combined or averaged. A missing dimension is a gap, "
    "not a low value.",
    "The report holds identifiers, hashes and accepted summaries only. It contains no exploit code, proof "
    "payloads, queries or prompts.",
    "A named limitation is a limit of the review or of the pipeline, never evidence that the target is clean.",
)


def build_report(gate: Mapping[str, Any], *, gate_handoff: Mapping[str, str],
                 gate_document: Mapping[str, str]) -> dict[str, Any]:
    packages = gate["packages"]

    def bucket(name: str) -> list[Any]:
        return [item for item in packages if item["bucket"] == name]

    limitations = list(gate["limitations"])
    review = gate["review"]
    complete = (review["status"] == "COMPLETE" and not review["review_incomplete"]
                and not any(item["kind"] == "gap" for item in limitations))
    return {
        "schema": FINAL_REPORT_SCHEMA, "run_id": gate["run_id"],
        "provenance": {
            "gate_handoff": dict(gate_handoff), "gate_document": dict(gate_document),
            "review_handoff": dict(gate["inputs"]["review_handoff"]),
            "accepted_manifest_sha256": review["accepted_manifest_sha256"],
            "configuration_sha256": review["configuration_sha256"],
            "ledger_head_sha256": review["ledger_head_sha256"],
            "ship_block_policy_sha256": review["ship_block_policy_sha256"]},
        "status": {"review": review["status"], "review_incomplete": review["review_incomplete"],
                   "publication": gate["status"], "review_complete": complete},
        "summary": {"accounting": gate["accounting"], "package_counts": gate["package_counts"],
                    "ship_block": gate["ship_block"], "coverage": gate["coverage"]},
        "findings": bucket("publishable"),
        "attack_chains": {"status": "none_available", "reason": ATTACK_CHAIN_UNAVAILABLE, "items": []},
        "poc_outcomes": {"status": "none_available", "reason": POC_UNAVAILABLE, "items": []},
        "verification_backlog": bucket("verification_backlog"),
        "withheld": bucket("withheld"),
        "limitations": limitations,
        "gap_ids": list(gate["gap_ids"]),
        "renderers": {"markdown": {"file": "final-report.md", "renderer": RENDERER},
                      "pdf": {"state": "not_rendered", "reason": PDF_REASON}},
        "notices": list(NOTICES),
    }
