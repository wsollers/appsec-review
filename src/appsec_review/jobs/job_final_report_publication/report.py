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


POC_STALE = ("A proof-of-concept handoff exists in the run but was produced from a different gate handoff, so it is "
             "not shown; run job_poc_generation again on the current gate.")
POC_EMPTY = "The proof-of-concept job ran and had no candidate to attempt: {reason}"
POC_REASON = ("Compile-checked proof-of-concept unit-test functions written for findings the judge agreed with. "
              "Each was checked by deterministic validators and compiled against the project's own build flags; "
              "none was linked or run. compile_failed and artifact_generated do not contradict a finding.")


def poc_section(poc: Mapping[str, Any] | None) -> tuple[dict[str, Any], dict[str, str] | None]:
    """The ``poc_outcomes`` block and the PoC handoff reference to record in the provenance (or ``None``).

    ``poc`` is the verified PoC summary (``load.accepted_gate`` re-proved it from bytes):
    ``{"handoff": ref, "document": summary, "stale": bool}`` when the run holds a PoC handoff, else ``None``, in
    which case the block says the job did not run and the report is what it was before the job existed.
    """
    if poc is None:
        return {"status": "none_available", "reason": POC_UNAVAILABLE, "items": []}, None
    if poc["stale"]:
        return {"status": "none_available", "reason": POC_STALE, "items": []}, None
    document = poc["document"]
    items = [{"finding_package_id": row["finding_package"]["finding_package_id"], "status": row["status"],
              "result_id": None, "claim_id": row["claim_id"], "description": row["description"],
              "functions": ({key: row["functions"][key] for key in ("test_function", "negative_control")}
                            if row["functions"] else None),
              "files": row["files"]} for row in document["candidates"]]
    reason = POC_REASON if items else POC_EMPTY.format(
        reason=(document["gaps"][0] if document["gaps"] else "no claim qualified")[:200])
    return ({"status": "available" if items else "none_available", "reason": reason, "items": items,
             "poc_handoff": dict(poc["handoff"])}, dict(poc["handoff"]))


def build_report(gate: Mapping[str, Any], *, gate_handoff: Mapping[str, str],
                 gate_document: Mapping[str, str], poc: Mapping[str, Any] | None = None) -> dict[str, Any]:
    packages = gate["packages"]

    def bucket(name: str) -> list[Any]:
        return [item for item in packages if item["bucket"] == name]

    limitations = list(gate["limitations"])
    review = gate["review"]
    complete = (review["status"] == "COMPLETE" and not review["review_incomplete"]
                and not any(item["kind"] == "gap" for item in limitations))
    outcomes, poc_reference = poc_section(poc)
    provenance: dict[str, Any] = {
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
        "attack_chains": {"status": "none_available", "reason": ATTACK_CHAIN_UNAVAILABLE, "items": []},
        "poc_outcomes": outcomes,
        "verification_backlog": bucket("verification_backlog"),
        "withheld": bucket("withheld"),
        "limitations": limitations,
        "gap_ids": list(gate["gap_ids"]),
        "renderers": {"markdown": {"file": "final-report.md", "renderer": RENDERER},
                      "pdf": {"state": "not_rendered", "reason": PDF_REASON}},
        "notices": list(NOTICES),
    }
