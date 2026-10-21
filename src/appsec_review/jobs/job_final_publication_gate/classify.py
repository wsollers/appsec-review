"""Classify verified finding packages into publication buckets and name every limitation.

The classification only projects accepted state. A package is publishable when the accepted handoff
placed it in ``remediation_intake`` (``confirmed``) and in the verification backlog when the handoff
placed it there (``supported``, labelled unconfirmed). It is withheld, with a named reason, only
when it references an artifact class whose manifest does not exist, because that reference cannot
be verified. Claim states and ship-block statuses are never recomputed or changed.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from appsec_review.review.models import IntegrityError

from .verify import ATTACK_CHAIN_UNAVAILABLE, POC_UNAVAILABLE

LIMITATION_ORDER = (
    "review_degraded", "review_empty", "review_incomplete", "lane_degraded", "gaps_recorded", "coverage_incomplete",
    "pending_distinct_verification", "technical_severity_unrated", "findings_without_scores",
    "withheld_packages", "possible_duplicates", "remediation_planning_not_run", "remediation_validation_not_run",
    "attack_chain_composition_not_run", "poc_lane_not_run")


def withheld_reasons(package: Mapping[str, Any]) -> list[str]:
    reasons = []
    if package["poc"] is not None:
        reasons.append("poc_outcome_unavailable")
    if package["attack_chains"]:
        reasons.append("attack_chain_unavailable")
    return reasons


def bucket_packages(packages: Sequence[Mapping[str, Any]], partition: Mapping[str, Sequence[str]]
                    ) -> list[dict[str, Any]]:
    """Place every package in exactly one bucket; a package the handoff did not partition is an error."""
    confirmed, supported = set(partition["confirmed"]), set(partition["supported"])
    placed = []
    for package in sorted(packages, key=lambda item: item["finding_package_id"]):
        identity = package["finding_package_id"]
        reasons = withheld_reasons(package)
        if reasons:
            bucket = "withheld"
        elif identity in confirmed and package["state"] == "confirmed":
            bucket = "publishable"
        elif identity in supported and package["state"] == "supported":
            bucket = "verification_backlog"
        else:
            raise IntegrityError(f"finding package is not in the handoff partition for its state: {identity}")
        placed.append({**package, "bucket": bucket, "withheld_reasons": reasons})
    return placed


def package_counts(packages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts = {bucket: sum(1 for item in packages if item["bucket"] == bucket)
              for bucket in ("publishable", "verification_backlog", "withheld")}
    if sum(counts.values()) != len(packages):
        raise IntegrityError("a finding package is in no bucket or in more than one")
    return {"total": len(packages), **counts, "exact": True}


def _percent(value: float) -> str:
    return f"{value:.3f}"


def limitations(verified: Mapping[str, Any], packages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Every named limitation, in a fixed order; ``gap`` ones make the publication non-clean."""
    review, accounting = verified["review"], verified["accounting"]
    found: dict[str, dict[str, Any]] = {}

    def add(identity: str, kind: str, statement: str, count: int = 0) -> None:
        found[identity] = {"limitation_id": identity, "kind": kind, "statement": statement[:2000], "count": count}

    gaps = len(verified["gap_ids"])
    by_class = {key: value for key, value in sorted(accounting["gaps_by_class"].items()) if value}
    classes = ", ".join(f"{key} {value}" for key, value in by_class.items()) or "none by class"
    if review["status"] == "DEGRADED":
        add("review_degraded", "gap", "The inference review finished DEGRADED: at least one gap or failed lane is "
            "accounted. A degraded review is never a clean verdict.", gaps)
    if review["status"] == "EMPTY":
        add("review_empty", "gap", "The inference review produced no claims. An empty result is not evidence that the "
            "target is free of defects.", 0)
    if review["review_incomplete"]:
        add("review_incomplete", "gap", f"The review gap ratio {_percent(accounting['gap_ratio'])} exceeds the configured "
            f"threshold {_percent(accounting['incomplete_gap_ratio'])}; no consumer may present this review as complete.",
            gaps)
    degraded = [lane for lane in verified["lanes"] if lane["outcome"] in {"DEGRADED", "FAILED", "CANCELED"}]
    if degraded:
        detail = "; ".join(f"{lane['lane']} {lane['outcome']} ({lane['gapped_cells']} gapped cells, "
                           f"{lane['gapped_packages']} gapped packages, {lane['cells_missing']} missing cells)"
                           for lane in degraded)
        add("lane_degraded", "gap", f"A review lane did not complete: {detail}.", sum(l["gapped_cells"] for l in degraded))
    if gaps:
        add("gaps_recorded", "gap", f"{gaps} gaps are recorded in the claim ledger ({classes}). Each is an unresolved "
            "limit of this review and not evidence that a target is clean.", gaps)
    summary = verified["coverage"]["summary"]
    uncovered = sum(count for status, count in summary.items() if status != "reviewed")
    if uncovered:
        add("coverage_incomplete", "gap", f"{uncovered} of {verified['coverage']['rows']} lane B coverage cells are not "
            "reviewed (" + ", ".join(f"{key} {value}" for key, value in sorted(summary.items())) + "). "
            + verified["coverage"]["statement"] + ".", uncovered)
    pending = [item for item in packages if item["ship_block"]["status"] == "ship_blocking_pending_distinct_verification"]
    if pending:
        warning = verified["verification"]["warning"]
        add("pending_distinct_verification", "gap", f"{len(pending)} finding package(s) would block shipment but were "
            "verified on a red cell's model, so they are published as ship_blocking_pending_distinct_verification."
            + (f" {warning}" if warning else ""), len(pending))
    unrated = [item for item in packages if "technical_severity_unrated" in item["ship_block"]["reasons"]]
    if unrated:
        add("technical_severity_unrated", "gap", f"{len(unrated)} finding package(s) have no application_risk_matrix/2 "
            "technical severity. Unrated is a gap to resolve, not a low-risk verdict.", len(unrated))
    unscored = [item for item in packages if not item["scores"]]
    if unscored:
        add("findings_without_scores", "gap", f"{len(unscored)} finding package(s) have no score package.", len(unscored))
    withheld = [item for item in packages if item["bucket"] == "withheld"]
    if withheld:
        add("withheld_packages", "gap", f"{len(withheld)} finding package(s) are withheld because they reference proof or "
            "attack-chain artifacts whose manifests do not exist; they are listed with their ship-block status.",
            len(withheld))
    if verified["possible_duplicate_pairs"]:
        add("possible_duplicates", "gap", f"{verified['possible_duplicate_pairs']} claim pair(s) are nominated as possible "
            "duplicates and were not merged.", verified["possible_duplicate_pairs"])
    add("remediation_planning_not_run", "not_run", "job_remediation_planning does not exist yet, so no remediation plan "
        "was produced. This is a named limitation of the pipeline, not a failure.")
    add("remediation_validation_not_run", "not_run", "job_remediation_validation does not exist yet, so no remediation "
        "was validated. This is a named limitation of the pipeline, not a failure.")
    add("attack_chain_composition_not_run", "not_run", ATTACK_CHAIN_UNAVAILABLE)
    add("poc_lane_not_run", "not_run", POC_UNAVAILABLE)
    return [found[identity] for identity in LIMITATION_ORDER if identity in found]


def classify(verified: Mapping[str, Any]) -> dict[str, Any]:
    packages = bucket_packages(verified["packages"], verified["partition"])
    found = limitations(verified, packages)
    return {
        "packages": packages, "package_counts": package_counts(packages),
        "buckets": {bucket: [item["finding_package_id"] for item in packages if item["bucket"] == bucket]
                    for bucket in ("publishable", "verification_backlog", "withheld")},
        "limitations": found,
        "status": "PUBLISHABLE_WITH_LIMITATIONS" if any(item["kind"] == "gap" for item in found) else "PUBLISHABLE",
    }


def gate_document(schema: str, verified: Mapping[str, Any], classification: Mapping[str, Any]) -> dict[str, Any]:
    """Assemble the gate document (schema ``final-publication-gate/1``)."""
    return {
        "schema": schema, "run_id": verified["run_id"], "review": verified["review"], "inputs": verified["inputs"],
        "unavailable_inputs": {"attack_chain_manifest": {"state": "unavailable", "reason": ATTACK_CHAIN_UNAVAILABLE},
                               "poc_status_manifest": {"state": "unavailable", "reason": POC_UNAVAILABLE}},
        "accounting": verified["accounting"], "ship_block": verified["ship_block"],
        "verification": verified["verification"], "coverage": verified["coverage"],
        "packages": classification["packages"], "package_counts": classification["package_counts"],
        "buckets": classification["buckets"], "limitations": classification["limitations"],
        "gap_ids": verified["gap_ids"], "status": classification["status"], "bindings": verified["bindings"],
    }
