"""The leads a review does not reason over in lane A, in one readable artifact.

``lead-packages.json`` carries the package manifest's admission list (every observation with its status), but a
reader who asks "what did the review leave out, and why" should not have to sift 1,268 entries for the 1,246 that
were not admitted. ``excluded_leads_document`` lists exactly those: leads outside the review scope (vendored,
sdk, generated, test or stylistic), leads whose effective severity is outside ``lanes.lead_admission``, leads
reported unknown without an assessed severity, and exploration-reserve cutoffs, each with its scanner, rule,
location, severities, the reason, and whether lane B still sees it on a hunt menu. Messages are left out: a
secret-family lead's message may carry the literal (``secret-redaction/1``); the rule and location identify it.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from appsec_review.review.lead_families import Lead, LeadCollection
from appsec_review.review.packages import Assembly

SCHEMA = "appsec-review/inference-review-excluded-leads/1"


def _lead_row(lead: Lead, entry: Mapping[str, Any], hunted: bool) -> dict[str, Any]:
    return {
        "lead_id": lead.observation_id, "lead_family": lead.family, "scanner": lead.scanner, "rule_id": lead.rule_id,
        "path": lead.path, "start_line": lead.start_line, "location_exact": lead.location_exact,
        "reported_severity": lead.reported_severity, "effective_severity": lead.effective_severity,
        "severity_from": lead.effective_from, "rule_cwe": list(lead.rule_cwe),
        "residual_coverage": entry["residual_coverage"], "reasons": list(entry.get("reasons", ())),
        "exclusion": entry.get("exclusion"), "exclusion_detail": entry.get("exclusion_detail"),
        "hunted": hunted,
    }


def excluded_leads_document(collection: LeadCollection, assembly: Assembly, *, run_id: str, manifest_sha256: str,
                            policy: Mapping[str, Any]) -> dict[str, Any]:
    """Every lead the package manifest did not admit to lane A, with the reason and lane B coverage."""
    by_id: dict[str, Lead] = {lead.observation_id: lead for lead in collection.leads}
    by_id.update({item.lead.observation_id: item.lead for item in collection.excluded})
    hunted = {lead_id for package in assembly.packages if package.kind == "hunt" for lead_id in package.lead_ids}
    rows = []
    for entry in assembly.manifest["admission"]:
        if entry["status"] == "admitted":
            continue
        lead = by_id.get(entry["lead_id"])
        if lead is None:          # the manifest and the collection come from one assembly; this never happens
            raise ValueError(f"admission entry names a lead the collection does not hold: {entry['lead_id']}")
        rows.append(_lead_row(lead, entry, entry["lead_id"] in hunted))
    rows.sort(key=lambda row: (row["residual_coverage"], row["exclusion"] or "", row["path"] or "",
                               row["start_line"] or 0, row["lead_id"]))
    counts = Counter(row["residual_coverage"] for row in rows)
    exclusions = Counter(row["exclusion"] for row in rows if row["exclusion"])
    return {
        "schema": SCHEMA, "run_id": run_id, "manifest_sha256": manifest_sha256,
        "policy": dict(policy),
        "counts": {"observations": len(assembly.manifest["admission"]),
                   "admitted": sum(1 for entry in assembly.manifest["admission"] if entry["status"] == "admitted"),
                   "excluded": len(rows), "by_residual_coverage": dict(sorted(counts.items())),
                   "by_exclusion": dict(sorted(exclusions.items())),
                   "hunted": sum(1 for row in rows if row["hunted"])},
        "leads": rows,
    }
