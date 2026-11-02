"""Per-run triage reduction: admitted scanner leads versus what survives review.

The ``triage_reduction`` run-metrics section answers the before/after-triage question for lane A
(``Lane.LEAD``): of the scanner leads admitted for review, how many survived as supported or
confirmed claims, how many were dismissed by adjudication, how many the red cells examined and
raised no claim for, and how many remain unresolved.

Doctrine:

* A dismissed or no-claim lead is a triage outcome, never a confirmed false positive.
* A lead that was never admitted was never triaged. It is reported as unreviewed, by its
  ``residual_coverage``, and is excluded from every ratio.
* An unresolved lead (blocked, unaccounted, insufficient evidence, coverage gap, non-final claim,
  or a proposal without a linked claim) never counts as reduced. Any unresolved lead, an
  incomplete review, or an integrity gap sets ``accounting_complete`` to false.
* Unavailable inputs yield ``available: false`` with null counts, never zero, and named
  ``integrity_gap_codes``.
* Lane B (hunt) claims are not scanner-derived; their count is reported as excluded.

Section shape (``TRIAGE_REDUCTION_SCHEMA``)::

    {
      "schema": TRIAGE_REDUCTION_SCHEMA,
      "available": bool,
      "scope": SCOPE,
      "sources": {<name>: {"path": str, "sha256": str}} | None,
      "leads": {"collected": int|None, "admitted": int|None, "not_admitted": int|None,
                "not_admitted_by_residual_coverage": {<residual_coverage>: int} | None,
                "non_lead_observations": int|None},
      "admitted_dispositions": {<DISPOSITIONS>: int|None},
      "dismissed_by_claim_state": {<DISMISSED_STATES>: int|None},
      "unresolved_by_reason": {<UNRESOLVED_REASONS>: int|None},
      "hunt_lane_claims_excluded": int|None,
      "reduction": {"ratio_over_resolved": float|None, "lower_bound_over_admitted": float|None,
                    "resolved_denominator": int|None, "admitted_denominator": int|None},
      "by_family": {<lead_family>: {"admitted": int, <DISPOSITIONS>: int}} | None,
      "by_scanner": {<scanner>: {"admitted": int, <DISPOSITIONS>: int}} | None,
      "review_incomplete": bool|None,
      "accounting_complete": bool,
      "integrity_gap_codes": [<INTEGRITY_GAP_CODES>, ...],
      "interpretation": INTERPRETATION,
    }

Ratios:

* ``ratio_over_resolved`` = (dismissed_by_adjudication + no_claim_raised) /
  (survived_confirmed + survived_supported + dismissed_by_adjudication + no_claim_raised).
* ``lower_bound_over_admitted`` = (dismissed_by_adjudication + no_claim_raised) / admitted;
  unresolved leads count as not reduced.
* Each ratio is null when its denominator is zero or the section is unavailable.
"""
from __future__ import annotations

from typing import Any, Iterable

TRIAGE_REDUCTION_SCHEMA = "appsec-review/triage-reduction-metrics/1"
SCOPE = "lane_a_scanner_leads"
INTERPRETATION = ("triage outcomes for admitted scanner leads; dismissed and no-claim leads are not "
                  "confirmed false positives, and unresolved or unadmitted leads are never counted as reduced")

DISPOSITIONS = ("survived_confirmed", "survived_supported", "dismissed_by_adjudication",
                "no_claim_raised", "unresolved")
SURVIVED_DISPOSITIONS = ("survived_confirmed", "survived_supported")
REDUCED_DISPOSITIONS = ("dismissed_by_adjudication", "no_claim_raised")

# Final claim states that dismiss a lead's claim. ``duplicate`` resolves to its canonical claim.
DISMISSED_STATES = ("contradicted", "not_reachable", "not_exploitable_in_observed_configuration",
                    "out_of_scope")
# Final claim states that leave the lead's question open.
UNRESOLVED_CLAIM_STATES = ("insufficient_evidence", "coverage_gap", "proposed")

UNRESOLVED_REASONS = ("blocked", "unaccounted", "insufficient_evidence", "coverage_gap",
                      "claim_not_final", "proposal_without_claim")

INTEGRITY_GAP_CODES = (
    "review_handoff_unavailable",      # no accepted, hash-verified inference review handoff
    "lead_manifest_unavailable",       # lead package manifest missing or failed verification
    "lane_document_unavailable",       # lane A document missing or failed verification
    "claim_projection_unavailable",    # claim ledger projection missing or failed verification
    "lead_outcome_mismatch",           # per-lead outcomes disagree with handoff leads_by_outcome
    "lead_outcome_missing",            # an admitted lead has no red outcome
    "lead_package_unlinked",           # an admitted lead has no finding_lead package
    "duplicate_unresolved",            # a duplicate claim does not resolve to a canonical claim
    "review_incomplete",               # handoff accounting marks lane A review incomplete
)


def empty_dispositions() -> dict[str, int]:
    return dict.fromkeys(DISPOSITIONS, 0)


def unavailable_section(codes: Iterable[str]) -> dict[str, Any]:
    """The section when its inputs cannot be read and verified: null counts, named gaps."""
    gap_codes = sorted(set(codes))
    unknown = [code for code in gap_codes if code not in INTEGRITY_GAP_CODES]
    if unknown or not gap_codes:
        raise ValueError(f"unavailable triage reduction needs known integrity gap codes: {unknown or gap_codes}")
    return {
        "schema": TRIAGE_REDUCTION_SCHEMA,
        "available": False,
        "scope": SCOPE,
        "sources": None,
        "leads": {"collected": None, "admitted": None, "not_admitted": None,
                  "not_admitted_by_residual_coverage": None, "non_lead_observations": None},
        "admitted_dispositions": dict.fromkeys(DISPOSITIONS),
        "dismissed_by_claim_state": dict.fromkeys(DISMISSED_STATES),
        "unresolved_by_reason": dict.fromkeys(UNRESOLVED_REASONS),
        "hunt_lane_claims_excluded": None,
        "reduction": {"ratio_over_resolved": None, "lower_bound_over_admitted": None,
                      "resolved_denominator": None, "admitted_denominator": None},
        "by_family": None,
        "by_scanner": None,
        "review_incomplete": None,
        "accounting_complete": False,
        "integrity_gap_codes": gap_codes,
        "interpretation": INTERPRETATION,
    }


def triage_reduction_metrics(run_root: Any) -> dict[str, Any]:
    """Compute the ``triage_reduction`` section from the run's verified review artifacts.

    Implemented by the metric-computation chunk. Never raises for missing or unverifiable
    inputs; returns ``unavailable_section`` with named integrity gap codes instead.
    """
    raise NotImplementedError
