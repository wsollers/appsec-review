"""The typed build outcome of a language-build receipt and the build/provenance classes of its gaps.

One rule, stated once:

* ``terminal_status`` describes the *receipt*. It is drawn from the closed ``ProducerStatus``
  vocabulary and any named gap on the receipt makes it ``COMPLETED_WITH_GAPS``; native target
  enforcement that cannot prove the build's target flips a ``SUCCEEDED`` receipt the same way and
  moves its artifacts to ``rejected_artifacts``.
* ``build_outcome`` describes the *build*: whether the family's build commands ran to completion
  and the bound products exist (the protected compile database and workspace manifest for native,
  their equivalents for the other families). It is decided from the build's own result before
  provenance and enforcement gaps are appended, and it is kept when enforcement later flips
  ``terminal_status``. The vocabulary is closed: ``built``, ``failed`` (the build started but did
  not complete) and ``not_run`` (blocked, skipped, not applicable, never dispatched).
* a gap record's ``code`` classifies the gap. ``provenance_unavailable`` marks a gap about where an
  output ships (``delivery_fact_unavailable``), how a build-output root was classified
  (``build-output-heuristic``) or what the execution capture could not establish about the compilers
  it saw (``unknown_compiler_in_capture``, ``capture_empty``, ``mixed_targets_in_capture``).
  ``producer_reported_gap`` and ``producer_failed`` mark gaps that mean the build itself is
  incomplete or its target is not permitted.

A consumer that asks "do the build products exist" reads ``build_outcome``; one that asks "was the
receipt clean" keeps reading ``terminal_status``. Receipts written before the field existed carry
none, so :func:`build_succeeded` falls back to the caller's legacy status test for them. A receipt
whose target enforcement is unproven keeps its artifacts in ``rejected_artifacts`` whatever its
``build_outcome`` says: that is a provenance consequence, never a build failure, and never a
reason to widen enforcement.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from appsec_review.interchange import GapCode
from appsec_review.jobs.build_output_scope import is_heuristic_gap
from appsec_review.jobs.delivery_scope import is_delivery_gap

BUILT = "built"
FAILED = "failed"
NOT_RUN = "not_run"
BUILD_OUTCOMES = frozenset({BUILT, FAILED, NOT_RUN})

#: Statuses a language-build receipt reaches only after its build commands ran to completion.
#: ``COMPLETED_WITH_GAPS`` is reached from ``SUCCEEDED`` alone (the enforcement flip).
_COMPLETED_STATUSES = frozenset({"SUCCEEDED", "COMPLETED_WITH_GAPS"})
#: Statuses that mean the build started but did not complete.
_FAILED_STATUSES = frozenset({"FAILED", "TIMED_OUT"})

#: Enforcement ``unresolved_inputs`` that describe the capture's provenance, not the build or a
#: forbidden target (``cross_target_not_permitted`` stays a producer-reported gap).
PROVENANCE_UNRESOLVED_INPUTS = frozenset({"unknown_compiler_in_capture", "capture_empty",
                                          "mixed_targets_in_capture"})


def build_outcome_from_status(terminal_status: Any) -> str:
    """The build outcome a receipt's own result implies, before provenance gaps are appended.

    ``SUCCEEDED`` and ``COMPLETED_WITH_GAPS`` mean the build completed; ``FAILED`` and ``TIMED_OUT``
    mean it did not; every other status (``BLOCKED``, ``NOT_APPLICABLE``, ``SKIPPED_NA``,
    ``SKIPPED_POLICY``, ``GAP``, ...) means it was never run.
    """
    status = str(terminal_status or "")
    if status in _COMPLETED_STATUSES:
        return BUILT
    if status in _FAILED_STATUSES:
        return FAILED
    return NOT_RUN


def validate_build_outcome(value: Any, *, context: str = "language-build receipt") -> str:
    if not isinstance(value, str) or value not in BUILD_OUTCOMES:
        raise ValueError(f"{context} build_outcome {value!r} is not one of {sorted(BUILD_OUTCOMES)}")
    return value


def with_build_outcome(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """The receipt with a validated ``build_outcome``; derived from its status when the producer set none."""
    value = dict(receipt)
    if "build_outcome" in value:
        validate_build_outcome(value["build_outcome"],
                               context=f"language-build receipt {value.get('build_unit_id')}")
    else:
        value["build_outcome"] = build_outcome_from_status(value.get("terminal_status"))
    return value


def build_succeeded(receipt: Mapping[str, Any], *,
                    legacy_statuses: frozenset[str] = frozenset({"SUCCEEDED"})) -> bool:
    """Whether the receipt's build products exist.

    ``build_outcome == "built"`` when the receipt carries the field (an unknown value is a
    ``ValueError``); otherwise the caller's legacy ``terminal_status`` test for older receipts.
    """
    if "build_outcome" in receipt:
        return validate_build_outcome(receipt["build_outcome"],
                                      context=f"language-build receipt {receipt.get('build_unit_id')}") == BUILT
    return receipt.get("terminal_status") in legacy_statuses


def gap_code_for(reason: str) -> GapCode:
    """The ``producer-gap/1`` code of a language-build gap, decided by the producer that wrote it."""
    text = str(reason)
    if text in PROVENANCE_UNRESOLVED_INPUTS or is_delivery_gap(text) or is_heuristic_gap(text):
        return GapCode.PROVENANCE_UNAVAILABLE
    return GapCode.PRODUCER_REPORTED_GAP


__all__ = ["BUILD_OUTCOMES", "BUILT", "FAILED", "NOT_RUN", "PROVENANCE_UNRESOLVED_INPUTS",
           "build_outcome_from_status", "build_succeeded", "gap_code_for", "validate_build_outcome",
           "with_build_outcome"]
