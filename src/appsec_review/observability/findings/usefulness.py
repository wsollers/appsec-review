"""Volume and usefulness of the published findings (finding-metrics.md sections 5.1 and 5.3, T-064).

Every function takes one ``finding-snapshot/1`` and reads nothing else. Doctrine:

* The unit is the finding (one root cause, deduplicated by fingerprint); a published finding is one
  in state ``confirmed`` or ``supported``. Counts are a final-state snapshot, not event counts.
* Precision needs labels that are independent of the detector (answer key, developer outcome, audit
  sample, crash), keyed by fingerprint ``exact``. Without them it is ``unavailable``, never zero or
  one, and an unlabelled finding is neither true nor false.
* Precision is emitted with the number of findings it was computed over, so a run that publishes
  almost nothing cannot look good on precision alone; actionable yield is reported beside it.
* Supported-but-unconfirmed findings are counted separately from confirmed ones.
* Money is ``decimal.Decimal`` carried as a decimal string with its currency and provenance kind.
* Proportions over findings carry a Wilson interval. Pure and deterministic; inputs never mutated.
"""
from __future__ import annotations

from collections.abc import Mapping
import decimal
import math
import re
from typing import Any

from .contracts import (
    ACTIONABLE_BANDS, BUCKETS, LANES, SEVERITY_BANDS, SHIP_BLOCK_STATUSES, LabelOutcome, check_snapshot, counts,
    is_actionable, is_published, ratio, unavailable,
)

MAX_BUDGET = 1_000                                   # largest alert budget of precision_at_budget
COST_FIELDS = ("amount", "currency", "kind")
COST_KINDS = ("provider_reported", "api_estimate")
COST_PLACES = decimal.Decimal("0.000001")            # resolution of a derived cost

_OUTCOMES = tuple(item.value for item in LabelOutcome)
_TRUE, _FALSE, _UNRESOLVED = (LabelOutcome.TRUE.value, LabelOutcome.FALSE.value, LabelOutcome.UNRESOLVED.value)
_AMOUNT = re.compile(r"\d{1,18}(?:\.\d{1,12})?")
_CURRENCY = re.compile(r"[A-Z]{3}")
_STATE_RANK = {"confirmed": 0, "supported": 1}
_SEVERITY_RANK = {band: position for position, band in enumerate(reversed(SEVERITY_BANDS))}   # critical first


def _findings(snapshot: Any) -> list[Mapping[str, Any]]:
    return sorted(check_snapshot(snapshot)["findings"], key=lambda finding: finding["finding_id"])


def volume(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Final-state counts of one snapshot: findings are root causes, deduplicated by fingerprint.

    ``duplicate_rate`` is the share of reported findings that collapsed into another one:
    ``duplicates_collapsed / (findings + duplicates_collapsed)``.
    """
    findings = _findings(snapshot)
    states: dict[str, int] = {}
    for finding in findings:
        states[finding["state"]] = states.get(finding["state"], 0) + 1
    duplicates = sum(finding.get("duplicates_collapsed", 0) for finding in findings)
    return {
        "findings": len(findings),
        "published": sum(1 for finding in findings if is_published(finding)),
        "by_state": dict(sorted(states.items())),
        "by_bucket": counts((finding.get("bucket") for finding in findings), BUCKETS),
        "by_lane": counts((finding.get("lane") for finding in findings), LANES),
        "duplicates_collapsed": duplicates,
        "duplicate_rate": ratio(duplicates, len(findings) + duplicates),
    }


def severity(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Severity of the published findings, and the share nobody has rated.

    A published finding is unrated when it has no severity band or its ship-block status is
    ``decision_pending``.
    """
    published = [finding for finding in _findings(snapshot) if is_published(finding)]
    unrated = sum(1 for finding in published
                  if finding.get("severity") is None or finding.get("ship_block_status") == "decision_pending")
    return {
        "published": len(published),
        "distribution": counts((finding.get("severity") for finding in published), SEVERITY_BANDS),
        "by_ship_block_status": counts((finding.get("ship_block_status") for finding in published),
                                       SHIP_BLOCK_STATUSES),
        "unrated_share": ratio(unrated, len(published), interval=True),
    }


def _cost(cost: Any) -> tuple[decimal.Decimal, str, str] | None:
    if cost is None:
        return None
    if not isinstance(cost, Mapping) or set(cost) != set(COST_FIELDS):
        raise ValueError("cost must hold exactly an amount, a currency and a kind")
    amount, currency, kind = cost["amount"], cost["currency"], cost["kind"]
    if not isinstance(amount, str) or not _AMOUNT.fullmatch(amount):
        raise ValueError("cost amount must be a non-negative, finite decimal string")
    if not isinstance(currency, str) or not _CURRENCY.fullmatch(currency):
        raise ValueError("cost currency must be a three-letter code")
    if not isinstance(kind, str) or kind not in COST_KINDS:
        raise ValueError(f"cost kind {kind!r} is outside the closed vocabulary")
    return decimal.Decimal(amount), currency, kind


def _group(findings: list[Mapping[str, Any]]) -> dict[str, Any]:
    return {"count": len(findings), "finding_ids": sorted(finding["finding_id"] for finding in findings)}


def actionable_yield(snapshot: Mapping[str, Any], *, reviewed_kloc: float | None = None,
                     cost: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Confirmed high and critical findings: per run, per reviewed KLOC and per known cost.

    ``supported_actionable`` (supported, high or critical) is listed separately and enters no rate.
    ``cost`` is ``{"amount": decimal string, "currency": 3-letter code, "kind": "provider_reported" |
    "api_estimate"}``; the cost per confirmed actionable finding keeps its currency and kind and is
    ``None`` with a named reason when the cost is unknown or there is no such finding.
    """
    findings = _findings(snapshot)
    if reviewed_kloc is not None and (isinstance(reviewed_kloc, bool) or not isinstance(reviewed_kloc, (int, float))
                                      or not math.isfinite(reviewed_kloc) or reviewed_kloc <= 0):
        raise ValueError("reviewed_kloc must be a positive number or null")
    known = _cost(cost)
    confirmed = [finding for finding in findings if is_actionable(finding)]
    supported = [finding for finding in findings
                 if finding["state"] == "supported" and finding.get("severity") in ACTIONABLE_BANDS]
    per_cost: dict[str, Any] = {"amount": None, "currency": None, "kind": None, "reason": "cost_unavailable"}
    if known is not None:
        amount, currency, kind = known
        per_cost = {"amount": None, "currency": currency, "kind": kind,
                    "reason": "no_confirmed_actionable_findings"}
        if confirmed:
            with decimal.localcontext() as context:
                context.prec = 50
                share = (amount / len(confirmed)).quantize(COST_PLACES, rounding=decimal.ROUND_HALF_EVEN)
            per_cost.update(amount=format(share, "f"), reason=None)
    return {
        "confirmed_actionable": _group(confirmed),
        "supported_actionable": _group(supported),
        "per_reviewed_kloc": {
            "value": None if reviewed_kloc is None else round(len(confirmed) / reviewed_kloc, 6),
            "reviewed_kloc": reviewed_kloc,
            "reason": "reviewed_kloc_unavailable" if reviewed_kloc is None else None},
        "cost_per_confirmed_actionable": per_cost,
    }


def _labels(labels: Any) -> dict[str, tuple[str, str | None]]:
    """``fingerprint exact -> (outcome, expected severity)`` of a validated label map."""
    if not isinstance(labels, Mapping):
        raise ValueError("labels must map a fingerprint to a label")
    table = {}
    for subject_id, label in labels.items():
        outcome = label.get("outcome") if isinstance(label, Mapping) else None
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise ValueError(f"label of {subject_id!r} has an outcome outside the closed vocabulary")
        expected = label.get("expected_severity")
        if expected is not None and expected not in SEVERITY_BANDS:
            raise ValueError(f"label of {subject_id!r} has an expected severity outside the closed vocabulary")
        table[subject_id] = (outcome, expected)
    return table


def _precision(findings: list[Mapping[str, Any]], labels: Mapping[str, tuple[str, str | None]]) -> dict[str, Any]:
    tally = {_TRUE: 0, _FALSE: 0, _UNRESOLVED: 0, None: 0}
    for finding in findings:
        tally[labels.get(finding["fingerprint"]["exact"], (None, None))[0]] += 1
    return {"considered": len(findings), "true": tally[_TRUE], "false": tally[_FALSE],
            "unresolved": tally[_UNRESOLVED], "unlabelled": tally[None],
            "precision": ratio(tally[_TRUE], tally[_TRUE] + tally[_FALSE], interval=True)}


def precision(snapshot: Mapping[str, Any], labels: Mapping[str, Mapping[str, Any]] | None) -> dict[str, Any]:
    """Labelled precision of the published findings, and of the confirmed high and critical ones.

    Precision is ``true / (true + false)``; ``unresolved`` and ``unlabelled`` findings are counted
    beside it and never treated as either. ``severity_agreement`` compares the reported band with the
    label's ``expected_severity`` over published findings that have one: ``equal``, ``over_rated``
    (reported higher), ``under_rated``, and ``unrated`` when the finding has no band to compare.
    """
    findings = _findings(snapshot)
    if labels is None:
        return unavailable("no_finding_labels")
    table = _labels(labels)
    published = [finding for finding in findings if is_published(finding)]
    agreement = {"equal": 0, "over_rated": 0, "under_rated": 0, "unrated": 0}
    for finding in published:
        expected = table.get(finding["fingerprint"]["exact"], (None, None))[1]
        if expected is None:
            continue
        reported = finding.get("severity")
        if reported is None:
            agreement["unrated"] += 1
            continue
        difference = SEVERITY_BANDS.index(reported) - SEVERITY_BANDS.index(expected)
        agreement["equal" if difference == 0 else "over_rated" if difference > 0 else "under_rated"] += 1
    return {
        "available": True,
        "published_precision": _precision(published, table),
        "actionable_precision": _precision([finding for finding in published if is_actionable(finding)], table),
        "severity_agreement": agreement,
    }


def precision_at_budget(snapshot: Mapping[str, Any], labels: Mapping[str, Mapping[str, Any]] | None,
                        budget: int) -> dict[str, Any]:
    """Labelled precision of the first ``budget`` published findings as ranked for the team.

    Rank: confirmed before supported, then critical to low, then unrated, then ``finding_id``.
    ``considered`` is the number actually ranked, which is below ``budget`` when fewer are published.
    """
    if isinstance(budget, bool) or not isinstance(budget, int) or not 1 <= budget <= MAX_BUDGET:
        raise ValueError("alert budget must be between 1 and the bounded budget")
    findings = _findings(snapshot)
    if labels is None:
        return unavailable("no_finding_labels")
    table = _labels(labels)
    ranked = sorted((finding for finding in findings if is_published(finding)),
                    key=lambda finding: (_STATE_RANK[finding["state"]],
                                         _SEVERITY_RANK.get(finding.get("severity"), len(SEVERITY_BANDS)),
                                         finding["finding_id"]))
    return {"available": True, "budget": budget, **_precision(ranked[:budget], table)}


__all__ = ["COST_FIELDS", "COST_KINDS", "MAX_BUDGET", "actionable_yield", "precision", "precision_at_budget",
           "severity", "volume"]
