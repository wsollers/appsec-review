"""Coverage: the denominator of every finding count (finding-metrics.md sections 5.7 and 5.8, T-068).

A finding count is never reported without the coverage it was found in: catalogued entry points
as reviewed, not admitted and not built; reviewed and unreviewed units; translation units built
and extracted. The hunt-lane value is reported here too, because it is only meaningful beside
that denominator: it is the measured difference between this system and running scanners alone.

Doctrine:

* A missing input is ``unavailable(reason)`` or an unavailable ratio with a named reason, never
  zero. Code with no finding is not clean; an unreviewed entry point is listed with its reason.
* Coverage shares are a census of the catalogue, not a sample, so they carry no interval.
* A finding whose scanner backing is unknown is never counted as scanner-independent.
* Outputs are sorted and deterministic; inputs are never mutated.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import (
    SEVERITY_BANDS, check_snapshot, counts, is_actionable, is_published, normalize_path, ratio, unavailable)
from .slices import slice_counts

MAX_ENTRY_POINTS = 100_000     # per catalogue
MAX_UNCOVERED_LISTED = 200     # uncovered entry points listed in the result
ENTRY_POINT_KINDS = ("network_handler", "parser", "rpc_handler", "file_loader")
ENTRY_POINT_STATUSES = ("reviewed", "not_admitted", "not_built")
_ENTRY_FIELDS = ("entry_id", "kind", "path", "status", "reason")


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a short single-line string")
    return value


def _tally(statuses: list[str]) -> dict[str, Any]:
    by_status = {status: 0 for status in ENTRY_POINT_STATUSES}
    for status in statuses:
        by_status[status] += 1
    return {"total": len(statuses), "by_status": by_status,
            "reviewed_share": ratio(by_status["reviewed"], len(statuses))}


def entry_point_coverage(entry_points: Any) -> dict[str, Any]:
    """Catalogued entry points as reviewed, not admitted (by reason) and not built.

    ``entry_points`` is a list of ``{"entry_id", "kind", "path", "status", "reason"}`` rows
    (``reason`` may be omitted for a reviewed row), or ``None`` when no catalogue exists. A
    reviewed row carries no reason; every other row names one. ``uncovered`` lists at most
    ``MAX_UNCOVERED_LISTED`` rows; ``uncovered_truncated`` counts the rows left out.
    """
    if entry_points is None:
        return unavailable("entry_point_catalog_unavailable")
    if not isinstance(entry_points, (list, tuple)):
        raise ValueError("entry point catalogue must be a list")
    if len(entry_points) > MAX_ENTRY_POINTS:
        raise ValueError("entry point catalogue exceeds the bounded number of entry points")
    seen: set[str] = set()
    statuses: list[str] = []
    by_kind: dict[str, list[str]] = {kind: [] for kind in ENTRY_POINT_KINDS}
    reasons: dict[str, int] = {}
    uncovered: list[dict[str, Any]] = []
    for row in entry_points:
        if not isinstance(row, Mapping) or set(row) - set(_ENTRY_FIELDS):
            raise ValueError("an entry point must be an object without unknown fields")
        entry_id = _text(row.get("entry_id"), "entry point entry_id")
        if entry_id in seen:
            raise ValueError(f"entry point catalogue repeats entry_id {entry_id!r}")
        seen.add(entry_id)
        kind, status, reason = row.get("kind"), row.get("status"), row.get("reason")
        if kind not in ENTRY_POINT_KINDS:
            raise ValueError(f"entry point kind {kind!r} is outside its closed vocabulary")
        if status not in ENTRY_POINT_STATUSES:
            raise ValueError(f"entry point status {status!r} is outside its closed vocabulary")
        normalize_path(row.get("path"))
        if status == "reviewed":
            if reason is not None:
                raise ValueError(f"reviewed entry point {entry_id!r} carries a residual-coverage reason")
        else:
            if reason is None:
                raise ValueError(f"entry point {entry_id!r} is {status} without a reason")
            reason = _text(reason, "entry point reason")
            reasons[reason] = reasons.get(reason, 0) + 1
            uncovered.append({"entry_id": entry_id, "kind": kind, "status": status, "reason": reason})
        statuses.append(status)
        by_kind[kind].append(status)
    uncovered.sort(key=lambda item: (item["kind"], item["entry_id"]))
    return {
        "available": True, **_tally(statuses),
        "by_kind": {kind: _tally(by_kind[kind]) for kind in sorted(by_kind)},
        "uncovered_by_reason": {reason: reasons[reason] for reason in sorted(reasons)},
        "uncovered": uncovered[:MAX_UNCOVERED_LISTED],
        "uncovered_truncated": max(0, len(uncovered) - MAX_UNCOVERED_LISTED),
    }


def unit_coverage(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Reviewed and unreviewed units of a snapshot.

    Unknown ``reviewed_units`` is ``unavailable("coverage_unknown")``. When the reviewed units are
    known but the unreviewed ones are not, the reviewed count is reported and the share is an
    unavailable ratio: the denominator is not assumed to be the reviewed units alone.
    """
    checked = check_snapshot(snapshot)
    reviewed, unreviewed = checked["reviewed_units"], checked["unreviewed_units"]
    if reviewed is None:
        return unavailable("coverage_unknown")
    result: dict[str, Any] = {
        "available": True, "reviewed": len(reviewed),
        "content_identity_known": sum(1 for content in reviewed.values() if content is not None)}
    if unreviewed is None:
        return {**result, "unreviewed": None, "unreviewed_by_reason": None,
                "reviewed_share": ratio(None, None, reason="unreviewed_units_unknown")}
    both = sorted(set(reviewed) & set(unreviewed))
    if both:
        raise ValueError(f"a unit is both reviewed and unreviewed: {both[0]!r}")
    by_reason: dict[str, int] = {}
    for reason in unreviewed.values():
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {**result, "unreviewed": len(unreviewed),
            "unreviewed_by_reason": {reason: by_reason[reason] for reason in sorted(by_reason)},
            "reviewed_share": ratio(len(reviewed), len(reviewed) + len(unreviewed))}


def _units(value: Any, name: str) -> int | None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
        raise ValueError(f"translation unit count {name} must be a non-negative integer or null")
    return value


def translation_units(built: int | None, extracted: int | None, total: int | None) -> dict[str, Any]:
    """Share of translation units built and share extracted, both over ``total``.

    Each count may be ``None``; the affected share is then an unavailable ratio with a named reason.
    """
    built, extracted, total = _units(built, "built"), _units(extracted, "extracted"), _units(total, "total")
    if built is not None and extracted is not None and extracted > built:
        raise ValueError("more translation units extracted than built")
    for name, value in (("built", built), ("extracted", extracted)):
        if value is not None and total is not None and value > total:
            raise ValueError(f"more translation units {name} than exist")

    def share(value: int | None, name: str) -> dict[str, Any]:
        if total is None:
            return ratio(None, None, reason="translation_unit_total_unavailable")
        if value is None:
            return ratio(None, None, reason=f"{name}_count_unavailable")
        return ratio(value, total)

    return {"available": True, "built": built, "extracted": extracted, "total": total,
            "built_share": share(built, "built"), "extracted_share": share(extracted, "extracted")}


def hunt_lane_value(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Published hunt-lane findings with no scanner observation at the same root cause.

    ``scanner_independent`` counts only ``scanner_backed is False``; a finding whose backing was
    not established is ``scanner_backing_unknown`` and never counted as independent.
    ``share_of_published`` is over all published findings of both lanes.
    """
    published = [finding for finding in check_snapshot(snapshot)["findings"] if is_published(finding)]
    hunt = [finding for finding in published if finding.get("lane") == "hunt"]
    independent = [finding for finding in hunt if finding.get("scanner_backed") is False]
    return {
        "available": True, "published": len(published), "hunt_published": len(hunt),
        "scanner_independent": {
            "count": len(independent),
            "finding_ids": sorted(finding["finding_id"] for finding in independent),
            "by_weakness_family": slice_counts(independent, "weakness_family"),
            "by_severity": counts((finding.get("severity") for finding in independent), SEVERITY_BANDS),
        },
        "scanner_backed": sum(1 for finding in hunt if finding.get("scanner_backed") is True),
        "scanner_backing_unknown": sum(1 for finding in hunt if finding.get("scanner_backed") is None),
        "share_of_published": ratio(len(independent), len(published), interval=True),
        "confirmed_actionable_scanner_independent": sum(1 for finding in independent if is_actionable(finding)),
    }


__all__ = ["ENTRY_POINT_KINDS", "ENTRY_POINT_STATUSES", "MAX_ENTRY_POINTS", "MAX_UNCOVERED_LISTED",
           "entry_point_coverage", "hunt_lane_value", "translation_units", "unit_coverage"]
