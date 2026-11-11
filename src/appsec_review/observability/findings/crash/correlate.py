"""Crash evidence against the published finding set (finding-metrics.md sections 7.5 and 7.6, T-072).

Doctrine:

* A crash is independent evidence. Corroboration supports that a defect is real and reachable; it
  is evidence for the judge and a label source, and it never moves a claim to ``confirmed`` by
  itself. It labels nothing about severity, and the absence of a crash labels nothing.
* The fault class orders crashes for review. It is reported ordering, never an adjudicated severity
  and never an exploitability claim.
* A falling crash count after a fix supports the fix; it never establishes one, and a build with no
  crash data says nothing.
* Crash strings are untrusted data. They are compared by equality with finding locations and carried
  in listed rows; they never become a metric key. ``metrics`` keys only on adapter name, fault class,
  binding tier and failure kind.
* Units are not mixed: the unit here is the crash bucket, against the finding (root cause).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import re
from typing import Any

from ..contracts import (FAULT_ORDER, MAX_LEADS, MEMORY_SAFETY_FAULTS, BindingTier, FaultClass, LabelOutcome,
                         LabelSource, check_snapshot, counts, is_actionable, is_published, is_sha256, ratio,
                         unavailable, weakness_family)
from .binding import check_bindings
from .records import FAILURE_KINDS, check_evidence, review_rank

CORROBORATION_FRAMES = 32          # frames of a bucket considered when corroborating a finding
MAX_MISSED_ROWS = 200              # listed missed buckets; the rest are counted in ``truncated``
LEAD_LOCATIONS = 8                 # locations per crash lead candidate

_MEMORY_FAMILIES = frozenset({"memory_safety", "numeric", "format_string", "input_and_deserialization"})
# Which weakness families (``contracts.weakness_family`` names) a fault class can corroborate.
FAULT_FAMILIES: Mapping[str, frozenset[str]] = {
    **{name: _MEMORY_FAMILIES for name in sorted(MEMORY_SAFETY_FAULTS)},
    FaultClass.SANITIZER_UNDEFINED.value: frozenset({"memory_safety", "numeric"}),
    FaultClass.SANITIZER_RACE.value: frozenset({"concurrency"}),
    FaultClass.NEAR_NULL_READ.value: frozenset({"memory_safety"}),
    FaultClass.STACK_OVERFLOW.value: frozenset({"resource_management"}),
    FaultClass.OUT_OF_MEMORY.value: frozenset({"resource_management"}),
    FaultClass.ASSERTION.value: frozenset(),
    FaultClass.ABORT.value: frozenset(),
    FaultClass.UNKNOWN.value: frozenset(),
}
_UNBOUND = BindingTier.UNBOUND.value
_STAGE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
Key = tuple[str, str]


def _key(report: Mapping[str, Any]) -> Key:
    return report["adapter"], report["bucket_id"]


def _inputs(evidence: Any, bindings: Any) -> tuple[dict[str, Any], dict[Key, dict[str, Any]]]:
    checked = check_evidence(evidence)
    return checked, check_bindings(checked, bindings)


def _bound(evidence: Mapping[str, Any], index: Mapping[Key, Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [report for report in evidence["reports"] if index[_key(report)]["tier"] != _UNBOUND]


def corroborate(snapshot: Mapping[str, Any], evidence: Mapping[str, Any], bindings: Mapping[str, Any]
                ) -> dict[str, Any]:
    """Which published findings a bound crash bucket corroborates.

    A published finding (state confirmed or supported) is ``crash_corroborated`` by a bucket when
    all three hold: the bucket is bound (tier not ``unbound``); one of its first 32 frames has a
    ``function`` equal to the function of one of the finding's locations (match ``function``), or a
    ``file`` equal to a location's path with the frame line inside the location's line range (match
    ``file_and_line``); and the bucket's fault class is compatible with the finding's weakness family
    (``FAULT_FAMILIES``). A finding without a weakness is corroborated by nothing.

    Returns ``findings`` (rows ``{finding_id, fingerprint_exact, buckets}`` by finding id, buckets by
    bucket id), ``labels`` (``fingerprint_exact -> {"outcome": "true", "source": "crash",
    "expected_severity": None, "disposition": None}``), ``counts`` and
    ``corroborated_share_of_actionable`` (corroborated confirmed high/critical findings over
    confirmed high/critical findings, with its interval).

    Corroboration is evidence for the judge. It never moves a claim to ``confirmed`` by itself, it
    labels nothing about severity, and a finding no crash corroborates is not thereby less true.
    """
    snapshot = check_snapshot(snapshot)
    evidence, index = _inputs(evidence, bindings)
    bound = {_key(report): report for report in _bound(evidence, index)}
    by_function: dict[str, set[Key]] = {}
    by_file: dict[str, list[tuple[int, Key]]] = {}
    for key, report in bound.items():
        for frame in report["frames"][:CORROBORATION_FRAMES]:
            if frame["function"] is not None:
                by_function.setdefault(frame["function"], set()).add(key)
            if frame["file"] is not None and frame["line"] is not None:
                by_file.setdefault(frame["file"], []).append((frame["line"], key))
    rows, labels, used = [], {}, set()
    actionable = corroborated_actionable = published = 0
    for finding in snapshot["findings"]:
        if not is_published(finding):
            continue
        published += 1
        actionable += is_actionable(finding)
        family = weakness_family(finding["weakness_cwe"])
        matches: dict[Key, str] = {}
        for location in finding["locations"]:
            for line, key in by_file.get(location["path"], ()):
                if location["start_line"] <= line <= location["end_line"]:
                    matches.setdefault(key, "file_and_line")
            for key in by_function.get(location["function"] or "", ()):
                matches[key] = "function"
        buckets = [{"bucket_id": key[1], "adapter": key[0], "tier": index[key]["tier"],
                    "fault_class": bound[key]["fault"]["class"], "occurrences": bound[key]["occurrences"],
                    "match": match}
                   for key, match in matches.items() if family in FAULT_FAMILIES[bound[key]["fault"]["class"]]]
        if not buckets:
            continue
        used |= {(item["adapter"], item["bucket_id"]) for item in buckets}
        corroborated_actionable += is_actionable(finding)
        exact = finding["fingerprint"]["exact"]
        rows.append({"finding_id": finding["finding_id"], "fingerprint_exact": exact,
                     "buckets": sorted(buckets, key=lambda item: (item["bucket_id"], item["adapter"]))})
        labels[exact] = {"outcome": LabelOutcome.TRUE.value, "source": LabelSource.CRASH.value,
                         "expected_severity": None, "disposition": None}
    return {
        "findings": sorted(rows, key=lambda item: item["finding_id"]),
        "labels": dict(sorted(labels.items())),
        "counts": {"published_findings": published, "corroborated_findings": len(rows),
                   "actionable_findings": actionable, "corroborated_actionable_findings": corroborated_actionable,
                   "bound_buckets": len(bound), "corroborating_buckets": len(used)},
        "corroborated_share_of_actionable": ratio(corroborated_actionable, actionable, interval=True),
    }


def _top_frame(report: Mapping[str, Any], binding: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The frame a bucket is listed under: its first symbol-matched frame, else its first symbolicated one."""
    if binding["tier"] == BindingTier.SYMBOL_MATCHED.value and binding["matched_frames"]:
        return report["frames"][min(binding["matched_frames"])]
    return next((frame for frame in report["frames"] if frame["symbolicated"]), None)


def missed_buckets(snapshot: Mapping[str, Any], evidence: Mapping[str, Any], bindings: Mapping[str, Any], *,
                   stage_of: Callable[[str | None, str | None], str] | None = None) -> dict[str, Any]:
    """Bound memory-safety crash buckets with no finding at any frame: the missed-defect signal.

    A bucket is listed when it is bound, its fault class is in ``MEMORY_SAFETY_FAULTS``, and no
    finding of *any* state matches *any* of its frames by function or by file and line, whatever the
    finding's weakness family. This is the nearest thing to a recall measure on a real target; it
    is a list of places to look, not a count of missed vulnerabilities.

    Rows are ``{bucket_id, adapter, tier, fault_class, occurrences, top_function, top_file, stage,
    covered}`` ordered by (review rank, most occurrences, bucket id); at most 200 are listed and the
    rest are counted in ``truncated``. ``stage_of(path, function)`` is the caller's answer to where
    the location dropped out of the funnel (``not_covered``, ``no_lead``, ``lead_dismissed``, ...);
    without it ``stage`` is ``None``. ``covered`` is the snapshot's own answer: whether the top
    frame's file is a reviewed unit, ``None`` when coverage or the file is unknown.
    """
    snapshot = check_snapshot(snapshot)
    evidence, index = _inputs(evidence, bindings)
    functions = {location["function"] for finding in snapshot["findings"] for location in finding["locations"]
                 if location["function"]}
    ranges: dict[str, list[tuple[int, int]]] = {}
    for finding in snapshot["findings"]:
        for location in finding["locations"]:
            ranges.setdefault(location["path"], []).append((location["start_line"], location["end_line"]))
    reviewed = snapshot["reviewed_units"]
    rows = []
    for report in _bound(evidence, index):
        if report["fault"]["class"] not in MEMORY_SAFETY_FAULTS:
            continue
        if any(frame["function"] in functions
               or (frame["line"] is not None
                   and any(start <= frame["line"] <= end for start, end in ranges.get(frame["file"] or "", ())))
               for frame in report["frames"]):
            continue
        binding = index[_key(report)]
        top = _top_frame(report, binding)
        function, file = (top["function"], top["file"]) if top is not None else (None, None)
        stage = None
        if stage_of is not None:
            stage = stage_of(file, function)
            if not isinstance(stage, str) or not _STAGE.match(stage):
                raise ValueError("stage_of must return a short lower-case stage name")
        rows.append({"bucket_id": report["bucket_id"], "adapter": report["adapter"], "tier": binding["tier"],
                     "fault_class": report["fault"]["class"], "occurrences": report["occurrences"],
                     "top_function": function, "top_file": file, "stage": stage,
                     "covered": None if reviewed is None or file is None else file in reviewed})
    rows.sort(key=lambda item: (FAULT_ORDER.index(item["fault_class"]), -item["occurrences"], item["bucket_id"],
                                item["adapter"]))
    return {"buckets": rows[:MAX_MISSED_ROWS], "count": len(rows), "truncated": max(0, len(rows) - MAX_MISSED_ROWS)}


def lead_candidates(evidence: Mapping[str, Any], bindings: Mapping[str, Any], *, max_leads: int = 500
                    ) -> list[dict[str, Any]]:
    """Bound buckets as lead candidates of the ``crash_report`` lead family, best review order first.

    Each is ``{"lead_family": "crash_report", "lead_id": "crash:<adapter>:<bucket_id>", "reported_rank",
    "fault_class", "occurrences", "locations"}``; ``locations`` are ``{path, line, function}`` of the
    first eight symbolicated bound frames (the matched frames of a ``symbol_matched`` bucket, every
    frame of a build- or revision-matched one). Order is (rank, most occurrences, bucket id) and the
    list stops at ``max_leads``; ``metrics`` reports the full number of candidates.

    ``reported_rank`` is review ordering only, as for every other lead family. It is never an
    adjudicated severity.
    """
    if isinstance(max_leads, bool) or not isinstance(max_leads, int) or not 1 <= max_leads <= MAX_LEADS:
        raise ValueError("max_leads must be between 1 and the bounded number of leads")
    evidence, index = _inputs(evidence, bindings)
    leads = []
    for report in _bound(evidence, index):
        binding = index[_key(report)]
        frames = ([report["frames"][item] for item in sorted(binding["matched_frames"])]
                  if binding["tier"] == BindingTier.SYMBOL_MATCHED.value else report["frames"])
        leads.append({
            "lead_family": "crash_report", "lead_id": f"crash:{report['adapter']}:{report['bucket_id']}",
            "reported_rank": review_rank(report), "fault_class": report["fault"]["class"],
            "occurrences": report["occurrences"],
            "locations": [{"path": frame["file"], "line": frame["line"], "function": frame["function"]}
                          for frame in frames if frame["symbolicated"]][:LEAD_LOCATIONS]})
    leads.sort(key=lambda item: (item["reported_rank"], -item["occurrences"], item["lead_id"]))
    return leads[:max_leads]


def fix_support(fingerprint_exact: str, corroboration: Mapping[str, Any], evidence: Mapping[str, Any], *,
                fixed_in_version: str, version_order: Sequence[str]) -> dict[str, Any]:
    """Crash occurrences of a fixed finding's buckets before and after the fixing version.

    ``version_order`` is the caller's explicit ordering of build versions, oldest first, and must
    contain ``fixed_in_version``; nothing is inferred from how a version string looks. A bucket
    whose ``build.version`` is missing or not in the ordering is counted in
    ``occurrences_unknown_version``, never guessed. A merged bucket carries the build of one report,
    so occurrences are attributed per bucket, not per occurrence.

    ``direction`` is ``falling`` or ``not_falling`` only when the finding is crash-corroborated,
    crashes were seen before the fix, and the evidence holds at least one bucket from a build at or
    after the fix (``post_fix_builds_observed``); otherwise ``None``, because a build with no crash
    data says nothing. A falling count supports the fix; it never establishes one:
    ``establishes_fix`` is always ``False``.
    """
    if not is_sha256(fingerprint_exact):
        raise ValueError("fingerprint_exact must be a SHA-256")
    if isinstance(version_order, (str, bytes)) or not isinstance(version_order, Sequence) or any(
            not isinstance(item, str) or not item for item in version_order):
        raise ValueError("version_order must be a sequence of version strings")
    if len(set(version_order)) != len(version_order) or fixed_in_version not in version_order:
        raise ValueError("version_order must be unique and contain fixed_in_version")
    evidence = check_evidence(evidence)
    listed = corroboration.get("findings") if isinstance(corroboration, Mapping) else None
    if not isinstance(listed, list):
        raise ValueError("corroboration must be a corroborate result")
    position = {version: index for index, version in enumerate(version_order)}
    fixed = position[fixed_in_version]
    reports = {_key(report): report for report in evidence["reports"]}
    observed = any(position.get(report["build"]["version"], -1) >= fixed for report in reports.values())
    result: dict[str, Any] = {
        "fingerprint_exact": fingerprint_exact, "fixed_in_version": fixed_in_version,
        "status": "not_crash_corroborated", "buckets": 0, "occurrences_before_fix": None,
        "occurrences_at_or_after_fix": None, "occurrences_unknown_version": None,
        "post_fix_builds_observed": observed, "direction": None, "establishes_fix": False}
    rows = [row for row in listed if isinstance(row, Mapping) and row.get("fingerprint_exact") == fingerprint_exact]
    if not rows:
        return result
    before = after = unknown = 0
    try:
        keys = sorted({(item["adapter"], item["bucket_id"]) for row in rows for item in row["buckets"]})
    except (KeyError, TypeError):
        raise ValueError("corroboration must be a corroborate result") from None
    for key in keys:
        if key not in reports:
            raise ValueError("corroboration names a bucket the crash evidence does not hold")
        index = position.get(reports[key]["build"]["version"])
        if index is None:
            unknown += reports[key]["occurrences"]
        elif index < fixed:
            before += reports[key]["occurrences"]
        else:
            after += reports[key]["occurrences"]
    direction = None if not observed or before == 0 else "falling" if after < before else "not_falling"
    return {**result, "status": "measured", "buckets": len(keys), "occurrences_before_fix": before,
            "occurrences_at_or_after_fix": after, "occurrences_unknown_version": unknown, "direction": direction}


def metrics(evidence: Mapping[str, Any] | None, bindings: Mapping[str, Any] | None,
            corroboration: Mapping[str, Any] | None, missed: Mapping[str, Any] | None) -> dict[str, Any]:
    """The crash section of the finding scorecard (finding-metrics.md section 7.6).

    ``evidence is None`` (no crash source registered) is ``unavailable("no_crash_source_registered")``:
    null, never zero. Otherwise ``bindings`` is required; ``corroboration`` and ``missed`` may be
    ``None`` when there is no finding snapshot, and their numbers are then ``None`` with the reason
    ``no_finding_snapshot``. Keys are closed vocabularies only: observed adapter names (sorted),
    binding tiers and fault classes (zero-filled), failure kinds.
    """
    if evidence is None:
        return unavailable("no_crash_source_registered")
    evidence, index = _inputs(evidence, bindings)
    reports = evidence["reports"]
    by_adapter: dict[str, dict[str, int]] = {}
    for report in sorted(reports, key=_key):
        row = by_adapter.setdefault(report["adapter"], {"buckets": 0, "occurrences": 0})
        row["buckets"] += 1
        row["occurrences"] += report["occurrences"]
    frames = [frame for report in reports for frame in report["frames"]]
    if corroboration is not None and not (isinstance(corroboration, Mapping)
                                          and isinstance(corroboration.get("counts"), Mapping)
                                          and "corroborated_share_of_actionable" in corroboration):
        raise ValueError("corroboration must be a corroborate result")
    if missed is not None and not (isinstance(missed, Mapping) and isinstance(missed.get("count"), int)):
        raise ValueError("missed must be a missed_buckets result")
    return {
        "available": True,
        "reports": evidence["counts"]["reports"], "buckets": len(reports),
        "occurrences": sum(report["occurrences"] for report in reports),
        "by_adapter": by_adapter,
        "by_binding_tier": counts((index[_key(report)]["tier"] for report in reports),
                                  tuple(tier.value for tier in BindingTier)),
        "by_fault_class": counts((report["fault"]["class"] for report in reports), FAULT_ORDER),
        "symbolicated_frame_share": ratio(sum(frame["symbolicated"] for frame in frames), len(frames)),
        "parse_failures": {"files": evidence["counts"]["failed"],
                           "by_error": counts((item["error"] for item in evidence["failures"]), FAILURE_KINDS)},
        "corroborated_findings": None if corroboration is None else corroboration["counts"]["corroborated_findings"],
        "corroborated_share_of_actionable": (
            ratio(None, None, reason="no_finding_snapshot", interval=True) if corroboration is None
            else corroboration["corroborated_share_of_actionable"]),
        "memory_safety_buckets_without_finding": None if missed is None else missed["count"],
        "lead_candidates": len(_bound(evidence, index)),
    }


__all__ = ["CORROBORATION_FRAMES", "FAULT_FAMILIES", "LEAD_LOCATIONS", "MAX_MISSED_ROWS", "corroborate",
           "fix_support", "lead_candidates", "metrics", "missed_buckets"]
