"""Label sources of the finding-metrics domain (finding-metrics.md sections 4.3 and 5.10, T-064, T-069).

A label says whether a finding or a lead is real. Doctrine:

* Labels are independent of the detector. They come from an answer key, a developer outcome file, a
  human audit sample or a crash report. A model's dismissal, confidence or agreement with another
  model is a triage outcome and never becomes a label here.
* Unlabelled is not false. A finding that touches no key case gets no label (unlabelled code is not
  known clean), a ``duplicate`` developer outcome labels nothing, and an audit-sample member a person
  did not label is ``unresolved``.
* A missing input is ``None`` or ``unavailable(reason)``, never zero.
* Everything is pure and deterministic: no clock (the evaluation date is passed in), no ``random``
  (the audit sample is ordered by a seeded hash), sorted outputs, inputs never mutated.

A label is ``{"outcome", "source", "expected_severity", "disposition"}``; a label set
(``finding-labels/1``) is what ``merge`` returns. The subject id of a finding label is the finding's
fingerprint ``exact`` key; of a lead label, the lead id.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import datetime
import hashlib
import re
import statistics
from typing import Any

from appsec_review.acceptance.scoring_model import EntryKind, KeyEntry, ScoringKey
from appsec_review.observability.triage_reduction import DISPOSITIONS, REDUCED_DISPOSITIONS

from .contracts import (
    AUDIT_SAMPLE_SCHEMA, LABEL_AUTHORITY, LABEL_SET_SCHEMA, MAX_FINDINGS, MAX_LEADS, OUTCOME_FILE_SCHEMA,
    SEVERITY_BANDS, DeveloperDisposition, LabelOutcome, LabelSource, digest, is_sha256, normalize_location,
    normalize_path, ratio, unavailable, weakness_family,
)

MAX_OUTCOMES = 10_000          # per developer-outcomes file
MAX_AUDIT_SAMPLE = 5_000       # per exported audit sample

LABEL_FIELDS = ("outcome", "source", "expected_severity", "disposition")
OUTCOME_FILE_FIELDS = ("schema", "target_id", "outcomes")
OUTCOME_FIELDS = ("fingerprint", "disposition", "opened_on", "decided_on", "expires_on")
AUDIT_ELIGIBLE_DISPOSITIONS = REDUCED_DISPOSITIONS

_OUTCOMES = tuple(item.value for item in LabelOutcome)
_DEVELOPER_DISPOSITIONS = tuple(item.value for item in DeveloperDisposition)
_DECIDED = (LabelOutcome.TRUE.value, LabelOutcome.FALSE.value)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# What the team's decision says about whether the finding is real. ``duplicate`` says nothing.
_DISPOSITION_OUTCOME = {
    DeveloperDisposition.FIXED.value: LabelOutcome.TRUE.value,
    DeveloperDisposition.REJECTED_FALSE.value: LabelOutcome.FALSE.value,
    DeveloperDisposition.ACCEPTED_RISK.value: LabelOutcome.TRUE.value,
}


def _label(outcome: str, source: LabelSource, *, expected_severity: str | None = None,
           disposition: str | None = None) -> dict[str, Any]:
    return {"outcome": outcome, "source": source.value, "expected_severity": expected_severity,
            "disposition": disposition}


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a short single-line string")
    return value


# --------------------------------------------------------------------------------- answer key

def _key_entries(key: Any) -> list[tuple[KeyEntry, str]]:
    """The key's entries in id order, each with its comparable target-relative path."""
    if not isinstance(key, ScoringKey):
        raise ValueError("an answer key must be a ScoringKey")
    entries = sorted(key.entries, key=lambda entry: entry.id)
    if len({entry.id for entry in entries}) != len(entries):
        raise ValueError("answer key repeats an entry id")
    paired = []
    for entry in entries:
        try:
            path = normalize_path(entry.path)
        except ValueError:
            path = entry.path          # never equal to a normalized location path: the case is unhittable
        paired.append((entry, path))
    return paired


def _key_findings(findings: Any) -> list[dict[str, Any]]:
    """``{finding_id, subject, family, locations}`` per snapshot finding, in ``finding_id`` order."""
    if isinstance(findings, (str, bytes, Mapping)) or not isinstance(findings, Iterable):
        raise ValueError("findings must be a sequence of snapshot finding records")
    rows = []
    for finding in findings:
        if len(rows) >= MAX_FINDINGS:
            raise ValueError("more findings than the bounded number per snapshot")
        identity = finding.get("fingerprint") if isinstance(finding, Mapping) else None
        if not isinstance(identity, Mapping) or not is_sha256(identity.get("exact")):
            raise ValueError("a finding to label needs a fingerprint with an exact key")
        locations = finding.get("locations")
        if not isinstance(locations, (list, tuple)) or not locations:
            raise ValueError("a finding to label needs at least one location")
        rows.append({"finding_id": _identifier(finding.get("finding_id"), "finding_id"),
                     "subject": identity["exact"], "family": weakness_family(finding.get("weakness_cwe")),
                     "locations": [normalize_location(item) for item in locations]})
    if len({row["subject"] for row in rows}) != len(rows) or len({row["finding_id"] for row in rows}) != len(rows):
        raise ValueError("findings repeat a fingerprint or a finding_id")
    return sorted(rows, key=lambda row: row["finding_id"])


def _in_scope(entry: KeyEntry, path: str, location: Mapping[str, Any]) -> bool:
    if location["path"] != path:
        return False
    return entry.scope is None or (location["start_line"] <= entry.scope[1]
                                   and location["end_line"] >= entry.scope[0])


def key_entries_at(key: ScoringKey, locations: Iterable[Mapping[str, Any]]) -> list[KeyEntry]:
    """The key's entries, in id order, whose scope one of ``locations`` overlaps.

    This is the scope rule of every answer-key label: same normalized path, and the lines overlap
    the entry's scope when it declares one. Locations are validated, never mutated.
    """
    normalized = [normalize_location(item) for item in locations]
    return [entry for entry, path in _key_entries(key)
            if any(_in_scope(entry, path, location) for location in normalized)]


def _relations(entries: list[tuple[KeyEntry, str]], finding: Mapping[str, Any]) -> dict[str, list[KeyEntry]]:
    """How one finding relates to the key cases its locations fall in.

    ``hit``: a defect, same weakness family. ``wrong``: a defect, another family. ``unknown``: a
    defect, but the finding names no weakness. ``control``: a negative control.
    """
    relation: dict[str, list[KeyEntry]] = {"hit": [], "wrong": [], "unknown": [], "control": []}
    for entry, path in entries:
        if not any(_in_scope(entry, path, location) for location in finding["locations"]):
            continue
        if entry.kind is EntryKind.CONTROL:
            relation["control"].append(entry)
        elif finding["family"] is None:
            relation["unknown"].append(entry)
        elif finding["family"] == weakness_family(entry.cwe):
            relation["hit"].append(entry)
        else:
            relation["wrong"].append(entry)
    return relation


def _expected_severities(severities: Any, entries: list[tuple[KeyEntry, str]]) -> dict[str, str]:
    if severities is None:
        return {}
    if not isinstance(severities, Mapping):
        raise ValueError("severities must map a defect entry id to a severity band")
    defects = {entry.id for entry, _ in entries if entry.kind is EntryKind.DEFECT}
    for entry_id, band in severities.items():
        if entry_id not in defects:
            raise ValueError(f"expected severity names an entry that is not a defect of the key: {entry_id!r}")
        if band not in SEVERITY_BANDS:
            raise ValueError(f"expected severity of {entry_id!r} is outside the closed vocabulary: {band!r}")
    return dict(severities)


def label_findings_from_key(key: ScoringKey, findings: Iterable[Mapping[str, Any]], *,
                            severities: Mapping[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """``fingerprint exact -> label`` for the findings that touch a case of the answer key.

    * ``true``: a location overlaps a defect's scope and the weakness families agree.
    * ``false``: a location overlaps a control's scope, or overlaps a defect's scope while the finding
      names a weakness of another family (the wrong weakness was reported for that code).
    * ``unresolved``: a location overlaps a defect's scope but the finding names no weakness, and
      nothing above applies. The location is known, the weakness is not, so neither verdict is earned.
    * no label: the finding touches no key case.

    ``true`` wins over ``false`` across a finding's locations. ``expected_severity`` is the band
    ``severities`` gives the matched defect; when a finding matches several defects whose bands
    differ it is ``None`` (not established).
    """
    entries = _key_entries(key)
    expected = _expected_severities(severities, entries)
    labels: dict[str, dict[str, Any]] = {}
    for finding in _key_findings(findings):
        relation = _relations(entries, finding)
        if relation["hit"]:
            bands = {expected[entry.id] for entry in relation["hit"] if entry.id in expected}
            label = _label(LabelOutcome.TRUE.value, LabelSource.ANSWER_KEY,
                           expected_severity=next(iter(bands)) if len(bands) == 1 else None)
        elif relation["control"] or relation["wrong"]:
            label = _label(LabelOutcome.FALSE.value, LabelSource.ANSWER_KEY)
        elif relation["unknown"]:
            label = _label(LabelOutcome.UNRESOLVED.value, LabelSource.ANSWER_KEY)
        else:
            continue
        labels[finding["subject"]] = label
    return dict(sorted(labels.items()))


def key_case_hits(key: ScoringKey, findings: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    """``entry id -> sorted finding ids`` for every case of the key; an empty list is a case not hit.

    A defect is hit by a finding that is ``true`` because of it; a control by any finding in its scope.
    """
    entries = _key_entries(key)
    hits: dict[str, list[str]] = {entry.id: [] for entry, _ in entries}
    for finding in _key_findings(findings):
        relation = _relations(entries, finding)
        for entry in (*relation["hit"], *relation["control"]):
            hits[entry.id].append(finding["finding_id"])
    return {entry_id: sorted(ids) for entry_id, ids in hits.items()}


# ------------------------------------------------------------------------- developer outcomes

def _date(value: Any, name: str, *, optional: bool = False) -> datetime.date | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError(f"{name} must be an ISO date YYYY-MM-DD")
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{name} is not a real calendar date: {value!r}") from exc


def _closed(value: Any, allowed: tuple[str, ...], required: tuple[str, ...], name: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    unknown = sorted(str(key) for key in set(value) - set(allowed))
    missing = sorted(key for key in required if key not in value)
    if unknown or missing:
        raise ValueError(f"{name} has unknown fields {unknown} or lacks required fields {missing}")


def admit_outcomes(document: Any, *, as_of: str) -> dict[str, Any]:
    """Validate an operator-supplied ``developer-outcomes/1`` file and derive its finding labels.

    ``as_of`` is the evaluation date (ISO); the clock is never read. Returns ``{"target_id",
    "outcomes", "labels"}``: outcomes sorted by fingerprint, each with ``expired`` (an accepted risk
    whose ``expires_on`` precedes ``as_of``), and ``fingerprint -> label`` where ``fixed`` and
    ``accepted_risk`` are ``true`` (the team accepted the finding is real), ``rejected_false`` is
    ``false`` and ``duplicate`` labels nothing.
    """
    evaluated = _date(as_of, "as_of")
    _closed(document, OUTCOME_FILE_FIELDS, OUTCOME_FILE_FIELDS, "developer outcomes file")
    if document["schema"] != OUTCOME_FILE_SCHEMA:
        raise ValueError("unsupported developer outcomes schema")
    target_id = _identifier(document["target_id"], "developer outcomes target_id")
    rows = document["outcomes"]
    if not isinstance(rows, (list, tuple)) or len(rows) > MAX_OUTCOMES:
        raise ValueError("developer outcomes must be a list within the bounded number of outcomes")
    outcomes: dict[str, dict[str, Any]] = {}
    for row in rows:
        _closed(row, OUTCOME_FIELDS, ("fingerprint", "disposition", "decided_on"), "developer outcome")
        fingerprint, disposition = row["fingerprint"], row["disposition"]
        if not is_sha256(fingerprint):
            raise ValueError("developer outcome fingerprint must be 64 lowercase hexadecimal characters")
        if fingerprint in outcomes:
            raise ValueError(f"developer outcomes repeat fingerprint {fingerprint}")
        if not isinstance(disposition, str) or disposition not in _DEVELOPER_DISPOSITIONS:
            raise ValueError(f"developer outcome disposition {disposition!r} is outside the closed vocabulary")
        opened = _date(row.get("opened_on"), "opened_on", optional=True)
        decided = _date(row["decided_on"], "decided_on")
        expires = _date(row.get("expires_on"), "expires_on", optional=True)
        if opened is not None and decided < opened:      # type: ignore[operator]
            raise ValueError("developer outcome was decided before it was opened")
        accepted = disposition == DeveloperDisposition.ACCEPTED_RISK.value
        if accepted and expires is None:
            raise ValueError("an accepted risk needs an expiry date")
        if not accepted and expires is not None:
            raise ValueError("only an accepted risk carries an expiry date")
        outcomes[fingerprint] = {
            "fingerprint": fingerprint, "disposition": disposition, "opened_on": row.get("opened_on"),
            "decided_on": row["decided_on"], "expires_on": row.get("expires_on"),
            "expired": bool(accepted and expires < evaluated)}      # type: ignore[operator]
    ordered = [outcomes[fingerprint] for fingerprint in sorted(outcomes)]
    labels = {row["fingerprint"]: _label(_DISPOSITION_OUTCOME[row["disposition"]], LabelSource.DEVELOPER_OUTCOME,
                                         disposition=row["disposition"])
              for row in ordered if row["disposition"] in _DISPOSITION_OUTCOME}
    return {"target_id": target_id, "outcomes": ordered, "labels": labels}


def _timing(days: list[int]) -> dict[str, Any]:
    return {"median": float(statistics.median(days)) if days else None, "count": len(days)}


def outcome_metrics(admitted: Mapping[str, Any] | None,
                    findings_by_fingerprint: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """What the developers did with the findings (section 5.10), from ``admit_outcomes`` output.

    ``findings_by_fingerprint`` maps a fingerprint ``exact`` key to its finding record. The fix rate
    is reported beside the rejected-as-false rate over the same outcomes. Time to disposition is the
    median whole days from ``opened_on`` to ``decided_on`` over the outcomes that state an opening
    date, overall and by the matching finding's severity band (``"null"``: unrated or no such finding).
    """
    if admitted is None:
        return unavailable("no_developer_outcomes")
    if not isinstance(admitted, Mapping) or not isinstance(admitted.get("outcomes"), (list, tuple)):
        raise ValueError("outcome metrics need the result of admit_outcomes")
    if not isinstance(findings_by_fingerprint, Mapping):
        raise ValueError("findings_by_fingerprint must map a fingerprint to its finding record")
    outcomes = admitted["outcomes"]
    by_disposition = dict.fromkeys(_DEVELOPER_DISPOSITIONS, 0)
    overall: list[int] = []
    by_band: dict[str, list[int]] = {band: [] for band in (*SEVERITY_BANDS, "null")}
    expired = unmatched = 0
    for row in outcomes:
        by_disposition[row["disposition"]] += 1
        expired += bool(row["expired"])
        finding = findings_by_fingerprint.get(row["fingerprint"])
        unmatched += finding is None
        if row["opened_on"] is None:
            continue
        band = finding.get("severity") if finding is not None else None
        if band is not None and band not in SEVERITY_BANDS:
            raise ValueError(f"finding severity {band!r} is outside the closed vocabulary")
        days = (_date(row["decided_on"], "decided_on") - _date(row["opened_on"], "opened_on")).days  # type: ignore
        overall.append(days)
        by_band["null" if band is None else band].append(days)
    total = len(outcomes)
    return {
        "available": True,
        "target_id": admitted.get("target_id"),
        "outcomes": total,
        "by_disposition": by_disposition,
        "fix_rate": ratio(by_disposition[DeveloperDisposition.FIXED.value], total, interval=True),
        "rejected_false_rate": ratio(by_disposition[DeveloperDisposition.REJECTED_FALSE.value], total,
                                     interval=True),
        "accepted_risk": {"total": by_disposition[DeveloperDisposition.ACCEPTED_RISK.value], "expired": expired},
        "time_to_disposition_days": {**_timing(overall),
                                     "by_severity": {band: _timing(days) for band, days in by_band.items()}},
        "unmatched_outcomes": unmatched,
    }


# -------------------------------------------------------------------------------- audit sample

def _sample_sha256(lead_ids: Iterable[str]) -> str:
    return digest(sorted(lead_ids))


def export_audit_sample(leads: Iterable[Mapping[str, Any]], *, seed: str, size: int) -> dict[str, Any]:
    """A reproducible sample of removed leads (dismissed or no claim raised) for a person to label.

    Eligible leads are ordered by ``sha256(seed + "\\0" + lead_id)`` and the first ``size`` are taken,
    so the same seed and leads give the same sample in any input order, without ``random``.
    """
    if not isinstance(seed, str) or not seed:
        raise ValueError("an audit sample needs a non-empty seed")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_AUDIT_SAMPLE:
        raise ValueError("audit sample size must be between 1 and the bounded sample size")
    if isinstance(leads, (str, bytes, Mapping)) or not isinstance(leads, Iterable):
        raise ValueError("leads must be a sequence of lead records")
    eligible: dict[str, str] = {}
    seen: set[str] = set()
    for lead in leads:
        if len(seen) >= MAX_LEADS:
            raise ValueError("more leads than the bounded number per triage computation")
        if not isinstance(lead, Mapping):
            raise ValueError("a lead record must be an object")
        lead_id, disposition = _identifier(lead.get("lead_id"), "lead_id"), lead.get("disposition")
        if lead_id in seen:
            raise ValueError(f"leads repeat lead id {lead_id!r}")
        seen.add(lead_id)
        if disposition is not None and disposition not in DISPOSITIONS:
            raise ValueError(f"lead disposition {disposition!r} is outside the closed vocabulary")
        if disposition in AUDIT_ELIGIBLE_DISPOSITIONS:
            eligible[lead_id] = disposition
    ranked = sorted(eligible, key=lambda lead_id: (
        hashlib.sha256(f"{seed}\0{lead_id}".encode("utf-8")).hexdigest(), lead_id))
    chosen = sorted(ranked[:size])
    return {"schema": AUDIT_SAMPLE_SCHEMA, "seed": seed, "eligible": len(eligible), "requested": size,
            "sample": [{"lead_id": lead_id, "disposition": eligible[lead_id]} for lead_id in chosen],
            "sample_sha256": _sample_sha256(chosen)}


def admit_audit_labels(sample: Any, labels: Any) -> dict[str, dict[str, Any]]:
    """``lead_id -> label`` for every member of an exported audit sample.

    ``labels`` is a person's ``{lead_id: "true" | "false" | "unresolved"}``. A labelled id outside the
    sample is refused; a sample member without a label is ``unresolved``, never ``false``.
    """
    if not isinstance(sample, Mapping) or sample.get("schema") != AUDIT_SAMPLE_SCHEMA:
        raise ValueError("unsupported audit sample schema")
    members = sample.get("sample")
    if not isinstance(members, (list, tuple)) or not all(isinstance(item, Mapping) for item in members):
        raise ValueError("audit sample members are invalid")
    lead_ids = [_identifier(item.get("lead_id"), "lead_id") for item in members]
    if len(set(lead_ids)) != len(lead_ids) or sample.get("sample_sha256") != _sample_sha256(lead_ids):
        raise ValueError("audit sample does not match its recorded identity")
    if not isinstance(labels, Mapping):
        raise ValueError("audit labels must map a lead id to true, false or unresolved")
    outside = sorted(str(lead_id) for lead_id in set(labels) - set(lead_ids))
    if outside:
        raise ValueError(f"audit labels name leads outside the sample: {', '.join(outside[:5])}")
    for lead_id, outcome in labels.items():
        if not isinstance(outcome, str) or outcome not in _OUTCOMES:
            raise ValueError(f"audit label of {lead_id!r} is outside the closed vocabulary: {outcome!r}")
    return {lead_id: _label(str(labels.get(lead_id, LabelOutcome.UNRESOLVED.value)), LabelSource.AUDIT_SAMPLE)
            for lead_id in sorted(lead_ids)}


# -------------------------------------------------------------------------------------- merge

def _checked_label(subject_id: Any, value: Any) -> dict[str, Any]:
    _identifier(subject_id, "label subject id")
    _closed(value, LABEL_FIELDS, ("outcome", "source"), "label")
    outcome, source = value["outcome"], value["source"]
    severity, disposition = value.get("expected_severity"), value.get("disposition")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        raise ValueError(f"label outcome {outcome!r} is outside the closed vocabulary")
    if not isinstance(source, str) or source not in LABEL_AUTHORITY:
        raise ValueError(f"label source {source!r} is outside the closed vocabulary")
    if severity is not None and severity not in SEVERITY_BANDS:
        raise ValueError(f"label expected_severity {severity!r} is outside the closed vocabulary")
    if disposition is not None and disposition not in _DEVELOPER_DISPOSITIONS:
        raise ValueError(f"label disposition {disposition!r} is outside the closed vocabulary")
    return {"outcome": str(outcome), "source": str(source), "expected_severity": severity,
            "disposition": disposition}


def merge(*label_maps: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """One ``finding-labels/1`` label set from several ``subject id -> label`` maps.

    Per subject the decided label (``true`` or ``false``) of the highest-authority source is kept
    (``LABEL_AUTHORITY`` order); ``unresolved`` is kept only when no source decided, so it never
    overrides a decided label from a lower authority. Each lower-authority source that decided the
    opposite adds a conflict row ``{subject_id, kept_source, overridden_source}``. One source giving
    two different labels for a subject is refused: authority cannot order a source against itself.
    The result does not depend on the order of the maps.
    """
    rank = {source: position for position, source in enumerate(LABEL_AUTHORITY)}
    gathered: dict[str, dict[str, dict[str, Any]]] = {}
    for label_map in label_maps:
        if not isinstance(label_map, Mapping):
            raise ValueError("a label map must map a subject id to a label")
        for subject_id, value in label_map.items():
            label = _checked_label(subject_id, value)
            previous = gathered.setdefault(subject_id, {}).setdefault(label["source"], label)
            if previous != label:
                raise ValueError(f"source {label['source']} gives two different labels for {subject_id!r}")
    labels: dict[str, dict[str, Any]] = {}
    conflicts: list[dict[str, str]] = []
    for subject_id in sorted(gathered):
        ordered = sorted(gathered[subject_id].values(), key=lambda label: rank[label["source"]])
        decided = [label for label in ordered if label["outcome"] in _DECIDED]
        kept = decided[0] if decided else ordered[0]
        labels[subject_id] = kept
        conflicts.extend({"subject_id": subject_id, "kept_source": kept["source"], "overridden_source": other["source"]}
                         for other in decided[1:] if other["outcome"] != kept["outcome"])
    by_source = dict.fromkeys(LABEL_AUTHORITY, 0)
    by_outcome = dict.fromkeys(_OUTCOMES, 0)
    for label in labels.values():
        by_source[label["source"]] += 1
        by_outcome[label["outcome"]] += 1
    return {"schema": LABEL_SET_SCHEMA, "labels": labels,
            "conflicts": sorted(conflicts, key=lambda row: (row["subject_id"], row["kept_source"],
                                                            row["overridden_source"])),
            "counts": {"labels": len(labels), "conflicts": len(conflicts), "by_source": by_source,
                       "by_outcome": by_outcome}}


__all__ = [
    "AUDIT_ELIGIBLE_DISPOSITIONS", "LABEL_FIELDS", "MAX_AUDIT_SAMPLE", "MAX_OUTCOMES", "OUTCOME_FIELDS",
    "OUTCOME_FILE_FIELDS", "admit_audit_labels", "admit_outcomes", "export_audit_sample", "key_case_hits",
    "key_entries_at", "label_findings_from_key", "merge", "outcome_metrics",
]
