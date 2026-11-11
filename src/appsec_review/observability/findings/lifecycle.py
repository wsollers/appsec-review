"""Lifecycle of every prior finding in a new run (finding-metrics.md sections 4.2 and 5.6).

Doctrine:

* Absence is not evidence. A prior finding that the new run did not match is ``not_covered``,
  ``not_redetected`` or a ``fix_candidate``; none of them is progress. Only ``fixed``, which
  exists solely as the admitted outcome of a targeted re-check (``recheck``), counts as a fix.
* Missing information never claims progress: unknown coverage is ``not_covered``, an unknown
  content hash is ``not_redetected`` with ``change_known: false``.
* Null is not zero: without a named prior run the whole section is unavailable.

Everything here is pure: two ``finding-snapshot/1`` documents in, plain sorted dictionaries out,
inputs never mutated.
"""
from __future__ import annotations

from collections.abc import Mapping
import copy
import statistics
from typing import Any

from .contracts import (ACTIONABLE_BANDS, MAX_FINDINGS, SEVERITY_BANDS, SNAPSHOT_STAGES, LifecycleState, MatchTier,
                        check_snapshot, counts, is_sha256, normalize_cwe, normalize_path, ratio, unavailable)
from .identity import match_findings

PRIOR_STATES = tuple(state.value for state in (
    LifecycleState.PERSISTING, LifecycleState.NOT_COVERED, LifecycleState.NOT_REDETECTED,
    LifecycleState.FIX_CANDIDATE, LifecycleState.FIXED, LifecycleState.STILL_PRESENT))
CURRENT_STATES = tuple(state.value for state in (
    LifecycleState.NEW, LifecycleState.REGRESSED, LifecycleState.PERSISTING))
RECHECKABLE_STATES = (LifecycleState.FIX_CANDIDATE.value, LifecycleState.NOT_REDETECTED.value)
RECHECK_OUTCOMES = ("fixed", "still_present", "insufficient_evidence")
LIFECYCLE_FIELDS = ("prior_run_id", "current_run_id", "target_id", "stage", "prior", "current")
PRIOR_ROW_FIELDS = ("finding_id", "fingerprint_exact", "state", "match_tier", "matched_finding_id", "reason",
                    "change_known", "severity", "weakness_cwe")
CURRENT_ROW_FIELDS = ("finding_id", "fingerprint_exact", "state", "severity")
_TIERS = tuple(tier.value for tier in MatchTier)


def _units(snapshot: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    units = snapshot[name]
    if units is not None and not isinstance(units, Mapping):
        raise ValueError(f"finding snapshot {name} must be an object or null")
    return units


def _unmatched_prior(finding: Mapping[str, Any], prior: Mapping[str, Any], current: Mapping[str, Any]
                     ) -> tuple[str, str | None, bool | None]:
    """``(state, reason, change_known)`` of a prior finding the new run did not match."""
    reviewed_now, reviewed_before = _units(current, "reviewed_units"), _units(prior, "reviewed_units")
    if reviewed_now is None:
        return LifecycleState.NOT_COVERED.value, "coverage_unknown", None
    paths = sorted({normalize_path(location["path"]) for location in finding["locations"]})
    absent = [path for path in paths if path not in reviewed_now]
    if absent:
        residual = _units(current, "unreviewed_units") or {}
        named = [str(residual[path]) for path in absent if residual.get(path)]
        return LifecycleState.NOT_COVERED.value, named[0] if named else "unit_not_reviewed", None
    known = 0
    for path in paths:
        before = None if reviewed_before is None else reviewed_before.get(path)
        now = reviewed_now[path]
        if before is None or now is None:
            continue
        if before != now:
            return LifecycleState.FIX_CANDIDATE.value, None, True
        known += 1
    return LifecycleState.NOT_REDETECTED.value, None, known == len(paths)


def classify(prior: Mapping[str, Any], current: Mapping[str, Any], *,
             previously_fixed: frozenset[str] = frozenset()) -> dict[str, Any]:
    """The lifecycle of ``prior``'s findings in ``current`` and of ``current``'s findings against it.

    ``previously_fixed`` holds fingerprint keys the history records as ``fixed``; an unmatched
    current finding whose ``exact`` or ``relocated`` key is among them is ``regressed``.
    """
    prior, current = check_snapshot(prior), check_snapshot(current)
    if prior["target_id"] != current["target_id"]:
        raise ValueError("lifecycle compares snapshots of one target")
    if prior["stage"] != current["stage"]:
        raise ValueError("lifecycle compares snapshots of one stage")
    if prior["run_id"] == current["run_id"]:
        raise ValueError("lifecycle needs a prior run distinct from the current run")
    if isinstance(previously_fixed, (str, bytes)) or not all(isinstance(key, str) for key in previously_fixed):
        raise ValueError("previously_fixed must be a set of fingerprint keys")
    fixed_keys = frozenset(previously_fixed)
    matches = match_findings(prior["findings"], current["findings"])
    prior_rows = []
    for finding in sorted(prior["findings"], key=lambda item: item["finding_id"]):
        row = {"finding_id": finding["finding_id"], "fingerprint_exact": finding["fingerprint"]["exact"],
               "state": LifecycleState.PERSISTING.value, "match_tier": None, "matched_finding_id": None,
               "reason": None, "change_known": None, "severity": finding.get("severity"),
               "weakness_cwe": finding.get("weakness_cwe")}
        match = matches.get(finding["finding_id"])
        if match is not None:
            row["matched_finding_id"], row["match_tier"] = match[0], match[1].value
        else:
            row["state"], row["reason"], row["change_known"] = _unmatched_prior(finding, prior, current)
        prior_rows.append(row)
    matched_now = {current_id for current_id, _ in matches.values()}
    current_rows = []
    for finding in sorted(current["findings"], key=lambda item: item["finding_id"]):
        identity = finding["fingerprint"]
        state = (LifecycleState.PERSISTING if finding["finding_id"] in matched_now
                 else LifecycleState.REGRESSED if {identity["exact"], identity["relocated"]} & fixed_keys
                 else LifecycleState.NEW)
        current_rows.append({"finding_id": finding["finding_id"], "fingerprint_exact": identity["exact"],
                             "state": state.value, "severity": finding.get("severity")})
    return {"prior_run_id": prior["run_id"], "current_run_id": current["run_id"], "target_id": prior["target_id"],
            "stage": prior["stage"], "prior": prior_rows, "current": current_rows}


def _name(value: Any, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"lifecycle {name} must be a non-empty string")


def _rows(value: Any, side: str, fields: tuple[str, ...], states: tuple[str, ...]) -> None:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise ValueError(f"lifecycle {side} rows must be a bounded list")
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, Mapping) or set(row) != set(fields):
            raise ValueError(f"lifecycle {side} row has missing or unknown fields")
        _name(row["finding_id"], "finding_id")
        if row["finding_id"] in seen:
            raise ValueError(f"lifecycle {side} rows repeat a finding_id")
        seen.add(row["finding_id"])
        if not is_sha256(row["fingerprint_exact"]):
            raise ValueError("lifecycle fingerprint_exact must be a SHA-256")
        if row["state"] not in states:
            raise ValueError(f"lifecycle {side} state {row['state']!r} is outside its closed vocabulary")
        if row["severity"] is not None and row["severity"] not in SEVERITY_BANDS:
            raise ValueError("lifecycle severity is outside its closed vocabulary")


def check_lifecycle(value: Any) -> dict[str, Any]:
    """A lifecycle document's shape; raises ``ValueError`` for anything ``classify`` could not have produced."""
    if not isinstance(value, Mapping) or set(value) != set(LIFECYCLE_FIELDS):
        raise ValueError("lifecycle has missing or unknown fields")
    for name in ("prior_run_id", "current_run_id", "target_id"):
        _name(value[name], name)
    if value["prior_run_id"] == value["current_run_id"]:
        raise ValueError("lifecycle needs a prior run distinct from the current run")
    if value["stage"] not in SNAPSHOT_STAGES:
        raise ValueError("lifecycle stage is outside its closed vocabulary")
    _rows(value["prior"], "prior", PRIOR_ROW_FIELDS, PRIOR_STATES)
    _rows(value["current"], "current", CURRENT_ROW_FIELDS, CURRENT_STATES)
    for row in value["prior"]:
        persisting = row["state"] == LifecycleState.PERSISTING.value
        if persisting != (row["match_tier"] is not None) or persisting != (row["matched_finding_id"] is not None):
            raise ValueError("lifecycle match fields belong to persisting rows only")
        if row["match_tier"] is not None and row["match_tier"] not in _TIERS:
            raise ValueError("lifecycle match_tier is outside its closed vocabulary")
        if row["matched_finding_id"] is not None:
            _name(row["matched_finding_id"], "matched_finding_id")
        if row["reason"] is not None:
            _name(row["reason"], "reason")
        if row["change_known"] is not None and not isinstance(row["change_known"], bool):
            raise ValueError("lifecycle change_known must be a Boolean or null")
        if row["weakness_cwe"] is not None and normalize_cwe(row["weakness_cwe"]) != row["weakness_cwe"]:
            raise ValueError("lifecycle weakness_cwe must be a normalized CWE or null")
    return copy.deepcopy(dict(value))


def apply_rechecks(lifecycle: Mapping[str, Any], results: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """A new lifecycle in which admitted re-check outcomes move re-checkable prior rows.

    ``fix_candidate`` and ``not_redetected`` rows move to ``fixed`` or ``still_present``;
    ``insufficient_evidence`` leaves the row as it was. A result for any other row is refused.
    """
    updated = check_lifecycle(lifecycle)
    if not isinstance(results, Mapping):
        raise ValueError("recheck results must map a finding id to its admitted result")
    rows = {row["finding_id"]: row for row in updated["prior"]}
    for finding_id in sorted(results, key=str):
        result = results[finding_id]
        outcome = result.get("outcome") if isinstance(result, Mapping) else None
        if outcome not in RECHECK_OUTCOMES:
            raise ValueError("recheck result outcome is outside its closed vocabulary")
        row = rows.get(finding_id) if isinstance(finding_id, str) else None
        if row is None:
            raise ValueError("recheck result names a finding the lifecycle does not hold")
        if row["state"] not in RECHECKABLE_STATES:
            raise ValueError(f"recheck result names a finding in state {row['state']!r}")
        if outcome != "insufficient_evidence":
            row["state"] = outcome
    return updated


def _median_age(rows: list[Mapping[str, Any]], ages: Mapping[str, int] | None) -> int | float | None:
    if ages is None:
        return None
    if not isinstance(ages, Mapping):
        raise ValueError("ages must map a fingerprint key to a count of runs")
    seen = []
    for row in rows:
        age = ages.get(row["fingerprint_exact"])
        if age is None:
            return None   # an age the history cannot supply is unknown, never a shorter median
        if isinstance(age, bool) or not isinstance(age, int) or age < 1:
            raise ValueError("a finding age is a positive count of runs")
        seen.append(age)
    return statistics.median(seen) if seen else None


def metrics(lifecycle: Mapping[str, Any] | None, *, ages: Mapping[str, int] | None = None) -> dict[str, Any]:
    """The scorecard's lifecycle section; unavailable, never zero, without a named prior run.

    State tables come from ``contracts.counts`` and so carry its ``"null"`` row (always zero here).
    ``median_age_of_persisting_actionable`` is ``None`` when ``ages`` is absent, when no high or
    critical finding persists, or when ``ages`` lacks one of them.
    """
    if lifecycle is None:
        return unavailable("no_prior_run")
    lifecycle = check_lifecycle(lifecycle)
    prior, current = lifecycle["prior"], lifecycle["current"]
    actionable = [row for row in prior if row["severity"] in ACTIONABLE_BANDS]
    states = counts((row["state"] for row in prior), PRIOR_STATES)
    current_states = counts((row["state"] for row in current), CURRENT_STATES)
    persisting = LifecycleState.PERSISTING.value
    return {
        "available": True,
        "prior_run_id": lifecycle["prior_run_id"],
        "current_run_id": lifecycle["current_run_id"],
        "prior_states": states,
        "current_states": current_states,
        "fix_rate": ratio(states[LifecycleState.FIXED.value], len(prior)),
        "not_redetected_rate": ratio(states[LifecycleState.NOT_REDETECTED.value], len(prior)),
        "not_covered_rate": ratio(states[LifecycleState.NOT_COVERED.value], len(prior)),
        "change_unknown": sum(1 for row in prior if row["change_known"] is False),
        "match_tiers": {tier: sum(1 for row in prior if row["match_tier"] == tier) for tier in _TIERS},
        "actionable": counts((row["state"] for row in actionable), PRIOR_STATES),
        "introduced": current_states[LifecycleState.NEW.value],
        "median_age_of_persisting_actionable": _median_age(
            [row for row in actionable if row["state"] == persisting], ages),
    }


__all__ = ["CURRENT_ROW_FIELDS", "CURRENT_STATES", "LIFECYCLE_FIELDS", "PRIOR_ROW_FIELDS", "PRIOR_STATES",
           "RECHECKABLE_STATES", "RECHECK_OUTCOMES", "apply_rechecks", "check_lifecycle", "classify", "metrics"]
