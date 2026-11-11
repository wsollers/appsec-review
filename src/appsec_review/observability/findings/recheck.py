"""Targeted fix re-check, model-free part (finding-metrics.md section 4.2, T-061).

Discovery is not repeatable enough to treat a finding's absence as a fix. For each prior finding
the new run left as ``fix_candidate`` or ``not_redetected`` this module builds one bounded
re-check request, and it admits the answer.

Doctrine:

* This module never calls a model. The transport is injected by the caller, and a transport that
  declares itself ``live`` runs only when the caller says ``live=True``.
* A re-check answer is untrusted data. It is validated against a closed shape, its free-text
  reason is never stored (only its SHA-256), and transport failures are recorded by exception
  class alone.
* A claim needs resolving evidence. ``fixed`` is admitted only with a citation into a reviewed
  unit whose content is known to have changed since the prior run (or is new); ``still_present``
  only with a citation into a reviewed unit. Anything else is ``insufficient_evidence``, which
  never moves a lifecycle state.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
import copy
import hashlib
from typing import Any

from .contracts import ACTIONABLE_BANDS, check_snapshot, normalize_path, ratio
from .lifecycle import RECHECKABLE_STATES, RECHECK_OUTCOMES, check_lifecycle

REQUEST_SCHEMA = "appsec-review/fix-recheck-request/1"
DEFAULT_MAX_REQUESTS = 200
MAX_REQUESTS = 1000
MAX_CITATIONS = 16
MAX_REASON_CHARS = 2000
RESULT_FIELDS = ("finding_id", "outcome", "cited", "reason")
CITATION_FIELDS = ("path", "start_line", "end_line")
_LOCATION_FIELDS = ("path", "start_line", "end_line", "function", "code")
_INSUFFICIENT = "insufficient_evidence"


def build_requests(lifecycle: Mapping[str, Any], prior_snapshot: Mapping[str, Any], *,
                   max_requests: int = DEFAULT_MAX_REQUESTS) -> dict[str, Any]:
    """``{"requests", "eligible", "truncated"}``: one request per re-checkable prior row.

    High and critical findings come first, then ``finding_id`` order; the list is cut at
    ``max_requests`` (1..``MAX_REQUESTS``) and ``truncated`` counts what was left out.
    """
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= MAX_REQUESTS:
        raise ValueError(f"max_requests must be an integer from 1 to {MAX_REQUESTS}")
    lifecycle, prior_snapshot = check_lifecycle(lifecycle), check_snapshot(prior_snapshot)
    if (prior_snapshot["run_id"], prior_snapshot["target_id"], prior_snapshot["stage"]) != (
            lifecycle["prior_run_id"], lifecycle["target_id"], lifecycle["stage"]):
        raise ValueError("the prior snapshot is not the lifecycle's prior run")
    findings = {finding["finding_id"]: finding for finding in prior_snapshot["findings"]}
    eligible = sorted((row for row in lifecycle["prior"] if row["state"] in RECHECKABLE_STATES),
                      key=lambda row: (row["severity"] not in ACTIONABLE_BANDS, row["finding_id"]))
    requests = []
    for row in eligible[:max_requests]:
        finding = findings.get(row["finding_id"])
        if finding is None or finding["fingerprint"]["exact"] != row["fingerprint_exact"]:
            raise ValueError("the lifecycle names a finding the prior snapshot does not hold")
        requests.append({
            "schema": REQUEST_SCHEMA, "finding_id": row["finding_id"], "fingerprint_exact": row["fingerprint_exact"],
            "lifecycle_state": row["state"], "weakness_cwe": finding.get("weakness_cwe"),
            "security_predicate": finding.get("security_predicate"), "severity": finding.get("severity"),
            "prior_run_id": lifecycle["prior_run_id"], "current_run_id": lifecycle["current_run_id"],
            "prior_locations": [{name: location.get(name) for name in _LOCATION_FIELDS}
                                for location in finding["locations"]]})
    return {"requests": requests, "eligible": len(eligible), "truncated": len(eligible) - len(requests)}


def _request(request: Any, prior: Mapping[str, Any], current: Mapping[str, Any]) -> str:
    if (not isinstance(request, Mapping) or request.get("schema") != REQUEST_SCHEMA
            or not isinstance(request.get("finding_id"), str) or not request["finding_id"]):
        raise ValueError("unsupported fix re-check request")
    if request.get("prior_run_id") != prior["run_id"] or request.get("current_run_id") != current["run_id"]:
        raise ValueError("the re-check request does not belong to these snapshots")
    return request["finding_id"]


def _snapshots(prior_snapshot: Any, current_snapshot: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    prior, current = check_snapshot(prior_snapshot), check_snapshot(current_snapshot)
    if prior["target_id"] != current["target_id"] or prior["run_id"] == current["run_id"]:
        raise ValueError("a re-check compares two runs of one target")
    for snapshot in (prior, current):
        for name in ("reviewed_units", "unreviewed_units"):
            if snapshot[name] is not None and not isinstance(snapshot[name], Mapping):
                raise ValueError(f"finding snapshot {name} must be an object or null")
    return prior, current


def _citations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_CITATIONS:
        raise ValueError(f"a re-check result cites a list of at most {MAX_CITATIONS} locations")
    cited = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) - set(CITATION_FIELDS) or "start_line" not in item:
            raise ValueError("a re-check citation has missing or unknown fields")
        start, end = item["start_line"], item.get("end_line", item["start_line"])
        for line in (start, end):
            if isinstance(line, bool) or not isinstance(line, int) or line < 1:
                raise ValueError("citation lines must be positive integers")
        if end < start:
            raise ValueError("citation end_line precedes start_line")
        cited.add((normalize_path(item.get("path")), start, end))
    return [{"path": path, "start_line": start, "end_line": end} for path, start, end in sorted(cited)]


def _changed(path: str, prior: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    """Whether ``path`` is reviewed now with known content that is new or differs from the prior run."""
    now = (current["reviewed_units"] or {}).get(path)
    if now is None or prior["reviewed_units"] is None:
        return False
    if path not in prior["reviewed_units"]:
        return path not in (prior["unreviewed_units"] or {})   # new, unless it existed unreviewed
    before = prior["reviewed_units"][path]
    return before is not None and before != now


def _admit(finding_id: str, result: Any, prior: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(result, Mapping):
        raise ValueError("a re-check result must be an object")
    unknown = set(result) - set(RESULT_FIELDS)
    if unknown or "finding_id" not in result or "outcome" not in result:
        raise ValueError("a re-check result has missing or unknown fields")
    if result["finding_id"] != finding_id:
        raise ValueError("a re-check result names another finding")
    claimed = result["outcome"]
    if not isinstance(claimed, str) or claimed not in RECHECK_OUTCOMES:
        raise ValueError("a re-check outcome is outside its closed vocabulary")
    reason = result.get("reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > MAX_REASON_CHARS):
        raise ValueError(f"a re-check reason is a string of at most {MAX_REASON_CHARS} characters")
    cited = _citations(result.get("cited", ()))
    outcome, downgrade = claimed, None
    if claimed == "fixed" and not any(_changed(item["path"], prior, current) for item in cited):
        outcome, downgrade = _INSUFFICIENT, "fixed_without_changed_citation"
    elif claimed == "still_present" and not any(
            item["path"] in (current["reviewed_units"] or {}) for item in cited):
        outcome, downgrade = _INSUFFICIENT, "still_present_without_citation"
    return {"finding_id": finding_id, "outcome": outcome, "claimed_outcome": claimed, "downgrade_reason": downgrade,
            "cited": cited,
            "reason_sha256": None if reason is None else hashlib.sha256(reason.encode("utf-8")).hexdigest()}


def admit_result(request: Mapping[str, Any], result: Mapping[str, Any], *, prior_snapshot: Mapping[str, Any],
                 current_snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one untrusted re-check result and admit, or downgrade, its outcome.

    Returns ``{"finding_id", "outcome", "claimed_outcome", "downgrade_reason", "cited",
    "reason_sha256"}``. The free-text reason is never returned.
    """
    prior, current = _snapshots(prior_snapshot, current_snapshot)
    return _admit(_request(request, prior, current), result, prior, current)


def run_rechecks(requests: Iterable[Mapping[str, Any]], transport: Callable[[dict[str, Any]], Mapping[str, Any]],
                 *, prior_snapshot: Mapping[str, Any], current_snapshot: Mapping[str, Any],
                 live: bool = False) -> dict[str, Any]:
    """Send each request through the injected ``transport`` and admit what comes back.

    ``{"results": {finding_id: row}, "counts": {...}}``, suitable for ``lifecycle.apply_rechecks``.
    A transport ``OSError``, ``TimeoutError`` or ``ValueError``, or an invalid result, becomes
    ``{"finding_id", "outcome": "insufficient_evidence", "error_class"}`` with no exception text.
    ``counts["insufficient_evidence"]`` includes those rows; ``counts["errors"]`` counts them alone.
    """
    if transport is None or not callable(transport):
        raise ValueError("a recheck transport must be supplied; this module never calls a model")
    if not isinstance(live, bool):
        raise ValueError("live must be a Boolean")
    if getattr(transport, "live", False) is True and not live:
        raise ValueError("a live recheck transport runs only with live=True")
    prior, current = _snapshots(prior_snapshot, current_snapshot)
    requests = list(requests)
    if len(requests) > MAX_REQUESTS:
        raise ValueError(f"a re-check batch holds at most {MAX_REQUESTS} requests")
    ids = [_request(request, prior, current) for request in requests]
    if len(ids) != len(set(ids)):
        raise ValueError("a re-check batch repeats a finding_id")
    results: dict[str, dict[str, Any]] = {}
    for finding_id, request in zip(ids, requests):
        try:
            results[finding_id] = _admit(finding_id, transport(copy.deepcopy(dict(request))), prior, current)
        except (OSError, TimeoutError, ValueError) as error:
            results[finding_id] = {"finding_id": finding_id, "outcome": _INSUFFICIENT,
                                   "error_class": type(error).__name__}
    table = {outcome: sum(1 for row in results.values() if row["outcome"] == outcome) for outcome in RECHECK_OUTCOMES}
    table["errors"] = sum(1 for row in results.values() if "error_class" in row)
    return {"results": dict(sorted(results.items())), "counts": table}


def score_fix_pairs(expected: Mapping[str, str], results: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Score re-check outcomes against a keyed fix-pair corpus.

    ``expected`` maps a finding id to ``fixed`` (post-fix revision) or ``still_present`` (pre-fix
    revision). A finding with no result, or with ``insufficient_evidence``, is ``undecided``.
    Proportions are over independent key cases and carry Wilson intervals.
    """
    if not isinstance(expected, Mapping) or not isinstance(results, Mapping):
        raise ValueError("fix-pair scoring needs an expected mapping and a results mapping")
    if set(results) - set(expected):
        raise ValueError("a re-check result names a finding outside the fix-pair key")
    table = {"correct_fixed": 0, "correct_still_present": 0, "false_fix": 0, "missed_fix": 0, "undecided": 0}
    wanted = {"fixed": 0, "still_present": 0}
    for finding_id in sorted(expected, key=str):
        want = expected[finding_id]
        if want not in wanted:
            raise ValueError("a fix-pair key expects fixed or still_present")
        wanted[want] += 1
        result = results.get(finding_id)
        got = _INSUFFICIENT if result is None else result.get("outcome") if isinstance(result, Mapping) else None
        if got not in RECHECK_OUTCOMES:
            raise ValueError("recheck result outcome is outside its closed vocabulary")
        if got == _INSUFFICIENT:
            table["undecided"] += 1
        elif got == want:
            table[f"correct_{want}"] += 1
        else:
            table["false_fix" if got == "fixed" else "missed_fix"] += 1
    total = len(expected)
    return {
        **table, "expected_fixed": wanted["fixed"], "expected_still_present": wanted["still_present"], "total": total,
        "fix_recall": ratio(table["correct_fixed"], wanted["fixed"], interval=True),
        "false_fix_rate": ratio(table["false_fix"], wanted["still_present"], interval=True),
        "still_present_recall": ratio(table["correct_still_present"], wanted["still_present"], interval=True),
        "undecided_rate": ratio(table["undecided"], total, interval=True),
    }


__all__ = ["CITATION_FIELDS", "DEFAULT_MAX_REQUESTS", "MAX_CITATIONS", "MAX_REASON_CHARS", "MAX_REQUESTS",
           "REQUEST_SCHEMA", "RESULT_FIELDS", "admit_result", "build_requests", "run_rechecks", "score_fix_pairs"]
