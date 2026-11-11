"""Stability of repeated runs of one corpus revision (finding-metrics.md section 5.5, T-065).

Doctrine:

* Stability is not truth. A stable false finding is stable, so nothing here stands in for
  precision, and a stability number is only ever shown beside one.
* Repeated findings are not independent evidence. Adjacent and pairwise run comparisons share
  runs, so they carry **no** confidence interval.
* The per-defect detection rate over repeated runs is a binomial proportion over independent runs,
  so it does carry a Wilson interval.
* Incomparable runs are reported ``incomparable``; they are never silently compared, and an unknown
  identity hash is not equal to anything.
* A missing input is ``unavailable(reason)`` or ``None``, never zero. Empty against non-empty is a
  measured Jaccard of 0; two empty sets are ``both_empty`` (not applicable).
* Outputs are sorted and deterministic, inputs are never mutated, and nothing reads a clock, a
  random source, a run directory or a model.

``experiment_document`` is the adapter that registers real runs as launches and completions of the
existing offline experiments domain (docs/operations/glasswing-experiments.md); it never invents an
identity hash, a CWE or a usage figure.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from itertools import combinations
from typing import Any

from appsec_review.observability.experiments.contracts import INPUT_SCHEMA, NORMALIZER, load_experiment

from .contracts import check_snapshot, digest, is_actionable, is_published, is_sha256, ratio, unavailable

MAX_SERIES_RUNS = 512              # the experiments domain's launch bound
MAX_DETECTION_RUNS = 1000
MAX_DEFECTS = 10_000
MINIMUM_RUNS_RECOMMENDED = 5
SUBSETS = ("actionable", "all", "published")
COMPARISON_FIELDS = ("target_id", "source_revision", "stage", "configuration_sha256", "guidance_sha256",
                     "model_sha256")
EXPERIMENT_STAGE = "verified"      # the experiments stage a published-stage snapshot is registered under

_IDENTITY_HASHES = ("configuration_sha256", "guidance_sha256", "model_sha256")
_LAUNCH_HASHES = ("scope_sha256", "agent_sha256", "tools_sha256", "decoding_sha256")
_LAUNCH_REQUIRED = ("run_index", "started_at", "completed_at", "raw_artifact_sha256", "status",
                    *_LAUNCH_HASHES, "context_condition", "positive_event")
_LAUNCH_OPTIONAL = ("error_ids", "usage", *_IDENTITY_HASHES)
_STATUSES = ("cancelled", "complete", "failed", "partial")
_CONTEXTS = ("build_context", "source_only")
_UNAVAILABLE_USAGE = {"input_tokens": None, "output_tokens": None, "wall_seconds": None, "cost": None,
                      "currency": None, "cost_kind": "unavailable", "evidence_ids": [],
                      "missing_reason": "usage_not_supplied"}
_SELECT = {"all": lambda finding: True, "published": is_published, "actionable": is_actionable}


# ------------------------------------------------------------------------------- comparability

def comparison_key(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """The frozen identity two snapshots must share to be comparable."""
    return {name: snapshot[name] for name in COMPARISON_FIELDS}


def comparable(a: Mapping[str, Any], b: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """``(comparable, differing field names)``; a ``None`` identity on either side differs."""
    left, right = comparison_key(a), comparison_key(b)
    differing = [name for name in COMPARISON_FIELDS
                 if left[name] is None or right[name] is None or left[name] != right[name]]
    return not differing, differing


def _admit(snapshots: Any, maximum: int = MAX_SERIES_RUNS) -> list[dict[str, Any]]:
    if isinstance(snapshots, (str, bytes, Mapping)) or not isinstance(snapshots, Sequence):
        raise ValueError("snapshots must be a sequence of finding snapshots in launch order")
    if len(snapshots) > maximum:
        raise ValueError(f"a stability series holds at most {maximum} runs")
    rows = [check_snapshot(item) for item in snapshots]
    run_ids = [row["run_id"] for row in rows]
    if len(set(run_ids)) != len(run_ids):
        raise ValueError("a stability series repeats a run_id; a repeated run is not a new observation")
    return rows


def _mutual_difference(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    """Fields on which the runs are not all mutually comparable (empty when they are)."""
    differing: set[str] = set()
    for other in rows[1:]:
        differing.update(comparable(rows[0], other)[1])
    if rows:
        differing.update(comparable(rows[0], rows[0])[1])    # an unknown identity is not equal to itself
    return [name for name in COMPARISON_FIELDS if name in differing]


def _mean(values: Sequence[float]) -> float | None:
    return round(sum(values) / len(values), 6) if values else None


# -------------------------------------------------------------------------------------- series

def series(snapshots: Sequence[Mapping[str, Any]], *, subset: str = "all") -> dict[str, Any]:
    """Adjacent and pairwise set stability of repeated runs, in launch order.

    The set of a run is the ``exact`` fingerprints of its findings in ``subset``: ``"all"``,
    ``"published"`` (confirmed or supported) or ``"actionable"`` (confirmed high or critical). No
    statistic here carries an interval: the pairs share runs.
    """
    if subset not in SUBSETS:
        raise ValueError(f"unknown stability subset {subset!r}; one of {', '.join(SUBSETS)}")
    rows = _admit(snapshots)
    if len(rows) < 2:
        return unavailable("fewer_than_two_runs")
    select = _SELECT[subset]
    sets = [{finding["fingerprint"]["exact"] for finding in row["findings"] if select(finding)} for row in rows]
    adjacent: list[dict[str, Any]] = []
    for index in range(1, len(rows)):
        previous, current = sets[index - 1], sets[index]
        same, differing = comparable(rows[index - 1], rows[index])
        entry: dict[str, Any] = {
            "previous_run_id": rows[index - 1]["run_id"], "run_id": rows[index]["run_id"],
            "status": "valid", "differing": differing, "shared": None, "union": None,
            "jaccard": ratio(None, None, reason="incomparable"),
            "retention": ratio(None, None, reason="incomparable"),
            "new_to_previous": None, "dropped": None}
        if not same:
            entry["status"] = "incomparable"
        else:
            shared, union = len(previous & current), len(previous | current)
            entry.update(status="valid" if union else "both_empty", shared=shared, union=union,
                         jaccard=ratio(shared, union), retention=ratio(shared, len(previous)),
                         new_to_previous=len(current - previous), dropped=len(previous - current))
        adjacent.append(entry)
    adjacent_values = [entry["jaccard"]["value"] for entry in adjacent if entry["status"] == "valid"]
    pair_values: list[float] = []
    both_empty = incomparable = 0
    for left, right in combinations(range(len(rows)), 2):
        if not comparable(rows[left], rows[right])[0]:
            incomparable += 1
        elif not sets[left] and not sets[right]:
            both_empty += 1
        else:
            pair_values.append(len(sets[left] & sets[right]) / len(sets[left] | sets[right]))
    difference = _mutual_difference(rows)
    recurrence = None
    if not difference:
        recurrence = [{"fingerprint": key, "runs": sum(key in items for items in sets),
                       "frequency": ratio(sum(key in items for items in sets), len(rows))}
                      for key in sorted(set().union(*sets))]
    return {
        "available": True, "subset": subset, "unit": "finding_fingerprint_exact",
        "interval": "none_overlapping_run_pairs", "counterweight": "stability_is_not_precision",
        "runs": [{"run_id": row["run_id"], "set_size": len(items)} for row, items in zip(rows, sets)],
        "adjacent": adjacent,
        "mean_adjacent_jaccard": {"value": _mean(adjacent_values), "valid_count": len(adjacent_values),
                                  "total_count": len(adjacent)},
        "mean_pairwise": {"value": _mean(pair_values), "valid_count": len(pair_values),
                          "both_empty_pairs": both_empty, "incomparable_pairs": incomparable,
                          "total_count": len(rows) * (len(rows) - 1) // 2},
        "mutually_comparable": not difference,
        "recurrence": recurrence,
        "recurrence_reason": None if not difference else "runs_not_mutually_comparable",
    }


# ------------------------------------------------------------------------------------ flapping

def flapping(snapshots: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Findings whose severity band or disposition differs between mutually comparable runs."""
    rows = _admit(snapshots)
    if len(rows) < 2:
        return unavailable("fewer_than_two_runs")
    difference = _mutual_difference(rows)
    if difference:
        return {"available": True, "status": "incomparable", "differing": difference}
    present: dict[str, int] = {}
    severities: dict[str, set[str]] = {}
    states: dict[str, set[str]] = {}
    for row in rows:
        seen: set[str] = set()
        for finding in row["findings"]:
            key = finding["fingerprint"]["exact"]
            seen.add(key)
            severities.setdefault(key, set()).add("null" if finding.get("severity") is None
                                                  else str(finding["severity"]))
            states.setdefault(key, set()).add(str(finding["state"]))
        for key in seen:
            present[key] = present.get(key, 0) + 1
    recurring = sorted(key for key, count in present.items() if count >= 2)
    severity_rows = [{"fingerprint": key, "severities": sorted(severities[key])}
                     for key in recurring if len(severities[key]) > 1]
    state_rows = [{"fingerprint": key, "states": sorted(states[key])} for key in recurring if len(states[key]) > 1]
    flapped = {row["fingerprint"] for row in severity_rows} | {row["fingerprint"] for row in state_rows}
    return {
        "available": True, "status": "measured", "runs": len(rows), "unit": "finding_fingerprint_exact",
        "interval": "none_overlapping_run_pairs",
        "recurring_fingerprints": len(recurring),
        "severity_flapping": severity_rows, "severity_flapping_count": len(severity_rows),
        "state_flapping": state_rows, "state_flapping_count": len(state_rows),
        "flapping_share": ratio(len(flapped), len(recurring)),
    }


# ----------------------------------------------------------------------------- detection rates

def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\n" in value or "\r" in value:
        raise ValueError(f"{name} must be a short single-line string")
    return value


def detection_rates(runs: Sequence[Mapping[str, Any]], defect_ids: Iterable[str]) -> dict[str, Any]:
    """Per-defect detection rate over independent repeated runs, each with a Wilson interval.

    ``runs`` is ``[{"run_id", "detected": [defect ids]}]``. No run or no defect is unavailable,
    never a rate of zero. ``mean_single_run_recall`` is a mean of per-run recalls and carries no
    interval.
    """
    defects = [_identifier(item, "defect id") for item in defect_ids]
    if len(defects) > MAX_DEFECTS:
        raise ValueError(f"detection rates cover at most {MAX_DEFECTS} defects")
    if len(set(defects)) != len(defects):
        raise ValueError("defect ids repeat")
    if isinstance(runs, (str, bytes, Mapping)) or not isinstance(runs, Sequence):
        raise ValueError("runs must be a sequence of run records")
    if len(runs) > MAX_DETECTION_RUNS:
        raise ValueError(f"detection rates cover at most {MAX_DETECTION_RUNS} runs")
    known = set(defects)
    detections = {name: 0 for name in defects}
    run_ids: list[str] = []
    recalls: list[float] = []
    for run in runs:
        if not isinstance(run, Mapping) or set(run) != {"run_id", "detected"}:
            raise ValueError("a run record holds exactly run_id and detected")
        run_ids.append(_identifier(run["run_id"], "run_id"))
        detected = run["detected"]
        if isinstance(detected, (str, bytes)) or not isinstance(detected, (list, tuple)):
            raise ValueError("detected must be a list of defect ids")
        found = [_identifier(item, "detected defect id") for item in detected]
        if len(set(found)) != len(found):
            raise ValueError(f"run {run_ids[-1]} repeats a detected defect id")
        foreign = sorted(set(found) - known)
        if foreign:
            raise ValueError(f"run {run_ids[-1]} detects ids outside the key: {', '.join(foreign[:5])}")
        for name in found:
            detections[name] += 1
        if defects:
            recalls.append(len(found) / len(defects))
    if len(set(run_ids)) != len(run_ids):
        raise ValueError("detection runs repeat a run_id; a repeated run is not a new observation")
    if not run_ids:
        return unavailable("no_runs")
    if not defects:
        return unavailable("no_defects")
    total = len(run_ids)
    ordered = sorted(defects)
    groups = {
        "always_detected": [name for name in ordered if detections[name] == total],
        "never_detected": [name for name in ordered if detections[name] == 0],
        "intermittent": [name for name in ordered if 0 < detections[name] < total],
    }
    return {
        "available": True, "runs": total, "run_ids": sorted(run_ids), "defect_count": len(ordered),
        "defects": [{"defect_id": name, "detections": detections[name], "runs": total,
                     "rate": ratio(detections[name], total, interval=True)} for name in ordered],
        **{name: {"count": len(ids), "defect_ids": ids} for name, ids in groups.items()},
        "mean_single_run_recall": {"value": _mean(recalls), "runs": total,
                                   "basis": "mean_of_single_run_recalls_no_interval"},
        "minimum_runs_recommended": MINIMUM_RUNS_RECOMMENDED,
        "sufficient_runs": total >= MINIMUM_RUNS_RECOMMENDED,
    }


def _rates(value: Any, name: str) -> dict[str, Mapping[str, Any]] | None:
    if not isinstance(value, Mapping) or not isinstance(value.get("available"), bool):
        raise ValueError(f"{name} is not a detection_rates result")
    if not value["available"]:
        return None
    rows = value.get("defects")
    if not isinstance(rows, list):
        raise ValueError(f"{name} is not a detection_rates result")
    table: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        rate = row.get("rate") if isinstance(row, Mapping) else None
        interval = rate.get("interval") if isinstance(rate, Mapping) else None
        if (not isinstance(row.get("defect_id") if isinstance(row, Mapping) else None, str)
                or not isinstance(interval, Mapping)
                or any(isinstance(interval.get(edge), bool) or not isinstance(interval.get(edge), (int, float))
                       for edge in ("low", "high"))):
            raise ValueError(f"{name} holds a defect row without a measured interval")
        table[row["defect_id"]] = rate
    if len(table) != len(rows):
        raise ValueError(f"{name} repeats a defect id")
    return table


def detection_alarm(baseline: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Defects whose candidate interval lies wholly below the baseline interval.

    An alarm for the operator, never a run verdict, and never a statement that a target is clean.
    """
    before, after = _rates(baseline, "baseline"), _rates(candidate, "candidate")
    if before is None or after is None:
        return unavailable("detection_rates_unavailable")
    scope = {"available": True, "scope": "operator_alarm_not_run_verdict"}
    if set(before) != set(after):
        return {**scope, "status": "incomparable", "reason": "different_defect_ids",
                "only_in_baseline": sorted(set(before) - set(after)),
                "only_in_candidate": sorted(set(after) - set(before))}
    fell = [{"defect_id": name, "baseline": deepcopy(dict(before[name])), "candidate": deepcopy(dict(after[name]))}
            for name in sorted(before) if after[name]["interval"]["high"] < before[name]["interval"]["low"]]
    return {**scope, "status": "detection_alarm" if fell else "no_alarm", "defect_count": len(before),
            "fell": fell, "fell_count": len(fell),
            "sufficient_runs": bool(baseline.get("sufficient_runs")) and bool(candidate.get("sufficient_runs"))}


# ------------------------------------------------------------------ experiments-domain adapter

def _launch_record(run_id: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"launch record of {run_id} must be an object")
    missing = sorted(set(_LAUNCH_REQUIRED) - set(value))
    unknown = sorted(str(key) for key in set(value) - set(_LAUNCH_REQUIRED) - set(_LAUNCH_OPTIONAL))
    if missing or unknown:
        raise ValueError(f"launch record of {run_id}: missing {missing or 'nothing'}, unknown {unknown or 'nothing'}")
    index = value["run_index"]
    if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= 100_000:
        raise ValueError(f"launch record of {run_id}: run_index must be an integer from 1 to 100000")
    for name in (*_LAUNCH_HASHES, "raw_artifact_sha256"):
        if not is_sha256(value[name]):
            raise ValueError(f"launch record of {run_id}: {name} must be a SHA-256")
    if value["status"] not in _STATUSES or value["context_condition"] not in _CONTEXTS:
        raise ValueError(f"launch record of {run_id}: status or context_condition is outside its vocabulary")
    errors = value.get("error_ids", [])
    if not isinstance(errors, (list, tuple)) or not all(isinstance(item, str) and item for item in errors):
        raise ValueError(f"launch record of {run_id}: error_ids must be a list of ids")
    if value["status"] != "complete" and not errors:
        raise ValueError(f"launch record of {run_id}: a {value['status']} run needs error_ids")
    usage = value.get("usage")
    if usage is not None and not isinstance(usage, Mapping):
        raise ValueError(f"launch record of {run_id}: usage must be a usage object or null")
    return {**value, "error_ids": list(errors), "usage": deepcopy(dict(usage)) if usage is not None else None}


def _report(run_id: str, finding: Mapping[str, Any]) -> dict[str, Any]:
    locations = sorted({(item["path"], item["start_line"], item["end_line"]) for item in finding["locations"]})
    return {
        "raw_report_id": finding["finding_id"], "cwe": finding["weakness_cwe"],
        "cause_key": finding["fingerprint"]["relocated"],
        "source_symbol": finding.get("source_symbol"), "sink_symbol": finding.get("sink_symbol"),
        "locations": [{"path": path, "start_line": start, "end_line": end} for path, start, end in locations],
        "severity": "null" if finding.get("severity") is None else finding["severity"],
        "confidence": None, "evidence_ids": [f"finding-snapshot:{run_id}:{finding['finding_id']}"],
    }


def experiment_document(snapshots: Sequence[Mapping[str, Any]], *, experiment_id: str,
                        launches: Mapping[str, Mapping[str, Any]],
                        labels: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """``{"document", "gaps", "stage_mapping"}``: a ``quality-experiment/1`` input built from real runs.

    One launch and one completion (discovery task) per published-stage snapshot of one target at
    one source revision. ``launches`` maps each ``run_id`` to what a snapshot cannot know:
    required ``run_index``, ``started_at``, ``completed_at``, ``raw_artifact_sha256``, ``status``,
    ``scope_sha256``, ``agent_sha256``, ``tools_sha256``, ``decoding_sha256``,
    ``context_condition`` and ``positive_event``; optional ``error_ids`` (required for a run that
    is not complete), ``usage`` (absent or ``None`` becomes unavailable usage with the reason
    ``usage_not_supplied``) and any of ``configuration_sha256``, ``guidance_sha256``,
    ``model_sha256`` the snapshot holds as ``None``. A hash is never fabricated: a missing one is a
    ``ValueError`` naming it. A finding without a CWE is skipped and counted in ``gaps``; one
    fingerprint that different runs locate on different lines is also a named gap, because the
    experiments normalizer hashes line ranges and then counts it as two root causes. The
    experiments domain has no ``published`` stage, so the group is registered at
    ``EXPERIMENT_STAGE`` and the mapping is returned.
    """
    experiment_id = _identifier(experiment_id, "experiment_id")
    rows = _admit(snapshots)
    if not isinstance(launches, Mapping):
        raise ValueError("launches must map run_id to its launch record")
    run_ids = [row["run_id"] for row in rows]
    stray = sorted(str(key) for key in set(launches) - set(run_ids))
    absent = sorted(set(run_ids) - set(launches))
    if stray or absent:
        raise ValueError(f"launch records and snapshots disagree: without snapshot {stray}, without launch {absent}")
    if len({(row["target_id"], row["source_revision"]) for row in rows}) > 1:
        raise ValueError("an experiment document covers one target at one source revision")
    launch_rows: list[dict[str, Any]] = []
    completions: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    root_locations: dict[str, set[str]] = {}
    for row in rows:
        run_id = row["run_id"]
        if row["stage"] != "published":
            raise ValueError(f"snapshot {run_id} is at stage {row['stage']!r}; "
                             "the adapter registers published snapshots")
        record = _launch_record(run_id, launches[run_id])
        hashes: dict[str, str] = {}
        for name in _IDENTITY_HASHES:
            supplied = record.get(name)
            if supplied is not None and not is_sha256(supplied):
                raise ValueError(f"launch record of {run_id}: {name} must be a SHA-256")
            if row[name] is not None and supplied is not None and supplied != row[name]:
                raise ValueError(f"launch record of {run_id} contradicts the snapshot's {name}")
            value = row[name] if row[name] is not None else supplied
            if value is None:
                raise ValueError(f"run {run_id} has no {name}: supply it in launches; an identity is never fabricated")
            hashes[name] = value
        launch_rows.append({
            "run_id": run_id, "source_run_id": run_id, "run_index": record["run_index"],
            "started_at": record["started_at"],
            "group": {"source_revision": row["source_revision"], "scope_sha256": record["scope_sha256"],
                      "context_condition": record["context_condition"], **hashes,
                      "agent_sha256": record["agent_sha256"], "tools_sha256": record["tools_sha256"],
                      "decoding_sha256": record["decoding_sha256"], "normalizer_version": NORMALIZER,
                      "stage": EXPERIMENT_STAGE, "task": "discovery", "positive_event": record["positive_event"],
                      "warning_set_sha256": None}})
        reports = []
        without_cwe = []
        for finding in sorted(row["findings"], key=lambda item: item["finding_id"]):
            if finding.get("weakness_cwe") is None:
                without_cwe.append(finding["finding_id"])
                continue
            report = _report(run_id, finding)
            reports.append(report)
            root_locations.setdefault(finding["fingerprint"]["exact"], set()).add(digest(report["locations"]))
        if without_cwe:
            gaps.append({"gap": "finding_without_cwe", "run_id": run_id, "count": len(without_cwe),
                         "finding_ids": without_cwe})
        completions.append({
            "run_id": run_id, "status": record["status"], "completed_at": record["completed_at"],
            "raw_artifact_sha256": record["raw_artifact_sha256"], "reports": reports, "decisions": [],
            "usage": record["usage"] if record["usage"] is not None else dict(_UNAVAILABLE_USAGE,
                                                                             evidence_ids=[]),
            "coverage": [], "error_ids": record["error_ids"]})
    if len({row["run_index"] for row in launch_rows}) != len(launch_rows):
        raise ValueError("run_index must be unique and assigned at launch")
    drifting = sorted(key for key, places in root_locations.items() if len(places) > 1)
    if drifting:
        gaps.append({"gap": "fingerprint_located_on_different_lines", "run_id": None, "count": len(drifting),
                     "fingerprints": drifting})
    matching = {"schema": "appsec-review/quality-matching/1", "revision": "finding-snapshot-adapter-1",
                "normalizer_version": NORMALIZER, "overrides": []}
    if labels is None:
        adjudications: dict[str, Any] = {"schema": "appsec-review/quality-adjudications/1", "revision": "unlabelled",
                                         "matching_snapshot_id": digest(matching), "labels": []}
    else:
        if not isinstance(labels, Mapping):
            raise ValueError("labels must be an adjudications document")
        adjudications = deepcopy(dict(labels))
        if adjudications.get("matching_snapshot_id") != digest(matching):
            raise ValueError("labels are bound to a different matching snapshot; rebuild the labels explicitly")
    document = {
        "schema": INPUT_SCHEMA, "experiment_id": experiment_id,
        "launches": sorted(launch_rows, key=lambda item: item["run_index"]),
        "completions": sorted(completions, key=lambda item: item["run_id"]),
        "warning_sets": [], "matching": matching, "adjudications": adjudications, "inference_policy": None}
    load_experiment(document)       # closed-schema admission; ``experiments.rebuild`` checks the rest
    return {"document": document, "gaps": sorted(gaps, key=lambda item: (item["gap"], item["run_id"] or "")),
            "stage_mapping": {"published": EXPERIMENT_STAGE}}


__all__ = [
    "COMPARISON_FIELDS", "EXPERIMENT_STAGE", "MAX_DEFECTS", "MAX_DETECTION_RUNS", "MAX_SERIES_RUNS",
    "MINIMUM_RUNS_RECOMMENDED", "SUBSETS", "comparable", "comparison_key", "detection_alarm", "detection_rates",
    "experiment_document", "flapping", "series",
]
