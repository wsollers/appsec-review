"""Deterministic full rebuilds from immutable launch/result and independent truth records."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from decimal import Decimal, localcontext
from itertools import combinations
from pathlib import PurePosixPath
from statistics import fmean
from typing import Any, Iterable, Literal

from .contracts import (
    OUTPUT, OUTPUT_SCHEMA, Completion, Decision, Experiment, Label, Launch,
    digest, load_experiment, population_id, root_cause_id, validate,
)


def ratio(numerator: int | float | None, denominator: int | float | None,
          reason: str | None = None) -> dict[str, Any]:
    available = numerator is not None and denominator is not None
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if numerator is not None and denominator else None,
            "status": "measured" if available and denominator else
                      "empty_denominator" if available else "unavailable",
            "reason": reason if not available else "zero_denominator" if not denominator else None}


def summary(values: Iterable[float | None], total: int | None = None) -> dict[str, Any]:
    rows = list(values)
    defined = [value for value in rows if value is not None]
    return {"value": fmean(defined) if defined else None, "valid_count": len(defined),
            "total_count": len(rows) if total is None else total}


def _unique(rows: Iterable[Any], key: Any, description: str) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for row in rows:
        identity = key(row)
        if identity in result and row != result[identity]:
            raise ValueError(f"conflicting immutable {description}: {identity}")
        result[identity] = row
    return result


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _prepare(value: Any) -> Experiment:
    document = load_experiment(value)
    launches = _unique(document["launches"], lambda row: row["run_id"], "launch")
    document["launches"] = sorted(launches.values(), key=lambda row: row["run_index"])
    indices: set[int] = set()
    source_runs: set[tuple[str, str]] = set()
    previous_time: datetime | None = None
    for launch in document["launches"]:
        if launch["run_index"] in indices:
            raise ValueError("run_index must be unique and assigned at launch")
        indices.add(launch["run_index"])
        started = _time(launch["started_at"])
        if previous_time is not None and started < previous_time:
            raise ValueError("run_index contradicts launch-time order")
        previous_time = started
        identity = (digest(launch["group"]), launch["source_run_id"])
        if identity in source_runs:
            raise ValueError("repeated source_run_id is not a new independent run")
        source_runs.add(identity)
        group = launch["group"]
        if (group["task"] == "triage") != (group["warning_set_sha256"] is not None):
            raise ValueError("only fixed-warning triage requires a warning set")
    warning_sets = _unique(document["warning_sets"], lambda row: row["warning_set_sha256"], "warning set")
    for warning_set in warning_sets.values():
        warning_set["warning_ids"].sort()
        if digest({"warning_ids": warning_set["warning_ids"]}) != warning_set["warning_set_sha256"]:
            raise ValueError("warning set digest mismatch")
    document["warning_sets"] = sorted(warning_sets.values(), key=lambda row: row["warning_set_sha256"])
    for launch in launches.values():
        warning_set_id = launch["group"]["warning_set_sha256"]
        if warning_set_id is not None and warning_set_id not in warning_sets:
            raise ValueError("missing fixed warning set")

    completions = _unique(document["completions"], lambda row: row["run_id"], "completion")
    document["completions"] = sorted(completions.values(), key=lambda row: row["run_id"])
    report_keys: set[tuple[str, str]] = set()
    for run_id, completion in completions.items():
        if run_id not in launches:
            raise ValueError("completion requires an immutable launch record")
        launch = launches[run_id]
        if _time(completion["completed_at"]) < _time(launch["started_at"]):
            raise ValueError("completion precedes launch")
        if completion["status"] != "complete" and not completion["error_ids"]:
            raise ValueError("incomplete runs require explicit error/gap IDs")
        _unique(completion["reports"], lambda row: row["raw_report_id"], "raw report")
        completion["reports"].sort(key=lambda row: row["raw_report_id"])
        for report in completion["reports"]:
            report_keys.add((run_id, report["raw_report_id"]))
            for location in report["locations"]:
                path = PurePosixPath(location["path"])
                if (path.is_absolute() or path.as_posix() == "." or ".." in path.parts or "\\" in location["path"]
                        or ":" in location["path"] or path.as_posix() != location["path"]
                        or location["end_line"] < location["start_line"]):
                    raise ValueError("root-cause locations require canonical source-relative paths and lines")
            confidence = report["confidence"]
            if confidence is not None:
                raw = confidence["raw"]
                if confidence["kind"] != "verbal_score" and type(raw) not in (int, float):
                    raise ValueError("numeric confidence kind requires a numeric score")
                if confidence["kind"] in {"probability", "token_probability", "vote_fraction"} and not 0 <= raw <= 1:
                    raise ValueError("probability/fraction score must be in [0,1]")
                if confidence["calibrated"] and (
                    confidence["kind"] != "probability" or not confidence["calibration_version"]
                ):
                    raise ValueError("calibrated correctness requires probability kind and calibration version")
                if not confidence["calibrated"] and confidence["calibration_version"] is not None:
                    raise ValueError("uncalibrated score cannot declare a calibration version")
        decisions = _unique(completion["decisions"], lambda row: row["warning_id"], "triage decision")
        completion["decisions"] = sorted(decisions.values(), key=lambda row: row["warning_id"])
        group = launch["group"]
        if group["task"] == "discovery" and decisions:
            raise ValueError("discovery cannot contain fixed-warning triage decisions")
        if group["task"] == "triage":
            if completion["reports"]:
                raise ValueError("triage uses original warning units, not discovery report counts")
            warnings = set(warning_sets[group["warning_set_sha256"]]["warning_ids"])
            if not decisions.keys() <= warnings:
                raise ValueError("triage decision names a foreign warning")
            if completion["status"] == "complete" and decisions.keys() != warnings:
                raise ValueError("complete triage must decide or abstain on every fixed warning")
        usage = completion["usage"]
        if (usage["cost"] is None) != (usage["currency"] is None) or (
            (usage["cost_kind"] == "unavailable") != (usage["cost"] is None)
        ):
            raise ValueError("cost amount, currency and provenance disagree")
        missing = any(usage[name] is None for name in ("input_tokens", "output_tokens", "wall_seconds", "cost"))
        if missing and not usage["missing_reason"]:
            raise ValueError("missing usage requires an explicit reason")
        if any(usage[name] is not None for name in ("input_tokens", "output_tokens", "wall_seconds", "cost")):
            if not usage["evidence_ids"]:
                raise ValueError("measured or estimated usage requires source evidence")
        for coverage in completion["coverage"]:
            analyzed, eligible = coverage["analyzed"], coverage["eligible"]
            if analyzed is not None and eligible is not None and analyzed > eligible:
                raise ValueError("analyzed coverage exceeds eligible population")
            if (analyzed is None or eligible is None) and not coverage["missing_reason"]:
                raise ValueError("missing coverage denominator requires a reason")
            if (analyzed is not None or eligible is not None) and not coverage["evidence_ids"]:
                raise ValueError("coverage counts require source evidence")

    matching = document["matching"]
    overrides = _unique(matching["overrides"], lambda row: (row["run_id"], row["raw_report_id"]), "matching override")
    if not overrides.keys() <= report_keys:
        raise ValueError("matching override names an absent raw report")
    matching["overrides"] = [overrides[key] for key in sorted(overrides)]
    labels = document["adjudications"]
    if labels["matching_snapshot_id"] != digest(matching):
        raise ValueError("adjudications refer to a different matching snapshot; rebuild labels explicitly")
    label_rows = _unique(labels["labels"], lambda row: (row["population_id"], row["subject_id"]), "adjudication")
    populations = {population_id(row["group"]) for row in launches.values()}
    for row in label_rows.values():
        if row["population_id"] not in populations:
            raise ValueError("adjudication refers to a foreign label population")
        if row["is_rank1_critical"] is True and row["is_real_bug"] is not True:
            raise ValueError("rank-1 critical adjudication must also identify a real bug")
        if row["outcome"] == "tp" and row["is_real_bug"] is False:
            raise ValueError("true-positive adjudication contradicts a no-real-bug label")
    labels["labels"] = [label_rows[key] for key in sorted(label_rows)]
    policy = document["inference_policy"]
    if policy is not None and document["launches"] and (
        _time(policy["predeclared_at"]) > _time(document["launches"][0]["started_at"])
    ):
        raise ValueError("inferential policy was not predeclared before launches")
    return document


def _quality(subjects: Iterable[str], outcomes: dict[str, str]) -> dict[str, Any]:
    counts = Counter(outcomes.get(subject, "unresolved") for subject in subjects)
    tp, fp, unresolved = counts["tp"], counts["fp"], counts["unresolved"]
    adjudicated, total = tp + fp, tp + fp + unresolved
    return {"tp": tp, "fp": fp, "unresolved": unresolved, "out_of_scope": counts["out_of_scope"],
            "precision": ratio(tp, adjudicated), "false_discovery_rate": ratio(fp, adjudicated),
            "pending_lower": ratio(tp, total), "pending_upper": ratio(tp + unresolved, total),
            "adjudication_coverage": ratio(adjudicated, total)}


def _triage(decisions: list[Decision], outcomes: dict[str, str]) -> dict[str, Any]:
    count: Counter[tuple[str, str]] = Counter(
        (row["decision"], outcomes.get(row["warning_id"], "unresolved")) for row in decisions)
    total = len(decisions)
    tp, fp, tn, fn = count["retain", "tp"], count["retain", "fp"], count["reject", "fp"], count["reject", "tp"]
    retained = sum(row["decision"] == "retain" for row in decisions)
    rejected = sum(row["decision"] == "reject" for row in decisions)
    abstained = sum(row["decision"] == "abstain" for row in decisions)
    known_positive = sum(count[decision, "tp"] for decision in ("retain", "reject", "abstain"))
    known_negative = sum(count[decision, "fp"] for decision in ("retain", "reject", "abstain"))
    return {
        "warning_count": total, "retained": retained, "rejected": rejected, "abstained": abstained,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "known_positive": known_positive, "known_negative": known_negative,
        "unresolved_inputs": sum(count[decision, "unresolved"] for decision in ("retain", "reject", "abstain")),
        "out_of_scope_inputs": sum(count[decision, "out_of_scope"] for decision in ("retain", "reject", "abstain")),
        "abstained_tp": count["abstain", "tp"], "abstained_fp": count["abstain", "fp"],
        "tp_retention": ratio(tp, known_positive), "fp_removal": ratio(tn, known_negative),
        "false_positive_rate": ratio(fp, fp + tn), "decision_coverage": ratio(retained + rejected, total),
        "abstention_rate": ratio(abstained, total), "suppression_rate": ratio(rejected, total),
        "rejection_precision": ratio(tn, tn + fn),
    }


def _transition(previous: dict[str, Any] | None, current: dict[str, Any],
                sets: dict[str, set[str]], first_seen: int | None) -> dict[str, Any]:
    reason = None
    if current["run_index"] == 1:
        reason = "first_run"
    elif previous is None:
        reason = "missing_predecessor"
    elif previous["comparison_group_id"] != current["comparison_group_id"]:
        reason = "incomparable_predecessor"
    elif previous["status"] != "complete":
        reason = "predecessor_" + previous["status"]
    elif current["status"] != "complete":
        reason = "current_" + current["status"]
    left = sets[previous["run_id"]] if previous and previous["status"] == "complete" else None
    right = sets[current["run_id"]] if current["status"] == "complete" else None
    if reason is None and not left and not right:
        reason = "both_empty"
    result = {
        "previous_run_id": previous["run_id"] if previous else None,
        "status": "unavailable" if reason else "valid", "reason": reason,
        "previous_size": len(left) if left is not None else None,
        "current_size": len(right) if right is not None else None,
        "shared": None, "union": None, "new_to_previous": None, "dropped": None, "reappearing": None,
        "jaccard": ratio(None, None, reason), "retention": ratio(None, None, reason),
    }
    if reason not in {None, "both_empty"}:
        return result
    assert left is not None and right is not None and first_seen is not None
    shared, union = len(left & right), len(left | right)
    result.update(shared=shared, union=union, new_to_previous=len(right - left),
                  dropped=len(left - right), reappearing=len(right - left) - first_seen,
                  jaccard=ratio(shared, union), retention=ratio(shared, len(left)))
    return result


UsageField = Literal["input_tokens", "output_tokens", "wall_seconds"]
USAGE_FIELDS: tuple[UsageField, ...] = ("input_tokens", "output_tokens", "wall_seconds")


def _usage_total(launches: list[Launch], completions: dict[str, Completion], field: UsageField) -> dict[str, Any]:
    known: list[int | float] = []
    missing = []
    for launch in launches:
        completion = completions.get(launch["run_id"])
        value = completion["usage"][field] if completion is not None else None
        if value is None:
            missing.append(launch["run_id"])
        else:
            known.append(value)
    return {"observed_sum": sum(known) if known else None,
            "total": sum(known) if known and not missing else None, "missing_run_ids": missing}


def _cost(launches: list[Launch], completions: dict[str, Completion], yield_count: int | None) -> dict[str, Any]:
    observed = []
    missing = []
    for launch in launches:
        completion = completions.get(launch["run_id"])
        if completion is None or completion["usage"]["cost_kind"] != "observed":
            missing.append(launch["run_id"])
        else:
            observed.append(completion["usage"])
    currencies = {usage["currency"] for usage in observed}
    compatible = len(currencies) == 1
    with localcontext() as context:
        context.prec = 60
        known = sum((Decimal(usage["cost"]) for usage in observed if usage["cost"] is not None),
                    Decimal(0)) if compatible else None
        total = known if not missing else None
        per_tp = total / yield_count if total is not None and yield_count else None
    return {"observed_sum": str(known) if known is not None else None,
            "total": str(total) if total is not None else None,
            "currency": next(iter(currencies)) if compatible else None,
            "missing_run_ids": missing, "incompatible_currency": len(currencies) > 1,
            "per_unique_tp": str(per_tp) if per_tp is not None else None,
            "reason": "missing_observed_cost" if missing else "incompatible_or_missing_currency" if not compatible
                      else "no_completed_yield" if yield_count is None else "zero_unique_tp" if not yield_count else None}


def rebuild(value: Any) -> dict[str, Any]:
    """Recompute every metric under one matching/label revision; never skip a predecessor."""
    document = _prepare(value)
    matching_id = digest(document["matching"])
    completions = {row["run_id"]: row for row in document["completions"]}
    overrides = {(row["run_id"], row["raw_report_id"]): row["root_cause_id"]
                 for row in document["matching"]["overrides"]}
    labels: dict[str, dict[str, Label]] = {}
    for label in document["adjudications"]["labels"]:
        labels.setdefault(label["population_id"], {})[label["subject_id"]] = label
    groups: dict[str, list[Launch]] = {}
    outcomes_by_group: dict[str, dict[str, str]] = {}
    sets: dict[str, set[str]] = {}
    seen: dict[str, set[str]] = {}
    runs: list[dict[str, Any]] = []
    by_index: dict[int, dict[str, Any]] = {}
    membership = []
    root_sources: dict[str, str] = {}
    for launch in document["launches"]:
        group, run_id = launch["group"], launch["run_id"]
        group_id = digest({"frozen_group": group, "matching_snapshot_id": matching_id})
        groups.setdefault(group_id, []).append(launch)
        population = population_id(group)
        outcomes: dict[str, str] = {key: row["outcome"] for key, row in labels.get(population, {}).items()}
        outcomes_by_group[group_id] = outcomes
        completion = completions.get(run_id)
        complete = completion is not None and completion["status"] == "complete"
        subjects: set[str] = set()
        raw_ids: set[str] = set()
        if completion is not None:
            if group["task"] == "discovery":
                for report in completion["reports"]:
                    raw_id = report["raw_report_id"]
                    subject = overrides.get((run_id, raw_id), root_cause_id(group, report))
                    if root_sources.setdefault(subject, group["source_revision"]) != group["source_revision"]:
                        raise ValueError("matching cannot merge root causes across source revisions")
                    subjects.add(subject)
                    if raw_id not in raw_ids:
                        membership.append({
                            "run_id": run_id, "source_run_id": launch["source_run_id"], "comparison_group_id": group_id,
                            "unit": "root_cause", "raw_report_id": raw_id, "subject_id": subject, "included": complete,
                            "outcome": outcomes.get(subject, "unresolved"), "evidence_ids": report["evidence_ids"],
                            "confidence": report["confidence"]})
                    raw_ids.add(raw_id)
            else:
                for decision in completion["decisions"]:
                    retained = decision["decision"] == "retain"
                    subject = decision["warning_id"]
                    if retained:
                        subjects.add(subject)
                    membership.append({
                        "run_id": run_id, "source_run_id": launch["source_run_id"], "comparison_group_id": group_id,
                        "unit": "warning", "raw_report_id": None, "subject_id": subject,
                        "included": complete and retained, "outcome": outcomes.get(subject, "unresolved"),
                        "evidence_ids": [completion["raw_artifact_sha256"]], "confidence": None})
        sets[run_id] = subjects
        first_seen = len(subjects - seen.setdefault(group_id, set())) if complete else None
        if complete:
            seen[group_id].update(subjects)
        row = {
            "run_id": run_id, "source_run_id": launch["source_run_id"], "run_index": launch["run_index"],
            "comparison_group_id": group_id, "frozen_group_id": digest(group), "label_population_id": population,
            "status": completion["status"] if completion else "pending", "launch_sha256": digest(launch),
            "completion_sha256": digest(completion) if completion else None,
            "raw_artifact_sha256": completion["raw_artifact_sha256"] if completion else None,
            "raw_report_count": len(completion["reports"]) if completion else None,
            "duplicate_report_count": len(completion["reports"]) - len(raw_ids) if completion else None,
            "set_size": len(subjects) if complete else None,
            "diagnostic_set_size": len(subjects) if completion else None,
            "subject_ids": sorted(subjects), "first_seen": first_seen,
            "quality": _quality(subjects, outcomes) if complete else None,
            "triage": _triage(completion["decisions"], outcomes)
                      if completion is not None and complete and group["task"] == "triage" else None,
        }
        row["transition"] = _transition(by_index.get(launch["run_index"] - 1), row, sets, first_seen)
        by_index[launch["run_index"]] = row
        window = range(max(2, launch["run_index"] - 4), launch["run_index"] + 1)
        row["ror_5"] = summary(
            by_index[index]["transition"]["jaccard"]["value"] if index in by_index
            and by_index[index]["comparison_group_id"] == group_id else None for index in window)
        runs.append(row)

    aggregates: list[dict[str, Any]] = []
    for group_id, launches in sorted(groups.items()):
        group = launches[0]["group"]
        outcomes = outcomes_by_group[group_id]
        group_runs = [by_index[launch["run_index"]] for launch in launches]
        completed = [row for row in group_runs if row["status"] == "complete"]
        pair_values = []
        empty_pairs = 0
        for left, right in combinations(completed, 2):
            a, b = sets[left["run_id"]], sets[right["run_id"]]
            if a or b:
                pair_values.append(len(a & b) / len(a | b))
            else:
                empty_pairs += 1
        union = set().union(*(sets[row["run_id"]] for row in completed))
        distinct = _quality(union, outcomes) if completed else None
        occurrences = _quality((subject for row in completed for subject in sets[row["run_id"]]), outcomes) if completed else None
        tp_yield = distinct["tp"] if distinct is not None else None
        counts = Counter(row["status"] for row in group_runs)
        empty_count = sum(row["set_size"] == 0 for row in completed)
        usage_metrics: dict[str, Any] = {field: _usage_total(launches, completions, field) for field in USAGE_FIELDS}
        aggregates.append({
            "comparison_group_id": group_id, "frozen_group_id": digest(group), "group": group,
            "unit": "root_cause" if group["task"] == "discovery" else "warning",
            "source_run_ids": [launch["source_run_id"] for launch in launches],
            "included_run_ids": [launch["run_id"] for launch in launches],
            "completed_run_ids": [row["run_id"] for row in completed],
            "counts": {"attempted": len(launches), "complete": counts["complete"], "failed": counts["failed"],
                       "partial": counts["partial"], "cancelled": counts["cancelled"], "pending": counts["pending"],
                       "completed_empty": empty_count},
            "completion_rate": ratio(counts["complete"], len(launches)),
            "empty_run_rate": ratio(empty_count, counts["complete"]),
            "mps": summary(pair_values, len(completed) * (len(completed) - 1) // 2),
            "empty_pair_count": empty_pairs,
            "ror": summary(row["transition"]["jaccard"]["value"] for row in group_runs if row["run_index"] > 1),
            "distinct": distinct, "occurrences": occurrences,
            "macro_run_precision": summary(row["quality"]["precision"]["value"] for row in completed),
            "unique_tp_yield": tp_yield,
            "unique_tp_per_completed_run": ratio(tp_yield, len(completed), "no_completed_runs"),
            "recurrence": [{
                "subject_id": subject, "outcome": outcomes.get(subject, "unresolved"),
                "run_ids": [row["run_id"] for row in completed if subject in sets[row["run_id"]]],
                "frequency": ratio(sum(subject in sets[row["run_id"]] for row in completed), len(completed)),
            } for subject in sorted(union)],
            **usage_metrics,
            "cost": _cost(launches, completions, tp_yield),
            "triage": _triage([decision for row in completed
                               for decision in completions[row["run_id"]]["decisions"]], outcomes)
                      if group["task"] == "triage" and completed else None,
            "open_world_recall": ratio(None, None, "unknown_total_vulnerabilities" if group["task"] == "discovery"
                                      else "not_an_open_world_population"),
        })
    snapshot = {
        "schema": OUTPUT_SCHEMA, "experiment_id": document["experiment_id"], "source_sha256": digest(document),
        "source": document, "matching_snapshot_id": matching_id,
        "normalizer_version": document["matching"]["normalizer_version"],
        "matching_revision": document["matching"]["revision"],
        "label_snapshot_id": digest(document["adjudications"]), "label_revision": document["adjudications"]["revision"],
        "runs": runs, "groups": aggregates, "membership": membership,
        "inference": {"status": "not_certified", "lower_confidence_bound": None,
                      "reason": "not_predeclared" if document["inference_policy"] is None else "inference_not_implemented",
                      "pending_bounds": "not_confidence_intervals", "repeated_findings": "not_independent_evidence"},
    }
    validate(snapshot, OUTPUT)
    return snapshot
