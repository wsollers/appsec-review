"""Low-cardinality, event-derived debug-symbol operational metrics."""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from appsec_review.debug_symbols.contract import JOB_ID, QueryMode


def debug_symbol_metrics(records: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    decisions = []
    completed = []
    queries = []
    readers = []
    fallbacks = 0
    failures = 0
    attempts: set[tuple[str, str, str]] = set()
    attempt_identity_unavailable = False
    gaps: list[str] = []
    allowed_modes = {mode.value for mode in QueryMode}
    for record in records:
        event = record.get("event_type")
        producer_event = (record.get("job_id") == JOB_ID and event == "JOB_STARTED") or event in {
            "DEBUG_SYMBOL_TARGET_SELECTED", "DEBUG_SYMBOL_INDEX_COMPLETED",
            "DEBUG_SYMBOL_ARTIFACT_COMPLETED", "DEBUG_SYMBOL_ARTIFACT_FAILED"}
        if producer_event:
            identity = tuple(str(record.get(key) or "-") for key in ("run_id", "job_id", "attempt_id"))
            if "-" in identity:
                attempt_identity_unavailable = True
            else:
                attempts.add(identity)
        if not isinstance(event, str) or not event.startswith("DEBUG_SYMBOL_"):
            continue
        details = record.get("details", {})
        target = details.get("compiler_target")
        if target is not None and target not in {"clang", "msvc", "mixed", "unknown"}:
            gaps.append("debug_symbol_metric_invalid_target")
            continue
        if event == "DEBUG_SYMBOL_TARGET_SELECTED":
            decisions.append(target)
        elif event == "DEBUG_SYMBOL_INDEX_COMPLETED":
            completed.append(details)
        elif event == "DEBUG_SYMBOL_ARTIFACT_FAILED":
            failures += 1
        elif event == "DEBUG_SYMBOL_READER_COMPLETED":
            if (details.get("environment") not in {"build", "catalog"}
                    or details.get("outcome") not in {
                        "succeeded", "tool_unavailable", "image_unavailable", "image_incompatible",
                        "tool_failed", "tool_timeout", "tool_oom", "output_limit",
                        "export_configuration_invalid", "identity_rejected", "execution_failed"}):
                gaps.append("debug_symbol_metric_invalid_reader_outcome")
                continue
            readers.append(details)
        elif event == "DEBUG_SYMBOL_READER_FALLBACK":
            fallbacks += 1
        elif event == "DEBUG_SYMBOL_QUERY_COMPLETED":
            if details.get("mode") not in allowed_modes:
                gaps.append("debug_symbol_metric_invalid_mode")
                continue
            queries.append(details)

    def count(value: Mapping[str, Any], key: str) -> int | None:
        number = value.get(key)
        if type(number) is not int or number < 0:
            gaps.append(f"debug_symbol_metric_missing_or_invalid_{key}")
            return None
        return number

    latest = completed[-1] if completed else None
    index: dict[str, Any] = {
        "available": latest is not None,
        "record_count": None,
        "artifact_count": None,
        "gap_count": None,
        "duration_ms": None,
        "unavailable_reason": None if latest is not None else "debug_symbol_index_metrics_not_emitted",
    }
    if latest is not None:
        for key in ("record_count", "artifact_count", "gap_count", "duration_ms"):
            index[key] = count(latest, key)
    modes = Counter()
    returned = []
    durations = []
    query_gaps = []
    truncations = []
    for query in queries:
        modes[query["mode"]] += 1
        for values, key in ((returned, "returned_count"), (durations, "duration_ms"),
                            (query_gaps, "gap_count"), (truncations, "truncated_count")):
            number = count(query, key)
            if number is not None:
                values.append(number)

    def total(values: list[int]) -> int | None:
        return sum(values) if len(values) == len(queries) else None

    if attempt_identity_unavailable:
        gaps.append("debug_symbol_metric_attempt_identity_unavailable")
    reader_durations = [count(reader, "duration_ms") for reader in readers]
    reader_bytes = [count(reader, "output_bytes") for reader in readers]
    return {
        "schema": "appsec-review/debug-symbol-metrics/1",
        "compiler_target": decisions[-1] if decisions else None,
        "decision_count": len(decisions),
        "index_attempt_count": None if attempt_identity_unavailable else len(attempts),
        "artifact_failure_count": failures,
        "readers": {
            "attempt_count": len(readers), "fallback_count": fallbacks,
            "by_environment": dict(sorted(Counter(
                reader["environment"] for reader in readers).items())),
            "by_outcome": dict(sorted(Counter(reader["outcome"] for reader in readers).items())),
            "duration_ms": (sum(value for value in reader_durations if value is not None)
                            if None not in reader_durations else None),
            "output_bytes": (sum(value for value in reader_bytes if value is not None)
                             if None not in reader_bytes else None),
        },
        "index": index,
        "queries": {
            "count": len(queries), "by_mode": dict(sorted(modes.items())),
            "returned_count": total(returned), "duration_ms": total(durations),
            "gap_count": total(query_gaps), "truncated_count": total(truncations),
        },
        "metric_gaps": sorted(set(gaps)),
    }
