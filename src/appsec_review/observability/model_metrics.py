"""Bounded model dispatch accounting over validated pipeline events, without model text."""
from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any, Mapping, Sequence

from appsec_review.observability.costs import account_calls
from appsec_review.observability.telemetry import _percentile
from appsec_review.reporting.telemetry.inputs import event_timestamp

USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_tokens", "reasoning_tokens")
_TERMINALS = {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "REUSED", "REPLAYED", "CACHED"}


def label(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:/@+-]{1,128}", value):
        return value
    return "sha256:" + hashlib.sha256(str(value).encode()).hexdigest()[:16]


def number(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value < 2**63 else None


def distribution(values: Sequence[int | None]) -> dict[str, Any]:
    measured = [value for value in values if value is not None]
    return {"sample_count": len(measured), "missing_count": len(values) - len(measured),
            "sum_ms": sum(measured) if measured else None,
            "p50_ms": _percentile(measured, .5), "p95_ms": _percentile(measured, .95),
            "max_ms": max(measured, default=None)}


def _wall(intervals: Sequence[tuple[Any, Any]]) -> int | None:
    if not intervals:
        return None
    start, end = sorted(intervals)[0]
    elapsed = 0
    for next_start, next_end in sorted(intervals)[1:]:
        if next_start > end:
            elapsed += int((end - start).total_seconds() * 1000)
            start, end = next_start, next_end
        else:
            end = max(end, next_end)
    return elapsed + int((end - start).total_seconds() * 1000)


def aggregate_model_calls(events: Sequence[Mapping[str, Any]], *, complete: bool,
                          max_rows: int = 8) -> dict[str, Any]:
    """Count distinct dispatches, not cumulative retry counters or copied checkpoint usage."""
    if len(events) > 100000 or not 1 <= max_rows <= 30:
        raise ValueError("model accounting bounds exceeded")
    calls: dict[tuple[Any, ...], dict[str, Any]] = {}
    gaps: Counter[str] = Counter()
    duplicates = 0
    for event in events:
        if event["event_type"] not in {"MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"}:
            continue
        details = event["details"]
        invocation = details.get("model_invocation_id") or details.get("invocation_id")
        if not isinstance(invocation, str) or not invocation:
            gaps["missing_invocation_identity"] += 1
            continue
        key = tuple(event[name] for name in ("run_id", "job_id", "attempt_id")) + (invocation,)
        row = calls.setdefault(key, {})
        phase = "start" if event["event_type"] == "MODEL_CALL_STARTED" else "end"
        if phase in row:
            duplicates += 1
            if row[phase]["details"] != details:
                row["conflict"] = True
                gaps["conflicting_call_records"] += 1
        else:
            row[phase] = event
    rows = []
    for call in calls.values():
        start, end = call.get("start"), call.get("end")
        event = end or start
        details = event["details"]
        reused = (details.get("execution_mode") in {"replay", "cache", "cached", "reused"}
                  or details.get("terminal_status") in {"REUSED", "REPLAYED", "CACHED"}
                  or details.get("usage_unavailable_reason") == "recorded_replay")
        status = details.get("terminal_status") if end else "RUNNING"
        if end and status not in _TERMINALS:
            gaps["unsupported_call_status"] += 1
            status = "UNKNOWN"
        if not start:
            gaps["missing_call_start"] += 1
        begun = event_timestamp(start["timestamp"]) if start else None
        ended = event_timestamp(end["timestamp"]) if end else None
        interval = (begun, ended) if begun and ended and ended >= begun else None
        if end and not interval:
            gaps["call_interval_unavailable"] += 1
        conflict = bool(call.get("conflict"))
        usage = {name: number(details.get(name)) if not reused and not conflict else None
                 for name in USAGE_FIELDS}
        rows.append({
            "provider": label(details.get("served_provider") or details.get("provider")),
            "model": label(details.get("served_model") or details.get("model")),
            "job": label(event["job_id"]), "role": label(details.get("role")),
            "status": "CONFLICT" if conflict else status, "reused": reused,
            "retry": number(details.get("retry_count")),
            "invalid_output": details.get("failure_category") == "schema",
            "usage": usage, "usage_reason": label(details.get("usage_unavailable_reason")),
            "latency": number(details.get("call_latency_ms")) if not conflict else None,
            "elapsed": number(details.get("duration_ms")) if not conflict else None,
            "queue": number(details.get("queue_delay_ms")) if not conflict else None,
            "interval": interval if not conflict and not reused else None,
        })
    accounting_complete = complete and not gaps

    def summarize(selected: list[dict[str, Any]]) -> dict[str, Any]:
        fresh = [row for row in selected if not row["reused"]]
        usage = {}
        for field in USAGE_FIELDS:
            measured = [row["usage"][field] for row in fresh if row["usage"][field] is not None]
            missing = len(fresh) - len(measured)
            usage[field] = {
                "known_sum": sum(measured) if measured else None,
                "measured_calls": len(measured), "missing_calls": missing,
                "lower_bound": not accounting_complete or bool(missing),
                "reason": ("not_reported" if not measured else "incomplete_usage" if missing else
                           None if accounting_complete else "incomplete_events"),
            }
        return {
            "fresh_calls": len(fresh), "reused_calls": len(selected) - len(fresh),
            "retry_calls": sum((row["retry"] or 0) > 0 for row in fresh),
            "retry_identity_missing": sum(row["retry"] is None for row in fresh),
            "statuses": dict(sorted(Counter(row["status"] for row in fresh).items())),
            "invalid_output_calls": sum(row["invalid_output"] for row in fresh),
            "usage": usage,
            "call_latency": distribution([row["latency"] for row in fresh]),
            "queue_delay": distribution([row["queue"] for row in fresh]),
            "execution_elapsed": distribution([row["elapsed"] for row in fresh]),
            "concurrent_dispatch_wall_ms": _wall([row["interval"] for row in fresh if row["interval"]]),
            "wall_sample_count": sum(row["interval"] is not None for row in fresh),
            "usage_unavailable_reasons": dict(sorted(Counter(
                row["usage_reason"] for row in fresh if any(
                    row["usage"][field] is None for field in USAGE_FIELDS[:3])).items())),
        }

    def grouped(fields: tuple[str, ...]) -> tuple[list[dict[str, Any]], int]:
        groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for row in rows:
            groups.setdefault(tuple(row[field] for field in fields), []).append(row)
        result = [{**dict(zip(fields, key)), **summarize(group)} for key, group in sorted(groups.items())]
        result.sort(key=lambda row: -(row["execution_elapsed"]["sum_ms"] or 0))
        return result[:max_rows], max(0, len(result) - max_rows)

    by_model, omitted_models = grouped(("provider", "model"))
    by_job_role, omitted_roles = grouped(("job", "role"))
    hotspots = {}
    for metric, score in (
        ("time", lambda row: row["elapsed"] or 0),
        ("tokens", lambda row: (row["usage"]["input_tokens"] or 0) + (row["usage"]["output_tokens"] or 0)),
        ("retries", lambda row: int((row["retry"] or 0) > 0)),
    ):
        sums: Counter[tuple[str, str]] = Counter()
        for row in rows:
            if not row["reused"]:
                sums[(row["job"], row["role"])] += score(row)
        hotspots[metric] = [{"job": key[0], "role": key[1], "known_value": value}
                            for key, value in sorted(sums.items(), key=lambda item: (-item[1], item[0]))[:3]
                            if value]
    costs = account_calls(events)["run"]
    return {"totals": summarize(rows), "by_model": by_model, "by_job_role": by_job_role,
            "omitted_model_rows": omitted_models, "omitted_job_role_rows": omitted_roles,
            "hotspots": hotspots, "duplicate_records": duplicates,
            "accounting_complete": accounting_complete, "gaps": dict(sorted(gaps.items())),
            "cost": costs, "credits": None, "credits_reason": "not_reported",
            "interpretation": "retry/invalid-output hotspots merit investigation; not proved waste"}
