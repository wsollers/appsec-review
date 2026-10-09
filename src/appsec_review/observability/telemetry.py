from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import math
from pathlib import Path
from typing import Any, Mapping

from appsec_review.observability.events import PipelineLog
from appsec_review.storage import atomic_json, canonical_json


SCHEMA = "appsec-review/telemetry-event/1"
FINDING_STATES = {"CANDIDATE", "REFUTED", "CONFIRMED"}
TERMINAL_EVENTS = {"SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "FAILED",
                   "BLOCKED", "PARTIAL", "NOT_APPLICABLE"}


def validate_event(record: Mapping[str, Any]) -> None:
    required = {"schema", "sequence", "timestamp", "event_type", "event_id", "run_id",
                "job_id", "attempt_id", "trigger", "orchestrator", "details"}
    if record.get("schema") != SCHEMA or not required <= set(record):
        raise ValueError("unsupported or incomplete telemetry event")
    if not isinstance(record["sequence"], int) or record["sequence"] < 1:
        raise ValueError("telemetry sequence is invalid")
    if len(str(record["event_id"])) != 64:
        raise ValueError("telemetry event identity is invalid")


def identity_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class FindingLifecycle:
    """Append-only finding state transitions; scanner observations are never findings."""

    def __init__(self, run_root: Path):
        self.log = PipelineLog(run_root)

    def transition(self, *, run_id: str, finding_package_id: str, new_state: str,
                   evidence_identities: tuple[str, ...], actor_class: str,
                   reason_hash: str, job_id: str = "finding_lifecycle",
                   attempt_id: str = "-") -> Mapping[str, Any]:
        if new_state not in FINDING_STATES:
            raise ValueError("invalid finding state")
        if actor_class not in {"deterministic", "model", "human"}:
            raise ValueError("invalid finding actor class")
        if not finding_package_id or not evidence_identities or len(reason_hash) != 64:
            raise ValueError("finding transition requires package, evidence, and reason identities")
        records, _ = self.log.read()
        transitions = [item for item in records if item.get("event_type") == "FINDING_TRANSITION" and
                       item.get("details", {}).get("finding_package_id") == finding_package_id]
        prior = transitions[-1]["details"]["new_state"] if transitions else None
        if prior == new_state:
            candidate_hash = identity_hash({"state": new_state,
                                            "evidence_identities": sorted(evidence_identities),
                                            "reason_hash": reason_hash})
            if transitions[-1]["details"].get("transition_hash") != candidate_hash:
                raise ValueError("finding transition conflicts with the existing terminal state")
            return transitions[-1]
        allowed = prior is None and new_state == "CANDIDATE" or prior == "CANDIDATE" and new_state in {"REFUTED", "CONFIRMED"}
        if not allowed:
            raise ValueError(f"invalid finding transition: {prior or 'NONE'} -> {new_state}")
        transition_hash = identity_hash({"state": new_state,
                                         "evidence_identities": sorted(evidence_identities),
                                         "reason_hash": reason_hash})
        return self.log.write("FINDING_TRANSITION", run_id=run_id, job_id=job_id,
                              attempt_id=attempt_id, details={
            "finding_package_id": finding_package_id, "prior_state": prior, "new_state": new_state,
            "evidence_identities": sorted(evidence_identities),
            "evidence_count": len(set(evidence_identities)), "actor_class": actor_class,
            "reason_hash": reason_hash, "transition_hash": transition_hash,
        })


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(max(0, int(value)) for value in values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _operation_identity(record: Mapping[str, Any]) -> str:
    details = record.get("details", {})
    return "/".join(str(value or "-") for value in (
        record.get("job_id"), record.get("step_id"), record.get("task_id"),
        details.get("tool_id") or details.get("operation_id") or "-",
    ))


def aggregate_run_metrics(run_root: Path) -> Mapping[str, Any]:
    records, torn = PipelineLog(run_root).read()
    for record in records:
        validate_event(record)
    event_counts = Counter(str(record["event_type"]) for record in records)
    dispositions = Counter()
    tool_calls = Counter()
    finding_states = Counter()
    durations_ms = Counter()
    tokens = Counter()
    domain_counts = Counter()
    throughput_counts = Counter()
    operation_durations: dict[str, list[int]] = {}
    task_intervals: list[tuple[datetime, datetime, str, int]] = []
    starts: dict[tuple[str, str, str, str], list[datetime]] = {}
    job_bounds: dict[str, list[datetime]] = {}
    queue_delays: list[int] = []
    reuse = Counter()
    for record in records:
        details = record.get("details", {})
        disposition = details.get("disposition") or details.get("terminal_status") or details.get("completion_status")
        if disposition:
            dispositions[str(disposition)] += 1
        if record["event_type"] in {"TOOL_INVOCATION_COMPLETED", "MCP_TOOL_COMPLETED"}:
            tool_calls[str(details.get("tool_id") or details.get("mcp_tool") or "unknown")] += 1
        if record["event_type"] == "FINDING_TRANSITION":
            finding_states[str(details.get("new_state"))] += 1
        if isinstance(details.get("duration_ms"), int):
            durations_ms[str(record["event_type"])] += details["duration_ms"]
            identity = _operation_identity(record)
            operation_durations.setdefault(identity, []).append(details["duration_ms"])
        if isinstance(details.get("queue_delay_ms"), int):
            queue_delays.append(max(0, details["queue_delay_ms"]))
        if record["event_type"].endswith("REUSED") or details.get("checkpoint_reused") is True:
            reuse["hits"] += 1
        elif "reuse" in details and details.get("reuse") is False:
            reuse["misses"] += 1
        for key in ("input_tokens", "output_tokens", "cache_tokens"):
            if isinstance(details.get(key), int):
                tokens[key] += details[key]
        for key in ("inspected_count", "check_count", "observation_count", "confirmed_count",
                    "refuted_count", "unvalidated_count", "gap_count", "truncated_count",
                    "resumption_count"):
            if isinstance(details.get(key), int):
                domain_counts[key] += details[key]
        for key in ("file_count", "artifact_count", "shard_count", "processed_count", "size_bytes",
                    "processed_bytes", "saved_count", "saved_bytes"):
            if isinstance(details.get(key), int):
                throughput_counts[key] += details[key]
        timestamp = datetime.fromisoformat(str(record["timestamp"]))
        job = str(record.get("job_id", "-"))
        job_bounds.setdefault(job, []).append(timestamp)
        event = str(record["event_type"])
        family = event.split("_", 1)[0]
        key = (family, job, str(record.get("step_id") or "-"), str(record.get("task_id") or "-"))
        if event.endswith("STARTED"):
            starts.setdefault(key, []).append(timestamp)
        elif event.endswith(("SUCCEEDED", "FAILED", "COMPLETED", "COMPLETED_WITH_GAPS",
                             "CANCELED", "CANCELLED", "TIMED_OUT")):
            pending = starts.get(key, [])
            if pending:
                begun = pending.pop(0)
                if family == "TASK":
                    task_intervals.append((begun, timestamp, _operation_identity(record),
                                           max(0, int((timestamp - begun).total_seconds() * 1000))))
    timestamps = [datetime.fromisoformat(str(item["timestamp"])) for item in records]
    wall_ms = max(0, int((max(timestamps) - min(timestamps)).total_seconds() * 1000)) if timestamps else 0
    summed_task_ms = sum(item[3] for item in task_intervals)
    operation_summaries = [{"operation": identity, "count": len(values),
                            "p50_ms": _percentile(values, .50),
                            "p95_ms": _percentile(values, .95), "max_ms": max(values)}
                           for identity, values in sorted(operation_durations.items())]
    operation_summaries.sort(key=lambda item: (-int(item["p95_ms"] or 0), item["operation"]))
    job_spans = {job: max(0, int((max(values) - min(values)).total_seconds() * 1000))
                 for job, values in job_bounds.items() if values}
    genuinely_running = [{"family": key[0], "job_id": key[1], "step_id": key[2], "task_id": key[3],
                          "started_at": value.isoformat()}
                         for key, values in sorted(starts.items()) for value in values]
    critical = max(task_intervals, key=lambda item: item[3], default=None)
    return {"schema": "appsec-review/run-metrics/2", "run_id": Path(run_root).name,
            "event_count": len(records), "event_counts": dict(sorted(event_counts.items())),
            "dispositions": dict(sorted(dispositions.items())),
            "tool_calls": dict(sorted(tool_calls.items())),
            "finding_states": dict(sorted(finding_states.items())),
            "duration_ms_by_event": dict(sorted(durations_ms.items())),
            "model_tokens": dict(sorted(tokens.items())),
            "domain_counts": dict(sorted(domain_counts.items())),
            "throughput_totals": dict(sorted(throughput_counts.items())),
            "wall_time_ms": wall_ms, "summed_concurrent_task_ms": summed_task_ms,
            "job_family_wall_span_ms": dict(sorted(job_spans.items())),
            "queue_delay_ms": {"count": len(queue_delays), "p50": _percentile(queue_delays, .50),
                               "p95": _percentile(queue_delays, .95),
                               "max": max(queue_delays) if queue_delays else None},
            "reuse": dict(sorted(reuse.items())), "operations": operation_summaries[:200],
            "critical_path_candidate": (None if critical is None else
                {"operation": critical[2], "duration_ms": critical[3],
                 "contribution_ratio": round(critical[3] / wall_ms, 6) if wall_ms else None}),
            "genuinely_running": genuinely_running[:200],
            "completed_work_count": sum(1 for item in records if str(item["event_type"]).endswith(
                ("SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "REUSED"))),
            "torn_tail_ignored": torn}


def write_run_metrics(run_root: Path) -> Mapping[str, Any]:
    """Persist a cheap, redacted, derivable summary beside the authoritative event stream."""
    report = aggregate_run_metrics(run_root)
    atomic_json(Path(run_root) / "data" / "telemetry" / "summary.json", report)
    return report


def emit_model_event(log: PipelineLog, *, event_type: str, run_id: str, invocation_id: str,
                     provider: str, model: str, reasoning_level: str,
                     guidance_bundle_sha256: str, request_sha256: str,
                     terminal_status: str | None = None, duration_ms: int | None = None,
                     retry_count: int = 0, input_tokens: int | None = None,
                     output_tokens: int | None = None, cache_tokens: int | None = None,
                     error_class: str | None = None, **correlation: Any) -> Mapping[str, Any]:
    if event_type not in {"MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"}:
        raise ValueError("invalid model telemetry event")
    details = {"model_invocation_id": invocation_id, "provider": provider, "model": model,
               "reasoning_level": reasoning_level, "guidance_bundle_sha256": guidance_bundle_sha256,
               "request_sha256": request_sha256, "retry_count": retry_count,
               "terminal_status": terminal_status, "duration_ms": duration_ms,
               "input_tokens": input_tokens, "output_tokens": output_tokens,
               "cache_tokens": cache_tokens, "error_class": error_class, **correlation}
    return log.write(event_type, run_id=run_id, job_id=str(correlation.get("job_id", "inference")),
                     attempt_id=str(correlation.get("attempt_id", "-")), details=details)
