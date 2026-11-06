"""Bounded, derived operator views. This module never changes job or run state."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

from appsec_review.observability.costs import account_calls
from appsec_review.observability.diagnostics import execution_event_summary, diagnostic_reference, read_execution_receipt
from appsec_review.observability.events import EventCursor, PipelineLog
from appsec_review.observability.telemetry import validate_event
from appsec_review.reporting.telemetry.inputs import (
    JOB_TERMINALS, RUN_TERMINALS, job_spans, event_timestamp, STATUS_ALIASES,
)
from appsec_review.storage import canonical_json
from appsec_review.storage.atomic import atomic_bytes

SCHEMA = "appsec-review/operator-status/1"
MAX_CHECKPOINT_BYTES = 32 * 1024 * 1024
_ACTIVE = {"STARTED", "STARTING", "MANAGED", "CANCELING"}
_QUEUED = {"QUEUED", "NOT_STARTED"}
_TERMINAL = {"SUCCESS", "FAILURE", "CANCELED", "CANCELLED"}


class OperatorFollower:
    """Retain bounded lifecycle evidence and coalesce only replaceable progress samples."""

    def __init__(self, run_root: Path, *, capacity: int = 10000):
        if not 1 <= capacity <= 100000:
            raise ValueError("operator capacity must be between 1 and 100000")
        self.log, self.capacity = PipelineLog(run_root), capacity
        self.cursor = EventCursor()
        self.records: dict[str, Mapping[str, Any]] = {}
        self.counts: Counter[str] = Counter()
        self.read_status = "not_read"
        self.reset_reason: str | None = None
        self.alert_keys: set[str] = set()

    def save_checkpoint(self, path: Path) -> None:
        state = {"schema": "appsec-review/operator-checkpoint/1", "run_log": str(self.log.path.absolute()),
                 "cursor": asdict(self.cursor), "records": list(self.records.values()),
                 "counts": dict(self.counts), "alert_keys": sorted(self.alert_keys)}
        payload = canonical_json({**state, "sha256": hashlib.sha256(canonical_json(state)).hexdigest()})
        if len(payload) > MAX_CHECKPOINT_BYTES:
            raise ValueError("operator checkpoint exceeds bound")
        atomic_bytes(path, payload)

    def restore_checkpoint(self, path: Path) -> None:
        if path.stat().st_size > MAX_CHECKPOINT_BYTES:
            raise ValueError("operator checkpoint exceeds bound")
        state = json.loads(path.read_bytes())
        digest = state.pop("sha256", None)
        if (state.get("schema") != "appsec-review/operator-checkpoint/1"
                or state.get("run_log") != str(self.log.path.absolute())
                or digest != hashlib.sha256(canonical_json(state)).hexdigest()
                or len(state["records"]) > self.capacity or len(state["alert_keys"]) > 1000):
            raise ValueError("operator checkpoint integrity or scope mismatch")
        cursor = EventCursor(**state["cursor"])
        records = {}
        for record in state["records"]:
            validate_event(record)
            if record["sequence"] > cursor.sequence:
                raise ValueError("operator checkpoint record exceeds cursor")
            records[self._key(record)] = record
        if (any(type(count) is not int or count < 0 for count in state["counts"].values())
                or sum(state["counts"].values()) != cursor.sequence):
            raise ValueError("operator checkpoint counters do not match cursor")
        self.records, self.cursor = records, cursor
        self.counts, self.alert_keys = Counter(state["counts"]), set(state["alert_keys"])

    @staticmethod
    def _key(record: Mapping[str, Any]) -> str:
        if record["event_type"] == "OPERATION_PROGRESS" and record["details"].get("span_id"):
            details = record["details"]
            return "/".join(str(value) for value in (
                record["run_id"], record["job_id"], record["attempt_id"],
                details.get("span_id"), "progress"))
        return str(record["sequence"])

    def poll(self, *, max_records: int = 256, max_bytes: int = 1024 * 1024) -> str:
        page = self.log.follow(self.cursor, max_records=max_records, max_bytes=max_bytes)
        if page.reset_reason:
            self.records.clear()
            self.counts.clear()
            self.alert_keys.clear()
            self.cursor = EventCursor()
        self.reset_reason = page.reset_reason
        for record in page.records:
            validate_event(record)
            if (not isinstance(record["details"], Mapping) or event_timestamp(record["timestamp"]) is None
                    or record["run_id"] != self.log.path.parents[2].name):
                raise ValueError("operator event provenance or timestamp is invalid")
        keys = {self._key(record) for record in page.records}
        if len(self.records.keys() | keys) > self.capacity:
            self.read_status = "capacity_reached"
            return self.read_status
        for record in page.records:
            self.records[self._key(record)] = record
            self.counts[record["event_type"]] += 1
        self.cursor, self.read_status = page.cursor, page.status
        return self.read_status

    def snapshot(self, *, now: datetime | None = None,
                 dispatches: Sequence[Mapping[str, Any]] = (), stale_seconds: int = 3600,
                 alert_after_seconds: int = 3600, max_alerts: int = 100,
                 prices: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if stale_seconds < 1 or alert_after_seconds < 1 or not 1 <= max_alerts <= 1000:
            raise ValueError("operator alert bounds must be positive and bounded")
        if len(dispatches) > 1000:
            raise ValueError("dispatch snapshot exceeds 1000 records")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("operator clock must be timezone-aware")
        run_id = self.log.path.parents[2].name
        events = tuple(sorted(self.records.values(), key=lambda event: event["sequence"]))
        last_start = max((event["sequence"] for event in events if event["event_type"] == "RUN_STARTED"),
                         default=0)
        terminals = [event for event in events
                     if event["event_type"] in RUN_TERMINALS and event["sequence"] > last_start]
        raw_statuses = {str(event["details"].get("completion_status") or RUN_TERMINALS[event["event_type"]])
                        for event in terminals}
        raw_statuses.discard("None")
        statuses = {STATUS_ALIASES.get(status, status) for status in raw_statuses}
        supported = {"SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED", "CANCELLED", "TIMED_OUT", "BLOCKED", "PARTIAL"}
        lifecycle_gaps = []
        if not statuses <= supported:
            statuses = set()
            lifecycle_gaps.append({"reason": "unsupported_run_completion_status"})
        operation = next(iter(statuses)) if len(statuses) == 1 else "CONFLICT" if statuses else "UNKNOWN"
        gaps, failures, references, resources, blocked = [], [], {}, {}, []
        execution_receipts, receipt_gaps = {}, []
        reuse_gaps = []
        units: dict[tuple[str, ...], dict[str, Any]] = {}
        progress = []
        for event in events:
            details, kind = event["details"], event["event_type"]
            if event.get("step_id") or event.get("task_id"):
                key = tuple(str(event.get(name) or "-") for name in (
                    "job_id", "attempt_id", "step_id", "task_id"))
                unit = units.setdefault(key, {
                    **dict(zip(("job_id", "attempt_id", "step_id", "task_id"), key)),
                    "reported_status": "UNKNOWN", "last_event": None, "last_update": None})
                unit.update(last_event=kind, last_update=event["timestamp"])
                if kind == "TASK_STARTED":
                    unit["reported_status"] = "RUNNING"
                elif kind.startswith("TASK_") and kind.endswith((
                    "SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "FAILED", "REUSED", "TIMED_OUT", "CANCELLED"
                )):
                    unit["reported_status"] = details.get("completion_status") or kind.removeprefix("TASK_")
            stamp = event_timestamp(event["timestamp"])
            if kind in {"OPERATION_PROGRESS", "JOB_STARTED", "TASK_STARTED", "TASK_COMPLETED",
                        "TASK_COMPLETED_WITH_GAPS", "TOOL_INVOCATION_COMPLETED", "MODEL_CALL_COMPLETED"}:
                progress.append(stamp)
            disposition = details.get("completion_status") or details.get("coverage_disposition")
            if kind in {"JOB_REUSED", "TASK_REUSED"} and disposition not in supported:
                reuse_gaps.append({"event_id": event["event_id"], "job_id": event["job_id"],
                                   "attempt_id": event["attempt_id"], "reason": "reuse_completion_unavailable"})
            for name in ("handoff_sha256", "receipt_sha256", "artifact_sha256"):
                reference = diagnostic_reference({"sha256": details.get(name)})
                if reference:
                    references[reference["sha256"]] = {
                        **reference, "reuse_eligibility": "not_verified_by_status_view"}
            if "BLOCKED" in kind or kind in {"RESOURCE_TIMED_OUT", "RESOURCE_QUARANTINED"}:
                blocked.append({"event_id": event["event_id"], "job_id": event["job_id"],
                                "attempt_id": event["attempt_id"], "step_id": event.get("step_id"),
                                "task_id": event.get("task_id"), "reason_event": kind,
                                "safe_action": "inspect_owner_and_admission_receipt_before_retry"})
            if ("GAP" in kind or disposition in {"COMPLETED_WITH_GAPS", "GAP", "PARTIAL", "BLOCKED"}
                    or details.get("gap_count") or details.get("gaps")):
                gaps.append({"event_id": event["event_id"], "job_id": event["job_id"],
                             "attempt_id": event["attempt_id"], "source": "declared_gap",
                             "reused": "REUSED" in kind})
            outcome = execution_event_summary(event)
            if outcome["category"] in {"failure", "exit_failure", "timeout", "oom", "cancelled"} or kind.endswith(
                ("FAILED", "TIMED_OUT", "CANCELLED", "CANCELED")
            ):
                failures.append({"event_id": event["event_id"], "job_id": event["job_id"],
                                 "attempt_id": event["attempt_id"], "event_type": kind, **outcome})
            for name in ("receipt", "execution_receipt", "metrics_receipt", "handoff", "artifact"):
                ref = diagnostic_reference(details.get(name))
                if ref:
                    references[ref["sha256"]] = {**ref, "reuse_eligibility": "not_verified_by_status_view"}
                    if name in {"execution_receipt", "metrics_receipt"} and ref["sha256"] not in execution_receipts:
                        if len(execution_receipts) + len(receipt_gaps) >= 16:
                            if "receipt_read_limit_reached" not in receipt_gaps:
                                receipt_gaps.append("receipt_read_limit_reached")
                        else:
                            try:
                                execution_receipts[ref["sha256"]] = read_execution_receipt(
                                    self.log.path.parents[2], details[name])
                            except (OSError, ValueError) as exc:
                                receipt_gaps.append(f"receipt_unavailable:{ref['sha256']}:{type(exc).__name__}")
            lease = details.get("resource_lease_id") or (
                details.get("span_id") if kind.startswith("RESOURCE_") else None)
            if lease and (kind.startswith("RESOURCE_") or str(lease) not in resources):
                resources[str(lease)] = {
                    "lease_id": str(lease), "job_id": event["job_id"], "attempt_id": event["attempt_id"],
                    "last_event": kind, "timestamp": event["timestamp"],
                    "cleanup": "confirmed" if kind in {"RESOURCE_RELEASED", "RESOURCE_CLEANUP_CONFIRMED"}
                    else "not_acquired" if kind == "RESOURCE_TIMED_OUT"
                    else "unconfirmed"}
        known_stamps = [stamp for stamp in progress if stamp is not None and stamp <= now]
        last_progress = max(known_stamps, default=None)
        age = (now - last_progress).total_seconds() if last_progress else None
        selected = []
        for dispatch in dispatches:
            tags = {item["key"]: item["value"] for item in dispatch.get("tags", [])}
            if tags.get("appsec/application_run_id") == run_id:
                selected.append({name: dispatch.get(name) for name in (
                    "runId", "status", "startTime", "endTime")})
        states = {item["status"] for item in selected}
        caught_up = self.read_status == "caught_up"
        if not caught_up:
            operation = "UNKNOWN"
        conflict = operation == "CONFLICT" or bool(terminals and states & (_ACTIVE | _QUEUED))
        if conflict:
            liveness, action = "conflicting_evidence", "reconcile_dispatch_and_application_receipts"
        elif operation != "UNKNOWN":
            liveness, action = "terminal", "inspect_declared_gaps_and_accepted_evidence"
        elif states & _ACTIVE:
            liveness, action = "active", "observe_progress_do_not_restart"
        elif states & _QUEUED:
            liveness, action = "queued", "inspect_orchestrator_queue"
        elif states and states <= _TERMINAL:
            liveness, action = "interrupted_or_unconfirmed", "reconcile_dispatch_and_application_receipts"
        elif age is not None and age <= stale_seconds:
            liveness, action = "recent_progress", "observe_progress_do_not_restart"
        else:
            liveness, action = "unknown", "verify_process_and_orchestrator_before_recovery"
        jobs = [asdict(span) for span in job_spans(events)]
        attempts = Counter(row["job_id"] for row in jobs)
        job_terminals: dict[tuple[str, str], set[str]] = {}
        for event in events:
            if event["event_type"] in JOB_TERMINALS:
                key = (event["job_id"], event["attempt_id"])
                job_terminals.setdefault(key, set()).add(JOB_TERMINALS[event["event_type"]])
        for job in jobs:
            job["retry_attempts_observed"] = max(0, attempts[job["job_id"]] - 1)
            key = (job["job_id"], job["attempt_id"])
            if len(job_terminals.get(key, ())) > 1:
                job["status"] = "CONFLICT"
                lifecycle_gaps.append({"job_id": key[0], "attempt_id": key[1],
                                       "reason": "conflicting_job_terminals"})
            elif liveness == "terminal" and job["status"] == "RUNNING":
                lifecycle_gaps.append({"job_id": key[0], "attempt_id": key[1],
                                       "reason": "missing_job_terminal"})
        if lifecycle_gaps and operation == "SUCCEEDED":
            operation = "UNKNOWN"
        candidates = []
        if caught_up and states & _ACTIVE and (age is None or age >= alert_after_seconds):
            candidates.append(("progress_unconfirmed", run_id))
        for lease, resource in resources.items():
            stamp = event_timestamp(resource["timestamp"])
            if (resource["cleanup"] == "unconfirmed" and liveness == "terminal" and stamp
                    and (now - stamp).total_seconds() >= alert_after_seconds):
                candidates.append(("cleanup_unconfirmed", lease))
        alerts = []
        for category, identity in candidates:
            key = hashlib.sha256(canonical_json([run_id, last_start, category, identity])).hexdigest()
            if key not in self.alert_keys and len(self.alert_keys) < max_alerts:
                self.alert_keys.add(key)
                alerts.append({"id": key, "category": category, "action":
                               "verify_cleanup_and_resource_owner_before_release"
                               if category == "cleanup_unconfirmed" else action})
        return {
            "schema": SCHEMA, "run_id": run_id, "operational_status": operation,
            "analysis_completeness": "declared_gaps" if gaps else "unknown" if reuse_gaps or receipt_gaps else
            "no_declared_gaps_not_proof_of_coverage" if caught_up and operation == "SUCCEEDED" else "unknown",
            "liveness": liveness, "safe_action": action, "dispatches": selected, "jobs": jobs,
            "units": list(units.values()),
            "last_progress": last_progress.isoformat() if last_progress else None,
            "progress_age_seconds": age, "event_counts": dict(self.counts),
            "gaps": gaps, "failures": failures, "reusable_evidence": list(references.values()),
            "blocked": blocked,
            "execution_receipts": list(execution_receipts.values()), "receipt_gaps": receipt_gaps,
            "reuse_gaps": reuse_gaps,
            "lifecycle_gaps": lifecycle_gaps,
            "resources": list(resources.values()), "alerts": alerts,
            "alert_capacity_reached": len(self.alert_keys) >= max_alerts,
            "costs": account_calls(events, prices=prices),
            "coverage": {"status": self.read_status, "reset_reason": self.reset_reason,
                         "cursor": asdict(self.cursor), "retained_records": len(self.records),
                         "progress_samples_coalesced": True},
        }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=5)
    parser.add_argument("--pages", type=int, default=1)
    parser.add_argument("--capacity", type=int, default=10000)
    parser.add_argument("--dispatches", type=Path, help="Recorded Dagster results; never queried implicitly")
    parser.add_argument("--prices", type=Path, help="Opt in to a versioned API estimate table")
    parser.add_argument("--checkpoint", type=Path, help="Persist bounded derived state and cursor together")
    args = parser.parse_args(argv)
    if not 0.1 <= args.interval <= 3600 or not 1 <= args.pages <= 100:
        parser.error("interval must be 0.1..3600 seconds and pages 1..100")
    follower = OperatorFollower(args.run, capacity=args.capacity)
    if args.checkpoint and args.checkpoint.exists():
        follower.restore_checkpoint(args.checkpoint)
    prices = json.loads(args.prices.read_text()) if args.prices else None
    while True:
        for _ in range(args.pages):
            if follower.poll() != "backlog":
                break
        dispatches = json.loads(args.dispatches.read_text()) if args.dispatches else []
        print(json.dumps(follower.snapshot(dispatches=dispatches, prices=prices), sort_keys=True), flush=True)
        if args.checkpoint:
            follower.save_checkpoint(args.checkpoint)
        if not args.watch or follower.read_status == "capacity_reached":
            return 0 if follower.read_status == "caught_up" else 2
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
