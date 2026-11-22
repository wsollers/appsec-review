"""One bounded, read-only run poll and concise report. Scheduling belongs to the owning agent."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from uuid import UUID

from appsec_review.observability.model_metrics import aggregate_model_calls, label, USAGE_FIELDS
from appsec_review.observability.monitor_inputs import frozen_inputs, read_json
from appsec_review.observability.operator import OperatorFollower
from appsec_review.reporting.telemetry.inputs import event_timestamp, JOB_TERMINALS, RUN_TERMINALS, STATUS_ALIASES
from appsec_review.storage import atomic_json

SCHEMA = "appsec-review/run-monitor/1"
_FINISHED = {"SUCCEEDED", "COMPLETED_WITH_GAPS", "NOT_APPLICABLE", "FAILED",
             "CANCELLED", "TIMED_OUT", "BLOCKED", "PARTIAL"}
_STATE_DIR = "data/telemetry/monitor"


class MonitorFollower(OperatorFollower):
    """Reuse the validated incremental cursor; retain lifecycle, coalesce incidental log samples."""

    @staticmethod
    def _key(record: Mapping[str, Any]) -> str:
        kind = record["event_type"]
        if (kind.startswith(("MODEL_CALL_", "JOB_", "TASK_", "RUN_", "GRAPH_", "RESOURCE_"))
                or "BLOCKED" in kind or kind.endswith(("FAILED", "TIMED_OUT", "CANCELLED"))):
            return OperatorFollower._key(record)
        if kind == "OPERATION_PROGRESS":
            return OperatorFollower._key(record)
        return "latest/" + "/".join(str(record.get(key) or "-") for key in
                                   ("job_id", "attempt_id", "step_id", "task_id"))

    def _project(self) -> None:
        identity_fields = {
            "dagster_run_id", "unit_id", "model_invocation_id", "invocation_id", "span_id",
            "provider", "model", "served_provider", "served_model", "role", "execution_mode",
            "terminal_status", "completion_status", "usage_unavailable_reason", "failure_category",
            "request_sha256", "billing_mode",
        }
        measurements = {*USAGE_FIELDS, "retry_count", "duration_ms", "call_latency_ms", "queue_delay_ms"}
        for key, event in self.records.items():
            details = event["details"]
            projected = {name: label(details[name]) if details[name] is not None else None
                         for name in identity_fields & details.keys()}
            # Invalid measurements must remain unavailable, not copied provider payloads.
            from appsec_review.observability.model_metrics import number
            projected.update({name: number(details[name]) for name in measurements & details.keys()})
            ref = details.get("graph_reference")
            if isinstance(ref, Mapping):
                path, sha = ref.get("path"), ref.get("sha256")
                if (isinstance(path, str) and re.fullmatch(r"data/configuration/graphs/[a-f0-9]{64}\.json", path)
                        and isinstance(sha, str) and re.fullmatch(r"[a-f0-9]{64}", sha)):
                    projected["graph_reference"] = {"path": path, "sha256": sha}
            charge = details.get("provider_charge")
            if isinstance(charge, Mapping):
                amount = charge.get("amount")
                if (type(amount) in (int, float, str) and len(str(amount)) <= 64
                        and re.fullmatch(r"[0-9.eE+-]+", str(amount))):
                    projected["provider_charge"] = {
                        "amount": amount, "currency": label(charge.get("currency")),
                        "source": label(charge.get("source"))}
            self.records[key] = {
                **{name: event[name] for name in ("schema", "sequence", "event_id", "timestamp")},
                **{name: label(event.get(name)) if event.get(name) is not None else None for name in
                   ("run_id", "job_id", "attempt_id", "step_id", "task_id", "trigger", "orchestrator")},
                "event_type": label(event["event_type"]), "details": projected}

    def poll(self, **bounds: Any) -> str:
        status = super().poll(**bounds)
        self._project()
        return status

    def restore_checkpoint(self, path: Path) -> None:
        super().restore_checkpoint(path)
        self._project()


def _age(now: datetime, stamp: str | None) -> float | None:
    parsed = event_timestamp(stamp)
    return max(0, (now - parsed).total_seconds()) if parsed else None


def _state(events: Sequence[Mapping[str, Any]], graph: Mapping[str, Any] | None,
           *, now: datetime, complete: bool, max_rows: int) -> dict[str, Any]:
    attempts: dict[tuple[str, str], dict[str, Any]] = {}
    units: dict[tuple[str, ...], dict[str, Any]] = {}
    gaps: Counter[str] = Counter()
    run_status = "UNKNOWN"
    run_epoch = 0
    graph_dispatch = None
    terminals: set[str] = set()
    blocked = []
    reused_units: set[tuple[str, ...]] = set()
    for event in events:
        kind, details, stamp = event["event_type"], event["details"], event["timestamp"]
        progress_event = kind in {
            "OPERATION_PROGRESS", "JOB_STARTED", "TASK_STARTED", "TASK_COMPLETED", "TASK_SUCCEEDED",
            "TASK_COMPLETED_WITH_GAPS", "TASK_FAILED", "MODEL_CALL_COMPLETED", "TOOL_INVOCATION_COMPLETED",
        } or kind in JOB_TERMINALS
        if (kind == "RUN_GRAPH_SNAPSHOT" and details.get("dagster_run_id")
                and details["dagster_run_id"] != graph_dispatch):
            graph_dispatch = details["dagster_run_id"]
            run_status, run_epoch, terminals = "ACTIVE_UNCONFIRMED", event["sequence"], set()
        if kind == "RUN_STARTED":
            run_status, run_epoch, terminals = "ACTIVE_UNCONFIRMED", event["sequence"], set()
        if kind in RUN_TERMINALS:
            status = details.get("completion_status") or RUN_TERMINALS[kind]
            status = STATUS_ALIASES.get(status, status)
            if status in _FINISHED:
                terminals.add(status)
                run_status = status if len(terminals) == 1 else "CONFLICT"
            else:
                gaps["unsupported_run_status"] += 1
        job, attempt = event["job_id"], event["attempt_id"]
        if job == "-" or attempt == "-":
            continue
        key = (job, attempt)
        row = attempts.setdefault(key, {
            "job": label(job), "attempt": label(attempt), "status": "UNKNOWN",
            "started_at": None, "last_progress": None, "last_event_at": stamp, "last_sequence": event["sequence"],
            "reused": False, "terminals": set()})
        row["last_event_at"], row["last_sequence"] = stamp, event["sequence"]
        if progress_event:
            row["last_progress"] = stamp
        if kind == "JOB_STARTED":
            row["started_at"] = row["started_at"] or stamp
            row["status"] = "RUNNING"
        elif kind in JOB_TERMINALS or kind in {"JOB_NOT_APPLICABLE", "JOB_BLOCKED", "JOB_PARTIAL"}:
            status = details.get("completion_status") or JOB_TERMINALS.get(kind, kind.removeprefix("JOB_"))
            status = STATUS_ALIASES.get(status, status)
            if status in _FINISHED:
                row["terminals"].add(status)
                row["status"] = status if len(row["terminals"]) == 1 else "CONFLICT"
            else:
                row["status"] = "UNKNOWN"
                gaps["unsupported_job_status"] += 1
        elif kind == "JOB_QUEUED":
            row["status"] = "QUEUED"
        elif kind == "JOB_REUSED":
            row["reused"] = True
            status = details.get("completion_status")
            if status in _FINISHED and not row["terminals"]:
                row["status"] = status
            elif not row["terminals"]:
                row["status"] = "REUSED_UNKNOWN"
                gaps["reused_completion_unavailable"] += 1
        if kind == "TASK_REUSED":
            reused_units.add((*key, str(details.get("unit_id") or event.get("step_id")),
                              str(event.get("task_id"))))
        step, task = event.get("step_id"), event.get("task_id")
        if step or task or details.get("unit_id"):
            unit_key = (*key, str(step or "-"), str(task or details.get("unit_id") or "-"))
            unit = units.setdefault(unit_key, {
                "job": label(job), "attempt": label(attempt), "step": label(step), "task": label(
                    task or details.get("unit_id")), "status": "UNKNOWN", "started_at": None})
            unit.setdefault("last_progress", None)
            if progress_event:
                unit["last_progress"] = stamp
            if kind == "TASK_STARTED":
                unit["status"], unit["started_at"] = "RUNNING", stamp
            elif kind.startswith("TASK_") and kind != "TASK_PROGRESS":
                unit["status"] = kind.removeprefix("TASK_")
        if "BLOCKED" in kind or kind in {"RESOURCE_TIMED_OUT", "RESOURCE_QUARANTINED"}:
            blocked.append({"job": label(job), "event": label(kind), "timestamp": stamp})
    latest: dict[str, dict[str, Any]] = {}
    for row in attempts.values():
        if row["status"] == "CONFLICT":
            gaps["conflicting_job_terminals"] += 1
        if row["status"] == "RUNNING" and run_status in _FINISHED:
            gaps["missing_job_terminal"] += 1
            row["status"] = "UNCONFIRMED"
        if row["job"] not in latest or row["last_sequence"] > latest[row["job"]]["last_sequence"]:
            latest[row["job"]] = row
    selected = graph["jobs"] if graph else None
    if selected is not None:
        outside = set(latest) - set(selected)
        if outside:
            gaps["observed_jobs_outside_frozen_graph"] = len(outside)
    partition = Counter(latest[job]["status"] if job in latest else "REMAINING"
                        for job in selected) if selected else Counter()
    completed = sum(partition[state] for state in _FINISHED)
    active = [row for row in latest.values() if row["status"] in {"RUNNING", "QUEUED", "UNCONFIRMED"}]
    active.sort(key=lambda row: (row["started_at"] or row["last_event_at"], row["job"]))
    current_units = []
    for unit in units.values():
        if unit["status"] == "RUNNING":
            if latest.get(unit["job"], {}).get("attempt") != unit["attempt"]:
                continue
            current_units.append({**unit, "elapsed_seconds": _age(now, unit["started_at"]),
                                  "progress_age_seconds": _age(now, unit["last_progress"])})
    reliable = complete and selected is not None and not gaps and run_status != "CONFLICT"
    return {
        "status": run_status if complete else "UNKNOWN", "run_epoch_sequence": run_epoch,
        "terminal_confirmed": complete and run_status in _FINISHED and not gaps["unsupported_run_status"],
        "jobs": {"total": len(selected) if selected is not None else None,
                 "completed": completed if selected is not None else None,
                 "running": partition["RUNNING"] if selected is not None else None,
                 "remaining": len(selected) - completed - partition["RUNNING"] if selected is not None else None,
                 "by_status": dict(sorted(partition.items())), "accounting_complete": reliable},
        "attempts": {"total_observed": len(attempts),
                     "by_status": dict(sorted(Counter(row["status"] for row in attempts.values()).items())),
                     "reused": sum(row["reused"] for row in attempts.values()),
                     "retry_attempts": len(attempts) - len(latest), "reused_tasks": len(reused_units)},
        "current": [{key: value for key, value in row.items() if key != "terminals"} | {
            "elapsed_seconds": _age(now, row["started_at"]),
            "progress_age_seconds": _age(now, row["last_progress"])} for row in active[:max_rows]],
        "current_steps": current_units[:max_rows],
        "omitted_current_rows": max(0, len(active) - max_rows),
        "omitted_step_rows": max(0, len(current_units) - max_rows),
        "blocked": blocked[-3:], "omitted_blockage_rows": max(0, len(blocked) - 3),
        "gaps": dict(sorted(gaps.items())),
    }


def snapshot_delta(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> dict[str, Any]:
    reason = None
    if not isinstance(previous, Mapping) or previous.get("schema") != SCHEMA:
        reason = "previous_snapshot_unavailable_or_invalid"
    elif (any(not isinstance(previous.get(key), Mapping) for key in ("coverage", "state", "models"))
          or not isinstance(previous["models"].get("totals"), Mapping)
          or not isinstance(previous["state"].get("jobs"), Mapping)
          or type(previous["coverage"].get("sequence")) is not int):
        reason = "previous_snapshot_unavailable_or_invalid"
    elif any(current.get(key) != previous.get(key) for key in
             ("run_id", "dagster_run_id", "configuration_sha256", "source_sha256", "graph_sha256")):
        reason = "snapshot_scope_changed"
    elif any(current.get(key) is None for key in ("configuration_sha256", "source_sha256", "graph_sha256")):
        reason = "snapshot_identity_unavailable"
    elif (current["coverage"]["reset_reason"]
          or current["coverage"]["generation"] != previous.get("coverage", {}).get("generation")
          or current["state"]["run_epoch_sequence"] != previous.get("state", {}).get("run_epoch_sequence")
          or current["coverage"]["sequence"] < previous.get("coverage", {}).get("sequence", 0)):
        reason = "counter_reset_or_restart"
    elif not current["coverage"]["complete"] or not previous.get("coverage", {}).get("complete"):
        reason = "incomplete_event_coverage"
    elif (event_timestamp(previous.get("observed_at")) is None
          or event_timestamp(current["observed_at"]) <= event_timestamp(previous["observed_at"])):
        reason = "observation_clock_not_increasing"
    if reason:
        return {"available": False, "reason": reason}
    if not current["models"]["accounting_complete"] or not previous.get("models", {}).get("accounting_complete"):
        return {"available": False, "reason": "incomplete_model_accounting"}
    totals, prior = current["models"]["totals"], previous.get("models", {}).get("totals", {})
    if not isinstance(prior.get("usage"), Mapping):
        return {"available": False, "reason": "previous_snapshot_unavailable_or_invalid"}
    differences = {}
    for field in ("fresh_calls", "retry_calls", "reused_calls"):
        if type(prior.get(field)) is not int or totals[field] < prior[field]:
            return {"available": False, "reason": "counter_reset_or_invalid_snapshot"}
        differences[field] = totals[field] - prior[field]
    usage = {}
    for field in USAGE_FIELDS:
        new, old = totals["usage"][field], prior.get("usage", {}).get(field, {})
        if not isinstance(old, Mapping):
            return {"available": False, "reason": "previous_snapshot_unavailable_or_invalid"}
        usage[field] = (new["known_sum"] - old["known_sum"] if not new["lower_bound"]
                        and old.get("lower_bound") is False and type(old.get("known_sum")) is int
                        and new["known_sum"] is not None and new["known_sum"] >= old["known_sum"] else None)
    before_jobs, after_jobs = previous.get("state", {}).get("jobs", {}), current["state"]["jobs"]
    completed = (after_jobs["completed"] - before_jobs["completed"]
                 if after_jobs["accounting_complete"] and before_jobs.get("accounting_complete")
                 and type(before_jobs.get("completed")) is int else None)
    return {"available": True, "since": previous["observed_at"], **differences,
            "completed_jobs": completed, "usage": usage, "usage_null_reason": "incomplete_or_unreported_usage"}


def poll_run(run_root: Path, *, dagster_run_id: str | None = None, save: bool = False,
             pages: int = 16, max_rows: int = 8, now: datetime | None = None) -> dict[str, Any]:
    if not 1 <= pages <= 100 or not 1 <= max_rows <= 30:
        raise ValueError("monitor bounds: pages 1..100, rows 1..30")
    if not run_root.is_dir():
        raise ValueError("explicit application run directory does not exist")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("monitor observation clock must be timezone aware")
    if dagster_run_id is not None:
        dagster_run_id = str(UUID(dagster_run_id))
    follower = MonitorFollower(run_root, capacity=20000)
    checkpoint = run_root / _STATE_DIR / "checkpoint.json"
    previous = None
    gaps: list[str] = []
    try:
        previous, _ = read_json(run_root, f"{_STATE_DIR}/snapshot.json")
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        gaps.append("previous_snapshot_invalid")
    if checkpoint.exists():
        try:
            # read_json also checks run-root custody; the follower verifies its digest and cursor.
            read_json(run_root, f"{_STATE_DIR}/checkpoint.json", limit=32 * 1024 * 1024)
            follower.restore_checkpoint(checkpoint)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            follower = MonitorFollower(run_root, capacity=20000)
            gaps.append("checkpoint_invalid_replaying_bounded_prefix")
    reset_reason = None
    try:
        for _ in range(pages):
            status = follower.poll()
            reset_reason = follower.reset_reason or reset_reason
            if status != "backlog":
                break
    except (OSError, ValueError, KeyError, TypeError):
        follower.read_status = "invalid_or_unreadable"
        gaps.append("pipeline_invalid_or_unreadable")
    events = sorted(follower.records.values(), key=lambda item: item["sequence"])
    if any(event_timestamp(event["timestamp"]) > now for event in events):
        gaps.append("future_event_timestamp")
    complete = follower.read_status == "caught_up" and not gaps
    identities = frozen_inputs(run_root, events, max_rows=max_rows)
    graph = identities.pop("graph")
    graph_dagster = graph.get("dagster_run_id") if graph else None
    if dagster_run_id and graph_dagster and dagster_run_id != graph_dagster:
        gaps.append("dagster_graph_identity_mismatch")
        graph, complete = None, False
    dagster_run_id = dagster_run_id or graph_dagster
    last_event = events[-1]["timestamp"] if events else None
    state = _state(events, graph, now=now, complete=complete, max_rows=max_rows)
    report = {
        "schema": SCHEMA, "run_id": run_root.name, "dagster_run_id": dagster_run_id,
        "observed_at": now.isoformat(), **identities, "state": state,
        "models": aggregate_model_calls(events, complete=complete, max_rows=max_rows),
        "coverage": {
            "status": follower.read_status, "complete": complete, "reset_reason": reset_reason,
            "sequence": follower.cursor.sequence, "offset": follower.cursor.offset,
            "generation": [follower.cursor.device, follower.cursor.inode],
            "last_event_at": last_event, "last_event_age_seconds": _age(now, last_event),
            "retained_records": len(events), "observed_event_count": sum(follower.counts.values()),
            "coalesced_incidental_records": True,
            "receipts": "not_revalidated_by_monitor; lifecycle reports are not accepted evidence",
            "bounds": {"pages": pages, "page_bytes": 1024 * 1024, "page_events": 256,
                       "retained_events": follower.capacity, "report_rows": max_rows},
        },
        "signals": ["no_recent_events_is_not_proof_of_dead_worker"] if (
            _age(now, last_event) is None or _age(now, last_event) >= 300) else [],
    }
    report["gaps"] = sorted(set(report["gaps"] + gaps + (
        ["pipeline_" + follower.read_status] if not complete else [])))
    if state["terminal_confirmed"] and report["models"]["totals"]["statuses"].get("RUNNING"):
        report["models"]["gaps"]["missing_call_terminal_after_run_end"] = (
            report["models"]["totals"]["statuses"]["RUNNING"])
        report["models"]["accounting_complete"] = False
    report["delta"] = snapshot_delta(report, previous)
    if save:
        destination = (run_root / _STATE_DIR).resolve()
        if run_root.resolve() not in destination.parents:
            raise ValueError("monitor output escapes run")
        try:
            follower.save_checkpoint(checkpoint)
        except ValueError:
            report["gaps"].append("checkpoint_size_bound_exceeded")
            report["coverage"]["complete"] = False
            report["delta"] = {"available": False, "reason": "checkpoint_size_bound_exceeded"}
        atomic_json(destination / "snapshot.json", report)
    return report


def render_report(report: Mapping[str, Any]) -> str:
    def shown(value: Any) -> str:
        return "unknown" if value is None else str(value)

    def usage(value: Mapping[str, Any]) -> str:
        return shown(value["known_sum"]) + ("+" if value["lower_bound"] and value["known_sum"] is not None else "")

    state, model = report["state"], report["models"]["totals"]
    jobs = state["jobs"]
    lines = [
        f"Run {label(report['run_id'])} | Dagster {shown(report['dagster_run_id'])} | {report['observed_at']}",
        f"Profile {shown(report['profile'])} | source {shown(report['source_sha256'])}",
        "Frozen models: " + (", ".join(f"{row['provider']}/{row['model']}"
                                      for row in report["configured_models"]) or "unknown"),
        f"{state['status']} | jobs total/completed/running/remaining "
        f"{shown(jobs['total'])}/{shown(jobs['completed'])}/{shown(jobs['running'])}/{shown(jobs['remaining'])}"
        f" | states {json.dumps(jobs['by_status'], sort_keys=True)}"
        + (" (provisional/incomplete)" if not jobs["accounting_complete"] else ""),
        f"Attempts {state['attempts']['total_observed']} (retries {state['attempts']['retry_attempts']}, "
        f"reused {state['attempts']['reused']}, reused tasks {state['attempts']['reused_tasks']}); "
        f"{json.dumps(state['attempts']['by_status'], sort_keys=True)}",
    ]
    for row in state["current"]:
        lines.append(f"  {row['job']}/{row['attempt']} {row['status']} elapsed "
                     f"{shown(row['elapsed_seconds'])}s; last progress {shown(row['progress_age_seconds'])}s ago")
    for row in state["current_steps"]:
        lines.append(f"  step {row['job']}/{row['step']}/{row['task']} elapsed "
                     f"{shown(row['elapsed_seconds'])}s; progress age {shown(row['progress_age_seconds'])}s")
    lines.append(f"Model totals: fresh/reused/retry {model['fresh_calls']}/{model['reused_calls']}/"
                 f"{model['retry_calls']}; statuses {json.dumps(model['statuses'], sort_keys=True)}; "
                 f"invalid-output {model['invalid_output_calls']}; "
                 + "/".join(usage(model["usage"][name]) for name in USAGE_FIELDS)
                 + " input/output/cache/reasoning tokens.")
    if not report["models"]["accounting_complete"]:
        lines.append("Model counts/timing are observed lower bounds; model accounting is incomplete.")
    lines.append("Models: provider/model | fresh/reused/retry | statuses | in/out/cache/reasoning | "
                 "call p50/p95/max ms (n/missing), queue p95 ms (n/missing)")
    for row in report["models"]["by_model"]:
        latency, queue = row["call_latency"], row["queue_delay"]
        lines.append(f"  {row['provider']}/{row['model']} | "
                     f"{row['fresh_calls']}/{row['reused_calls']}/{row['retry_calls']} | "
                     f"{json.dumps(row['statuses'], sort_keys=True)} | "
                     + "/".join(usage(row["usage"][name]) for name in USAGE_FIELDS)
                     + " | " + "/".join(shown(latency[name]) for name in ("p50_ms", "p95_ms", "max_ms"))
                     + f" ({latency['sample_count']}/{latency['missing_count']}), {shown(queue['p95_ms'])}"
                     + f" ({queue['sample_count']}/{queue['missing_count']})")
    known_costs = report["models"]["cost"]["known_amounts"]
    lines.append(f"Summed call latency {shown(model['call_latency']['sum_ms'])}ms; inclusive execution "
                 f"{shown(model['execution_elapsed']['sum_ms'])}ms; concurrent dispatch wall "
                 f"{shown(model['concurrent_dispatch_wall_ms'])}ms (n={model['wall_sample_count']}). "
                 f"Known costs {json.dumps(known_costs, sort_keys=True) if known_costs else 'unknown'}; "
                 f"billing {report['models']['cost']['status']}, credits unknown. + = known lower bound.")
    for metric, rows in report["models"]["hotspots"].items():
        lines.append(f"Top {metric}: " + (", ".join(
            f"{row['job']}/{row['role']}={row['known_value']}" for row in rows) or "unknown"))
    lines.append("Delta: " + json.dumps(report["delta"], sort_keys=True))
    gaps = list(report["gaps"]) + list(state["gaps"]) + list(report["models"]["gaps"])
    lines.append(f"Coverage {report['coverage']['status']} @ sequence {report['coverage']['sequence']}; "
                 f"last event {shown(report['coverage']['last_event_at'])}; "
                 f"gaps {', '.join(gaps) or 'none detected in bounded telemetry'}.")
    omitted = (report["omitted_configured_models"] + state["omitted_current_rows"]
               + state["omitted_step_rows"] + state["omitted_blockage_rows"]
               + report["models"]["omitted_model_rows"] + report["models"]["omitted_job_role_rows"])
    if omitted:
        lines.append(f"{omitted} detail rows omitted; retained totals/coverage are not silently discarded.")
    if state["blocked"]:
        lines.append("Blockage signals: " + json.dumps(state["blocked"], sort_keys=True))
    lines.append("Retry/invalid/no-progress work warrants investigation, not proved waste. "
                 "Quiet logs do not prove a dead worker. Receipts not revalidated; not findings or quality assurance.")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Exact application run ID; never latest")
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument("--dagster-run-id", help="Optional exact Dagster UUID (not application run ID)")
    parser.add_argument("--save", action="store_true", help="Write only run-owned monitor checkpoint/snapshot")
    parser.add_argument("--json", action="store_true", help="Print the structured snapshot instead of text")
    parser.add_argument("--pages", type=int, default=16, help="Bounded incremental pages, 1..100")
    parser.add_argument("--rows", type=int, default=8, help="Maximum rows per detail table, 1..30")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.run_id):
        parser.error("application run ID must be one safe path component")
    try:
        report = poll_run(args.runs_root / args.run_id, dagster_run_id=args.dagster_run_id,
                          save=args.save, pages=args.pages, max_rows=args.rows)
    except (OSError, ValueError) as exc:
        parser.error(f"monitor input unavailable or invalid ({type(exc).__name__})")
    print(json.dumps(report, sort_keys=True) if args.json else render_report(report))
    return 0 if report["coverage"]["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
