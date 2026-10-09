from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import math
from pathlib import Path
from typing import Any, Mapping

from appsec_review.observability.events import PipelineLog
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage import file_sha256


SCHEMA = "appsec-review/telemetry-event/1"
FINDING_STATES = {"CANDIDATE", "REFUTED", "CONFIRMED"}
TERMINAL_EVENTS = {"SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "FAILED",
                   "BLOCKED", "PARTIAL", "NOT_APPLICABLE"}
METRICS_SEMANTICS = "appsec-review/review-metrics-semantics/1"


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


def _receipt_json(run_root: Path, identity: object) -> Mapping[str, Any]:
    if not isinstance(identity, Mapping):
        raise ValueError("metrics receipt identity is missing")
    relative, expected = identity.get("path"), identity.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("metrics receipt identity is invalid")
    path = (run_root / relative).resolve()
    root = run_root.resolve()
    if path == root or root not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("metrics receipt escaped the run or is unavailable")
    if file_sha256(path) != expected:
        raise ValueError("metrics receipt hash changed")
    import json
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("metrics receipt is not an object")
    return value


def _artifact_size(run_root: Path, identity: Mapping[str, Any]) -> int:
    relative, expected = identity.get("path"), identity.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("artifact identity is incomplete")
    path = (run_root / relative).resolve()
    root = run_root.resolve()
    if path == root or root not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("artifact escaped the run or is unavailable")
    size = path.stat().st_size
    if file_sha256(path) != expected or int(identity.get("size_bytes", -1)) != size:
        raise ValueError("artifact content or size changed")
    return size


def _new_timing_bucket() -> dict[str, Any]:
    return {"fresh_ms": [], "reused_ms": [], "intervals": [], "gaps": 0,
            "receipts": set(), "dispositions": Counter()}


def _timing_summary(bucket: Mapping[str, Any]) -> dict[str, Any]:
    fresh = list(bucket["fresh_ms"])
    reused = list(bucket["reused_ms"])
    values = fresh + reused
    intervals = sorted(bucket["intervals"])
    wall = 0
    if intervals:
        start, end = intervals[0]
        for next_start, next_end in intervals[1:]:
            if next_start <= end:
                end = max(end, next_end)
            else:
                wall += max(0, int((end - start).total_seconds() * 1000))
                start, end = next_start, next_end
        wall += max(0, int((end - start).total_seconds() * 1000))
    return {"count": len(values), "fresh_count": len(fresh), "reused_count": len(reused),
            "p50_ms": _percentile(values, .50), "p95_ms": _percentile(values, .95),
            "max_ms": max(values) if values else None, "summed_work_ms": sum(values),
            "wall_span_ms": wall, "gap_count": int(bucket["gaps"]),
            "receipt_count": len(bucket["receipts"]),
            "terminal_dispositions": dict(sorted(bucket["dispositions"].items()))}


def _review_metrics(run_root: Path, records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    source_rows: list[Mapping[str, Any]] = []
    source_gaps: list[object] = []
    projects: list[Mapping[str, Any]] = []
    targets: list[Mapping[str, Any]] = []
    build_receipts: list[Mapping[str, Any]] = []
    codeql_scopes: list[Mapping[str, Any]] = []
    receipt_refs: set[tuple[str, str]] = set()
    gaps: list[str] = []
    seen_producers: set[str] = set()
    for record in records:
        details = record.get("details", {})
        event = record.get("event_type")
        try:
            if event == "REVIEW_SCOPE_CATALOGED":
                seen_producers.add("catalog")
                partition = _receipt_json(run_root, details.get("source_receipt"))
                project_doc = _receipt_json(run_root, details.get("project_receipt"))
                target_doc = _receipt_json(run_root, details.get("build_target_receipt"))
                if partition.get("source_metrics_semantics") != "appsec-review/source-counting/1":
                    raise ValueError("source metrics semantics are unsupported")
                source_rows = list(partition.get("source_metrics", ()))
                source_gaps = [*partition.get("source_metric_gaps", ()), *partition.get("gaps", ())]
                projects = list(project_doc.get("projects", ()))
                targets = list(target_doc.get("targets", ()))
                for key in ("source_receipt", "project_receipt", "build_target_receipt"):
                    item = details[key]
                    receipt_refs.add((str(item["path"]), str(item["sha256"])))
            elif event == "LANGUAGE_BUILDS_RECORDED":
                seen_producers.add("build")
                document = _receipt_json(run_root, details.get("receipt"))
                if document.get("schema") != "appsec-review/language-build-handoff/1":
                    raise ValueError("language build metrics receipt schema is unsupported")
                build_receipts = list(document.get("receipts", ()))
                item = details["receipt"]
                receipt_refs.add((str(item["path"]), str(item["sha256"])))
            elif event == "CODEQL_SCOPES_RECORDED":
                seen_producers.add("codeql")
                document = _receipt_json(run_root, details.get("receipt"))
                if document.get("schema") != "appsec-review/codeql-analysis-handoff/1":
                    raise ValueError("CodeQL metrics receipt schema is unsupported")
                codeql_scopes = list(document.get("scopes", ()))
                item = details["receipt"]
                receipt_refs.add((str(item["path"]), str(item["sha256"])))
        except (KeyError, OSError, ValueError, UnicodeError) as exc:
            gaps.append(f"{event}: {exc}")
    for producer, description in (("catalog", "source/catalog"), ("build", "language-build"),
                                  ("codeql", "CodeQL scope")):
        if producer not in seen_producers:
            gaps.append(f"{description} metrics producer receipt is unavailable")

    source = {}
    for row in source_rows:
        language = str(row.get("language") or "Other")
        value = source.setdefault(language, {"file_count": 0, "sloc": 0, "generated_files": 0,
            "generated_sloc": 0, "vendored_files": 0, "vendored_sloc": 0,
            "test_files": 0, "test_sloc": 0})
        sloc = max(0, int(row.get("sloc", 0)))
        value["file_count"] += 1
        value["sloc"] += sloc
        for flag in ("generated", "vendored", "test"):
            if row.get(flag) is True:
                value[f"{flag}_files"] += 1
                value[f"{flag}_sloc"] += sloc

    statuses: dict[str, Counter[str]] = {}
    artifacts_by_scope: dict[str, dict[str, Any]] = {}
    global_artifacts: dict[str, int] = {}
    selected_projects: set[str] = set()
    for receipt in build_receipts:
        language = str(receipt.get("family") or "unknown")
        unit_id = str(receipt.get("build_unit_id") or "unknown")
        root = str(receipt.get("root") or ".")
        selected_projects.add(root)
        counter = statuses.setdefault(language, Counter(
            {"success": 0, "failure": 0, "gap": 0, "not_applicable": 0, "reuse": 0}))
        status = str(receipt.get("terminal_status") or "GAP")
        if receipt.get("checkpoint_reused") is True:
            counter["reuse"] += 1
        elif status == "SUCCEEDED":
            counter["success"] += 1
        elif status == "NOT_APPLICABLE":
            counter["not_applicable"] += 1
        else:
            counter["failure"] += 1
        if receipt.get("gaps"):
            counter["gap"] += 1
        for artifact in receipt.get("artifacts", ()):
            if not isinstance(artifact, Mapping):
                continue
            family = str(artifact.get("kind") or artifact.get("family") or "unknown")
            digest = str(artifact.get("sha256") or "")
            try:
                size = _artifact_size(run_root, artifact)
            except (OSError, ValueError) as exc:
                gaps.append(f"artifact {language}/{unit_id}/{family}: {exc}")
                continue
            scope = f"{language}/{unit_id}/{family}"
            bucket = artifacts_by_scope.setdefault(scope, {"language": language,
                "build_unit_id": unit_id, "artifact_family": family, "reference_count": 0,
                "reference_bytes": 0, "deduplicated_count": 0, "deduplicated_bytes": 0,
                "_seen": set()})
            bucket["reference_count"] += 1
            bucket["reference_bytes"] += size
            if len(digest) == 64 and digest not in bucket["_seen"]:
                bucket["_seen"].add(digest)
                bucket["deduplicated_count"] += 1
                bucket["deduplicated_bytes"] += size
                prior = global_artifacts.setdefault(digest, size)
                if prior != size:
                    gaps.append(f"artifact {digest} has conflicting sizes")
    artifact_groups = []
    for key in sorted(artifacts_by_scope):
        value = dict(artifacts_by_scope[key])
        value.pop("_seen")
        artifact_groups.append(value)
    total_statuses = Counter({"success": 0, "failure": 0, "gap": 0,
                              "not_applicable": 0, "reuse": 0})
    for value in statuses.values():
        total_statuses.update(value)
    discovered_by_language = Counter(str(item.get("family") or item.get("language") or "unknown")
                                     for item in targets)
    selected_by_language = Counter(str(item.get("family") or "unknown") for item in build_receipts)

    timings: dict[tuple[str, str, str, str, str, str, str, str, str], dict[str, Any]] = {}
    starts: dict[tuple[str, str], list[datetime]] = {}
    database_images: dict[str, str] = {}
    for record in records:
        details = record.get("details", {})
        if details.get("tool_id") != "codeql":
            continue
        action = "query" if details.get("query_identity") else "database"
        identity = str(details.get("query_identity") or details.get("database_identity") or "")
        database_identity = str(details.get("database_identity") or "")
        if details.get("image_id"):
            database_images[database_identity] = str(details["image_id"])
        pair = (action, identity)
        stamp = datetime.fromisoformat(str(record["timestamp"]))
        if record.get("event_type") == "TOOL_INVOCATION_STARTED":
            starts.setdefault(pair, []).append(stamp)
            continue
        if record.get("event_type") != "TOOL_INVOCATION_COMPLETED":
            continue
        key = (action, str(details.get("scope_id") or "-"),
               str(details.get("language") or "unknown"), str(details.get("project_root") or "."),
               str(details.get("build_unit_id") or "-"), str(details.get("query_profile") or "-"),
               str(details.get("query_suite") or "-"), str(details.get("query_pack") or "-"),
               str(details.get("image_id") or database_images.get(database_identity) or "-"))
        bucket = timings.setdefault(key, _new_timing_bucket())
        receipt = details.get("metrics_receipt")
        try:
            resolved = _receipt_json(run_root, receipt)
            duration = max(0, int(resolved.get("duration_ms", details.get("duration_ms", 0))))
            bucket["receipts"].add((str(receipt["path"]), str(receipt["sha256"])))
            receipt_refs.add((str(receipt["path"]), str(receipt["sha256"])))
            bucket["reused_ms" if details.get("checkpoint_reused") else "fresh_ms"].append(duration)
            bucket["dispositions"][str(details.get("disposition") or "UNKNOWN")] += 1
            pending = starts.get(pair, [])
            if pending:
                bucket["intervals"].append((pending.pop(0), stamp))
            if str(details.get("disposition")) != "SUCCEEDED" or int(details.get("gap_count", 0)):
                bucket["gaps"] += 1
        except (KeyError, OSError, ValueError, UnicodeError) as exc:
            bucket["gaps"] += 1
            gaps.append(f"CodeQL {action}/{identity or '-'}: {exc}")
    timing_rows = [{"action": key[0], "scope_id": key[1], "language": key[2], "project": key[3],
                    "build_unit_id": key[4], "profile": key[5], "query_suite": key[6],
                    "query_pack": key[7], "image_id": key[8],
                    **_timing_summary(value)}
                   for key, value in sorted(timings.items())]
    aggregate_buckets: dict[str, dict[str, Any]] = {}
    dimension_buckets: dict[str, dict[str, dict[str, Any]]] = {
        "language": {}, "project": {}, "profile": {}}
    for key, value in timings.items():
        aggregate = aggregate_buckets.setdefault(key[0], _new_timing_bucket())
        for field in ("fresh_ms", "reused_ms", "intervals"):
            aggregate[field].extend(value[field])
        aggregate["gaps"] += value["gaps"]
        aggregate["receipts"].update(value["receipts"])
        aggregate["dispositions"].update(value["dispositions"])
        for dimension, position in (("language", 2), ("project", 3), ("profile", 5)):
            dimension_key = f"{key[0]}/{key[position]}"
            target = dimension_buckets[dimension].setdefault(dimension_key, _new_timing_bucket())
            for field in ("fresh_ms", "reused_ms", "intervals"):
                target[field].extend(value[field])
            target["gaps"] += value["gaps"]
            target["receipts"].update(value["receipts"])
            target["dispositions"].update(value["dispositions"])
    timed_scope_profiles = {(item["language"], item["project"], item["build_unit_id"], item["profile"])
                            for item in timing_rows if item["action"] == "query"}
    for scope in codeql_scopes:
        scope_key = (str(scope.get("language") or "unknown"), str(scope.get("root") or "."),
                     str(scope.get("build_unit_id") or "-"), str(scope.get("query_profile") or "-"))
        if scope_key not in timed_scope_profiles or scope.get("gaps"):
            gaps.append(f"CodeQL scope {scope.get('scope_id', '-')}/{scope_key[3]} has missing or failed producer data")
    return {"semantics": METRICS_SEMANTICS,
            "classification": {"source": "appsec-review/source-counting/1",
                "sloc": "UTF-8 non-empty physical lines; comments included",
                "generated": "path segment generated or gen; dist/build trees are excluded gaps",
                "vendored": "path segment vendor, vendors, or third_party; node_modules trees are excluded gaps",
                "tests": "test/tests/spec/specs segment or test_/spec_ filename",
                "artifacts": "references count each build-unit edge; deduplicated totals use SHA-256 content identity"},
            "source_by_language": dict(sorted(source.items())),
            "source_gap_count": len(source_gaps), "source_gaps": source_gaps[:200],
            "projects": {"discovered": len(projects), "selected": len(selected_projects)},
            "build_units": {"discovered": len(targets), "selected": len(build_receipts),
                "outcomes": dict(sorted(total_statuses.items())),
                "discovered_by_language": dict(sorted(discovered_by_language.items())),
                "selected_by_language": dict(sorted(selected_by_language.items())),
                "by_language": {key: dict(sorted(value.items())) for key, value in sorted(statuses.items())}},
            "artifacts": {"groups": artifact_groups, "reference_count": sum(
                item["reference_count"] for item in artifact_groups),
                "reference_bytes": sum(item["reference_bytes"] for item in artifact_groups),
                "deduplicated_count": len(global_artifacts),
                "deduplicated_bytes": sum(global_artifacts.values())},
            "codeql_timings": {"groups": timing_rows,
                "aggregate": {key: _timing_summary(value) for key, value in sorted(aggregate_buckets.items())},
                **{f"by_{dimension}": {key: _timing_summary(value) for key, value in sorted(buckets.items())}
                   for dimension, buckets in dimension_buckets.items()}},
            "receipt_count": len(receipt_refs), "gaps": gaps,
            "authoritative_findings": {"source": "FINDING_TRANSITION", "note":
                "Raw observations are excluded; lifecycle counts are reported in finding_states."}}


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
    return {"schema": "appsec-review/run-metrics/3", "run_id": Path(run_root).name,
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
            "review": _review_metrics(Path(run_root), records),
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
