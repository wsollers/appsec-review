from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import math
from pathlib import Path
from typing import Any, Mapping

from appsec_review.observability.events import PipelineLog
from appsec_review.observability.completion import completion_metrics
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage import file_sha256
from appsec_review.observability.debug_symbols import debug_symbol_metrics


SCHEMA = "appsec-review/telemetry-event/1"
FINDING_STATES = {"CANDIDATE", "REFUTED", "CONFIRMED"}
TERMINAL_EVENTS = {"SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "FAILED",
                   "BLOCKED", "PARTIAL", "NOT_APPLICABLE"}
METRICS_SEMANTICS = "appsec-review/review-metrics-semantics/1"
RUN_METRICS_SCHEMA = "appsec-review/run-metrics/4"
CODEQL_METRICS_SEMANTICS = "appsec-review/codeql-execution-metrics/1"
CODEQL_QUERY_METRICS_SCHEMA = "appsec-review/codeql-query-metrics/1"
CODEQL_TOOLS = {"codeql", "codeql-graph-export", "codeql-graph-export-compile"}
CODEQL_ACTIONS = {"database": "database", "query": "analyze", "analyze": "analyze",
                  "compile": "compile", "export": "export"}
CODEQL_STATUSES = ("SUCCEEDED", "FAILED", "TIMED_OUT", "SKIPPED", "REUSED")
DATABASE_PACK = "(database creation)"
_CODEQL_ROW_LIMIT = 2000
_CODEQL_GAP_LIMIT = 200


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


def _tree_sitter_metrics(run_root: Path, records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    from appsec_review.container_runtime.measurement import COUNTERS, INVOCATION_SCHEMA
    sources: dict[str, dict[str, Any]] = {}
    reused: dict[str, Mapping[str, Any]] = {}
    reused_tasks: set[tuple[str, str, str, str]] = set()
    gaps: list[str] = []
    kinds = {"TOOL_INVOCATION_STARTED": "start", "TOOL_INVOCATION_COMPLETED": "execution",
             "TREE_SITTER_OUTPUT_VALIDATED": "output"}
    for event in records:
        details = event.get("details", {})
        if event.get("event_type") == "TASK_REUSED" and event.get("job_id") in {
                "job_source_history_analysis", "job_tree_sitter_ast"}:
            reused_tasks.add(tuple(str(event.get(key)) for key in ("job_id", "attempt_id", "step_id", "task_id")))
        if details.get("tool_id") != "tool-tree-sitter":
            continue
        if event["event_type"] == "TREE_SITTER_REUSED":
            identity = str(details.get("reuse_id"))
            if identity in reused and reused[identity] != details:
                gaps.append(f"conflicting Tree-sitter reuse identity: {identity}")
            reused[identity] = details
            continue
        kind = kinds.get(event["event_type"])
        if kind is None:
            continue
        identity = str(details.get("tool_invocation_id") or "")
        row = sources.setdefault(identity, {"references": {}, "documents": {}, "invalid": False})
        reference = details.get("metrics_receipt")
        if kind in row["references"]:
            if row["references"][kind] != reference:
                row["invalid"] = True
                gaps.append(f"conflicting Tree-sitter invocation receipt: {identity}/{kind}")
            continue
        row["references"][kind] = reference
        try:
            document = _receipt_json(run_root, reference)
            if document.get("invocation_id") != identity:
                raise ValueError("invocation identity mismatch")
            if kind != "output":
                if document.get("schema") != INVOCATION_SCHEMA or any(
                        document.get(key) != event.get(key) for key in ("run_id", "job_id", "attempt_id")):
                    raise ValueError("invocation provenance mismatch")
            elif document.get("schema") != "appsec-review/tree-sitter-output-metrics/1":
                raise ValueError("output metrics schema mismatch")
            row["documents"][kind] = document
        except (OSError, ValueError, UnicodeError) as exc:
            row["invalid"] = True
            gaps.append(f"Tree-sitter invocation {identity}/{kind}: {exc}")

    invocations = []
    for identity, source in sorted(sources.items()):
        documents = source["documents"]
        start, execution, output = (documents.get(key, {}) for key in ("start", "execution", "output"))
        base = execution or start
        if start and execution and any(start.get(key) != execution.get(key) for key in start):
            source["invalid"] = True
            gaps.append(f"Tree-sitter start/completion mismatch: {identity}")
        resources = execution.get("resources", {}) if not source["invalid"] else {}
        invocations.append({
            "invocation_id": identity,
            **{key: base.get(key) for key in ("run_id", "job_id", "attempt_id", "unit_id", "scope_id", "language",
                                             "image_id", "started_at", "completed_at", "duration_ms")},
            "status": "INTEGRITY_ERROR" if source["invalid"] else execution.get("status", "INCOMPLETE"),
            "exit_code": execution.get("exit_code"), "timed_out": execution.get("timed_out"),
            "oom_killed": execution.get("oom_killed"), "configured_limits": base.get("configured_limits"),
            "resources": resources, "receipts": source["references"],
            "files_requested": len(base["files"]) if "files" in base else None,
            **{key: output.get(key) if not source["invalid"] else None
               for key in ("files_accounted", "files_parsed", "nodes_emitted", "truncated_files")},
            "resource_accounting_complete": not source["invalid"] and execution.get(
                "resource_accounting_complete", False),
            "accounting_complete": bool(start and execution and output and not source["invalid"] and
                                        execution.get("resource_accounting_complete")),
        })

    def summarize(rows):
        complete_intervals = []
        for row in rows:
            if row["started_at"] and row["completed_at"] and row["status"] != "INTEGRITY_ERROR":
                start = datetime.fromisoformat(row["started_at"])
                end = datetime.fromisoformat(row["completed_at"])
                if end >= start:
                    complete_intervals.append((start, end))
        points = sorted((stamp, delta) for start, end in complete_intervals if end > start
                        for stamp, delta in ((start, 1), (end, -1)))
        active = peak = covered_ms = 0
        previous = None
        for stamp, delta in points:
            if active and previous is not None:
                covered_ms += (stamp - previous).total_seconds() * 1000
            active += delta
            peak = max(peak, active)
            previous = stamp
        values = {key: [row["resources"].get(key) for row in rows
                        if row["resources"].get(key) is not None] for key in COUNTERS}
        measurements = {
            key: {"value": (max(items) if key == "memory_peak_bytes" else sum(items)) if items else None,
                  "measured_invocations": len(items), "unavailable_invocations": len(rows) - len(items),
                  "complete": len(items) == len(rows) and all(row["resource_accounting_complete"] for row in rows)}
            for key, items in values.items()}
        durations = [row["duration_ms"] for row in rows if row["duration_ms"] is not None
                     and row["status"] != "INTEGRITY_ERROR"]
        elapsed = (int((max(end for _, end in complete_intervals) -
                        min(start for start, _ in complete_intervals)).total_seconds() * 1000)
                   if complete_intervals else None)
        return {
            "invocation_count": len(rows), "outcomes": dict(sorted(Counter(row["status"] for row in rows).items())),
            "summed_invocation_duration_ms": sum(durations) if durations else None,
            "elapsed_window_ms": elapsed, "covered_wall_ms": int(covered_ms) if complete_intervals else None,
            "max_concurrency": peak if complete_intervals else None,
            "timing_complete": len(complete_intervals) == len(rows),
            "measurements": measurements,
            "memory_peak_semantics": "maximum_individual_container_peak; concurrent_aggregate_peak_not_measured",
            "counts": {key: {
                "value": sum(row[key] for row in rows if row[key] is not None)
                         if any(row[key] is not None for row in rows) else None,
                "complete": all(row[key] is not None for row in rows)}
                for key in ("files_requested", "files_accounted", "files_parsed", "nodes_emitted", "truncated_files")},
            "accounting_complete": all(row["accounting_complete"] for row in rows),
        }

    groups = sorted({(str(row["job_id"]), str(row["attempt_id"])) for row in invocations})
    return {"schema": "appsec-review/tree-sitter-metrics/1", **summarize(invocations),
            "by_job_attempt": [{"job_id": job, "attempt_id": attempt, **summarize([
                row for row in invocations if str(row["job_id"]) == job and str(row["attempt_id"]) == attempt])}
                for job, attempt in groups],
            "invocations": invocations, "reused_scopes": [reused[key] for key in sorted(reused)],
            "reused_scope_count": len(reused), "reused_task_count": len(reused_tasks), "gaps": gaps,
            "incomplete_accounting": bool(gaps) or any(not row["accounting_complete"] for row in invocations)}


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
        elif status in {"NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}:
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
    starts: dict[tuple[str, ...], list[datetime]] = {}
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
        pair = (str(record["run_id"]), str(record["job_id"]), str(record["attempt_id"]),
                str(details.get("tool_invocation_id") or identity), action)
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
                "generated": "path segment generated or gen; delivered build/dist content is not blanket-excluded",
                "vendored": "path segment vendor, vendors, or third_party; directory name is not platform ownership",
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


def _codeql_action(event: str, details: Mapping[str, Any]) -> str | None:
    action = details.get("action")
    if isinstance(action, str) and action in CODEQL_ACTIONS:
        return CODEQL_ACTIONS[action]
    if event == "CODEQL_ACTION_FAILED" or isinstance(action, str):
        return None
    tool = details.get("tool_id")
    if tool == "codeql-graph-export-compile":
        return "compile"
    if tool == "codeql-graph-export":
        return "export"
    return "analyze" if details.get("query_identity") or details.get("query_pack") else "database"


def _codeql_stats(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    statuses = Counter({status: 0 for status in CODEQL_STATUSES})
    statuses.update(str(row["status"]) for row in rows)
    measured = [int(row["duration_ms"]) for row in rows
                if row.get("duration_ms") is not None and row["status"] not in {"REUSED", "SKIPPED"}]
    results = [int(row["result_count"]) for row in rows if isinstance(row.get("result_count"), int)]
    return {"count": len(rows), "statuses": dict(sorted(statuses.items())),
            "runtime_ms": {"measured_count": len(measured), "unmeasured_count": sum(
                               1 for row in rows if row.get("duration_ms") is None
                               and row["status"] not in {"REUSED", "SKIPPED"}),
                           "total": sum(measured), "min": min(measured) if measured else None,
                           "max": max(measured) if measured else None,
                           "p50": _percentile(measured, .50), "p95": _percentile(measured, .95)},
            "result_count": sum(results) if results else None,
            "gap_count": sum(int(row.get("gap_count") or 0) for row in rows),
            "truncated_count": sum(1 for row in rows if row.get("truncated") is True)}


def _codeql_view(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    by_action: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_action.setdefault(str(row["action"]), []).append(row)
    return {**_codeql_stats(rows),
            "by_action": {action: _codeql_stats(items) for action, items in sorted(by_action.items())}}


def _codeql_query_rows(run_root: Path, row: Mapping[str, Any], details: Mapping[str, Any],
                       gaps: list[str]) -> list[dict[str, Any]]:
    """Per-query rows of one execution, or named gaps; an absent source never reads as zero."""
    label = f"CodeQL {row['action']} {row['language']}/{row['query_pack']} {row['scope_id']}"
    if row["status"] in {"REUSED", "SKIPPED"} or row["action"] == "database" or row["reason"] is not None:
        row["per_query"] = {"status": "not_applicable", "reason":
                            "no CodeQL query was evaluated in this run for this action"}
        return []
    identity = details.get("query_metrics")
    if identity is None:
        reason = str(details.get("query_metrics_gap") or "per-query metrics were not recorded")
        row["per_query"] = {"status": "gap", "reason": reason}
        gaps.append(f"{label}: {reason}")
        return []
    try:
        document = _receipt_json(run_root, identity)
        if document.get("schema") != CODEQL_QUERY_METRICS_SCHEMA:
            raise ValueError("per-query metrics schema is unsupported")
    except (KeyError, OSError, ValueError, UnicodeError) as exc:
        row["per_query"] = {"status": "gap", "reason": str(exc)}
        gaps.append(f"{label}: per-query metrics {exc}")
        return []
    named = [str(item) for item in document.get("gaps", ())]
    gaps.extend(f"{label}: {item}" for item in named)
    queries = [item for item in document.get("queries", ()) if isinstance(item, Mapping)]
    rules = [item for item in document.get("rules", ()) or () if isinstance(item, Mapping)]
    row["per_query"] = {"status": "gap" if named and not queries else "partial" if named else "complete",
                        "source": document.get("source"), "path": identity.get("path"),
                        "expected_query_count": document.get("expected_query_count"),
                        "observed_query_count": len(queries), "rule_count": len(rules), "gaps": named}
    common = {"action": row["action"], "language": row["language"], "query_pack": row["query_pack"]}
    values = [{**common, "query": str(item.get("query")), "key_kind": str(item.get("key_kind") or "query"),
               "status": str(item.get("status") or "SUCCEEDED"),
               "duration_ms": item.get("duration_ms") if isinstance(item.get("duration_ms"), int) else None,
               "result_count": item.get("result_count") if isinstance(item.get("result_count"), int) else None,
               "truncated": item.get("truncated") is True, "gap_count": 0}
              for item in queries]
    values.extend({**common, "query": str(item.get("rule_id")), "key_kind": "rule_id",
                   "status": row["status"], "duration_ms": None,
                   "result_count": item.get("result_count") if isinstance(item.get("result_count"), int) else None,
                   "truncated": False, "gap_count": 0} for item in rules)
    return values


def _codeql_metrics(run_root: Path, records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    """Every CodeQL execution as one row, viewed by query pack, by language and by both."""
    starts: dict[str, datetime] = {}
    rows: list[dict[str, Any]] = []
    query_rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    for record in records:
        event, details = str(record.get("event_type")), record.get("details", {})
        if details.get("tool_id") not in CODEQL_TOOLS and event != "CODEQL_ACTION_FAILED":
            continue
        if event not in {"TOOL_INVOCATION_STARTED", "TOOL_INVOCATION_COMPLETED",
                         "CODEQL_ACTION_SKIPPED", "CODEQL_ACTION_FAILED"}:
            continue
        action = _codeql_action(event, details)
        if action is None:
            continue
        stamp = datetime.fromisoformat(str(record["timestamp"]))
        invocation = str(details.get("tool_invocation_id") or "")
        if event == "TOOL_INVOCATION_STARTED":
            if invocation:
                starts.setdefault(invocation, stamp)
            continue
        pack = details.get("query_pack") or details.get("export_pack")
        row: dict[str, Any] = {
            "action": action, "tool_id": details.get("tool_id"),
            "scope_id": str(details.get("scope_id") or "-"),
            "language": str(details.get("language") or "unknown"),
            "source_languages": sorted(str(item) for item in details.get("source_languages") or ()),
            "build_mode": details.get("build_mode"), "project_root": details.get("project_root"),
            "build_unit_id": details.get("build_unit_id"),
            "query_pack": str(pack or (DATABASE_PACK if action == "database" else "unknown")),
            "query_pack_version": details.get("query_pack_version") or details.get("export_pack_version"),
            "query_suite": details.get("query_suite"), "query_profile": details.get("query_profile"),
            "status": "SKIPPED" if event == "CODEQL_ACTION_SKIPPED" else "FAILED",
            "duration_ms": None, "started_at": None, "completed_at": stamp.isoformat(),
            "result_count": None, "gap_count": 1, "truncated": False, "receipt": None,
            "reason": details.get("reason")}
        if event == "TOOL_INVOCATION_COMPLETED":
            reused = details.get("checkpoint_reused") is True
            row.update(result_count=details.get("result_count") if isinstance(details.get("result_count"), int) else None,
                       gap_count=int(details.get("gap_count") or 0), truncated=details.get("truncated") is True,
                       reason=None)
            begun = starts.pop(invocation, None)
            row["started_at"] = begun.isoformat() if begun else None
            receipt: Mapping[str, Any] = {}
            try:
                receipt = _receipt_json(run_root, details.get("metrics_receipt"))
                row["receipt"] = details["metrics_receipt"]["path"]
            except (KeyError, OSError, ValueError, UnicodeError) as exc:
                gaps.append(f"CodeQL {action} {row['language']}/{row['query_pack']} {row['scope_id']}: "
                            f"runtime unverified ({exc})")
            timed_out = details.get("timed_out") is True or receipt.get("timed_out") is True
            row["status"] = ("REUSED" if reused else "TIMED_OUT" if timed_out
                             else str(details.get("disposition") or "UNKNOWN"))
            if not reused and receipt:
                duration = receipt.get("duration_ms", details.get("duration_ms"))
                row["duration_ms"] = max(0, int(duration)) if isinstance(duration, (int, float)) else None
                row["started_at"] = receipt.get("started_at") or row["started_at"]
                row["completed_at"] = receipt.get("completed_at") or row["completed_at"]
        elif event == "CODEQL_ACTION_FAILED":
            gaps.append(f"CodeQL {action} {row['language']}/{row['query_pack']} {row['scope_id']}: "
                        f"runtime unmeasured, action failed without an execution receipt ({row['reason']})")
        query_rows.extend(_codeql_query_rows(run_root, row, details, gaps))
        rows.append(row)

    def grouped(*fields: str) -> dict[tuple[str, ...], list[Mapping[str, Any]]]:
        groups: dict[tuple[str, ...], list[Mapping[str, Any]]] = {}
        for item in rows:
            groups.setdefault(tuple(str(item[field]) for field in fields), []).append(item)
        return groups

    by_pack = {}
    for (pack,), items in sorted(grouped("query_pack").items()):
        by_pack[pack] = {**_codeql_view(items), "query_pack_versions": sorted(
            {str(item["query_pack_version"]) for item in items if item["query_pack_version"]}),
            "languages": sorted({item["language"] for item in items})}
    by_language = {}
    for (language,), items in sorted(grouped("language").items()):
        by_language[language] = {**_codeql_view(items), "source_languages": sorted(
            {value for item in items for value in item["source_languages"]}),
            "query_packs": sorted({item["query_pack"] for item in items})}
    by_pack_language: dict[str, dict[str, Any]] = {}
    for (pack, language), items in sorted(grouped("query_pack", "language").items()):
        by_pack_language.setdefault(pack, {})[language] = _codeql_view(items)
    source_groups: dict[str, list[Mapping[str, Any]]] = {}
    for item in rows:
        for value in item["source_languages"] or ["unknown"]:
            source_groups.setdefault(value, []).append(item)
    query_groups: dict[tuple[str, ...], list[Mapping[str, Any]]] = {}
    for item in query_rows:
        key = (item["action"], item["language"], item["query_pack"], item["key_kind"], item["query"])
        query_groups.setdefault(key, []).append(item)
    by_query = [{"action": key[0], "language": key[1], "query_pack": key[2], "key_kind": key[3],
                 "query": key[4], **_codeql_stats(items)} for key, items in sorted(query_groups.items())]
    by_query.sort(key=lambda item: (-int(item["runtime_ms"]["total"]), item["action"], item["language"],
                                    item["query_pack"], item["key_kind"], item["query"]))
    executions = sorted(rows, key=lambda item: (item["action"], item["language"], item["query_pack"],
                                                item["scope_id"], str(item["completed_at"])))
    return {"semantics": CODEQL_METRICS_SEMANTICS,
            "status_vocabulary": list(CODEQL_STATUSES),
            "runtime_semantics": ("execution receipt duration of fresh executions; REUSED and SKIPPED "
                                  "rows are counted but excluded from runtime statistics"),
            "totals": _codeql_view(rows),
            "by_query_pack": by_pack, "by_language": by_language,
            "by_query_pack_language": by_pack_language,
            "by_source_language": {key: _codeql_view(items) for key, items in sorted(source_groups.items())},
            "by_query": by_query[:_CODEQL_ROW_LIMIT], "by_query_total": len(by_query),
            "by_query_truncated": len(by_query) > _CODEQL_ROW_LIMIT,
            "executions": executions[:_CODEQL_ROW_LIMIT], "execution_total": len(executions),
            "executions_truncated": len(executions) > _CODEQL_ROW_LIMIT,
            "gap_count": len(gaps), "gaps": gaps[:_CODEQL_GAP_LIMIT]}


def _owasp_metrics(run_root: Path, records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    publications, gaps, seen = [], [], set()
    latest = None
    for record in records:
        if record["event_type"] != "OWASP_ASSESSMENT_RECORDED":
            continue
        reference = record["details"].get("metrics_receipt")
        key = (record["attempt_id"], identity_hash(reference) if isinstance(reference, Mapping) else "")
        if key in seen:
            continue
        seen.add(key)
        latest = None
        try:
            report = _receipt_json(run_root, reference)
            if report.get("schema") != "appsec-review/owasp-workbench-result/1":
                raise ValueError("unsupported OWASP metrics receipt")
            coverage = report["coverage"]
            if (not isinstance(coverage, Mapping) or type(coverage.get("selected_rows")) is not int
                    or any(type(value) is not int or value < 0 for value in coverage.values())
                    or any(value > coverage["selected_rows"] for name, value in coverage.items()
                           if name.endswith("_rows"))):
                raise ValueError("invalid OWASP coverage denominators")
            batches = report["telemetry"]
            source_resolution = Counter()
            for batch in batches:
                counters = batch.get("retrieval", {})
                values = [*counters.values(), *(batch.get(name, 0) for name in (
                    "model_calls", "model_requested_retrievals", "reused_model_results"))]
                if any(type(value) is not int or value < 0 for value in values):
                    raise ValueError("invalid OWASP source-resolution counters")
                source_resolution.update(counters)
            input_retrieval = report.get("input_retrieval", {})
            if any(type(value) is not int or value < 0 for value in input_retrieval.values()):
                raise ValueError("invalid OWASP input-retrieval counters")
            latest = {
                "attempt_id": record["attempt_id"], "receipt": reference,
                "assessment_mode": report["assessment_mode"], "coverage": dict(coverage),
                "manifest_sha256": report["index_manifest"]["sha256"],
                "input_retrieval": input_retrieval,
                "source_resolution": dict(source_resolution),
                "model_requested_retrievals": sum(batch.get("model_requested_retrievals", 0) for batch in batches),
                "reused_model_results": sum(batch.get("reused_model_results", 0) for batch in batches),
                "declared_model_calls": sum(batch.get("model_calls", 0) for batch in batches),
                "gap_count": len(report["gaps"]),
            }
            publications.append(latest)
        except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
            gaps.append({"attempt_id": record["attempt_id"], "reason": "owasp_metrics_receipt_unavailable",
                         "error_class": type(exc).__name__})
    dispatches = [record["details"] for record in records if record["event_type"] == "MODEL_CALL_COMPLETED"
                  and record["job_id"] == "job_owasp_control_assessment"]
    calls = [call for call in dispatches if call.get("execution_mode") != "replay"]
    return {
        "latest_publication": latest, "publications": publications, "gaps": gaps,
        "coverage_unavailable_reason": None if latest is not None else "no_valid_publication_receipt",
        "new_model_calls": sum(record["event_type"] == "MODEL_CALL_STARTED"
                               and record["job_id"] == "job_owasp_control_assessment"
                               and record["details"].get("execution_mode") != "replay" for record in records),
        "completed_model_calls": len(calls),
        "replay_attempts": sum(call.get("execution_mode") == "replay" for call in dispatches),
        "model_dispositions": dict(Counter(str(call.get("terminal_status")) for call in calls)),
        "model_calls_by_role": dict(Counter(str(call.get("role")) for call in calls)),
        "unknown_usage_calls": sum(any(call.get(name) is None for name in (
            "input_tokens", "output_tokens")) for call in calls),
        "verified_reuse_events": sum(record["event_type"] == "OWASP_MODEL_REUSED" for record in records),
        "model_requested_retrieval_dispositions": dict(Counter(
            str(record["details"].get("terminal_status")) for record in records
            if record["event_type"] == "OWASP_RETRIEVAL_COMPLETED")),
        "interpretation": "publication metrics are not evidence of target safety or accepted job completion",
    }


def _review_flow_metrics(records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    cells, milestones = {}, {}
    for record in records:
        event, details = record["event_type"], record["details"]
        if event == "INFERENCE_REVIEW_CELL_COMPLETED":
            key = (record["run_id"], record["attempt_id"], details["cell_id"])
            cells[key] = details
        milestone = (
            "control_evidence" if event == "PRECOMPUTED_PRODUCT_PUBLISHED"
            and details.get("query_set") == "control_evidence" else
            "packages" if event == "REVIEW_PACKAGES_PUBLISHED" else
            f"lane:{details.get('lane')}" if event == "INFERENCE_REVIEW_LANE_COMPLETED" else None)
        if milestone:
            milestones[(record["job_id"], record["attempt_id"], milestone)] = {
                "stage": milestone, "job_id": record["job_id"], "attempt_id": record["attempt_id"],
                "counts": {name: value for name, value in details.items()
                           if type(value) is int and name in {
                               "fact_count", "package_count", "gap_count", "coverage_gap_count",
                               "cells_run", "cells_reused", "cells_not_launched", "claims", "cells", "gaps"}},
                "manifest_sha256": details.get("manifest_sha256"),
                "owasp_manifest_sha256": details.get("owasp_manifest_sha256"),
                "package_manifest_sha256": details.get("package_manifest_sha256"),
                "reused": details.get("reused"),
            }
    return {
        "cell_count": len(cells),
        "cells_by_role": dict(Counter(str(cell["role"]) for cell in cells.values())),
        "cell_dispositions": dict(Counter(str(cell["terminal_status"]) for cell in cells.values())),
        "reused_cells": sum(bool(cell["reused"]) for cell in cells.values()),
        "cell_model_dispatches": sum(cell["model_dispatches"] for cell in cells.values()),
        "new_model_calls": sum(record["event_type"] == "MODEL_CALL_STARTED"
                               and record["job_id"] == "job_inference_security_review"
                               and record["details"].get("execution_mode") != "replay" for record in records),
        "fresh_retrieval_queries": sum(cell["counts"].get("queries", 0) for cell in cells.values()
                                       if not cell["reused"]),
        "milestones": list(milestones.values()),
        "interpretation": "absent milestones are unrecorded, not successful or zero-work stages",
    }


_NATIVE_SBOM_JOB = "job_dependency_intelligence"
_NATIVE_SBOM_UNIT = "publication.publish_sbom"


def _native_sbom_ref(run_root: Path, value: object) -> Mapping[str, Any]:
    from appsec_review.storage.shared import verify_reference
    if (not isinstance(value, Mapping) or not isinstance(value.get("path"), str)
            or not _native_sbom_hash(value.get("sha256"))
            or type(value.get("size_bytes")) is not int or value["size_bytes"] < 0):
        raise ValueError("native SBOM artifact reference is incomplete")
    verify_reference(run_root, value)
    return {key: value[key] for key in ("path", "sha256", "size_bytes")}


def _native_sbom_hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value)


def _native_sbom_json(run_root: Path, relative: str) -> Mapping[str, Any]:
    import json
    from appsec_review.storage.shared import safe_path
    value = json.loads(safe_path(run_root, relative).read_bytes())
    if not isinstance(value, Mapping):
        raise ValueError("native SBOM metadata is not an object")
    return value


def _native_sbom_receipt(run_root: Path, reference: object, *, attempt_id: str,
                         source_fingerprint: object, input_fingerprint: object) -> Mapping[str, Any]:
    from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
        GAP_KINDS, METRIC_COUNTERS, METRICS_SCHEMA, NativeSbomMetrics,
    )
    ref = _native_sbom_ref(run_root, reference)
    if ref["size_bytes"] > 64 * 1024:
        raise ValueError("native SBOM metrics receipt exceeds its bound")
    document = _native_sbom_json(run_root, ref["path"])
    if (set(document) != NativeSbomMetrics.__required_keys__
            or document.get("schema") != METRICS_SCHEMA):
        raise ValueError("native SBOM metrics schema mismatch")
    expected = {"run_id": run_root.name, "job_id": _NATIVE_SBOM_JOB,
                "attempt_id": attempt_id, "unit_id": _NATIVE_SBOM_UNIT,
                "source_fingerprint": source_fingerprint, "input_fingerprint": input_fingerprint}
    if (not _native_sbom_hash(source_fingerprint) or not _native_sbom_hash(input_fingerprint)
            or any(document.get(key) != value for key, value in expected.items())):
        raise ValueError("native SBOM metrics provenance mismatch")
    if (document["status"] not in ("SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED")
            or document["discovery_status"] not in ("SUCCEEDED", "COMPLETED_WITH_GAPS")
            or document["conversion_status"] not in ("SUCCEEDED", "FAILED")
            or document["validation_status"] not in ("SUCCEEDED", "FAILED")):
        raise ValueError("native SBOM metrics disposition is invalid")
    counters, gaps = document["counters"], document["gaps_by_kind"]
    if (not isinstance(counters, Mapping) or set(counters) != set(METRIC_COUNTERS)
            or not isinstance(gaps, Mapping) or not set(gaps) <= GAP_KINDS
            or any(type(value) is not int or value < 0
                   for value in (*counters.values(), *gaps.values()))):
        raise ValueError("native SBOM metrics counters are invalid")
    failed = document["status"] == "FAILED"
    if ((failed and (document["sbom_sha256"] is not None
                    or document["validation_status"] != "FAILED"))
            or (not failed and (not _native_sbom_hash(document["sbom_sha256"])
                               or document["validation_status"] != "SUCCEEDED"))
            or (document["status"] == "SUCCEEDED" and (
                document["discovery_status"] != "SUCCEEDED"
                or document["conversion_status"] != "SUCCEEDED" or any(gaps.values())))):
        raise ValueError("native SBOM metrics dispositions contradict publication")
    return document


def _native_sbom_accepted(run_root: Path, *,
                          historical: tuple[str, str] | None = None) -> Mapping[str, Any] | None:
    from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
    from appsec_review.storage.shared import safe_path
    latest = f"data/jobs/{_NATIVE_SBOM_JOB}/latest.json"
    if historical is None:
        if not safe_path(run_root, latest).exists():
            return None
        pointer = _native_sbom_json(run_root, latest)
    else:
        attempt, digest = historical
        pointer = {"schema": "appsec-review/latest-handoff/1", "attempt_id": attempt,
                   "handoff_path": f"data/jobs/{_NATIVE_SBOM_JOB}/attempts/{attempt}/handoff.json",
                   "handoff_sha256": digest}
    attempt = pointer.get("attempt_id")
    if (pointer.get("schema") != "appsec-review/latest-handoff/1"
            or not isinstance(attempt, str) or not attempt
            or pointer.get("handoff_path") != f"data/jobs/{_NATIVE_SBOM_JOB}/attempts/{attempt}/handoff.json"):
        raise ValueError("native SBOM accepted pointer is invalid")
    handoff_ref = _native_sbom_ref(run_root, {
        "path": pointer["handoff_path"], "sha256": pointer.get("handoff_sha256"),
        "size_bytes": safe_path(run_root, pointer["handoff_path"]).stat().st_size,
    })
    handoff = _native_sbom_json(run_root, handoff_ref["path"])
    if (handoff.get("schema") != "appsec-review/job-handoff/1"
            or handoff.get("status") != "ACCEPTED" or handoff.get("job_id") != _NATIVE_SBOM_JOB
            or handoff.get("attempt_id") != attempt
            or not _native_sbom_hash(handoff.get("source_fingerprint"))):
        raise ValueError("native SBOM framework handoff binding is invalid")
    members = handoff.get("artifacts")
    if not isinstance(members, list):
        raise ValueError("native SBOM framework artifact inventory is missing")

    def member(reference: object) -> Mapping[str, Any]:
        ref = _native_sbom_ref(run_root, reference)
        matches = [item for item in members if isinstance(item, Mapping)
                   and item.get("path") == ref["path"]]
        if not matches or any(any(item.get(key) != ref[key] for key in ref) for item in matches):
            raise ValueError("native SBOM publication lacks exact framework membership")
        return ref

    outputs = handoff.get("outputs")
    output = outputs.get("acceptance.publish_handoff") if isinstance(outputs, Mapping) else None
    if not isinstance(output, Mapping):
        raise ValueError("native SBOM accepted publication is missing")
    publication_ref = member(output.get("artifact"))
    publication = _native_sbom_json(run_root, publication_ref["path"])
    if (publication.get("schema") != DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
            or publication.get("source_fingerprint") != handoff["source_fingerprint"]):
        raise ValueError("native SBOM publication snapshot/schema mismatch")
    if "sbom" not in publication:
        return {"document": None, "reference": None, "handoff_sha256": handoff_ref["sha256"]}
    sbom = publication["sbom"]
    if (not isinstance(sbom, Mapping) or sbom.get("format") != "spdx-json"
            or sbom.get("spec_version") != "2.3"):
        raise ValueError("native SBOM advertised publication is invalid")
    metrics_ref = member(sbom.get("metrics"))
    document = _native_sbom_receipt(
        run_root, metrics_ref, attempt_id=attempt,
        source_fingerprint=handoff["source_fingerprint"], input_fingerprint=sbom.get("input_fingerprint"))
    if sbom.get("status") != document["status"] or "artifact" not in sbom:
        raise ValueError("native SBOM publication/metrics disposition mismatch")
    artifact = sbom["artifact"]
    if artifact is None:
        if document["status"] != "FAILED":
            raise ValueError("native SBOM successful publication has no artifact")
    elif member(artifact)["sha256"] != document["sbom_sha256"]:
        raise ValueError("native SBOM publication/metrics artifact mismatch")
    member(sbom.get("provenance"))
    if sbom.get("baseline") is not None:
        member(sbom["baseline"])
    return {"document": document, "reference": metrics_ref, "handoff_sha256": handoff_ref["sha256"]}


def _native_sbom_metrics(run_root: Path, records: list[Mapping[str, Any]]) -> Mapping[str, Any]:
    from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import GAP_KINDS, METRIC_COUNTERS
    gaps: list[str] = []
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    reuse: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    handoffs: dict[tuple[str, str], set[str]] = {}
    failures: set[tuple[str, str]] = set()
    accepted = None
    try:
        accepted = _native_sbom_accepted(run_root)
    except (OSError, ValueError, UnicodeError) as exc:
        gaps.append(f"native SBOM accepted publication: {exc}")

    for event in records:
        details = event.get("details", {})
        kind = event["event_type"]
        if event.get("job_id") != _NATIVE_SBOM_JOB:
            if kind == "NATIVE_SBOM_RESULT":
                gaps.append("native SBOM result has an unexpected job")
            continue
        key = (str(event["run_id"]), str(event["attempt_id"]))
        unit = details.get("unit_id") or ".".join(
            str(event.get(field) or "") for field in ("step_id", "task_id"))
        if kind == "NATIVE_SBOM_RESULT":
            binding = {name: details.get(name) for name in (
                "metrics_receipt", "input_fingerprint", "source_fingerprint", "status")}
            binding["unit_id"] = unit
            source = sources.setdefault(key, {"binding": binding, "invalid": False, "document": None})
            if source["binding"] != binding:
                source["invalid"] = True
                gaps.append("native SBOM result has conflicting duplicate receipts")
            if (unit != _NATIVE_SBOM_UNIT or event["run_id"] != run_root.name
                    or (event.get("step_id") not in {None, "publication"})
                    or (event.get("task_id") not in {None, "publish_sbom"})):
                source["invalid"] = True
                gaps.append("native SBOM result has an invalid event binding")
        elif kind == "JOB_REUSED" or kind == "TASK_REUSED" and unit == _NATIVE_SBOM_UNIT:
            reuse.setdefault(key, []).append(details)
        elif kind == "HANDOFF_ACCEPTED" and _native_sbom_hash(details.get("handoff_sha256")):
            handoffs.setdefault(key, set()).add(details["handoff_sha256"])
        elif (kind in {"JOB_FAILED", "TASK_FAILED", "STEP_FAILED"}
              or kind == "OPERATION_COMPLETED" and details.get("terminal_status") == "FAILED"
              and details.get("operation_id") in {"native-sbom.discovery", "native-sbom.publication"}):
            failures.add(key)

    for key, source in sources.items():
        if source["invalid"]:
            continue
        try:
            claim = _native_sbom_json(
                run_root, f"data/jobs/{_NATIVE_SBOM_JOB}/attempts/{key[1]}/claim.json")
            if (claim.get("schema") != "appsec-review/attempt-claim/1"
                    or any(claim.get(name) != value for name, value in (
                        ("run_id", key[0]), ("job_id", _NATIVE_SBOM_JOB), ("attempt_id", key[1])))):
                raise ValueError("native SBOM attempt claim binding mismatch")
            binding = source["binding"]
            if (binding["source_fingerprint"] is not None
                    and binding["source_fingerprint"] != claim.get("source_fingerprint")):
                raise ValueError("native SBOM event snapshot mismatch")
            source["document"] = _native_sbom_receipt(
                run_root, binding["metrics_receipt"], attempt_id=key[1],
                source_fingerprint=claim.get("source_fingerprint"),
                input_fingerprint=binding["input_fingerprint"])
            if binding["status"] is not None and binding["status"] != source["document"]["status"]:
                raise ValueError("native SBOM event disposition mismatch")
        except (OSError, ValueError, UnicodeError) as exc:
            source["invalid"] = True
            gaps.append(f"native SBOM result receipt: {exc}")

    selected = accepted["document"] if accepted is not None else None
    legacy = accepted is not None and selected is None
    selected_key = (run_root.name, str(selected["attempt_id"])) if selected is not None else None
    if selected_key in sources:
        source = sources[selected_key]
        if (source["invalid"] or source["document"] != selected
                or source["binding"]["metrics_receipt"] != accepted["reference"]):
            gaps.append("native SBOM accepted metrics conflict with result event")
            source["invalid"] = True
            selected = None

    rows = []
    reused_count = 0
    keys = set(sources) | failures | (set(reuse) if not legacy or sources else set())
    for key in sorted(keys):
        source = sources.get(key)
        document = source["document"] if source and not source["invalid"] else None
        reused = key in reuse
        invalid = bool(source and source["invalid"])
        if reused:
            reused_publication = accepted if key == selected_key else None
            try:
                hashes = handoffs.get(key, set()) | {
                    item["handoff_sha256"] for item in reuse[key]
                    if _native_sbom_hash(item.get("handoff_sha256"))}
                if key[0] != run_root.name or len(hashes) > 1:
                    raise ValueError("native SBOM reuse has a conflicting handoff")
                if reused_publication is None and len(hashes) == 1:
                    reused_publication = _native_sbom_accepted(
                        run_root, historical=(key[1], next(iter(hashes))))
                if (reused_publication is None or reused_publication["document"] is None or any(
                        item.get("handoff_sha256") is not None
                        and item["handoff_sha256"] != reused_publication["handoff_sha256"]
                        for item in reuse[key])):
                    raise ValueError("native SBOM reused publication is unavailable")
                if source and (source["invalid"] or source["document"] != reused_publication["document"]):
                    raise ValueError("native SBOM reused metrics conflict with result event")
                document = reused_publication["document"]
                reused_count += 1
            except (OSError, ValueError, UnicodeError) as exc:
                invalid = True
                gaps.append(f"native SBOM reuse: {exc}")
        fresh = source is not None or key in failures
        if document is None and not invalid:
            gaps.append("native SBOM failed attempt has no metrics receipt")
        status = ("INTEGRITY_ERROR" if invalid else "FAILED" if key in failures else
                  str(document["status"]) if document is not None else "INCOMPLETE")
        if invalid:
            document = None
        rows.append({
            "run_id": key[0], "job_id": _NATIVE_SBOM_JOB, "attempt_id": key[1],
            "unit_id": _NATIVE_SBOM_UNIT, "reused": reused, "fresh_work": fresh, "status": status,
            "publication_status": document["status"] if document is not None else None,
            **{name: document[name] if document is not None else None for name in (
                "source_fingerprint", "input_fingerprint", "sbom_sha256",
                "discovery_status", "conversion_status", "validation_status")},
            "counters": {name: document["counters"][name] if document is not None else None
                         for name in METRIC_COUNTERS},
            "gaps_by_kind": {name: document["gaps_by_kind"].get(name, 0) if document is not None else None
                             for name in sorted(GAP_KINDS)},
            "accounting_complete": document is not None,
            "duration_ms": None, "resources": None,
            "resource_timing_unavailable_reason": "metrics_receipt_has_no_resource_timing",
        })

    inventory_document = selected if selected is not None and selected["status"] != "FAILED" else None
    inventory = {
        "availability": "available" if inventory_document is not None else "not_available",
        **{name: selected[name] if selected is not None else None for name in (
            "status", "source_fingerprint", "input_fingerprint", "sbom_sha256")},
        "counters": {name: inventory_document["counters"][name] if inventory_document is not None else None
                     for name in METRIC_COUNTERS},
        "gaps_by_kind": {name: selected["gaps_by_kind"].get(name, 0) if selected is not None else None
                         for name in sorted(GAP_KINDS)},
    }
    available = bool(rows or selected is not None)
    if (sources or reused_count) and selected is None:
        gaps.append("native SBOM current inventory has no accepted publication")
    complete = available and not gaps and all(row["accounting_complete"] for row in rows)
    return {
        "availability": "partial" if gaps else "available" if available else "not_available",
        "accounting_complete": complete, "attempt_count": len(rows),
        "attempt_outcomes": dict(sorted(Counter(row["status"] for row in rows).items())),
        "fresh_work": sum(row["fresh_work"] for row in rows),
        "reused_publication_count": reused_count, "attempts": rows,
        "current_inventory": inventory, "gaps": sorted(set(gaps)),
    }


def aggregate_run_metrics(run_root: Path) -> Mapping[str, Any]:
    records, torn = PipelineLog(run_root).read()
    for record in records:
        validate_event(record)
    tree_sitter = _tree_sitter_metrics(Path(run_root), records)
    native_sbom = _native_sbom_metrics(Path(run_root), records)
    raw_event_count = len(records)
    raw_event_counts = Counter(str(record["event_type"]) for record in records)
    unique_records = []
    seen_invocations: dict[tuple[str, ...], Mapping[str, Any]] = {}
    duplicate_lifecycle_records = 0
    lifecycle_conflicts = []
    for record in records:
        details = record.get("details", {})
        invocation = (details.get("span_id") or details.get("model_invocation_id")
                      or details.get("tool_invocation_id") or details.get("invocation_id"))
        event = str(record["event_type"])
        if invocation:
            phase = "start" if event.endswith("STARTED") else "terminal" if event.endswith(
                ("COMPLETED", "SUCCEEDED", "FAILED", "COMPLETED_WITH_GAPS", "CANCELLED", "TIMED_OUT")) else event
            key = (str(record["run_id"]), str(record["job_id"]), str(record["attempt_id"]),
                   event.split("_", 1)[0], str(invocation), phase)
            if key in seen_invocations:
                duplicate_lifecycle_records += 1
                prior = seen_invocations[key]
                if prior["event_type"] != event or prior.get("details", {}) != details:
                    lifecycle_conflicts.append({
                        "job_id": record["job_id"], "attempt_id": record["attempt_id"],
                        "invocation_id": str(invocation), "phase": phase,
                        "reason": "conflicting_lifecycle_records"})
                continue
            seen_invocations[key] = record
        unique_records.append(record)
    records = unique_records
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
    starts: dict[tuple[str, ...], list[datetime]] = {}
    job_bounds: dict[str, list[datetime]] = {}
    queue_delays: list[int] = []
    reuse = Counter()
    work = Counter()
    measured_spans = []
    resource_admissions = []
    model_usage = []
    lifecycle_gaps = []
    ambiguous_pairs = set()
    closed_attempts = {
        (str(record["job_id"]), str(record["attempt_id"])) for record in records
        if record["event_type"] in {"JOB_SUCCEEDED", "JOB_COMPLETED_WITH_GAPS", "JOB_FAILED",
                                   "JOB_CANCELLED", "JOB_CANCELED", "JOB_TIMED_OUT"}
    }
    for record in records:
        details = record.get("details", {})
        if record["event_type"] == "OPERATION_COMPLETED":
            work.update(details.get("work", {}))
            measured_spans.append({
                "run_id": record["run_id"], "job_id": record["job_id"], "attempt_id": record["attempt_id"],
                "span_id": details.get("span_id"), "parent_span_id": details.get("parent_span_id"),
                "unit_id": details.get("unit_id"), "scope_id": details.get("scope_id"),
                "query_profile": details.get("query_profile"),
                "resource_lease_id": details.get("resource_lease_id"),
                "tool_invocation_id": details.get("tool_invocation_id"),
                "stage": details.get("operation_id"), "terminal_status": details.get("terminal_status"),
                "duration_ms": details.get("duration_ms"), "resources": details.get("resources"),
                "work": details.get("work"),
            })
        if record["event_type"] in {"RESOURCE_ADMITTED", "RESOURCE_TIMED_OUT"}:
            resource_admissions.append({
                "run_id": record["run_id"], "job_id": record["job_id"], "attempt_id": record["attempt_id"],
                "resource_lease_id": details.get("span_id"), "stage": details.get("operation_id"),
                "unit_id": details.get("unit_id"), "scope_id": details.get("scope_id"),
                "query_profile": details.get("query_profile"),
                "status": record["event_type"].removeprefix("RESOURCE_"),
                "queue_delay_ms": details.get("queue_delay_ms"),
                "reservation": details.get("reservation"), "reason": details.get("reason"),
            })
        if record["event_type"] == "MODEL_CALL_COMPLETED":
            model_usage.append({
                "run_id": record["run_id"], "job_id": record["job_id"], "attempt_id": record["attempt_id"],
                "step_id": record.get("step_id"), "task_id": record.get("task_id"),
                "invocation_id": details.get("model_invocation_id"),
                **{name: details.get(name) for name in (
                    "role", "persona", "cell_id", "batch_id", "package_id", "lane",
                    "terminal_status", "error_class", "served_provider", "served_model", "execution_mode")},
                "provider": details.get("provider"), "model": details.get("model"),
                "duration_ms": details.get("duration_ms"), "retry_count": details.get("retry_count"),
                "input_tokens": details.get("input_tokens"), "output_tokens": details.get("output_tokens"),
                "cache_tokens": details.get("cache_tokens"), "cost": details.get("cost"),
                "cost_unavailable_reason": None if details.get("cost") is not None else "no_trusted_rate_source",
                "usage_unavailable_reason": details.get("usage_unavailable_reason") or ("provider_usage_unavailable" if any(
                    details.get(name) is None for name in ("input_tokens", "output_tokens", "cache_tokens"))
                    else None),
            })
        disposition = details.get("disposition") or details.get("terminal_status") or details.get("completion_status")
        if disposition:
            dispositions[str(disposition)] += 1
        if record["event_type"] in {"TOOL_INVOCATION_COMPLETED", "MCP_TOOL_COMPLETED"}:
            tool_calls[str(details.get("tool_id") or details.get("mcp_tool") or "unknown")] += 1
        if record["event_type"] == "FINDING_TRANSITION":
            finding_states[str(details.get("new_state"))] += 1
        if isinstance(details.get("duration_ms"), (int, float)):
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
        key = (family, job, str(record.get("step_id") or "-"), str(record.get("task_id") or "-"),
               str(record.get("attempt_id") or "-"),
               str(details.get("span_id") or details.get("model_invocation_id")
                   or details.get("tool_invocation_id") or details.get("invocation_id") or "-"))
        if event.endswith("STARTED"):
            starts.setdefault(key, []).append(timestamp)
        elif event.endswith(("SUCCEEDED", "FAILED", "COMPLETED", "COMPLETED_WITH_GAPS",
                             "CANCELED", "CANCELLED", "TIMED_OUT")):
            if key in ambiguous_pairs:
                continue
            pending = starts.get(key, [])
            if pending:
                if family in {"TOOL", "MODEL", "MCP"} and key[-1] == "-" and len(pending) > 1:
                    lifecycle_gaps.append({
                        "family": family, "job_id": job, "attempt_id": key[4],
                        "invocation_id": None, "reason": "ambiguous_legacy_invocation_pairing"})
                    ambiguous_pairs.add(key)
                    starts.pop(key, None)
                    continue
                begun = pending.pop(0)
                if family == "TASK":
                    task_intervals.append((begun, timestamp, _operation_identity(record),
                                           max(0, int((timestamp - begun).total_seconds() * 1000))))
            elif family in {"TOOL", "MODEL", "MCP", "OPERATION", "TASK"}:
                lifecycle_gaps.append({
                    "family": family, "job_id": job, "attempt_id": key[4],
                    "invocation_id": None if key[-1] == "-" else key[-1], "reason": "missing_start"})
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
    genuinely_running = []
    for key, values in sorted(starts.items()):
        for value in values:
            state = {"family": key[0], "job_id": key[1], "step_id": key[2], "task_id": key[3],
                     "attempt_id": key[4], "invocation_id": None if key[-1] == "-" else key[-1],
                     "started_at": value.isoformat()}
            if (key[1], key[4]) in closed_attempts:
                lifecycle_gaps.append({**state, "reason": "missing_terminal_after_job_finished"})
            else:
                genuinely_running.append(state)
    critical = max(task_intervals, key=lambda item: item[3], default=None)
    return {"schema": RUN_METRICS_SCHEMA, "run_id": Path(run_root).name,
            "event_count": len(records), "event_counts": dict(sorted(event_counts.items())),
            "raw_event_count": raw_event_count, "raw_event_counts": dict(sorted(raw_event_counts.items())),
            "duplicate_lifecycle_records": duplicate_lifecycle_records,
            "lifecycle_conflicts": lifecycle_conflicts,
            "lifecycle_gaps": lifecycle_gaps,
            "lifecycle_accounting": "partial" if lifecycle_gaps or lifecycle_conflicts else "complete",
            "work_counters": dict(sorted(work.items())),
            "platform_work": {
                "hash_bytes": work.get("platform_hash_bytes"),
                "scan_invocations": work.get("platform_scan_invocations"),
                "measurement_scope": "explicit_instrumented_counters_only",
                "unavailable_reason": (
                    "platform_counters_not_emitted"
                    if not {"platform_hash_bytes", "platform_scan_invocations"} <= work.keys() else None),
            },
            "resource_spans": measured_spans,
            "resource_admissions": resource_admissions,
            "resource_totals": None,
            "resource_totals_unavailable_reason": "inclusive_process_spans_must_not_be_summed",
            "model_invocations": model_usage,
            "avoided_platform_work": None,
            "avoided_platform_work_unavailable_reason": "excluded_trees_are_not_enumerated",
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
            "completion": completion_metrics(records),
            "owasp": _owasp_metrics(Path(run_root), records),
            "review_flow": _review_flow_metrics(records),
            "tree_sitter": tree_sitter,
            "native_sbom": native_sbom,
            "codeql": _codeql_metrics(Path(run_root), records),
            "debug_symbols": debug_symbol_metrics(records),
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
                     attempt_id=str(correlation.get("attempt_id", "-")),
                     step_id=correlation.get("step_id"), task_id=correlation.get("task_id"), details=details)
