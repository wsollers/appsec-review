"""Run-owned OpenVEX measurements; semantic counters require verified acceptance."""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
import hashlib
import math
from pathlib import Path
from typing import Any

from appsec_review.review.models import IntegrityError
from appsec_review.storage.shared import safe_path

from .contracts import (
    ArtifactRef, DURATION_BUCKETS, EVENT_NAMES, ExportBundle, ExportFailureReason,
    ExportOutcome, ExportPhase, ExportReportView, JOB_ID, METRICS_SCHEMA, SIZE_BUCKETS,
    parse_json_bytes,
)
from .settings import OpenVexExportSettings

_OUTCOMES = (*tuple(item.value for item in ExportOutcome), "failed")
_EXCLUSIONS = ("gate_verification_backlog", "gate_withheld")
_OPERATIONS = {
    "openvex.verify_inputs": "load", "openvex.assemble": "assemble",
    "openvex.validate": "validate", "openvex.accept": "accept",
}
_SUCCEEDED = {"JOB_SUCCEEDED", "JOB_COMPLETED_WITH_GAPS"}
_FAILED = {"JOB_FAILED", "JOB_CANCELLED", "JOB_CANCELED", "JOB_TIMED_OUT"}
_RUNTIME = _SUCCEEDED | _FAILED | {"JOB_STARTED", "JOB_REUSED", "HANDOFF_ACCEPTED"}
_READ_ERRORS = (OSError, ValueError, UnicodeError, IntegrityError)
_CONFIG_BYTES = 8 * 1024 * 1024


def _read_accepted_export(run_root: Path, handoff: ArtifactRef, settings: OpenVexExportSettings,
                          repository_root: Path) -> ExportBundle:
    from .reporting import read_accepted_export
    return read_accepted_export(run_root, handoff, settings, repository_root)


def _load_export(run_root: Path, settings: OpenVexExportSettings, repository_root: Path, *,
                 exporter_release: str) -> ExportReportView:
    from .reporting import load_export
    return load_export(run_root, settings, repository_root, exporter_release=exporter_release)


def _bounded_json(run_root: Path, relative: str, limit: int) -> tuple[dict[str, Any], bytes]:
    path = safe_path(run_root, relative)
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    return parse_json_bytes(payload, max_bytes=limit), payload


def _configuration(run_root: Path) -> tuple[OpenVexExportSettings | None, str]:
    manifest, _ = _bounded_json(run_root, "data/configuration/manifest.json", _CONFIG_BYTES)
    resolved, payload = _bounded_json(run_root, "data/configuration/resolved.json", _CONFIG_BYTES)
    if (manifest.get("schema") != "appsec-review/run-configuration/2"
            or hashlib.sha256(payload).hexdigest() != manifest.get("resolved_sha256")):
        raise ValueError("OpenVEX frozen configuration integrity mismatch")
    jobs = resolved.get("jobs")
    if not isinstance(jobs, Mapping):
        raise ValueError("OpenVEX frozen configuration has no jobs table")
    if JOB_ID not in jobs:
        return None, "undeclared"
    job = jobs[JOB_ID]
    if not isinstance(job, Mapping) or not isinstance(job.get("settings"), Mapping):
        raise ValueError("OpenVEX frozen job settings are unavailable")
    settings = OpenVexExportSettings.from_mapping(job["settings"])
    policy = resolved.get("review_policy", {})
    if not isinstance(policy, Mapping) or not isinstance(policy.get("releases", {}), Mapping):
        raise ValueError("OpenVEX frozen release policy is invalid")
    releases = policy.get("releases", {})
    release = releases.get(JOB_ID, releases.get("platform", "undeclared"))
    if not isinstance(release, str) or not release:
        raise ValueError("OpenVEX frozen exporter release is invalid")
    return settings, release


def _histogram(bounds: Sequence[int | float], values: Sequence[int | float] = (), *,
               unmeasured: int = 0) -> dict[str, Any]:
    return {
        "buckets": {**{str(bound): sum(value <= bound for value in values) for bound in bounds},
                    "+Inf": len(values)},
        "count": len(values), "sum": sum(values) if values else None,
        "measured_count": len(values), "unmeasured_count": unmeasured,
    }


def _seconds(value: object) -> float | None:
    if type(value) not in {int, float} or value < 0:
        return None
    try:
        seconds = value / 1000
    except OverflowError:
        return None
    return seconds if math.isfinite(seconds) else None


def _wall_duration(start: Mapping[str, Any] | None, terminal: Mapping[str, Any] | None
                   ) -> float | None:
    if terminal is None:
        return None
    measured = _seconds(terminal.get("details", {}).get("duration_ms"))
    if measured is not None:
        return measured
    if start is None:
        return None
    try:
        begun, ended = (datetime.fromisoformat(str(event.get("timestamp"))) for event in (start, terminal))
    except ValueError:
        return None
    if begun.utcoffset() is None or ended.utcoffset() is None or ended < begun:
        return None
    duration = (ended - begun).total_seconds()
    return duration if math.isfinite(duration) else None


def _counts(bundle: ExportBundle) -> dict[str, Any]:
    return {
        "outcome": bundle.result["outcome"],
        **{name: bundle.result[name] for name in (
            "statement_count", "included_findings", "excluded_findings")},
        "exclusion_counts": {reason: bundle.manifest["accounting"]["exclusion_counts"][reason]
                             for reason in _EXCLUSIONS},
        "document_bytes": bundle.document_ref.size_bytes if bundle.document_ref else 0,
    }


def aggregate_openvex_metrics(run_root: Path, records: Sequence[Mapping[str, Any]], *,
                              repository_root: Path | None = None) -> dict[str, Any]:
    """Consume raw events, before generic lifecycle deduplication can hide conflicts.

    Metric series use only the closed labels below. Identities belong solely to correlation
    rows/gaps. Historical bundles go through the same full verifier as report consumers.
    """
    run_root = Path(run_root)
    repository_root = repository_root or Path(__file__).resolve().parents[4]
    gaps: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    duplicate_count = 0

    def gap(reason: str, correlation: Mapping[str, Any] | None = None, *, conflict: bool = False) -> None:
        row = {"reason": reason, **(correlation or {})}
        target = conflicts if conflict else gaps
        if row not in target:
            target.append(row)

    relevant = [event for event in records if event.get("job_id") == JOB_ID and (
        event.get("event_type") in {*EVENT_NAMES, *_RUNTIME}
        or event.get("event_type") in {"OPERATION_STARTED", "OPERATION_COMPLETED"}
        and event.get("details", {}).get("operation_id") in _OPERATIONS)]
    settings = None
    release = "undeclared"
    config_invalid = False
    try:
        config_present = safe_path(run_root, "data/configuration/manifest.json").exists()
        if config_present or relevant:
            settings, release = _configuration(run_root)
    except _READ_ERRORS:
        config_invalid = True
        gap("configuration_unavailable")
    enabled = settings.enabled if settings is not None else None
    attempts: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    reuses: dict[tuple[str, ...], Mapping[str, Any]] = {}
    for event in relevant:
        details = event.get("details", {})
        run_id, attempt_id = str(event["run_id"]), str(event["attempt_id"])
        if event["event_type"] == "JOB_REUSED":
            reuse_invocation = details.get("invocation_id") or details.get("dagster_run_id")
            key = (run_id, attempt_id, str(details.get("handoff_sha256")),
                   str(reuse_invocation))
            if not reuse_invocation:
                gap("reuse_invocation_unavailable",
                    {"run_id": run_id, "job_id": JOB_ID, "attempt_id": attempt_id})
            if key in reuses:
                duplicate_count += 1
                if reuses[key].get("details") != details:
                    gap("conflicting_reuse_records", {"run_id": run_id, "attempt_id": attempt_id},
                        conflict=True)
            else:
                reuses[key] = event
            continue
        attempts.setdefault((run_id, attempt_id), []).append(event)

    attempt_totals = Counter({outcome: 0 for outcome in _OUTCOMES})
    failures: Counter[tuple[str, str]] = Counter()
    durations: dict[str, list[float]] = {outcome: [] for outcome in _OUTCOMES}
    duration_unknown: Counter[str] = Counter()
    phase_durations: dict[str, list[float]] = {phase.value: [] for phase in ExportPhase}
    phase_unknown: Counter[str] = Counter()
    unresolved_unmeasured = unreconciled_measured = 0
    document_sizes: list[int] = []
    document_unknown = 0
    statement_total = included_total = bytes_total = 0
    exclusion_totals = Counter({reason: 0 for reason in _EXCLUSIONS})
    accepted_digests: set[str] = set()
    verified: dict[ArtifactRef, ExportBundle] = {}
    attempt_rows: list[dict[str, Any]] = []

    def accepted(reference: ArtifactRef) -> ExportBundle:
        if settings is None or not settings.enabled:
            raise ValueError("OpenVEX accepted metrics require enabled frozen settings")
        if reference not in verified:
            verified[reference] = _read_accepted_export(run_root, reference, settings, repository_root)
        return verified[reference]

    for (run_id, attempt_id), events in attempts.items():
        correlation: dict[str, Any] = {"run_id": run_id, "job_id": JOB_ID, "attempt_id": attempt_id}
        by_type: dict[str, list[Mapping[str, Any]]] = {}
        invocations = set()
        for event in events:
            event_type, details = str(event["event_type"]), event.get("details", {})
            if event_type in EVENT_NAMES:
                invocation = details.get("invocation_id")
                if isinstance(invocation, str) and invocation:
                    invocations.add(invocation)
                else:
                    gap("missing_invocation_id", correlation)
            by_type.setdefault(event_type, []).append(event)
        if len(invocations) == 1:
            correlation["invocation_id"] = next(iter(invocations))
        elif len(invocations) > 1:
            gap("conflicting_invocation_ids", correlation, conflict=True)
        conflicted_types: set[str] = set()

        def one(event_type: str) -> Mapping[str, Any] | None:
            nonlocal duplicate_count
            candidates = by_type.get(event_type, [])
            if not candidates:
                return None
            first = candidates[0]
            for other in candidates[1:]:
                duplicate_count += 1
                if first.get("details") != other.get("details"):
                    conflicted_types.add(event_type)
                    gap("conflicting_" + event_type.lower(), correlation, conflict=True)
            return first

        start = one("JOB_STARTED")
        domain_start = one("OPENVEX_EXPORT_STARTED")
        one("OPENVEX_INPUTS_VERIFIED")
        one("OPENVEX_EXPORT_ACCOUNTED")
        completed = one("OPENVEX_EXPORT_COMPLETED")
        failed = one("OPENVEX_EXPORT_FAILED")
        runtime_successes = [event for name in sorted(_SUCCEEDED) if (event := one(name)) is not None]
        runtime_failures = [event for name in sorted(_FAILED) if (event := one(name)) is not None]
        acceptance = one("HANDOFF_ACCEPTED")
        if completed and failed:
            gap("conflicting_domain_terminals", correlation, conflict=True)
        if failed and runtime_successes:
            gap("conflicting_runtime_domain_terminals", correlation, conflict=True)
        if len(runtime_successes) > 1 or len(runtime_failures) > 1:
            gap("conflicting_runtime_terminals", correlation, conflict=True)
        if not (domain_start or start):
            gap("missing_start", correlation)
        if invocations and not domain_start:
            gap("missing_domain_start", correlation)
        if domain_start and not (completed or failed):
            gap("missing_domain_terminal", correlation)
        if not (runtime_successes or runtime_failures):
            gap("missing_runtime_terminal", correlation)

        outcome = None
        bundle = None
        handoff = None
        is_failed = bool(runtime_failures or failed)
        terminal = runtime_failures[-1] if runtime_failures else (
            runtime_successes[-1] if runtime_successes else failed or completed)
        timing_conflict = (len(runtime_successes) > 1 or len(runtime_failures) > 1
                           or bool(conflicted_types & {
                               "JOB_STARTED", "OPENVEX_EXPORT_COMPLETED", "OPENVEX_EXPORT_FAILED",
                               *_SUCCEEDED, *_FAILED}))
        duration = None if timing_conflict else _wall_duration(start, terminal)
        if (duration is None and not timing_conflict and (failed or completed)
                and not (runtime_failures and not failed)):
            duration = _seconds((failed or completed)["details"].get("duration_ms"))
        if is_failed:
            outcome = "failed"
            detail = (failed or runtime_failures[-1])["details"]
            if "OPENVEX_EXPORT_FAILED" in conflicted_types:
                detail = {}
            phase = detail.get("phase", "accept" if completed else "load")
            reason = detail.get("reason")
            if not isinstance(phase, str) or phase not in {item.value for item in ExportPhase}:
                gap("invalid_failure_phase", correlation)
                phase = "accept" if completed else "load"
            if not isinstance(reason, str) or reason not in {item.value for item in ExportFailureReason}:
                error = detail.get("error_type")
                reason = "timed_out" if (
                    error == "TimeoutError" or any(event["event_type"] == "JOB_TIMED_OUT"
                                                 for event in runtime_failures)) else "internal_error"
                gap("failure_reason_unavailable", correlation)
            failures[(phase, reason)] += 1
            if completed or acceptance:
                gap("runtime_finalization_failed", correlation)
        elif acceptance:
            try:
                details = acceptance["details"]
                handoff = ArtifactRef(details.get("handoff_path"), details.get("handoff_sha256"))
                if any(event["details"] != details for event in by_type["HANDOFF_ACCEPTED"]):
                    raise ValueError("conflicting accepted handoff identities")
                # Execution terminals survive later artifact corruption; semantic totals do not.
                if (completed and runtime_successes and len(invocations) <= 1
                        and "OPENVEX_EXPORT_COMPLETED" not in conflicted_types):
                    recorded_outcome = completed["details"].get("outcome")
                    if isinstance(recorded_outcome, str) and recorded_outcome in _OUTCOMES[:-1]:
                        outcome = recorded_outcome
                    else:
                        gap("invalid_terminal_outcome", correlation)
                bundle = accepted(handoff)
                if bundle.result["run_id"] != run_id:
                    raise ValueError("accepted output belongs to another run")
                outcome = ExportOutcome(bundle.result["outcome"]).value
                if completed and (
                        completed["details"].get("outcome") != outcome
                        or completed["details"].get("result_reference") != bundle.result_ref.reference.to_json()):
                    gap("domain_accepted_output_mismatch", correlation, conflict=True)
                if not completed:
                    gap("missing_domain_terminal", correlation)
                if handoff.sha256 not in accepted_digests:
                    accepted_digests.add(handoff.sha256)
                    counts = _counts(bundle)
                    statement_total += counts["statement_count"]
                    included_total += counts["included_findings"]
                    exclusion_totals.update(counts["exclusion_counts"])
                    bytes_total += counts["document_bytes"]
                    if bundle.document_ref:
                        document_sizes.append(bundle.document_ref.size_bytes)
            except _READ_ERRORS:
                bundle = None
                gap("accepted_output_unavailable", correlation)
                document_unknown += 1
        elif completed or runtime_successes:
            gap("runtime_acceptance_missing", correlation)

        if outcome is not None:
            attempt_totals[outcome] += 1
            if duration is None:
                duration_unknown[outcome] += 1
                gap("wall_duration_unavailable", correlation)
            else:
                durations[outcome].append(duration)
        else:
            if duration is None:
                unresolved_unmeasured += 1
            else:
                unreconciled_measured += 1
        attempt_rows.append({
            **correlation, "outcome": outcome, "accepted": bundle is not None,
            "handoff": handoff.to_json() if handoff else None, "duration_seconds": duration,
        })

        operations: dict[str, list[Mapping[str, Any]]] = {}
        for event in events:
            if event["event_type"] not in {"OPERATION_STARTED", "OPERATION_COMPLETED"}:
                continue
            span = event["details"].get("span_id")
            if not isinstance(span, str) or not span:
                gap("missing_phase_span_id", correlation)
                continue
            operations.setdefault(span, []).append(event)
        for span, measurements in operations.items():
            first = measurements[0]
            phase = _OPERATIONS[first["details"]["operation_id"]]
            finished = [event for event in measurements if event["event_type"] == "OPERATION_COMPLETED"]
            span_correlation = {**correlation, "span_id": span}
            if not any(event["event_type"] == "OPERATION_STARTED" for event in measurements):
                gap("missing_phase_start", span_correlation)
            valid = all(event["details"]["operation_id"] == first["details"]["operation_id"]
                        for event in measurements)
            if finished:
                duplicate_count += len(finished) - 1
                valid = valid and all(event["details"] == finished[0]["details"] for event in finished)
            if not valid:
                gap("conflicting_phase_measurements", span_correlation, conflict=True)
            measurement = _seconds(finished[0]["details"].get("duration_ms")) if finished and valid else None
            if measurement is None:
                phase_unknown[phase] += 1
                gap("phase_duration_unavailable", span_correlation)
            else:
                phase_durations[phase].append(measurement)

    latest = None
    latest_state = "disabled" if enabled is False else "not_run"
    if settings is not None and settings.enabled:
        try:
            view = _load_export(run_root, settings, repository_root, exporter_release=release)
            latest_state = view.state.value
            if view.handoff is not None:
                latest = _counts(accepted(view.handoff))
                latest["handoff"] = view.handoff.to_json()
            for reason in view.gaps:
                # Consumer gap text is data, never a metric label or diagnostic message.
                gap("latest_export_gap", {"gap_id": reason})
        except _READ_ERRORS:
            latest_state = "stale"
            gap("latest_accepted_output_unavailable")
    elif (relevant or config_invalid) and enabled is not False:
        latest_state = "stale"

    measured = bool(accepted_digests)
    return {
        "schema": METRICS_SCHEMA, "configured_enabled": enabled, "latest_state": latest_state,
        "latest_accepted": latest, "accepted_fresh_output_count": len(accepted_digests),
        "openvex_export_attempts_total": dict(attempt_totals),
        "openvex_export_reuses_total": len(reuses),
        "openvex_export_failures_total": [
            {"phase": phase, "reason": reason, "value": count}
            for (phase, reason), count in sorted(failures.items())],
        "openvex_export_statements_total": {"affected": statement_total if measured else None},
        "openvex_export_findings_total": [
            {"disposition": "included", "reason": "included", "value": included_total if measured else None},
            *({"disposition": "excluded", "reason": reason,
               "value": exclusion_totals[reason] if measured else None} for reason in _EXCLUSIONS)],
        "openvex_export_document_bytes_total": bytes_total if measured else None,
        "openvex_export_duration_seconds": {
            "series": [{"outcome": outcome, **_histogram(
                DURATION_BUCKETS, durations[outcome], unmeasured=duration_unknown[outcome])}
                for outcome in _OUTCOMES],
            "measured_count": sum(map(len, durations.values())),
            "unmeasured_count": sum(duration_unknown.values()) + unresolved_unmeasured,
            "unreconciled_measured_count": unreconciled_measured,
        },
        "openvex_export_phase_duration_seconds": [
            {"phase": phase.value, **_histogram(
                DURATION_BUCKETS, phase_durations[phase.value], unmeasured=phase_unknown[phase.value])}
            for phase in ExportPhase],
        "openvex_export_document_bytes": _histogram(SIZE_BUCKETS, document_sizes, unmeasured=document_unknown),
        "attempts": attempt_rows, "duplicate_lifecycle_records": duplicate_count,
        "gaps": gaps, "conflicts": conflicts,
        "accounting_complete": not gaps and not conflicts,
    }
