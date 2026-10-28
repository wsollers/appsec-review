from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_openvex_export import contracts as c, metrics
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from tests.openvex_support import RELEASE, enabled_settings, example_bundle, make_verified_inputs


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "run-openvex-fixture"
NOW = datetime(2026, 10, 28, 14, tzinfo=timezone.utc)


def configuration(root, settings=None, *, include_job=True, releases=None):
    settings = settings or enabled_settings()
    path = root / "data" / "configuration" / "resolved.json"
    atomic_json(path, {
        "jobs": {c.JOB_ID: {"settings": settings.to_mapping()}} if include_job else {},
        "review_policy": {"releases": releases if releases is not None else {c.JOB_ID: RELEASE}},
    })
    atomic_json(path.with_name("manifest.json"), {
        "schema": "appsec-review/run-configuration/2", "resolved_sha256": file_sha256(path),
    })


class AcceptedBoundary:
    """A doubled full-verifier edge over small synthetic hash-bound output files."""

    def __init__(self, root, monkeypatch, *, settings=None):
        self.root = root
        self.settings = settings or enabled_settings()
        self.bundles = {}
        self.bound_refs = {}
        self.reads = []
        self.latest = None
        self.state = None
        self.gaps = ()
        self.release = RELEASE
        self.repository_root = ROOT
        configuration(root, self.settings)
        monkeypatch.setattr(metrics, "_read_accepted_export", self.read)
        monkeypatch.setattr(metrics, "_load_export", self.load)

    def publish(self, attempt="attempt", *, buckets=("publishable",), review_gap=False):
        inputs = make_verified_inputs(buckets, settings=self.settings, review_gap=review_gap)
        bundle = example_bundle(inputs, self.settings, output_prefix=f"data/export/{attempt}")
        references = []
        for name in ("document", "manifest", "result"):
            reference = getattr(bundle, f"{name}_ref")
            if reference is not None:
                atomic_bytes(self.root / reference.path, getattr(bundle, f"{name}_bytes"))
                references.append(reference.reference)
        # A synthetic original-input binding also exercises failure beyond document bytes.
        original = self.root / "data" / "inputs" / f"{attempt}.json"
        atomic_json(original, {"synthetic": attempt})
        references.append(c.ArtifactRef(original.relative_to(self.root).as_posix(), file_sha256(original)))
        path = self.root / "data" / "handoffs" / f"{attempt}.json"
        atomic_json(path, {
            "schema": "synthetic-accepted-handoff", "status": "ACCEPTED", "job_id": c.JOB_ID,
            "attempt_id": attempt, "artifacts": [reference.to_json() for reference in references],
        })
        handoff = c.ArtifactRef(path.relative_to(self.root).as_posix(), file_sha256(path))
        self.bundles[handoff] = bundle
        self.bound_refs[handoff] = [handoff, *references]
        self.latest = handoff
        return handoff, bundle

    def read(self, root, handoff, settings, repository_root):
        assert root == self.root and settings == self.settings
        assert repository_root == self.repository_root
        self.reads.append(handoff)
        for reference in self.bound_refs[handoff]:
            if file_sha256(root / reference.path) != reference.sha256:
                raise ValueError("private verifier diagnostic including issuer and source")
        return self.bundles[handoff]

    def load(self, root, settings, repository_root, *, exporter_release):
        assert (root, settings, repository_root, exporter_release) == (
            self.root, self.settings, self.repository_root, self.release)
        if self.state is not None or self.latest is None:
            return c.ExportReportView(
                self.state or c.ExportReportState.NOT_RUN, None, None, None, None, None,
                None, None, None, self.gaps)
        bundle = self.bundles[self.latest]
        state = c.ExportReportState.NO_STATEMENTS if bundle.document is None else c.ExportReportState.AVAILABLE
        return c.ExportReportView(
            state, bundle.result["outcome"], self.latest, bundle.result_ref, bundle.manifest_ref,
            bundle.document_ref, bundle.result["statement_count"], bundle.result["included_findings"],
            bundle.result["excluded_findings"], self.gaps)


def event(root, name, *, attempt="attempt", offset=0, **details):
    if name in c.EVENT_NAMES:
        details = {"invocation_id": attempt, **details}
    record = PipelineLog(root).write(name, run_id=RUN_ID, job_id=c.JOB_ID,
                                    attempt_id=attempt, details=details)
    if offset:
        # Runtime logs use wall-clock event timestamps; set deterministic test boundaries.
        path = PipelineLog(root).path
        lines = path.read_text(encoding="utf-8").splitlines()
        record["timestamp"] = (NOW + timedelta(seconds=offset)).isoformat()
        lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        path.write_bytes(("\n".join(lines) + "\n").encode())
    return record


def fresh(root, handoff=None, bundle=None, *, attempt="attempt", duration=1000, terminal=True):
    event(root, "JOB_STARTED", attempt=attempt, offset=1)
    event(root, "OPENVEX_EXPORT_STARTED", attempt=attempt)
    if bundle is not None:
        event(root, "OPENVEX_EXPORT_COMPLETED", attempt=attempt, offset=2, outcome=bundle.result["outcome"],
              result_reference=bundle.result_ref.reference.to_json())
    if terminal:
        event(root, "JOB_SUCCEEDED", attempt=attempt, duration_ms=duration)
    if handoff is not None:
        event(root, "HANDOFF_ACCEPTED", attempt=attempt, handoff_path=handoff.path,
              handoff_sha256=handoff.sha256)


def section(root):
    return aggregate_run_metrics(root)["openvex"]


def gap_reasons(report):
    return {row["reason"] for row in report["gaps"]}


def duration_series(report, outcome="exported"):
    return next(row for row in report["openvex_export_duration_seconds"]["series"] if row["outcome"] == outcome)


def test_fresh_mixed_accepted_counts_come_from_verified_bytes_not_accounting_events(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish(buckets=("publishable", "verification_backlog", "withheld"))
    fresh(tmp_path, handoff, bundle)
    event(tmp_path, "OPENVEX_EXPORT_ACCOUNTED", statement_count=999, included_findings=999,
          exclusion_counts={"gate_withheld": 999})
    report = section(tmp_path)
    assert report["schema"] == c.METRICS_SCHEMA and report["configured_enabled"] is True
    assert report["latest_state"] == "available" and report["accounting_complete"]
    assert report["openvex_export_attempts_total"] == {
        "exported": 0, "exported_with_gaps": 1, "no_statements": 0, "failed": 0}
    assert report["openvex_export_statements_total"] == {"affected": 1}
    assert report["openvex_export_findings_total"] == [
        {"disposition": "included", "reason": "included", "value": 1},
        {"disposition": "excluded", "reason": "gate_verification_backlog", "value": 1},
        {"disposition": "excluded", "reason": "gate_withheld", "value": 1}]
    assert report["openvex_export_document_bytes_total"] == len(bundle.document_bytes)
    assert report["latest_accepted"]["exclusion_counts"] == {
        "gate_verification_backlog": 1, "gate_withheld": 1}
    assert boundary.reads == [handoff]  # Latest and cumulative accounting share the full verifier.


@pytest.mark.parametrize("buckets", [(), ("verification_backlog", "withheld")])
def test_accepted_empty_is_explicit_zero_not_unavailable_or_zero_size_sample(tmp_path, monkeypatch, buckets):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish(buckets=buckets)
    fresh(tmp_path, handoff, bundle)
    report = section(tmp_path)
    assert report["latest_state"] == "no_statements"
    assert report["openvex_export_attempts_total"]["no_statements"] == 1
    assert report["openvex_export_statements_total"] == {"affected": 0}
    assert report["openvex_export_document_bytes_total"] == 0
    assert report["openvex_export_findings_total"][0]["value"] == 0
    assert report["latest_accepted"]["excluded_findings"] == len(buckets)
    assert report["openvex_export_document_bytes"]["count"] == 0
    assert report["openvex_export_document_bytes"]["sum"] is None


def test_export_with_review_gaps_has_distinct_outcome_not_clean_export(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish(review_gap=True)
    fresh(tmp_path, handoff, bundle)
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["exported_with_gaps"] == 1
    assert report["latest_accepted"]["outcome"] == "exported_with_gaps"
    assert report["openvex_export_statements_total"]["affected"] == 1


@pytest.mark.parametrize("acceptance", ["domain_only", "runtime_succeeded"])
def test_completed_events_and_files_are_not_accepted_semantic_success(tmp_path, monkeypatch, acceptance):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    _, bundle = boundary.publish()
    boundary.state = c.ExportReportState.NOT_RUN
    fresh(tmp_path, bundle=bundle, terminal=acceptance == "runtime_succeeded")
    report = section(tmp_path)
    assert sum(report["openvex_export_attempts_total"].values()) == 0
    assert report["openvex_export_statements_total"] == {"affected": None}
    assert report["openvex_export_document_bytes_total"] is None
    assert report["latest_accepted"] is None and not boundary.reads
    assert "runtime_acceptance_missing" in gap_reasons(report)
    assert report["openvex_export_duration_seconds"]["measured_count"] == 0
    timing = report["openvex_export_duration_seconds"]
    assert timing["unreconciled_measured_count"] == 1


def test_runtime_finalization_failure_overrides_domain_completion(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    _, bundle = boundary.publish()
    boundary.state = c.ExportReportState.NOT_RUN
    fresh(tmp_path, bundle=bundle)
    event(tmp_path, "JOB_FAILED", offset=3, error_type="ValueError")
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert report["openvex_export_attempts_total"]["exported"] == 0
    assert report["openvex_export_statements_total"]["affected"] is None
    assert report["openvex_export_failures_total"] == [
        {"phase": "accept", "reason": "internal_error", "value": 1}]
    assert duration_series(report, "failed")["sum"] == 2
    assert "runtime_finalization_failed" in gap_reasons(report) and not boundary.reads


def test_runtime_failure_still_prevents_fresh_semantic_totals_after_an_acceptance_event(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    event(tmp_path, "JOB_FAILED", duration_ms=1100)
    boundary.state = c.ExportReportState.STALE
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert report["openvex_export_attempts_total"]["exported"] == 0
    assert report["openvex_export_statements_total"]["affected"] is None
    assert not boundary.reads


@pytest.mark.parametrize("phase,reason", [
    ("load", "input_missing"), ("assemble", "identity_conflict"),
    ("validate", "schema_invalid"), ("accept", "io_error")])
def test_closed_domain_failures_count_once_and_measure_when_available(tmp_path, monkeypatch, phase, reason):
    AcceptedBoundary(tmp_path, monkeypatch)
    fresh(tmp_path, terminal=False)
    event(tmp_path, "OPENVEX_EXPORT_FAILED", phase=phase, reason=reason, duration_ms=250)
    event(tmp_path, "JOB_FAILED", error_type="ExportError", duration_ms=500)
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert report["openvex_export_failures_total"] == [{"phase": phase, "reason": reason, "value": 1}]
    assert duration_series(report, "failed")["sum"] == .5
    assert report["openvex_export_statements_total"]["affected"] is None


@pytest.mark.parametrize("runtime,error,reason", [
    ("JOB_FAILED", "TimeoutError", "timed_out"),
    ("JOB_TIMED_OUT", "WorkerError", "timed_out"),
    ("JOB_FAILED", "ValueError", "internal_error"),
])
def test_pre_domain_admission_failures_are_counted_without_invented_reason(tmp_path, monkeypatch, runtime, error, reason):
    AcceptedBoundary(tmp_path, monkeypatch)
    event(tmp_path, "JOB_STARTED", offset=1)
    event(tmp_path, runtime, offset=2, error_type=error)
    report = section(tmp_path)
    assert report["openvex_export_failures_total"] == [{"phase": "load", "reason": reason, "value": 1}]
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert duration_series(report, "failed")["sum"] == 1
    assert "failure_reason_unavailable" in gap_reasons(report)


def test_runtime_failure_without_start_or_duration_has_no_fake_zero(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    event(tmp_path, "JOB_FAILED", error_type="ValueError")
    report = section(tmp_path)
    histogram = duration_series(report, "failed")
    assert histogram["count"] == 0 and histogram["sum"] is None
    assert histogram["unmeasured_count"] == 1
    assert "wall_duration_unavailable" in gap_reasons(report)


def test_interrupted_attempt_is_gap_not_failed_or_successful_zero_work(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    fresh(tmp_path, terminal=False)
    report = section(tmp_path)
    assert sum(report["openvex_export_attempts_total"].values()) == 0
    assert report["openvex_export_statements_total"]["affected"] is None
    assert report["openvex_export_duration_seconds"]["unmeasured_count"] == 1
    assert duration_series(report)["count"] == 0
    assert {"missing_domain_terminal", "missing_runtime_terminal"} <= gap_reasons(report)


def test_reuse_only_has_latest_verified_counts_but_no_fresh_work_or_timing(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, _ = boundary.publish()
    for _ in range(2):
        event(tmp_path, "JOB_REUSED", handoff_sha256=handoff.sha256, dagster_run_id="same-dispatch")
    report = section(tmp_path)
    assert report["openvex_export_reuses_total"] == 1
    assert report["duplicate_lifecycle_records"] == 1
    assert not report["attempts"] and sum(report["openvex_export_attempts_total"].values()) == 0
    assert report["openvex_export_statements_total"]["affected"] is None
    assert report["latest_accepted"]["statement_count"] == 1
    assert report["openvex_export_duration_seconds"]["measured_count"] == 0
    assert report["openvex_export_duration_seconds"]["unmeasured_count"] == 0
    assert report["openvex_export_document_bytes"]["count"] == 0


def test_distinct_reuse_dispatches_count_separately_and_never_repeat_fresh_totals(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    for dispatch in ("dispatch-1", "dispatch-2"):
        event(tmp_path, "JOB_REUSED", handoff_sha256=handoff.sha256, dagster_run_id=dispatch)
    report = section(tmp_path)
    assert report["openvex_export_reuses_total"] == 2
    assert report["openvex_export_attempts_total"]["exported"] == 1
    assert report["openvex_export_statements_total"]["affected"] == 1
    assert report["openvex_export_duration_seconds"]["measured_count"] == 1


def test_reuse_invocations_distinguish_same_orchestrator_dispatch(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, _ = boundary.publish()
    for invocation in ("reuse-1", "reuse-2", "reuse-2"):
        event(tmp_path, "JOB_REUSED", handoff_sha256=handoff.sha256,
              invocation_id=invocation, dagster_run_id="same-dispatch")
    report = section(tmp_path)
    assert report["openvex_export_reuses_total"] == 2
    assert report["duplicate_lifecycle_records"] == 1
    assert not report["gaps"]


def test_uncorrelated_manual_reuse_is_a_named_gap_not_silent_exact_accounting(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, _ = boundary.publish()
    for _ in range(2):
        event(tmp_path, "JOB_REUSED", handoff_sha256=handoff.sha256)
    report = section(tmp_path)
    assert report["openvex_export_reuses_total"] == 1
    assert "reuse_invocation_unavailable" in gap_reasons(report)
    assert not report["accounting_complete"]


def test_duplicates_across_runtime_domain_and_spans_do_not_double_work(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    event(tmp_path, "OPERATION_STARTED", span_id="span", operation_id="openvex.validate")
    event(tmp_path, "OPERATION_COMPLETED", span_id="span", operation_id="openvex.validate", duration_ms=12)
    records, _ = PipelineLog(tmp_path).read()
    for record in records:
        PipelineLog(tmp_path).write(record["event_type"], run_id=record["run_id"], job_id=record["job_id"],
                                   attempt_id=record["attempt_id"], details=record["details"])
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["exported"] == 1
    assert report["openvex_export_statements_total"]["affected"] == 1
    assert report["openvex_export_document_bytes"]["count"] == 1
    assert report["openvex_export_duration_seconds"]["measured_count"] == 1
    assert report["openvex_export_phase_duration_seconds"][2]["count"] == 1
    assert not report["conflicts"]
    assert boundary.reads == [handoff]


def test_distinct_attempts_are_cumulative_but_latest_output_is_not(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    old, first = boundary.publish("old", buckets=("publishable", "publishable"))
    fresh(tmp_path, old, first, attempt="old")
    new, last = boundary.publish("new")
    fresh(tmp_path, new, last, attempt="new")
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["exported"] == 2
    assert report["openvex_export_statements_total"]["affected"] == 3
    assert report["latest_accepted"]["statement_count"] == 1
    assert report["latest_accepted"]["handoff"] == new.to_json()
    assert boundary.reads == [old, new]  # Historical reader never demands old == latest.


def test_semantic_counters_dedupe_same_accepted_digest_even_with_replayed_attempt(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    fresh(tmp_path, handoff, bundle, attempt="replayed")
    report = section(tmp_path)
    assert report["accepted_fresh_output_count"] == 1
    assert report["openvex_export_statements_total"]["affected"] == 1
    assert report["openvex_export_document_bytes"]["count"] == 1


@pytest.mark.parametrize("tamper", ["document", "manifest", "result", "handoff", "original_input"])
def test_tampered_accepted_output_is_a_named_gap_not_semantic_totals(tmp_path, monkeypatch, tamper):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    path = (tmp_path / "data" / "inputs" / "attempt.json" if tamper == "original_input" else
            tmp_path / (handoff.path if tamper == "handoff" else getattr(bundle, f"{tamper}_ref").path))
    path.write_bytes(b"{}\n")
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["exported"] == 1
    assert duration_series(report)["count"] == 1
    assert not report["attempts"][0]["accepted"]
    assert report["openvex_export_statements_total"]["affected"] is None
    assert report["openvex_export_document_bytes_total"] is None
    assert report["openvex_export_document_bytes"]["count"] == 0
    assert report["latest_accepted"] is None and report["latest_state"] == "stale"
    assert {"accepted_output_unavailable", "latest_accepted_output_unavailable"} <= gap_reasons(report)
    assert "private verifier diagnostic" not in str(report)


def test_conflicting_domain_terminals_remain_visible_before_generic_dedup(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    fresh(tmp_path, terminal=False)
    event(tmp_path, "OPENVEX_EXPORT_COMPLETED", outcome="exported", duration_ms=10)
    event(tmp_path, "OPENVEX_EXPORT_FAILED", phase="accept", reason="io_error", duration_ms=20)
    event(tmp_path, "JOB_FAILED", duration_ms=30)
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert "conflicting_domain_terminals" in {row["reason"] for row in report["conflicts"]}
    assert report["openvex_export_statements_total"]["affected"] is None


def test_conflicting_duplicate_terminal_timings_are_unmeasured_not_first_wins(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    fresh(tmp_path, terminal=False)
    for ms in (10, 20):
        event(tmp_path, "OPENVEX_EXPORT_FAILED", phase="load", reason="input_missing", duration_ms=ms)
    event(tmp_path, "JOB_FAILED", duration_ms=30)
    report = section(tmp_path)
    assert report["openvex_export_attempts_total"]["failed"] == 1
    assert duration_series(report, "failed")["count"] == 0
    assert duration_series(report, "failed")["unmeasured_count"] == 1
    assert "conflicting_openvex_export_failed" in {row["reason"] for row in report["conflicts"]}


def test_conflicting_accepted_handoffs_fail_closed_without_double_counts(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    other, _ = boundary.publish("other")
    fresh(tmp_path, handoff, bundle)
    event(tmp_path, "HANDOFF_ACCEPTED", handoff_path=other.path, handoff_sha256=other.sha256)
    report = section(tmp_path)
    assert report["accepted_fresh_output_count"] == 0
    assert report["openvex_export_statements_total"]["affected"] is None
    assert "conflicting_handoff_accepted" in {row["reason"] for row in report["conflicts"]}
    assert "accepted_output_unavailable" in gap_reasons(report)


def test_missing_domain_terminal_does_not_hide_verified_accepted_counts(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, _ = boundary.publish()
    fresh(tmp_path, handoff)
    report = section(tmp_path)
    assert report["openvex_export_statements_total"]["affected"] == 1
    assert report["openvex_export_attempts_total"]["exported"] == 1
    assert "missing_domain_terminal" in gap_reasons(report)


@pytest.mark.parametrize("duration", [True, -1, "5", float("inf"), float("nan")])
def test_invalid_measurements_never_become_zero_samples(tmp_path, monkeypatch, duration):
    AcceptedBoundary(tmp_path, monkeypatch)
    event(tmp_path, "OPENVEX_EXPORT_FAILED", phase="load", reason="input_missing", duration_ms=duration)
    event(tmp_path, "OPERATION_STARTED", span_id="span", operation_id="openvex.verify_inputs")
    event(tmp_path, "OPERATION_COMPLETED", span_id="span", operation_id="openvex.verify_inputs",
          duration_ms=duration)
    # Test the OpenVEX boundary directly: existing generic metrics predate finite-number validation.
    records, _ = PipelineLog(tmp_path).read()
    report = metrics.aggregate_openvex_metrics(tmp_path, records)
    assert duration_series(report, "failed")["count"] == 0
    assert duration_series(report, "failed")["unmeasured_count"] == 1
    assert report["openvex_export_phase_duration_seconds"][0]["count"] == 0
    assert report["openvex_export_phase_duration_seconds"][0]["unmeasured_count"] == 1


def test_histograms_have_exact_cumulative_finite_buckets_and_string_infinity(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle, duration=50)
    for stage, ms in zip(("verify_inputs", "assemble", "validate", "accept"), (0, 50, 121000, None)):
        event(tmp_path, "OPERATION_STARTED", span_id=stage, operation_id=f"openvex.{stage}")
        if ms is not None:
            event(tmp_path, "OPERATION_COMPLETED", span_id=stage, operation_id=f"openvex.{stage}", duration_ms=ms)
    report = section(tmp_path)
    histogram = duration_series(report)
    assert list(histogram["buckets"]) == [*(str(bound) for bound in c.DURATION_BUCKETS), "+Inf"]
    assert list(histogram["buckets"].values()) == [0, *([1] * 10)]
    assert histogram["count"] == histogram["measured_count"] == 1 and histogram["sum"] == .05
    phases = report["openvex_export_phase_duration_seconds"]
    assert phases[0]["sum"] == 0 and phases[0]["count"] == 1  # Actual measured zero is legitimate.
    assert phases[2]["buckets"]["120"] == 0 and phases[2]["buckets"]["+Inf"] == 1
    assert phases[3]["count"] == 0 and phases[3]["unmeasured_count"] == 1
    size = report["openvex_export_document_bytes"]
    assert list(size["buckets"]) == [*(str(bound) for bound in c.SIZE_BUCKETS), "+Inf"]
    assert size["sum"] == len(bundle.document_bytes)
    assert list(size["buckets"].values()) == sorted(size["buckets"].values())
    canonical_json(report)  # No JSON Infinity/NaN or non-string bucket sentinel.


def test_conflicting_phase_samples_are_unmeasured_and_not_doubled(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    fresh(tmp_path, terminal=False)
    event(tmp_path, "OPERATION_STARTED", span_id="same-span", operation_id="openvex.validate")
    for ms in (10, 20):
        event(tmp_path, "OPERATION_COMPLETED", span_id="same-span", operation_id="openvex.validate", duration_ms=ms)
    report = section(tmp_path)
    histogram = report["openvex_export_phase_duration_seconds"][2]
    assert histogram["count"] == 0 and histogram["unmeasured_count"] == 1
    assert "conflicting_phase_measurements" in {row["reason"] for row in report["conflicts"]}


@pytest.mark.parametrize("enabled", [False, True])
def test_disabled_and_not_run_are_explicit_states_not_success(tmp_path, monkeypatch, enabled):
    settings = enabled_settings() if enabled else OpenVexExportSettings()
    AcceptedBoundary(tmp_path, monkeypatch, settings=settings)
    report = section(tmp_path)
    assert report["configured_enabled"] is enabled
    assert report["latest_state"] == ("not_run" if enabled else "disabled")
    assert report["latest_accepted"] is None and report["accounting_complete"]
    assert report["openvex_export_statements_total"]["affected"] is None
    assert sum(report["openvex_export_attempts_total"].values()) == 0


def test_legacy_run_without_exporter_preserves_unknown_configuration(tmp_path):
    report = section(tmp_path)
    assert report["configured_enabled"] is None and report["latest_state"] == "not_run"
    assert report["openvex_export_statements_total"]["affected"] is None
    assert not report["gaps"]
    configuration(tmp_path, include_job=False)
    assert section(tmp_path) == report


@pytest.mark.parametrize("kind", ["tampered", "missing_resolved", "invalid_settings", "invalid_manifest"])
def test_unreadable_frozen_configuration_never_supplies_default_zeros(tmp_path, monkeypatch, kind):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    resolved = tmp_path / "data" / "configuration" / "resolved.json"
    manifest = resolved.with_name("manifest.json")
    if kind == "tampered":
        resolved.write_bytes(b"{}\n")
    elif kind == "missing_resolved":
        resolved.unlink()
    elif kind == "invalid_settings":
        atomic_json(resolved, {"jobs": {c.JOB_ID: {"settings": {}}}})
        atomic_json(manifest, {"schema": "appsec-review/run-configuration/2",
                               "resolved_sha256": file_sha256(resolved)})
    else:
        atomic_json(manifest, {})
    report = section(tmp_path)
    assert report["configured_enabled"] is None and report["latest_state"] == "stale"
    assert "configuration_unavailable" in gap_reasons(report)
    assert report["openvex_export_statements_total"]["affected"] is None and not boundary.reads


def test_stale_latest_does_not_erase_verified_historical_work_or_expose_latest_counts(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    boundary.state, boundary.gaps = c.ExportReportState.STALE, ("openvex_inputs_stale",)
    report = section(tmp_path)
    assert report["latest_state"] == "stale" and report["latest_accepted"] is None
    assert report["openvex_export_statements_total"]["affected"] == 1
    assert "latest_export_gap" in gap_reasons(report)


@pytest.mark.parametrize("releases,release", [({}, "undeclared"), ({"platform": "platform-v1"}, "platform-v1")])
def test_frozen_release_fallback_and_explicit_repository_root(tmp_path, monkeypatch, releases, release):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    configuration(tmp_path, releases=releases)
    boundary.release = release
    boundary.repository_root = tmp_path
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    records, _ = PipelineLog(tmp_path).read()
    report = metrics.aggregate_openvex_metrics(tmp_path, records, repository_root=tmp_path)
    assert report["latest_state"] == "available"


def test_unbounded_failure_text_and_identity_correlation_never_enter_metric_labels(tmp_path, monkeypatch):
    AcceptedBoundary(tmp_path, monkeypatch)
    event(tmp_path, "OPENVEX_EXPORT_FAILED", phase="private/source/path", reason="issuer private advice",
          source_text="private source", diagnostic="private diagnostic", duration_ms=1)
    report = section(tmp_path)
    assert report["openvex_export_failures_total"] == [
        {"phase": "load", "reason": "internal_error", "value": 1}]
    metric_fields = {key: value for key, value in report.items() if key.startswith("openvex_export_")}
    text = json.dumps(list(metric_fields.values()))
    assert all(value not in text for value in (RUN_ID, "attempt", "private", "issuer", "source", "sha256", "path"))
    assert "invalid_failure_phase" in gap_reasons(report)


def test_openvex_addition_preserves_correlated_owasp_and_review_flow_sections(tmp_path, monkeypatch):
    boundary = AcceptedBoundary(tmp_path, monkeypatch)
    log = PipelineLog(tmp_path)
    model_details = {"model_invocation_id": "owasp-call", "execution_mode": "inference",
                     "role": "control_assessor", "duration_ms": 3, "input_tokens": 7,
                     "output_tokens": 2, "terminal_status": "SUCCEEDED"}
    for name in ("MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"):
        log.write(name, run_id=RUN_ID, job_id="job_owasp_control_assessment",
                  attempt_id="owasp-attempt", details=model_details)
    before = aggregate_run_metrics(tmp_path)
    handoff, bundle = boundary.publish()
    fresh(tmp_path, handoff, bundle)
    after = aggregate_run_metrics(tmp_path)
    for key in ("owasp", "review", "review_flow", "model_invocations", "model_tokens"):
        assert after[key] == before[key]
    assert after["openvex"]["openvex_export_statements_total"]["affected"] == 1


def test_default_acceptance_edges_late_import_the_shared_full_readers(tmp_path, monkeypatch):
    settings = enabled_settings()
    handoff = c.ArtifactRef("data/handoff.json", "a" * 64)
    bundle = example_bundle(settings=settings)
    view = c.ExportReportView(c.ExportReportState.NOT_RUN, None, None, None, None, None,
                              None, None, None, ())
    calls = []

    def read(root, reference, frozen_settings, repository_root):
        calls.append(("read", root, reference, frozen_settings, repository_root))
        return bundle

    def load(root, frozen_settings, repository_root, *, exporter_release):
        calls.append(("load", root, frozen_settings, repository_root, exporter_release))
        return view

    monkeypatch.setitem(sys.modules, "appsec_review.jobs.job_openvex_export.reporting",
                        SimpleNamespace(read_accepted_export=read, load_export=load))
    assert metrics._read_accepted_export(tmp_path, handoff, settings, ROOT) is bundle
    assert metrics._load_export(tmp_path, settings, ROOT, exporter_release=RELEASE) is view
    assert calls == [("read", tmp_path, handoff, settings, ROOT),
                     ("load", tmp_path, settings, ROOT, RELEASE)]
