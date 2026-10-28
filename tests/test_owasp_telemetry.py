from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings
from appsec_review.inference import ModelResult, ReviewModelRequest
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.observability.model_calls import call_model
from appsec_review.owasp_workbench import assessment
from appsec_review.storage import atomic_json, file_sha256


def request(role="control_assessor"):
    return ReviewModelRequest("schema", role, "authorization_access_control", "owasp", "a" * 64,
                              "private guidance", {"private": "source content"}, (), "provider", "model",
                              "high", 10000, 1000, cell_id="cell")


def dispatch(root, infer, model_request=None):
    return call_model(infer, model_request or request(), timeout_seconds=10, run_root=root,
                      run_id="run", job_id="job_owasp_control_assessment", attempt_id="attempt",
                      step_id="validation", task_id="cell_1", batch_id="batch")


@pytest.mark.parametrize("role", ["control_assessor", "independent_reviewer", "red_team_analyst",
                                  "blue_team_refuter", "independent_verifier"])
def test_model_lifecycle_is_correlated_private_and_preserves_unknown_usage(tmp_path, role):
    result = ModelResult({"private": "answer content"}, input_tokens=12, served_model="served",
                         raw_response="raw provider content")
    assert dispatch(tmp_path, lambda *args, **kwargs: result, request(role)) is result
    records, _ = PipelineLog(tmp_path).read()
    assert [row["event_type"] for row in records] == ["MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"]
    assert {row["details"]["model_invocation_id"] for row in records} == {
        records[0]["details"]["model_invocation_id"]}
    assert all((row["attempt_id"], row["step_id"], row["task_id"]) ==
               ("attempt", "validation", "cell_1") for row in records)
    metrics = aggregate_run_metrics(tmp_path)
    call = metrics["model_invocations"][0]
    assert (call["role"], call["cell_id"], call["batch_id"]) == (role, "cell", "batch")
    assert call["input_tokens"] == 12 and call["output_tokens"] is None
    assert call["served_model"] == "served" and call["model"] == "model"
    assert call["cost"] is None and call["usage_unavailable_reason"] == "provider_usage_unavailable"
    assert metrics["model_tokens"] == {"input_tokens": 12}
    text = PipelineLog(tmp_path).path.read_text()
    assert all(secret not in text for secret in (
        "private guidance", "source content", "answer content", "raw provider content"))


@pytest.mark.parametrize("error,status", [
    (ValueError("private failure text"), "FAILED"), (TimeoutError("private timeout"), "TIMED_OUT"),
    (KeyboardInterrupt(), "CANCELLED"),
])
def test_transport_errors_and_cancellation_have_one_terminal_event(tmp_path, error, status):
    def fail(*args, **kwargs):
        raise error
    with pytest.raises(type(error)):
        dispatch(tmp_path, fail)
    records, _ = PipelineLog(tmp_path).read()
    assert len(records) == 2 and records[-1]["details"]["terminal_status"] == status
    assert records[-1]["details"]["error_class"] == type(error).__name__
    assert records[-1]["details"]["input_tokens"] is None
    assert "private" not in PipelineLog(tmp_path).path.read_text()
    assert not aggregate_run_metrics(tmp_path)["genuinely_running"]


@pytest.mark.parametrize("invalid", [-1, True, "4"])
def test_invalid_provider_usage_is_not_aggregated_as_measured_zero(tmp_path, invalid):
    dispatch(tmp_path, lambda *args, **kwargs: ModelResult({}, input_tokens=invalid))
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["model_invocations"][0]["input_tokens"] is None
    assert metrics["model_invocations"][0]["usage_unavailable_reason"] == "invalid_provider_usage"
    assert not metrics["model_tokens"]


def test_duplicate_lifecycle_records_do_not_double_model_usage(tmp_path):
    dispatch(tmp_path, lambda *args, **kwargs: ModelResult({}, input_tokens=10, output_tokens=2))
    log = PipelineLog(tmp_path)
    records, _ = log.read()
    log.write(records[-1]["event_type"], run_id="run", job_id="job_owasp_control_assessment",
              attempt_id="attempt", details=records[-1]["details"])
    metrics = aggregate_run_metrics(tmp_path)
    assert len(metrics["model_invocations"]) == 1
    assert metrics["owasp"]["new_model_calls"] == 1
    assert metrics["model_tokens"] == {"input_tokens": 10, "output_tokens": 2}


def test_inflight_dispatch_is_not_zero_calls_or_completed_coverage(tmp_path):
    PipelineLog(tmp_path).write("MODEL_CALL_STARTED", run_id="run", job_id="job_owasp_control_assessment",
        attempt_id="attempt", details={"model_invocation_id": "inflight", "execution_mode": "inference"})
    report = aggregate_run_metrics(tmp_path)
    assert report["owasp"]["new_model_calls"] == 1 and report["owasp"]["completed_model_calls"] == 0
    assert report["owasp"]["latest_publication"] is None
    assert report["owasp"]["coverage_unavailable_reason"] == "no_valid_publication_receipt"
    assert report["genuinely_running"]


def investigate_fixture(tmp_path, monkeypatch):
    monkeypatch.delenv("APPSEC_REVIEW_MODEL_RECORDING", raising=False)
    monkeypatch.setattr(assessment, "_guidance", lambda *args: ({"bundle_sha256": "a" * 64}, "guidance"))
    monkeypatch.setattr(assessment, "validate_final", lambda *args: None)
    monkeypatch.setattr(assessment, "_rebind", lambda proposal, *args: proposal)
    monkeypatch.setattr(assessment, "consume_named", lambda *args, **kwargs: None)
    def publish(root, path, content, **kwargs):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    monkeypatch.setattr(assessment, "publish_named", publish)
    settings = OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 2, 20, 2, 2, 2, 1)
    profile = {"provider": "provider", "model": "model", "reasoning": "high", "retries": 1,
               "timeout_seconds": 10, "max_input_tokens": 10000, "max_output_tokens": 1000}
    resolver = SimpleNamespace(scope=SimpleNamespace(run_id="run"), metrics={
        "attempts": 0, "denials": 0, "truncations": 0, "missing": 0})
    return dict(repository_root=tmp_path, run_root=tmp_path, batch={
        "batch_id": "batch", "assignment": {"persona": "authorization_access_control"}},
        packages=[], role="control_assessor", profile=profile, settings=settings, resolver=resolver,
        attempt_id="attempt", unit_id="validation.cell_1")


def test_owasp_retry_and_verified_reuse_count_only_new_calls(tmp_path, monkeypatch):
    args = investigate_fixture(tmp_path, monkeypatch)
    calls = []
    def infer(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError("provider timeout")
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final", "results": []})
    first = assessment.investigate(**args, infer=infer)
    assert first["status"] == "succeeded" and len(first["attempts"]) == 2
    second = assessment.investigate(**args, infer=infer)
    assert second["status"] == "reused" and not second["attempts"]
    assert len(calls) == 2
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["owasp"]["new_model_calls"] == 2
    assert metrics["owasp"]["verified_reuse_events"] == 1
    assert [call["retry_count"] for call in metrics["model_invocations"]] == [0, 1]


def test_owasp_denied_and_budgeted_retrievals_are_not_source_resolution(tmp_path, monkeypatch):
    args = investigate_fixture(tmp_path, monkeypatch)
    args["settings"] = replace(args["settings"], max_turns=1)
    def infer(*args, **kwargs):
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "retrieve", "requests": [
            {"source_identity": "outside", "locator": None}, {"source_identity": "outside", "locator": None}]})
    result = assessment.investigate(**args, infer=infer)
    assert result["status"] == "retrieval_budget"
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["owasp"]["model_requested_retrieval_dispositions"] == {"DENIED": 1, "SKIPPED": 1}
    assert args["resolver"].metrics["attempts"] == 0


@pytest.mark.parametrize("fails", [False, True])
def test_owasp_expansion_records_truncation_or_error_without_source_text(tmp_path, monkeypatch, fails):
    args = investigate_fixture(tmp_path, monkeypatch)
    args["settings"] = replace(args["settings"], max_turns=1)
    args["packages"] = [{"component": {"component_id": "component"}, "evidence_references": [
        {"reference": {"source_identity": "allowed"}}]}]
    def materialize(*args, **kwargs):
        if fails:
            raise ValueError("private source diagnostic")
        return {"truncated": True, "excerpt": "private source text"}
    args["resolver"].materialize = materialize
    def infer(*args, **kwargs):
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "retrieve", "requests": [
            {"source_identity": "allowed", "locator": None}]})
    assessment.investigate(**args, infer=infer)
    records, _ = PipelineLog(tmp_path).read()
    retrieval = next(row["details"] for row in records if row["event_type"] == "OWASP_RETRIEVAL_COMPLETED")
    assert retrieval["terminal_status"] == ("FAILED" if fails else "SUCCEEDED")
    assert retrieval["truncated"] == (not fails) and retrieval["duration_ms"] >= 0
    assert "private source" not in PipelineLog(tmp_path).path.read_text()


def publication(root, *, attempt="attempt", rows=3):
    path = root / "data" / "metrics" / f"{attempt}.json"
    atomic_json(path, {
        "schema": "appsec-review/owasp-workbench-result/1", "assessment_mode": "assessment",
        "coverage": {"selected_rows": rows, "dispatched_rows": 1, "reused_rows": 1, "unresolved_rows": 1},
        "index_manifest": {"sha256": "f" * 64}, "input_retrieval": {"attempts": 7},
        "telemetry": [{"model_calls": 2, "model_requested_retrievals": 1, "reused_model_results": 1,
                       "retrieval": {"attempts": 4, "denials": 1, "truncations": 2}}],
        "gaps": ["private gap text"],
    })
    reference = {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)}
    PipelineLog(root).write("OWASP_ASSESSMENT_RECORDED", run_id="run", job_id="job_owasp_control_assessment",
                            attempt_id=attempt, details={"metrics_receipt": reference})
    return path, reference


def test_metrics_resolve_publication_once_and_keep_denominators_separate(tmp_path):
    _, reference = publication(tmp_path)
    PipelineLog(tmp_path).write("OWASP_ASSESSMENT_RECORDED", run_id="run",
        job_id="job_owasp_control_assessment", attempt_id="attempt", details={"metrics_receipt": reference})
    report = aggregate_run_metrics(tmp_path)["owasp"]
    latest = report["latest_publication"]
    assert len(report["publications"]) == 1
    assert latest["coverage"]["selected_rows"] == 3 and latest["coverage"]["dispatched_rows"] == 1
    assert latest["source_resolution"]["attempts"] == 4 and latest["input_retrieval"]["attempts"] == 7
    assert latest["model_requested_retrievals"] == 1 and latest["declared_model_calls"] == 2
    assert report["new_model_calls"] == 0  # a receipt never fabricates model dispatch events
    assert latest["manifest_sha256"] == "f" * 64
    assert "private gap text" not in str(report)


@pytest.mark.parametrize("failure", ["missing", "tampered", "invalid_counts"])
def test_latest_bad_receipt_is_a_gap_not_a_fallback_to_old_coverage(tmp_path, failure):
    publication(tmp_path, attempt="old")
    path, _ = publication(tmp_path, attempt="new", rows=-1 if failure == "invalid_counts" else 4)
    if failure == "missing":
        path.unlink()
    elif failure == "tampered":
        path.write_bytes(b"{}")
    report = aggregate_run_metrics(tmp_path)["owasp"]
    assert report["latest_publication"] is None
    assert len(report["gaps"]) == 1 and report["gaps"][0]["attempt_id"] == "new"


@pytest.mark.parametrize("role", ["red_team_analyst", "blue_team_refuter", "independent_verifier"])
def test_review_guard_reports_real_dispatch_and_checks_budget_first(tmp_path, role):
    from appsec_review.jobs.job_inference_security_review.teams import _Guard
    from appsec_review.review.cells import CellBudgetExceeded
    from appsec_review.review.models import Lane
    charges = []
    ctx = SimpleNamespace(run_root=tmp_path, run_id="run", attempt_id="attempt",
        budget=SimpleNamespace(cell_launch_allowed=lambda: True, charge=lambda **kw: charges.append(kw)),
        infer=lambda *args, **kwargs: ModelResult({}, input_tokens=5, output_tokens=2))
    cell = SimpleNamespace(spec=SimpleNamespace(lane=Lane.HUNT, package_id="package"))
    profile = SimpleNamespace(timeout_seconds=10, max_input_tokens=100, max_output_tokens=100)
    guard = _Guard(ctx, cell, profile, capture=False)
    guard(request(role), timeout_seconds=10)
    assert guard.dispatches == 1 and charges == [{"model_turns": 1, "input_tokens": 5, "output_tokens": 2}]
    call = aggregate_run_metrics(tmp_path)["model_invocations"][0]
    assert (call["job_id"], call["role"], call["lane"], call["package_id"]) == (
        "job_inference_security_review", role, "hunt", "package")
    ctx.budget.cell_launch_allowed = lambda: False
    ctx.budget.usage_exhausted = lambda: "max_model_turns"
    with pytest.raises(CellBudgetExceeded):
        guard(request(role), timeout_seconds=10)
    assert len(aggregate_run_metrics(tmp_path)["model_invocations"]) == 1


def test_downstream_milestones_and_reuse_are_not_inference_or_confirmation(tmp_path):
    log = PipelineLog(tmp_path)
    log.write("PRECOMPUTED_PRODUCT_PUBLISHED", run_id="run", job_id="index", attempt_id="a", details={
        "query_set": "control_evidence", "fact_count": 3, "owasp_manifest_sha256": "f" * 64})
    log.write("REVIEW_PACKAGES_PUBLISHED", run_id="run", job_id="packages", attempt_id="a", details={
        "package_count": 2, "coverage_gap_count": 1, "package_manifest_sha256": "e" * 64})
    log.write("INFERENCE_REVIEW_CELL_COMPLETED", run_id="run", job_id="review", attempt_id="a", details={
        "cell_id": "c", "role": "independent_verifier", "terminal_status": "succeeded", "reused": True,
        "model_dispatches": 0, "counts": {"queries": 20}})
    report = aggregate_run_metrics(tmp_path)
    assert report["review_flow"]["reused_cells"] == 1
    assert report["review_flow"]["fresh_retrieval_queries"] == 0
    assert len(report["review_flow"]["milestones"]) == 2
    assert report["review_flow"]["new_model_calls"] == 0 and not report["finding_states"]


@pytest.mark.parametrize("disposition", ["fresh", "reused", "not_launched"])
def test_review_cell_terminal_metrics_cover_reuse_and_not_launched(tmp_path, monkeypatch, disposition):
    from appsec_review.jobs.job_inference_security_review import teams
    from appsec_review.review.cells import CellOutcome
    from appsec_review.review.models import CellStatus, Lane, Role
    allowed = disposition != "not_launched"
    profile = SimpleNamespace(timeout_seconds=10, max_input_tokens=100, max_output_tokens=100)
    ctx = SimpleNamespace(run_root=tmp_path, run_id="run", attempt_id="attempt",
        settings=SimpleNamespace(retry=SimpleNamespace(max_attempts=1, retry_on_timeout=True,
            retry_on_provider_error=True, retry_on_invalid_output=False)),
        budget=SimpleNamespace(cell_launch_allowed=lambda: allowed, charge=lambda **kw: None,
                               usage_exhausted=lambda: "max_model_turns"),
        infer=lambda *args, **kwargs: ModelResult({}), profile=lambda role: profile,
        core=None, receipts_root=tmp_path / "receipts")
    cell = SimpleNamespace(cell_id="cell", spec=SimpleNamespace(
        lane=Lane.HUNT, package_id="package", role=Role.INDEPENDENT_VERIFIER, persona="specialist",
        stack_profile="stack", task="task", claim_id=None), capability=None)
    record, _ = teams._not_launched(cell, "unit fixture")
    record = replace(record, status=CellStatus.SUCCEEDED, attempts=1)
    def reuse_or_run(spec, *, infer, **kwargs):
        if disposition == "fresh":
            infer(request("independent_verifier"), timeout_seconds=10)
        return CellOutcome(record, {}, (), (), (), disposition == "reused", {"queries": 4})
    monkeypatch.setattr(teams, "reuse_or_run", reuse_or_run)
    teams._run(ctx, cell, lambda result: [])
    report = aggregate_run_metrics(tmp_path)["review_flow"]
    assert report["cell_count"] == 1
    assert report["reused_cells"] == (disposition == "reused")
    assert report["new_model_calls"] == (disposition == "fresh")
    assert report["fresh_retrieval_queries"] == (4 if disposition == "fresh" else 0)


def test_recorded_replay_does_not_count_historical_usage_as_new_inference(tmp_path, monkeypatch):
    from appsec_review.inference.recording import recorded, unit_scope
    with unit_scope(run_root=tmp_path, job_id="job_owasp_control_assessment",
                    repository_root=None, target_root=None):
        monkeypatch.setenv("APPSEC_REVIEW_MODEL_RECORDING", "record")
        dispatch(tmp_path, recorded(lambda *args, **kwargs: ModelResult({}, input_tokens=9, output_tokens=2)))
        monkeypatch.setenv("APPSEC_REVIEW_MODEL_RECORDING", "replay")
        monkeypatch.setenv("APPSEC_REVIEW_MODEL_REPLAY_DIR", str(tmp_path / "data" / "inference-recordings"))
        dispatch(tmp_path, recorded(lambda *args, **kwargs: pytest.fail("replay must not call a provider")))
    report = aggregate_run_metrics(tmp_path)
    assert report["owasp"]["new_model_calls"] == 1 and report["owasp"]["replay_attempts"] == 1
    assert report["model_tokens"] == {"input_tokens": 9, "output_tokens": 2}
    assert report["model_invocations"][-1]["usage_unavailable_reason"] == "recorded_replay"


def test_publication_unit_emits_the_actual_resolving_metrics_receipt(tmp_path, monkeypatch):
    from appsec_review.jobs.job_owasp_control_assessment import job
    from appsec_review.observability import EventLog
    monkeypatch.setattr(job, "parse_settings", lambda settings: SimpleNamespace(mode=AssessmentMode.ASSESSMENT))
    monkeypatch.setattr(job, "_catalogs", lambda unit: {"ASVS": SimpleNamespace(records=[1, 2])})
    row = {"applicability": "applicable", "worker_attempt_count": 0, "execution_completion": "reused",
           "assessment_mode": "assessment", "control_status": "satisfied", "reviewer_attempt_count": 0,
           "verification_status": "independently_assessed", "coverage_completeness": "scoped",
           "lead_eligible": False, "gaps": []}
    outputs = {
        "join.deterministic_join": {"joined": {"results": [row], "accounting": {}}, "artifact": {}},
        "standards_selection.select_profiles": {"selection": {"control_count": 1}},
        "standards_selection.ingest_catalogs": {"manifest": {"gaps": []}},
        "characterization.load_inputs": {"retrieval_metrics": {"attempts": 2}},
        "publication.publish_indexes": {"manifest": {"sha256": "f" * 64}},
        "verification.independent_review": {"batch_results": [{
            "metrics": {"model_calls": 0, "reused_model_results": 2, "retrieval": {"attempts": 3}}}]},
        **{f"validation.{cell}": {"failed_batch_count": 0} for cell in job.CELLS},
    }
    events = EventLog(tmp_path / "attempt-events.jsonl", PipelineLog(tmp_path),
                      {"run_id": "run", "job_id": "job_owasp_control_assessment", "attempt_id": "a"})
    context = SimpleNamespace(run_root=tmp_path, attempt_root=tmp_path / "data" / "attempts" / "a",
                              events=events, config=SimpleNamespace(settings={}))
    unit = SimpleNamespace(job=context, unit_id="publication.publish_handoff", output=outputs.__getitem__)
    handler = next(unit.handler for unit in job.build_job().units if unit.unit_id == "publication.publish_handoff")
    result = handler(unit)
    report = aggregate_run_metrics(tmp_path)["owasp"]["latest_publication"]
    assert report["receipt"] == result["artifact"]
    assert report["coverage"]["reused_rows"] == 1 and report["coverage"]["dispatched_rows"] == 0
    assert report["input_retrieval"]["attempts"] == 2 and report["source_resolution"]["attempts"] == 3
