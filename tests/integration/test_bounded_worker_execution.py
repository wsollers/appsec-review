"""Manual adapter integration; no provider, retrieval service or complete review graph is launched."""
from dataclasses import replace
from functools import partial
from pathlib import Path

import pytest

from appsec_review.config.remediation import RemediationBounds, RemediationModel, RemediationValidationSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ModelOutputError, ProviderError
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_inference_security_review.teams import _Cell, _run
from appsec_review.jobs.job_remediation_planning.model import run_model
from appsec_review.jobs.job_remediation_validation.job import semantic_answer
from appsec_review.observability import PipelineLog
from appsec_review.review.lead_triage import RESULT_SCHEMA, TriageGuidance, run_triage
from appsec_review.review.models import CellStatus, Role
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner
from tests.review.test_cells import LEAD, SPAN, capability, spec
from tests.review.test_execution_budget_wiring import context
from tests.review.test_lead_triage import PROFILE, lead, reader, settings

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = "PRIVATE_ADAPTER_INTEGRATION_TEXT"


def _owner(root, job):
    """Bind the real publication-context API for direct adapter calls, not graph-admission testing."""
    attempt = root / "data" / "jobs" / job / "attempts" / "attempt-1"
    return SharedArtifacts(root, attempt, {"run_id": "run-1", "job_id": job, "attempt_id": "attempt-1"})


@pytest.mark.parametrize("first_error", [
    ProviderError("temporary transport failure", retryable=True),
    ModelOutputError("malformed provider reply"),
])
def test_real_adapters_share_execution_without_sharing_authority(tmp_path, first_error):
    claim_id = "claim-" + "a" * 64
    blue = {"schema": "appsec-review/blue-result/1", "claim_id": claim_id, "citations": {},
            "proposed_relations": [], "evidence_requests": [], "rationale": PRIVATE,
            "task": "blue_control", "disposition": "unresolved"}
    calls = []
    review_replies = iter([
        first_error,
        {"action": "retrieve", "requests": [{"tool": "read_excerpt", "parameters": {"identity": SPAN}}]},
        {"action": "final", "result": blue},
    ])

    def provider(request, *, timeout_seconds):
        calls.append(request)
        assert timeout_seconds > 0
        if request.role == "blue_team_refuter":
            reply = next(review_replies)
            if isinstance(reply, BaseException):
                raise reply
            return ModelResult({"schema": request.schema, **reply}, 20, 5)
        if request.role == "lead_triager":
            assert not request.transcript
            return ModelResult({"schema": RESULT_SCHEMA, "items": [{
                "lead_id": "unknown-lead", "severity": None, "basis": "insufficient_context",
                "reason": PRIVATE,
            }]}, None, 5)
        assert request.role == "remediation_reviewer"
        assert request.task_input["protocol"]["actions"] == ["final"]
        return ModelResult({"schema": request.schema, "action": "final", "result": {
            "decision": "unresolved", "reason": PRIVATE, "evidence_ids": [LEAD],
            "residual_concerns": ["No validated repair is available."],
        }}, 20, 5)

    review = context(tmp_path, provider)
    review.settings.retry = replace(review.settings.retry, retry_on_invalid_output=True)
    cell = _Cell(spec(role=Role.BLUE_TEAM_REFUTER, claim_id=claim_id, task="blue_control",
                      output_schema=blue["schema"], guidance_text=PRIVATE),
                 capability(role=Role.BLUE_TEAM_REFUTER), "blue")
    schemas = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
    _run(review, cell, partial(schemas.errors, "blue-result"))
    assert cell.record.status is CellStatus.SUCCEEDED
    assert cell.outcome.result["disposition"] == "unresolved"
    assert len(review.core.calls) == 1
    assert review.core.calls[0][0] == "read_excerpt" and review.core.calls[0][1]["identity"] == SPAN
    assert review.budget.snapshot().input_tokens == 40
    assert review.budget.snapshot().actual_input_tokens is None

    with publication_scope_for_owner(_owner(tmp_path, "job_inference_security_review")):
        triage = run_triage([lead("unknown-lead")], settings=settings(), profile=PROFILE, infer=provider,
                            read_excerpt=reader, reference=None,
                            guidance=TriageGuidance({"sha256": "a" * 64}, PRIVATE), schemas=schemas)
    assert triage.document["leads"][0]["assessed"] is None
    assert triage.document["batches"][0]["attempts"][0]["usage"]["input_tokens"] is None

    profile = RemediationModel("test", "test-model", "high", 32_000, 8_000, 2, 0, 60)
    bounds = RemediationBounds(1, 2, 2, 8192, 2, 8192, 8192, 4, 10, 1024, 20, 32768)
    configured = RemediationValidationSettings(True, bounds, profile, (), 10, 8192)
    with publication_scope_for_owner(_owner(tmp_path, "job_remediation_validation")):
        answer, receipt = run_model(
            infer=provider, profile=profile, role="remediation_reviewer", cell_id="repair-1",
            guidance_text=PRIVATE, guidance_sha256="b" * 64, task={"evidence_ids": [LEAD]},
            validate=partial(semantic_answer, settings=configured, evidence_ids={LEAD}))
    assert answer["decision"] == "unresolved" and receipt["status"] == "answered"
    events, incomplete = PipelineLog(tmp_path).read()
    completed = [row for row in events if row["event_type"] == "MODEL_CALL_COMPLETED"]
    assert not incomplete and len(completed) == 5
    assert {row["job_id"] for row in completed} == {
        "job_inference_security_review", "job_remediation_validation"}
    assert len({row["details"]["model_invocation_id"] for row in completed}) == 5
    assert PRIVATE not in repr(events)
    assert [request.role for request in calls] == ["blue_team_refuter"] * 3 + [
        "lead_triager", "remediation_reviewer"]
