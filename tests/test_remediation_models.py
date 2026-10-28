from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.config.remediation import RemediationModel
from appsec_review.inference import ModelOutputError, ModelResult
from appsec_review.jobs.job_remediation_planning.model import run_model
from appsec_review.review.models import IntegrityError
from tests import remediation_support as support


def model(infer, *, profile=None, retrieve=None):
    return run_model(infer=infer, profile=profile or RemediationModel.from_mapping(support.MODEL),
                     role="remediation_writer", cell_id="remediation-writer:claim-1",
                     guidance_text="governing rules and role", guidance_sha256="a" * 64,
                     task={"kind": "unit"}, validate=lambda value: value if value == {"safe": True}
                     else (_ for _ in ()).throw(ValueError("closed answer expected")), retrieve=retrieve)


@pytest.mark.parametrize("error", [TimeoutError("timeout"), RuntimeError("provider unavailable"),
                                     ModelOutputError("unparseable"), OSError("transport failed")])
def test_writer_failures_are_explicit_unavailable_outcomes(error):
    def infer(*_args, **_kwargs):
        raise error
    result, receipt = model(infer)
    assert result is None and receipt["status"] == "failed"
    assert receipt["reason"].startswith("model_failure:")


def test_retrieval_query_budget_and_turn_caps_are_real():
    requests, retrieved = [], []
    def infer(request, **_kwargs):
        requests.append(request)
        return ModelResult({"action": "retrieve", "request": {"path": "source.c", "start_line": 1, "end_line": 1}})
    profile = replace(RemediationModel.from_mapping(support.MODEL), max_queries=1)
    result, receipt = model(infer, profile=profile, retrieve=lambda value: retrieved.append(value) or {"lines": ["x"]})
    assert result is None and len(retrieved) == 1 and len(requests) == 2
    assert "budget" in receipt["reason"]
    assert requests[1].transcript


def test_invalid_output_is_not_repaired_into_a_policy_bypass():
    calls = []
    def infer(request, **_kwargs):
        calls.append(request)
        return ModelResult({"action": "final", "result": {"commands": ["bash"]}})
    answer, receipt = model(infer)
    assert answer is None and receipt["reason"].startswith("invalid_output:")
    assert len(calls) == 1


def test_receipts_pin_model_and_answer_without_storing_raw_prompts_or_transcripts():
    answer, receipt = model(lambda *_args, **_kwargs: ModelResult(
        {"action": "final", "result": {"safe": True}}, input_tokens=3, output_tokens=4))
    assert answer == {"safe": True} and receipt["queries"] == 0
    assert receipt["guidance_bundle_sha256"] == "a" * 64 and receipt["result_sha256"]
    assert "transcript" not in receipt and "guidance_text" not in receipt and "task" not in receipt
    assert receipt["model"]["provider"] == "claude-cli"


def test_integrity_errors_do_not_become_writer_unavailability():
    def retrieve(_value):
        raise IntegrityError("accepted source changed")
    infer = lambda *_args, **_kwargs: ModelResult({"action": "retrieve", "request": {}})
    with pytest.raises(IntegrityError, match="source changed"):
        model(infer, retrieve=retrieve)


def test_input_and_output_budgets_are_enforced():
    profile = replace(RemediationModel.from_mapping(support.MODEL), max_input_tokens=1)
    result, receipt = model(lambda *_args, **_kwargs: pytest.fail("over-budget model turn"), profile=profile)
    assert result is None and receipt["reason"] == "input_budget_exceeded"
    profile = replace(RemediationModel.from_mapping(support.MODEL), max_output_tokens=1)
    result, receipt = model(lambda *_args, **_kwargs: ModelResult({"action": "final", "result": {"safe": True}}),
                            profile=profile)
    assert result is None and receipt["reason"] == "output_budget_exceeded"
