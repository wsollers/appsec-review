"""Offline adapter regressions: real execution, validation and receipts, scripted Infer only."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config.owasp import AssessmentMode, OwaspSettings
from appsec_review.inference import ModelResult
from appsec_review.inference.errors import ExecutionContractError, ModelCancelled, ModelOutputError, ProviderError
from appsec_review.inference.execution import CallContext, Execution
from appsec_review.jobs.job_dependency_intelligence.inference import PROPOSAL_SCHEMA, resolve_with_inference
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import (
    CURATION_SCHEMA, NativeInferenceBounds,
)
from appsec_review.jobs.job_dependency_intelligence.native_inference_runtime import NativeProposer
from appsec_review.jobs.job_poc_generation import writer
from appsec_review.jobs.job_post_build_security_assessment.job import build_job
from appsec_review.jobs.job_project_build.job import _infer_repair
from appsec_review.observability import PipelineLog
from appsec_review.observability.events import EventLog
from appsec_review.owasp_workbench import assessment
from appsec_review.runtime import UnitContext
from tests.test_build_topology_feedback import _inputs
from tests.test_native_inference_runtime import MODEL, proposer
from tests.test_poc_writer import BRIEF, CLAIM, SCHEMAS, with_models
from tests.test_project_build import _repair_recipe, _repair_unit
from tests.test_remediation_models import model as remediation_model
from tests.fixtures.poc_generation import relay

ROOT = Path(__file__).parents[1]
ADAPTERS = ("poc", "remediation", "dependency", "native", "planning", "repair", "post_build", "owasp")
PRIVATE = "private prompt response or provider diagnostic"


class Script:
    def __init__(self, *results):
        self.results = iter(results)
        self.calls = []

    def __call__(self, request, *, timeout_seconds):
        self.calls.append((request, timeout_seconds))
        value = next(self.results)
        if isinstance(value, BaseException):
            raise value
        return value


def _owasp(root, *, role="control_assessor", profile=None):
    return {
        "repository_root": ROOT, "run_root": root,
        "batch": {"batch_id": "batch", "assignment": {"persona": "authorization_access_control"}},
        "packages": [], "role": role, "profile": profile or {**MODEL, "retries": 1},
        "settings": OwaspSettings(True, AssessmentMode.ASSESSMENT, "reviewer", 2, 20, 2, 2, 3, 2),
        "resolver": SimpleNamespace(scope=SimpleNamespace(run_id="run"),
                                    metrics={"attempts": 0, "denials": 0, "truncations": 0, "missing": 0}),
        "attempt_id": "attempt", "unit_id": "validation.assessment",
    }


def _job(root, *, retries=1):
    return SimpleNamespace(
        run_root=root, run_id="run", attempt_id="attempt", repository_root=ROOT,
        config=SimpleNamespace(settings={"model": {**MODEL, "retries": retries}}),
        events=EventLog(root / "events.jsonl"),
    )


def _adapter(name, root, monkeypatch):
    context = CallContext(root, "run", "job_" + name, "attempt", "model", "unit")
    monkeypatch.setattr(CallContext, "current", classmethod(lambda cls: context))
    if name == "poc":
        reader = writer.WorkspaceReader(root, {}, (".",), lambda name: [])
        return (lambda infer: writer.run_writer(
            BRIEF, guidance=writer.Guidance(PRIVATE, "a" * 64), settings=with_models(),
            infer=infer, reader=reader, schemas=SCHEMAS, claim_id=CLAIM)), relay.answer()
    if name == "remediation":
        return lambda infer: remediation_model(infer), {"action": "final", "result": {"safe": True}}
    if name == "dependency":
        dependency = {"dependency_id": "dependency", "repository": None, "name": "unknown",
                      "native_candidate": {"candidate_id": "candidate", "observations": []}, "observations": []}
        return (lambda infer: resolve_with_inference(
            dependency, repository_root=ROOT, run_root=root, model={**MODEL, "retries": 1},
            supported_hosts=("github.com",), infer=infer, max_candidate_bytes=10000)), {
                "schema": PROPOSAL_SCHEMA, "candidate_id": "candidate", "repository": None, "confidence": 0}
    if name == "native":
        instance = NativeProposer(repository_root=ROOT, run_root=root, model={**MODEL, "retries": 1},
                                  infer=None, bounds=NativeInferenceBounds())
        def invoke(infer):
            instance.infer = infer
            return instance("curate", {})
        return invoke, {"schema": CURATION_SCHEMA}
    if name == "planning":
        from appsec_review.config import PlanningFeedbackSettings
        from appsec_review.jobs.job_target_analysis_plan.planning import bounded_feedback
        catalog, request, final, texts = _inputs()
        return (lambda infer: bounded_feedback(
            infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda item, bound: texts[item["path"]].encode()[:bound + 1],
            cache_root=root / "cache", identity={})), final
    if name == "repair":
        recipe = _repair_recipe("native", "lib", ["lib/CMakeLists.txt"], build_system="cmake",
                                commands=[["cmake", "--build", "lib/build"]])
        action = _repair_unit(recipe, "cmake")
        unit = SimpleNamespace(job=_job(root), unit_root=root / "repair")
        return (lambda infer: _infer_repair(
            unit, action=action, recipe=recipe, dockerfile=b"FROM accepted-image", diagnostics={},
            attempts=[], repair_number=1, infer=infer)), {
                "schema": "appsec-review/build-image-repair/3", "outcome": "NOT_IMAGE_REPAIRABLE",
                "reason": "no admitted image repair"}
    if name == "post_build":
        outputs = {
            "load.accepted_cpp_build": {"cases": {"unit-a": {}}},
            "provenance.native_units": {"projects": {"unit-a": {"actions": []}}},
            "inspection.native_units": {"projects": {"unit-a": {"records": []}}},
            "deterministic.native_units": {"projects": {"unit-a": {"checks": []}}},
        }
        unit = UnitContext(_job(root), "inference.native_units", "inference", "native_units",
                           root / "post-build", outputs)
        def invoke(infer):
            handler = next(item.handler for item in build_job(infer=infer).units
                           if item.unit_id == "inference.native_units")
            return handler(unit)["projects"]["unit-a"]
        return invoke, {"observations": []}
    assert name == "owasp"
    return (lambda infer: assessment.investigate(**_owasp(root), infer=infer)), {
        "schema": assessment.TURN_SCHEMA, "action": "final", "results": []}


def _receipts(root):
    return [json.loads(path.read_bytes()) for path in
            sorted((root / "data" / "inference-executions").rglob("*.json"))]


def _assert_accepted(name, outcome):
    if name == "poc":
        assert outcome.status == "answered"
    elif name == "remediation":
        assert outcome[0] == {"safe": True} and outcome[1]["status"] == "answered"
    elif name == "dependency":
        assert outcome[1] is None and outcome[0]["repository"] is None
    elif name == "native":
        assert outcome == {"schema": CURATION_SCHEMA}
    elif name == "planning":
        assert outcome["status"] == "ACCEPTED"
    elif name == "repair":
        assert outcome["outcome"] == "NOT_IMAGE_REPAIRABLE"
    elif name == "post_build":
        assert outcome["terminal_status"] == "SUCCEEDED"
    else:
        assert outcome["status"] == "succeeded"


@pytest.mark.parametrize("name", ADAPTERS)
@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, TypeError])
def test_programming_errors_propagate_without_model_repair(tmp_path, monkeypatch, name, error_type):
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    failure = error_type(PRIVATE)
    script = Script(failure, ModelResult(final))
    with pytest.raises(error_type) as caught:
        invoke(script)
    assert caught.value is failure and len(script.calls) == 1
    receipt, = _receipts(tmp_path)
    assert receipt["category"] == "contract" and receipt["error_class"] == error_type.__name__
    assert PRIVATE not in PipelineLog(tmp_path).path.read_text()


@pytest.mark.parametrize("name", ADAPTERS)
def test_cancellation_remains_control_flow(tmp_path, monkeypatch, name):
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    stop = ModelCancelled("stop")
    script = Script(stop, ModelResult(final))
    with pytest.raises(ModelCancelled) as caught:
        invoke(script)
    assert caught.value is stop and len(script.calls) == 1
    receipt, = _receipts(tmp_path)
    assert receipt["status"] == "CANCELLED"


@pytest.mark.parametrize("name", ADAPTERS)
@pytest.mark.parametrize("source,usage,reason", [
    ("provider", (None, None, None), "provider_usage_missing"),
    ("provider", (-1, True, "7"), "invalid_provider_usage"),
    ("replay", (17, 4, 1), "recorded_replay"),
])
def test_unknown_and_replayed_usage_are_not_zero_or_new_billing(
        tmp_path, monkeypatch, name, source, usage, reason):
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    result = ModelResult(final, *usage, raw_response=PRIVATE, usage_source=source)
    script = Script(result)
    _assert_accepted(name, invoke(script))
    assert len(script.calls) == 1
    receipt, = _receipts(tmp_path)
    assert receipt["status"] == "SUCCEEDED" and receipt["usage"]["unavailable_reason"] == reason
    events, gaps = PipelineLog(tmp_path).read()
    assert not gaps
    started = [event for event in events if event["event_type"] == "MODEL_CALL_STARTED"]
    completed = [event for event in events if event["event_type"] == "MODEL_CALL_COMPLETED"]
    assert len(started) == len(completed) == 1
    assert started[0]["details"]["model_invocation_id"] == completed[0]["details"]["model_invocation_id"]
    assert all(completed[0]["details"][key] is None for key in ("input_tokens", "output_tokens", "cache_tokens"))
    assert completed[0]["details"]["usage_source"] == source
    assert PRIVATE not in PipelineLog(tmp_path).path.read_text()
    assert PRIVATE not in json.dumps(receipt)


@pytest.mark.parametrize("name", ("poc", "dependency", "native", "planning", "post_build", "owasp"))
def test_schema_repairs_use_common_retry_metadata(tmp_path, monkeypatch, name):
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    script = Script(ModelOutputError(PRIVATE), ModelResult(final))
    _assert_accepted(name, invoke(script))
    assert len(script.calls) == 2
    receipts = _receipts(tmp_path)
    assert [item["retry_count"] for item in receipts] == [0, 1]
    assert [item["retry_reason"] for item in receipts] == [None, "schema"]
    assert PRIVATE not in PipelineLog(tmp_path).path.read_text()


@pytest.mark.parametrize("name", ("dependency", "native", "repair", "post_build"))
def test_model_request_receipts_use_the_exact_pinned_guidance(tmp_path, monkeypatch, name):
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    _assert_accepted(name, invoke(Script(ModelResult(final))))
    receipt, = _receipts(tmp_path)
    assert (tmp_path / "data" / "guidance" / receipt["guidance_sha256"]).is_dir()
    events, _ = PipelineLog(tmp_path).read()
    completed, = [item for item in events if item["event_type"] == "MODEL_CALL_COMPLETED"]
    assert completed["details"]["guidance_bundle_sha256"] == receipt["guidance_sha256"]
    if name == "repair":
        assert completed["details"]["build_unit_id"] == "build-unit-" + "a" * 20
    elif name == "post_build":
        assert completed["details"]["case_id"] == "unit-a"


@pytest.mark.parametrize("name", ("poc", "dependency", "native", "planning", "post_build", "owasp"))
def test_first_error_mode_never_repairs_a_model_reply(tmp_path, monkeypatch, name):
    from appsec_review.runtime import execution_safety as safety
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    monkeypatch.setattr(safety, "active", lambda: True)
    script = Script(ModelOutputError("invalid"), ModelResult(final))
    if name in {"native", "dependency"}:
        with pytest.raises(safety.ReviewStopped):
            invoke(script)
    else:
        invoke(script)
    assert len(script.calls) == 1
    assert len(_receipts(tmp_path)) == 1


@pytest.mark.parametrize("name", ("poc", "dependency", "native", "post_build", "owasp"))
@pytest.mark.parametrize("retryable", [False, True])
def test_only_transient_provider_errors_are_retried(tmp_path, monkeypatch, name, retryable):
    from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import NativeInferenceError
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    script = Script(ProviderError(PRIVATE, retryable=retryable), ModelResult(final))
    if name == "native" and not retryable:
        with pytest.raises(NativeInferenceError):
            invoke(script)
    else:
        invoke(script)
    assert len(script.calls) == (2 if retryable else 1)
    assert PRIVATE not in PipelineLog(tmp_path).path.read_text()


def test_native_contract_result_is_not_an_unavailable_provider(tmp_path):
    instance = proposer(tmp_path, fake=Script({"proposal": {}}))
    with pytest.raises(ExecutionContractError, match="ModelResult"):
        instance("curate", {})


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, TypeError])
def test_outer_build_repair_does_not_swallow_inference_programming_errors(tmp_path, monkeypatch, error_type):
    from appsec_review.jobs.job_project_build import job
    recipe = _repair_recipe("native", "lib", ["lib/CMakeLists.txt"], build_system="cmake",
                            commands=[["cmake", "--build", "lib/build"]])
    action = {**_repair_unit(recipe, "cmake"), "recipe": recipe}
    unit = SimpleNamespace(job=_job(tmp_path), unit_root=tmp_path / "probe")
    unit.job.config.settings["repair_attempts"] = 2
    monkeypatch.setattr(job, "_probe_one", lambda *_args, **_kwargs: {
        "terminal_status": "FAILED", "gaps": ["observed external build failure"]})
    resolver = SimpleNamespace(definition=lambda *_args: ("identity", b"FROM accepted-image"))
    failure = error_type("inference programming error")
    script = Script(failure)
    with pytest.raises(error_type) as caught:
        job._probe_with_repairs(unit, {"action": action}, profile=None, resolver=resolver, infer=script)
    assert caught.value is failure and len(script.calls) == 1


def test_native_known_subtotals_are_separate_from_unknown_complete_usage(tmp_path):
    from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import CURATION_SCHEMA
    final = {"schema": CURATION_SCHEMA}
    instance = proposer(tmp_path, fake=Script(
        ModelResult(final, input_tokens=3, output_tokens=2, cache_tokens=0),
        ModelResult(final),
        ModelResult(final, input_tokens=90, output_tokens=50, cache_tokens=0, usage_source="replay")))
    for _ in range(3):
        instance("curate", {})
    assert instance.metrics["input_tokens"] == 3 and instance.metrics["output_tokens"] == 2
    assert instance.usage_totals == {"input_tokens": None, "output_tokens": None, "cache_tokens": None}
    assert instance.metrics["unknown_usage_calls"] == 2


def test_poc_private_capability_and_final_turn_prevent_another_read(tmp_path):
    reads = []
    reader = writer.WorkspaceReader(tmp_path, {}, (".",), lambda name: reads.append(name) or [])
    assert reader.capabilities.scope == "hash-verified-accepted-workspace"
    assert reader.capabilities.read_only and reader.capabilities.tools == writer.TOOLS
    ask = ModelResult({"action": "retrieve", "requests": [
        {"tool": "find_declaration", "parameters": {"name": "Header"}}]})
    script = Script(ask, ask)
    result = writer.run_writer(BRIEF, guidance=writer.Guidance("", "a" * 64),
        settings=with_models(max_turns=2, max_attempts=1), infer=script, reader=reader,
        schemas=SCHEMAS, claim_id=CLAIM)
    assert result.status == "failed" and reads == ["Header"]
    assert result.attempts[0].reason == "cap_reached_without_final"


def test_poc_whole_conversation_deadline_retains_usage_and_stops_retrieval(tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(writer, "Execution", lambda **kwargs: Execution(**kwargs, clock=lambda: now[0]))
    reads = []
    reader = writer.WorkspaceReader(tmp_path, {}, (".",), lambda name: reads.append(name) or [])
    def infer(request, *, timeout_seconds):
        now[0] += timeout_seconds + 1
        return ModelResult({"action": "retrieve", "requests": [
            {"tool": "find_declaration", "parameters": {"name": "Header"}}]},
                           input_tokens=4, output_tokens=3)
    result = writer.run_writer(BRIEF, guidance=writer.Guidance("", "a" * 64), settings=with_models(),
                               infer=infer, reader=reader, schemas=SCHEMAS, claim_id=CLAIM)
    assert len(result.attempts) == 1 and not reads
    assert result.attempts[0].reason == "execution_deadline"
    assert (result.attempts[0].input_tokens, result.attempts[0].output_tokens) == (4, 3)


def test_poc_private_reader_contract_cannot_be_widened(tmp_path):
    reader = writer.WorkspaceReader(tmp_path, {}, (".",), lambda name: [])
    reader.capabilities = replace(reader.capabilities, tools=(*writer.TOOLS, "shell"))
    with pytest.raises(ExecutionContractError, match="private"):
        writer.run_writer(BRIEF, guidance=writer.Guidance("", "a" * 64), settings=with_models(),
            infer=lambda *_a, **_kw: pytest.fail("invalid capability must prevent dispatch"), reader=reader,
            schemas=SCHEMAS, claim_id=CLAIM)


def test_poc_transcript_cap_prevents_the_next_physical_call(tmp_path):
    reader = writer.WorkspaceReader(tmp_path, {}, (".",), lambda name: [{"text": ["x" * 6000]}])
    script = Script(ModelResult({"action": "retrieve", "requests": [
        {"tool": "find_declaration", "parameters": {"name": "Header"}}]}))
    result = writer.run_writer(BRIEF, guidance=writer.Guidance("", "a" * 64),
        settings=with_models(max_input_tokens=800), infer=script, reader=reader, schemas=SCHEMAS, claim_id=CLAIM)
    assert result.status == "failed" and len(script.calls) == 1
    assert result.attempts[-1].reason == "input_byte_bound"


def test_remediation_cumulative_output_cap_retains_usage_of_rejected_final():
    from appsec_review.config.remediation import RemediationModel
    from tests.remediation_support import MODEL as REMEDIATION_MODEL
    profile = replace(RemediationModel.from_mapping(REMEDIATION_MODEL), max_output_tokens=30)
    script = Script(ModelResult({"action": "retrieve", "request": {"padding": "x" * 170}},
                                input_tokens=3, output_tokens=2),
                    ModelResult({"action": "final", "result": {"safe": True}}, input_tokens=4, output_tokens=3))
    result, receipt = remediation_model(script, profile=profile, retrieve=lambda request: {})
    assert result is None and receipt["reason"] == "output_budget_exceeded"
    assert len(script.calls) == 2 and [turn["input_tokens"] for turn in receipt["turns"]] == [3, 4]


@pytest.mark.parametrize("error_type", [RuntimeError, TypeError])
def test_remediation_retrieval_programming_errors_are_not_invalid_model_output(error_type):
    def retrieve(_request):
        raise error_type("retrieval contract bug")
    with pytest.raises(error_type, match="retrieval contract bug"):
        remediation_model(Script(ModelResult({"action": "retrieve", "request": {}})), retrieve=retrieve)


def test_remediation_real_reader_denial_is_terminal_without_repair():
    from appsec_review.jobs.job_remediation_planning.inputs import SourceReader
    reader = SourceReader(None, None, [], None)
    script = Script(ModelResult({"action": "retrieve", "request": {
        "path": "outside.c", "start_line": 1, "end_line": 1}}))
    answer, receipt = remediation_model(script, retrieve=reader.retrieve)
    assert answer is None and "admitted source file" in receipt["reason"]
    assert len(script.calls) == 1 and receipt["queries"] == 1


@pytest.mark.parametrize("name", ADAPTERS)
def test_token_overrun_is_bounded_but_actual_spend_is_retained(tmp_path, monkeypatch, name):
    from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import NativeInferenceError
    from appsec_review.inference.errors import ExecutionLimit
    invoke, final = _adapter(name, tmp_path, monkeypatch)
    script = Script(ModelResult(final, input_tokens=1_000_000, output_tokens=2))
    if name == "native":
        with pytest.raises(NativeInferenceError):
            invoke(script)
    elif name == "repair":
        with pytest.raises(ExecutionLimit):
            invoke(script)
    else:
        invoke(script)
    assert len(script.calls) == 1
    receipt, = _receipts(tmp_path)
    assert receipt["failure_code"] == "model_token_cap"
    assert receipt["usage"]["input_tokens"] == 1_000_000
    events, _ = PipelineLog(tmp_path).read()
    completed, = [item for item in events if item["event_type"] == "MODEL_CALL_COMPLETED"]
    assert completed["details"]["input_tokens"] == 1_000_000


def test_owasp_roles_keep_separate_blind_contexts_and_memos(tmp_path):
    calls = []
    def infer(request, **kwargs):
        calls.append(request)
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final", "results": []})
    first = assessment.investigate(**_owasp(tmp_path), infer=infer)
    second = assessment.investigate(**_owasp(tmp_path, role="independent_reviewer"), infer=infer)
    reused = assessment.investigate(**_owasp(tmp_path), infer=infer)
    assert first["status"] == second["status"] == "succeeded" and reused["status"] == "reused"
    assert len(calls) == 2 and all(request.transcript == () for request in calls)
    assert [request.role for request in calls] == ["control_assessor", "independent_reviewer"]
    assert calls[0].guidance_bundle_sha256 != calls[1].guidance_bundle_sha256
    assert first["receipt"] != second["receipt"]


def test_owasp_no_evidence_stays_unknown_with_independent_usage_and_blind_inputs(tmp_path):
    args = _owasp(tmp_path)
    package = {
        "row_id": "row", "package_id": "package", "component": {"component_id": "component"},
        "control": {}, "evidence_references": [], "proof_obligations": [{
            "obligation_id": "obligation", "subject_id": "subject", "supported": True,
            "evidence_mode": "static_source"}],
    }
    marker = "worker-only missing evidence explanation"
    calls = []
    def infer(request, **kwargs):
        calls.append(request)
        independent = request.role == "independent_reviewer"
        if independent:
            assert marker not in json.dumps(request.task_input)
            assert not request.transcript
        result = {"schema": assessment.TURN_SCHEMA, "action": "final", "results": [
            {"row_id": "row", "obligations": [{
                "obligation_id": "obligation", "subject_id": "subject", "outcome": "cannot_verify",
                "rationale": "independent evidence gap" if independent else marker,
                "supporting": [], "contradictory": [], "assumptions": [], "evidence_requests": [],
                "hypotheses": [], "limitations": [],
            }]}]}
        return ModelResult(result, input_tokens=None if independent else 3,
                           output_tokens=None if independent else 2)
    result = assessment.run_batch(repository_root=ROOT, run_root=tmp_path,
        batch={**args["batch"], "fingerprint": "b" * 64}, packages=[package], settings=args["settings"],
        worker_profile=args["profile"], reviewer_profile=args["profile"], resolver=args["resolver"], infer=infer)
    assert len(calls) == 2 and result["results"][0]["status"] == "cannot_verify"
    assert result["results"][0]["verification_status"] == "unresolved"
    assert result["metrics"]["input_tokens_reported"] is None
    assert result["metrics"]["output_tokens_reported"] is None
    assert result["metrics"]["known_input_tokens_subtotal"] == 3
    assert result["metrics"]["known_output_tokens_subtotal"] == 2
    assert result["metrics"]["unknown_usage_attempts"] == 1
