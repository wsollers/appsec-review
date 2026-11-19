"""T-5153/5154/5155: real bounded assessment and source-bound prerequisite acceptance."""
from copy import deepcopy
from functools import partial
from itertools import count
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.inference import ModelResult
from appsec_review.jobs.job_owasp_control_assessment import job
from appsec_review.owasp_workbench import assessment
from appsec_review.owasp_workbench.engine import deterministic_join, extract_verified_control_gaps
from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.owasp_workbench.obligations import PROCEDURES
from tests.unit.job_owasp_control_assessment.test_subject_acceptance import (
    SQL, package_for, proposal_for,
)
from tests.test_owasp_assessment_job import _base_app_config


ROOT = Path(__file__).resolve().parents[3]
PROFILE = {"provider": "offline-test", "model": "inert", "reasoning": "low", "retries": 1,
           "timeout_seconds": 5, "max_input_tokens": 20000, "max_output_tokens": 5000}
BATCH = {"batch_id": "audit", "fingerprint": "audit", "assignment": {"persona": "api_web"}}


def assessment_package(evidence, rule=PROCEDURES[0], row_id="row"):
    value = package_for(evidence, rule)
    return {**value, "row_id": row_id, "package_id": row_id, "evidence_references": [evidence],
            "expansion_identities": [evidence["reference"]["source_identity"]]}


def unknown_turn(request):
    return {"schema": assessment.TURN_SCHEMA, "action": "final", "results": [
        {"row_id": row["row_id"], "obligations": [
            {"obligation_id": item["obligation_id"], "subject_id": item["subject_id"],
             "outcome": "cannot_verify", "rationale": "No decisive evidence.", "supporting": [],
             "contradictory": [], "assumptions": [], "evidence_requests": ["Resolve provenance."],
             "hypotheses": [], "limitations": []}
            for item in row["proof_obligations"] if item.get("supported")]}
        for row in request.task_input["packages"]]}


@pytest.mark.parametrize("field", ["row_id", "obligation_id", "subject_id", "outcome", "severity"])
@pytest.mark.parametrize("bad", [[], {}, None, True], ids=["array", "object", "null", "boolean"])
def test_malformed_final_fields_use_bounded_retry(accepted, settings, tmp_path, field, bad):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        proposal = unknown_turn(request)
        if len(calls) == 1:
            row = proposal["results"][0]
            if field == "row_id":
                row[field] = bad
            elif field == "severity":
                row["obligations"][0]["hypotheses"] = [
                    {"mechanism": "Synthetic hypothesis.", "severity": bad, "ship_blocking": False}]
            else:
                row["obligations"][0][field] = bad
        return ModelResult(proposal)

    result = assessment.investigate(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[assessment_package(evidence)],
        role="control_assessor", profile=PROFILE, settings=settings, resolver=boundary.resolver, infer=infer)
    assert len(calls) == 2 and result["status"] == "succeeded"
    assert result["attempts"][0]["error_class"] == "ModelOutputError"
    assert result["attempts"][0]["error"]
    assert result["attempts"][1]["outcome"] == "succeeded"


@pytest.mark.parametrize("bad_query", [
    {"source_identity": [], "locator": None},
    {"source_identity": "source", "locator": []},
    {"source_identity": "source", "locator": {"kind": "source", "lines": [True, 1]}},
], ids=["identity-array", "locator-array", "locator-invalid-span"])
def test_malformed_retrieval_fields_use_same_retry(accepted, settings, tmp_path, bad_query):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "retrieve", "requests": [bad_query]}
                           if len(calls) == 1 else unknown_turn(request))

    result = assessment.investigate(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[assessment_package(evidence)],
        role="control_assessor", profile=PROFILE, settings=settings, resolver=boundary.resolver, infer=infer)
    assert result["status"] == "succeeded" and len(calls) == 2
    assert calls[1].transcript == ()
    assert result["attempts"][0]["error_class"] == "ModelOutputError"
    assert result["retrieval_requests"] == 0


@pytest.mark.parametrize("field,bad", [("locator", []), ("source_identity", []),
                                      ("locator", {"kind": "source", "lines": [1, False]})],
                         ids=["locator-array", "identity-array", "boolean-line"])
def test_malformed_citation_fields_retry_before_resolution(accepted, settings, tmp_path, field, bad):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        proposal = unknown_turn(request)
        reference = deepcopy(evidence["reference"])
        if len(calls) == 1:
            reference[field] = bad
        proposal["results"][0]["obligations"][0]["supporting"] = [reference]
        return ModelResult(proposal)

    result = assessment.investigate(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[assessment_package(evidence)],
        role="control_assessor", profile=PROFILE, settings=settings, resolver=boundary.resolver, infer=infer)
    assert result["status"] == "succeeded" and len(calls) == 2
    assert result["attempts"][0]["error_class"] == "ModelOutputError"
    assert result["proposal"]["results"][0]["obligations"][0]["supporting"] == [evidence["reference"]]


def test_exhausted_malformed_output_keeps_reason_and_successful_sibling(accepted, settings, tmp_path):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    package = assessment_package(evidence)
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final",
                            "results": [{"row_id": [], "obligations": []}]})

    result = assessment.run_batch(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[package], settings=settings,
        worker_profile=PROFILE, reviewer_profile=PROFILE, resolver=boundary.resolver, infer=infer,
        independent=False)
    [row] = result["results"]
    assert len(calls) == 2 and row["status"] == "cannot_verify"
    assert row["execution_completion"] == "invalid_or_provider_error"
    assert any("row_id" in gap and "string" in gap for gap in row["gaps"])
    assert all(item["error_class"] == "ModelOutputError" for item in result["worker"]["attempts"])
    # A subsequent batch in the same cell can still return a valid result, without the prior exception.
    good = assessment.investigate(
        repository_root=ROOT, run_root=tmp_path, batch={**BATCH, "batch_id": "sibling"},
        packages=[package], role="control_assessor", profile=PROFILE, settings=settings,
        resolver=boundary.resolver, infer=lambda request, **_: ModelResult(unknown_turn(request)))
    assert good["status"] == "succeeded"


def test_real_cell_keeps_completed_batches_after_later_malformed_output(accepted, tmp_path, monkeypatch):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    configured = deepcopy(dict(_base_app_config().job("job_owasp_control_assessment").settings))
    configured["model"] = {**configured["model"], **PROFILE}
    batches = [{**BATCH, "batch_id": f"batch-{index}"} for index in range(5)]
    packages = {batch["batch_id"]: [assessment_package(evidence, row_id=f"row-{index}")]
                for index, batch in enumerate(batches)}
    outputs = {"batching.partition_work": {"work": {"batches": batches}},
               "batching.build_packages": {"packages": packages}}
    # Inject accepted storage at the factory seam; the actual evidence resolver and cell execute below.
    monkeypatch.setattr(job, "_resolver", lambda _: boundary.resolver)
    calls = []

    def infer(request, **_):
        calls.append(request)
        proposal = unknown_turn(request)
        if request.task_input["packages"][0]["row_id"] == "row-4":
            proposal["results"][0]["row_id"] = []
        return ModelResult(proposal)

    unit = SimpleNamespace(
        job=SimpleNamespace(config=SimpleNamespace(settings=configured), repository_root=ROOT,
                            run_root=tmp_path, run_id="unit-run", attempt_id="attempt"),
        unit_id="validation.cell_01", output=outputs.__getitem__)
    handler = next(item.handler for item in job.build_job(infer=infer).units if item.unit_id == unit.unit_id)
    result = handler(unit)
    assert len(calls) == 3
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["failed_batch_count"] == 1
    first, second = result["batch_results"]
    assert first["terminal_state"] == "succeeded" and first["results"][0]["row_id"] == "row-0"
    assert second["terminal_state"] == "failed" and second["results"][0]["row_id"] == "row-4"
    assert any("row_id" in gap for gap in second["results"][0]["gaps"])


def test_split_rows_count_only_actual_dispatch_and_reuse(accepted, settings, tmp_path):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    huge, small = [assessment_package(evidence, row_id=f"row-{n}") for n in range(2)]
    huge["control"]["text"] = "x" * 100000
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult(unknown_turn(request))

    arguments = dict(repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[huge, small],
                     settings=settings, worker_profile=PROFILE, reviewer_profile=PROFILE,
                     resolver=boundary.resolver, infer=infer)
    result = assessment.run_batch(**arguments)
    assert [(request.role, [row["row_id"] for row in request.task_input["packages"]]) for request in calls] == [
        ("control_assessor", ["row-1"]), ("independent_reviewer", ["row-1"])]
    first, second = result["results"]
    assert first["execution_completion"] == "input_budget"
    assert first["verification_status"] == "pending"
    assert (first["worker_attempt_count"], first["reviewer_attempt_count"]) == (0, 0)
    assert (second["worker_attempt_count"], second["reviewer_attempt_count"]) == (1, 1)
    again = assessment.run_batch(**arguments)
    assert len(calls) == 2
    assert again["results"][1]["execution_completion"] == "reused"
    assert all(row["worker_attempt_count"] == row["reviewer_attempt_count"] == 0 for row in again["results"])


def test_deadline_before_transport_does_not_count_as_dispatch(accepted, settings, tmp_path, monkeypatch):
    boundary = accepted({"app.py": SQL})
    evidence = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    monkeypatch.setattr(assessment, "Execution", partial(assessment.Execution, clock=partial(next, count(0, 10))))
    calls = []

    def infer(request, **_):
        calls.append(request)
        return ModelResult(unknown_turn(request))

    result = assessment.run_batch(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[assessment_package(evidence)],
        settings=settings, worker_profile=PROFILE, reviewer_profile=PROFILE, resolver=boundary.resolver,
        infer=infer, independent=False)
    [row] = result["results"]
    assert not calls and not result["worker"]["attempts"][0]["dispatched"]
    assert row["execution_completion"] == "execution_deadline"
    assert row["worker_attempt_count"] == row["reviewer_attempt_count"] == result["metrics"]["model_calls"] == 0


COPY = "void copy(char *s) {\n char b[8]; strcpy(b,s);\n}\n"
CALLER = "void serve(int fd) {\n char in[32]; recv(fd,in,sizeof(in),0);\n copy(in);\n}\n"
RULE = next(rule for rule in PROCEDURES if rule.control == "V1.4.1")


def prerequisite_fixture(accepted, settings, *, caller=CALLER, primary_source=COPY):
    boundary = accepted({"copy.c": primary_source, "caller.c": caller},
                        languages={"copy.c": "C", "caller.c": "C"})
    evidence, _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    primary = next(item for item in evidence if item["reference"]["locator"]["path"] == "copy.c")
    context = boundary.resolver.materialize(boundary.files[1].identity, component_id="api")
    package = assessment_package(primary, RULE)
    package["evidence_references"].append(context)
    package["expansion_identities"].append(context["reference"]["source_identity"])
    return boundary, primary, context, package


@pytest.mark.parametrize("outcome", ["satisfied", "not_satisfied"])
@pytest.mark.parametrize("reverse", [False, True], ids=["primary-first", "context-first"])
@pytest.mark.parametrize("call", ["copy(in);", "if (fd) return copy(in);"], ids=["direct", "conditional-return"])
def test_source_bound_caller_prerequisite_is_not_a_second_primary(accepted, settings, outcome, reverse, call):
    boundary, primary, context, package = prerequisite_fixture(
        accepted, settings, caller=CALLER.replace("copy(in);", call))
    refs = [primary["reference"], context["reference"]]
    if reverse:
        refs.reverse()
    relation = "supporting" if outcome == "satisfied" else "contradictory"
    proposal = proposal_for(package, primary["reference"], outcome, **{relation: refs})
    [result] = assessment.accept_obligations(package, proposal, boundary.resolver)
    assert result["outcome"] == outcome and not result["gaps"]
    checks = {item["reference"]["source_identity"]: item for item in result["citation_checks"]}
    assert checks[primary["reference"]["source_identity"]]["subject_binding"]
    prerequisite = checks[context["reference"]["source_identity"]]
    assert not prerequisite["subject_binding"]
    assert prerequisite["prerequisite_binding"]["kind"] == "caller"
    assert prerequisite["prerequisite_binding"]["primary"] == primary["reference"]
    assert "analyst_assessed" in prerequisite["predicate_support"]


def test_admitted_expansion_callee_can_supply_prerequisite_context(accepted, settings):
    rule = next(rule for rule in PROCEDURES if rule.control == "V1.3.3")
    boundary, primary, context, _ = prerequisite_fixture(accepted, settings)
    package = assessment_package(context, rule)
    # The source was omitted from the initial request, but remains explicitly admitted for bounded expansion.
    package["expansion_identities"].append(primary["reference"]["source_identity"])
    refs = [context["reference"], primary["reference"]]
    [result] = assessment.accept_obligations(package,
        proposal_for(package, context["reference"], "not_satisfied", contradictory=refs), boundary.resolver)
    assert result["outcome"] == "not_satisfied" and not result["gaps"]
    [check] = [item for item in result["citation_checks"] if not item["subject_binding"]]
    assert check["prerequisite_binding"]["kind"] == "callee"
    assert check["prerequisite_binding"]["call_line"] == 3


def test_prerequisite_custody_survives_blinded_review_join_and_gap_projection(accepted, settings, tmp_path):
    boundary, primary, context, package = prerequisite_fixture(accepted, settings)
    calls = []

    def infer(request, **_):
        calls.append(request)
        row = proposal_for(package, primary["reference"], "not_satisfied",
                           contradictory=[primary["reference"], context["reference"]])
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final",
                            "results": [{"row_id": package["row_id"], **row}]})

    assessed = assessment.run_batch(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[package], settings=settings,
        worker_profile=PROFILE, reviewer_profile=PROFILE, resolver=boundary.resolver, infer=infer)
    applicability = {"row_id": package["row_id"], "outcome": "applicable", "assessment_mode": "assessment",
                     "control_identity": "ASVS:5.0.0:V1.4.1", "component_id": "api", "project_id": "project",
                     "target_id": boundary.scope.target_snapshot, "standard": "ASVS", "version": "5.0.0",
                     "profile": "L2", "evidence": [], "gaps": []}
    joined = deterministic_join([applicability], assessed["results"])
    [row] = joined["results"]
    assert [request.role for request in calls] == ["control_assessor", "independent_reviewer"]
    assert row["control_status"] == "not_satisfied" and row["verification_status"] == "independently_assessed"
    assert not calls[1].transcript and "worker" not in calls[1].task_input
    projection = extract_verified_control_gaps(boundary.scope.run_id, "assessment", [row],
                                               resolver=boundary.resolver)
    assert projection["verified_gaps_indexed"] == 1 and not projection["coverage_gaps"]
    assert {span["path"] for span in projection["control_gaps"][0]["subject_spans"]} == {"copy.c", "caller.c"}
    assert {ref["source_identity"] for ref in row["evidence_used"]} == {
        primary["reference"]["source_identity"], context["reference"]["source_identity"]}


@pytest.mark.parametrize("fault", ["unrelated", "not-admitted", "foreign", "unresolved", "no-primary",
                                  "changed-bytes", "comment-only", "build", "incomplete", "redacted",
                                  "member-call", "indirect-call", "prototype-only", "assumption", "static-linkage"])
def test_prerequisite_cannot_authorize_unrelated_or_unresolved_evidence(accepted, settings, fault):
    caller = CALLER.replace(" copy(in);", " /* copy(in); */") if fault == "comment-only" else (
        CALLER.replace(" copy(in);", " other(in);") if fault == "unrelated" else CALLER)
    if fault == "member-call":
        caller = CALLER.replace("copy(in)", "object.copy(in)")
    elif fault == "indirect-call":
        caller = CALLER.replace("int fd)", "int fd, void (*copy)(char*))")
    elif fault == "prototype-only":
        caller = CALLER.replace("copy(in)", "void copy(char *)")
    elif fault == "redacted":
        caller = CALLER.replace(" copy(in);", ' char *password = "value"; copy(in);')
    boundary, primary, context, package = prerequisite_fixture(
        accepted, settings, caller=caller, primary_source="static " + COPY if fault == "static-linkage" else COPY)
    ref = deepcopy(context["reference"])
    if fault == "not-admitted":
        package["evidence_references"] = [primary]
        package["expansion_identities"] = [primary["reference"]["source_identity"]]
    elif fault == "foreign":
        ref["target_snapshot"] = "foreign"
    elif fault == "unresolved":
        ref["source_identity"] = "asr:source_file:missing"
    elif fault == "changed-bytes":
        boundary.data["caller.c"] += b"\n"
    elif fault == "build":
        ref["build_unit_id"] = "foreign"
    elif fault == "incomplete":
        ref = boundary.resolver.materialize(boundary.files[1].identity, component_id="api",
            locator={**ref["locator"], "lines": [2, 3]})["reference"]
    refs = [ref] if fault == "no-primary" else [primary["reference"], ref]
    proposal = proposal_for(package, primary["reference"], "not_satisfied", contradictory=refs)
    if fault == "assumption":
        proposal["obligations"][0]["assumptions"] = ["The caller selects this symbol at runtime."]
    [result] = assessment.accept_obligations(package, proposal, boundary.resolver)
    assert result["outcome"] == "cannot_verify" and result["gaps"]
    assert not result["hypotheses"]
