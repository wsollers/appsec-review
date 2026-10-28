from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult, ReviewModelRequest
from appsec_review.jobs.job_owasp_control_assessment import build_job
from appsec_review.observability import EventLog
from appsec_review.owasp_workbench import WorkbenchIndex
from appsec_review.owasp_workbench.assessment import TURN_SCHEMA
from appsec_review.owasp_workbench.obligations import procedure_for, subjects
from appsec_review.runtime import JobContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.retrieval.model import canonical_json
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import publication_scope
from tests.fixtures.inference_review import builder


ROOT = Path(__file__).parents[1]


def accepted_fixture(path, *, source=None, extra_files=None, **kwargs):
    source = source or "import db\ndef get(q):\n    return db.raw('SELECT name FROM users WHERE id = ' + q)\n"
    with patch.dict(builder.FILES, {"svc/api/handler.py": ("Python", source), **(extra_files or {})}):
        return builder.build_accepted_index_set(path, omit_feeds=builder.FEEDS, **kwargs)


def context_for(fixture, *, attempt: int = 1, manifest_path=None, retries=0, **overrides) -> JobContext:
    application = load_config(ROOT / "appsec-review.toml")
    config = application.job("job_owasp_control_assessment")
    settings = deepcopy(dict(config.settings))
    settings.update({"enabled": True, **overrides})
    settings["model"]["retries"] = retries
    settings["models"][settings["reviewer_profile"]]["retries"] = retries
    if settings["mode"] == "qualification":
        settings["model"]["enabled"] = False
        settings["models"][settings["reviewer_profile"]]["enabled"] = False
    manifest = manifest_path or fixture.run_root / "data" / "indices" / "manifests" / "fixture.json"
    resolved = fixture.run_root / "data" / "configuration" / "resolved.json"
    if not resolved.is_file():
        document = json.loads(application.resolved_json)
        document["jobs"][config.job_id]["settings"] = settings
        atomic_json(resolved, document)
        atomic_json(resolved.with_name("manifest.json"), {"resolved_sha256": file_sha256(resolved)})
    attempt_id = f"attempt_{attempt:04d}"
    attempt_root = fixture.run_root / "data" / "jobs" / config.job_id / "attempts" / attempt_id
    atomic_json(attempt_root / "claim.json", {
        "schema": "appsec-review/attempt-claim/1", "run_id": fixture.run_id, "job_id": config.job_id,
        "attempt_id": attempt_id, "attempt_path": attempt_root.relative_to(fixture.run_root).as_posix(),
        "source_fingerprint": fixture.snapshot, "orchestration": {},
        "dataset_contract": dataset_contract(config.job_id, tuple(config.steps), build_job().datasets),
    })
    return JobContext(
        fixture.run_id, attempt_id, "test", ROOT, fixture.run_root, attempt_root,
        fixture.runs_dir / "metadata", {}, replace(config, settings=settings),
        EventLog(attempt_root / "events.jsonl"), source_fingerprint=fixture.snapshot,
        input_manifest_path=manifest, input_manifest_sha256=file_sha256(manifest),
        evidence_target_snapshot=fixture.snapshot,
    )


class ScriptedAssessment:
    """A transport double, not a proof oracle: application acceptance is exercised separately."""

    def __init__(self, *, outcome="not_satisfied", reviewer_outcome=None, corrupt=None,
                 usage=True, error=None, retrieve=False, retrieval_identity=None, assumptions=()):
        self.outcome = outcome
        self.reviewer_outcome = reviewer_outcome or outcome
        self.corrupt = corrupt
        self.usage = usage
        self.error = error
        self.retrieve = retrieve
        self.retrieval_identity = retrieval_identity
        self.assumptions = assumptions
        self.calls: list[ReviewModelRequest] = []

    def __call__(self, request, *, timeout_seconds):
        assert isinstance(request, ReviewModelRequest)
        assert timeout_seconds > 0
        self.calls.append(request)
        if self.error is not None:
            raise self.error
        packages = request.task_input["packages"]
        if self.retrieve and not request.transcript:
            reference = packages[0]["evidence_references"][0]["reference"]
            return ModelResult({"schema": TURN_SCHEMA, "action": "retrieve", "requests": [{
                "source_identity": self.retrieval_identity or reference["source_identity"],
                "locator": reference["locator"],
            }]})
        outcome = self.reviewer_outcome if request.role == "independent_reviewer" else self.outcome
        rows = []
        for package in packages:
            rule = procedure_for(package["control"])
            obligations = []
            for obligation in package["proof_obligations"]:
                if not obligation.get("supported"):
                    continue
                evidence = next(item for item in package["evidence_references"]
                                if obligation["subject_id"] in subjects(rule, item))
                reference = deepcopy(evidence["reference"])
                if self.corrupt:
                    self.corrupt(reference, package, request)
                adverse = outcome == "not_satisfied"
                obligations.append({
                    "obligation_id": obligation["obligation_id"], "subject_id": obligation["subject_id"],
                    "outcome": outcome,
                    "rationale": "WORKER_ONLY_REASON" if request.role == "control_assessor" else "Fresh evidence review",
                    "supporting": [reference] if outcome == "satisfied" else [],
                    "contradictory": [reference] if adverse else [],
                    "assumptions": list(self.assumptions),
                    "evidence_requests": ["Need additional context"] if outcome == "cannot_verify" else [],
                    "hypotheses": [{"mechanism": "Dynamic SQL reaches the named raw query call",
                                    "severity": "high", "ship_blocking": True}] if adverse else [],
                    "limitations": ["Static subject only; no exploitation claim."],
                })
            rows.append({"row_id": package["row_id"], "obligations": obligations})
        return ModelResult({"schema": TURN_SCHEMA, "action": "final", "results": rows},
                           input_tokens=100 if self.usage else None,
                           output_tokens=50 if self.usage else None,
                           served_model="scripted-fixture", served_provider="offline-test")


def execute(fixture, transport, *, attempt=1, manifest_path=None, **overrides):
    context = context_for(fixture, attempt=attempt, manifest_path=manifest_path, **overrides)
    with publication_scope(context):
        result = build_job(infer=transport).execute(context)
    assert not result["failed_units"], {
        unit: (context.attempt_root / "steps" / unit.split(".")[0] / "tasks" /
               unit.split(".")[1] / "traceback.txt").read_text()
        for unit in result["failed_units"]
    }
    return result["outputs"]


def sql_row(outputs):
    rows = outputs["join.deterministic_join"]["joined"]["results"]
    return next(row for row in rows
                if row["component_id"] == "component:0001" and row["control_identity"].endswith(":V1.2.4"))


def test_real_job_calls_worker_and_blinded_reviewer_over_accepted_tagged_evidence(tmp_path):
    fixture = accepted_fixture(tmp_path, secrets=True)
    transport = ScriptedAssessment(retrieve=True)
    outputs = execute(fixture, transport)
    row = sql_row(outputs)
    assert row["control_status"] == "not_satisfied"
    assert row["lead_eligible"] is True
    assert row["verification_status"] == "independently_assessed"
    assert row["evidence_used"] and row["obligations"]
    assert {request.role for request in transport.calls} == {"control_assessor", "independent_reviewer"}
    for request in transport.calls:
        serialized = json.dumps(request.task_input)
        assert builder.FIXTURE_SECRET not in serialized
        assert request.task_input["packages"][0]["assessment_mode"] == "assessment"
        if request.role == "independent_reviewer":
            assert "WORKER_ONLY_REASON" not in serialized
            assert not any("worker" in key for key in request.task_input)
    loaded = outputs["characterization.load_inputs"]
    assert any(component.get("routing_context") for component in loaded["components"])
    joined = outputs["join.deterministic_join"]["joined"]
    assert joined["accounting"]["exactly_once"] is True
    assert joined["accounting"]["selected"] == len(joined["results"])
    accepted = WorkbenchIndex(fixture.runs_dir, fixture.run_id).query(
        family="control-result", component="component:0001", control=row["control_identity"])
    assert accepted["assessment_mode"] == "assessment"
    assert any(item["record"]["lead_eligible"] for item in accepted["results"])
    manifest = outputs["publication.publish_indexes"]["manifest"]
    published = json.loads((fixture.run_root / manifest["path"]).read_text())
    assert published["configuration_sha256"] == file_sha256(
        fixture.run_root / "data" / "configuration" / "resolved.json")
    batches = outputs["verification.independent_review"]["batch_results"]
    assert sum(batch["metrics"]["model_calls"] for batch in batches) == len(transport.calls)
    assert all(batch["metrics"]["input_tokens_reported"] is None for batch in batches
               if batch["metrics"]["unknown_usage_attempts"])
    dispatched = {package["row_id"] for request in transport.calls if request.role == "control_assessor"
                  for package in request.task_input["packages"]}
    reviewed = {package["row_id"] for request in transport.calls if request.role == "independent_reviewer"
                for package in request.task_input["packages"]}
    assert {item["row_id"] for item in joined["results"] if item["worker_attempt_count"]} == dispatched
    assert {item["row_id"] for item in joined["results"] if item["reviewer_attempt_count"]} == reviewed
    report = json.loads((fixture.run_root / outputs["publication.publish_handoff"]["artifact"]["path"]).read_text())
    assert report["coverage"]["dispatched_rows"] == len(dispatched)
    assert report["coverage"]["independent_review_attempted_rows"] == len(reviewed)
    assert sum(batch["metrics"]["model_requested_retrievals"] for batch in batches) == sum(
        not request.transcript for request in transport.calls)
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "docs" / "schemas" / "owasp-workbench.schema.json").read_text())
    Draft202012Validator(schema).validate(joined)
    assert_adverse_downstream(fixture, row)


def assert_adverse_downstream(fixture, row):
    from appsec_review.retrieval import EntityKind
    from appsec_review.review.evidence import classify
    from appsec_review.review.models import Admissibility, Predicate
    from tests.test_owasp_downstream import project_and_assemble

    downstream = project_and_assemble(fixture)
    leads = [lead for lead in downstream.collection.leads if lead.family == "owasp_control"]
    assert leads
    for lead in leads:
        assert lead.path is None and not lead.location_exact
        assessment = lead.control_assessment
        assert assessment["production_eligible"] and assessment["provisional"]
        assert assessment["control_status"] == "not_satisfied"
        assert assessment["obligations"] == row["obligations"]
        assert assessment["observations"] == row["observations"]
        assert assessment["limitations"] == row["limitations"]
        assert assessment["disagreements"] == row["disagreements"]
        assert all(item["resolved"] for item in assessment["evidence"])
        package = next(package for package in downstream.assembly.packages
                       if package.kind == "finding_lead" and package.lead_ids == (lead.observation_id,))
        document = package.document()
        view = downstream.views[package.package_id].document
        assert document["lead_menu"][0]["control_assessment"] == assessment
        assert view["leads"][0]["control_assessment"] == assessment
        assert {item["source_identity"] for item in assessment["evidence"]} <= set(
            document["retrieval"]["entity_ids"])
        assert all(item["ref"] != lead.observation_id for item in view["source"])
    excerpt = downstream.core.read_excerpt(identity=fixture.ids["svc/api/handler.py"])
    assert "SELECT" in json.dumps(excerpt)
    for record in downstream.product_rows:
        for predicate in Predicate:
            assert classify(EntityKind.PRECOMPUTED_FACT, predicate, tuple(Predicate),
                            fact_payload=record["payload"]) is Admissibility.INDIRECT
    assert classify(EntityKind.SOURCE_FILE, Predicate.AFFECTED_CONSTRUCT,
                    tuple(Predicate)) is Admissibility.DIRECT
    return downstream


def test_benign_source_is_scoped_counterevidence_not_component_safety(tmp_path):
    fixture = accepted_fixture(tmp_path, source=(
        "import db\ndef get(q):\n    return db.execute('SELECT name FROM users WHERE id = ?', (q,))\n"))
    outputs = execute(fixture, ScriptedAssessment(outcome="satisfied"))
    row = sql_row(outputs)
    assert row["control_status"] == "satisfied"
    assert row["verification_status"] == "independently_assessed"
    assert row["lead_eligible"] is False
    assert row["coverage_completeness"] == "scoped"
    assert any(item["control_status"] == "cannot_verify" for item in
               outputs["join.deterministic_join"]["joined"]["results"])
    assert all(item["obligation"]["scope"] for item in row["obligations"])
    from tests.test_owasp_downstream import project_and_assemble
    downstream = project_and_assemble(fixture)
    assert not any(lead.family == "owasp_control" for lead in downstream.collection.leads)
    effective = [
        entry["control_assessment"]
        for package in downstream.assembly.packages for entry in package.document()["context"]
        if entry["role"] == "control_context" and entry["control_assessment"]["control_status"] == "satisfied"
    ]
    assert effective and all(not assessment["lead_eligible"] for assessment in effective)
    assert any(assessment["obligations"] == row["obligations"] for assessment in effective)
    assert any(entry["control_assessment"]["control_status"] == "satisfied"
               for view in downstream.views.values() for entry in view.document["other_context"]
               if entry.get("role") == "control_context")


def test_independent_disagreement_stays_visible_and_provisional(tmp_path):
    fixture = accepted_fixture(tmp_path)
    row = sql_row(execute(fixture, ScriptedAssessment(reviewer_outcome="satisfied")))
    assert row["control_status"] == "not_satisfied"
    assert row["verification_status"] == "dissent"
    assert row["disagreements"]
    assert row["observations"][0]["state"] == "awaiting_independent_verification"
    assert row["observations"][0]["state"] != "confirmed"


@pytest.mark.parametrize("field,value", [
    ("run_id", "2020-01-01-0001"), ("target_snapshot", "target-sha256:" + "0" * 64),
    ("component_id", "component:0002"), ("build_unit_id", "build_unit:unrelated"),
    ("content_sha256", "0" * 64), ("source_identity", "asr:source_file:" + "0" * 64),
])
def test_real_job_denies_invalid_typed_citations(tmp_path, field, value):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment(corrupt=lambda ref, _package, _request: ref.update({field: value}))
    row = sql_row(execute(fixture, transport))
    assert row["control_status"] == "cannot_verify"
    assert row["lead_eligible"] is False
    assert row["gaps"] and row["obligations"][0]["citation_checks"]
    assert all(check["resolution"] == "rejected" for obligation in row["obligations"]
               for check in obligation["citation_checks"])


@pytest.mark.parametrize("error", [TimeoutError("scripted timeout"), ValueError("scripted malformed response")])
def test_provider_and_output_failure_are_named_gaps_not_results(tmp_path, error):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment(error=error)
    outputs = execute(fixture, transport)
    row = sql_row(outputs)
    assert row["control_status"] == "cannot_verify" and row["lead_eligible"] is False
    assert any("timeout" in gap or "invalid_or_provider_error" in gap for gap in row["gaps"])
    assert sum(item["metrics"]["model_calls"] for item in
               outputs["verification.independent_review"]["batch_results"]) == len(transport.calls)


def test_resume_reuses_only_verified_content_bound_model_receipts(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment()
    first = execute(fixture, transport)
    initial_calls = len(transport.calls)
    second = execute(fixture, transport, attempt=2)
    assert initial_calls > 0 and len(transport.calls) == initial_calls
    before, after = sql_row(first), sql_row(second)
    assert before["execution_completion"] == "succeeded"
    assert after["execution_completion"] == "reused"
    assert {key: value for key, value in before.items()
            if key not in {"execution_completion", "worker_attempt_count", "reviewer_attempt_count"}} == {
        key: value for key, value in after.items()
        if key not in {"execution_completion", "worker_attempt_count", "reviewer_attempt_count"}}
    assert all(batch["metrics"]["model_calls"] == 0 for batch in
               second["verification.independent_review"]["batch_results"])
    assert any(batch["metrics"]["reused_model_results"] for batch in
               second["verification.independent_review"]["batch_results"])


def test_explicit_mode_does_not_autoselect_qualification_input(tmp_path):
    fixture = accepted_fixture(tmp_path)
    fixture_input = fixture.run_root / "data" / "inputs" / "owasp-workbench.json"
    fixture_input.parent.mkdir(parents=True)
    fixture_input.write_text('{"schema":"appsec-review/owasp-workbench-input/1"}')
    transport = ScriptedAssessment()
    context = context_for(fixture)
    with publication_scope(context):
        result = build_job(infer=transport).execute(context)
    assert "characterization.load_inputs" in result["failed_units"]
    assert not transport.calls


def test_batch_cap_accounts_for_every_unlaunched_row_and_unknown_usage(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment(usage=False)
    outputs = execute(fixture, transport, max_batches=1)
    joined = outputs["join.deterministic_join"]["joined"]
    assert joined["accounting"]["exactly_once"] is True
    capped = [row for row in joined["results"] if any("max_batches cap" in gap for gap in row["gaps"])]
    assert capped and all(not row["lead_eligible"] for row in capped)
    for batch in outputs["verification.independent_review"]["batch_results"]:
        if batch["metrics"]["model_calls"]:
            assert batch["metrics"]["input_tokens_reported"] is None
            assert batch["metrics"]["output_tokens_reported"] is None


def test_authentic_unrelated_evidence_cannot_prove_the_named_subject(tmp_path):
    fixture = accepted_fixture(tmp_path)

    def unrelated(reference, package, _request):
        other = next(item["reference"] for item in package["evidence_references"]
                     if item["reference"]["locator"].get("path") == "svc/api/util.py")
        reference.clear()
        reference.update(deepcopy(other))

    row = sql_row(execute(fixture, ScriptedAssessment(corrupt=unrelated)))
    assert row["control_status"] == "cannot_verify" and not row["lead_eligible"]
    checks = [check for item in row["obligations"] for check in item["citation_checks"]]
    assert checks and all(check["resolution"] == "resolved" and not check["subject_binding"] for check in checks)
    assert any("named subject" in gap for gap in row["gaps"])


@pytest.mark.parametrize("damage", ["missing", "span", "publication"])
def test_missing_out_of_span_and_stale_citations_are_not_results(tmp_path, damage):
    fixture = accepted_fixture(tmp_path)

    def corrupt(reference, _package, _request):
        if damage == "missing":
            reference.clear()
        elif damage == "span":
            reference["locator"]["lines"] = [999, 1000]
        else:
            reference["publication"]["sha256"] = "0" * 64

    row = sql_row(execute(fixture, ScriptedAssessment(corrupt=corrupt)))
    assert row["control_status"] == "cannot_verify" and not row["lead_eligible"]
    assert row["gaps"]


def test_out_of_scope_expansion_is_denied_and_counted(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment(retrieve=True, retrieval_identity="asr:source_file:" + "0" * 64)
    outputs = execute(fixture, transport)
    followups = [request for request in transport.calls if request.transcript]
    assert followups
    assert all("denied" in request.transcript[-1]["evidence"][0] for request in followups)
    assert sum(batch["metrics"]["retrieval"]["denials"]
               for batch in outputs["verification.independent_review"]["batch_results"]) > 0


def test_disabled_and_unsupported_transport_fail_before_inference(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment()
    with pytest.raises(ValueError, match="disabled"):
        build_job(infer=transport).execute(context_for(fixture, enabled=False))
    context = context_for(fixture, attempt=2)
    settings = deepcopy(dict(context.config.settings))
    settings["model"]["provider"] = "not-a-transport"
    with pytest.raises(ValueError, match="unsupported OWASP inference transport"):
        build_job(infer=transport).execute(replace(context, config=replace(context.config, settings=settings)))
    assert not transport.calls


def test_qualification_is_explicit_and_never_eligible(tmp_path):
    fixture = accepted_fixture(tmp_path)
    context = context_for(fixture, mode="qualification")
    settings = deepcopy(dict(context.config.settings))
    settings["model"]["enabled"] = False
    settings["models"][settings["reviewer_profile"]]["enabled"] = False
    context = replace(context, config=replace(context.config, settings=settings))
    from tests.test_owasp_workbench import component
    atomic_json(fixture.run_root / "data" / "inputs" / "owasp-workbench.json", {
        "schema": "appsec-review/owasp-workbench-input/1",
        "components": [component("qualification", ["server", "api"])], "evidence": [],
        "retrieval_manifest": {"fixture": "explicit synthetic qualification"},
    })
    transport = ScriptedAssessment()
    with publication_scope(context):
        result = build_job(infer=transport).execute(context)
    assert not result["failed_units"]
    assert not transport.calls
    rows = result["outputs"]["join.deterministic_join"]["joined"]["results"]
    assert rows and all(row["assessment_mode"] == "qualification" and not row["lead_eligible"] for row in rows)
    query = WorkbenchIndex(fixture.runs_dir, fixture.run_id).query(family="control-result")
    assert query["assessment_mode"] == "qualification"
    assert all(not item["record"]["lead_eligible"] for item in query["results"])


def test_assumed_material_prerequisites_cannot_create_adverse_control_result(tmp_path):
    fixture = accepted_fixture(tmp_path)
    row = sql_row(execute(fixture, ScriptedAssessment(assumptions=["The query parameter is attacker-controlled."])))
    assert row["control_status"] == "cannot_verify" and not row["lead_eligible"]
    assert any("material prerequisites" in gap for gap in row["gaps"])


def test_unrelated_manifest_republication_does_not_repeat_model_work(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment()
    before = execute(fixture, transport)
    initial_calls = len(transport.calls)
    manifest = fixture.run_root / "data" / "indices" / "manifests" / "fixture.json"
    document = json.loads(manifest.read_text())
    document["publication_note"] = "Unrelated inventory bookkeeping; accepted source and routing are unchanged."
    document.pop("content_sha256")
    document["content_sha256"] = hashlib.sha256(canonical_json(document)).hexdigest()
    renewed = manifest.with_name("renewed.json")
    atomic_json(renewed, document)
    after = execute(fixture, transport, attempt=2, manifest_path=renewed)
    assert initial_calls > 0 and len(transport.calls) == initial_calls
    assert sql_row(after)["control_status"] == sql_row(before)["control_status"]
    assert sql_row(after)["execution_completion"] == "reused"
    assert {ref["publication"]["manifest_sha256"] for ref in sql_row(after)["evidence_used"]} == {
        file_sha256(renewed)}


def test_actual_malformed_model_proposal_is_an_explicit_unresolved_gap(tmp_path):
    class Malformed(ScriptedAssessment):
        def __call__(self, request, *, timeout_seconds):
            super().__call__(request, timeout_seconds=timeout_seconds)
            return ModelResult({"schema": TURN_SCHEMA, "action": "final", "results": []})

    fixture = accepted_fixture(tmp_path)
    transport = Malformed()
    row = sql_row(execute(fixture, transport))
    assert transport.calls and row["control_status"] == "cannot_verify" and not row["lead_eligible"]
    assert any("invalid_or_provider_error" in gap for gap in row["gaps"])


@pytest.mark.parametrize("budget", ["max_input_tokens", "max_output_tokens"])
def test_model_budget_exhaustion_cannot_simulate_assessment(tmp_path, budget):
    fixture = accepted_fixture(tmp_path)
    profile = dict(load_config(ROOT / "appsec-review.toml").job("job_owasp_control_assessment").settings["model"])
    profile[budget] = 1
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport, model=profile)
    row = sql_row(outputs)
    assert row["control_status"] == "cannot_verify" and not row["lead_eligible"]
    if budget == "max_input_tokens":
        assert not any(request.role == "control_assessor" for request in transport.calls)
        assert any("input_budget" in gap for gap in row["gaps"])
    else:
        assert any(request.role == "control_assessor" for request in transport.calls)
        assert any("invalid_or_provider_error" in gap for gap in row["gaps"])


def test_retry_accounts_for_failed_attempt_and_success_without_hiding_unknown_usage(tmp_path):
    class RetryOnce(ScriptedAssessment):
        def __call__(self, request, *, timeout_seconds):
            self.error = TimeoutError("first worker attempt timed out") if not self.calls else None
            return super().__call__(request, timeout_seconds=timeout_seconds)

    fixture = accepted_fixture(tmp_path)
    transport = RetryOnce()
    outputs = execute(fixture, transport, retries=1)
    row = sql_row(outputs)
    assert row["control_status"] == "not_satisfied"
    attempts = [attempt for batch in outputs["verification.independent_review"]["batch_results"]
                for attempt in batch["metrics"]["attempts"]]
    assert len(attempts) == len(transport.calls)
    assert any(attempt["outcome"] == "timeout" and attempt["retry"] == 0 for attempt in attempts)
    assert any(attempt["outcome"] == "succeeded" and attempt["retry"] == 1 for attempt in attempts)
    assert any(batch["metrics"]["unknown_usage_attempts"] and
               batch["metrics"]["input_tokens_reported"] is None
               for batch in outputs["verification.independent_review"]["batch_results"])


def test_partial_resume_reuses_worker_but_performs_missing_independent_review(tmp_path):
    class ReviewerOutage(ScriptedAssessment):
        failed = False

        def __call__(self, request, *, timeout_seconds):
            self.error = None
            if request.role == "independent_reviewer" and not self.failed:
                self.failed = True
                self.error = TimeoutError("reviewer unavailable")
            return super().__call__(request, timeout_seconds=timeout_seconds)

    fixture = accepted_fixture(tmp_path)
    transport = ReviewerOutage()
    before = execute(fixture, transport)
    calls = len(transport.calls)
    assert sql_row(before)["verification_status"] == "pending"
    after = execute(fixture, transport, attempt=2)
    assert len(transport.calls) == calls + 1
    assert transport.calls[-1].role == "independent_reviewer"
    assert sql_row(after)["execution_completion"] == "reused"
    assert sql_row(after)["verification_status"] == "independently_assessed"
    assert before["join.deterministic_join"]["joined"]["accounting"] == after[
        "join.deterministic_join"]["joined"]["accounting"]


@pytest.mark.parametrize("change", ["model", "guidance"])
def test_model_or_guidance_policy_change_invalidates_actual_model_receipts(tmp_path, monkeypatch, change):
    from appsec_review.owasp_workbench import assessment

    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment()
    execute(fixture, transport)
    calls = len(transport.calls)
    overrides = {}
    if change == "model":
        profile = dict(load_config(ROOT / "appsec-review.toml").job("job_owasp_control_assessment").settings["model"])
        profile["model"] = "changed-scripted-model"
        overrides["model"] = profile
    else:
        compose = assessment.compose

        def changed_guidance(*args, **kwargs):
            kwargs["task"] = {**kwargs["task"], "question": kwargs["task"]["question"] + " Resolve every named site."}
            return compose(*args, **kwargs)

        monkeypatch.setattr(assessment, "compose", changed_guidance)
    outputs = execute(fixture, transport, attempt=2, **overrides)
    assert len(transport.calls) > calls
    if change == "model":
        assert all(request.model == "changed-scripted-model" for request in transport.calls[calls:])
        assert all(request.role == "control_assessor" for request in transport.calls[calls:])
    else:
        assert {request.role for request in transport.calls[calls:]} == {
            "control_assessor", "independent_reviewer"}
    assert outputs["join.deterministic_join"]["joined"]["accounting"]["exactly_once"]


def test_runtime_obligations_stay_unresolved_even_when_dynamic_is_authorized(tmp_path):
    fixture = accepted_fixture(tmp_path, extra_files={
        "native/app.kt": ("Kotlin", "class App\n"),
        "native/AndroidManifest.xml": ("XML", "<manifest package=\"example.fixture\" />\n"),
    })
    outputs = execute(fixture, ScriptedAssessment(), dynamic_authorized=True)
    rows = outputs["join.deterministic_join"]["joined"]["results"]
    row = next(row for row in rows if row["component_id"] == "component:0002"
               and row["control_identity"] == "MASVS:2.1.0:MASVS-NETWORK-1")
    assert row["applicability"] == "unsupported_missing_evidence"
    assert row["control_status"] == "not_assessed" and not row["lead_eligible"]
    assert row["coverage_completeness"] == "unresolved"
    assert any("runtime" in gap or "adapter" in gap for gap in row["gaps"])


def test_configured_source_cap_survives_publication_and_projection(tmp_path):
    fixture = accepted_fixture(tmp_path, source=(
        "import db\ndef get(q):\n    return db.raw('SELECT name FROM users WHERE id = ' + q)\n" +
        "# accepted source context\n" * 140))
    outputs = execute(fixture, ScriptedAssessment(), max_source_lines=200)
    manifest = outputs["publication.publish_indexes"]["manifest"]
    assert json.loads((fixture.run_root / manifest["path"]).read_text())["assessment_bounds"] == {
        "max_source_lines": 200}
    row = sql_row(outputs)
    assert row["control_status"] == "not_satisfied"
    assert_adverse_downstream(fixture, row)
