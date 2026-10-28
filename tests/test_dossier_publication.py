from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.inventory import Claim, FileClaims
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import (
    DOSSIER_PUBLICATION_HANDOFF_SCHEMA, REMEDIATION_PLANNING_HANDOFF_SCHEMA, REMEDIATION_PLANNING_SCHEMA,
    REMEDIATION_PLAN_SCHEMA, nonexecution_assurance,
)
from appsec_review.jobs.engineering_contracts import POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA
from appsec_review.jobs.job_dossier_publication import JOB_ID, build_job
from appsec_review.jobs.job_dossier_publication import inputs
from appsec_review.jobs.job_dossier_publication.datasets import CONSUMES, DATASETS
from appsec_review.jobs.job_dossier_publication.job import TOPOLOGY, verify_publication
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.storage import atomic_json
from tests.dossier_fixture import ROOT, seed, settings


def write(root, name, value):
    path = root / "data" / "seed" / name
    atomic_json(path, value)
    return artifact_ref(root, path)


def acceptance(root, job, document, name):
    path = root / "data" / "seed" / name
    atomic_json(path, document)
    ref = artifact_ref(root, path)
    return SimpleNamespace(path=ref["path"], sha256=ref["sha256"], handoff=document)


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    root = tmp_path / "r"
    source = seed(root)
    finding = source["finding"]
    reference = write(root, "finding.json", finding)
    finding.update(reference)
    binding = {key: finding[key] for key in ("claim_id", "finding_package_id", "sha256")}
    source["poc"]["finding"] = binding
    projection_ref = write(root, "projection.json", {"claims": [source["claim"]],
                                                     "relations": {finding["claim_id"]: source["relations"]}})
    manifest = write(root, "manifest.json", {"run_id": root.name, "indexes": []})
    scope = write(root, "scope.json", {"manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    review_ref = write(root, "review.json", {"run_id": root.name})
    review_job = acceptance(root, inputs.REVIEW_JOB, {
        "job_id": inputs.REVIEW_JOB, "outputs": {"scope.accept_manifest": {"artifact": scope}}}, "review-job.json")
    accepted = {inputs.REVIEW_JOB: review_job}

    def producer(job, schema, handoff_schema, items, *, review=review_ref, gaps=None):
        key = "candidates" if job == "job_poc_generation" else "items"
        document = {"schema": schema, "run_id": root.name, "upstream": {"review_handoff": review},
                    key: items, "gaps": gaps or []}
        ref = write(root, job + ".json", document)
        unit = inputs.PRODUCERS[job][0]
        accepted[job] = acceptance(root, job, {"job_id": job, "outputs": {unit: {
            "schema": handoff_schema, "artifact": ref, "item_count": len(items), "gaps": gaps or []}}},
            job + "-handoff.json")
        return document

    producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [source["poc"]])
    verified = {
        "run_id": root.name, "packages": [finding],
        "inputs": {"projection": projection_ref, "review_handoff": review_ref,
                   "job_handoff": {"path": review_job.path, "sha256": review_job.sha256}},
        "review": {"ledger_head_sha256": "a" * 64, "configuration_sha256": "b" * 64}}
    monkeypatch.setattr(inputs, "accepted_handoff", lambda _root, job: accepted.get(job))
    calls = []

    class Core:
        def read_excerpt(self, *, identity, context_lines):
            calls.append((identity, context_lines))
            return {"results": source["excerpts"], "coverage_gaps": [], "truncated": False}

    return SimpleNamespace(root=root, source=source, verified=verified, accepted=accepted,
                           producer=producer, core=Core(), calls=calls)


def context(fixture, name="a", **overrides):
    config = SimpleNamespace(settings=settings(**{"render_pdf": False, **overrides}).identity(), steps=TOPOLOGY,
                             step=lambda key: SimpleNamespace(tasks=TOPOLOGY[key]))
    attempt = fixture.root / "data" / "jobs" / JOB_ID / "attempts" / name
    attempt.mkdir(parents=True, exist_ok=True)
    return JobContext(run_id=fixture.root.name, attempt_id=name, trigger="test", repository_root=ROOT,
                      run_root=fixture.root, attempt_root=attempt, metadata_root=attempt,
                      orchestration={}, config=config, events=EventLog(attempt / "events.jsonl"))


def job(fixture, **kwargs):
    return build_job(repository_root=ROOT, review_loader=lambda *args, **kw: SimpleNamespace(document=fixture.verified),
                     core_factory=lambda *args: fixture.core, **kwargs)


def output_summary(fixture, result):
    assert not result["failed_units"], result
    publication = result["outputs"]["acceptance.publish_handoff"]
    return publication, read_bound_json(fixture.root, publication["artifact"])


def test_semantic_job_creates_one_per_confirmed_finding_and_each_poc(seeded):
    result = job(seeded).execute(context(seeded))
    publication, summary = output_summary(seeded, result)
    assert publication["schema"] == DOSSIER_PUBLICATION_HANDOFF_SCHEMA
    assert publication["item_count"] == 2
    assert summary["counts"] == {"admitted": 2, "items": 2, "omitted": 0,
                                "by_kind": {"confirmed_finding": 1, "poc": 1},
                                "by_status": {"rendered": 0, "render_failed": 0, "latex_only": 2}}
    assert {item["kind"] for item in summary["items"]} == {"confirmed_finding", "poc"}
    assert summary["upstream"]["review_handoff"] == seeded.verified["inputs"]["review_handoff"]
    assert summary["upstream"]["poc_handoff"]["sha256"] == seeded.accepted["job_poc_generation"].sha256
    assert summary["upstream"]["remediation_planning_handoff"] is None
    assert publication["gaps"] and result["status"] == "COMPLETED_WITH_GAPS"
    assert all(call[1] == 2 for call in seeded.calls)
    verify_publication(seeded.root, summary)


def test_dossier_cap_exact_accounting_and_retry_retention(seeded):
    result = job(seeded).execute(context(seeded, max_dossiers=1))
    _published, summary = output_summary(seeded, result)
    assert summary["counts"]["admitted"] == 2
    assert summary["counts"]["items"] == summary["counts"]["omitted"] == 1
    assert summary["omitted"][0]["kind"] == "poc"
    assert summary["omitted"][0]["reason"] == "max_dossiers"
    assert any("dossier_cap" in gap for gap in summary["gaps"])
    refs = copy.deepcopy(summary["items"][0]["files"])
    job(seeded).execute(context(seeded, "b"))
    assert all((seeded.root / ref["path"]).is_file() for ref in refs.values() if ref is not None)
    verify_publication(seeded.root, summary)


def test_empty_scope_does_not_read_target_or_call_renderer(seeded):
    seeded.verified["packages"] = []
    del seeded.accepted["job_poc_generation"]
    result = job(seeded, renderer=lambda *args, **kw: pytest.fail("no admitted dossier")).execute(context(seeded))
    _publication, summary = output_summary(seeded, result)
    assert summary["counts"]["admitted"] == summary["counts"]["items"] == 0
    assert not seeded.calls
    assert summary["gaps"] == []


def test_supported_finding_has_only_a_poc_dossier(seeded):
    seeded.verified["packages"][0]["state"] = "supported"
    seeded.source["claim"]["state"] = "supported"
    seeded.verified["inputs"]["projection"] = write(
        seeded.root, "supported-projection.json", {"claims": [seeded.source["claim"]],
        "relations": {seeded.source["claim"]["claim_id"]: seeded.source["relations"]}})
    _publication, summary = output_summary(seeded, job(seeded).execute(context(seeded)))
    assert len(summary["items"]) == 1 and summary["items"][0]["kind"] == "poc"
    assert summary["counts"]["by_kind"] == {"confirmed_finding": 0, "poc": 1}


@pytest.mark.parametrize("status", ["compile_failed", "artifact_generated", "policy_denied", "insufficient_evidence",
                                   "not_applicable", "unsafe_to_attempt"])
def test_failed_or_unavailable_poc_still_has_dossier(seeded, status):
    seeded.source["poc"]["status"] = status
    seeded.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [seeded.source["poc"]])
    _publication, summary = output_summary(seeded, job(seeded).execute(context(seeded)))
    assert len(summary["items"]) == 2
    model = next(read_bound_json(seeded.root, item["files"]["json"]) for item in summary["items"] if item["kind"] == "poc")
    assert model["poc"]["status"] == status
    assert any("poc_assurance_limited" in gap for gap in model["gaps"])


@pytest.mark.parametrize("mutation", ["cross_review", "cross_finding", "count", "tamper", "runtime", "duplicate"])
def test_input_integrity_rejects_mixed_tampered_inexact_producers(seeded, mutation):
    poc = copy.deepcopy(seeded.source["poc"])
    extra = {}
    items = [poc]
    if mutation == "cross_review":
        extra["review"] = {"path": "data/seed/review.json", "sha256": "0" * 64}
    elif mutation == "cross_finding":
        poc["finding"]["sha256"] = "0" * 64
    elif mutation == "runtime":
        poc["runtime_verified"] = True
    elif mutation == "duplicate":
        items.append(poc)
    seeded.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, items, **extra)
    if mutation == "tamper":
        (seeded.root / poc["files"]["source"]["path"]).write_text("changed")
    elif mutation == "count":
        seeded.accepted["job_poc_generation"].handoff["outputs"]["publish.publish_handoff"]["item_count"] = 0
    with pytest.raises(IntegrityError):
        inputs.load_inputs(seeded.root, seeded.verified, settings())


def test_snapshot_detects_new_optional_acceptance_and_changed_review(seeded):
    document = inputs.load_inputs(seeded.root, seeded.verified, settings())
    del seeded.accepted[inputs.REVIEW_JOB]
    with pytest.raises(IntegrityError, match="changed"):
        inputs.verify_snapshot(seeded.root, document, settings())


def test_poc_producer_status_accounting_is_recomputed(seeded):
    source = seeded.source["poc"]
    producer = seeded.producer("job_poc_generation", POC_GENERATION_SCHEMA, POC_GENERATION_HANDOFF_SCHEMA, [source])
    producer["counts"] = {"candidates": 2, "omitted": 0, "by_status": {}}
    path = seeded.root / "data" / "seed" / "job_poc_generation.json"
    atomic_json(path, producer)
    publication = seeded.accepted["job_poc_generation"].handoff["outputs"]["publish.publish_handoff"]
    publication["artifact"] = artifact_ref(seeded.root, path)
    with pytest.raises(IntegrityError, match="accounting"):
        inputs.load_inputs(seeded.root, seeded.verified, settings())


def test_remediation_is_confirmed_only_and_stays_assurance_labelled(seeded):
    binding = seeded.source["poc"]["finding"]
    plan = write(seeded.root, "plan.json", {
        "schema": REMEDIATION_PLAN_SCHEMA, "run_id": seeded.root.name, "finding": binding,
        "status": "proposal_generated", "upstream": {"review_handoff": seeded.verified["inputs"]["review_handoff"]},
        "assurance": nonexecution_assurance(), "violated_invariant": "Every returned record must be scoped.",
        "corrected_invariant": "Preserve the check.",
        "compatibility_effects": ["Public interface unchanged."],
        "regression_spec": {"safety_assertion": "Use harmless in-memory synthetic data."}})
    item = {"finding": binding, "status": "proposal_generated", "reason": "Synthetic proposal", "plan": plan,
            "gap_ids": []}
    seeded.producer("job_remediation_planning", REMEDIATION_PLANNING_SCHEMA,
                    REMEDIATION_PLANNING_HANDOFF_SCHEMA, [item])
    _publication, summary = output_summary(seeded, job(seeded).execute(context(seeded)))
    model = read_bound_json(seeded.root, summary["items"][0]["files"]["json"])
    assert model["remediation"][0]["status"] == "proposal_generated"
    assert "Not fixed" in model["remediation"][0]["notice"]
    assert model["remediation"][0]["compatibility_effects"] == ["Public interface unchanged."]
    assert "harmless" in model["remediation"][0]["regression_safety"]
    seeded.verified["packages"][0]["state"] = "supported"
    # Rewriting the projection is not allowed; even before remediation validation it must fail.
    with pytest.raises(IntegrityError):
        inputs.load_inputs(seeded.root, seeded.verified, settings())


def test_publication_verifier_detects_tamper_bad_counts_and_pdf_claims(seeded):
    _publication, summary = output_summary(seeded, job(seeded).execute(context(seeded)))
    for key in ("admitted", "items", "omitted"):
        altered = copy.deepcopy(summary)
        altered["counts"][key] += 1
        with pytest.raises(IntegrityError, match="accounting"):
            verify_publication(seeded.root, altered)
    altered = copy.deepcopy(summary)
    altered["items"][0]["status"] = "rendered"
    altered["counts"]["by_status"]["rendered"] = 1
    altered["counts"]["by_status"]["latex_only"] -= 1
    with pytest.raises(IntegrityError, match="PDF"):
        verify_publication(seeded.root, altered)
    path = seeded.root / summary["items"][0]["files"]["latex"]["path"]
    path.write_text("changed")
    with pytest.raises(IntegrityError, match="changed"):
        verify_publication(seeded.root, summary)


def test_datasets_claim_all_outputs_as_protected_and_no_gate_dependency(seeded):
    _publication, summary = output_summary(seeded, job(seeded).execute(context(seeded)))
    declarations = FileClaims([Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS])
    assert "job_final_publication_gate" not in CONSUMES
    assert all(item.disposition == "protected" and item.sensitivity == "sensitive" for item in DATASETS)
    attempt = seeded.root / "data" / "jobs" / JOB_ID / "attempts" / "a"
    for path in attempt.rglob("*"):
        if path.is_file() and path.name not in {"status.json", "result.json", "events.jsonl"}:
            owner = declarations.file(path.relative_to(seeded.root).as_posix())
            assert owner is not None, path
    assert all(item["files"]["receipt"] for item in summary["items"])


@pytest.mark.parametrize("status", ["rendered", "render_failed", "latex_only"])
def test_telemetry_emits_bounded_counts_durations_sizes_and_receipts(seeded, status):
    from appsec_review.reporting.dossier_render import render_dossier
    from tests.test_dossiers import executor_factory
    def render(*args, **kwargs):
        return render_dossier(*args, **kwargs, executor_factory=executor_factory(
            [], render_status=0 if status == "rendered" else 1,
            pdf=b"%PDF-1.5\n" + b"synthetic-unit-double " * 3 + b"\n%%EOF\n" if status == "rendered" else None))
    ctx = context(seeded, render_pdf=status != "latex_only")
    result = job(seeded, renderer=render).execute(ctx)
    _publication, summary = output_summary(seeded, result)
    events = [json.loads(line) for line in (ctx.attempt_root / "events.jsonl").read_text().splitlines()]
    names = {event["event"] for event in events}
    assert {"DOSSIER_INPUTS_VERIFIED", "DOSSIER_BATCH_PLANNED", "DOSSIER_RENDER_STARTED",
            "DOSSIER_RENDER_COMPLETED", "DOSSIER_PUBLICATION_ASSEMBLED", "DOSSIER_PUBLICATION_PUBLISHED"} <= names
    completed = [event for event in events if event["event"] == "DOSSIER_RENDER_COMPLETED"]
    assert len(completed) == 2
    for event in completed:
        assert event["status"] == status and event["duration_ms"] >= 0
        assert event["json_bytes"] > 0 and event["latex_bytes"] > 0 and event["receipt_bytes"] > 0
        assert bool(event["pdf_bytes"]) == (status == "rendered")
        assert event["render_failed"] == (status == "render_failed")
        assert len(event["receipt_sha256"]) == 64
        assert not {"statement", "source", "poc_source", "prompt", "description"} & set(event)
    published = next(event for event in events if event["event"] == "DOSSIER_PUBLICATION_PUBLISHED")
    assert published[status + "_count"] == 2 and published["item_count"] == 2
    assert published["gap_count"] == len(summary["gaps"])


def test_raised_render_failure_emits_no_sensitive_error_content(seeded):
    def broken(*args, **kwargs):
        raise IntegrityError("PRIVATE_SOURCE_MUST_NOT_ENTER_TELEMETRY")
    ctx = context(seeded)
    result = job(seeded, renderer=broken).execute(ctx)
    assert result["failed_units"] == ["dossiers.create"]
    events = [json.loads(line) for line in (ctx.attempt_root / "events.jsonl").read_text().splitlines()]
    event = next(value for value in events if value["event"] == "DOSSIER_RENDER_FAILED")
    assert event["duration_ms"] >= 0 and event["error_type"] == "IntegrityError"
    assert "PRIVATE_SOURCE" not in json.dumps(event)


def test_real_accepted_review_reader_to_dossier_models(tmp_path):
    from appsec_review.jobs.accepted_review import load_accepted_review
    from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
    from tests.final_report_support import run_review_chain
    chain = run_review_chain(tmp_path / "c", tmp_path / "l")
    verified = load_accepted_review(chain.run_root, SchemaSet(ROOT / SCHEMA_DIRECTORY), max_packages=10000)
    document = inputs.load_inputs(chain.run_root, verified.document, settings())
    assert document["run_id"] == chain.fixture.run_id
    assert document["source_manifest"]["sha256"] == verified.document["review"]["accepted_manifest_sha256"]
    fixture = SimpleNamespace(root=chain.run_root, verified=verified.document)
    result = build_job(repository_root=ROOT).execute(context(fixture))
    _publication, summary = output_summary(fixture, result)
    confirmed = sum(row["state"] == "confirmed" for row in verified.document["packages"])
    assert summary["counts"]["items"] == confirmed
    assert all(item["kind"] == "confirmed_finding" for item in summary["items"])
