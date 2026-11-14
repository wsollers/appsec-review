from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_inference_security_review import audit, job
from appsec_review.review.decision_audit.publication import AuditUnavailable, PublishedAudit
from appsec_review.review.identity import sha256_hex
from appsec_review.review.lead_families import Lead, LeadCollection
from appsec_review.review.lead_triage import assessments_from_document
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

from .helpers import ATTEMPT, AUDIT_DIR, HASH, context_fixture, put


def publication_fixture(tmp_path, monkeypatch, *, enabled=True, triage_enabled=True, status="COMPLETE",
                        incomplete=False):
    """Only original decision stages are doubles; all new identity and wiring logic is real."""
    f = context_fixture(tmp_path, enabled=enabled)
    f.handoff.update(status=status, gap_ids=["gap-" + HASH] if status != "COMPLETE" else [],
                     poc_candidates=[{"original": "eligibility is unchanged"}])
    f.handoff_bytes = canonical_json(f.handoff)
    f.accounting = SimpleNamespace(review_incomplete=incomplete, claims_total=2, to_json=lambda: {"claims": 2})
    f.projection = SimpleNamespace(head=HASH)
    f.chain_cells = {}
    f.triage = {"schema": "appsec-review/lead-triage/1", "enabled": triage_enabled, "leads": [
        {"lead_id": "unadmitted-low-lead", "assessed": None,
         "gap": {"code": "triage_failed:fixture", "reason": "explicit triage input"}, "references": []}
    ]}
    documents = {
        "lead_review.teams": {"lane": "lead"},
        "hunt_review.teams": {"lane": "hunt"},
        "merge.claims": {"possible_duplicates": []},
        "adjudicate.apply_policy": {"adjudications": [{"original": "accepted state"}]},
        "scoring.score_claims": {"scores": [{"original": "score"}]},
        "triage.lead_severity": f.triage,
    }
    for lane in ("lead", "hunt"):
        documents[f"packages.assemble_{lane}_packages"] = {
            "schema": "appsec-review/inference-review-lane-packages/1",
            "lane": lane, "package_manifest_content_sha256": sha256_hex(lane), "packages": []}
    for unit_id in job.LEDGER_UNITS[4:7]:
        cell = "cell-" + sha256_hex(unit_id)
        f.chain_cells[cell] = "hunt"
        documents[unit_id] = {"expected_cells": {cell: "hunt"}}
    matrix = put(f.root, ATTEMPT + "/coverage.json", {"rows": []})
    documents["completeness.audit"] = {"accounting": f.accounting.to_json(), "coverage_matrix": matrix}
    for unit_id, document in documents.items():
        step, task = unit_id.split(".")
        f.outputs[unit_id] = {"artifact": put(f.root, ATTEMPT + f"/steps/{step}/tasks/{task}/source.json", document)}
    for unit_id in job.LEDGER_UNITS:
        f.outputs[unit_id]["ledger_shard"] = put(
            f.root, ATTEMPT + f"/{unit_id.replace('.', '-')}.jsonl", b"")
    f.outputs["attack_chains.verify_weakest_links"]["attack_chain_manifest"] = put(
        f.root, ATTEMPT + "/chain-manifest.json", {})
    monkeypatch.setattr(job, "_scope", lambda unit: f.scope)
    monkeypatch.setattr(job.stages, "audit", lambda *args, **kwargs: (
        f.accounting, f.projection, SimpleNamespace(events=())))
    f.findings = [{"original": "finding and ship-block decision"}]
    monkeypatch.setattr(job.stages, "finding_packages", lambda *args, **kwargs: deepcopy(f.findings))
    monkeypatch.setattr(job.stages, "poc_candidates", lambda *args: deepcopy(f.handoff["poc_candidates"]))
    monkeypatch.setattr(job.chains, "verify_publication", lambda *args: None)
    f.handoff_calls = []

    def original_handoff(**kwargs):
        f.handoff_calls.append(kwargs)
        return deepcopy(f.handoff)

    monkeypatch.setattr(job.stages, "build_handoff", original_handoff)
    f.handler = next(unit.handler for unit in job.build_job().units if unit.unit_id == "publication.publish_handoff")
    return f


@pytest.mark.parametrize("population", ["empty", "all-leads"])
@pytest.mark.parametrize("triage_enabled", [True, False])
def test_publication_passes_actual_collection_triage_pins_and_chain_cells_without_changing_originals(
        tmp_path, monkeypatch, population, triage_enabled):
    f = publication_fixture(tmp_path, monkeypatch, triage_enabled=triage_enabled)
    # This collector boundary supplies all collected leads, not only admitted packages/claims.
    lead = Lead("unadmitted-low-lead", "source_sast", "scanner-native", "native-rule",
                "low", "low", "reported", "source text stays private", (), "file.c", 1, True,
                "observations", "scanner-native", HASH)
    collection = LeadCollection(() if population == "empty" else (lead,), (), {}, None)
    collector_calls = []

    def collect(scope, assessments):
        collector_calls.append((scope, assessments))
        return collection

    monkeypatch.setattr(job, "collect_leads", collect)
    calls = []

    def publish(**kwargs):
        assert (f.root / kwargs["inputs"].handoff["path"]).read_bytes() == f.handoff_bytes
        calls.append(kwargs)
        metadata = put(f.root, AUDIT_DIR + "/publication.json", {"inert": "publisher boundary"})
        manifest = put(f.root, AUDIT_DIR + "/manifest.json", {})
        source = put(f.root, ATTEMPT + "/nested/source.json", {})
        return PublishedAudit(None, metadata, (manifest,), (source,))

    monkeypatch.setattr(audit, "publish_decision_audit", publish)
    result = f.handler(f.unit)
    expected_assessments = assessments_from_document(f.triage) if triage_enabled else None
    assert collector_calls == [(f.scope, expected_assessments)]
    assert len(calls) == 1
    called = calls[0]
    assert called["collection"] is collection
    assert called["scope"] is f.scope
    assert called["settings"] is f.settings
    assert called["attempt_root"] == f.unit.job.attempt_root
    assert called["run_root"] == f.root
    assert called["origin"].configuration_sha256 == f.config_ref["sha256"]
    inputs = called["inputs"]
    assert inputs.handoff == result["artifact"]
    assert inputs.ledger == f.outputs["publication.publish_claim_ledger"]["ledger"]
    assert inputs.projection == f.outputs["publication.publish_claim_ledger"]["projection"]
    assert inputs.lanes == tuple(f.outputs[f"{lane}_review.teams"]["artifact"] for lane in ("lead", "hunt"))
    assert inputs.package_sets == tuple(f.outputs[f"packages.assemble_{lane}_packages"]["artifact"]
                                       for lane in ("lead", "hunt"))
    assert inputs.additional_expected_cells == f.chain_cells
    assert inputs.triage == f.outputs["triage.lead_severity"]["artifact"]
    assert inputs.adjudications == f.outputs["adjudicate.apply_policy"]["artifact"]
    assert inputs.scores == f.outputs["scoring.score_claims"]["artifact"]
    assert inputs.verification_inputs == (f.config_ref, f.outputs["scope.accept_manifest"]["artifact"])
    assert result["metadata_path"] == result["audit_metadata_artifact"]["path"] == AUDIT_DIR + "/publication.json"
    assert result["audit_artifacts"][0]["path"] == AUDIT_DIR + "/manifest.json"
    assert result["audit_source_artifacts"][0]["path"] == ATTEMPT + "/nested/source.json"
    assert not result["metadata_path"].startswith(f.unit.unit_root.relative_to(f.root).as_posix() + "/")
    assert result["schema"] == job.SCHEMA and result["status"] == "COMPLETE"
    assert result["item_count"] == 2 and result["ledger_head_sha256"] == HASH
    assert result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED"
    assert f.handoff_calls[0]["findings"] == f.findings
    assert f.handoff_calls[0]["poc_candidate_list"] == f.handoff["poc_candidates"]
    assert (f.root / result["artifact"]["path"]).read_bytes() == f.handoff_bytes
    if collection.leads:
        assert called["collection"].leads[0].family == "source_sast"
        assert called["collection"].leads[0].scanner == "scanner-native"
        assert called["collection"].leads[0].observation_id == "unadmitted-low-lead"


@pytest.mark.parametrize("detail", ["disabled", "max_records", "max_input_bytes", "input_unavailable:receipt"])
@pytest.mark.parametrize("status,incomplete", [("COMPLETE", False), ("DEGRADED", True)])
def test_only_named_unavailability_publishes_descriptor_and_honest_status(
        tmp_path, monkeypatch, detail, status, incomplete):
    f = publication_fixture(tmp_path, monkeypatch, enabled=detail != "disabled", status=status, incomplete=incomplete)
    collection = LeadCollection((), (), {}, None)
    collector_calls = []
    monkeypatch.setattr(job, "collect_leads", lambda *args: collector_calls.append(args) or collection)

    def unavailable(**kwargs):
        assert (f.root / kwargs["inputs"].handoff["path"]).read_bytes() == f.handoff_bytes
        raise AuditUnavailable(detail)

    monkeypatch.setattr(audit, "publish_decision_audit", unavailable)
    result = f.handler(f.unit)
    document = json.loads((f.root / result["metadata_path"]).read_bytes())
    reason = AuditUnavailable(detail).reason
    assert document["unavailable_reason"] == reason
    assert document["manifest"] is None
    assert result["audit_artifacts"] == result["audit_source_artifacts"] == []
    assert result["status"] == status and result["review_incomplete"] == incomplete
    assert result["terminal_status"] == (
        "SUCCEEDED" if status == "COMPLETE" and reason == "disabled" else "COMPLETED_WITH_GAPS")
    assert any(gap.startswith("decision_audit_") for gap in result["gaps"]) is (reason != "disabled")
    assert bool(collector_calls) is (reason != "disabled")
    assert (f.root / result["artifact"]["path"]).read_bytes() == f.handoff_bytes
    event = next(data for event, data in f.unit.job.events.rows if event == "INFERENCE_REVIEW_DECISION_AUDIT_UNAVAILABLE")
    assert event == {"reason": reason, "detail": detail}
    assert json.loads(f.handoff_bytes)["gap_ids"] == f.handoff["gap_ids"]


@pytest.mark.parametrize("exception", [IntegrityError("tampered audit input"), ValueError("malformed"),
                                       RuntimeError("unexpected failure")], ids=["integrity", "value", "unexpected"])
def test_integrity_or_unexpected_failures_do_not_become_successful_descriptors(tmp_path, monkeypatch, exception):
    f = publication_fixture(tmp_path, monkeypatch, triage_enabled=False)
    monkeypatch.setattr(job, "collect_leads", lambda *args: LeadCollection((), (), {}, None))

    def fail(**kwargs):
        raise exception

    monkeypatch.setattr(audit, "publish_decision_audit", fail)
    with pytest.raises(type(exception), match=str(exception)):
        f.handler(f.unit)
    assert (f.root / f.handoff_ref["path"]).read_bytes() == f.handoff_bytes
    assert not (f.root / AUDIT_DIR / "publication.json").exists()
    assert not any(event == "INFERENCE_REVIEW_PUBLISHED" for event, _ in f.unit.job.events.rows)


def test_original_ledger_failure_prevents_even_starting_audit(tmp_path, monkeypatch):
    f = publication_fixture(tmp_path, monkeypatch)
    (f.root / f.outputs["publication.publish_claim_ledger"]["ledger"]["path"]).write_bytes(b"tampered")
    with pytest.raises(IntegrityError, match="claim ledger changed"):
        f.handler(f.unit)
    assert not (f.root / AUDIT_DIR).exists()


def test_attempt_policy_mismatch_cannot_be_swallowed_as_audit_unavailability(tmp_path, monkeypatch):
    f = publication_fixture(tmp_path, monkeypatch)
    typed = replace(f.unit.job.config.typed_settings, decision_audit=replace(f.settings, max_records=1))
    unit = replace(f.unit, job=replace(f.unit.job, config=replace(f.unit.job.config, typed_settings=typed)))
    with pytest.raises(IntegrityError, match="settings differ"):
        f.handler(unit)
    assert not (f.root / AUDIT_DIR).exists()
