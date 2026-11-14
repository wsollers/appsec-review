from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.accepted_review import VerifiedReview
from appsec_review.jobs.job_final_publication_gate import attachments, classify, job
from appsec_review.jobs.job_final_publication_gate.verify import verify_gate_snapshot
from appsec_review.review.models import IntegrityError

from .helpers import HASH, REVIEW_JOB, gate_fixture, put


@pytest.mark.parametrize("reason", [None, "disabled", "legacy_unrecorded", "capacity_exceeded", "input_unavailable"])
def test_gate_verification_explicitly_opts_in_and_retains_every_certified_read(tmp_path, monkeypatch, reason):
    f = gate_fixture(tmp_path, reason=reason)
    calls = []

    def accepted(root, schemas, *, max_packages, include_decision_audit=False):
        calls.append((root, max_packages, include_decision_audit))
        return VerifiedReview(f.document, f.audit)

    monkeypatch.setattr(job, "load_accepted_review", accepted)
    result = job.build_job().units[0].handler(f.unit("load.verify_review"))
    assert calls == [(f.root, 10, True)]
    document = json.loads((f.root / result["artifact"]["path"]).read_bytes())
    assert document["_decision_audit"] == classify.decision_audit_summary(f.audit, f.audit.accepted_handoff_sha256)
    assert all(ref in document["bindings"] for ref in (*f.audit_refs, f.config_ref))
    assert document["bindings"].count(f.config_ref) == 1
    assert len(document["bindings"]) == len({(ref["path"], ref["sha256"]) for ref in document["bindings"]})
    assert set(document["capabilities"]) == {"poc_generation", "attack_chains", "remediation_planning",
                                             "remediation_validation", "dossiers"}
    assert document["packages"] == f.document["packages"]
    assert result["binding_count"] == len(document["bindings"])
    assert "private" not in json.dumps(document) and "records" not in document["_decision_audit"]
    assert result["terminal_status"] == "SUCCEEDED"


@pytest.mark.parametrize("reason", [None, "disabled", "legacy_unrecorded", "capacity_exceeded", "input_unavailable"])
def test_reader_shaped_configuration_binding_survives_direct_gate_callbacks(tmp_path, monkeypatch, reason):
    f = gate_fixture(tmp_path, reason=reason)
    original_bindings = list(f.document["bindings"])
    assert (f.config_ref in original_bindings) is (reason != "legacy_unrecorded")
    assert (f.config_ref in [read.reference() for read in f.audit.reads]) is (reason != "legacy_unrecorded")

    def accepted_review(root, schemas, *, max_packages, include_decision_audit):
        assert root == f.root and max_packages == 10 and include_decision_audit is True
        return VerifiedReview(f.document, f.audit)

    def accepted_handoff(root, producer):
        assert root == f.root and producer == REVIEW_JOB
        ref = f.document["inputs"]["job_handoff"]
        return SimpleNamespace(path=ref["path"], sha256=ref["sha256"])

    monkeypatch.setattr(job, "load_accepted_review", accepted_review)
    monkeypatch.setattr(attachments, "accepted_handoff", accepted_handoff)
    # The upstream verifier is inert. Only this model-free gate component's three callbacks run.
    gate = job.build_job()
    outputs = {}
    for callback in gate.units:
        outputs[callback.unit_id] = callback.handler(f.unit(callback.unit_id, outputs))
    result = outputs["acceptance.publish_handoff"]
    document = json.loads((f.root / result["artifact"]["path"]).read_bytes())
    verified = json.loads((f.root / outputs["load.verify_review"]["artifact"]["path"]).read_bytes())
    assert document["bindings"] == verified["bindings"]
    assert document["bindings"].count(f.config_ref) == 1
    assert all(ref in document["bindings"] for ref in original_bindings)
    assert len(document["bindings"]) == len({(ref["path"], ref["sha256"]) for ref in document["bindings"]})
    assert document["schema"] == "appsec-review/final-publication-gate/2"
    assert document["gap_ids"] == f.document["gap_ids"] == []
    assert result["package_counts"] == {"total": 2, "publishable": 1, "verification_backlog": 1,
                                        "withheld": 0, "exact": True}
    assert "_decision_audit" not in document and "private" not in json.dumps(document)
    verify_gate_snapshot(f.root, document)


@pytest.mark.parametrize("conflict", ["replacement", "alongside-valid"])
def test_gate_rejects_configuration_path_with_conflicting_certified_hash(tmp_path, monkeypatch, conflict):
    f = gate_fixture(tmp_path)
    conflicting = {**f.config_ref, "sha256": "0" * 64}
    if conflict == "replacement":
        f.document["bindings"].remove(f.config_ref)
    f.document["bindings"].append(conflicting)
    original_bindings = list(f.document["bindings"])
    monkeypatch.setattr(job, "load_accepted_review", lambda *args, **kwargs: VerifiedReview(f.document, f.audit))
    unit = f.unit("load.verify_review")
    with pytest.raises(IntegrityError, match="configuration.*conflicting"):
        job.build_job().units[0].handler(unit)
    assert all(ref in f.document["bindings"] for ref in original_bindings)
    assert not (unit.unit_root / "verified-review.json").exists()


@pytest.mark.parametrize("change", ["absent", "untyped", "foreign", "integrity-error"])
def test_gate_opt_in_never_downgrades_a_bad_sidecar_to_historical_absence(tmp_path, monkeypatch, change):
    f = gate_fixture(tmp_path)
    sidecar = {"absent": None, "untyped": {}, "foreign": replace(f.audit, accepted_handoff_sha256="0" * 64),
               "integrity-error": f.audit}[change]

    def accepted(*args, **kwargs):
        if change == "integrity-error":
            raise IntegrityError("changed accepted audit bytes")
        return VerifiedReview(f.document, sidecar)

    monkeypatch.setattr(job, "load_accepted_review", accepted)
    with pytest.raises(IntegrityError):
        job.build_job().units[0].handler(f.unit("load.verify_review"))
    assert not (f.unit("load.verify_review").unit_root / "verified-review.json").exists()


def test_classification_handler_carries_only_sanitized_summary(tmp_path):
    f = gate_fixture(tmp_path, reason="capacity_exceeded")
    f.document["_decision_audit"] = classify.decision_audit_summary(f.audit, f.audit.accepted_handoff_sha256)
    verified_ref = put(f.root, "data/gate/verified.json", f.document)
    result = job.build_job().units[1].handler(f.unit("gate.classify", {
        "load.verify_review": {"artifact": verified_ref}}))
    document = json.loads((f.root / result["artifact"]["path"]).read_bytes())
    assert document == classify.classify(f.document)
    assert result["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert "_decision_audit" not in document and "private" not in json.dumps(document)


@pytest.mark.parametrize("reason", [None, "disabled", "legacy_unrecorded", "capacity_exceeded", "input_unavailable"])
def test_gate_seal_keeps_bindings_and_public_shape_with_honest_limitation_status(tmp_path, monkeypatch, reason):
    f = gate_fixture(tmp_path, reason=reason)
    f.document["_decision_audit"] = classify.decision_audit_summary(f.audit, f.audit.accepted_handoff_sha256)
    verified_ref = put(f.root, "data/gate/verified.json", f.document)
    classified = classify.classify(f.document)
    classified_ref = put(f.root, "data/gate/classification.json", classified)
    calls = []

    def accepted(root, producer):
        calls.append((root, producer))
        ref = f.document["inputs"]["job_handoff"]
        return SimpleNamespace(path=ref["path"], sha256=ref["sha256"])

    monkeypatch.setattr(attachments, "accepted_handoff", accepted)
    result = job.build_job().units[2].handler(f.unit("acceptance.publish_handoff", {
        "load.verify_review": {"artifact": verified_ref}, "gate.classify": {"artifact": classified_ref}}))
    assert calls == [(f.root, REVIEW_JOB)]
    document = json.loads((f.root / result["artifact"]["path"]).read_bytes())
    assert document["bindings"] == f.document["bindings"]
    assert all(ref in document["bindings"] for ref in f.audit_refs)
    assert document["gap_ids"] == f.document["gap_ids"] == []
    assert document["packages"] == classified["packages"]
    assert "_decision_audit" not in document and "private" not in json.dumps(document)
    assert result["terminal_status"] == (
        "COMPLETED_WITH_GAPS" if reason in {"capacity_exceeded", "input_unavailable"} else "SUCCEEDED")
    assert len(result["gaps"]) == (1 if reason in {"capacity_exceeded", "input_unavailable"} else 0)


@pytest.mark.parametrize("artifact_index", range(5), ids=["metadata", "manifest", "shard", "continuation", "source"])
def test_changed_audit_binding_cannot_pass_gate_sealing(tmp_path, monkeypatch, artifact_index):
    f = gate_fixture(tmp_path)
    f.document["_decision_audit"] = classify.decision_audit_summary(f.audit, f.audit.accepted_handoff_sha256)
    verified_ref = put(f.root, "data/gate/verified.json", f.document)
    classified_ref = put(f.root, "data/gate/classification.json", classify.classify(f.document))
    (f.root / f.audit_refs[artifact_index]["path"]).write_bytes(b"tampered")
    unit = f.unit("acceptance.publish_handoff", {
        "load.verify_review": {"artifact": verified_ref}, "gate.classify": {"artifact": classified_ref}})
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        job.build_job().units[2].handler(unit)
    assert not (unit.unit_root / "final-publication-gate.json").exists()


def test_post_seal_snapshot_reverification_rejects_a_changed_audit(tmp_path):
    f = gate_fixture(tmp_path)
    document = classify.gate_document("appsec-review/final-publication-gate/2", f.document, classify.classify(f.document))
    # This is the snapshot certificate verifier, not a joined review or accepted-run reader.
    for package in document["packages"]:
        document["bindings"].append(put(f.root, package["path"], {}))
    for name in ("inputs", "capabilities", "attachments"):
        assert name in document
    verify_gate_snapshot(f.root, document)
    (f.root / f.audit_refs[0]["path"]).write_bytes(b"changed")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        verify_gate_snapshot(f.root, document)
