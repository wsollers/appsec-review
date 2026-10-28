"""Snapshot reader units; accepted-handoff and schema authorities are explicit doubles."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import verify
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json


@pytest.fixture
def snapshot(tmp_path: Path, monkeypatch):
    root = tmp_path / "run-snapshot"
    evidence = root / "data" / "evidence.json"
    atomic_json(evidence, {"accepted": True})
    reference = artifact_ref(root, evidence)
    gate = {
        "schema": FINAL_PUBLICATION_GATE_SCHEMA, "run_id": root.name, "status": "COMPLETED",
        "review": {"status": "DEGRADED"}, "package_counts": {"total": 1},
        "packages": [{"finding_package_id": "finding-unit"}],
        "buckets": {"publishable": ["finding-unit"], "verification_backlog": [], "withheld": []},
        "bindings": [reference], "inputs": {"review": reference},
        "capabilities": {"unit": {"artifact": reference}}, "attachments": {"unit": [reference]},
    }
    path = root / "data" / "gate.json"
    published = {"schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, "item_count": 1}
    handoff = AcceptedHandoff(
        "job_final_publication_gate",
        {"job_id": "job_final_publication_gate", "outputs": {"acceptance.publish_handoff": published}},
        "a" * 64, "data/gate-handoff.json",
    )
    calls = []

    def accepted(_root, job_id):
        calls.append(job_id)
        return handoff

    def write():
        atomic_json(path, gate)
        published["artifact"] = artifact_ref(root, path)

    write()
    monkeypatch.setattr(verify, "accepted_handoff", accepted)
    return SimpleNamespace(
        root=root, gate=gate, evidence=evidence, handoff=handoff, published=published,
        calls=calls, write=write, schemas=SimpleNamespace(errors=lambda _name, _document: []),
    )


def test_snapshot_reader_ignores_corrupt_live_optional_heads(snapshot):
    for job in ("job_poc_generation", "job_remediation_planning", "job_remediation_validation",
                "job_dossier_publication", "job_inference_security_review"):
        pointer = snapshot.root / "data" / "jobs" / job / "latest.json"
        pointer.parent.mkdir(parents=True)
        pointer.write_bytes(b"not valid JSON")
    accepted, gate = verify.load_accepted_gate(
        snapshot.root, snapshot.schemas, expected_handoff_sha256=snapshot.handoff.sha256)
    assert accepted == snapshot.handoff and gate == snapshot.gate
    assert snapshot.calls == ["job_final_publication_gate"]


@pytest.mark.parametrize("mutation", [
    "run", "package_count", "bucket_membership", "gate_version", "published_count",
    "published_version", "unbound_input", "unbound_capability", "unbound_attachment", "bound_bytes",
])
def test_snapshot_reader_rejects_rehashed_certificate_or_binding_tamper(snapshot, mutation):
    if mutation == "run":
        snapshot.gate["run_id"] = "another-run"
    elif mutation == "package_count":
        snapshot.gate["package_counts"]["total"] = snapshot.published["item_count"] = 2
    elif mutation == "bucket_membership":
        snapshot.gate["buckets"]["publishable"] = ["different-finding"]
    elif mutation == "gate_version":
        snapshot.gate["schema"] = "appsec-review/final-publication-gate/1"
    elif mutation == "published_count":
        snapshot.published["item_count"] = 2
    elif mutation == "published_version":
        snapshot.published["schema"] = "appsec-review/final-publication-gate-handoff/1"
    elif mutation == "bound_bytes":
        snapshot.evidence.write_bytes(b"changed")
    else:
        key = {"unbound_input": "inputs", "unbound_capability": "capabilities",
               "unbound_attachment": "attachments"}[mutation]
        snapshot.gate[key] = {"unbound": {"path": "data/absent.json", "sha256": "b" * 64}}
    snapshot.write()
    with pytest.raises(IntegrityError):
        verify.load_accepted_gate(snapshot.root, snapshot.schemas)


def test_snapshot_reader_keeps_schema_and_claimed_handoff_authorities(snapshot):
    with pytest.raises(IntegrityError, match="upstream identity"):
        verify.load_accepted_gate(snapshot.root, snapshot.schemas, expected_handoff_sha256="b" * 64)
    schemas = SimpleNamespace(errors=lambda _name, _document: ["schema authority rejected document"])
    with pytest.raises(IntegrityError, match="schema authority rejected"):
        verify.load_accepted_gate(snapshot.root, schemas)


def test_report_load_delegates_to_shared_snapshot_authority_and_remains_gate_only(snapshot, monkeypatch):
    from appsec_review.jobs.job_final_report_publication import job

    calls = []

    def load(root, schemas, *, expected_handoff_sha256):
        calls.append((root, expected_handoff_sha256))
        return snapshot.handoff, deepcopy(snapshot.gate)

    monkeypatch.setattr(job, "load_accepted_gate", load)
    report = job.build_job()
    unit = SimpleNamespace(job=SimpleNamespace(
        run_root=snapshot.root, repository_root=Path(__file__).parents[1],
        upstream_handoffs={"job_final_publication_gate": snapshot.handoff.sha256},
    ))
    result = report.units[0].handler(unit)
    assert calls == [(snapshot.root, snapshot.handoff.sha256)]
    assert result["gate_handoff"] == {"path": snapshot.handoff.path, "sha256": snapshot.handoff.sha256}
    assert result["gate_document"] == snapshot.published["artifact"]
    assert report.consumes == ("job_final_publication_gate",)
    assert "openvex" not in result
