"""Handler, upstream-pin, and optional-attachment edge tests for job_final_publication_gate."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs import completion_contracts as contracts
from appsec_review.jobs.job_final_publication_gate import attachments as intake
from appsec_review.jobs.job_final_publication_gate import job as gate_job
from appsec_review.review.models import IntegrityError
from tests.test_completion_publication import CLAIM, Fixture, ROOT
from tests.unit.review_decision_audit_wiring.helpers import HASH, gate_fixture, put


def test_verify_unit_enforces_review_and_optional_producer_upstream_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = gate_fixture(tmp_path)
    monkeypatch.setattr(
        gate_job, "load_accepted_review",
        lambda *_args, **_kw: SimpleNamespace(document=deepcopy(fx.document), decision_audit=fx.audit),
    )

    mismatched_review_job = replace(
        fx.job, upstream_handoffs={"job_inference_security_review": "f" * 64}
    )
    unit_bad_review = SimpleNamespace(
        job=mismatched_review_job, unit_root=fx.root / "attempt/verify",
    )
    with pytest.raises(IntegrityError, match="accepted review differs from the gate attempt's upstream identity"):
        gate_job.build_job(repository_root=ROOT).units[0].handler(unit_bad_review)

    # Enable remediation_planning in frozen config and supply a mismatched upstream_handoffs pin.
    config_ref = put(fx.root, "data/configuration/resolved.json", {
        "jobs": {"job_remediation_planning": {"settings": {"enabled": True}}}
    })
    put(fx.root, "data/configuration/manifest.json", {"resolved_sha256": config_ref["sha256"]})
    fx.document["bindings"] = [
        ref for ref in fx.document["bindings"] if ref["path"] != "data/configuration/resolved.json"
    ]
    mismatched_optional_job = replace(
        fx.job,
        upstream_handoffs={
            "job_inference_security_review": fx.audit.accepted_handoff_sha256,
            "job_remediation_planning": "e" * 64,
        },
    )
    unit_bad_optional = SimpleNamespace(
        job=mismatched_optional_job, unit_root=fx.root / "attempt/verify2",
    )
    with pytest.raises(IntegrityError, match="accepted job_remediation_planning differs from the gate attempt"):
        gate_job.build_job(repository_root=ROOT).units[0].handler(unit_bad_optional)


def test_publish_unit_rejects_schema_errors_and_inexact_package_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fx = gate_fixture(tmp_path)
    monkeypatch.setattr(
        gate_job, "load_accepted_review",
        lambda *_args, **_kw: SimpleNamespace(document=deepcopy(fx.document), decision_audit=fx.audit),
    )
    monkeypatch.setattr(gate_job, "reverify_snapshot", lambda *_args, **_kw: None)
    built = gate_job.build_job(repository_root=ROOT)
    verified_out = built.units[0].handler(fx.unit("load.verify_review"))
    classified_out = built.units[1].handler(fx.unit("gate.classify", {"load.verify_review": verified_out}))
    outputs = {"load.verify_review": verified_out, "gate.classify": classified_out}

    # Force schema error at publish.
    monkeypatch.setattr(
        gate_job, "SchemaSet",
        lambda _path: SimpleNamespace(errors=lambda _name, _doc: ["bad gate field"]),
    )
    with pytest.raises(IntegrityError, match="gate document does not satisfy its schema: bad gate field"):
        built.units[2].handler(fx.unit("acceptance.publish_handoff", outputs))

    # Restore valid schema stub and force package_counts accounting mismatch.
    monkeypatch.setattr(
        gate_job, "SchemaSet",
        lambda _path: SimpleNamespace(errors=lambda _name, _doc: []),
    )
    tampered_doc = deepcopy(fx.document)
    monkeypatch.setattr(
        gate_job.classifier, "gate_document",
        lambda schema, verified, classification: {
            **classification, "schema": schema, "run_id": verified["run_id"],
            "package_counts": {**classification["package_counts"], "total": 99},
        },
    )
    with pytest.raises(IntegrityError, match="gate package accounting is not exact"):
        built.units[2].handler(fx.unit("acceptance.publish_handoff", outputs))
    assert len(tampered_doc["packages"]) == 2


def test_attachments_cover_poc_compile_files_language_pin_and_corrupt_handoff_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Fixture(tmp_path, monkeypatch)
    doc = fixture.poc(status="compile_verified")
    candidate = doc["candidates"][0]

    # compile_verified without files is rejected.
    fixture.publish("poc_generation", deepcopy(doc))
    with pytest.raises(IntegrityError, match="compile_verified PoC has no compile artifacts"):
        fixture.verify("poc_generation")

    # Add valid compile + provenance + source + readme + language_build handoff.
    lang_handoff_ref = fixture.write("lang-handoff.json", {"job_id": "job_language_build"})
    fixture.accepted["job_language_build"] = AcceptedHandoff(
        "job_language_build", {"job_id": "job_language_build"}, lang_handoff_ref["sha256"], lang_handoff_ref["path"]
    )
    doc["upstream"]["language_build_handoff_sha256"] = lang_handoff_ref["sha256"]

    source_ref = fixture.write("poc/repro.c", {"code": "int x;"})
    readme_ref = fixture.write("poc/README.json", {"note": "synthetic"})
    compile_ref = fixture.write("poc/compile.json", {
        "schema": "appsec-review/poc-compile/1",
        "claim_id": CLAIM,
        "status": "compile_verified",
        "reason": "compiled to object only",
        "execution_policy": "nothing is linked into an executable and nothing is run",
        "steps": [{
            "name": "compile",
            "command": ["cc", "-c", "repro.c"],
            "command_sha256": HASH,
            "working_directory": ".",
            "exit_code": 0,
            "timed_out": False,
            "duration_ms": 5,
            "diagnostics": [],
        }],
        "objects": {"repro.o": HASH},
        "symbol_check": None,
        "policy": {"schema": "appsec-review/poc-policy/1", "verdict": "passed", "violations": []},
        "gaps": [],
    })
    provenance_ref = fixture.write("poc/provenance.json", {
        "schema": "appsec-review/poc-provenance/2",
        "run_id": "run",
        "claim_id": CLAIM,
        "package_id": candidate["package_id"],
        "finding_package": candidate["finding_package"],
        "state": candidate["state"],
        "judge_verdict": candidate["judge_verdict"],
        "poc_basis_sha256": candidate["poc_basis_sha256"],
        "brief_sha256": HASH,
        "package_sha256": HASH,
        "source_sha256": source_ref["sha256"],
        "settings_sha256": doc["settings_sha256"],
        "writer_receipt_sha256": None,
        "status": "compile_verified",
        "model": {"provider": "fixture", "model": "fixture", "reasoning": "low"},
        "upstream": doc["upstream"],
        "source_tree": None,
        "image": {"image": "fixture", "digest": "sha256:" + HASH},
        "files": {"source": source_ref, "compile": compile_ref, "readme": readme_ref},
        **contracts.nonexecution_assurance(),
    })
    brief_ref = fixture.write("poc/brief.json", {"brief": True})
    # Align brief_sha256 with row["brief"]["sha256"].
    provenance_ref = fixture.write("poc/provenance.json", {
        "schema": "appsec-review/poc-provenance/2",
        "run_id": "run",
        "claim_id": CLAIM,
        "package_id": candidate["package_id"],
        "finding_package": candidate["finding_package"],
        "state": candidate["state"],
        "judge_verdict": candidate["judge_verdict"],
        "poc_basis_sha256": candidate["poc_basis_sha256"],
        "brief_sha256": brief_ref["sha256"],
        "package_sha256": HASH,
        "source_sha256": source_ref["sha256"],
        "settings_sha256": doc["settings_sha256"],
        "writer_receipt_sha256": None,
        "status": "compile_verified",
        "model": {"provider": "fixture", "model": "fixture", "reasoning": "low"},
        "upstream": doc["upstream"],
        "source_tree": None,
        "image": {"image": "fixture", "digest": "sha256:" + HASH},
        "files": {"source": source_ref, "compile": compile_ref, "readme": readme_ref},
        **contracts.nonexecution_assurance(),
    })
    candidate["brief"] = brief_ref
    candidate["files"] = {
        "source": source_ref,
        "compile": compile_ref,
        "readme": readme_ref,
        "provenance": provenance_ref,
    }
    fixture.publish("poc_generation", doc)
    verified_poc = fixture.verify("poc_generation")
    assert verified_poc["capabilities"]["poc_generation"]["disposition"] == "SUCCEEDED"
    assert any(b["path"] == lang_handoff_ref["path"] for b in verified_poc["bindings"])

    # Mismatched language_build handoff fails closed.
    fixture.accepted["job_language_build"] = AcceptedHandoff(
        "job_language_build", {"job_id": "job_language_build"}, "0" * 64, lang_handoff_ref["path"]
    )
    with pytest.raises(IntegrityError, match="PoC language-build handoff differs"):
        fixture.verify("poc_generation")

    # Attack chain with an unrelated unattached finding exercises false branch on chain membership check.
    chain_fx = Fixture(tmp_path / "chain-branch", monkeypatch)
    chain_fx.chain()
    unrelated = {
        **chain_fx.review["packages"][0],
        "claim_id": "claim-" + "a" * 64,
        "finding_package_id": "finding-" + "a" * 64,
        "attack_chains": [],
    }
    chain_fx.review["packages"].append(unrelated)
    chain_out = chain_fx.verify("attack_chains")
    assert len(chain_out["attachments"]["attack_chains"]) == 1
    # The capability says what became of every proposed candidate, so a report can explain "none available".
    assert chain_out["capabilities"]["attack_chains"]["status_counts"] == {
        "proposed": 1, "admitted": 1, "assessed": 1, "capped": 0, "rejected": 0, "deduplicated": 0,
        "confirmed": 0, "qualified_supported": 1, "refuted": 0, "insufficient_evidence": 0}
    assert "status_counts" not in chain_out["capabilities"]["poc_generation"]

    # ValueError from accepted_handoff in verify_attachments and reverify_snapshot becomes IntegrityError.
    def raise_corrupt(_root, _job):
        raise ValueError("corrupt latest pointer")

    monkeypatch.setattr(intake, "accepted_handoff", raise_corrupt)
    with pytest.raises(IntegrityError, match="cannot be verified: corrupt latest pointer"):
        fixture.verify("dossiers")

    snap = {**chain_fx.review, **chain_out}
    with pytest.raises(IntegrityError, match="changed during gate publication"):
        intake.reverify_snapshot(chain_fx.root, snap)
