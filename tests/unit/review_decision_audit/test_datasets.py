from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from appsec_review.indexing.inventory import compile_glob
from appsec_review.jobs.job_dossier_publication.datasets import CONTRACT as DOSSIER_CONTRACT
from appsec_review.jobs.job_final_publication_gate.datasets import CONTRACT as GATE_CONTRACT
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS
from appsec_review.jobs.job_poc_generation.datasets import CONTRACT as POC_CONTRACT
from appsec_review.jobs.job_remediation_planning.datasets import CONTRACT as REMEDIATION_CONTRACT
from appsec_review.runtime.contracts import Availability, MissingPolicy
from appsec_review.runtime.datasets import EvidenceAuthority, validate_declarations
from appsec_review.runtime.inputs import admit_inputs
from tests.unit.review_decision_audit_consumers.source_permission_fixture import SourceRun

JOB = "job_inference_security_review"
ROOT = f"data/jobs/{JOB}/attempts/attempt-1/artifacts/decision-audit"
CASES = (
    ("publication.json", "review_audit_metadata", "appsec-review/review-audit-publication/1"),
    ("manifest.json", "review_decision_audit", "appsec-review/review-audit-manifest/1"),
    ("decision/000001.jsonl", "review_decisions", "appsec-review/review-decision/1"),
    ("verification_coverage/000001.jsonl", "review_verification_coverage",
     "appsec-review/verification-coverage/1"),
    ("decision_basis/000001.jsonl", "review_decision_bases", "appsec-review/decision-basis/1"),
    ("continuations/000001.jsonl", "review_audit_continuations", "application/x-ndjson"),
    ("continuations/relations/000001.jsonl", "review_audit_continuations", "application/x-ndjson"),
)
KINDS = frozenset(kind for _, kind, _ in CASES)


@pytest.mark.parametrize("relative,kind,schema", CASES, ids=[path for path, _, _ in CASES])
def test_each_audit_file_has_one_exact_protected_operational_owner(relative, kind, schema):
    validate_declarations(JOB, DATASETS)
    path = f"{ROOT}/{relative}"
    owners = [item for item in DATASETS
              if any(compile_glob(pattern).fullmatch(path) for pattern in item.artifacts)]
    assert len(owners) == 1
    owner = owners[0]
    assert owner.output_kind == kind
    assert owner.schema == schema
    assert owner.step == "publication"
    assert owner.authority is EvidenceAuthority.OPERATIONAL
    assert owner.disposition == "protected"
    assert owner.sensitivity == "sensitive"
    assert owner.indexes == ()
    assert "sanitized identity" in owner.query_route


@pytest.mark.parametrize("contract", [DOSSIER_CONTRACT, GATE_CONTRACT], ids=["dossier", "gate"])
def test_only_declared_application_consumers_get_optional_audit_permissions(contract):
    inputs = {item.output_kind: item for item in contract.inputs
              if item.producer == JOB and item.output_kind in KINDS}
    assert set(inputs) == KINDS
    for kind, item in inputs.items():
        declaration = next(value for value in DATASETS if value.output_kind == kind)
        assert item.schema == declaration.schema
        assert item.authority is EvidenceAuthority.OPERATIONAL
        assert item.availability is Availability.WHEN_DECLARED
        assert item.missing is (MissingPolicy.GAP if kind == "review_audit_metadata"
                                else MissingPolicy.NOT_APPLICABLE)


@pytest.mark.parametrize("contract", [POC_CONTRACT, REMEDIATION_CONTRACT], ids=["poc", "remediation"])
def test_shared_base_review_reader_does_not_grant_unrelated_jobs_audit_content(contract):
    assert not any(item.producer == JOB and item.output_kind in KINDS for item in contract.inputs)


def test_new_audit_routes_do_not_claim_existing_finding_payloads():
    path = f"data/jobs/{JOB}/attempts/attempt-1/steps/publication/tasks/publish_handoff/findings/f.json"
    owners = [item.output_kind for item in DATASETS
              if any(compile_glob(pattern).fullmatch(path) for pattern in item.artifacts)]
    assert owners == ["scores_and_findings"]


@pytest.mark.parametrize("consumer,contract", [
    ("job_dossier_publication", DOSSIER_CONTRACT),
    ("job_final_publication_gate", GATE_CONTRACT),
], ids=["dossier", "gate"])
@pytest.mark.parametrize("publication", ["legacy", "declared", "wrong-schema", "wrong-authority"])
def test_actual_consumer_contracts_admit_only_compatible_audit_declarations(tmp_path, consumer, contract, publication):
    run = SourceRun(tmp_path)
    declarations = tuple(row for row in DATASETS if publication != "legacy" or row.output_kind not in KINDS)
    if publication in {"wrong-schema", "wrong-authority"}:
        changes = ({"schema": "appsec-review/review-audit-publication/999"} if publication == "wrong-schema"
                   else {"authority": EvidenceAuthority.PROVISIONAL})
        declarations = tuple(replace(row, **changes) if row.output_kind == "review_audit_metadata" else row
                             for row in declarations)
    accepted = run.publish(JOB, {}, declarations=declarations)
    context = SimpleNamespace(run_root=run.root, evidence_target_snapshot=run.target,
                              config=SimpleNamespace(job_id=consumer), contract=contract,
                              upstream_handoffs={JOB: accepted.sha256})
    if publication in {"wrong-schema", "wrong-authority"}:
        with pytest.raises(ValueError, match="producer output contract mismatch|producer evidence authority mismatch"):
            admit_inputs(context, {JOB, consumer})
        return
    admission = admit_inputs(context, {JOB, consumer})
    rows = {row["output_kind"]: row for row in admission["requirements"]
            if row["producer"] == JOB and row["output_kind"] in KINDS}
    assert set(rows) == KINDS
    for kind, row in rows.items():
        assert row["available"] is False and row["supplied"] is False and row["read"] is False
        assert row["cited"] is None
        assert row["handoff_sha256"] == accepted.sha256
        assert row["status"] == ("gap" if kind == "review_audit_metadata" else "not_applicable")
