"""Optional-producer integrity, accounting and public projection at the final gate."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest

from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs import completion_contracts as contracts
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.engineering_contracts import POC_GENERATION_SCHEMA
from appsec_review.jobs.job_final_publication_gate import attachments as intake
from appsec_review.jobs.job_inference_security_review.stages import poc_candidates
from appsec_review.jobs.job_poc_generation.candidates import parse_candidates
from appsec_review.jobs.job_poc_generation.statuses import STATUSES
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json
from tests.fixtures.poc_generation import relay

ROOT = Path(__file__).parents[1]
CLAIM = "claim-" + "1" * 64
FINDING = "finding-" + "2" * 64
PACKAGE = "finding_lead-" + "3" * 64
CHAIN = "chain-" + "4" * 64
BINDING = {"claim_id": CLAIM, "finding_package_id": FINDING, "sha256": "5" * 64}
BASIS = {"entry": ["asr:entry_point:" + "1" * 64], "path": ["asr:call_site:" + "2" * 64],
         "trigger": [relay.TRIGGER], "input_format": "synthetic input",
         "preconditions": [], "expected_observation": "compile-only documentation", "unknowns": []}


class Fixture:
    def __init__(self, root: Path, monkeypatch):
        self.root = root / "run"
        self.accepted = {}
        self.source = {"poc_candidates": []}
        self.review_ref = self.write("review.json", self.source)
        self.review = {
            "run_id": "run", "inputs": {"review_handoff": self.review_ref, "job_handoff": self.write("job.json", {})},
            "review": {"status": "DEGRADED", "accepted_manifest_sha256": self.write("manifest.json", {})["sha256"]},
            "bindings": [], "packages": [{**BINDING, "state": "confirmed", "attack_chains": [],
                                        "adjudication_id": "adjudication-" + "6" * 64}]}
        monkeypatch.setattr(intake, "accepted_handoff", lambda _root, job: self.accepted.get(job))

    def write(self, name, document):
        path = self.root / "data" / name
        atomic_json(path, document)
        return artifact_ref(self.root, path)

    def source_update(self):
        self.review_ref = self.write("review.json", self.source)
        self.review["inputs"]["review_handoff"] = self.review_ref

    def publish(self, name, document):
        job, schema, _, unit = intake.PRODUCERS[name]
        ref = self.write(f"{name}.json", document)
        rows = document["candidates"] if name == "poc_generation" else document["items"]
        handoff = {"job_id": job, "outputs": {unit: {
            "schema": schema, "artifact": ref, "item_count": len(rows), "gaps": document["gaps"],
            "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}}}
        handoff_ref = self.write(f"{job}.json", handoff)
        self.accepted[job] = AcceptedHandoff(job, handoff, handoff_ref["sha256"], handoff_ref["path"])
        return ref

    def verify(self, *enabled):
        return intake.verify_attachments(self.root, self.review, repository_root=ROOT,
                                          enabled={name: True for name in enabled})

    def poc(self, *, status="not_applicable", omitted=False):
        from appsec_review.config.inference_review import PocCandidateSettings

        # Use the actual review producer, not a consumer-shaped hand-authored candidate.
        findings = [{**BINDING, "state": "confirmed", "judge_verdict": "red_correct", "technical_severity": "high",
                     "direct_evidence": []}]
        candidates = poc_candidates(findings, [{"claim_id": CLAIM, "cell_id": "cell", "package_id": PACKAGE,
                                                "poc_basis": BASIS}], PocCandidateSettings())
        assert len(candidates) == 1
        assert parse_candidates(candidates)[0].poc_basis.record() == BASIS
        self.source["poc_candidates"] = candidates
        self.source_update()
        candidate = candidates[0]
        rows = [] if omitted else [{
            **{key: candidate[key] for key in ("claim_id", "package_id", "state", "judge_verdict", "finding_package")},
            "poc_basis_sha256": candidate["poc_basis"]["sha256"], "status": status, "reason": "bounded outcome",
            "description": "DO_NOT_LEAK_SOURCE", "functions": None, "files": None, "brief": None,
            "writer_receipt": None, "gaps": [], **contracts.nonexecution_assurance()}]
        return {"schema": POC_GENERATION_SCHEMA, "run_id": "run", "upstream": {
                    "review_handoff": self.review_ref, "review_job_handoff": self.review["inputs"]["job_handoff"],
                    "manifest": self.write("manifest.json", {}), "language_build_handoff_sha256": None},
                "execution_policy": "nothing is linked into an executable and nothing is run",
                "settings_sha256": "7" * 64, "counts": {"candidates": len(rows), "omitted": int(omitted),
                    "by_status": {key: int(not omitted and key == status) for key in STATUSES}},
                "candidates": rows, "omitted_claims": [CLAIM] if omitted else [], "gaps": [],
                **contracts.nonexecution_assurance()}

    def planning(self):
        from tests.remediation_support import answer
        upstream = {"review_handoff": self.review_ref, "poc_handoff": None}
        plan = self.write("plan.json", {
            **answer(["relation"], {}, "proposal_generated"),
            "schema": contracts.REMEDIATION_PLAN_SCHEMA, "run_id": "run", "finding": BINDING,
            "adjudication_id": self.review["packages"][0]["adjudication_id"],
            "violated_invariant": "DO_NOT_LEAK_SOURCE", "reason": "proposed only",
            "upstream": upstream, "patch": self.write("patch.json", {}),
            "provenance": {"settings_sha256": "7" * 64, "source_context": self.write("context.json", {}),
                           "writer_receipt": self.write("writer.json", {}), "guidance_bundle_sha256": "8" * 64},
            "gaps": [], "assurance": contracts.nonexecution_assurance()})
        return {"schema": contracts.REMEDIATION_PLANNING_SCHEMA, "run_id": "run",
                "upstream": upstream, "items": [
                    {"finding": BINDING, "status": "proposal_generated", "plan": plan, "reason": "proposed only",
                     "gap_ids": []}], "gaps": []}

    def validation(self, planning):
        planning_ref = self.accepted[contracts.REMEDIATION_PLANNING_JOB]
        plan = planning["items"][0]["plan"]
        upstream = {"review_handoff": self.review_ref, "poc_handoff": None,
                    "planning_handoff": {"path": planning_ref.path, "sha256": planning_ref.sha256}}
        checks = {name: {"status": "not_performed", "reason": "not configured", "artifact": None}
                  for name in ("patch_applicability", "policy", "semantic_review", "static_checks", "build",
                               "regression_compile", "runtime_regression")}
        checks["runtime_regression"]["status"] = "not_performed_by_policy"
        artifact = self.write("validation.json", {
            "schema": contracts.REMEDIATION_VALIDATION_SCHEMA, "run_id": "run", "finding": BINDING,
            "adjudication_id": self.review["packages"][0]["adjudication_id"], "upstream": upstream,
            "plan": plan, "patch": self.write("patch.json", {}), "checks": checks,
            "status": "manual_validation_required", "reason": "not executed", "cleanup": None,
            "settings_sha256": "7" * 64, "gaps": [], "assurance": contracts.nonexecution_assurance()})
        return {"schema": contracts.REMEDIATION_VALIDATION_SUMMARY_SCHEMA, "run_id": "run",
                "upstream": upstream, "items": [{"finding": BINDING, "status": "manual_validation_required",
                    "validation": artifact, "reason": "not executed", "gap_ids": []}], "gaps": []}

    def dossier(self):
        files = {"json": self.write("dossier.json", {
            "schema": contracts.DOSSIER_SCHEMA, "run_id": "run", "finding": BINDING, "dossier_id": "dossier",
            "kind": "confirmed_finding", "source_excerpt": "DO_NOT_LEAK_SOURCE"}),
            "latex": self.write("dossier.tex", {"source_excerpt": "DO_NOT_LEAK_SOURCE"}), "pdf": None}
        receipt = self.write("receipt.json", {"dossier_id": "dossier", "run_id": "run", "status": "latex_only",
                                             "files": files, "execution": None})
        return {"schema": contracts.DOSSIER_PUBLICATION_SCHEMA, "run_id": "run", "upstream": {
            "review_handoff": self.review_ref, "poc_handoff": None, "remediation_planning_handoff": None,
            "remediation_validation_handoff": None},
            "items": [{"dossier_id": "dossier", "kind": "confirmed_finding", "finding": BINDING,
                       "status": "latex_only", "files": {**files, "receipt": receipt}, "gap_ids": []}],
            "omitted": [], "gaps": [], "settings_sha256": "7" * 64,
            "counts": {"admitted": 1, "items": 1, "omitted": 0, "by_kind": {"confirmed_finding": 1, "poc": 0},
                       "by_status": {"rendered": 0, "render_failed": 0, "latex_only": 1}},
            "caps": {"max_dossiers": 1, "max_source_excerpts": 1, "max_evidence_rows": 1}}

    def chain(self):
        other = {**self.review["packages"][0], "claim_id": "claim-" + "9" * 64,
                 "finding_package_id": "finding-" + "9" * 64}
        self.review["packages"].append(other)
        components = [{key: row[key] for key in ("claim_id", "adjudication_id", "state")} |
                      {"missing_predicates": [], "requires_extra_verifier": False} for row in self.review["packages"]]
        proposal = {"chain_id": CHAIN, "objective": "bounded synthetic chain", "environment": "fixture",
            "components": components, "prerequisites": [],
            "edges": [{"from_claim_id": CLAIM, "to_claim_id": other["claim_id"], "output_entity": BASIS["entry"][0],
                       "input_entity": BASIS["path"][0], "obligations": [
                           {"dimension": name, "evidence": []} for name in (
                               "identity", "privilege", "trust_boundary", "artifact_deployment", "temporal")]}],
            "composer": {"actor_id": "actor-fixture", "provider": "fixture", "model": "fixture",
                         "conversation_id": "fixture", "prior_response_sha256": None, "cache_key": None}}
        artifact = self.write("chain.json", {
            "schema": contracts.ATTACK_CHAIN_SCHEMA, "run_id": "run", "proposal": proposal, "challenges": [],
            "status": "qualified_supported", "limitations": ["continuity remains qualified"],
            "assessment": {"objective": proposal["objective"], "path_confidence": "qualified", "prerequisites": [],
                           "boundary_exposure": "unresolved", "remediation_choke_points": [],
                           "shipment_decision": "not_assessed_by_chain_policy"}})
        for row in self.review["packages"]:
            row["attack_chains"] = [CHAIN]
        document = {"schema": contracts.ATTACK_CHAIN_MANIFEST_SCHEMA, "run_id": "run",
            "items": [{"chain_id": CHAIN, "status": "qualified_supported",
                       "component_claim_ids": [CLAIM, other["claim_id"]], "artifact": artifact,
                       "limitations": ["continuity remains qualified"], "disposition": "assessed"}],
            "gaps": ["qualified continuity"], "accounting": {
                "proposed": 1, "admitted": 1, "assessed": 1, "capped": 0, "rejected": 0, "deduplicated": 0,
                "seeds_received": 0, "seeds_rejected": 0},
            "exploration": {"expanded": 1, "limit": 10, "frontier": [], "frontier_truncated": False}}
        self.source["attack_chain_manifest"] = self.write("chains.json", document)
        self.source_update()
        return document


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    return Fixture(tmp_path, monkeypatch)


def test_disabled_and_missing_enabled_work_have_distinct_truthful_dispositions(fixture):
    disabled = fixture.verify()
    assert all(record["disposition"] == "SKIPPED_POLICY" for record in disabled["capabilities"].values())
    missing = fixture.verify("poc_generation", "remediation_planning")
    assert missing["capabilities"]["poc_generation"]["disposition"] == "GAP"
    assert missing["capabilities"]["remediation_planning"]["disposition"] == "GAP"
    assert not any(missing["attachments"].values())


def test_disabled_lane_does_not_discover_an_existing_handoff(fixture):
    fixture.publish("remediation_planning", fixture.planning())
    assert fixture.verify()["capabilities"]["remediation_planning"]["handoff"] is None


def test_real_review_candidate_contract_is_consumed_and_capped_work_is_exact(fixture):
    document = fixture.poc(omitted=True)
    fixture.publish("poc_generation", document)
    result = fixture.verify("poc_generation")
    assert result["capabilities"]["poc_generation"]["disposition"] == "GAP"
    assert result["capabilities"]["poc_generation"]["omitted_count"] == 1


def test_poc_outcomes_are_compile_only_and_model_descriptions_are_not_public(fixture):
    document = fixture.poc()
    fixture.publish("poc_generation", document)
    result = fixture.verify("poc_generation")
    row = result["attachments"]["poc_generation"][0]
    assert row["runtime_verified"] is False and row["result_id"] is None
    assert row["execution"] == "not_performed_by_policy"
    assert "DO_NOT_LEAK_SOURCE" not in str(result)


@pytest.mark.parametrize("mutate", [
    lambda d: d["counts"].update(candidates=2),
    lambda d: d["counts"]["by_status"].update(not_applicable=0),
    lambda d: d.update(omitted_claims=[CLAIM]),
    lambda d: d["candidates"].append(deepcopy(d["candidates"][0])),
    lambda d: d["candidates"][0].update(poc_basis_sha256="0" * 64),
    lambda d: d["candidates"][0].update(runtime_verified=True),
    lambda d: d["candidates"][0].update(result_id="fake-runtime-result"),
    lambda d: d["upstream"].update(review_handoff={"path": "data/other.json", "sha256": "8" * 64}),
    lambda d: d.update(run_id="another-run"),
])
def test_poc_mixed_reviews_inexact_accounting_and_runtime_claims_fail_integrity(fixture, mutate):
    document = fixture.poc()
    mutate(document)
    fixture.publish("poc_generation", document)
    with pytest.raises(IntegrityError):
        fixture.verify("poc_generation")


def test_empty_scope_is_accounted_and_not_clean_coverage(fixture):
    document = fixture.poc(omitted=True)
    fixture.source["poc_candidates"] = []
    fixture.source_update()
    document["upstream"]["review_handoff"] = fixture.review_ref
    document.update(omitted_claims=[])
    document["counts"]["omitted"] = 0
    fixture.publish("poc_generation", document)
    record = fixture.verify("poc_generation")["capabilities"]["poc_generation"]
    assert record["disposition"] == "SKIPPED_NA"
    assert "not clean coverage" in record["reason"]


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(items=[]),
    lambda d: d["items"].append(deepcopy(d["items"][0])),
    lambda d: d["items"][0].update(finding={**BINDING, "sha256": "0" * 64}),
    lambda d: d["items"][0].update(plan=None),
])
def test_remediation_is_confirmed_only_exact_and_hash_bound(fixture, mutate):
    document = fixture.planning()
    mutate(document)
    fixture.publish("remediation_planning", document)
    with pytest.raises(IntegrityError):
        fixture.verify("remediation_planning")


def test_supported_finding_cannot_enter_remediation_or_become_confirmed(fixture):
    document = fixture.planning()
    fixture.review["packages"][0]["state"] = "supported"
    fixture.publish("remediation_planning", document)
    with pytest.raises(IntegrityError, match="confirmed"):
        fixture.verify("remediation_planning")
    assert fixture.review["packages"][0]["state"] == "supported"


def test_plan_contents_are_protected_and_tampering_is_not_silently_omitted(fixture):
    document = fixture.planning()
    fixture.publish("remediation_planning", document)
    result = fixture.verify("remediation_planning")
    assert "DO_NOT_LEAK_SOURCE" not in str(result)
    assert result["attachments"]["remediation_planning"][0]["status"] == "proposal_generated"
    path = fixture.root / document["items"][0]["plan"]["path"]
    path.write_text("{}")
    with pytest.raises(IntegrityError, match="changed after acceptance"):
        fixture.verify("remediation_planning")


def test_concurrent_optional_acceptance_invalidates_gate_snapshot(fixture):
    verified = {**fixture.review, **fixture.verify("remediation_planning")}
    review_ref = fixture.review["inputs"]["job_handoff"]
    fixture.accepted["job_inference_security_review"] = AcceptedHandoff(
        "job_inference_security_review", {}, review_ref["sha256"], review_ref["path"])
    fixture.publish("remediation_planning", fixture.planning())
    with pytest.raises(IntegrityError, match="changed during gate publication"):
        intake.reverify_snapshot(fixture.root, verified)


def test_validation_binds_exact_planning_wrapper_plan_and_nonexecution_policy(fixture):
    planning = fixture.planning()
    fixture.publish("remediation_planning", planning)
    fixture.publish("remediation_validation", fixture.validation(planning))
    result = fixture.verify("remediation_planning", "remediation_validation")
    assert result["attachments"]["remediation_validation"][0]["runtime_verified"] is False
    assert result["capabilities"]["remediation_validation"]["disposition"] == "GAP"


@pytest.mark.parametrize("field,value", [
    ("plan", {"path": "data/other.json", "sha256": "0" * 64}),
    ("adjudication_id", "adjudication-other"),
    ("runtime", "passed"),
])
def test_validation_rejects_another_plan_adjudication_or_runtime_proof(fixture, field, value):
    planning = fixture.planning()
    fixture.publish("remediation_planning", planning)
    document = fixture.validation(planning)
    ref = document["items"][0]["validation"]
    import json
    artifact = json.loads((fixture.root / ref["path"]).read_text())
    if field == "runtime":
        artifact["checks"]["runtime_regression"]["status"] = value
    else:
        artifact[field] = value
    document["items"][0]["validation"] = fixture.write("validation.json", artifact)
    fixture.publish("remediation_validation", document)
    with pytest.raises(IntegrityError):
        fixture.verify("remediation_planning", "remediation_validation")


def test_dossiers_reuse_peer_verifier_and_keep_protected_contents_out_of_projection(fixture):
    fixture.publish("dossiers", fixture.dossier())
    result = fixture.verify("dossiers")
    assert result["capabilities"]["dossiers"]["disposition"] == "GAP"
    assert "DO_NOT_LEAK_SOURCE" not in str(result)


@pytest.mark.parametrize("mutate", [
    lambda d: d["items"][0].update(status="rendered"),
    lambda d: d["items"][0].update(finding={**BINDING, "sha256": "0" * 64}),
    lambda d: d["counts"]["by_kind"].update(poc=1),
    lambda d: d.update(items=[]),
])
def test_dossier_receipt_status_findings_and_accounting_fail_closed(fixture, mutate):
    document = fixture.dossier()
    mutate(document)
    fixture.publish("dossiers", document)
    with pytest.raises(IntegrityError):
        fixture.verify("dossiers")


def test_dossier_cap_exactly_accounts_for_omitted_confirmed_work(fixture):
    document = fixture.dossier()
    other = {**fixture.review["packages"][0], "claim_id": "claim-" + "9" * 64,
             "finding_package_id": "finding-" + "9" * 64}
    fixture.review["packages"].append(other)
    document["omitted"] = [{"kind": "confirmed_finding", "finding": {
        key: other[key] for key in ("claim_id", "finding_package_id", "sha256")}, "reason": "max_dossiers"}]
    document["counts"].update(admitted=2, omitted=1, by_kind={"confirmed_finding": 2, "poc": 0})
    fixture.publish("dossiers", document)
    assert fixture.verify("dossiers")["capabilities"]["dossiers"]["omitted_count"] == 1


@pytest.mark.parametrize("admission", ["absent", "exact", "mismatched"])
def test_disabled_poc_requires_exact_explicit_admission_and_emits_bounded_metrics(fixture, monkeypatch, admission):
    from appsec_review.jobs.job_final_publication_gate import job
    fixture.publish("poc_generation", fixture.poc())
    producer = fixture.accepted["job_poc_generation"]
    configuration = fixture.write("configuration/resolved.json", {"jobs": {}})
    monkeypatch.setattr(job, "resolved_configuration_identity", lambda _root: configuration["sha256"])
    monkeypatch.setattr(job, "load_accepted_review", lambda *_args, **_kw: SimpleNamespace(document=deepcopy(fixture.review)))
    events = []
    settings = tomllib.loads((ROOT / "appsec-review.toml").read_text())["jobs"]["job_final_publication_gate"]["settings"]
    context = SimpleNamespace(
        job=SimpleNamespace(run_root=fixture.root, repository_root=ROOT, config=SimpleNamespace(settings=settings),
                            upstream_handoffs={} if admission == "absent" else {
                                "job_poc_generation": producer.sha256 if admission == "exact" else "0" * 64},
                            events=SimpleNamespace(write=lambda name, **fields: events.append((name, fields)))),
        unit_root=fixture.root / "data" / "gate")
    if admission == "mismatched":
        with pytest.raises(IntegrityError, match="explicit upstream identity"):
            job.build_job(repository_root=ROOT).units[0].handler(context)
        assert events == []
        return
    job.build_job(repository_root=ROOT).units[0].handler(context)
    fields = events[0][1]
    assert events[0][0] == "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED"
    assert fields["explicit_poc_admission"] == (admission == "exact")
    assert fields["attachment_counts"]["poc_generation"] == int(admission == "exact")
    assert fields["enabled"]["poc_generation"] == (admission == "exact")
    assert sum(fields["outcomes"].values()) == 5
    assert fields["attachment_count"] == int(admission == "exact")
    assert "DO_NOT_LEAK_SOURCE" not in str(events) and CLAIM not in str(fields)


def test_qualified_chain_is_certified_without_unconditional_withholding(fixture):
    from appsec_review.jobs.job_final_publication_gate.classify import withheld_reasons
    fixture.chain()
    result = fixture.verify("attack_chains")
    assert result["attachments"]["attack_chains"][0]["status"] == "qualified_supported"
    assert result["capabilities"]["attack_chains"]["disposition"] == "GAP"
    for row in fixture.review["packages"]:
        assert withheld_reasons({**row, "poc": None}, result["attachments"]) == []


@pytest.mark.parametrize("mutate", [
    lambda d: d["accounting"].update(proposed=2),
    lambda d: d["accounting"].update(capped=1),
    lambda d: d["items"][0].update(component_claim_ids=[CLAIM]),
    lambda d: d["items"][0].update(status="confirmed"),
    lambda d: d["items"][0].update(limitations=[]),
    lambda d: d["items"].append(deepcopy(d["items"][0])),
    lambda d: d.update(run_id="another-run"),
])
def test_chain_identity_artifact_status_and_candidate_accounting_are_exact(fixture, mutate):
    document = fixture.chain()
    mutate(document)
    fixture.source["attack_chain_manifest"] = fixture.write("chains.json", document)
    fixture.source_update()
    with pytest.raises(IntegrityError):
        fixture.verify("attack_chains")


def test_report_rechecks_only_bound_snapshot_references_and_requires_all_attachments_bound(fixture):
    from appsec_review.jobs.job_final_report_publication.job import _verify_bindings
    reference = fixture.write("attachment.json", {})
    gate = {"run_id": "run", "inputs": {}, "bindings": [reference],
            "capabilities": {}, "attachments": {"example": [reference]}}
    _verify_bindings(fixture.root, gate)
    gate["bindings"] = []
    with pytest.raises(IntegrityError, match="certified bindings"):
        _verify_bindings(fixture.root, gate)
