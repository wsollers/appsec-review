"""Retained, deterministic fixture producers for the report happy-path demo.

The documents are deliberately labelled fixture evidence.  They exercise the real accepted-result,
assembly, synthesis, completion, and publication contracts; they are not target scan results.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from execution_state import atomic_json, digest, file_hash, tree_hashes
import report_input_assembly as report
from worker_result import artifact_records, terminal_envelope

SOURCE = "sha256:" + "a" * 64
COMPONENT_ATTEMPT = "component-1"
STAMP = "2026-01-01T00:00:00Z"


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _rehash_entries(entries: list[dict[str, Any]]) -> str:
    previous = None
    for sequence, entry in enumerate(entries):
        entry["sequence"] = sequence
        entry["previous_entry_hash"] = previous
        entry["event_id"] = "event-" + digest({key: value for key, value in entry.items()
            if key not in {"event_id", "entry_hash"}})[:24]
        entry["entry_hash"] = _sha({key: value for key, value in entry.items() if key != "entry_hash"})
        previous = entry["entry_hash"]
    assert previous is not None
    return previous


def _publish(jobs: Path, run_id: str, job: str, contract: str, attempt_id: str,
             documents: dict[str, dict[str, Any]]) -> Path:
    base, attempt = jobs / job, jobs / job / "attempts" / attempt_id
    attempt.mkdir(parents=True)
    for relative, document in documents.items():
        atomic_json(attempt / relative, document)
    atomic_json(attempt / "permission.json", {
        "schema": "appsec-review/producer-permission-receipt/1.0", "run_id": run_id,
        "job_id": job, "source_snapshot_sha256": SOURCE,
        "permissions": report.CANONICAL_PERMISSIONS[job]})
    atomic_json(attempt / "lineage.json", {
        "schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": run_id,
        "job_id": job, "source_snapshot_sha256": SOURCE,
        "build_lineage_sha256": "sha256:" + "e" * 64})
    atomic_json(attempt / "status.json", {"status": "OK", "fixture": True})
    paths = [*documents, "permission.json", "lineage.json", "status.json"]
    envelope = terminal_envelope(run_id=run_id, job_id=job, attempt_id=attempt_id,
        worker_kind="deterministic_python", execution_status="OK", acceptance_status="CURRENT",
        input_fingerprint="sha256:" + "f" * 64, output_contract=contract,
        started_at=STAMP, finished_at="2026-01-01T00:00:01Z",
        summary="DEMO fixture producer; not live target evidence.",
        artifacts=artifact_records(attempt, paths))
    atomic_json(attempt / "result.json", envelope)
    atomic_json(base / "latest.json", {"attempt_id": attempt_id,
        "updated_at": "2026-01-01T00:00:02Z"})
    atomic_json(base / "accepted.json", {
        "schema": "appsec-review/accepted-worker-result/1.0", "status": "OK",
        "run_id": run_id, "job": job, "attempt_id": attempt_id,
        "fingerprint": envelope["input_fingerprint"], "envelope_path": "result.json",
        "envelope_sha256": file_hash(attempt / "result.json"), "hashes": tree_hashes(attempt),
        "accepted_at": "2026-01-01T00:00:02Z"})
    return base / "accepted.json"


def _authority(pointer_path: Path, artifact: str, role: str) -> dict[str, Any]:
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    attempt = pointer_path.parent / "attempts" / pointer["attempt_id"]
    return {"contract_id": pointer["job"], "job_id": pointer["job"],
        "attempt_id": pointer["attempt_id"], "role_id": role,
        "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
        "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path),
        "envelope_sha256": "sha256:" + file_hash(attempt / "result.json"),
        "artifact_path": artifact, "artifact_sha256": "sha256:" + file_hash(attempt / artifact),
        "permission_receipt_path": "permission.json",
        "permission_receipt_sha256": "sha256:" + file_hash(attempt / "permission.json"),
        "reason": "Accepted exact DEMO fixture decision."}


def materialize(run_root: Path, run_id: str) -> dict[str, str]:
    """Create the six exact accepted producers required by report assembly."""
    root = Path(__file__).resolve().parent
    jobs = Path(run_root) / "data" / "jobs"
    evidence = jobs / "evidence-source" / "attempts" / "evidence-1"
    evidence.mkdir(parents=True)
    atomic_json(evidence / "evidence.json", {
        "fixture": True, "observed": "Bounded DEMO fixture evidence; not a live scan result."})
    evidence_hash = "sha256:" + file_hash(evidence / "evidence.json")
    claim = "claim-" + digest({"route_id": "route-1", "producer": "03-threat-model-dfd-stride",
        "attempt": "threat-1", "artifact": "sha256:" + "c" * 64,
        "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT})[:24]

    def citation() -> dict[str, str]:
        return {"citation_id": "citation-1", "producer_job_id": "evidence-source",
            "producer_attempt_id": "evidence-1", "artifact_path": "evidence.json",
            "artifact_sha256": evidence_hash, "locator_json": "/observed",
            "observed_fact": "Bounded DEMO fixture evidence exists."}

    def actor(job: str, attempt: str, role: str, artifact: str, fill: str) -> dict[str, Any]:
        return {"job_id": job, "attempt_id": attempt, "role_id": role,
            "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
            "artifact_path": artifact, "artifact_sha256": "sha256:" + fill * 64,
            "permission_receipt_path": "permission.json",
            "permission_receipt_sha256": "sha256:" + fill * 64,
            "reason": f"Authorized {role} DEMO fixture decision."}

    component = json.loads((root / "tests/fixtures/component-characterization/hello-autotools.json").read_text())
    component["source_snapshot_sha256"] = SOURCE
    threat = json.loads((root / "tests/fixtures/threat-workbench/schema/integrated-threat-model.golden.json").read_text())
    threat.update(run_id=run_id, attempt_id="threat-1", source_snapshot=SOURCE,
                  component_map_attempt_id=COMPONENT_ATTEMPT, stride_hypotheses=[])
    selection = {"schema": "appsec-review/standard-selection/1.0", "selection_id": "selection-1",
        "engagement_id": run_id, "selections": [{"family": "ASVS", "snapshot_id": "demo-snapshot",
        "manifest_sha256": "1" * 64, "edition": "DEMO", "enabled_scope": ["V1"],
        "profile_or_level": "L1"}], "approver": "DEMO-FIXTURE", "approved_at": STAMP}
    zero_assessments = {name: 0 for name in ("partially_satisfied", "not_satisfied", "cannot_verify",
        "dynamic_test_required", "human_decision_required", "not_assessed", "not_applicable",
        "cannot_determine", "out_of_scope")}
    matrix = {"schema": "appsec-review/owasp-control-status-matrix/1.0", "run_id": run_id,
        "selection_id": "selection-1", "selection": selection,
        "permissions": {"static_inspection": True, "dynamic_execution": False,
            "manual_observation": False, "network_access": False, "target_mutation": False},
        "evidence_admitted_at": STAMP,
        "provenance": {"dispatch_attempt_id": "demo-dispatch", "dispatch_accounting_sha256": "2" * 64,
            "handoff_attempt_id": "demo-handoff", "handoff_set_sha256": "3" * 64,
            "worklist_sha256": "4" * 64, "applicability_model_sha256": "5" * 64,
            "input_manifest_sha256": "6" * 64},
        "denominators": {"selected": 1, "applicable": 1, "assessed": 1, "satisfied": 1},
        "applicability_counts": {"applicable": 1, "conditional": 0, "not_applicable": 0,
            "cannot_determine": 0, "out_of_scope": 0},
        "assessment_counts": {"satisfied": 1, **zero_assessments}, "dispatch_cells": [],
        "rows": [{"row_index": 0, "assignment_id": "demo-assignment", "target_id": "demo-target",
            "standard_family": "ASVS", "standard_version": "DEMO", "profile_or_level": "L1",
            "control_id": "V1.1.1", "component_id": "component-1", "domain_id": "architecture",
            "applicability_status": "applicable", "applicability_rationale": "DEMO fixture scope.",
            "applicability_citations": [], "decision_source": "DEMO fixture", "override_ids": [],
            "source_completeness": "adequate", "rescope_state": "none", "rescope_actions": [],
            "invalidated_result_ids": [], "crosswalk_lineage": [], "batch_ids": [],
            "proof_obligations": [], "dispatch_disposition": "DEMO fixture", "joined_status": "satisfied",
            "assessment_results": [], "dynamic_candidate_ids": [], "gap_ids": ["gap-1"],
            "dissent_ids": [], "candidate_route_ids": []}],
        "claim_limits": {"finding_created": False, "severity_assigned": False,
        "runtime_state_claimed": False, "compliance_certified": False,
        "status_upgrade_permitted": False}}
    gaps = {"schema": "appsec-review/owasp-coverage-gaps-report/1.0", "run_id": run_id,
        "selection_id": "selection-1", "gaps": [{"gap_id": "gap-1", "kind": "evidence",
        "row_indices": [0], "statement": "DEMO fixture coverage gap; not a live target conclusion.",
        "citation_ids": [], "result_ids": []}]}
    routes = {"schema": "appsec-review/owasp-candidate-promotion-routes/1.0", "run_id": run_id,
        "selection_id": "selection-1", "finding_promotion": "not_performed", "routes": []}
    producer = {"contract_id": "threat-model-core", "job_id": "03-threat-model-dfd-stride",
        "attempt_id": "threat-1", "artifact_path": "integrated-threat-model.json",
        "artifact_sha256": "sha256:" + "c" * 64,
        "accepted_pointer_sha256": "sha256:" + "d" * 64}
    base = {"event_type": "candidate_admitted", "claim_id": claim, "route_id": "route-1",
        "claim_class": "candidate_only", "hypothesis": "A bounded DEMO fixture hypothesis.",
        "status": "candidate", "confidence": "medium", "component_ids": ["component-1"],
        "source_generation": SOURCE, "component_generation": COMPONENT_ATTEMPT,
        "producer": producer, "citations": [citation()],
        "proof_obligations": [{"obligation_id": "obligation-1", "statement": "Verify fixture."}],
        "dissent_ids": ["dissent-1"], "causal_claim_ids": [], "supersedes_claim_id": None,
        "from_status": None, "decision_authority": None, "sequence": 0,
        "event_id": "", "previous_entry_hash": None, "entry_hash": ""}
    _rehash_entries([base])
    review = copy.deepcopy(base); review.update(event_type="status_decision", status="under_review",
        from_status="candidate", decision_authority=None)
    narrowed = copy.deepcopy(review); narrowed.update(status="narrowed", from_status="under_review")
    verified = copy.deepcopy(narrowed); verified.update(status="verified", from_status="narrowed")
    entries = [base, review, narrowed, verified]
    head = _rehash_entries(entries)
    ledger = {"schema": "appsec-review/claim-decision-ledger/1.0", "run_id": run_id,
        "job_id": "claim-ledger-decisions", "attempt_id": "ledger-1", "source_generation": SOURCE,
        "component_generation": COMPONENT_ATTEMPT, "entries": entries, "head_hash": head,
        "claim_states": [{"claim_id": claim, "latest_event_id": verified["event_id"], "status": "verified"}],
        "claim_limits": {"candidate_only": True, "finding_created": False,
        "severity_assigned": False, "runtime_claimed": False, "compliance_claimed": False}}
    red_actor = actor("07-red-team-adversarial", "red-1", "red-team-adversary", "red-assessment.json", "7")
    blue_actor = actor("08-blue-team-refutation", "blue-1", "blue-team-refuter", "blue-assessment.json", "8")
    verifier = actor("09-independent-verification", "verification-1", "independent-verifier",
                     "verification-evidence.json", "9")
    inherited = {"claim_id": claim, "route_id": "route-1", "claim_class": "candidate_only",
        "hypothesis": "A bounded DEMO fixture hypothesis.", "confidence": "medium",
        "component_ids": ["component-1"], "source_generation": SOURCE,
        "component_generation": COMPONENT_ATTEMPT, "producer": producer, "citations": [citation()],
        "proof_obligations": [{"obligation_id": "obligation-1", "statement": "Verify fixture.",
            "status": "SATISFIED", "citations": [citation()]}], "dissent_ids": ["dissent-1"],
        "causal_claim_ids": [], "supersedes_claim_id": None}
    verification_record = {**inherited, "hypothesis_id": "hyp_" + "4" * 20,
        "status": "VERIFIED", "red_reviewer": red_actor, "blue_reviewer": blue_actor,
        "verifier": verifier, "verification_method": "Hash-bound DEMO fixture verification.",
        "verification_citations": [citation()]}
    upstream = {"job_id": "upstream", "attempt_id": "upstream-1",
        "pointer_sha256": "sha256:" + "1" * 64, "artifact_path": "upstream.json",
        "artifact_sha256": "sha256:" + "2" * 64}
    verification = {"schema": "appsec-review/independent-verification/1.0", "run_id": run_id,
        "stage": "09-independent-verification", "ledger_head_id": base["event_id"],
        "ledger_head_sha256": base["entry_hash"], "upstream": upstream,
        "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
        "verifications": [verification_record]}
    priority = {**inherited, "verification_status": "VERIFIED", "verifier": verifier,
        "verification_citations": [citation()], "score": 16, "severity": "CRITICAL", "priority": "P0",
        "factors": {"impact": 4, "exploitability": 4, "exposure": 4, "confidence": 4},
        "scoring_rationale": "Deterministic DEMO fixture score."}
    scoring = {"schema": "appsec-review/scoring-prioritization/1.0", "run_id": run_id,
        "stage": "12-scoring-prioritization", "ledger_head_id": base["event_id"],
        "ledger_head_sha256": base["entry_hash"], "upstream": upstream,
        "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF", "priorities": [priority]}

    stage_pointers: dict[str, Path] = {}
    for job, artifact, collection, role, attempt_id in (
        ("07-red-team-adversarial", "red-team-adversarial.json", "hypotheses", "red-team-adversary", "red-1"),
        ("08-blue-team-refutation", "blue-team-refutation.json", "reviews", "blue-team-refuter", "blue-1")):
        row_keys = ("claim_id", "route_id", "claim_class", "hypothesis", "confidence", "component_ids",
            "component_generation", "source_generation", "producer", "citations", "proof_obligations",
            "dissent_ids", "causal_claim_ids", "supersedes_claim_id", "hypothesis_id")
        row = {key: copy.deepcopy(verification_record[key]) for key in row_keys}
        if job.startswith("07-"):
            row.update(status="HYPOTHESIS", attacker_case="Bounded DEMO attacker case.",
                reviewer=copy.deepcopy(verification_record["red_reviewer"]),
                review_citations=copy.deepcopy(verification_record["citations"]))
            schema = "appsec-review/red-team-adversarial/1.0"
        else:
            row.update(status="SURVIVING", attacker_case="Bounded DEMO attacker case.",
                red_reviewer=copy.deepcopy(verification_record["red_reviewer"]),
                blue_reviewer=copy.deepcopy(verification_record["blue_reviewer"]),
                refutation_rationale="DEMO obligations survived refutation.",
                refutation_citations=copy.deepcopy(verification_record["citations"]))
            schema = "appsec-review/blue-team-refutation/1.0"
        document = {"schema": schema, "run_id": run_id, "stage": job,
            "ledger_head_id": base["event_id"], "ledger_head_sha256": base["entry_hash"],
            "upstream": upstream, "claim_boundary": "DECISION_RECORD_NOT_RUNTIME_OR_COMPLIANCE_PROOF",
            collection: [row]}
        stage_pointers[job] = _publish(jobs, run_id, job, job, attempt_id, {artifact: document})
    stage_pointers["09-independent-verification"] = _publish(jobs, run_id,
        "09-independent-verification", "09-independent-verification", "verification-1",
        {"independent-verification.json": verification})
    ledger["entries"][1]["decision_authority"] = _authority(stage_pointers["07-red-team-adversarial"],
        "red-team-adversarial.json", "red-team-adversary")
    ledger["entries"][2]["decision_authority"] = _authority(stage_pointers["08-blue-team-refutation"],
        "blue-team-refutation.json", "blue-team-refuter")
    ledger["entries"][3]["decision_authority"] = _authority(stage_pointers["09-independent-verification"],
        "independent-verification.json", "independent-verifier")
    ledger["head_hash"] = _rehash_entries(ledger["entries"])
    ledger["claim_states"] = [{"claim_id": claim,
        "latest_event_id": ledger["entries"][-1]["event_id"], "status": "verified"}]

    documents = {"component": {"component-purpose-map.json": component},
        "threat": {"integrated-threat-model.json": threat},
        "owasp": {"owasp-control-status-matrix.json": matrix, "owasp-coverage-gaps.json": gaps,
                  "owasp-candidate-promotion-routes.json": routes},
        "ledger": {"claim-decision-ledger.json": ledger},
        "verification": {"independent-verification.json": verification},
        "scoring": {"scoring-prioritization.json": scoring}}
    pointers: dict[str, Path] = {}
    for name, spec in report.SPECS.items():
        if name == "verification":
            pointers[name] = stage_pointers["09-independent-verification"]
            continue
        attempt_id = COMPONENT_ATTEMPT if name == "component" else name + "-1"
        pointers[name] = _publish(jobs, run_id, spec[0], spec[1], attempt_id, documents[name])
    return {name: str(path) for name, path in pointers.items()}
