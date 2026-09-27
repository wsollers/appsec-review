"""Zero-config lifecycle adoption for deterministic review-control results.

Every input is reloaded from the newest accepted common-envelope publication.  The one exception is
the human decision itself: this worker deliberately stops at an evidence-bound publication
preparation receipt and never manufactures a signoff.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import bounded_analysis_workers as bounded
import completeness_audit
import control_lane_orchestration
import deterministic_pool_merge
import dynamic_rescope
import evidence_quorum
from execution_state import (Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json,
                             identifier, run_path, tree_hashes)
import pool_rendezvous
import persona_tool_pool_lifecycle
import remediation_retest
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from review_control_loops import completion_gate
from schema_validate import validate_document
import synthetic_hypothesis_resynthesis
from worker_result import validate_worker_result

HASH = "sha256:"
JOBS = {
    "deterministic-pool-merge": ("deterministic-pool-merge", "deterministic-pool-merge.json", "deterministic-pool-merge.schema.json"),
    "evidence-qualified-quorum": ("evidence-qualified-quorum", "evidence-qualified-quorum.json", "evidence-qualified-quorum.schema.json"),
    "dynamic-rescope": ("bounded-rescope-plan", "bounded-rescope-plan.json", "bounded-rescope-plan.schema.json"),
    "completeness-audit": ("completeness-audit", "completeness-audit.json", "completeness-audit.schema.json"),
    "synthetic-hypothesis-resynthesis": ("synthetic-hypothesis-resynthesis", "synthetic-hypothesis-resynthesis.json", "synthetic-hypothesis-resynthesis.schema.json"),
    "remediation-retest-feedback": ("remediation-retest-feedback", "remediation-retest.json", "remediation-retest-feedback.schema.json"),
    "final-publication-preparation": ("final-publication-preparation", "publication-gate-preparation.json", "final-publication-preparation.schema.json"),
}
UPSTREAM = {
    "persona-tool-pool-dispatch": ("persona-tool-pool-dispatch", "persona-tool-pool-dispatch.json", "persona-tool-pool-dispatch.schema.json"),
    "deterministic-pool-merge": JOBS["deterministic-pool-merge"],
    "10-synthesis-report": ("synthesis-report-publication", "report.json", "synthesis-report.schema.json"),
    "completeness-audit": JOBS["completeness-audit"],
    "synthetic-hypothesis-resynthesis": JOBS["synthetic-hypothesis-resynthesis"],
    "09-independent-verification": ("09-independent-verification", "independent-verification.json", "09-independent-verification.schema.json"),
    "11-remediation-proposal": ("11-remediation-proposal", "remediation-proposal.json", "remediation-proposal.schema.json"),
    "00-intake": ("intake", "outputs/intake.json", "intake.schema.json"),
    "evidence-qualified-quorum": JOBS["evidence-qualified-quorum"],
    "dynamic-rescope": JOBS["dynamic-rescope"],
    "remediation-retest-feedback": JOBS["remediation-retest-feedback"],
}


def _sha(value: Any) -> str:
    return HASH + digest(value)


def _generation(run_id: str) -> str:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise Blocked("control lifecycle: artifact manifest is unavailable")
    return HASH + file_hash(manifest)


def _accepted_base(run_id: str, job_id: str) -> Path:
    root = data_path(run_id, "jobs", job_id)
    choices = [path for path in (root, root / "whole") if (path / "accepted.json").is_file()]
    if len(choices) != 1:
        raise Blocked(f"{job_id}: exactly one accepted publication root is required")
    return choices[0]


def _current(run_id: str, job_id: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    contract, artifact, schema = UPSTREAM[job_id]
    base = _accepted_base(run_id, job_id)
    pointer_path = base / "accepted.json"
    pointer = read_json(pointer_path) if pointer_path.is_file() else {}
    if pointer.get("status") == "SKIPPED":
        return _skipped_current(base, pointer, run_id=run_id, job_id=job_id,
            contract=contract, artifact=artifact, schema=schema)
    value, binding = bounded.load_accepted(base / "accepted.json", run_id=run_id, job_id=job_id,
        contract=contract, artifact=artifact, schema=schema)
    return value, binding, base / "attempts" / binding["attempt_id"]


def _skipped_current(base: Path, pointer: dict[str, Any], *, run_id: str, job_id: str,
                     contract: str, artifact: str, schema: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    """Admit the one graph-authorized evidence-supported skip without weakening normal inputs."""
    if job_id != "remediation-retest-feedback":
        raise Blocked(f"{job_id}: an accepted skip is not an allowed publication input")
    expected = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                "envelope_path", "envelope_sha256", "hashes", "accepted_at", "reason"}
    if (not isinstance(pointer, dict) or set(pointer) != expected or
            pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != job_id or
            pointer.get("envelope_path") != "result.json" or
            pointer.get("reason") != "not-applicable-no-verified-claims"):
        raise Blocked(f"{job_id}: accepted skip identity is invalid")
    latest = read_json(base / "latest.json")
    try:
        attempt_id = identifier(pointer["attempt_id"])
    except ValueError as exc:
        raise Blocked(f"{job_id}: accepted skip attempt identity is invalid") from exc
    attempt = base / "attempts" / attempt_id
    if (latest.get("attempt_id") != pointer["attempt_id"] or attempt.is_symlink() or
            not attempt.is_dir() or tree_hashes(attempt) != pointer["hashes"]):
        raise Blocked(f"{job_id}: accepted skip attempt is stale or changed")
    envelope_path = attempt / "result.json"; envelope = read_json(envelope_path)
    if (file_hash(envelope_path) != pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id") != run_id or envelope.get("job_id") != job_id or
            envelope.get("attempt_id") != pointer["attempt_id"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("execution_status") != "SKIPPED" or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("output_contract") != contract or
            envelope.get("skip_reason") != pointer["reason"]):
        raise Blocked(f"{job_id}: accepted skip envelope is invalid")
    artifacts = {row.get("path"): row for row in envelope.get("artifacts", [])}
    if len(artifacts) != len(envelope.get("artifacts", [])) or artifact not in artifacts:
        raise Blocked(f"{job_id}: accepted skip artifact is absent or duplicated")
    for relative, row in artifacts.items():
        rel = PurePosixPath(relative)
        if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
            raise Blocked(f"{job_id}: accepted skip artifact path is unsafe")
        path = attempt.joinpath(*rel.parts)
        try:
            path.resolve(strict=True).relative_to(attempt.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise Blocked(f"{job_id}: accepted skip artifact escapes its attempt") from exc
        if path.is_symlink() or not path.is_file() or file_hash(path) != row.get("sha256"):
            raise Blocked(f"{job_id}: accepted skip artifact hash is invalid")
    value = read_json(attempt / artifact)
    if validate_document(value, schema):
        raise Blocked(f"{job_id}: accepted skip artifact schema is invalid")
    binding = {"job_id":job_id, "attempt_id":pointer["attempt_id"], "artifact_path":artifact,
        "artifact_sha256":HASH + file_hash(attempt / artifact),
        "accepted_pointer_sha256":HASH + file_hash(base / "accepted.json")}
    return value, binding, attempt


def _optional_current(run_id: str, job_id: str) -> tuple[dict[str, Any], dict[str, Any], Path] | None:
    root = data_path(run_id, "jobs", job_id)
    if not root.exists():
        return None
    return _current(run_id, job_id)


def _disposition(run_id: str, job_id: str) -> dict[str, Any]:
    base = _accepted_base(run_id, job_id); pointer = read_json(base / "accepted.json")
    attempt = base / "attempts" / pointer["attempt_id"]
    envelope = read_json(attempt / "result.json")
    return {"execution_status":pointer["status"], "skip_reason":pointer.get("reason"),
            "gaps":envelope["gaps"]}


def _code(job_id: str) -> dict[str, str]:
    contract, _artifact, schema = JOBS[job_id]
    paths = ["control_feature_lifecycle.py", "review_control_loops.py", "publish_job_output.py",
             f"registry/output-contracts/{contract}.json"]
    values = {path: file_hash(ROOT / path) for path in paths}
    values[f"schemas/{schema}"] = file_hash(ROOT.parent / "schemas" / schema)
    if job_id == "final-publication-preparation":
        values["schemas/control-publication-binding.schema.json"] = file_hash(
            ROOT.parent / "schemas" / "control-publication-binding.schema.json")
    return values


def _verified_dispatch(run_id: str) -> tuple[pool_rendezvous.VerifiedManifest, Path, dict[str, Any]]:
    dispatch, binding, attempt = _current(run_id, "persona-tool-pool-dispatch")
    record = read_json(attempt / "pool-context.json")
    context = persona_tool_pool_lifecycle._load_retained_context(record)
    spec_path = context.pool_parent / dispatch["pool_directory"] / "pool-specification.json"
    spec = read_json(spec_path)
    request = read_json(attempt / "deterministic-merge-request.json")
    expected = persona_tool_pool_lifecycle._handoff(
        persona_tool_pool_lifecycle._current_inputs(run_id), attempt, record)
    if request != expected:
        raise Blocked("deterministic merge: retained dispatch request changed")
    rendezvous_parent = Path(record["rendezvous_parent"]).absolute()
    verified = pool_rendezvous.load_verified_manifest(
        context.pool_parent / dispatch["pool_directory"], expected_spec=spec, context=context,
        rendezvous_parent=rendezvous_parent)
    if (verified.manifest["manifest_sha256"] != dispatch["terminal_manifest_sha256"] or
            verified.plan.manifest["expansion_sha256"] != dispatch["expansion_sha256"] or
            len(verified.instances) != dispatch["instance_count"] or verified.outcome != dispatch["outcome"]):
        raise Blocked("deterministic merge: accepted dispatch differs from reverified pool")
    return verified, context.pool_parent / dispatch["pool_directory"], binding


def _graph_index(run_id: str) -> tuple[list[str], list[dict[str, str]]]:
    graph = read_json(ROOT / "job-graph.json")
    jobs = graph.get("jobs")
    if not isinstance(jobs, dict) or "00-intake" not in jobs:
        raise Blocked("dynamic rescope: tracked job graph is invalid")
    nodes = sorted(jobs)
    edges = []
    for downstream, row in jobs.items():
        for dependency in row.get("dependencies", []):
            edges.append({"upstream": dependency["job"], "downstream": downstream})
    return nodes, edges


def _completeness_inputs(report: dict[str, Any], report_sha256: str | None = None) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    expected, observed, gaps = [], [], []
    for finding in report["verified_findings"]:
        oid = f"verified-finding:{finding['claim_id']}:citations"
        expected.append({"obligation_id": oid})
        observed.append({"obligation_id": oid, "evidence_sha256": _sha({
            "citations": finding["citations"], "verification_citations": finding["verification_citations"]})})
    for candidate in report["unresolved_candidates"]:
        for obligation in candidate["proof_obligations"]:
            oid = f"unresolved:{candidate['claim_id']}:{obligation['obligation_id']}"
            expected.append({"obligation_id": oid})
            gaps.append({"obligation_id": oid, "reason": obligation["statement"],
                         "evidence_sha256": _sha(candidate)})
    for limitation in report["limitations"]:
        oid = "limitation:" + digest(limitation)[:24]
        expected.append({"obligation_id": oid})
        gaps.append({"obligation_id": oid, "reason": limitation,
                     "evidence_sha256": report_sha256 or _sha(report)})
    return expected, observed, gaps


def _publication_controls(run_id: str, quorum: dict[str, Any], quorum_binding: dict[str, Any],
                          rescope: dict[str, Any], rescope_binding: dict[str, Any],
                          remediation: dict[str, Any], remediation_binding: dict[str, Any],
                          remediation_disposition: dict[str, Any]
                          ) -> tuple[dict[str, Any], list[str]]:
    """Project exact control evidence and identify states that cannot truthfully be published."""
    if any(value.get("run_id") != run_id for value in (quorum, rescope, remediation)):
        raise Blocked("final publication preparation: control evidence has mixed run identity")
    decisions = quorum.get("decisions", [])
    adverse = sorted(row["candidate_id"] + ":" + row["decision"] for row in decisions
                     if row["decision"] != "ADMITTED")
    blockers = ["quorum:" + value for value in adverse]
    affected = rescope.get("affected_nodes", [])
    final_affected = "final-publication-gate" in affected
    if rescope.get("state") == "RESCOPE_REQUIRED":
        blockers.append("rescope:additional-iteration-required")
    if not final_affected:
        blockers.append("rescope:final-publication-not-covered")
    proposals = {row["proposal_id"]: row for row in remediation.get("proposals", [])}
    retests = remediation.get("retests", [])
    skipped_na = remediation_disposition == {"execution_status":"SKIPPED",
        "skip_reason":"not-applicable-no-verified-claims",
        "gaps":["not-applicable-no-verified-claims"]}
    if not proposals and not retests and not skipped_na:
        blockers.append("remediation:empty-result-is-not-an-accepted-na-skip")
    by_proposal: dict[str, list[dict[str, Any]]] = {}
    for row in retests:
        by_proposal.setdefault(row["proposal_id"], []).append(row)
        proposal = proposals.get(row["proposal_id"])
        if proposal is None or proposal["claim_id"] != row["claim_id"]:
            blockers.append("remediation:orphan-retest:" + row["proposal_id"])
    for proposal_id, proposal in sorted(proposals.items()):
        matches = by_proposal.get(proposal_id, [])
        if proposal["state"] == "AUTHORIZED" and len(matches) != 1:
            blockers.append("remediation:authorized-without-one-retest:" + proposal_id)
        if any(row["state"] != "FIXED" for row in matches):
            blockers.append("remediation:retest-not-fixed:" + proposal_id)
    evidence = {"quorum": {"binding": quorum_binding, "decision_count": len(decisions),
            "admitted_count": sum(row["decision"] == "ADMITTED" for row in decisions)},
        "rescope": {"binding": rescope_binding, "state": rescope["state"],
            "final_publication_affected": final_affected},
        "remediation_retest": {"binding": remediation_binding,
            "proposal_count": len(proposals), "retest_count": len(retests),
            "skipped_not_applicable": skipped_na, "disposition":remediation_disposition}}
    return evidence, sorted(set(blockers))


def current_inputs(run_id: str, job_id: str) -> dict[str, Any]:
    if job_id not in JOBS:
        raise Blocked("control lifecycle: unsupported job")
    generation = _generation(run_id)
    base = {"run_id": run_id, "job_id": job_id, "source_generation": generation, "code": _code(job_id)}
    if job_id == "deterministic-pool-merge":
        _verified, _pool, binding = _verified_dispatch(run_id)
        return {**base, "dispatch": binding}
    if job_id == "evidence-qualified-quorum":
        _merge, binding, _attempt = _current(run_id, "deterministic-pool-merge")
        return {**base, "merge": binding, "minimum_producers": 2, "require_complete_pool": True}
    if job_id == "dynamic-rescope":
        _intake, binding, _attempt = _current(run_id, "00-intake")
        nodes, edges = _graph_index(run_id)
        return {**base, "intake": binding, "nodes": nodes, "edges": edges,
                "changed_nodes": ["00-intake"], "max_iterations": 1}
    if job_id == "completeness-audit":
        report, binding, _attempt = _current(run_id, "10-synthesis-report")
        expected, observed, gaps = _completeness_inputs(report, binding["artifact_sha256"])
        return {**base, "report": binding, "report_sha256": binding["artifact_sha256"],
                "expected": expected, "observed": observed, "declared_gaps": gaps}
    if job_id == "synthetic-hypothesis-resynthesis":
        audit, binding, _attempt = _current(run_id, "completeness-audit")
        routes = {oid: "10-synthesis-report" for oid in audit["missing_ids"]}
        return {**base, "audit": binding, "audit_sha256": _sha(audit), "routes": routes,
                "max_iterations": 1}
    if job_id == "remediation-retest-feedback":
        verification, verified_binding, _attempt = _current(run_id, "09-independent-verification")
        proposal = _optional_current(run_id, "11-remediation-proposal")
        return {**base, "verification": verified_binding,
                "verified_claim_ids": sorted(row["claim_id"] for row in verification["verifications"]
                                             if row["status"] == "VERIFIED"),
                "proposal": proposal[1] if proposal else None}
    report, report_binding, report_attempt = _current(run_id, "10-synthesis-report")
    audit, audit_binding, _ = _current(run_id, "completeness-audit")
    feedback, feedback_binding, _ = _current(run_id, "synthetic-hypothesis-resynthesis")
    _quorum, quorum_binding, _ = _current(run_id, "evidence-qualified-quorum")
    _rescope, rescope_binding, _ = _current(run_id, "dynamic-rescope")
    _remediation, remediation_binding, _ = _current(run_id, "remediation-retest-feedback")
    publication = report_attempt / "publication-manifest.json"
    if publication.is_symlink() or not publication.is_file():
        raise Blocked("final publication preparation: draft publication manifest is absent")
    publication_value = read_json(publication)
    report_records = [row for row in publication_value.get("artifacts", [])
                      if isinstance(row, dict) and row.get("path") == "report.json"]
    if (validate_document(publication_value, "report-publication-manifest.schema.json") or
            len(report_records) != 1 or report_records[0].get("sha256") != report_binding["artifact_sha256"] or
            publication_value.get("run_id") != run_id or publication_value.get("status") != "DRAFT_EVIDENCE_BACKED" or
            publication_value.get("final") is not False or publication_value.get("human_signoff") is not False or
            audit.get("run_id") != run_id or audit.get("subject_sha256") != report_binding["artifact_sha256"] or
            feedback.get("run_id") != run_id or feedback.get("audit_sha256") != _sha(audit)):
        raise Blocked("final publication preparation: draft completion lineage is inconsistent")
    return {**base, "report": report_binding, "audit": audit_binding, "feedback": feedback_binding,
            "quorum": quorum_binding, "rescope": rescope_binding,
            "remediation_retest": remediation_binding,
            "remediation_retest_disposition": _disposition(run_id, "remediation-retest-feedback"),
            "report_sha256": report_binding["artifact_sha256"], "publication_manifest_sha256": HASH + file_hash(publication),
            "draft_attempt": str(report_attempt)}


def _produce(run_id: str, job_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], str, list[str], str | None]:
    if job_id == "deterministic-pool-merge":
        verified, pool_root, _binding = _verified_dispatch(run_id)
        result = deterministic_pool_merge.merge_verified_manifest(verified, pool_root=pool_root, run_id=run_id)
        return result, "OK", [], None
    if job_id == "evidence-qualified-quorum":
        merge, _binding, _attempt = _current(run_id, "deterministic-pool-merge")
        result = evidence_quorum.evidence_qualified_quorum(run_id, merge,
            minimum_producers=inputs["minimum_producers"], require_complete_pool=inputs["require_complete_pool"])
        return result, "OK", [], None
    if job_id == "dynamic-rescope":
        index = dynamic_rescope.dependency_index(run_id, inputs["nodes"], inputs["edges"])
        result = dynamic_rescope.bounded_rescope(run_id, index, inputs["changed_nodes"], iteration=1,
            max_iterations=inputs["max_iterations"]); result["dependency_index"] = index
        return result, "OK_WITH_GAPS", ["initial-intake-change-rescopes-current-graph"], None
    if job_id == "completeness-audit":
        result = completeness_audit.completeness_audit(run_id, inputs["expected"], inputs["observed"],
            inputs["declared_gaps"], subject_sha256=inputs["report_sha256"])
        status = "OK" if result["complete"] else "OK_WITH_GAPS"
        return result, status, result["missing_ids"] + result["false_gap_ids"], None
    if job_id == "synthetic-hypothesis-resynthesis":
        audit, _binding, _attempt = _current(run_id, "completeness-audit")
        result = synthetic_hypothesis_resynthesis.synthetic_feedback(run_id, audit, inputs["routes"],
            iteration=1, max_iterations=inputs["max_iterations"])
        status = "OK" if result["terminal_state"] == "COMPLETE" else "OK_WITH_GAPS"
        return result, status, result["unresolved_obligation_ids"], None
    if job_id == "remediation-retest-feedback":
        verification, _binding, _attempt = _current(run_id, "09-independent-verification")
        verified = {row["claim_id"] for row in verification["verifications"] if row["status"] == "VERIFIED"}
        proposal = _optional_current(run_id, "11-remediation-proposal")
        if proposal:
            source = proposal[0]
            if any(row["claim_id"] not in verified for row in source["proposals"]):
                raise Blocked("remediation feedback: proposal is not bound to a current verified claim")
            result = {"schema":"appsec-review/remediation-retest-feedback/1.0", "run_id":run_id,
                "proposals":[{"proposal_id":row["proposal_id"], "claim_id":row["claim_id"],
                    "state":"PROPOSED", "author_id":"11-remediation-proposal",
                    "change_ref":row["proposal_id"], "rationale":row["remediation_objective"],
                    "target_components":row["component_ids"], "fixed":False}
                    for row in source["proposals"]], "retests":[]}
            return result, "OK_WITH_GAPS", [
                "No authorized target change exists; same-environment retesting has not run."], None
        result = {"schema":"appsec-review/remediation-retest-feedback/1.0", "run_id":run_id,
                  "proposals":[], "retests":[]}
        if not verified:
            return result, "SKIPPED", ["not-applicable-no-verified-claims"], "not-applicable-no-verified-claims"
        return result, "OK_WITH_GAPS", ["verified-claims-have-no-retained-remediation-proposal"], None
    report, _report_binding, _report_attempt = _current(run_id, "10-synthesis-report")
    audit, _audit_binding, _ = _current(run_id, "completeness-audit")
    feedback, _feedback_binding, _ = _current(run_id, "synthetic-hypothesis-resynthesis")
    quorum, quorum_binding, _ = _current(run_id, "evidence-qualified-quorum")
    rescope, rescope_binding, _ = _current(run_id, "dynamic-rescope")
    remediation, remediation_binding, _ = _current(run_id, "remediation-retest-feedback")
    if (audit.get("subject_sha256") != inputs["report_sha256"] or feedback.get("audit_sha256") != _sha(audit)):
        raise Blocked("final publication preparation: accepted completion evidence has mixed lineage")
    controls, control_blockers = _publication_controls(run_id, quorum, quorum_binding,
        rescope, rescope_binding, remediation, remediation_binding,
        inputs["remediation_retest_disposition"])
    if any(inputs[name] != binding for name, binding in
           (("quorum",quorum_binding), ("rescope",rescope_binding),
            ("remediation_retest",remediation_binding))):
        raise Blocked("final publication preparation: accepted control bindings changed")
    if control_blockers:
        raise Blocked("final publication preparation: control evidence has unresolved blockers (" +
                      ", ".join(control_blockers) + ")")
    gate = completion_gate(run_id, report, audit, feedback, None,
                           draft_report_sha256=inputs["report_sha256"])
    if gate["blockers"] != ["human_signoff_missing"]:
        raise Blocked("final publication preparation: completion evidence has unresolved blockers")
    result = {"schema":"appsec-review/final-publication-preparation/1.0", "run_id":run_id,
        "status":"PENDING_HUMAN_APPROVAL", "draft_report_sha256":inputs["report_sha256"],
        "draft_publication_manifest_sha256":inputs["publication_manifest_sha256"],
        "completion_gate":gate, "control_evidence":controls, "draft_attempt":inputs["draft_attempt"],
        "required_action":"A named human reviewer must approve the exact draft report hash using the authorized append-only signoff workflow."}
    return result, "OK_WITH_GAPS", ["human-signoff-required"], None


def _receipts(run_id: str, job_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema":"appsec-review/producer-permission-receipt/1.0", "run_id":run_id,
        "job_id":job_id, "source_snapshot_sha256":inputs["source_generation"],
        "permissions":["read-run-data", "write-run-data"]}
    lineage = {"schema":"appsec-review/producer-lineage-receipt/1.0", "run_id":run_id,
        "job_id":job_id, "source_snapshot_sha256":inputs["source_generation"],
        "build_lineage_sha256":_sha(inputs)}
    return permission, lineage


def _validate_attempt(run_id: str, job_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or current_inputs(run_id, job_id) != inputs:
        raise Blocked(f"{job_id}: immutable lifecycle inputs are stale")
    expected, _status, _gaps, _skip = _produce(run_id, job_id, inputs)
    result = read_json(attempt / JOBS[job_id][1])
    if result != expected or validate_document(result, JOBS[job_id][2]):
        raise Blocked(f"{job_id}: retained result differs from newest accepted inputs")
    if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json")) != _receipts(run_id, job_id, inputs):
        raise Blocked(f"{job_id}: retained permission or lineage receipt changed")


def run(run_id: str, dagster_run_id: str, job_id: str, force: bool = False) -> dict[str, Any]:
    if job_id not in JOBS:
        raise Blocked("control lifecycle: unsupported job")
    contract, result_name, _schema = JOBS[job_id]
    base = data_path(run_id, "jobs", job_id)
    def execute(allocation, inputs, fingerprint):
        if current_inputs(run_id, job_id) != inputs:
            raise Blocked(f"{job_id}: inputs changed before execution")
        result, status, gaps, skip = _produce(run_id, job_id, inputs)
        attempt = allocation["attempt"]
        atomic_json(attempt / result_name, result)
        permission, lineage = _receipts(run_id, job_id, inputs)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        status_doc = {"process":job_id, "status":status, "result":result_name,
                      "claim_limit":"CONTROL_DECISION_ONLY"}
        if job_id == "final-publication-preparation":
            status_doc = {"status":"PENDING_HUMAN_APPROVAL", "final":False, "human_signoff":False,
                          "process":job_id, "result":result_name}
        atomic_json(attempt / "status.json", status_doc)
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job_id,
            dagster_run_id=dagster_run_id, worker_kind="deterministic_python", output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status=status,
            summary=f"{job_id} published from newest accepted upstream evidence",
            status_record=status_doc, artifact_paths=[result_name,"permission.json","lineage.json","status.json"],
            gaps=gaps, skip_reason=skip,
            pre_envelope_validate=lambda path,_record:_validate_attempt(run_id,job_id,path,inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job_id,
        dagster_run_id=dagster_run_id, worker_kind="deterministic_python", output_contract=contract,
        resume_command=f"control_feature_lifecycle:{job_id}", derive_inputs=lambda:current_inputs(run_id,job_id),
        fingerprint_inputs=_sha, execute_attempt=execute,
        preflight_failure_inputs=lambda exc:{"run_id":run_id,"job_id":job_id,
            "error":f"{type(exc).__name__}: {exc}","code":_code(job_id)},
        post_validate=lambda attempt,_envelope,inputs:_validate_attempt(run_id,job_id,attempt,inputs),
        force=force, blocked_summary=f"{job_id} preflight blocked",
        failed_summary=f"{job_id} execution failed")


def validate(run_id: str, job_id: str) -> Path:
    inputs = current_inputs(run_id, job_id); base = data_path(run_id, "jobs", job_id)
    attempt, _ = validate_published(base, read_json(base / "accepted.json"), _sha(inputs),
        expected_run_id=run_id, expected_job_id=job_id)
    _validate_attempt(run_id, job_id, attempt, inputs)
    return attempt
