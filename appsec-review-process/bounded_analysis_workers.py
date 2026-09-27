"""Closed, deterministic workers for previously planned analysis and standards lanes.

These workers transform already accepted, hash-bound evidence.  They never execute a target,
invent tool output, or promote static evidence to a finding, runtime observation, compliance
verdict, or fuzzing result.  ``publish_attempt`` supplies the common immutable envelope and a
canonical producer permission receipt for standalone qualification and later orchestration.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any, Callable

from execution_state import Blocked, atomic_json, digest, file_hash, read_json, tree_hashes
from publish_job_output import ACCEPTED_SCHEMA
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope, validate_immutable_reuse, validate_worker_result

HASH = "sha256:"
PERMISSIONS = ["read-run-data", "write-run-data"]
JOBS = {
    "05-native-memory": ("native-memory-analysis.json", "native-memory-analysis.schema.json", "native-memory-analysis"),
    "13-fuzz-target-triage": ("fuzz-target-triage.json", "fuzz-target-triage.schema.json", "fuzz-target-triage"),
    "04-owasp-validation-worklist": ("owasp-validation-worklist.json", "owasp-validation-worklist-core.schema.json", "owasp-validation-worklist"),
    "15-stig-srg-validation-worklist": ("stig-srg-validation-worklist.json", "stig-srg-validation-worklist.schema.json", "stig-srg-validation-worklist"),
    "15-deployment-hardening": ("deployment-hardening.json", "deployment-hardening.schema.json", "deployment-hardening"),
}


def load_accepted(pointer_path: Path, *, run_id: str, job_id: str, contract: str,
                  artifact: str, schema: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one exact newest accepted common-envelope artifact with full hash re-verification."""
    pointer_path=Path(pointer_path); base=pointer_path.parent
    if base.is_symlink() or not base.is_dir() or pointer_path.is_symlink() or not pointer_path.is_file():
        raise Blocked("bounded analysis: accepted pointer root is unsafe")
    pointer=read_json(pointer_path)
    keys={"schema","status","run_id","job","attempt_id","fingerprint","envelope_path","envelope_sha256","hashes","accepted_at"}
    if (set(pointer)!=keys or pointer.get("schema")!=ACCEPTED_SCHEMA or pointer.get("status") not in {"OK","OK_WITH_GAPS"}
            or pointer.get("run_id")!=run_id or pointer.get("job")!=job_id or pointer.get("envelope_path")!="result.json"):
        raise Blocked("bounded analysis: accepted pointer identity is invalid")
    latest=read_json(base/"latest.json")
    if latest.get("attempt_id")!=pointer["attempt_id"]: raise Blocked("bounded analysis: accepted pointer is stale")
    attempt=base/"attempts"/pointer["attempt_id"]
    if attempt.is_symlink() or not attempt.is_dir() or tree_hashes(attempt)!=pointer["hashes"]:
        raise Blocked("bounded analysis: accepted attempt tree is invalid")
    envelope_path=attempt/"result.json"; envelope=read_json(envelope_path)
    if (file_hash(envelope_path)!=pointer["envelope_sha256"] or validate_worker_result(envelope) or
            envelope.get("run_id")!=run_id or envelope.get("job_id")!=job_id or
            envelope.get("attempt_id")!=pointer["attempt_id"] or envelope.get("input_fingerprint")!=pointer["fingerprint"] or
            envelope.get("output_contract")!=contract or envelope.get("acceptance_status")!="CURRENT"):
        raise Blocked("bounded analysis: accepted envelope is invalid")
    artifacts={row.get("path"):row for row in envelope.get("artifacts",[])}
    if len(artifacts)!=len(envelope.get("artifacts",[])) or artifact not in artifacts:
        raise Blocked("bounded analysis: accepted artifact is absent or duplicated")
    for relative,row in artifacts.items():
        path=attempt.joinpath(*PurePosixPath(relative).parts)
        try: path.resolve(strict=True).relative_to(attempt.resolve())
        except (OSError,ValueError) as exc: raise Blocked("bounded analysis: artifact escapes attempt") from exc
        if path.is_symlink() or not path.is_file() or file_hash(path)!=row.get("sha256"):
            raise Blocked("bounded analysis: artifact hash is invalid")
    document=read_json(attempt/artifact)
    if validate_document(document,schema): raise Blocked("bounded analysis: accepted artifact schema is invalid")
    binding={"job_id":job_id,"attempt_id":pointer["attempt_id"],"artifact_path":artifact,
             "artifact_sha256":"sha256:"+file_hash(attempt/artifact),
             "accepted_pointer_sha256":"sha256:"+file_hash(pointer_path)}
    return document,binding


def _sha(value: Any) -> str:
    return HASH + digest(value)


def _closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise Blocked(f"{label}: input shape is not closed")
    return value


def _binding(value: dict[str, Any]) -> dict[str, Any]:
    keys = {"job_id", "attempt_id", "artifact_path", "artifact_sha256", "accepted_pointer_sha256"}
    _closed(value, keys, "analysis binding")
    for key in ("artifact_sha256", "accepted_pointer_sha256"):
        if not isinstance(value[key], str) or not value[key].startswith(HASH) or len(value[key]) != 71:
            raise Blocked("analysis binding: invalid digest")
    if any(not isinstance(value[key], str) or not value[key] for key in keys - {"artifact_sha256", "accepted_pointer_sha256"}):
        raise Blocked("analysis binding: invalid identity")
    return value


def _citations(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        raise Blocked("analysis: citations must be a list")
    result, seen = [], {}
    keys = {"citation_id", "artifact_path", "artifact_sha256", "locator", "observed_fact"}
    for item in values:
        _closed(item, keys, "analysis citation")
        if (not item["citation_id"] or not item["observed_fact"] or
                not item["artifact_sha256"].startswith(HASH) or len(item["artifact_sha256"]) != 71):
            raise Blocked("analysis citation: identity, fact, or digest is invalid")
        prior = seen.setdefault(item["citation_id"], item)
        if prior != item:
            raise Blocked("analysis citation: one id names contradictory evidence")
        if prior is item:
            result.append(item)
    if len(result) != len(seen):
        raise Blocked("analysis citation: duplicate identity")
    return sorted(result, key=lambda row: row["citation_id"])


def _base(schema: str, job: str, run_id: str, attempt_id: str, generation: str,
          bindings: list[dict[str, Any]]) -> dict[str, Any]:
    if not generation.startswith(HASH) or len(generation) != 71:
        raise Blocked(f"{job}: source generation is invalid")
    checked = [_binding(row) for row in bindings]
    identities = [(row["job_id"], row["attempt_id"], row["artifact_path"]) for row in checked]
    if not checked or len(identities) != len(set(identities)):
        raise Blocked(f"{job}: accepted evidence bindings are absent or duplicated")
    return {"schema": schema, "run_id": run_id, "job_id": job, "attempt_id": attempt_id,
            "source_generation": generation, "upstream": sorted(checked, key=lambda row:
                (row["job_id"], row["attempt_id"], row["artifact_path"]))}


def native_memory(*, run_id: str, attempt_id: str, source_generation: str,
                  bindings: list[dict[str, Any]], units: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive cited native-memory candidates and explicit coverage; never host verification."""
    rows, coverage, obligations = [], [], []
    unit_keys = {"unit_id", "language", "path", "source_sha256", "signals", "coverage", "citations"}
    signal_keys = {"signal_id", "kind", "statement", "line"}
    for unit in units:
        _closed(unit, unit_keys, "native memory unit")
        if unit["language"] not in {"c", "cpp", "objective-c", "objective-cpp"}:
            raise Blocked("native memory: unsupported language cannot be represented as analyzed")
        cites = _citations(unit["citations"])
        citation_ids = [row["citation_id"] for row in cites]
        if not cites or not isinstance(unit["coverage"], list) or not unit["coverage"]:
            raise Blocked("native memory: each unit needs citations and coverage")
        coverage.append({"unit_id": unit["unit_id"], "path": unit["path"],
                         "source_sha256": unit["source_sha256"], "modes": sorted(set(unit["coverage"])),
                         "host_verification": False})
        for signal in unit["signals"]:
            _closed(signal, signal_keys, "native memory signal")
            if signal["kind"] not in {"bounds", "lifetime", "initialization", "ownership", "arithmetic"}:
                raise Blocked("native memory: unknown signal kind")
            key = {"unit_id": unit["unit_id"], **signal, "citation_ids": citation_ids}
            candidate_id = "mem-" + digest(key)[:20]
            obligation_id = "obl-" + digest((candidate_id, "independent-runtime-or-code-proof"))[:20]
            rows.append({"candidate_id": candidate_id, **key, "claim_class": "candidate_only",
                         "host_verified": False, "proof_obligation_ids": [obligation_id]})
            obligations.append({"obligation_id": obligation_id, "candidate_id": candidate_id,
                "statement": "Independently establish reachability and memory-safety impact in the bound target environment.",
                "status": "OPEN", "citation_ids": citation_ids})
    result = {**_base("appsec-review/native-memory-analysis/1.0", "05-native-memory", run_id,
                      attempt_id, source_generation, bindings),
              "status": "OK_WITH_GAPS", "candidates": sorted(rows, key=lambda row: row["candidate_id"]),
              "coverage": sorted(coverage, key=lambda row: row["unit_id"]),
              "proof_obligations": sorted(obligations, key=lambda row: row["obligation_id"]),
              "gaps": ["Host/runtime verification was not performed; every candidate remains candidate_only."],
              "claim_limits": {"finding_created": False, "severity_assigned": False,
                               "runtime_claimed": False, "compliance_claimed": False}}
    return _validate(result, "native-memory-analysis.schema.json")


def fuzz_triage(*, run_id: str, attempt_id: str, source_generation: str,
                bindings: list[dict[str, Any]], targets: list[dict[str, Any]]) -> dict[str, Any]:
    keys = {"target_id", "component_id", "entrypoint", "input_model", "buildable", "deterministic",
            "isolation", "blockers", "citation_ids"}
    ranked = []
    for row in targets:
        _closed(row, keys, "fuzz target")
        if not row["citation_ids"] or len(row["citation_ids"]) != len(set(row["citation_ids"])):
            raise Blocked("fuzz triage: target citations are absent or duplicated")
        score = sum((4 if row["buildable"] else 0, 3 if row["deterministic"] else 0,
                     2 if row["input_model"] != "unknown" else 0, 1 if row["isolation"] != "unknown" else 0))
        feasibility = "ready" if score >= 9 and not row["blockers"] else "blocked" if row["blockers"] else "needs_design"
        ranked.append({**row, "feasibility": feasibility, "score": score,
                       "fuzz_execution": "NOT_PERFORMED", "finding_created": False})
    ranked.sort(key=lambda row: (-row["score"], row["target_id"]))
    for index, row in enumerate(ranked, 1): row["rank"] = index
    result = {**_base("appsec-review/fuzz-target-triage/1.0", "13-fuzz-target-triage", run_id,
                      attempt_id, source_generation, bindings), "status": "OK_WITH_GAPS",
              "targets": ranked, "gaps": ["No fuzz campaign or runtime execution was performed."],
              "claim_limits": {"fuzz_executed": False, "crash_observed": False,
                               "finding_created": False, "severity_assigned": False}}
    return _validate(result, "fuzz-target-triage.schema.json")


def standards_worklist(*, family: str, run_id: str, attempt_id: str, source_generation: str,
                       bindings: list[dict[str, Any]], controls: list[dict[str, Any]]) -> dict[str, Any]:
    jobs = {"owasp": ("04-owasp-validation-worklist", "appsec-review/owasp-validation-worklist-core/1.0", "owasp-validation-worklist-core.schema.json"),
            "stig_srg": ("15-stig-srg-validation-worklist", "appsec-review/stig-srg-validation-worklist/1.0", "stig-srg-validation-worklist.schema.json")}
    if family not in jobs: raise Blocked("standards worklist: unknown family")
    keys = {"control_id", "standard_family", "standard_version", "target_id", "applicability",
            "tailoring", "evidence_mode", "citation_ids", "gaps"}
    rows = []
    for control in controls:
        _closed(control, keys, "standards work item")
        expected_family = "OWASP" if family == "owasp" else "DISA_STIG_SRG"
        if control["standard_family"] != expected_family:
            raise Blocked("standards worklist: control family is mixed")
        if control["applicability"] not in {"applicable", "conditional", "not_applicable", "cannot_determine"}:
            raise Blocked("standards worklist: applicability is invalid")
        if control["evidence_mode"] not in {"static", "runtime", "hybrid", "manual"}:
            raise Blocked("standards worklist: evidence mode is invalid")
        if control["evidence_mode"] in {"runtime", "hybrid"} and not any("runtime" in gap.lower() for gap in control["gaps"]):
            raise Blocked("standards worklist: runtime evidence requirement must remain an explicit gap")
        item = {**control, "work_item_id": "work-" + digest(control)[:20],
                "assessment_status": "NOT_ASSESSED", "finding_created": False,
                "compliance_claimed": False}
        rows.append(item)
    job, schema_id, schema_file = jobs[family]
    result = {**_base(schema_id, job, run_id,
                      attempt_id, source_generation, bindings), "family": family,
              "status": "OK_WITH_GAPS" if any(row["gaps"] for row in rows) else "OK",
              "work_items": sorted(rows, key=lambda row: row["work_item_id"]),
              "gaps": sorted({gap for row in rows for gap in row["gaps"]}),
              "claim_limits": {"finding_created": False, "control_satisfied": False,
                               "compliance_claimed": False}}
    return _validate(result, schema_file)


def deployment_hardening(*, run_id: str, attempt_id: str, source_generation: str,
                         bindings: list[dict[str, Any]], targets: list[dict[str, Any]]) -> dict[str, Any]:
    keys = {"target_id", "platform", "control_id", "standard_family", "standard_version",
            "applicability", "tailoring", "static_state", "citation_ids", "runtime_gaps"}
    rows = []
    for target in targets:
        _closed(target, keys, "deployment target")
        if not target["citation_ids"] or not target["runtime_gaps"]:
            raise Blocked("deployment hardening: static evidence and runtime gaps are required")
        rows.append({**target, "assessment_id": "hardening-" + digest(target)[:20],
                     "assessment_status": "STATIC_EVIDENCE_ONLY", "runtime_observed": False,
                     "finding_created": False, "compliance_claimed": False})
    result = {**_base("appsec-review/deployment-hardening/1.0", "15-deployment-hardening", run_id,
                      attempt_id, source_generation, bindings), "status": "OK_WITH_GAPS",
              "assessments": sorted(rows, key=lambda row: row["assessment_id"]),
              "gaps": sorted({gap for row in rows for gap in row["runtime_gaps"]}),
              "claim_limits": {"finding_created": False, "runtime_claimed": False,
                               "control_satisfied": False, "compliance_claimed": False}}
    return _validate(result, "deployment-hardening.schema.json")


def _validate(value: dict[str, Any], schema: str) -> dict[str, Any]:
    errors = validate_document(value, schema)
    if errors: raise Blocked(f"bounded analysis: output schema failed ({errors[0]})")
    return value


def permission_receipt(result: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": result["run_id"],
            "job_id": result["job_id"], "source_snapshot_sha256": result["source_generation"],
            "permissions": PERMISSIONS}


def lineage_receipt(result: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": result["run_id"],
            "job_id": result["job_id"], "source_snapshot_sha256": result["source_generation"],
            "build_lineage_sha256": _sha(result["upstream"])}


def publish_attempt(root: Path, result: dict[str, Any], *, started_at: str, finished_at: str) -> dict[str, Any]:
    """Write or exactly reuse one immutable standalone common-envelope attempt."""
    job = result["job_id"]
    if job not in JOBS: raise Blocked("bounded analysis: unknown job")
    artifact, schema, contract = JOBS[job]
    _validate(result, schema)
    attempt = Path(root) / "attempts" / result["attempt_id"]
    fingerprint = _sha({"upstream": result["upstream"], "source_generation": result["source_generation"]})
    if attempt.exists():
        envelope = read_json(attempt / "result.json")
        candidate = read_json(attempt / "result.json")
        declared = {item.get("path"): item.get("sha256") for item in envelope.get("artifacts", [])}
        expected_paths = {artifact, "permission-receipt.json", "lineage-receipt.json", "status.json"}
        hashes_valid = (set(declared) == expected_paths and all(
            (attempt / path).is_file() and not (attempt / path).is_symlink() and
            file_hash(attempt / path) == declared[path] for path in expected_paths))
        if (validate_worker_result(envelope) or validate_immutable_reuse(envelope, candidate) or
                envelope.get("input_fingerprint") != fingerprint or
                envelope.get("output_contract") != contract or not hashes_valid or
                read_json(attempt / artifact) != result or
                read_json(attempt / "permission-receipt.json") != permission_receipt(result) or
                read_json(attempt / "lineage-receipt.json") != lineage_receipt(result)):
            raise Blocked("bounded analysis: immutable attempt cannot be reused")
        return envelope
    attempt.mkdir(parents=True)
    atomic_json(attempt / artifact, result)
    atomic_json(attempt / "permission-receipt.json", permission_receipt(result))
    atomic_json(attempt / "lineage-receipt.json", lineage_receipt(result))
    gaps = result["gaps"]
    status = result["status"]
    atomic_json(attempt / "status.json", {"process": job, "status": status,
                "records": len(result.get("candidates", result.get("targets", result.get("work_items", result.get("assessments", []))))),
                "qualification": "implemented_not_qualified"})
    paths = [artifact, "permission-receipt.json", "lineage-receipt.json", "status.json"]
    envelope = terminal_envelope(run_id=result["run_id"], job_id=job, attempt_id=result["attempt_id"],
        worker_kind="deterministic_python", execution_status=status, acceptance_status="CURRENT",
        input_fingerprint=fingerprint, output_contract=contract, started_at=started_at,
        finished_at=finished_at, summary=f"{job} produced bounded evidence", artifacts=artifact_records(attempt, paths), gaps=gaps)
    if validate_worker_result(envelope): raise Blocked("bounded analysis: common envelope is invalid")
    atomic_json(attempt / "result.json", envelope)
    return envelope
