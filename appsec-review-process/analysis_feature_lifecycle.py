"""Zero-config lifecycle workers for native-memory, CVE reachability and fuzz triage."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

import automatic_evidence_inputs as automatic
import bounded_analysis_workers as bounded
import dependency_workers
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json, run_path
import ir_evidence
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
from worker_result import validate_worker_result

JOBS = {
    "05-native-memory": ("native-memory-analysis", "native-memory-analysis.json", "native-memory-analysis.schema.json"),
    "06-cve-reachability": ("cve-reachability", "outputs/cve-reachability.json", "cve-reachability.schema.json"),
    "13-fuzz-target-triage": ("fuzz-target-triage", "fuzz-target-triage.json", "fuzz-target-triage.schema.json"),
}
ASSEMBLY = ("02-full-review-input-assembly", "full-review-input-assembly",
            "full-review-input-assembly.json", "full-review-input-assembly.schema.json")
SKIPS = {"05-native-memory": "not-applicable-no-routed-native-unit",
         "13-fuzz-target-triage": "not-applicable-no-fuzz-target"}
CONSUMER = {"05-native-memory": "07-red-team-adversarial",
            "06-cve-reachability": "07-red-team-adversarial",
            "13-fuzz-target-triage": "07-red-team-adversarial"}
APPLICABILITY = "applicability-receipt.json"


def _sha(value: Any) -> str: return "sha256:" + digest(value)


def _code(job: str) -> dict[str, str]:
    paths = ["analysis_feature_lifecycle.py", "bounded_analysis_workers.py",
             "dependency_workers.py", "publish_job_output.py",
             {"05-native-memory":"native_memory_analysis.py","06-cve-reachability":"cve_reachability.py",
              "13-fuzz-target-triage":"fuzz_target_triage.py"}[job],
             f"registry/job-templates/{job}.json", f"registry/output-contracts/{JOBS[job][0]}.json"]
    values = {path: file_hash(ROOT / path) for path in paths}
    values["schemas/" + JOBS[job][2]] = file_hash(ROOT.parent / "schemas" / JOBS[job][2])
    values["schemas/analysis-applicability-receipt.schema.json"] = file_hash(
        ROOT.parent / "schemas/analysis-applicability-receipt.schema.json")
    return values


def _assembly(run_id: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    pointer = data_path(run_id, "jobs", ASSEMBLY[0], "accepted.json")
    document, binding = bounded.load_accepted(pointer, run_id=run_id, job_id=ASSEMBLY[0],
        contract=ASSEMBLY[1], artifact=ASSEMBLY[2], schema=ASSEMBLY[3])
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file() or manifest.is_symlink() or document["source_generation"] != "sha256:" + file_hash(manifest):
        raise Blocked("analysis lifecycle: accepted assembly source generation is stale")
    attempt = pointer.parent / "attempts" / binding["attempt_id"]
    return document, binding, attempt


def _bounded_inputs(run_id: str, job: str) -> dict[str, Any]:
    assembly, assembly_binding, attempt = _assembly(run_id)
    requests = [row for row in assembly["requests"] if row["job_id"] == job]
    skipped = [row for row in assembly["skipped"] if row["job_id"] == job]
    if len(requests) + len(skipped) != 1:
        raise Blocked(f"{job}: accepted assembly must account for the feature exactly once")
    if skipped:
        source = skipped[0]
        if source.get("status") != "SKIPPED_NA" or not isinstance(source.get("reason"), str) or not source["reason"]:
            raise Blocked(f"{job}: assembly skip decision is not evidence-supported")
        return {"run_id": run_id, "job_id": job, "source_generation": assembly["source_generation"],
            "assembly": assembly_binding, "mode": "SKIPPED_NA", "reason": SKIPS[job],
            "applicability": {"source_status": source["status"], "source_reason": source["reason"],
                              "source_sha256": _sha(source)},
            "bindings": [assembly_binding], "payload": [], "code": _code(job)}
    row = requests[0]; request_path = attempt.joinpath(*PurePosixPath(row["path"]).parts)
    if (not request_path.is_file() or request_path.is_symlink() or
            row["sha256"] != "sha256:" + file_hash(request_path)):
        raise Blocked(f"{job}: accepted assembly request changed")
    request = read_json(request_path)
    payload_name = "units" if job == "05-native-memory" else "targets"
    if (request.get("run_id") != run_id or request.get("job_id") != job or
            request.get("source_generation") != assembly["source_generation"] or
            not isinstance(request.get("upstream"), list) or
            not isinstance(request.get("payload"), dict) or set(request["payload"]) != {payload_name}):
        raise Blocked(f"{job}: accepted assembly request is invalid")
    bindings = []
    for item in request["upstream"]:
        _, binding = bounded.load_accepted(Path(item["pointer_path"]), run_id=run_id,
            job_id=item["job_id"], contract=item["contract"], artifact=item["artifact"], schema=item["schema"])
        bindings.append(binding)
    return {"run_id": run_id, "job_id": job, "source_generation": assembly["source_generation"],
        "assembly": assembly_binding, "mode": "EXECUTE", "reason": None,
        "applicability": {"source_status": "REQUESTED",
                          "source_reason": f"accepted assembly routed {len(request['payload'][payload_name])} item(s)",
                          "source_sha256": row["sha256"]},
        "bindings": bindings, "payload": request["payload"][payload_name], "code": _code(job)}


def _applicability(run_id: str, job: str, inputs: dict[str, Any]) -> dict[str, Any]:
    if job == "06-cve-reachability":
        binding = inputs["sca"]
        evidence = {"producer_job_id":"02-sca-vulnerability-match",
            "producer_attempt_id":binding["attempt_id"], "artifact_sha256":binding["sha256"],
            "accepted_pointer_sha256":"sha256:" + file_hash(Path(binding["accepted_path"]))}
        return {"schema":"appsec-review/analysis-applicability-receipt/1.0", "run_id":run_id,
            "job_id":job, "decision":"APPLICABLE", "reason":None,
            "rationale":"Accepted SCA evidence is present; an empty match set remains an executed analysis result.",
            "source_generation":inputs["source_generation"], "evidence":evidence}
    binding = inputs["assembly"]
    decision = "SKIPPED_NA" if inputs["mode"] == "SKIPPED_NA" else "APPLICABLE"
    return {"schema":"appsec-review/analysis-applicability-receipt/1.0", "run_id":run_id,
        "job_id":job, "decision":decision, "reason":inputs["reason"] if decision == "SKIPPED_NA" else None,
        "rationale":inputs["applicability"]["source_reason"], "source_generation":inputs["source_generation"],
        "evidence":{"producer_job_id":ASSEMBLY[0], "producer_attempt_id":binding["attempt_id"],
            "artifact_sha256":binding["artifact_sha256"],
            "accepted_pointer_sha256":binding["accepted_pointer_sha256"]}}


def _sca(run_id: str) -> tuple[dict[str, Any], dict[str, str], str]:
    binding, _ = automatic._accepted_binding(run_id, "02-sca-vulnerability-match")
    pointer = Path(binding["accepted_path"]); base = pointer.parent
    latest = base / "latest.json"
    if latest.is_file() and read_json(latest).get("attempt_id") != binding["attempt_id"]:
        raise Blocked("06-cve-reachability: newest SCA attempt is not the accepted success")
    result = read_json(Path(binding["path"]))
    if validate_document(result, "sca-vulnerability-match.schema.json"):
        raise Blocked("06-cve-reachability: accepted SCA result is invalid")
    envelope = read_json(base / "attempts" / binding["attempt_id"] / "result.json")
    return result, binding, envelope["finished_at"]


def _optional_ir(run_id: str, source: str) -> dict[str, Any] | None:
    base = data_path(run_id, "jobs", "02-ir-facts")
    if not base.exists(): return None
    try: attempt = ir_evidence.validate(run_id, "02-ir-facts")
    except Exception as exc: raise Blocked("06-cve-reachability: present IR facts are not current accepted evidence") from exc
    result = read_json(attempt / "ir-facts.json")
    if result["source_snapshot_sha256"] != source:
        raise Blocked("06-cve-reachability: IR facts and SCA have mixed source lineage")
    return {"job_id":"02-ir-facts","attempt_id":attempt.name,"artifact_path":"ir-facts.json",
            "artifact_sha256":"sha256:" + file_hash(attempt / "ir-facts.json"),
            "accepted_pointer_sha256":"sha256:" + file_hash(base / "accepted.json")}


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    if job not in JOBS: raise Blocked("analysis lifecycle: unsupported job")
    if job != "06-cve-reachability": return _bounded_inputs(run_id, job)
    sca, binding, generated = _sca(run_id)
    _tree, source_binding, _files = automatic.source_projection(run_id)
    source = sca["source_snapshot_sha256"]
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if source != "sha256:" + file_hash(manifest):
        raise Blocked("06-cve-reachability: accepted SCA source generation is stale")
    return {"run_id":run_id,"job_id":job,"source_generation":source,"sca":binding,
        "sca_matches_sha256":_sha(sca["matches"]),"source_binding":source_binding,
        "ir":_optional_ir(run_id, source),"generated_at":generated,"code":_code(job)}


def _receipts(run_id: str, job: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission={"schema":"appsec-review/producer-permission-receipt/1.0","run_id":run_id,"job_id":job,
        "source_snapshot_sha256":inputs["source_generation"],"permissions":["read-run-data","write-run-data"]}
    lineage={"schema":"appsec-review/producer-lineage-receipt/1.0","run_id":run_id,"job_id":job,
        "source_snapshot_sha256":inputs["source_generation"],"build_lineage_sha256":_sha(inputs)}
    return permission,lineage


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt/"inputs.json") != inputs or current_inputs(run_id,job) != inputs:
        raise Blocked(f"{job}: immutable lifecycle inputs are stale")
    result=read_json(attempt.joinpath(*PurePosixPath(JOBS[job][1]).parts))
    if validate_document(result,JOBS[job][2]) or result.get("run_id")!=run_id or result.get("job_id")!=job:
        raise Blocked(f"{job}: retained result is invalid")
    if job=="06-cve-reachability":
        evidence=attempt/"automatic-reachability-evidence.json"
        if read_json(evidence)!={"assessments":[]}:
            raise Blocked(f"{job}: automatic evidence input changed")
        request={"run_id":run_id,"source_snapshot_sha256":inputs["source_generation"],
            "generated_at":inputs["generated_at"],"output_root":str(data_path(run_id,"jobs")),
            "sca":inputs["sca"],"reachability_evidence":str(evidence),
            "reachability_evidence_sha256":"sha256:" + file_hash(evidence)}
        expected,_gaps=dependency_workers.build_reachability(request,attempt.name)
        for relative,payload in expected.items():
            path=attempt.joinpath(*PurePosixPath(relative).parts)
            if not path.is_file() or path.is_symlink() or path.read_bytes()!=payload:
                raise Blocked(f"{job}: retained result differs from automatic accepted inputs")
    if (read_json(attempt/"permission-receipt.json"),read_json(attempt/"lineage-receipt.json"))!=_receipts(run_id,job,inputs):
        raise Blocked(f"{job}: permission or lineage receipt changed")
    receipt = read_json(attempt / APPLICABILITY)
    if receipt != _applicability(run_id, job, inputs) or validate_document(
            receipt, "analysis-applicability-receipt.schema.json"):
        raise Blocked(f"{job}: applicability receipt changed")


def run(run_id: str, dagster_run_id: str, job_id: str, force: bool=False) -> dict[str, Any]:
    if job_id not in JOBS: raise Blocked("analysis lifecycle: unsupported job")
    contract,result_name,_schema=JOBS[job_id]; base=data_path(run_id,"jobs",job_id)
    def execute(allocation, inputs, fingerprint):
        if current_inputs(run_id,job_id)!=inputs: raise Blocked(f"{job_id}: inputs changed before execution")
        attempt=allocation["attempt"]
        if job_id=="05-native-memory":
            result=bounded.native_memory(run_id=run_id,attempt_id=allocation["attempt_id"],source_generation=inputs["source_generation"],bindings=inputs["bindings"],units=inputs["payload"])
        elif job_id=="13-fuzz-target-triage":
            result=bounded.fuzz_triage(run_id=run_id,attempt_id=allocation["attempt_id"],source_generation=inputs["source_generation"],bindings=inputs["bindings"],targets=inputs["payload"])
        else:
            evidence=attempt/"automatic-reachability-evidence.json"; atomic_json(evidence,{"assessments":[]})
            request={"run_id":run_id,"source_snapshot_sha256":inputs["source_generation"],
                "generated_at":inputs["generated_at"],"output_root":str(data_path(run_id,"jobs")),
                "sca":inputs["sca"],"reachability_evidence":str(evidence),
                "reachability_evidence_sha256":"sha256:" + file_hash(evidence)}
            artifacts,gaps=dependency_workers.build_reachability(request,allocation["attempt_id"])
            for relative,payload in artifacts.items():
                path=attempt.joinpath(*PurePosixPath(relative).parts); path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(payload)
            result=read_json(attempt/result_name)
        if job_id!="06-cve-reachability":
            if inputs["mode"]=="SKIPPED_NA":
                result["status"]="SKIPPED"; result["gaps"]=[SKIPS[job_id]]
            atomic_json(attempt/result_name,result)
        permission,lineage=_receipts(run_id,job_id,inputs); atomic_json(attempt/"permission-receipt.json",permission); atomic_json(attempt/"lineage-receipt.json",lineage)
        atomic_json(attempt/APPLICABILITY, _applicability(run_id,job_id,inputs))
        status=result.get("status") or ("OK_WITH_GAPS" if result.get("coverage_gaps") else "OK")
        record_count=len(result.get("candidates",result.get("targets",result.get("assessments",[]))))
        status_doc={"process":job_id,"status":status,"records":record_count,"qualification":"implemented_not_qualified",
            "execution_status":status,"acceptance_status":"CURRENT","run_id":run_id,"job_id":job_id,
            "attempt_id":allocation["attempt_id"]}
        atomic_json(attempt/"status.json",status_doc)
        paths=[result_name,"permission-receipt.json","lineage-receipt.json","status.json",APPLICABILITY]
        if job_id=="06-cve-reachability": paths += ["outputs/reachability-evidence-identity.json","automatic-reachability-evidence.json"]
        if job_id=="06-cve-reachability": paths += ["inputs.json"]
        skip=SKIPS.get(job_id) if status=="SKIPPED" else None
        return record_terminal_current(base,attempt,run_id=run_id,job_id=job_id,dagster_run_id=dagster_run_id,
            worker_kind="deterministic_python",output_contract=contract,input_fingerprint=fingerprint,
            started_at=allocation["started_at"],execution_status=status,summary=f"{job_id} published evidence-qualified output",
            status_record=status_doc,artifact_paths=paths,gaps=result.get("gaps",result.get("coverage_gaps",[])),
            skip_reason=skip,consumer_job_id=CONSUMER[job_id],
            pre_envelope_validate=lambda path,_status:_validate_attempt(run_id,job_id,path,inputs))
    return coordinate_worker_lifecycle(base,run_id=run_id,job_id=job_id,dagster_run_id=dagster_run_id,
        worker_kind="deterministic_python",output_contract=contract,resume_command=f"analysis_feature_lifecycle:{job_id}",
        derive_inputs=lambda:current_inputs(run_id,job_id),fingerprint_inputs=_sha,execute_attempt=execute,
        preflight_failure_inputs=lambda exc:{"run_id":run_id,"job_id":job_id,"error":f"{type(exc).__name__}: {exc}","code":_code(job_id)},
        post_validate=lambda attempt,_envelope,inputs:_validate_attempt(run_id,job_id,attempt,inputs),
        consumer_job_id=CONSUMER[job_id],force=force,
        blocked_summary=f"{job_id} preflight blocked",failed_summary=f"{job_id} execution failed")


def validate(run_id: str, job_id: str) -> Path:
    inputs=current_inputs(run_id,job_id); base=data_path(run_id,"jobs",job_id)
    attempt,_=validate_published(base,read_json(base/"accepted.json"),_sha(inputs),expected_run_id=run_id,
        expected_job_id=job_id,consumer_job_id=CONSUMER[job_id])
    _validate_attempt(run_id,job_id,attempt,inputs); return attempt
