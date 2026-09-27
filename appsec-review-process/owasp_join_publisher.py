#!/usr/bin/env python3
"""T14 nominal common-envelope publisher for qualified OWASP T11--T13 outputs."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import shlex
from typing import Any

from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json, tree_hashes
import owasp_dispatch as dispatch
import owasp_join_report as join
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

JOB = join.JOB_ID
CONTRACT = "owasp-join-report"
PERMISSIONS = ["read-run-data", "write-run-data"]
PUBLISHED = (join.MATRIX, join.GAPS, join.ROUTES)
SCHEMAS = {join.MATRIX:"owasp-control-status-matrix.schema.json",
           join.GAPS:"owasp-coverage-gaps-report.schema.json",
           join.ROUTES:"owasp-candidate-promotion-routes.schema.json"}
CODE_FILES = ("owasp_join_publisher.py","owasp_join_report.py","owasp_dispatch.py",
    "publish_job_output.py","validate_job_output.py","registry/output-contracts/owasp-join-report.json")


def root(run_id: str) -> Path:
    return data_path(run_id,"jobs",JOB)


def _sha(value: Any) -> str:
    return "sha256:"+digest(value)


def _code_hashes() -> dict[str,str]:
    values={name:file_hash(ROOT/name) for name in CODE_FILES}
    for name in SCHEMAS.values(): values["schemas/"+name]=file_hash(ROOT.parent/"schemas"/name)
    return values


def _facts_record(facts: dispatch.DispatchFacts) -> dict[str,Any]:
    try: registry_hashes=tree_hashes(facts.registry_dir)
    except (OSError,ValueError) as exc: raise Blocked(f"{JOB}: trusted registry tree is unsafe") from exc
    return {"registry_dir":str(Path(facts.registry_dir).resolve()),"registry_hashes":registry_hashes,
        "allowed_models":deepcopy(list(facts.allowed_models)),"invoker_id":facts.invoker_id,
        "source_snapshot_sha256":facts.source_snapshot_sha256,
        "registry_ceiling":deepcopy(facts.registry_ceiling)}


def current_inputs(run_id: str, facts: dispatch.DispatchFacts) -> dict[str,Any]:
    verified=join.load_verified_inputs(run_id,facts=facts)
    accounting=verified["accounting"]
    base=dispatch._base(run_id)
    pointer_path=base/"accepted.json"
    attempt=base/"attempts"/accounting["attempt_id"]
    accounting_path=attempt/dispatch.ACCOUNTING_ARTIFACT
    return {"run_id":run_id,"source_snapshot_sha256":facts.source_snapshot_sha256,
        "dispatch_attempt_id":accounting["attempt_id"],
        "dispatch_pointer_sha256":"sha256:"+file_hash(pointer_path),
        "dispatch_accounting_sha256":"sha256:"+file_hash(accounting_path),
        "dispatch_input_fingerprint":accounting["input_fingerprint"],
        "selection_id":verified["applicability"]["selection_id"],
        "input_manifest_sha256":"sha256:"+verified["input_manifest_sha256"].removeprefix("sha256:"),
        "applicability_model_sha256":"sha256:"+verified["applicability_model_sha256"].removeprefix("sha256:"),
        "facts":_facts_record(facts),"code":_code_hashes()}


def _receipts(inputs: dict[str,Any], outputs: dict[str,Any], attempt: Path) -> tuple[dict[str,Any],dict[str,Any]]:
    permission={"schema":"appsec-review/producer-permission-receipt/1.0","run_id":inputs["run_id"],
        "job_id":JOB,"source_snapshot_sha256":inputs["source_snapshot_sha256"],"permissions":PERMISSIONS}
    lineage={"schema":"appsec-review/producer-lineage-receipt/1.0","run_id":inputs["run_id"],
        "job_id":JOB,"source_snapshot_sha256":inputs["source_snapshot_sha256"],
        "build_lineage_sha256":_sha({"dispatch_pointer":inputs["dispatch_pointer_sha256"],
            "dispatch_accounting":inputs["dispatch_accounting_sha256"],
            "dispatch_fingerprint":inputs["dispatch_input_fingerprint"],
            "input_manifest":inputs["input_manifest_sha256"],
            "applicability_model":inputs["applicability_model_sha256"],
            "selection_id":inputs["selection_id"],
            "outputs":{name:"sha256:"+file_hash(attempt/name) for name in PUBLISHED}})}
    return permission,lineage


def _derive(run_id: str, facts: dispatch.DispatchFacts) -> dict[str,Any]:
    outputs=join.derive(join.load_verified_inputs(run_id,facts=facts))
    return {name:outputs[name] for name in PUBLISHED}


def _resume_command(run_id: str, dagster_id: str, facts: dispatch.DispatchFacts) -> str:
    argv=["python","-B","appsec-review-process/owasp_join_publisher.py","--run-id",run_id,
        "--dagster-run-id",dagster_id,"--registry-dir",str(Path(facts.registry_dir).resolve()),
        "--invoker-id",facts.invoker_id,"--source-snapshot-sha256",facts.source_snapshot_sha256,
        "--registry-ceiling-json",json.dumps(facts.registry_ceiling,sort_keys=True,separators=(",",":"))]
    for model in facts.allowed_models:
        argv.extend(("--allowed-model-json",json.dumps(model,sort_keys=True,separators=(",",":"))))
    return shlex.join(argv)


def _validate_attempt(attempt: Path, inputs: dict[str,Any], facts: dispatch.DispatchFacts) -> None:
    if read_json(attempt/"inputs.json")!=inputs: raise Blocked(f"{JOB}: immutable inputs changed")
    if current_inputs(inputs["run_id"],facts)!=inputs: raise Blocked(f"{JOB}: current verified OWASP inputs changed")
    outputs=_derive(inputs["run_id"],facts)
    for name in PUBLISHED:
        value=read_json(attempt/name)
        if value!=outputs[name]: raise Blocked(f"{JOB}: {name} differs from deterministic T11-T13 output")
        errors=validate_document(value,SCHEMAS[name])
        if errors: raise Blocked(f"{JOB}: {name} fails its closed schema ({errors[0]})")
    permission,lineage=_receipts(inputs,outputs,attempt)
    if read_json(attempt/"permission.json")!=permission or read_json(attempt/"lineage.json")!=lineage:
        raise Blocked(f"{JOB}: canonical permission or lineage receipt changed")


def run(run_id: str, dagster_id: str, facts: dispatch.DispatchFacts, force: bool=False) -> dict[str,Any]:
    base=root(run_id)
    def execute(allocation: dict[str,Any], inputs: dict[str,Any], fingerprint: str) -> dict[str,Any]:
        if inputs["code"]!=_code_hashes() or inputs["facts"]!=_facts_record(facts):
            raise Blocked(f"{JOB}: implementation or trusted dispatch facts changed before execution")
        attempt=allocation["attempt"]; outputs=_derive(run_id,facts)
        for name in PUBLISHED: atomic_json(attempt/name,outputs[name])
        permission,lineage=_receipts(inputs,outputs,attempt)
        atomic_json(attempt/"permission.json",permission); atomic_json(attempt/"lineage.json",lineage)
        gap_statements=[item["statement"] for item in outputs[join.GAPS]["gaps"]]
        status_name="OK_WITH_GAPS" if gap_statements else "OK"
        status={"process":JOB,"status":status_name,
            "selected":outputs[join.MATRIX]["denominators"]["selected"],
            "applicable":outputs[join.MATRIX]["denominators"]["applicable"],
            "assessed":outputs[join.MATRIX]["denominators"]["assessed"],
            "satisfied":outputs[join.MATRIX]["denominators"]["satisfied"],
            "coverage_gaps":len(gap_statements),"candidate_routes":len(outputs[join.ROUTES]["routes"]),
            "claim_limit":"control-accounting-and-candidate-routes-only"}
        return record_terminal_current(base,attempt,run_id=run_id,job_id=JOB,dagster_run_id=dagster_id,
            worker_kind="deterministic_python",output_contract=CONTRACT,input_fingerprint=fingerprint,
            started_at=allocation["started_at"],execution_status=status_name,
            summary="Qualified OWASP matrix, gaps, and candidate routes published in one common envelope.",
            status_record=status,artifact_paths=[*PUBLISHED,"permission.json","lineage.json","status.json"],
            gaps=gap_statements,pre_envelope_validate=lambda path,_status:_validate_attempt(path,inputs,facts))
    return coordinate_worker_lifecycle(base,run_id=run_id,job_id=JOB,dagster_run_id=dagster_id,
        worker_kind="deterministic_python",output_contract=CONTRACT,
        resume_command=_resume_command(run_id,dagster_id,facts),
        derive_inputs=lambda:current_inputs(run_id,facts),fingerprint_inputs=lambda value:_sha(value),
        execute_attempt=execute,preflight_failure_inputs=lambda exc:{"run_id":run_id,"job":JOB,
            "preflight_error":f"{type(exc).__name__}: {exc}","code":_code_hashes()},force=force,
        post_validate=lambda attempt,_envelope,inputs:_validate_attempt(attempt,inputs,facts),
        blocked_summary="OWASP join inputs were not current and exact.",
        failed_summary="OWASP join publication failed; no older result may be used.")


def validate(run_id: str, facts: dispatch.DispatchFacts, pointer: dict[str,Any]|None=None) -> Path:
    inputs=current_inputs(run_id,facts)
    attempt,_=validate_published(root(run_id),pointer or read_json(root(run_id)/"accepted.json"),_sha(inputs),
        expected_run_id=run_id,expected_job_id=JOB)
    _validate_attempt(attempt,inputs,facts); return attempt


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__.splitlines()[0]); parser.add_argument("--run-id",required=True)
    parser.add_argument("--dagster-run-id",default="standalone-owasp-join-report")
    parser.add_argument("--registry-dir",type=Path,required=True); parser.add_argument("--invoker-id",required=True)
    parser.add_argument("--source-snapshot-sha256",required=True); parser.add_argument("--allowed-model-json",action="append",required=True)
    parser.add_argument("--registry-ceiling-json",default="null")
    parser.add_argument("--force",action="store_true"); args=parser.parse_args()
    facts=dispatch.DispatchFacts(args.registry_dir,tuple(json.loads(item) for item in args.allowed_model_json),
        args.invoker_id,args.source_snapshot_sha256,json.loads(args.registry_ceiling_json))
    print(json.dumps(run(args.run_id,args.dagster_run_id,facts,args.force),indent=2))
