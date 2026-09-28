#!/usr/bin/env python3
"""T14 nominal common-envelope publisher for qualified OWASP T11--T13 outputs."""
from __future__ import annotations

import tunables
import argparse
from copy import deepcopy
import hashlib
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
MATRIX_MANIFEST = "owasp-control-status-matrix-manifest.json"
PAGE_DIRECTORY = "owasp-control-status-matrix-pages"
PAGE_BYTE_LIMIT = tunables.shared("owasp_join_page_max_bytes")
PUBLISHED = (MATRIX_MANIFEST, join.GAPS, join.ROUTES)
SCHEMAS = {MATRIX_MANIFEST:"owasp-control-status-matrix-manifest.schema.json",
           "matrix_page":"owasp-control-status-matrix-page.schema.json",
           join.GAPS:"owasp-coverage-gaps-report.schema.json",
           join.ROUTES:"owasp-candidate-promotion-routes.schema.json"}
CODE_FILES = ("owasp_join_publisher.py","owasp_join_report.py","owasp_dispatch.py",
    "publish_job_output.py","validate_job_output.py","registry/output-contracts/owasp-join-report.json")


def root(run_id: str) -> Path:
    return data_path(run_id,"jobs",JOB)


def _sha(value: Any) -> str:
    return "sha256:"+digest(value)


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value,indent=2,sort_keys=True)+"\n").encode()


def _page(matrix: dict[str,Any], page_index: int, first: int, rows: list[dict[str,Any]]) -> dict[str,Any]:
    return {"schema":"appsec-review/owasp-control-status-matrix-page/1.0",
        "run_id":matrix["run_id"],"selection_id":matrix["selection_id"],"page_index":page_index,
        "first_row_index":first,"last_row_index":first+len(rows)-1,"row_count":len(rows),"rows":rows}


def _partition_matrix(matrix: dict[str,Any]) -> dict[str,Any]:
    errors=validate_document(matrix,"owasp-control-status-matrix.schema.json")
    if errors: raise Blocked(f"{JOB}: logical matrix fails its closed schema ({errors[0]})")
    rows=matrix["rows"]
    if not rows: raise Blocked(f"{JOB}: logical matrix has no rows")
    pages=[]; current=[]; first=0
    for row in rows:
        candidate=[*current,row]
        value=_page(matrix,len(pages),first,candidate)
        if len(_json_bytes(value))>PAGE_BYTE_LIMIT and current:
            pages.append(_page(matrix,len(pages),first,current)); first+=len(current); current=[row]
            value=_page(matrix,len(pages),first,current)
        else: current=candidate
        if len(_json_bytes(value))>PAGE_BYTE_LIMIT:
            raise Blocked(f"{JOB}: one matrix row cannot fit in a bounded page")
    pages.append(_page(matrix,len(pages),first,current))
    outputs={}; records=[]
    for value in pages:
        path=f"{PAGE_DIRECTORY}/page-{value['page_index']:04d}.json"; data=_json_bytes(value)
        outputs[path]=value
        records.append({"page_index":value["page_index"],"path":path,
            "sha256":hashlib.sha256(data).hexdigest(),"byte_size":len(data),
            "first_row_index":value["first_row_index"],"last_row_index":value["last_row_index"],
            "row_count":value["row_count"]})
    header={key:value for key,value in matrix.items() if key!="rows"}
    outputs[MATRIX_MANIFEST]={"schema":"appsec-review/owasp-control-status-matrix-manifest/1.0",
        "run_id":matrix["run_id"],"selection_id":matrix["selection_id"],
        "logical_matrix_schema":matrix["schema"],"logical_matrix_sha256":digest(matrix),
        "rows_sha256":digest(rows),"row_count":len(rows),"matrix_header":header,"pages":records}
    return outputs


def published_names(outputs: dict[str,Any]) -> list[str]:
    return sorted(outputs)


def _code_hashes() -> dict[str,str]:
    values={name:file_hash(ROOT/name) for name in CODE_FILES}
    for name in {*SCHEMAS.values(),"owasp-control-status-matrix.schema.json"}:
        values["schemas/"+name]=file_hash(ROOT.parent/"schemas"/name)
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
            "outputs":{name:"sha256:"+file_hash(attempt/name) for name in published_names(outputs)}})}
    return permission,lineage


def _derive(run_id: str, facts: dispatch.DispatchFacts) -> dict[str,Any]:
    outputs=join.derive(join.load_verified_inputs(run_id,facts=facts))
    return {**_partition_matrix(outputs[join.MATRIX]),join.GAPS:outputs[join.GAPS],join.ROUTES:outputs[join.ROUTES]}


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
    expected_names=published_names(outputs)
    actual_pages=sorted(path.relative_to(attempt).as_posix() for path in (attempt/PAGE_DIRECTORY).glob("*.json"))
    expected_pages=sorted(name for name in expected_names if name.startswith(PAGE_DIRECTORY+"/"))
    if actual_pages!=expected_pages: raise Blocked(f"{JOB}: matrix page set is missing, duplicate, or substituted")
    for name in expected_names:
        value=read_json(attempt/name)
        if value!=outputs[name]: raise Blocked(f"{JOB}: {name} differs from deterministic T11-T13 output")
        schema=SCHEMAS["matrix_page"] if name.startswith(PAGE_DIRECTORY+"/") else SCHEMAS[name]
        errors=validate_document(value,schema)
        if errors: raise Blocked(f"{JOB}: {name} fails its closed schema ({errors[0]})")
    manifest=read_json(attempt/MATRIX_MANIFEST); cursor=0; reconstructed=[]
    for expected_index,record in enumerate(manifest["pages"]):
        if (record["page_index"]!=expected_index or record["path"]!=expected_pages[expected_index] or
                record["first_row_index"]!=cursor or record["last_row_index"]!=cursor+record["row_count"]-1):
            raise Blocked(f"{JOB}: matrix page order or row coverage is not exact")
        path=attempt/record["path"]; data=path.read_bytes(); page=read_json(path)
        if (len(data)!=record["byte_size"] or len(data)>PAGE_BYTE_LIMIT or
                hashlib.sha256(data).hexdigest()!=record["sha256"] or page["page_index"]!=expected_index or
                page["first_row_index"]!=cursor or page["last_row_index"]!=record["last_row_index"] or
                page["row_count"]!=record["row_count"] or len(page["rows"])!=record["row_count"]):
            raise Blocked(f"{JOB}: matrix page hash, size, identity, or coverage differs")
        reconstructed.extend(page["rows"]); cursor+=record["row_count"]
    logical={**manifest["matrix_header"],"rows":reconstructed}
    if (cursor!=manifest["row_count"] or digest(reconstructed)!=manifest["rows_sha256"] or
            digest(logical)!=manifest["logical_matrix_sha256"]):
        raise Blocked(f"{JOB}: matrix pages do not reconstruct the exact logical matrix")
    permission,lineage=_receipts(inputs,outputs,attempt)
    if read_json(attempt/"permission.json")!=permission or read_json(attempt/"lineage.json")!=lineage:
        raise Blocked(f"{JOB}: canonical permission or lineage receipt changed")


def run(run_id: str, dagster_id: str, facts: dispatch.DispatchFacts, force: bool=False) -> dict[str,Any]:
    base=root(run_id)
    def execute(allocation: dict[str,Any], inputs: dict[str,Any], fingerprint: str) -> dict[str,Any]:
        if inputs["code"]!=_code_hashes() or inputs["facts"]!=_facts_record(facts):
            raise Blocked(f"{JOB}: implementation or trusted dispatch facts changed before execution")
        attempt=allocation["attempt"]; outputs=_derive(run_id,facts)
        for name in published_names(outputs): atomic_json(attempt/name,outputs[name])
        permission,lineage=_receipts(inputs,outputs,attempt)
        atomic_json(attempt/"permission.json",permission); atomic_json(attempt/"lineage.json",lineage)
        gap_statements=[item["statement"] for item in outputs[join.GAPS]["gaps"]]
        status_name="OK_WITH_GAPS" if gap_statements else "OK"
        status={"process":JOB,"status":status_name,
            "selected":outputs[MATRIX_MANIFEST]["matrix_header"]["denominators"]["selected"],
            "applicable":outputs[MATRIX_MANIFEST]["matrix_header"]["denominators"]["applicable"],
            "assessed":outputs[MATRIX_MANIFEST]["matrix_header"]["denominators"]["assessed"],
            "satisfied":outputs[MATRIX_MANIFEST]["matrix_header"]["denominators"]["satisfied"],
            "coverage_gaps":len(gap_statements),"candidate_routes":len(outputs[join.ROUTES]["routes"]),
            "claim_limit":"control-accounting-and-candidate-routes-only"}
        return record_terminal_current(base,attempt,run_id=run_id,job_id=JOB,dagster_run_id=dagster_id,
            worker_kind="deterministic_python",output_contract=CONTRACT,input_fingerprint=fingerprint,
            started_at=allocation["started_at"],execution_status=status_name,
            summary="Qualified OWASP matrix, gaps, and candidate routes published in one common envelope.",
            status_record=status,artifact_paths=[*published_names(outputs),"permission.json","lineage.json","status.json"],
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


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
