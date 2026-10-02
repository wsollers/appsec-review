"""Config-driven shared orchestration for verified control and final-publication processes."""
from __future__ import annotations
from pathlib import Path
from typing import Any

import completeness_audit, control_process_worker, deterministic_pool_merge, dynamic_rescope
import evidence_quorum, final_publication, remediation_retest, synthetic_hypothesis_resynthesis
import pool_launcher, pool_rendezvous, pool_specification
import container_execution
from execution_state import Blocked, beneath, data_path, file_hash, identifier, read_json, run_path
from publish_job_output import mark_attempt_started, publish_validated
import registry_paths

SCHEMA="appsec-review/control-lane-orchestration-request/1.0"
SIMPLE={
 "dynamic-rescope":dynamic_rescope,
 "completeness-audit":completeness_audit,
 "synthetic-hypothesis-resynthesis":synthetic_hypothesis_resynthesis,
 "remediation-retest-feedback":remediation_retest,
}

def _owned(value:Any,owner:Path,label:str,*,directory=False)->Path:
    if not isinstance(value,str) or not value: raise Blocked(f"control orchestration: {label} is required")
    path=Path(value).absolute()
    try: path=beneath(owner,path)
    except ValueError as exc: raise Blocked(f"control orchestration: {label} is not run-owned") from exc
    if path.is_symlink() or not (path.is_dir() if directory else path.is_file()):
        raise Blocked(f"control orchestration: {label} is absent or linked")
    return path

def _request(run_id:str,job_id:str,path:str)->tuple[dict,Path,Path,str]:
    owner=run_path(run_id).absolute(); source=_owned(path,owner,"input request")
    try: value=read_json(source)
    except Exception: raise Blocked("control orchestration: request is unreadable") from None
    if not isinstance(value,dict) or set(value)!={"schema","run_id","job_id","source_generation","generated_at","payload"}:
        raise Blocked("control orchestration: request shape is not closed")
    if value["schema"]!=SCHEMA or value["run_id"]!=run_id or value["job_id"]!=job_id:
        raise Blocked("control orchestration: request identity is invalid")
    manifest=_owned(str(owner/"inputs/artifact-manifest.json"),owner,"artifact manifest")
    generation="sha256:"+file_hash(manifest)
    if value["source_generation"]!=generation: raise Blocked("control orchestration: request source generation is stale")
    if not isinstance(value["payload"],dict): raise Blocked("control orchestration: payload is invalid")
    return value,owner,source,generation

def _attempt(owner:Path,run_id:str,job_id:str,output_root:str,attempt_root:str)->tuple[Path,Path,str]:
    base=data_path(run_id,"jobs",job_id,"whole").absolute()
    if Path(output_root).absolute()!=base: raise Blocked("control orchestration: output root is not canonical")
    attempt=Path(attempt_root).absolute(); attempt_id=identifier(attempt.name)
    if attempt != base/"attempts"/attempt_id or attempt.exists(): raise Blocked("control orchestration: attempt root is not a new canonical path")
    beneath(owner,attempt.parent); base.mkdir(parents=True,exist_ok=True); mark_attempt_started(base,attempt_id)
    return base,attempt,attempt_id

def _publish(base:Path,attempt:Path,run_id:str,job_id:str)->dict:
    envelope=read_json(attempt/"result.json")
    return publish_validated(base,attempt,attempt/"result.json",envelope["input_fingerprint"],
        expected_run_id=run_id,expected_job_id=job_id)

def execute(*,job_id:str,run_id:str,dagster_run_id:str,input_path:str,output_root:str,attempt_root:str)->dict:
    run_id=identifier(run_id); identifier(dagster_run_id)
    value,owner,_request_path,generation=_request(run_id,job_id,input_path)
    base,attempt,attempt_id=_attempt(owner,run_id,job_id,output_root,attempt_root)
    payload=value["payload"]; started=value["generated_at"]
    source=_owned(payload.get("source_path"),owner,"source input")
    if job_id=="evidence-qualified-quorum":
        evidence_quorum.run_verified_attempt(owner,source,attempt,attempt_id=attempt_id,
            source_snapshot_sha256=generation,started_at=started,finished_at=started)
    elif job_id in SIMPLE:
        SIMPLE[job_id].run_attempt(source,attempt,attempt_id=attempt_id,source_snapshot_sha256=generation,
            started_at=started,finished_at=started)
    else: raise Blocked("control orchestration: job requires its dedicated verified adapter")
    return _publish(base,attempt,run_id,job_id)

def _pool_context(value:dict,owner:Path,generation:str)->pool_specification.PoolContext:
    expected={"pool_parent","prompt_root","readable_roots","allowed_models","invoker_id","host_flavor","docker_executable","container_user","mount_roots","registry_ceiling"}
    if set(value)!=expected: raise Blocked("control orchestration: pool context shape is not closed")
    roots=lambda rows:{key:_owned(path,owner,"pool context root",directory=True) for key,path in rows.items()}
    pool_parent=Path(value["pool_parent"]).absolute(); beneath(owner,pool_parent.parent)
    docker=Path(value["docker_executable"]).absolute() if value["docker_executable"] else None
    return pool_specification.PoolContext(pool_parent=pool_parent,registry_dir=registry_paths.REGISTRY,
        prompt_root=_owned(value["prompt_root"],owner,"prompt root",directory=True),readable_roots=roots(value["readable_roots"]),
        allowed_models=tuple(value["allowed_models"]),invoker_id=value["invoker_id"],images_dir=container_execution.IMAGES_DIR,
        host_flavor=value["host_flavor"],docker_host=None,docker_executable=docker,container_user=value["container_user"],
        mount_roots=roots(value["mount_roots"]),source_snapshot_sha256=generation,registry_ceiling=value["registry_ceiling"])

def execute_pool(*,job_id:str,run_id:str,dagster_run_id:str,input_path:str,output_root:str,attempt_root:str)->dict:
    run_id=identifier(run_id); identifier(dagster_run_id); value,owner,_,generation=_request(run_id,job_id,input_path)
    base,attempt,attempt_id=_attempt(owner,run_id,job_id,output_root,attempt_root); p=value["payload"]
    if set(p)!={"spec_path","context","runtime"}: raise Blocked("control orchestration: pool payload shape is not closed")
    spec=read_json(_owned(p["spec_path"],owner,"pool specification")); context=_pool_context(p["context"],owner,generation)
    runtime_cfg=p["runtime"]
    if set(runtime_cfg)!={"effort","budget_usd","stop_grace_seconds","max_parallel","wait_limit_seconds","drain_seconds","rendezvous_parent"}:
        raise Blocked("control orchestration: pool runtime shape is not closed")
    rendezvous_parent=Path(runtime_cfg["rendezvous_parent"]).absolute(); beneath(owner,rendezvous_parent.parent)
    if job_id=="persona-tool-pool-dispatch":
        import persona_tool_pool_lifecycle   # deferred: that module imports this one
        invoker=persona_tool_pool_lifecycle.GraphReviewInvoker()   # deterministic intake cells, no model (D4)
        runtime=pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous_parent,invoker=invoker,
            clock=lambda:value["generated_at"],stop_grace_seconds=runtime_cfg["stop_grace_seconds"],
            cancel=pool_rendezvous.PoolCancel(),max_parallel=runtime_cfg["max_parallel"],
            wait_limit_seconds=runtime_cfg["wait_limit_seconds"],drain_seconds=runtime_cfg["drain_seconds"])
        launched=pool_launcher.launch(spec,context=context,runtime=runtime)
        result={"schema":"appsec-review/persona-tool-pool-dispatch/1.0","run_id":run_id,
            "pool_directory":launched.pool_directory,"expansion_sha256":launched.expansion_sha256,
            "terminal_manifest_sha256":launched.terminal_manifest_sha256,"outcome":launched.outcome,
            "instance_count":launched.instance_count}
        control_process_worker.publish(run_id=run_id,job_id=job_id,attempt_id=attempt_id,
            contract_id=job_id,result_name="persona-tool-pool-dispatch.json",result=result,output_root=attempt,
            source_snapshot_sha256=generation,input_binding=value,started_at=value["generated_at"],finished_at=value["generated_at"])
    elif job_id=="deterministic-pool-merge":
        pool_root=context.pool_parent/pool_specification.pool_directory(pool_specification.spec_sha256(spec))
        verified=pool_rendezvous.load_verified_manifest(pool_root,
            expected_spec=spec,context=context,rendezvous_parent=rendezvous_parent)
        deterministic_pool_merge.run_verified_attempt(verified,pool_root=pool_root,output_root=attempt,
            run_id=run_id,attempt_id=attempt_id,source_snapshot_sha256=generation,
            started_at=value["generated_at"],finished_at=value["generated_at"])
    else: raise Blocked("control orchestration: unknown pool job")
    return _publish(base,attempt,run_id,job_id)

def execute_final(*,run_id:str,dagster_run_id:str,input_path:str,output_root:str)->dict:
    run_id=identifier(run_id); identifier(dagster_run_id); value,owner,_,_generation=_request(run_id,"final-publication-gate",input_path); p=value["payload"]
    required={"draft_attempt","signoff_ledger","authorization_key","expected_ledger_anchor","expected_ledger_head","completeness_ref","feedback_ref"}
    if set(p)!=required: raise Blocked("control orchestration: final publication payload shape is not closed")
    final_root=Path(output_root).absolute(); expected=owner/"data"/"publication"/"final"
    if final_root!=expected or final_root.exists(): raise Blocked("control orchestration: final output is not a new canonical path")
    draft=_owned(p["draft_attempt"],owner,"draft attempt",directory=True); ledger=read_json(_owned(p["signoff_ledger"],owner,"signoff ledger"))
    key=_owned(p["authorization_key"],owner,"authorization key").read_bytes()
    result=final_publication.publish(draft,ledger,final_root,run_root=owner,
        completeness_ref=p["completeness_ref"],feedback_ref=p["feedback_ref"],authorization_key=key,
        expected_ledger_anchor=p["expected_ledger_anchor"],expected_ledger_head=p["expected_ledger_head"])
    return {"attempt_id":"final","status":result["status"],"output_root":str(final_root)}
