#!/usr/bin/env python3
"""Separate deterministic process for typed pool-result merge."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import Blocked, atomic_json, file_hash, read_json
from review_control_loops import deterministic_merge
import control_process_worker
import pool_rendezvous

JOB = "deterministic-pool-merge"
RESULT = "deterministic-pool-merge.json"
CONTRACT = "deterministic-pool-merge"

def run_lifecycle(run_id: str, dagster_run_id: str, force: bool = False):
    from control_feature_lifecycle import run as lifecycle_run
    return lifecycle_run(run_id, dagster_run_id, JOB, force)

def _verified_file(attempt_root: Path, relative: str, record: dict):
    path=attempt_root.joinpath(*Path(relative).parts)
    if path.is_symlink() or not path.is_file(): raise Blocked("deterministic merge: verified output is unsafe")
    try: path.resolve(strict=True).relative_to(attempt_root.resolve(strict=True))
    except (OSError,ValueError) as exc: raise Blocked("deterministic merge: verified output escapes attempt") from exc
    if "sha256:"+file_hash(path)!=record.get("sha256"): raise Blocked("deterministic merge: verified output hash changed")
    try: value=read_json(path)
    except Exception as exc: raise Blocked("deterministic merge: verified output is not JSON") from exc
    if not isinstance(value,dict) or set(value)!={"candidates"} or not isinstance(value["candidates"],list):
        raise Blocked("deterministic merge: verified candidate document is invalid")
    return value["candidates"]

def merge_verified_manifest(verified: pool_rendezvous.VerifiedManifest, *, pool_root: Path,
                            run_id: str) -> dict:
    """Merge only the exact terminal population and outputs reverified by C02."""
    if not isinstance(verified,pool_rendezvous.VerifiedManifest):
        raise Blocked("deterministic merge: terminal manifest was not verified")
    expected=[]; results=[]
    for item in verified.instances:
        worker_id=item.instance.instance_id; adapter=item.result
        if adapter is not None and adapter.get("run_id")!=run_id:
            raise Blocked("deterministic merge: adapter result belongs to another run")
        if item.instance.worker_kind=="persona":
            producer_id=adapter.get("persona_id") if adapter else f"persona:{worker_id}"
        else:
            producer_id=adapter.get("image_reference") if adapter else f"container:{worker_id}"
        expected.append({"worker_id":worker_id,"producer_id":producer_id,"run_id":run_id})
        if adapter is None: continue
        candidates=[]
        if item.state==pool_rendezvous.SUCCEEDED:
            attempt=item.instance.attempt_root_path(Path(pool_root))
            if item.instance.worker_kind=="persona":
                matches=[entry for entry in adapter["outputs"] if entry["path"]=="candidates.json"]
                if len(matches)!=1: raise Blocked("deterministic merge: persona candidate output is absent")
                candidates=_verified_file(attempt,f'{adapter["output_root"]}/candidates.json',matches[0])
            else:
                matches=[entry for entry in adapter["files"] if entry["path"]=="stdout.log"]
                if len(matches)!=1: raise Blocked("deterministic merge: container stdout is absent")
                candidates=_verified_file(attempt,f'{adapter["log_path"]}/stdout.log',matches[0])
        status={pool_rendezvous.SUCCEEDED:"OK",pool_rendezvous.BLOCKED:"BLOCKED",
            pool_rendezvous.CANCELED:"CANCELED"}.get(item.state,"FAILED")
        results.append({"worker_id":worker_id,"producer_id":producer_id,"run_id":run_id,
                        "status":status,"candidates":candidates})
    return deterministic_merge(run_id,expected,results)

def run(source: Path, output: Path):
    value = read_json(source)
    result = deterministic_merge(value["run_id"], value["expected_workers"], value["worker_results"])
    atomic_json(output, result); return result

def run_attempt(source: Path, output_root: Path, *, attempt_id: str, source_snapshot_sha256: str,
                started_at: str, finished_at: str):
    raise Blocked("deterministic merge: raw caller-authored attempts cannot be published")

def run_verified_attempt(verified: pool_rendezvous.VerifiedManifest, *, pool_root: Path,
        output_root: Path, run_id: str, attempt_id: str, source_snapshot_sha256: str,
        started_at: str, finished_at: str):
    result=merge_verified_manifest(verified,pool_root=pool_root,run_id=run_id)
    binding={"run_id":run_id,"pool_manifest_sha256":verified.manifest["manifest_sha256"],
             "pool_expansion_sha256":verified.plan.manifest["expansion_sha256"]}
    return control_process_worker.publish(run_id=run_id,job_id=JOB,attempt_id=attempt_id,
        contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,
        source_snapshot_sha256=source_snapshot_sha256,input_binding=binding,started_at=started_at,finished_at=finished_at)

if __name__ == "__main__":
    raise SystemExit("verified C02 pool context is required; raw merge CLI publication is disabled")
