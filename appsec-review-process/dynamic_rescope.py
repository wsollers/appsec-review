#!/usr/bin/env python3
"""Separate deterministic process for dependency indexing and bounded affected-only rescope."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import Blocked, atomic_json, read_json
from review_control_loops import bounded_rescope, dependency_index
import control_process_worker
import synthesis_report

JOB = "dynamic-rescope"
RESULT = "bounded-rescope-plan.json"
CONTRACT = "bounded-rescope-plan"

def run(source: Path, output: Path):
    value=read_json(source); index=dependency_index(value["run_id"],value["nodes"],value["edges"])
    result=bounded_rescope(value["run_id"],index,value["changed_nodes"],iteration=value["iteration"],max_iterations=value["max_iterations"],previous_plan=value.get("previous_plan")); result["dependency_index"]=index; atomic_json(output,result); return result

def run_attempt(source: Path, output_root: Path, *, attempt_id: str, source_snapshot_sha256: str, started_at: str, finished_at: str):
    value=read_json(source); base=Path(output_root).parent.parent; accepted=base/"accepted.json"
    previous=None
    if accepted.exists():
        ref=value.get("previous_ref",{})
        if ref.get("job_id")!=JOB or ref.get("contract_id")!=CONTRACT:
            raise Blocked("dynamic rescope: previous accepted attempt reference is required")
        previous,_=synthesis_report.load_reference(base.parents[2],value["run_id"],ref)
        iteration=previous["iteration"]+1
    else:
        if value.get("previous_ref") is not None: raise Blocked("dynamic rescope: first iteration cannot name a predecessor")
        iteration=1
    index=dependency_index(value["run_id"],value["nodes"],value["edges"]); result=bounded_rescope(value["run_id"],index,value["changed_nodes"],iteration=iteration,max_iterations=value["max_iterations"],previous_plan=previous); result["dependency_index"]=index
    return control_process_worker.publish(run_id=value["run_id"],job_id=JOB,attempt_id=attempt_id,contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,source_snapshot_sha256=source_snapshot_sha256,input_binding=value,started_at=started_at,finished_at=finished_at)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
