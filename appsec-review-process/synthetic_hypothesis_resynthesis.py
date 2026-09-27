#!/usr/bin/env python3
"""Separate bounded synthetic-hypothesis resynthesis lifecycle process."""
from pathlib import Path
from execution_state import Blocked, atomic_json, read_json
from review_control_loops import synthetic_feedback
import control_process_worker

JOB="synthetic-hypothesis-resynthesis"; RESULT="synthetic-hypothesis-resynthesis.json"; CONTRACT="synthetic-hypothesis-resynthesis"

def _routes(routes):
    registered={path.stem for path in (Path(__file__).resolve().parent/"registry"/"job-templates").glob("*.json")}
    if any(job not in registered for job in routes.values()): raise Blocked("synthetic resynthesis: route is not registered")

def run(source:Path,output:Path):
    value=read_json(source); _routes(value["routes"]); result=synthetic_feedback(value["run_id"],value["audit"],value["routes"],iteration=value["iteration"],max_iterations=value["max_iterations"],previous_feedback=value.get("previous_feedback")); atomic_json(output,result); return result

def run_attempt(source:Path,output_root:Path,*,attempt_id:str,source_snapshot_sha256:str,started_at:str,finished_at:str):
    value=read_json(source); _routes(value["routes"]); result=synthetic_feedback(value["run_id"],value["audit"],value["routes"],iteration=value["iteration"],max_iterations=value["max_iterations"],previous_feedback=value.get("previous_feedback"))
    return control_process_worker.publish(run_id=value["run_id"],job_id=JOB,attempt_id=attempt_id,contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,source_snapshot_sha256=source_snapshot_sha256,input_binding=value,started_at=started_at,finished_at=finished_at)
