#!/usr/bin/env python3
"""Separate evidence-bound completeness-audit lifecycle process."""
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import completeness_audit
import control_process_worker

JOB="completeness-audit"; RESULT="completeness-audit.json"; CONTRACT="completeness-audit"

def run(source:Path,output:Path):
    value=read_json(source); result=completeness_audit(value["run_id"],value["expected"],value["observed"],value["declared_gaps"]); atomic_json(output,result); return result

def run_attempt(source:Path,output_root:Path,*,attempt_id:str,source_snapshot_sha256:str,started_at:str,finished_at:str):
    value=read_json(source); result=completeness_audit(value["run_id"],value["expected"],value["observed"],value["declared_gaps"])
    return control_process_worker.publish(run_id=value["run_id"],job_id=JOB,attempt_id=attempt_id,contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,source_snapshot_sha256=source_snapshot_sha256,input_binding=value,started_at=started_at,finished_at=finished_at)
