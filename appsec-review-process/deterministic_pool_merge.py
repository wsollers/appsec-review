#!/usr/bin/env python3
"""Separate deterministic process for typed pool-result merge."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import deterministic_merge
import control_process_worker

JOB = "deterministic-pool-merge"
RESULT = "deterministic-pool-merge.json"
CONTRACT = "deterministic-pool-merge"

def run(source: Path, output: Path):
    value = read_json(source)
    result = deterministic_merge(value["run_id"], value["expected_workers"], value["worker_results"])
    atomic_json(output, result); return result

def run_attempt(source: Path, output_root: Path, *, attempt_id: str, source_snapshot_sha256: str,
                started_at: str, finished_at: str):
    value=read_json(source); result=deterministic_merge(value["run_id"],value["expected_workers"],value["worker_results"])
    return control_process_worker.publish(run_id=value["run_id"],job_id=JOB,attempt_id=attempt_id,
        contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,
        source_snapshot_sha256=source_snapshot_sha256,input_binding=value,started_at=started_at,finished_at=finished_at)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    print(json.dumps(run(args.input,args.output),indent=2))
