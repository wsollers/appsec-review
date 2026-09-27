#!/usr/bin/env python3
"""Separate deterministic process for typed pool-result merge."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import deterministic_merge

JOB = "deterministic-pool-merge"
RESULT = "deterministic-pool-merge.json"

def run(source: Path, output: Path):
    value = read_json(source)
    result = deterministic_merge(value["run_id"], value["expected_workers"], value["worker_results"])
    atomic_json(output, result); return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args()
    print(json.dumps(run(args.input,args.output),indent=2))
