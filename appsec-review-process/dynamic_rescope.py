#!/usr/bin/env python3
"""Separate deterministic process for dependency indexing and bounded affected-only rescope."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import bounded_rescope, dependency_index

JOB = "dynamic-rescope"
RESULT = "bounded-rescope-plan.json"

def run(source: Path, output: Path):
    value=read_json(source); index=dependency_index(value["run_id"],value["nodes"],value["edges"])
    result=bounded_rescope(value["run_id"],index,value["changed_nodes"],iteration=value["iteration"],max_iterations=value["max_iterations"],prior_affected=value.get("prior_affected")); result["dependency_index"]=index; atomic_json(output,result); return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
