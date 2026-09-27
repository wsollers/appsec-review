#!/usr/bin/env python3
"""Separate deterministic process for evidence-qualified producer quorum."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import evidence_qualified_quorum

JOB = "evidence-qualified-quorum"
RESULT = "evidence-qualified-quorum.json"

def run(source: Path, output: Path):
    value=read_json(source); result=evidence_qualified_quorum(value["run_id"],value["merge"],minimum_producers=value["minimum_producers"],require_complete_pool=value.get("require_complete_pool",True)); atomic_json(output,result); return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
