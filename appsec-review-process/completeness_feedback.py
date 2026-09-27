#!/usr/bin/env python3
"""Separate deterministic process for completeness audit and bounded synthetic feedback."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import completeness_audit, synthetic_feedback

JOB = "completeness-feedback"
RESULT = "completeness-feedback.json"

def run(source: Path, output: Path):
    value=read_json(source); audit=completeness_audit(value["run_id"],value["expected"],value["observed"],value["declared_gaps"])
    feedback=synthetic_feedback(value["run_id"],audit,value["routes"],iteration=value["iteration"],max_iterations=value["max_iterations"],prior_missing=value.get("prior_missing")); result={"schema":"appsec-review/completeness-feedback/1.0","run_id":value["run_id"],"audit":audit,"feedback":feedback}; atomic_json(output,result); return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
