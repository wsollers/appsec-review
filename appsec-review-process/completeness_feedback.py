#!/usr/bin/env python3
"""Separate deterministic process for completeness audit and bounded synthetic feedback."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import Blocked, atomic_json, read_json
from review_control_loops import completeness_audit, synthetic_feedback
import control_process_worker
import registry_paths

JOB = "completeness-feedback"
RESULT = "completeness-feedback.json"
CONTRACT = "completeness-feedback"

def _registered_routes(routes):
    registered={path.stem for path in registry_paths.JOB_TEMPLATES_DIR.glob("*.json")}
    if any(job not in registered for job in routes.values()):
        raise Blocked("synthetic feedback route is not a registered job")

def run(source: Path, output: Path):
    value=read_json(source); _registered_routes(value["routes"]); audit=completeness_audit(value["run_id"],value["expected"],value["observed"],value["declared_gaps"],subject_sha256=value["subject_sha256"])
    feedback=synthetic_feedback(value["run_id"],audit,value["routes"],iteration=value["iteration"],max_iterations=value["max_iterations"],previous_feedback=value.get("previous_feedback")); result={"schema":"appsec-review/completeness-feedback/1.0","run_id":value["run_id"],"audit":audit,"feedback":feedback}; atomic_json(output,result); return result

def run_attempt(source: Path, output_root: Path, *, attempt_id: str, source_snapshot_sha256: str, started_at: str, finished_at: str):
    raise Blocked("combined completeness/feedback publication is retired; use the two separate lifecycle jobs")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
