#!/usr/bin/env python3
"""Separate deterministic process for remediation proposals and same-environment retest decisions."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import atomic_json, read_json
from review_control_loops import remediation_proposals, same_environment_retest

JOB = "remediation-retest-feedback"
RESULT = "remediation-retest.json"

def run(source: Path, output: Path):
    value=read_json(source); proposals=remediation_proposals(value["run_id"],value["verified_claims"],value["proposals"]); retests=[]
    by_id={row["proposal_id"]:row for row in proposals["proposals"]}
    for request in value.get("retests",[]):
        retests.append(same_environment_retest(value["run_id"],by_id[request["proposal_id"]],request["original_environment"],request["retest"],request["verifier"]))
    result={"schema":"appsec-review/remediation-retest-feedback/1.0","run_id":value["run_id"],"proposals":proposals["proposals"],"retests":sorted(retests,key=lambda row:row["proposal_id"])}; atomic_json(output,result); return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
