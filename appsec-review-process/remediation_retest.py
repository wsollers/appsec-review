#!/usr/bin/env python3
"""Separate deterministic process for remediation proposals and same-environment retest decisions."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from execution_state import Blocked, atomic_json, read_json
from review_control_loops import remediation_proposals, same_environment_retest
import control_process_worker

JOB = "remediation-retest-feedback"
RESULT = "remediation-retest.json"
CONTRACT = "remediation-retest-feedback"

def run(source: Path, output: Path):
    value=read_json(source); proposals=remediation_proposals(value["run_id"],value["verified_claims"],value["proposals"]); retests=[]
    by_id={row["proposal_id"]:row for row in proposals["proposals"]}
    seen=set()
    for request in value.get("retests",[]):
        proposal_id=request["proposal_id"]
        if proposal_id in seen: raise Blocked("duplicate terminal retest for proposal")
        seen.add(proposal_id)
        retests.append(same_environment_retest(value["run_id"],by_id[proposal_id],request["original_environment"],{**request["retest"],"proposal_id":proposal_id},request["verifier"]))
    result={"schema":"appsec-review/remediation-retest-feedback/1.0","run_id":value["run_id"],"proposals":proposals["proposals"],"retests":sorted(retests,key=lambda row:row["proposal_id"])}; atomic_json(output,result); return result

def run_attempt(source: Path, output_root: Path, *, attempt_id: str, source_snapshot_sha256: str, started_at: str, finished_at: str):
    value=read_json(source); proposals=remediation_proposals(value["run_id"],value["verified_claims"],value["proposals"]); by_id={row["proposal_id"]:row for row in proposals["proposals"]}; requests=value.get("retests",[]); ids=[item["proposal_id"] for item in requests]
    if len(ids)!=len(set(ids)): raise Blocked("duplicate terminal retest for proposal")
    retests=[same_environment_retest(value["run_id"],by_id[item["proposal_id"]],item["original_environment"],{**item["retest"],"proposal_id":item["proposal_id"]},item["verifier"]) for item in requests]; result={"schema":"appsec-review/remediation-retest-feedback/1.0","run_id":value["run_id"],"proposals":proposals["proposals"],"retests":sorted(retests,key=lambda row:row["proposal_id"])}
    return control_process_worker.publish(run_id=value["run_id"],job_id=JOB,attempt_id=attempt_id,contract_id=CONTRACT,result_name=RESULT,result=result,output_root=output_root,source_snapshot_sha256=source_snapshot_sha256,input_binding=value,started_at=started_at,finished_at=finished_at)

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--input",type=Path,required=True); parser.add_argument("--output",type=Path,required=True); args=parser.parse_args(); print(json.dumps(run(args.input,args.output),indent=2))
