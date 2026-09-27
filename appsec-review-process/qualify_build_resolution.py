#!/usr/bin/env python3
"""Live fault/recovery qualification for an SAT run that has passed build-resolution."""
from __future__ import annotations

import argparse
import json
import uuid

import build_resolution as worker
from execution_state import atomic_json, data_path, file_hash, read_json
from launch_job import TERMINAL, graphql, launch


def active_runs():
    query = """query { runsOrError(limit:100) { __typename ... on Runs {
      results { runId status jobName } } ... on PythonError { message } } }"""
    result = graphql(query, {})["runsOrError"]
    if result.get("__typename") != "Runs": raise RuntimeError("cannot inspect Dagster runs")
    return [x for x in result["results"] if x["status"] not in TERMINAL]


def evidence(run_id, pointer):
    attempt = worker.validate(run_id, pointer)
    result = read_json(attempt / worker.RESULT); receipts = read_json(attempt / worker.RECEIPTS)
    return {"attempt_id": attempt.name, "envelope": str(attempt / "result.json"),
            "envelope_sha256": file_hash(attempt / "result.json"),
            "lock": str(attempt / worker.LOCK_FILE), "lock_sha256": file_hash(attempt / worker.LOCK_FILE),
            "image_id": result["units"][0]["image_id"], "image_digest": result["units"][0]["image_digest"],
            "compile_commands": result["units"][0]["compile_commands"],
            "b13_result_sha256": receipts[0]["expected_result_sha256"]}


def qualify(run_id):
    active = active_runs()
    if active: raise RuntimeError("active Dagster runs exist; qualification did not start: " + json.dumps(active))
    base = worker.root(run_id); success_pointer = read_json(base / "accepted.json")
    success = evidence(run_id, success_pointer)

    reuse_launch = launch(run_id, job=worker.DAGSTER_JOB, launch_id="stage13-reuse", wait=True, timeout=1800)
    reuse_pointer = read_json(base / "accepted.json")
    if reuse_launch["status"] != "SUCCESS" or reuse_pointer != success_pointer:
        raise RuntimeError("unchanged stage-13 inputs did not reuse the immutable attempt")

    attempt = base / "attempts" / success_pointer["attempt_id"]
    lock = read_json(attempt / worker.LOCK_FILE); lock["source_revision"] = "tampered"
    atomic_json(attempt / worker.LOCK_FILE, lock)
    tamper_launch = launch(run_id, job=worker.DAGSTER_JOB, launch_id="stage13-tamper", wait=True, timeout=300)
    tamper_pointer = read_json(base / "accepted.json")
    if tamper_launch["status"] != "FAILURE" or tamper_pointer.get("status") != "BLOCKED" \
            or tamper_pointer.get("attempt_id") == success_pointer["attempt_id"]:
        raise RuntimeError("tampered accepted attempt was not rejected by a newer non-current pointer")

    worker.stage_control(run_id, "exit-nonzero")
    failed_launch = launch(run_id, job=worker.DAGSTER_JOB, launch_id="stage13-newer-failure",
                           wait=True, timeout=1800)
    failed_pointer = read_json(base / "accepted.json")
    if failed_launch["status"] != "FAILURE" or failed_pointer.get("status") != "FAILED" \
            or failed_pointer.get("attempt_id") == success_pointer["attempt_id"]:
        raise RuntimeError("newer real container failure did not block the old success")

    worker.stage_control(run_id, "success")
    recovery_launch = launch(run_id, job=worker.DAGSTER_JOB, launch_id="stage13-recovery",
                             wait=True, timeout=1800)
    recovery_pointer = read_json(base / "accepted.json")
    if recovery_launch["status"] != "SUCCESS" or recovery_pointer["attempt_id"] == success_pointer["attempt_id"]:
        raise RuntimeError("recovery failed or fell back to the old successful attempt")
    recovery = evidence(run_id, recovery_pointer)

    final_launch = launch(run_id, job=worker.DAGSTER_JOB, launch_id="stage13-recovery-reuse",
                          wait=True, timeout=300)
    if final_launch["status"] != "SUCCESS" or read_json(base / "accepted.json") != recovery_pointer:
        raise RuntimeError("recovered attempt was not immutably reusable")

    report_dir = data_path(run_id, "qualification", "build-resolution-" + uuid.uuid4().hex[:8])
    report = {"schema": "appsec-review/build-resolution-live-qualification/1", "status": "PASS",
        "engagement_run_id": run_id, "job": worker.DAGSTER_JOB,
        "success": success, "reuse": {"launch": reuse_launch, "attempt_id": reuse_pointer["attempt_id"]},
        "tamper_rejection": {"launch": tamper_launch, "pointer": tamper_pointer},
        "newer_failure": {"launch": failed_launch, "pointer": failed_pointer},
        "recovery": {"launch": recovery_launch, **recovery},
        "recovery_reuse": {"launch": final_launch, "attempt_id": recovery_pointer["attempt_id"]},
        "permissions": ["package-restore:apt@archive.ubuntu.com:80", "target-execution:build-resolution-v1@."],
        "scope": "hello-autotools stage 13 only; no repository Dockerfile, tests, or built target executed"}
    atomic_json(report_dir / "report.json", report)
    latest = {"status": "PASS", "run_id": run_id, "report": str(report_dir / "report.json"),
              "sha256": file_hash(report_dir / "report.json")}
    atomic_json(data_path(run_id, "qualification", "build-resolution-latest.json"), latest)
    return latest


if __name__ == "__main__":
    parser=argparse.ArgumentParser(); parser.add_argument("--run-id", required=True); args=parser.parse_args()
    print(json.dumps(qualify(args.run_id), indent=2))
