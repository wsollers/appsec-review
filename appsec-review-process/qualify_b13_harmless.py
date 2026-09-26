#!/usr/bin/env python3
"""Bounded live Dagster qualification for the Phase 3 harmless B13 job.

Runs success, immutable reuse, a real non-zero container failure, recovery without falling back to
the older success, and reuse of the recovered success. Existing run/build/registry state is never
deleted or rewritten.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import uuid

import b13_harmless
from execution_state import atomic_json, data_path, file_hash, read_json
from launch_job import TERMINAL, graphql, launch
import phase1
import run_process


def active_runs() -> list[dict]:
    query = """query { runsOrError(limit:100) { __typename ... on Runs {
      results { runId status jobName } } ... on PythonError { message } } }"""
    result = graphql(query, {})["runsOrError"]
    if result.get("__typename") != "Runs":
        raise RuntimeError("cannot inspect Dagster runs")
    return [item for item in result["results"] if item["status"] not in TERMINAL]


def attempt_evidence(run_id: str, pointer: dict) -> dict:
    attempt = b13_harmless.validate(run_id, pointer)
    receipt = read_json(attempt / b13_harmless.RECEIPT_FILE)
    adapter = read_json(attempt / "logs/container/container-result.json")
    return {
        "attempt_id": attempt.name,
        "envelope": str(attempt / "result.json"),
        "envelope_sha256": file_hash(attempt / "result.json"),
        "image_reference": receipt["image_reference"],
        "expected_result_sha256": receipt["expected_result_sha256"],
        "adapter_result_sha256": adapter["result_sha256"],
        "permission_fingerprint_sha256": receipt["permission_fingerprint_sha256"],
    }


def qualify(target: Path) -> dict:
    active = active_runs()
    if active:
        raise RuntimeError("active Dagster runs exist; qualification did not start: " + json.dumps(active))
    run_id = "phase3-b13-" + uuid.uuid4().hex[:10]
    run_process.init_run(run_id)
    phase1.stage(run_id, target, "fixture-harmless",
                 "Bounded Phase 3 B13 harmless-container qualification", ["Linux"],
                 budget="probe", permissions=["read-source"],
                 execution_environment="dagster-read-only-linux")
    b13_harmless.stage_control(run_id, "success")

    success = launch(run_id, job=b13_harmless.DAGSTER_JOB, launch_id="phase3-success",
                     wait=True, timeout=300)
    if success["status"] != "SUCCESS":
        raise RuntimeError("initial harmless-container launch failed")
    success_pointer = read_json(b13_harmless.root(run_id) / "accepted.json")
    success_evidence = attempt_evidence(run_id, success_pointer)

    reuse = launch(run_id, job=b13_harmless.DAGSTER_JOB, launch_id="phase3-reuse",
                   wait=True, timeout=300)
    if reuse["status"] != "SUCCESS":
        raise RuntimeError("reuse launch failed")
    reuse_pointer = read_json(b13_harmless.root(run_id) / "accepted.json")
    if reuse_pointer != success_pointer:
        raise RuntimeError("unchanged qualification did not reuse the immutable attempt")

    b13_harmless.stage_control(run_id, "exit-nonzero")
    failed = launch(run_id, job=b13_harmless.DAGSTER_JOB, launch_id="phase3-failure",
                    wait=True, timeout=300)
    if failed["status"] != "FAILURE":
        raise RuntimeError("non-zero fault launch did not fail")
    failed_pointer = read_json(b13_harmless.root(run_id) / "accepted.json")
    if failed_pointer.get("status") != "FAILED" or failed_pointer.get("attempt_id") == success_pointer["attempt_id"]:
        raise RuntimeError("newer failure did not block the old success")

    b13_harmless.stage_control(run_id, "success")
    recovery = launch(run_id, job=b13_harmless.DAGSTER_JOB, launch_id="phase3-recovery",
                      wait=True, timeout=300)
    if recovery["status"] != "SUCCESS":
        raise RuntimeError("recovery launch failed")
    recovery_pointer = read_json(b13_harmless.root(run_id) / "accepted.json")
    if recovery_pointer["attempt_id"] == success_pointer["attempt_id"]:
        raise RuntimeError("recovery fell back to the older successful attempt")
    recovery_evidence = attempt_evidence(run_id, recovery_pointer)

    final_reuse = launch(run_id, job=b13_harmless.DAGSTER_JOB, launch_id="phase3-recovery-reuse",
                         wait=True, timeout=300)
    if final_reuse["status"] != "SUCCESS" or read_json(
            b13_harmless.root(run_id) / "accepted.json") != recovery_pointer:
        raise RuntimeError("recovered attempt was not reusable")

    report_dir = data_path(run_id, "qualification", "b13-harmless-" + uuid.uuid4().hex[:8])
    report = {
        "schema": "appsec-review/b13-harmless-live-qualification/1.0",
        "status": "PASS", "engagement_run_id": run_id,
        "job": b13_harmless.DAGSTER_JOB,
        "success": {"launch": success, **success_evidence},
        "reuse": {"launch": reuse, "attempt_id": reuse_pointer["attempt_id"]},
        "failure": {"launch": failed, "attempt_id": failed_pointer["attempt_id"],
                    "pointer_status": failed_pointer["status"]},
        "recovery": {"launch": recovery, **recovery_evidence},
        "recovery_reuse": {"launch": final_reuse,
                           "attempt_id": recovery_pointer["attempt_id"]},
        "scope": "fixture-harmless only; no target mount, network, scanner, finding or severity claim",
    }
    atomic_json(report_dir / "report.json", report)
    latest = {"status": "PASS", "run_id": run_id, "report": str(report_dir / "report.json"),
              "sha256": file_hash(report_dir / "report.json")}
    atomic_json(data_path(run_id, "qualification", "b13-harmless-latest.json"), latest)
    return latest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True,
                        help="existing harmless fixture checkout used only to stage the run manifest")
    args = parser.parse_args(argv)
    result = qualify(args.target.resolve(strict=True))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
