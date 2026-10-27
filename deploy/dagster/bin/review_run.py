"""Submit, inspect, or wait for a wave1 review through the live Dagster instance."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import tomllib
from urllib.request import Request, urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[3]
QUERY = """query ReviewRun($runId: ID!) {
  runOrError(runId: $runId) {
    __typename
    ... on Run {
      runId status pipelineName tags { key value }
      stepStats { stepKey status }
    }
    ... on RunNotFoundError { message }
    ... on PythonError { message }
  }
}"""
TERMINAL = {"SUCCESS", "FAILURE", "CANCELED"}


def verify_build_profile_images(document: dict, *, runner=subprocess.run) -> None:
    if any(name.startswith("APPSEC_NATIVE_") for name in os.environ):
        raise RuntimeError("Compose cannot execute native configuration; ambient engine fallback is prohibited")
    profiles = document["jobs"]["job_project_build"]["settings"]["profiles"]
    mismatches = []
    for name, profile in sorted(profiles.items()):
        inspected = runner(
            ["docker", "image", "inspect", profile["tag"], "--format", "{{.Id}}"],
            cwd=ROOT, capture_output=True, text=True, timeout=60, check=False)
        actual = inspected.stdout.strip() if inspected.returncode == 0 else "unavailable"
        if actual != profile["image_id"]:
            mismatches.append(f"{name}: expected {profile['image_id']}, resolved {actual}")
    if mismatches:
        raise RuntimeError("project build image preflight failed; " + "; ".join(mismatches))


def get_run(url: str, run_id: str) -> dict:
    request = Request(url, data=json.dumps({"query": QUERY, "variables": {"runId": run_id}}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=15) as response:
        payload = json.load(response)
    if payload.get("errors"):
        raise RuntimeError(str(payload["errors"]))
    run = payload.get("data", {}).get("runOrError", {})
    if run.get("__typename") != "Run":
        raise RuntimeError(run.get("message") or f"Dagster run query failed: {run}")
    return run


def show_run(run: dict) -> None:
    tags = {item["key"]: item["value"] for item in run.get("tags", [])}
    active = [item["stepKey"] for item in run.get("stepStats", [])
              if item.get("status") in {"IN_PROGRESS", "STARTING"}]
    print(f"dagster_run_id={run['runId']} application_run_id="
          f"{tags.get('appsec/application_run_id', 'unallocated')} "
          f"status={run['status']} active_steps={','.join(active[:5]) or '-'}", flush=True)
    if run["status"] in {"FAILURE", "CANCELED"}:
        path = ROOT / "runs" / "metadata" / "dagster-error-state" / f"{run['runId']}.log"
        if path.is_file():
            print("\n".join(path.read_text(encoding="utf-8").splitlines()[-6:]), flush=True)
        else:
            failed = [item["stepKey"] for item in run.get("stepStats", [])
                      if item.get("status") == "FAILURE"]
            print(f"error_state_file=pending failed_steps={','.join(failed[-5:]) or '-'}", flush=True)


def submit(run_id: str) -> None:
    document = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))
    verify_build_profile_images(document)
    command = ["docker", "compose", "--env-file", "deploy/dagster/.env",
               "-f", "deploy/dagster/compose.yaml", "exec", "-T", "webserver",
               "dagster", "job", "launch", "-w", "/opt/dagster/home/workspace.yaml",
               "-l", "appsec_review", "-j", "wave1_review", "--run-id", run_id]
    subprocess.run(command, cwd=ROOT, check=True)
    print(f"submitted_dagster_run_id={run_id}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("submit", "status", "watch"))
    parser.add_argument("--run-id", help="Dagster UUID; generated for submit")
    parser.add_argument("--url", default="http://127.0.0.1:3000/graphql")
    parser.add_argument("--interval-seconds", type=int, default=30)
    args = parser.parse_args()
    if args.action != "submit" and not args.run_id:
        parser.error("--run-id is required for status and watch")
    if args.interval_seconds < 1:
        parser.error("--interval-seconds must be positive")
    run_id = args.run_id or str(uuid4())
    if args.action == "submit":
        submit(run_id)
    while True:
        run = get_run(args.url, run_id)
        if run["pipelineName"] != "wave1_review":
            raise RuntimeError(f"run {run_id} is not wave1_review")
        show_run(run)
        if args.action != "watch" or run["status"] in TERMINAL:
            return 0 if run["status"] not in {"FAILURE", "CANCELED"} else 1
        time.sleep(args.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
