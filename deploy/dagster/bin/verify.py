"""Verify the live deployment and optionally a completed production run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import urllib.request


WORKSPACE_QUERY = """
query VerifyDeployment {
  repositoriesOrError {
    __typename
    ... on RepositoryConnection {
      nodes {
        name
        location { name }
        pipelines { name }
        schedules {
          name
          cronSchedule
          executionTimezone
          scheduleState { status }
        }
      }
    }
    ... on PythonError { message }
  }
}
"""

RUN_QUERY = """
query VerifyRun($runId: ID!) {
  runOrError(runId: $runId) {
    __typename
    ... on Run {
      runId
      status
      pipelineName
      tags { key value }
      stepStats { stepKey status }
    }
    ... on RunNotFoundError { message }
    ... on PythonError { message }
  }
}
"""


def request_json(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def _workspace(url: str, document: dict) -> dict:
    request_json(f"{url}/server_info")
    payload = request_json(f"{url}/graphql", {"query": WORKSPACE_QUERY})
    result = payload.get("data", {}).get("repositoriesOrError", {})
    if result.get("__typename") != "RepositoryConnection":
        raise SystemExit(f"Dagster repository query failed: {result}")
    nodes = result.get("nodes", [])
    location = next(
        (node for node in nodes if node.get("location", {}).get("name") == "appsec_review"),
        None,
    )
    if location is None:
        raise SystemExit("Dagster code location appsec_review is not connected")
    jobs = sorted(item["name"] for item in location["pipelines"])
    schedules = sorted(location["schedules"], key=lambda item: item["name"])
    expected_jobs = sorted([*(value["name"] for value in document["jobs"].values()), "wave1_review"])
    expected_schedules = sorted(
        ({
            "name": f"{value['name']}_schedule",
            "cronSchedule": value["schedule"]["cron"],
            "executionTimezone": value["schedule"]["timezone"],
            "scheduleState": {"status": "RUNNING" if value["schedule"]["enabled"] else "STOPPED"},
        } for value in document["jobs"].values() if "schedule" in value),
        key=lambda item: item["name"],
    )
    if jobs != expected_jobs or schedules != expected_schedules:
        raise SystemExit(
            "semantic definition mismatch: "
            f"expected jobs={expected_jobs}, schedules={expected_schedules}; "
            f"found jobs={jobs}, schedules={schedules}"
        )
    return {
        "webserver": "healthy",
        "code_location": "appsec_review",
        "jobs": jobs,
        "schedules": schedules,
    }


def _relative(repository: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repository.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _run(url: str, run_id: str, repository: Path, document: dict) -> dict:
    payload = request_json(
        f"{url}/graphql",
        {"query": RUN_QUERY, "variables": {"runId": run_id}},
    )
    run = payload.get("data", {}).get("runOrError", {})
    if run.get("__typename") != "Run":
        raise SystemExit(f"Dagster run query failed: {run}")
    if run.get("status") != "SUCCESS":
        raise SystemExit(f"Dagster run is not successful: {run}")
    tags = {item["key"]: item["value"] for item in run.get("tags", [])}
    application_run_id = tags.get("appsec/application_run_id")
    if run.get("pipelineName") == "wave1_review":
        if not application_run_id:
            raise SystemExit("Dagster Wave 1 run does not contain the application run id")
        runs_dir = repository / document["runtime"]["runs_dir"]
        run_root = runs_dir / application_run_id
        orchestration_path = run_root / "data" / "orchestration" / "dagster" / f"{run_id}.json"
        orchestration_receipt = json.loads(orchestration_path.read_text(encoding="utf-8"))
        if orchestration_receipt.get("status") != "SUCCEEDED" or orchestration_receipt.get("orchestrator") != {
            "system": "dagster", "run_id": run_id
        }:
            raise SystemExit("application orchestration receipt does not link to the Dagster run")
        jobs = {}
        for job_id in (
            "job_review_intake",
            "job_target_catalog",
            "job_evidence_collection",
        ):
            pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
            pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
            handoff_path = run_root / pointer["handoff_path"]
            actual_hash = hashlib.sha256(handoff_path.read_bytes()).hexdigest()
            if actual_hash != pointer["handoff_sha256"]:
                raise SystemExit(f"{job_id} handoff pointer does not resolve")
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            attempt = handoff_path.parent
            status_path = attempt / "status.json"
            result_path = attempt / "result.json"
            status = json.loads(status_path.read_text(encoding="utf-8"))
            result = json.loads(result_path.read_text(encoding="utf-8"))
            if status.get("status") != "SUCCEEDED" or result.get("status") != "SUCCEEDED" or handoff.get("status") != "ACCEPTED":
                raise SystemExit(f"{job_id} application receipts are not accepted")
            if status.get("orchestration", {}).get("system") != "dagster":
                raise SystemExit(f"{job_id} accepted attempt lacks its originating Dagster link")
            publication = result.get("outputs", {}).get(
                "evidence_publication.publish_handoff",
                result.get("outputs", {}).get("publish_catalog.publish_handoff", {}),
            )
            job_report = {
                "attempt_id": handoff["attempt_id"],
                "handoff_sha256": actual_hash,
                "status_receipt": _relative(repository, status_path),
                "result_receipt": _relative(repository, result_path),
                "handoff_receipt": _relative(repository, handoff_path),
                "unit_statuses": {key: value["status"] for key, value in result["units"].items()},
                "gaps": publication.get("gaps", []),
            }
            if "dispositions" in publication:
                job_report["tool_dispositions"] = [
                    {
                        "tool_id": item["tool_id"],
                        "terminal_status": item["terminal_status"],
                        "record_count": item["record_count"],
                        "checkpoint_reused": item["checkpoint_reused"],
                    }
                    for item in publication["dispositions"]
                ]
            jobs[job_id] = job_report
        return {
            "dagster_run": {"run_id": run_id, "status": run["status"], "job": run["pipelineName"],
                            "step_statuses": {item["stepKey"]: item["status"] for item in run.get("stepStats", [])}},
            "application_run": {"run_id": application_run_id, "jobs": jobs,
                                "orchestration_receipt": _relative(repository, orchestration_path),
                                "resume_decisions": orchestration_receipt["decisions"]},
        }
    if run.get("pipelineName") != "third_party_data_sync":
        raise SystemExit(f"unsupported Dagster acceptance job: {run.get('pipelineName')}")
    attempt_id = tags.get("appsec/application_attempt_id")
    if not application_run_id or not attempt_id:
        raise SystemExit("Dagster run does not contain application correlation tags")

    job_id = "job_third_party_data_sync"
    runs_dir = repository / document["runtime"]["runs_dir"]
    attempt = runs_dir / application_run_id / "data" / "jobs" / job_id / "attempts" / attempt_id
    status_path = attempt / "status.json"
    result_path = attempt / "result.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if status.get("status") != "SUCCEEDED" or result.get("status") != "SUCCEEDED":
        raise SystemExit(f"application receipts are not successful: status={status}, result={result}")
    if status.get("orchestration") != {"system": "dagster", "run_id": run_id}:
        raise SystemExit("application status receipt does not link to the Dagster run")

    configured = document["jobs"][job_id]
    expected_units = {
        f"{step_id}.{task_id}"
        for step_id, step in configured["steps"].items()
        for task_id in step["tasks"]
    }
    unit_statuses = {
        unit_id: receipt.get("status") for unit_id, receipt in result.get("units", {}).items()
    }
    if set(unit_statuses) != expected_units or set(unit_statuses.values()) != {"SUCCEEDED"}:
        raise SystemExit(f"application unit receipt mismatch: {unit_statuses}")

    snapshots: dict[str, dict] = {}
    for step_id, step in configured["steps"].items():
        publication = result["outputs"].get(f"{step_id}.publish")
        if publication is None:
            continue
        feed_root = repository / step["settings"]["feed_root"]
        current_path = feed_root / "current.json"
        pointer = json.loads(current_path.read_text(encoding="utf-8"))
        identity = publication["identity"]
        if pointer.get("snapshot_id") != identity.get("snapshot_id"):
            raise SystemExit(f"{step_id} current pointer does not resolve to the published identity")
        manifest = feed_root / "snapshots" / pointer["snapshot_id"] / "manifest.json"
        if not manifest.is_file():
            raise SystemExit(f"{step_id} published manifest does not resolve: {manifest}")
        snapshots[step_id] = {
            "snapshot_id": identity["snapshot_id"],
            "manifest_sha256": pointer.get("manifest_sha256"),
            "current_pointer": _relative(repository, current_path),
            "manifest": _relative(repository, manifest),
        }

    receipts = {
        unit_id: _relative(
            repository,
            attempt / "steps" / receipt["step_id"] / "tasks" / receipt["task_id"] / "status.json",
        )
        for unit_id, receipt in result["units"].items()
    }
    return {
        "dagster_run": {
            "run_id": run_id,
            "status": run["status"],
            "job": run["pipelineName"],
            "step_statuses": {item["stepKey"]: item["status"] for item in run.get("stepStats", [])},
        },
        "application_run": {
            "run_id": application_run_id,
            "attempt_id": attempt_id,
            "status": status["status"],
            "trigger": status["trigger"],
            "status_receipt": _relative(repository, status_path),
            "result_receipt": _relative(repository, result_path),
            "unit_statuses": unit_statuses,
            "unit_receipts": receipts,
            "failed_units": result.get("failed_units", []),
            "skipped_units": result.get("skipped_units", []),
        },
        "published_snapshots": snapshots,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    parser.add_argument("--run-id", help="also verify this completed Dagster run and its application receipts")
    parser.add_argument("--evidence", type=Path, help="write the concise verification report to this path")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    config_path = repository / "appsec-review.toml"
    document = tomllib.loads(config_path.read_text(encoding="utf-8"))
    report = {"deployment": _workspace(args.url, document)}
    if args.run_id:
        report["acceptance_run"] = _run(args.url, args.run_id, repository, document)
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        with args.evidence.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
