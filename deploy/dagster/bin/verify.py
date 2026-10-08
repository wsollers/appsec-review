"""Verify the live deployment and optionally a completed production run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import urllib.request
from collections import Counter
from datetime import datetime


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
    composed = ["wave1_review"]
    if "job_ci_configuration_analysis" in document["jobs"]:
        composed.append("ci_configuration_review")
    if "job_project_build" in document["jobs"]:
        composed.append("project_build_review")
    expected_jobs = sorted([*(value["name"] for value in document["jobs"].values()), *composed])
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
    if run.get("pipelineName") in {"wave1_review", "ci_configuration_review", "project_build_review"}:
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
        job_ids = (
            "job_review_intake",
            "job_target_catalog",
            "job_target_analysis_plan",
            "job_project_build",
            "job_cpp_compiled_analysis",
            "job_post_build_security_assessment",
            "job_evidence_collection",
        ) if run.get("pipelineName") == "wave1_review" else ((
            "job_review_intake", "job_target_catalog", "job_ci_configuration_analysis",
        ) if run.get("pipelineName") == "ci_configuration_review" else (
            "job_review_intake", "job_target_catalog", "job_target_analysis_plan", "job_project_build",
        ))
        for job_id in job_ids:
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
            accepted_statuses = {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
            if (status.get("status") not in accepted_statuses or
                    result.get("status") not in accepted_statuses or handoff.get("status") != "ACCEPTED"):
                raise SystemExit(f"{job_id} application receipts are not accepted")
            if status.get("orchestration", {}).get("system") != "dagster":
                raise SystemExit(f"{job_id} accepted attempt lacks its originating Dagster link")
            publication_units = {
                "job_review_intake": "publish_intake.publish_handoff",
                "job_target_catalog": "publish_catalog.publish_handoff",
                "job_target_analysis_plan": "plan_acceptance.publish_handoff",
                "job_project_build": "acceptance.publish_handoff",
                "job_cpp_compiled_analysis": "acceptance.publish_handoff",
                "job_post_build_security_assessment": "publication.publish_handoff",
                "job_evidence_collection": "evidence_publication.publish_handoff",
                "job_ci_configuration_analysis": "ci_coverage.publish_handoff",
            }
            publication = result.get("outputs", {}).get(publication_units[job_id], {})
            job_report = {
                "attempt_id": handoff["attempt_id"],
                "handoff_sha256": actual_hash,
                "status_receipt": _relative(repository, status_path),
                "result_receipt": _relative(repository, result_path),
                "handoff_receipt": _relative(repository, handoff_path),
                "status": status["status"],
                "unit_count": len(result["units"]),
                "unit_status_counts": dict(sorted(Counter(
                    value["status"] for value in result["units"].values()).items())),
                "gap_count": len(publication.get("gaps", [])),
            }
            if job_id == "job_evidence_collection" and isinstance(publication.get("dispositions"), list):
                job_report["tool_dispositions"] = [
                    {
                        "tool_id": item["tool_id"],
                        "shard_id": item["shard_id"],
                        "terminal_status": item["terminal_status"],
                        "record_count": item["record_count"],
                        "checkpoint_reused": item["checkpoint_reused"],
                        "index_reused": item["index_reused"],
                    }
                    for item in publication["dispositions"]
                ]
                job_report["reuse_summary"] = {
                    "checkpoint_reused": sum(bool(item.get("checkpoint_reused"))
                                             for item in publication["dispositions"]),
                    "index_reused": sum(bool(item.get("index_reused"))
                                        for item in publication["dispositions"]),
                }
                job_report["gaps"] = publication.get("gaps", [])
                job_report["index_manifest"] = publication.get("index_manifest")
                scans = [value for key, value in result["units"].items() if key.endswith("_scan")]
                boundaries = []
                for receipt in scans:
                    boundaries.extend(((datetime.fromisoformat(receipt["started_at"]), 1),
                                       (datetime.fromisoformat(receipt["completed_at"]), -1)))
                active = peak = 0
                for _, delta in sorted(boundaries, key=lambda value: (value[0], value[1])):
                    active += delta
                    peak = max(peak, active)
                indexes = [value for key, value in result["units"].items() if key.endswith("_index")]
                barrier = result["units"]["evidence_publication.assemble_manifest"]
                latest_index = max(datetime.fromisoformat(value["completed_at"]) for value in indexes)
                barrier_start = datetime.fromisoformat(barrier["started_at"])
                job_report["concurrency_proof"] = {
                    "scanner_interval_count": len(scans),
                    "observed_peak_overlapping_scanners": peak,
                    "latest_producer_index_completed_at": latest_index.isoformat(),
                    "manifest_started_at": barrier_start.isoformat(),
                    "manifest_waited_for_all_producer_indexes": barrier_start >= latest_index,
                }
            if job_id == "job_cpp_compiled_analysis":
                summary_path = run_root / publication["artifact"]["path"]
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                manifest_path = run_root / publication["index_manifest"]["path"]
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                cpp_shards = [item for item in manifest["indexes"]
                              if str(item.get("shard_id", "")).startswith("cpp-case-")]
                branches = [value for key, value in result["units"].items()
                            if key.split(".", 1)[0] in {"compiled", "ast", "ir", "codeql", "joern", "binary"}]
                job_report["cpp_wave"] = {
                    "case_count": summary["case_count"],
                    "branch_count": summary["branch_count"],
                    "cpp_shard_count": len(cpp_shards),
                    "manifest_index_count": len(manifest["indexes"]),
                    "manifest_sha256": publication["index_manifest"]["sha256"],
                    "disposition_counts": dict(sorted(Counter(
                        publication.get("dispositions", {}).values()).items())),
                    "msbuild": {
                        key: publication.get("dispositions", {}).get(key)
                        for key in sorted(publication.get("dispositions", {}))
                        if key.startswith("case-038:")
                    },
                    "terminal_branch_count": len(branches),
                    "all_cpp_shards_preserved": len(cpp_shards) == summary["case_count"] * summary["branch_count"],
                }
            if job_id == "job_post_build_security_assessment":
                summary_path = run_root / publication["artifact"]["path"]
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                manifest_path = run_root / publication["index_manifest"]["path"]
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                build_security_shards = [
                    item for item in manifest["indexes"]
                    if item.get("name") == "build_security"
                ]
                indexes = [
                    value for key, value in result["outputs"].items()
                    if key.startswith("index.")
                ]
                job_report["post_build_security"] = {
                    "case_count": summary["case_count"],
                    "shard_count": summary["shard_count"],
                    "manifest_shard_count": len(build_security_shards),
                    "rule_version": summary["rule_version"],
                    "parser_version": summary["parser_version"],
                    "normalizer_version": summary["normalizer_version"],
                    "gap_count": len(summary.get("gaps", [])),
                    "index_reused": sum(bool(value.get("index_reused")) for value in indexes),
                    "all_build_security_shards_preserved": (
                        len(build_security_shards) == summary["case_count"] == summary["shard_count"]
                    ),
                }
            if job_id == "job_ci_configuration_analysis":
                manifest_path = run_root / publication["index_manifest"]["path"]
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                ci_shards = [item for item in manifest["indexes"]
                             if str(item.get("shard_id", "")).startswith("ci_")]
                coverage = json.loads((run_root / publication["coverage"]["path"]).read_text(encoding="utf-8"))
                job_report["ci_configuration"] = {
                    "finding_count": publication["finding_count"],
                    "ci_shard_count": len(ci_shards),
                    "definitions_by_provider": coverage["definitions_by_provider"],
                    "coverage_status": coverage["coverage_status"],
                    "tool_count": len(coverage["tools"]),
                    "manifest_sha256": publication["index_manifest"]["sha256"],
                    "all_provider_tools_joined": len(coverage["tools"]) == 15,
                }
            jobs[job_id] = job_report
        step_statuses = [item["status"] for item in run.get("stepStats", [])]
        return {
            "dagster_run": {"run_id": run_id, "status": run["status"], "job": run["pipelineName"],
                            "step_count": len(step_statuses),
                            "step_status_counts": dict(sorted(Counter(step_statuses).items()))},
            "application_run": {"run_id": application_run_id, "jobs": jobs,
                                "orchestration_receipt": _relative(repository, orchestration_path),
                                "completion_status": orchestration_receipt.get("completion_status"),
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
