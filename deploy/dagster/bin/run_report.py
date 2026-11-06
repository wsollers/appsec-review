"""Report live Dagster state beside redacted application timing summaries."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from itertools import islice
from urllib.request import Request, urlopen


QUERY = """query RunReport {
  runsOrError(limit: 1000) {
    __typename
    ... on Runs { results { runId status pipelineName startTime endTime tags { key value }
      stepStats { stepKey status startTime endTime } } }
    ... on PythonError { message }
  }
}"""


def build_report(repository: Path, dispatches: list[dict], *, now: datetime,
                 stale_seconds: int = 3600, max_runs: int = 100) -> dict:
    from appsec_review.observability.operator import OperatorFollower

    if not 1 <= max_runs <= 1000 or len(dispatches) > 1000:
        raise ValueError("operator report scope exceeds configured bounds")
    completed, running, queued, stale, orphaned, unknown = [], [], [], [], [], []
    reports, gaps, operations = {}, [], []
    runs = repository / "runs"
    names = set()
    if runs.exists():
        with os.scandir(runs) as entries:
            entries = list(islice(entries, max_runs + 1))
        if len(entries) > max_runs:
            gaps.append("run_scan_limit_reached")
        for entry in entries[:max_runs]:
            if entry.is_dir(follow_symlinks=False) and re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", entry.name):
                names.add(entry.name)
    for dispatch in dispatches:
        tags = {item["key"]: item["value"] for item in dispatch.get("tags", [])}
        name = tags.get("appsec/application_run_id")
        if isinstance(name, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{4}", name):
            names.add(name)
    if len(names) > max_runs:
        gaps.append("joined_run_limit_reached")
    for name in sorted(names)[:max_runs]:
        try:
            follower = OperatorFollower(runs / name)
            follower.poll()
            reports[name] = follower.snapshot(now=now, dispatches=dispatches,
                                               stale_seconds=stale_seconds,
                                               alert_after_seconds=stale_seconds)
        except (OSError, ValueError) as exc:
            reports[name] = {"schema": "appsec-review/operator-status/1", "run_id": name,
                             "liveness": "unknown", "coverage": {"status": type(exc).__name__}}
            gaps.append(f"run_input_unavailable:{name}")
        summary = runs / name / "data" / "telemetry" / "summary.json"
        try:
            if summary.is_symlink() or summary.stat().st_size > 4 * 1024 * 1024:
                raise ValueError("unbounded summary")
            report = json.loads(summary.read_text(encoding="utf-8"))
            if report.get("schema") != "appsec-review/run-metrics/7" or report.get("run_id") != name:
                raise ValueError("unsupported summary")
            for item in report.get("operations", [])[:200]:
                operations.append({"runId": name, **{key: item.get(key) for key in (
                    "operation", "count", "p50_ms", "p95_ms", "max_ms")}})
        except (OSError, ValueError, TypeError):
            gaps.append(f"summary_unavailable:{name}")
    for run in dispatches:
        tags = {item["key"]: item["value"] for item in run.get("tags", [])}
        row = {key: run.get(key) for key in ("runId", "status", "pipelineName", "startTime", "endTime")}
        row["applicationRunId"] = tags.get("appsec/application_run_id")
        row["activeSteps"] = [{key: item.get(key) for key in ("stepKey", "status", "startTime", "endTime")}
                              for item in run.get("stepStats", []) if item.get("status") in {
                                  "IN_PROGRESS", "STARTING", "UNKNOWN"}][:50]
        row["ageSeconds"] = max(0, int(now.timestamp() - float(run.get("startTime") or now.timestamp())))
        if run["status"] in {"SUCCESS", "FAILURE", "CANCELED"}:
            completed.append(row)
        elif run["status"] in {"QUEUED", "NOT_STARTED"}:
            queued.append(row)
        elif run["status"] in {"STARTED", "STARTING", "MANAGED", "CANCELING"}:
            running.append(row)
        else:
            unknown.append(row)
        observation = reports.get(row["applicationRunId"], {})
        if any(alert["category"] == "progress_unconfirmed" for alert in observation.get("alerts", [])):
            stale.append(row)
        if not row["applicationRunId"]:
            orphaned.append(row)
    operations.sort(key=lambda item: (-int(item.get("p95_ms") or 0), str(item.get("operation"))))
    return {"schema": "appsec-review/operator-performance-report/1", "generatedAt": now.isoformat(),
            "dagster": {"completed": completed, "genuinelyRunning": running, "queued": queued,
                        "stale": stale, "orphaned": orphaned, "unknown": unknown},
            "slowestOperations": operations[:100],
            "operator": {"schema": "appsec-review/operator-join/1", "runs": list(reports.values()),
                         "gaps": gaps, "max_runs": max_runs}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", help="Dagster GraphQL endpoint (default http://127.0.0.1:"
                        "<APPSEC_DAGSTER_WEB_PORT, default 3000>/graphql)")
    parser.add_argument("--stale-seconds", type=int, default=3600)
    parser.add_argument("--max-runs", type=int, default=100)
    args = parser.parse_args()
    from host import url_or_default

    args.url = url_or_default(parser, args.url, "/graphql")
    request = Request(args.url, data=json.dumps({"query": QUERY}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)
    value = payload.get("data", {}).get("runsOrError", {})
    if value.get("__typename") != "Runs":
        raise SystemExit(value.get("message") or payload.get("errors") or "Dagster run query failed")
    repository = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(repository / "src"))
    print(json.dumps(build_report(repository, value["results"], now=datetime.now(timezone.utc),
                                  stale_seconds=args.stale_seconds, max_runs=args.max_runs), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
