"""Report live Dagster state beside redacted application timing summaries."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.request import Request, urlopen


QUERY = """query RunReport {
  runsOrError(limit: 1000) {
    __typename
    ... on Runs { results { runId status pipelineName startTime endTime tags { key value }
      stepStats { stepKey status startTime endTime } } }
    ... on PythonError { message }
  }
}"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:3000/graphql")
    parser.add_argument("--stale-seconds", type=int, default=3600)
    args = parser.parse_args()
    request = Request(args.url, data=json.dumps({"query": QUERY}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)
    value = payload.get("data", {}).get("runsOrError", {})
    if value.get("__typename") != "Runs":
        raise SystemExit(value.get("message") or payload.get("errors") or "Dagster run query failed")
    now = datetime.now(timezone.utc).timestamp()
    terminal = {"SUCCESS", "FAILURE", "CANCELED"}
    completed, running, queued, stale, orphaned = [], [], [], [], []
    for run in value["results"]:
        tags = {item["key"]: item["value"] for item in run.get("tags", [])}
        row = {key: run.get(key) for key in ("runId", "status", "pipelineName", "startTime", "endTime")}
        row["applicationRunId"] = tags.get("appsec/application_run_id")
        active_steps = [item for item in run.get("stepStats", []) if item.get("status") in {
            "IN_PROGRESS", "STARTING", "UNKNOWN"}]
        row["activeSteps"] = active_steps[:50]
        age = max(0, int(now - float(run.get("startTime") or now)))
        row["ageSeconds"] = age
        if run["status"] in terminal:
            completed.append(row)
        elif run["status"] in {"QUEUED", "NOT_STARTED"}:
            queued.append(row)
        elif age >= args.stale_seconds:
            stale.append(row)
            if not row["applicationRunId"]:
                orphaned.append(row)
        else:
            running.append(row)
    repository = Path(__file__).resolve().parents[3]
    operations = []
    for summary in (repository / "runs").glob("*/data/telemetry/summary.json"):
        try:
            report = json.loads(summary.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        operations.extend({"runId": report.get("run_id"), **item} for item in report.get("operations", []))
    operations.sort(key=lambda item: (-int(item.get("p95_ms") or 0), str(item.get("operation"))))
    print(json.dumps({"schema": "appsec-review/operator-performance-report/1",
                      "generatedAt": datetime.now(timezone.utc).isoformat(),
                      "dagster": {"completed": completed, "genuinelyRunning": running,
                                  "queued": queued, "stale": stale, "orphaned": orphaned},
                      "slowestOperations": operations[:100]}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
