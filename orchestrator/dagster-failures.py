#!/usr/bin/env python3
"""Print the underlying error of every failed step in a Dagster run (unwraps retry wrappers).

    python3 orchestrator/dagster-failures.py <review run id | dagster run id | launch request.json>

A review run id (e.g. 20261003T211514Z-ef3fae) uses that run's newest launch record,
<runs>/<run id>/data/orchestration/launches/*/request.json.
"""
import json
import os
from pathlib import Path
import sys
import urllib.request

URL = "http://127.0.0.1:3000/graphql"
QUERY = """query($id: ID!, $cursor: String){ logsForRun(runId:$id, afterCursor:$cursor){ __typename
 ... on EventConnection { cursor hasMore events { __typename
   ... on ExecutionStepFailureEvent { stepKey error { message stack
       cause { message stack cause { message stack cause { message stack } } } } }
   ... on RunFailureEvent { message } } } } }"""


def deepest(error):
    while error and error.get("cause") and error["cause"].get("message"):
        error = error["cause"]
    return error or {}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__); return 2
    arg = sys.argv[1]
    runs = Path(os.environ.get("APPSEC_RUNS_ROOT") or Path(__file__).resolve().parents[1] / "appsec-review-process" / "runs")
    launches = sorted((runs / arg / "data" / "orchestration" / "launches").glob("*/request.json"),
                      key=lambda p: p.stat().st_mtime)
    if launches:
        arg = str(launches[-1])
        print("launch record", arg)
    run_id = json.load(open(arg))["dagster_run_id"] if arg.endswith((".json", ".log")) else arg
    print("dagster run", run_id)
    cursor, seen = None, set()
    while True:
        body = json.dumps({"query": QUERY, "variables": {"id": run_id, "cursor": cursor}}).encode()
        req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
        page = json.load(urllib.request.urlopen(req))["data"]["logsForRun"]
        for event in page.get("events", []):
            if event["__typename"] == "RunFailureEvent":
                print("== run:", event.get("message"))
            elif event["__typename"] == "ExecutionStepFailureEvent":
                err = deepest(event.get("error"))
                key = (event["stepKey"], (err.get("message") or "")[:300])
                if key in seen:
                    continue
                seen.add(key)
                print(f"\n--- {event['stepKey']}\n{(err.get('message') or '')[:1500]}")
                print("".join(err.get("stack") or [])[-1200:])
        cursor = page.get("cursor")
        if not page.get("hasMore"):
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
