"""Cancel every non-terminal Dagster run through the supported GraphQL API."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from urllib.request import Request, urlopen


LIST = """query RecoveryRuns { runsOrError(limit: 1000) {
  __typename ... on Runs { results { runId status pipelineName startTime tags { key value } } }
  ... on PythonError { message }
} }"""
TERMINATE = """mutation RecoverRun($runId: String!, $policy: TerminateRunPolicy!) {
  terminateRun(runId: $runId, terminatePolicy: $policy) { __typename }
}"""
TERMINAL = {"SUCCESS", "FAILURE", "CANCELED"}


def _request(url: str, query: str, variables: dict | None = None) -> dict:
    body = {"query": query, "variables": variables or {}}
    request = Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if payload.get("errors"):
        raise RuntimeError(str(payload["errors"]))
    return payload["data"]


def _runs(url: str) -> list[dict]:
    value = _request(url, LIST)["runsOrError"]
    if value.get("__typename") != "Runs":
        raise RuntimeError(value.get("message") or "Dagster run listing failed")
    return list(value["results"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:3000/graphql")
    parser.add_argument("--reason", required=True)
    parser.add_argument("--run-id", action="append", required=True,
                        help="exact previously enumerated non-terminal Dagster run id; repeat as needed")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--policy", choices=("SAFE_TERMINATE", "MARK_AS_CANCELED_IMMEDIATELY"),
                        default="SAFE_TERMINATE")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    requested = set(args.run_id)
    all_runs = {run["runId"]: run for run in _runs(args.url)}
    missing = sorted(requested - set(all_runs))
    terminal_requested = sorted(run_id for run_id in requested
                                if run_id in all_runs and all_runs[run_id]["status"] in TERMINAL)
    if missing or terminal_requested:
        raise SystemExit(f"recovery target mismatch: missing={missing}, already_terminal={terminal_requested}")
    selected = [all_runs[run_id] for run_id in sorted(requested)]
    requests = []
    for run in selected:
        outcome = _request(args.url, TERMINATE, {"runId": run["runId"], "policy": args.policy})["terminateRun"]
        requests.append({"runId": run["runId"], "priorStatus": run["status"],
                         "pipelineName": run["pipelineName"], "response": outcome["__typename"]})
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        final = {run["runId"]: run for run in _runs(args.url)}
        remaining = [run_id for run_id in (item["runId"] for item in requests)
                     if final.get(run_id, {}).get("status") not in TERMINAL]
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(2)
    completed = [{**item, "finalStatus": final.get(item["runId"], {}).get("status", "MISSING")}
                 for item in requests]
    evidence = args.evidence or (Path(__file__).resolve().parents[3] / "runs" / "metadata" /
        "dagster-recovery" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"))
    evidence.parent.mkdir(parents=True, exist_ok=True)
    report = {"schema": "appsec-review/dagster-run-recovery/1",
              "recordedAt": datetime.now(timezone.utc).isoformat(), "reason": args.reason,
              "selectedCount": len(selected), "policy": args.policy, "runs": completed,
              "remainingNonTerminal": remaining}
    evidence.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**report, "evidence": str(evidence)}, sort_keys=True, indent=2))
    return 1 if remaining else 0


if __name__ == "__main__":
    raise SystemExit(main())
