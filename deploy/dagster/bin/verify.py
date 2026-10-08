"""Verify the live webserver, code location, semantic jobs, and schedules."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib
import urllib.request


QUERY = """
query VerifyDeployment {
  repositoriesOrError {
    __typename
    ... on RepositoryConnection {
      nodes {
        name
        location { name }
        pipelines { name }
        schedules { name cronSchedule executionTimezone }
      }
    }
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    args = parser.parse_args()
    request_json(f"{args.url}/server_info")
    payload = request_json(f"{args.url}/graphql", {"query": QUERY})
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
    schedules = sorted(item["name"] for item in location["schedules"])
    config_path = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    config_jobs = tomllib.loads(config_path.read_text(encoding="utf-8"))["jobs"]
    expected_jobs = sorted(value["name"] for value in config_jobs.values())
    expected_schedules = sorted(
        f"{value['name']}_schedule"
        for value in config_jobs.values()
        if "schedule" in value
    )
    if jobs != expected_jobs or schedules != expected_schedules:
        raise SystemExit(
            "semantic definition mismatch: "
            f"expected jobs={expected_jobs}, schedules={expected_schedules}; "
            f"found jobs={jobs}, schedules={schedules}"
        )
    print(json.dumps({
        "webserver": "healthy",
        "code_location": "appsec_review",
        "jobs": jobs,
        "schedules": schedules,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
