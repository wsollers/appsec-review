"""Submit, inspect, or wait for a wave1 review through the live Dagster instance."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from appsec_review.storage import atomic_json, bounded_file_lock


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
SUBMISSION_SCHEMA = "appsec-review/dagster-submission/1"


def submission_directory(root: Path) -> Path:
    return root / "runs" / "metadata" / "dagster-submission"


@contextmanager
def submission_lock(root: Path):
    with bounded_file_lock(submission_directory(root) / "submission.lock", 5):
        yield


def read_submission(root: Path) -> dict | None:
    path = submission_directory(root) / "active.json"
    if not path.exists():
        return None
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("submission intent exceeds its size bound")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or record.get("schema") != SUBMISSION_SCHEMA
            or record.get("state") not in {"UNCERTAIN", "SUBMITTED", "RECONCILED"}
            or not isinstance(record.get("identity"), dict)
            or not isinstance(record.get("dagster_run_id"), str)
            or str(UUID(record["dagster_run_id"])) != record["dagster_run_id"]
            or record.get("identity_sha256") != submission_identity_sha256(record["identity"])):
        raise ValueError("invalid submission intent; explicit inspection is required")
    return record


def submission_identity_sha256(identity: dict) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def write_submission(root: Path, record: dict) -> None:
    directory = submission_directory(root)
    atomic_json(directory / "active.json", record)
    if os.name != "nt":
        # Persist both the replacement and any newly created journal directories before launch.
        for path in (directory, directory.parent, directory.parent.parent, root):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def submission_identity(root: Path, *, target: str, profile: str, overlay: str,
                        recording: str, image_id: str, project: str, url: str,
                        application_run_id: str | None) -> dict:
    def git_identity(path: Path, *, target_checkout: bool = False) -> str:
        def git(*arguments: str) -> str:
            result = subprocess.run(
                ["git", "-C", str(path), *arguments], capture_output=True, text=True,
                timeout=30, check=False)
            if result.returncode:
                raise ValueError(f"cannot establish Git identity for {path}")
            return result.stdout.strip()

        if Path(git("rev-parse", "--show-toplevel")).resolve() != path.resolve():
            raise ValueError(f"submission requires a distinct Git checkout at {path}")
        head = git("rev-parse", "HEAD")
        if len(head) not in {40, 64} or any(char not in "0123456789abcdef" for char in head):
            raise ValueError(f"invalid Git commit identity for {path}")
        if git("status", "--porcelain", "--untracked-files=all" if target_checkout else "--untracked-files=no"):
            raise ValueError(f"submission requires unchanged tracked source and a clean target: {path}")
        return head

    def mounted_path(value: str, prefix: str, local: Path) -> Path:
        if not value.startswith(prefix + "/"):
            raise ValueError(f"submission cannot bind an unmapped container path: {value}")
        path = (local / value[len(prefix) + 1:]).resolve(strict=True)
        if not path.is_relative_to(local.resolve()) or path == local.resolve():
            raise ValueError(f"submission path escapes its checkout mount: {value}")
        return path

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    target_path = mounted_path(target, "/opt/app/targets", root / "targets")
    profile_path = root / "profiles" / f"{profile}.toml"
    overlay_path = mounted_path(overlay, "/opt/app/test/acceptance", root / "test" / "acceptance") if overlay else None
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ValueError("running code-location immutable image identity is unavailable")
    return {
        "repository_root": str(root.resolve()), "source_commit": git_identity(root),
        "target_root": str(target_path), "target_commit": git_identity(target_path, target_checkout=True),
        "target": target, "project": project, "url": url, "code_location_image_id": image_id,
        "application_run_id": application_run_id,
        "configuration": {
            "base_sha256": digest(root / "appsec-review.toml"), "profile": profile,
            "profile_sha256": digest(profile_path) if profile != "dev" else None,
            "overlay_sha256": digest(overlay_path) if overlay_path else None,
            "overlay": overlay, "recording": recording,
        },
    }


def check_submission(root: Path, identity: dict, run_id: str) -> None:
    if str(UUID(run_id)) != run_id:
        raise ValueError("submission requires a canonical Dagster UUID")
    record = read_submission(root)
    if record and record["state"] != "RECONCILED":
        changed = "identity mismatch; " if record["identity"] != identity else ""
        raise ValueError(
            f"{changed}submission {record['dagster_run_id']} remains {record['state']}; "
            "no resubmission is allowed. Inspect that exact run and use review_run.py reconcile "
            "--run-id <uuid> --url <original-url> only after confirmed terminal state")
    if ((record and record["dagster_run_id"] == run_id)
            or (submission_directory(root) / f"{run_id}.json").exists()):
        raise ValueError(f"submission UUID {run_id} has already been used")


def begin_submission(root: Path, identity: dict, run_id: str) -> dict:
    check_submission(root, identity, run_id)
    previous = read_submission(root)
    if previous:
        atomic_json(submission_directory(root) / f"{previous['dagster_run_id']}.json", previous)
    record = {
        "schema": SUBMISSION_SCHEMA, "dagster_run_id": run_id, "identity": identity,
        "identity_sha256": submission_identity_sha256(identity),
        "state": "UNCERTAIN", "created_at": datetime.now(timezone.utc).isoformat(),
    }
    write_submission(root, record)
    return record


def reconcile_submission(run_id: str, url: str) -> None:
    with submission_lock(ROOT):
        record = read_submission(ROOT)
        if (record is None or record["dagster_run_id"] != run_id
                or record["identity"]["url"] != url):
            raise ValueError("reconciliation requires the occupied submission's exact UUID and endpoint")
        run = get_run(url, run_id)
        tags = {item["key"]: item["value"] for item in run.get("tags", [])}
        if (run.get("runId") != run_id or run.get("pipelineName") != "wave1_review"
                or run.get("status") not in TERMINAL
                or tags.get("appsec/submission_identity") != record["identity_sha256"]):
            raise ValueError("submission is not a confirmed terminal run with matching identity; intent retained")
        record.update(state="RECONCILED", terminal_status=run["status"],
                      reconciled_at=datetime.now(timezone.utc).isoformat())
        write_submission(ROOT, record)
        print(f"reconciled_dagster_run_id={run_id}; no review submitted", flush=True)


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


def submit(run_id: str, url: str = "http://127.0.0.1:3000/graphql", *,
           stop_on_first_error: bool = False) -> None:
    import ops

    args = ops.build_parser().parse_args(["review-start", "--url", url, "--id-wait", "0"])
    args.dagster_run_id = run_id
    args.stop_on_first_error = stop_on_first_error
    ops.cmd_review_start(args)
    print(f"submitted_dagster_run_id={run_id}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("submit", "status", "watch", "reconcile"))
    parser.add_argument("--run-id", help="Dagster UUID; generated for submit")
    parser.add_argument("--url", default="http://127.0.0.1:3000/graphql")
    parser.add_argument("--interval-seconds", type=int, default=30)
    parser.add_argument("--stop-on-first-error", action="store_true")
    args = parser.parse_args()
    if args.action != "submit" and not args.run_id:
        parser.error("--run-id is required for status and watch")
    if args.interval_seconds < 1:
        parser.error("--interval-seconds must be positive")
    run_id = args.run_id or str(uuid4())
    if args.action in {"submit", "reconcile"}:
        import ops

        try:
            if args.action == "reconcile":
                reconcile_submission(run_id, args.url)
                return 0
            submit(run_id, args.url, stop_on_first_error=args.stop_on_first_error)
        except ops.OpsError as error:
            print(f"error: {error}", file=sys.stderr, flush=True)
            return error.code
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}; submission intent retained if present", file=sys.stderr, flush=True)
            return 1
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
