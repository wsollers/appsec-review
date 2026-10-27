"""Serial host-platform and live third-party-feed smoke checks for Dagster Compose."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.error import URLError
from uuid import uuid4

from run_report import QUERY as RUNS_QUERY
from verify import request_json
from host import (actual_platform, deployment_profile, project_name, provider_overlay,
                  reject_other_deployments, validate_deployment)


ROOT = Path(__file__).resolve().parents[3]
DEPLOYMENT = ROOT / "deploy" / "dagster"
LOCK = ROOT / "runs" / "metadata" / "dagster-smoke.lock"
TERMINAL = {"SUCCESS", "FAILURE", "CANCELED"}
FEEDS = {"nvd_sync", "osv_sync", "mitre_sync", "kev_sync", "epss_sync", "cve_bin_tool_db_build"}


def compose(platform: str) -> list[str]:
    overlay = provider_overlay(platform, deployment_profile(DEPLOYMENT / ".env"))
    return ["docker", "compose", "--env-file", str(DEPLOYMENT / ".env"),
            "-f", str(DEPLOYMENT / "compose.yaml"), "-f", str(DEPLOYMENT / overlay)]


def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, check=True, text=True,
                          capture_output=capture)


def check_config(platform: str) -> dict:
    validate_deployment(ROOT, DEPLOYMENT / ".env", platform)
    if not shutil.which("docker"):
        raise RuntimeError("Docker CLI is unavailable")
    document = json.loads(run(compose(platform) + ["config", "--format", "json"], capture=True).stdout)
    if document["name"] != project_name(platform):
        raise RuntimeError("Compose project identity does not match this host")
    services = document["services"]
    if set(services) != {"postgres", "code-location", "webserver", "daemon"}:
        raise RuntimeError("Compose service set changed")
    code = services["code-location"]
    mounts = {item["target"]: item for item in code["volumes"]}
    for target in ("/opt/app/runs", "/opt/app/data", "/var/run/docker.sock"):
        if target not in mounts:
            raise RuntimeError(f"missing code-location mount: {target}")
    for target in ("/opt/app/runs", "/opt/app/data", "/opt/app/targets", "/opt/app/rules"):
        source = str(mounts[target]["source"])
        expected = str(ROOT / target.rsplit("/", 1)[-1])
        if os.path.normcase(os.path.normpath(source)) != os.path.normcase(os.path.normpath(expected)):
            raise RuntimeError(f"{target} must bind this host's checkout: {expected}")
    if deployment_profile(DEPLOYMENT / ".env") in {"copilot-dev", "copilot-prod"}:
        if code["build"].get("target") != "runtime-copilot":
            raise RuntimeError("Copilot code-location image does not install the SDK runtime")
        mount = mounts.get("/var/copilot-home")
        if not mount or not Path(mount["source"]).is_dir():
            raise RuntimeError("Copilot requires the dedicated worker login directory")
        if platform == "wsl" and not Path(mount["source"]).resolve().is_relative_to(Path.home().resolve()):
            raise RuntimeError("Copilot worker login must be stored in the WSL home filesystem")
        if code["environment"].get("APPSEC_COPILOT_HOME") != "/var/copilot-home":
            raise RuntimeError("Copilot authentication directory is not configured")
        if any(target in mounts for target in ("/usr/local/bin/claude", "/tmp/.claude", "/tmp/.claude.json")):
            raise RuntimeError("Copilot Compose must not require Claude authentication")
    elif platform == "windows":
        if any(services[name].get("user") != "0:0" for name in ("code-location", "webserver", "daemon")):
            raise RuntimeError("Windows services must ignore Linux uid/gid values in the shared environment")
        if any(target in mounts for target in ("/usr/local/bin/claude", "/tmp/.claude", "/tmp/.claude.json")):
            raise RuntimeError("Windows Compose still requires a Linux host CLI mount")
        if code["environment"].get("HOME") != "/var/claude-home" or "/var/claude-home" not in mounts:
            raise RuntimeError("Windows subscription CLI home is not persistent")
        if code["build"].get("target") != "runtime-windows":
            raise RuntimeError("Windows code-location image does not install the Claude CLI")
    else:
        for target, kind in (("/usr/local/bin/claude", "file"), ("/tmp/.claude", "dir"),
                             ("/tmp/.claude.json", "file")):
            mount = mounts.get(target)
            source = Path(mount["source"]) if mount else None
            if source is None or not (source.is_file() if kind == "file" else source.is_dir()):
                raise RuntimeError(f"{target} must bind a real Linux {kind}")
            if platform == "wsl" and not source.resolve().is_relative_to(Path.home().resolve()):
                raise RuntimeError(f"{target} must be stored in the WSL home filesystem")
    return {"platform": platform, "services": sorted(services),
            "cli": ("copilot-sdk" if deployment_profile(DEPLOYMENT / ".env") in {"copilot-dev", "copilot-prod"}
                    else "container" if platform == "windows" else "host-bind")}


@contextmanager
def serial_lock():
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    try:
        LOCK.mkdir()
    except FileExistsError as error:
        raise RuntimeError(f"another smoke run holds {LOCK}") from error
    try:
        (LOCK / "owner.json").write_text(json.dumps({"pid": os.getpid(), "platform": actual_platform()}),
                                         encoding="utf-8")
        yield
    finally:
        (LOCK / "owner.json").unlink(missing_ok=True)
        LOCK.rmdir()


def active_runs(url: str) -> list[str]:
    payload = request_json(f"{url}/graphql", {"query": RUNS_QUERY})
    value = payload.get("data", {}).get("runsOrError", {})
    if value.get("__typename") != "Runs":
        raise RuntimeError(f"cannot check Dagster contention: {value.get('message') or payload.get('errors')}")
    return [item["runId"] for item in value["results"] if item["status"] not in TERMINAL]


def reject_contention(url: str, platform: str) -> None:
    try:
        active = active_runs(url)
    except (URLError, OSError):
        existing = run(compose(platform) + ["ps", "--status", "running", "--services"], capture=True).stdout
        if existing.strip():
            raise RuntimeError("Dagster containers are running but the run ledger is unavailable")
        return
    if active:
        raise RuntimeError(f"Dagster has non-terminal runs: {', '.join(active)}")


def check_cli(platform: str) -> None:
    prefix = compose(platform) + ["exec", "-T", "code-location"]
    if deployment_profile(DEPLOYMENT / ".env") in {"copilot-dev", "copilot-prod"}:
        run(prefix + ["python", "-c",
                      "from appsec_review.inference.copilot_sdk import verify; verify()"], capture=True)
        return
    run(prefix + ["claude", "--version"])
    # Match the model transport: an optional API key must not mask subscription state.
    auth = run(prefix + ["env", "-u", "ANTHROPIC_API_KEY", "claude", "auth", "status"], capture=True)
    try:
        status = json.loads(auth.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Claude authentication status was not JSON") from error
    if status.get("loggedIn") is not True or status.get("authMethod") not in {"claude.ai", "oauth_token"}:
        raise RuntimeError("Claude subscription login is required inside the code location")


def live_stack(platform: str, url: str) -> None:
    reject_other_deployments(platform)
    reject_contention(url, platform)
    run(compose(platform) + ["build", "code-location"])
    run(compose(platform) + ["up", "-d", "--wait"])
    reject_contention(url, platform)
    check_cli(platform)
    run([sys.executable, str(DEPLOYMENT / "bin" / "verify.py"), "--url", url], capture=True)


def sync_feeds(platform: str, url: str, timeout_seconds: int) -> dict:
    reject_contention(url, platform)
    run_id = str(uuid4())
    run(compose(platform) + ["exec", "-T", "webserver", "dagster", "job", "launch",
                             "-w", "/opt/dagster/home/workspace.yaml", "-l", "appsec_review",
                             "-j", "third_party_data_sync", "--run-id", run_id])
    deadline = time.monotonic() + timeout_seconds
    while True:
        payload = request_json(f"{url}/graphql", {"query": "query($id: ID!){runOrError(runId:$id){__typename ... on Run {status pipelineName} ... on PythonError {message}}}",
                                                   "variables": {"id": run_id}})
        state = payload.get("data", {}).get("runOrError", {})
        if state.get("__typename") != "Run" or state.get("pipelineName") != "third_party_data_sync":
            raise RuntimeError(f"launched feed run cannot be resolved: {run_id}")
        if state["status"] in TERMINAL:
            if state["status"] != "SUCCESS":
                raise RuntimeError(f"feed sync {run_id} ended {state['status']}")
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(f"feed sync {run_id} still running after {timeout_seconds}s; inspect it before another smoke run")
        time.sleep(30)
    evidence = ROOT / "runs" / "metadata" / "dagster-smoke" / platform / f"{run_id}.json"
    report = json.loads(run([sys.executable, str(DEPLOYMENT / "bin" / "verify.py"), "--url", url,
                             "--run-id", run_id, "--evidence", str(evidence)], capture=True).stdout)
    snapshots = report["acceptance_run"]["published_snapshots"]
    if set(snapshots) != FEEDS:
        raise RuntimeError(f"feed publication coverage mismatch: {sorted(snapshots)}")
    return {"dagster_run_id": run_id, "evidence": str(evidence.relative_to(ROOT)), "feeds": sorted(snapshots)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "linux", "wsl"), required=True)
    parser.add_argument("--mode", choices=("config", "live", "feeds"), default="config")
    parser.add_argument("--url", default="http://127.0.0.1:3000")
    parser.add_argument("--timeout-seconds", type=int, default=14400)
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be positive")
    result = check_config(args.platform)
    if args.mode != "config":
        with serial_lock():
            live_stack(args.platform, args.url)
            if args.mode == "feeds":
                result["sync"] = sync_feeds(args.platform, args.url, args.timeout_seconds)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"smoke failed: {error}") from error
