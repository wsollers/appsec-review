"""Run the bounded lifecycle commands for the local Dagster Compose project."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from host import actual_platform, deployment_profile, provider_overlay, reject_native_environment, reject_other_deployments, validate_deployment


deployment = Path(__file__).resolve().parents[1]
repository = deployment.parents[1]
base = [
    "docker",
    "compose",
    "--env-file",
    str(deployment / ".env"),
    "-f",
    str(deployment / "compose.yaml"),
]
base.extend(["-f", str(deployment / provider_overlay(
    actual_platform(), deployment_profile(deployment / ".env")))])
commands = {
    "config": ["config"],
    "build": ["build"],
    "start": ["up", "-d", "--wait"],
    "reload": ["up", "-d", "--no-deps", "--force-recreate", "--wait", "code-location"],
    "status": ["ps"],
    "logs": ["logs", "--tail", "100"],
    "stop": ["stop"],
}


def main() -> int:
    reject_native_environment()
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=commands)
    args = parser.parse_args()
    platform = actual_platform()
    validate_deployment(repository, deployment / ".env", platform)
    if args.action in {"build", "start", "reload"}:
        reject_other_deployments(platform)
    return subprocess.run(base + commands[args.action], cwd=repository, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
