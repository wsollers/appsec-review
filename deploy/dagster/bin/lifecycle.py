"""Run the bounded lifecycle commands for the local Dagster Compose project."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


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
base.extend(["-f", str(deployment / ("compose.windows.yaml" if os.name == "nt" else "compose.claude.yaml"))])
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
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=commands)
    args = parser.parse_args()
    if not (deployment / ".env").exists():
        raise SystemExit("run deploy/dagster/bin/bootstrap.py first")
    return subprocess.run(base + commands[args.action], cwd=repository, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
