#!/usr/bin/env python3
"""Smoke-test process failure propagation for every lane."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_process.py"


def processes() -> list[str]:
    return sorted(p.name for p in ROOT.iterdir() if p.is_dir() and p.name[:2].isdigit() and "-" in p.name)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    failures = []
    for process in processes():
        cmd = [
            sys.executable,
            str(RUNNER),
            "--process",
            process,
            "--fail-immediately",
            "--message",
            "failure propagation smoke",
        ]
        proc = subprocess.run(cmd, cwd=ROOT.parent, text=True, capture_output=True)
        if proc.returncode == 0:
            failures.append(f"{process}: expected nonzero exit")
            continue
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            failures.append(f"{process}: stdout was not JSON: {proc.stdout[:200]}")
            continue
        run_id = payload.get("run_id")
        status = load(ROOT / "runs" / run_id / "run-status.json")
        proc_status = load(ROOT / "runs" / run_id / "processes" / process / "status.json")
        if status.get("status") != "FAILED":
            failures.append(f"{process}: run status did not fail")
        if status.get("failed_process") != process or status.get("resume_from") != process:
            failures.append(f"{process}: resume point not set to failed process")
        if process not in status.get("rerun_command", ""):
            failures.append(f"{process}: rerun command does not reference failed process")
        if proc_status.get("status") != "FAILED":
            failures.append(f"{process}: process status did not fail")

    summary = {
        "processes_tested": len(processes()),
        "status": "FAILED" if failures else "OK",
        "failures": failures,
    }
    print(json.dumps(summary, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

