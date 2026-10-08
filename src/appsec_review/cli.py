from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from appsec_review.config import load_config
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="appsec-review")
    root.add_argument("--config", type=Path, default=Path("appsec-review.toml"))
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="dispatch one job")
    run.add_argument("job_id")
    run.add_argument("--run-id")
    run.add_argument("--trigger", choices=("manual", "schedule"), default="manual")

    commands.add_parser("schedules", help="print configured schedules")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    config = load_config(args.config)
    if args.command == "schedules":
        schedules = {
            job_id: {
                "enabled": job.schedule.enabled,
                "cron": job.schedule.cron,
                "timezone": job.schedule.timezone,
            }
            for job_id, job in config.jobs.items()
            if job.schedule is not None
        }
        print(json.dumps(schedules, sort_keys=True))
        return 0

    job = builtin_registry().build(args.job_id)
    outcome = JobRunner(config).run(job, run_id=args.run_id, trigger=args.trigger)
    print(json.dumps(outcome, sort_keys=True))
    return 0
