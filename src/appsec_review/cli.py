from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Sequence

from appsec_review.config import load_config
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.runtime import GraphRunner
from appsec_review.jobs.cataloging import source_fingerprint


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="appsec-review")
    root.add_argument("--config", default="appsec-review.toml",
                      help="optional local path or file URI (defaults to repository configuration)")
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="dispatch one job")
    run.add_argument("job_id")
    run.add_argument("--run-id")
    run.add_argument("--trigger", choices=("manual", "schedule"), default="manual")

    start = commands.add_parser("start", help="start the Wave 1 review graph")
    start.add_argument("--target", type=Path, required=True)

    plan = commands.add_parser("plan-resume", help="explain Wave 1 resume decisions")
    plan.add_argument("--run-id", required=True)
    plan.add_argument("--target", type=Path, required=True)
    plan.add_argument("--force-from", choices=("job_review_intake", "job_target_catalog"))

    resume = commands.add_parser("resume", help="resume the Wave 1 review graph")
    resume.add_argument("--run-id", required=True)
    resume.add_argument("--target", type=Path, required=True)
    resume.add_argument("--force-from", choices=("job_review_intake", "job_target_catalog"))

    logs = commands.add_parser("logs", help="read or follow the run-wide structured log")
    logs.add_argument("--run-id", required=True)
    logs.add_argument("--follow", action="store_true")
    logs.add_argument("--raw", action="store_true")
    for field in ("level", "job", "step", "task", "attempt"):
        logs.add_argument(f"--{field}")

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

    if args.command == "logs":
        from appsec_review.observability import PipelineLog
        path = config.runtime.runs_dir / args.run_id
        logger = PipelineLog(path)
        seen = 0
        while True:
            records, torn = logger.read()
            filters = {"level": args.level, "job_id": args.job, "step_id": args.step,
                       "task_id": args.task, "attempt_id": args.attempt}
            for record in records[seen:]:
                if all(value is None or str(record.get(key)) == value for key, value in filters.items()):
                    print(json.dumps(record, sort_keys=True) if args.raw else
                          f"{record['sequence']:06d} {record['level']:<5} {record['job_id']} "
                          f"{record['event_type']} {record['message']}")
            seen = len(records)
            if torn:
                print("warning: ignored a torn final log record", file=__import__("sys").stderr)
            if not args.follow:
                if not records:
                    print(f"no pipeline log records for run {args.run_id}", file=__import__("sys").stderr)
                return 0
            time.sleep(0.5)

    if args.command in {"start", "plan-resume", "resume"}:
        registry = builtin_registry()
        jobs = [registry.build("job_review_intake"), registry.build("job_target_catalog")]
        fingerprint = source_fingerprint(args.target)
        graph = GraphRunner(config, jobs)
        if args.command == "plan-resume":
            decisions = graph.plan(args.run_id, fingerprint, force_from=args.force_from)
            print(json.dumps([item.as_dict() for item in decisions], sort_keys=True, indent=2))
            return 0
        outcome = graph.run(target_root=args.target, source_fingerprint=fingerprint,
                            run_id=getattr(args, "run_id", None),
                            force_from=getattr(args, "force_from", None))
        summary = {"run_id": outcome["run_id"], "status": outcome["status"],
                   "decisions": outcome["decisions"],
                   "jobs": {job_id: {"attempt_id": value.get("attempt_id") or value.get("status", {}).get("attempt_id"),
                                      "handoff_sha256": value.get("handoff_sha256"),
                                      "decision": value["decision"]}
                            for job_id, value in outcome["jobs"].items()}}
        print(json.dumps(summary, sort_keys=True))
        return 0

    job = builtin_registry().build(args.job_id)
    outcome = JobRunner(config).run(job, run_id=args.run_id, trigger=args.trigger)
    print(json.dumps(outcome, sort_keys=True))
    return 0
