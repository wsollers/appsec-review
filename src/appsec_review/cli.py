from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time
from typing import Sequence

from appsec_review.config import load_config
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.runner import JobRunner
from appsec_review.runtime import GraphRunner, active_job_ids, job_is_enabled
from appsec_review.jobs.cataloging import source_fingerprint

INDEX_TERMINAL_JOB_ID = "job_review_data_indexing"


def _graph_order() -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The resumable graph and its post-index consumers, in the order Dagster's ``wave1_review`` uses."""
    order = tuple(wave1_dependencies(frozenset(builtin_registry().job_ids())) or ())
    split = order.index(INDEX_TERMINAL_JOB_ID) + 1
    return order[:split], order[split:]


# The deterministic review graph in execution order; ``start``, ``resume`` and ``--force-from`` all
# use it. It is derived from ``orchestration.topology`` so the CLI and Dagster run the same jobs.
# ``job_image_pin_verification`` runs after the model gate and before intake and fails the run
# when any enabled catalog image or configured image-ID pin does not resolve on the local daemon to
# exactly its pinned image; it never builds an image. ``job_target_acquisition`` then acquires (or
# re-verifies) every component of the system named by ``--system`` into ``targets/<system>/`` before
# intake fingerprints that composed root; without ``--system`` it is a recorded no-op. ``job_code_graph_index``
# consumes CodeQL and prioritization output and must precede the indexing job that accounts for it.
# The code graph and security tags contextualize OWASP before data indexing, hunt assembly and
# red/blue investigation. Consumers of the accepted index (``POST_INDEX_JOB_IDS``) run after the resumable graph.
GRAPH_JOB_IDS, POST_INDEX_JOB_IDS = _graph_order()
# Jobs that are outside the automatic graph while ``settings.enabled`` is false and that an operator may still
# dispatch directly on a finished run (`run <job> --run-id <id> --upstream-from-run`). Every other disabled job
# is refused: disabling it means "do not run it".
MANUAL_JOB_IDS = frozenset({"job_poc_generation"})


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="appsec-review")
    root.add_argument("--config", default="appsec-review.toml",
                      help="optional local path or file URI (defaults to repository configuration)")
    root.add_argument("--profile", choices=("dev", "prod", "copilot-dev", "copilot-prod"), default=None,
                      help="runtime profile (default: APPSEC_REVIEW_PROFILE, else dev; Copilot profiles use a separate login)")
    commands = root.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="dispatch one job")
    run.add_argument("job_id")
    run.add_argument("--run-id")
    run.add_argument("--trigger", choices=("manual", "schedule"), default="manual")
    run.add_argument("--target", type=Path,
                     help="target checkout for target-reading jobs (default: APPSEC_REVIEW_TARGET)")
    run.add_argument("--upstream-from-run", action="store_true",
                     help="bind the run's accepted handoffs of the upstream jobs wave1_review would pass")

    def target_choice(command: argparse.ArgumentParser) -> None:
        choice = command.add_mutually_exclusive_group(required=True)
        choice.add_argument("--target", type=Path, help="an existing target checkout to review")
        choice.add_argument("--system", metavar="ID",
                            help="a configured [[target_acquisition.systems]] id: job_target_acquisition "
                                 "acquires (or re-verifies) its components into targets/<id>/ in parallel, "
                                 "then the graph reviews that composed root")

    start = commands.add_parser("start", help="start the deterministic review graph")
    target_choice(start)
    start.add_argument("--compiler-target", choices=("clang", "msvc"), default="clang",
                       help="native debug-symbol compiler family for this run (default: clang)")

    plan = commands.add_parser("plan-resume", help="explain review resume decisions")
    plan.add_argument("--run-id", required=True)
    target_choice(plan)
    plan.add_argument("--force-from", choices=GRAPH_JOB_IDS)

    resume = commands.add_parser("resume", help="resume the deterministic review graph")
    resume.add_argument("--run-id", required=True)
    target_choice(resume)
    resume.add_argument("--force-from", choices=GRAPH_JOB_IDS)

    tools = commands.add_parser("plan-tools", help="list planned static-tool applicability")
    tools.add_argument("--run-id", required=True)

    logs = commands.add_parser("logs", help="read or follow the run-wide structured log")
    logs.add_argument("--run-id", required=True)
    logs.add_argument("--follow", action="store_true")
    logs.add_argument("--raw", action="store_true")
    for field in ("level", "job", "step", "task", "attempt"):
        logs.add_argument(f"--{field}")

    metrics = commands.add_parser("metrics", help="derive bounded operational metrics from telemetry")
    metrics.add_argument("--run-id", required=True)

    binary = commands.add_parser(
        "binary-decompile", help="decompile configured third-party binaries before a review is submitted")
    binary.add_argument("--binary", action="append", dest="binaries", metavar="ID",
                        help="configured binary id; repeatable; default is every configured binary")
    binary.add_argument("--force", action="store_true",
                        help="decompile again even when a verified publication exists")
    binary.add_argument("--verify-only", action="store_true",
                        help="verify existing publications without running Ghidra")

    acquire = commands.add_parser(
        "acquire-target",
        help="check out every pinned component of a configured review system (Git with submodules by "
             "default, Perforce, or a code-review export) in parallel into targets/<system>/<component>/")
    acquire.add_argument("--system", action="append", dest="systems", metavar="ID",
                         help="configured system id; repeatable; default is every configured system")
    acquire.add_argument("--component", action="append", dest="components", metavar="ID",
                         help="acquire only this component of the single --system; repeatable")
    acquire.add_argument("--verify-only", action="store_true",
                         help="re-check existing acquisitions against their manifests without fetching")

    pins = commands.add_parser(
        "update-image-pins",
        help="re-pin every configured image-ID pin to the image its tag resolves to on the local daemon")
    pins.add_argument("--write", action="store_true",
                      help="apply the edits; without it the planned edits are only printed")

    commands.add_parser("schedules", help="print configured schedules")
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    compiler = getattr(args, "compiler_target", None)
    if args.command in {"run", "plan-resume", "resume"} and getattr(args, "run_id", None):
        preliminary = load_config(args.config, profile=args.profile)
        manifest_path = (preliminary.runtime.runs_dir / args.run_id /
                         "data" / "configuration" / "manifest.json")
        if manifest_path.is_file():
            compiler = json.loads(manifest_path.read_text(encoding="utf-8")).get(
                "selection", {}).get("compiler_target", "clang")
    config = load_config(args.config, profile=args.profile, compiler_target=compiler)
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

    if args.command == "update-image-pins":
        from appsec_review.container_runtime.build_executor import _run
        from appsec_review.jobs.job_image_pin_verification import pins as image_pins
        config_path = Path(args.config)
        if not config_path.is_file():
            config_path = config.runtime.repository_root / "appsec-review.toml"
        try:
            report = image_pins.update_pins(
                config_path=config_path,
                catalog_path=config.runtime.repository_root / "containers" / "catalog.toml",
                write=args.write, runner=_run)
        except image_pins.PinUpdateError as exc:
            print(json.dumps({"error": str(exc)}, sort_keys=True))
            return 1
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if not report["unpinned_missing"] and all(
            edit["status"] in {"planned", "applied"} for edit in report["edits"]) else 1

    if args.command == "binary-decompile":
        from appsec_review.binary_decompilation import (
            DecompilationError, PublicationError, decompile_binary, verify_binary)
        settings = config.binary_decompilation
        requests = [settings.binary(binary_id) for binary_id in args.binaries] if args.binaries             else list(settings.binaries)
        if not requests:
            parser().error("no binaries are configured under [[binary_decompilation.binaries]]")
        results, failed = [], False
        for request in requests:
            common = {"repository_root": config.runtime.repository_root,
                      "data_dir": config.runtime.data_dir, "settings": settings, "request": request}
            try:
                results.append({"status": "PUBLISHED", **(
                    verify_binary(**common) if args.verify_only
                    else decompile_binary(**common, force=args.force))})
            except (DecompilationError, PublicationError, ValueError, RuntimeError, OSError) as exc:
                failed = True
                results.append({"status": getattr(exc, "status", "REFUSED"), "binary_id": request.binary_id,
                                "binary_sha256": request.sha256, "error": str(exc),
                                "evidence": str(getattr(exc, "evidence", None) or "") or None})
        print(json.dumps(results, sort_keys=True, indent=2))
        return 1 if failed else 0

    if args.command == "acquire-target":
        from appsec_review.target_acquisition.acquire import acquire_system, verify_system
        settings = config.target_acquisition
        if args.components and (not args.systems or len(args.systems) != 1):
            parser().error("--component requires exactly one --system")
        if args.components and args.verify_only:
            parser().error("--verify-only checks every component of the system")
        try:
            systems = [settings.system(system_id) for system_id in args.systems] if args.systems \
                else list(settings.systems)
            for component_id in args.components or ():
                systems[0].component(component_id)
        except KeyError as exc:
            parser().error(str(exc.args[0]))
        if not systems:
            parser().error("no systems are configured under [[target_acquisition.systems]]")
        common = {"repository_root": config.runtime.repository_root, "settings": settings}
        results = [verify_system(**common, system=system) if args.verify_only
                   else acquire_system(**common, system=system, components=args.components)
                   for system in systems]
        print(json.dumps(results, sort_keys=True, indent=2))
        statuses = {item["status"] for item in results}
        if statuses <= {"COMPLETE", "VERIFIED"} and not any(item["gaps"] for item in results):
            return 0
        return 2 if statuses <= {"COMPLETE", "PARTIAL", "VERIFIED"} else 1

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

    if args.command == "metrics":
        from appsec_review.observability import write_run_metrics
        print(json.dumps(write_run_metrics(config.runtime.runs_dir / args.run_id), sort_keys=True, indent=2))
        return 0

    if args.command == "plan-tools":
        from appsec_review.jobs.job_evidence_collection import plan_applicability
        run_root = config.runtime.runs_dir / args.run_id
        print(json.dumps(plan_applicability(run_root), sort_keys=True, indent=2))
        return 0

    if args.command in {"start", "plan-resume", "resume"}:
        registry = builtin_registry()
        registry.require_matches(config.jobs, surface="CLI")
        selected = active_job_ids(config, (*GRAPH_JOB_IDS, *POST_INDEX_JOB_IDS))
        if getattr(args, "force_from", None) and args.force_from not in selected:
            raise ValueError(f"cannot force from disabled job: {args.force_from}")
        jobs = [registry.build(job_id) for job_id in selected]
        if args.system is not None:
            from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
            try:
                config.target_acquisition.system(args.system)
            except KeyError as exc:
                parser().error(str(exc.args[0]))
            if "job_target_acquisition" not in selected:
                parser().error("--system requires job_target_acquisition to be enabled")
            # The acquisition gate reads the requested system from the environment, as every driver does.
            os.environ[SYSTEM_ENVIRONMENT] = args.system
            args.target = (config.runtime.repository_root / config.target_acquisition.targets_dir /
                           args.system).absolute()
            fingerprint = None
        else:
            fingerprint = source_fingerprint(args.target)
        graph = GraphRunner(config, jobs)
        if args.command == "plan-resume":
            decisions = graph.plan(args.run_id, fingerprint, force_from=args.force_from,
                                   target_root=args.target)
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

    if not job_is_enabled(config, args.job_id) and args.job_id not in MANUAL_JOB_IDS:
        raise ValueError(f"job is disabled by configuration: {args.job_id}")
    from appsec_review.orchestration.topology import accepted_upstream_handoffs, describe_wave1
    from appsec_review.runtime.launch import configured_target, launch, launch_inputs
    from appsec_review.storage import RunStore

    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="CLI")
    job = registry.build(args.job_id)
    upstream: dict[str, str] = {}
    if args.upstream_from_run:
        if not args.run_id:
            parser().error("--upstream-from-run requires --run-id")
        entry = next((item for item in describe_wave1(config, registry, include=MANUAL_JOB_IDS & {args.job_id})["jobs"]
                      if item["job_id"] == args.job_id), None)
        if entry is None:
            raise ValueError(f"job is not in wave1_review: {args.job_id}")
        upstream = accepted_upstream_handoffs(RunStore(config.runtime.runs_dir).resolve(args.run_id),
                                              entry["upstream_handoffs"])
    inputs = launch_inputs(job, target=args.target or configured_target(
                               config.runtime.repository_root, config.target_acquisition.targets_dir),
                           upstream_handoffs=upstream)
    outcome = launch(JobRunner(config), job, inputs, run_id=args.run_id, trigger=args.trigger)
    print(json.dumps(outcome, sort_keys=True))
    return 0
