#!/usr/bin/env python3
"""Minimal manual-process run state manager.

This does not execute LLM prompts. It records lane/task state so a human or agent
can recover after a crash and resume from the failed or next pending process.
"""
from __future__ import annotations

import argparse
import json
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def process_dirs() -> list[Path]:
    return sorted(p for p in ROOT.iterdir() if p.is_dir() and p.name[:2].isdigit() and "-" in p.name)


def process_names() -> list[str]:
    # The authoritative lane sequence is process-manifest.json's process_order
    # (deliberately NOT alphabetical -- e.g. 02-evidence-pregather runs before
    # 01-component-characterization, and 10-synthesis-report runs last, after
    # 11/12). Alphabetical directory listing was the original placeholder and
    # silently diverged from that order, which made this script's own
    # resume_from/rerun_command point at the wrong next lane (discovered
    # 2026-09-17: after 00-intake-recovery completed, this returned
    # "01-component-characterization" instead of the manifest's
    # "02-evidence-pregather", which review_cli.py next-lane -- already
    # reading process-manifest.json directly -- correctly recommended).
    # Fall back to alphabetical only if the manifest is missing/unreadable,
    # so the script still works before it's staged.
    on_disk = {p.name for p in process_dirs()}
    manifest_path = ROOT / "process-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        order = manifest.get("process_order")
    except Exception:
        order = None
    if isinstance(order, list) and order:
        ordered = [name for name in order if name in on_disk]
        # Any lane directory that exists on disk but isn't listed in the
        # manifest still needs to be reachable -- append it (alphabetically)
        # rather than silently dropping it from the run.
        extra = sorted(on_disk - set(ordered))
        return ordered + extra
    return sorted(on_disk)


def resolve_process(name: str) -> str:
    names = process_names()
    if name in names:
        return name
    matches = [n for n in names if n.startswith(name) or n[3:] == name]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"unknown process {name!r}; valid: {', '.join(names)}")
    raise SystemExit(f"ambiguous process {name!r}; matches: {', '.join(matches)}")


def run_dir(run_id: str) -> Path:
    from execution_state import run_path
    return run_path(run_id)


def status_path(run_id: str) -> Path:
    return run_dir(run_id) / "run-status.json"


def events_path(run_id: str) -> Path:
    return run_dir(run_id) / "events.jsonl"


def process_status_path(run_id: str, process: str) -> Path:
    return run_dir(run_id) / "processes" / process / "status.json"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def append_event(run_id: str, event: dict[str, Any]) -> None:
    path = events_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {"time": now(), **event}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


def init_run(run_id: str) -> dict[str, Any]:
    names = process_names()
    rdir = run_dir(run_id)
    if (rdir / 'run-status.json').exists():
        raise ValueError('run already exists; initialization cannot reset history')
    (rdir / 'data').mkdir(parents=True, exist_ok=True)
    (rdir / "inputs").mkdir(parents=True, exist_ok=True)
    (rdir / "outputs").mkdir(parents=True, exist_ok=True)
    template = ROOT / "templates" / "artifact-manifest.template.json"
    staged_manifest = rdir / "inputs" / "artifact-manifest.json"
    if template.exists() and not staged_manifest.exists():
        shutil.copyfile(template, staged_manifest)
    data = {
        "schema": "appsec-review-process/run-status/0.1",
        "run_id": run_id,
        "created_at": now(),
        "updated_at": now(),
        "status": "READY",
        "default_budget": "probe",
        "process_order": names,
        "current_process": names[0] if names else None,
        "completed_processes": [],
        "failed_process": None,
        "resume_from": names[0] if names else None,
        "rerun_command": f"python3 appsec-review-process/run_process.py --run-id {run_id} --process {names[0]}" if names else "",
    }
    write_json(status_path(run_id), data)
    append_event(run_id, {"event": "RUN_CREATED", "run_id": run_id})
    return data


def get_or_create_run(run_id: str | None) -> tuple[str, dict[str, Any]]:
    rid = run_id or new_run_id()
    if status_path(rid).exists():
        return rid, load_json(status_path(rid))
    return rid, init_run(rid)


def next_process_after(completed: list[str]) -> str | None:
    done = set(completed)
    for name in process_names():
        if name not in done:
            return name
    return None


def update_run_for_process(run_id: str, process: str, state: str, message: str = "") -> dict[str, Any]:
    data = load_json(status_path(run_id))
    completed = list(data.get("completed_processes") or [])

    # OK and SKIPPED both let the run advance to the next lane -- SKIPPED means
    # "intentionally not run, don't block progress", which is the conventional
    # meaning in build/CI pipelines. The process's own status.json/events still
    # record "SKIPPED" verbatim (see mark_process), never silently rewritten to
    # "OK" -- only run-level progression treats them the same way.
    if state in ("OK", "SKIPPED"):
        if process not in completed:
            completed.append(process)
        nxt = next_process_after(completed)
        status = "OK" if nxt is None else "READY"
        failed_process = None
        resume_from = nxt
        rerun_command = f"python3 appsec-review-process/run_process.py --run-id {run_id} --process {nxt}" if nxt else ""
    elif state in ("FAILED", "BLOCKED"):
        # Both halt run progression and need explicit human/LLM recovery
        # judgment before continuing (see initiate.md) -- reusing the single
        # failed_process/resume_from pointer for both rather than adding a
        # second schema field, since every reader of run-status.json already
        # treats "there's a stuck process" as one condition. The distinct
        # FAILED vs. BLOCKED state itself is preserved verbatim in the
        # process's own status.json and in events.jsonl, so nothing is lost --
        # only the top-level run-status.json's halt pointer is shared.
        status = state
        failed_process = process
        resume_from = process
        rerun_command = f"python3 appsec-review-process/run_process.py --run-id {run_id} --process {process}"
    else:
        status = state
        failed_process = data.get("failed_process")
        resume_from = process
        rerun_command = f"python3 appsec-review-process/run_process.py --run-id {run_id} --process {process}"

    data.update({
        "updated_at": now(),
        "status": status,
        "current_process": resume_from,
        "completed_processes": completed,
        "failed_process": failed_process,
        "resume_from": resume_from,
        "rerun_command": rerun_command,
        "last_message": message,
    })
    write_json(status_path(run_id), data)
    return data


def mark_process(run_id: str, process: str, state: str, message: str = "", budget: str = "") -> dict[str, Any]:
    from execution_state import read_json
    manifest = read_json(run_dir(run_id) / 'inputs/artifact-manifest.json')
    if manifest.get('orchestration_version') == 1:
        raise ValueError('orchestrated run state is owned by phase1.py; manual status changes are forbidden')
    run_data = load_json(status_path(run_id))
    selected_budget = budget or str(run_data.get("default_budget") or "probe")
    payload = {
        "schema": "appsec-review-process/process-status/0.1",
        "run_id": run_id,
        "process": process,
        "budget": selected_budget,
        "status": state,
        "updated_at": now(),
        "message": message,
        "prompt": str(ROOT / process / "prompt.md"),
        "config": str(ROOT / process / "config.md"),
        "subprompts": str(ROOT / process / "subprompts.md"),
    }
    write_json(process_status_path(run_id, process), payload)
    append_event(run_id, {"event": f"PROCESS_{state}", "process": process, "message": message})
    return update_run_for_process(run_id, process, state, message)


def markdown_summary(run_id: str, data: dict[str, Any]) -> None:
    lines = [
        "# AppSec Review Process Run",
        "",
        f"- run_id: `{run_id}`",
        f"- status: **{data.get('status')}**",
        f"- current_process: `{data.get('current_process')}`",
        f"- failed_process: `{data.get('failed_process')}`",
        f"- resume_from: `{data.get('resume_from')}`",
        f"- rerun_command: `{data.get('rerun_command')}`",
        "",
        "## Completed",
    ]
    completed = data.get("completed_processes") or []
    lines += [f"- `{p}`" for p in completed] or ["- none"]
    (run_dir(run_id) / "run-status.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", default="", help="existing run id; omitted creates a new run")
    ap.add_argument("--process", default="", help="process folder name, prefix, or name without numeric prefix")
    ap.add_argument("--budget", choices=["probe", "standard", "full"], default="", help="operational budget recorded for this process")
    ap.add_argument("--start", action="store_true", help="create run and print status")
    ap.add_argument("--list-processes", action="store_true")
    ap.add_argument("--fail-immediately", action="store_true", help="mark process failed without doing work")
    ap.add_argument("--mark-ok", action="store_true", help="mark process successful")
    ap.add_argument(
        "--status",
        choices=["OK", "FAILED", "BLOCKED", "SKIPPED"],
        default="",
        help=(
            "explicit terminal status for this process. Supersedes --mark-ok/--fail-immediately "
            "when given (those two remain for backward compatibility with existing manual usage "
            "and only ever express OK or FAILED). Use this to record BLOCKED (e.g. missing "
            "required inputs -- halts the run like FAILED, requires the same recovery judgment) "
            "or SKIPPED (intentionally not run -- the run advances to the next lane, same as OK, "
            "but the process's own status.json/events.jsonl still say SKIPPED, not OK)."
        ),
    )
    ap.add_argument("--message", default="")
    args = ap.parse_args()

    if args.list_processes:
        for name in process_names():
            print(name)
        return 0

    run_id, data = get_or_create_run(args.run_id or None)

    if args.start and not args.process and not args.fail_immediately and not args.mark_ok and not args.status:
        markdown_summary(run_id, data)
        print(json.dumps({"run_id": run_id, "status": data.get("status"), "status_path": str(status_path(run_id))}, indent=2))
        return 0

    process = resolve_process(args.process or data.get("resume_from") or data.get("current_process") or "")

    if args.status:
        data = mark_process(run_id, process, args.status, args.message or f"marked {args.status}", args.budget)
        markdown_summary(run_id, data)
        exit_code = 0 if args.status in ("OK", "SKIPPED") else 1
        print(json.dumps({"run_id": run_id, "process": process, "status": args.status, "resume_from": data.get("resume_from"), "status_path": str(status_path(run_id))}, indent=2))
        return exit_code
    if args.fail_immediately:
        data = mark_process(run_id, process, "FAILED", args.message or "intentional failure propagation test", args.budget)
        markdown_summary(run_id, data)
        print(json.dumps({"run_id": run_id, "process": process, "status": "FAILED", "resume_from": data.get("resume_from"), "status_path": str(status_path(run_id))}, indent=2))
        return 1
    if args.mark_ok:
        data = mark_process(run_id, process, "OK", args.message or "marked successful", args.budget)
        markdown_summary(run_id, data)
        print(json.dumps({"run_id": run_id, "process": process, "status": data.get("status"), "resume_from": data.get("resume_from"), "status_path": str(status_path(run_id))}, indent=2))
        return 0

    data = mark_process(run_id, process, "RUNNING", args.message or "manual process started", args.budget)
    markdown_summary(run_id, data)
    print(json.dumps({"run_id": run_id, "process": process, "status": "RUNNING", "prompt": str(ROOT / process / "prompt.md"), "status_path": str(status_path(run_id))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
