#!/usr/bin/env python3
"""Print one line per job partition of a run: latest attempt status and accepted status.

    python3 orchestrator/run-status.py <run-id> [--failed] [--tooling]

--tooling appends the lookup-tool check of retrieval-report.py --check (findings only; the exit code
stays 0, so nothing fails on it).
"""
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def status_of(attempt: Path):
    for name in ("status.json", "result.json"):
        doc = read(attempt / name)
        if isinstance(doc, dict):
            for key in ("execution_status", "status", "state"):
                if isinstance(doc.get(key), str):
                    cause = doc.get("cause") or doc.get("reason") or doc.get("error") or ""
                    if isinstance(cause, dict):
                        cause = cause.get("message") or json.dumps(cause)[:160]
                    return doc[key], str(cause)[:160]
    return "?", ""


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    run_id, failed_only = sys.argv[1], "--failed" in sys.argv
    jobs = REPO / "appsec-review-process" / "runs" / run_id / "data" / "jobs"
    if not jobs.is_dir():
        print(f"no jobs directory: {jobs}"); return 2
    counts = {}
    for job in sorted(p for p in jobs.iterdir() if p.is_dir()):
        parts = [p for p in job.iterdir() if p.is_dir() and (p / "attempts").is_dir()] or [job]
        for part in sorted(parts):
            latest = read(part / "latest.json") or {}
            accepted = read(part / "accepted.json") or {}
            attempt_id = latest.get("attempt_id")
            status, cause = status_of(part / "attempts" / attempt_id) if attempt_id else ("-", "")
            acc = accepted.get("status") or ("ACCEPTED" if accepted.get("attempt_id") else "-")
            counts[status] = counts.get(status, 0) + 1
            if failed_only and status not in {"FAILED", "BLOCKED", "?"}:
                continue
            label = job.name if part == job else f"{job.name}/{part.name}"
            print(f"{label:55} {status:14} accepted={acc:10} {cause}")
    print("totals:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if "--tooling" in sys.argv:
        try:
            tooling(run_id)
        except Exception as exc:   # informational: a report problem never changes the status output
            print(f"tooling check unavailable: {type(exc).__name__}: {exc}")
    return 0


def tooling(run_id: str) -> None:
    """retrieval-report.py --check, printed after the job lines; never changes the exit code."""
    spec = importlib.util.spec_from_file_location("retrieval_report", Path(__file__).resolve().parent / "retrieval-report.py")
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)
    report.RUNS = REPO / "appsec-review-process" / "runs"
    loaded = report.load(run_id)
    findings = report.check(report.summarize(loaded), report.feedback(loaded))
    print("tooling check: " + (f"{len(findings)} finding(s)" if findings else "no finding")
          + f" (details: orchestrator/retrieval-report.py {run_id} --summary --feedback)")
    for rule, detail in findings:
        print(f"  [{rule}] {detail}")


if __name__ == "__main__":
    raise SystemExit(main())
