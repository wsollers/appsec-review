#!/usr/bin/env python3
"""review_cli.py -- single command surface for the appsec-review process harness.

Deterministic subcommands only (no LLM calls) unless explicitly noted:

  check       verify prerequisites (python, git, fable CLI, run dirs writable)
  next-lane   pick the next lane to run for a run-id, or flag ambiguous recovery
  budget      pick/validate the operational budget tier for a lane
  status      aggregate run status: lane states + pooled-worker progress, from
              on-disk artifacts only (safe to poll / run under `watch`)
  cost        summarize runs/<run_id>/telemetry.jsonl (token/time spend), if present

`run` / `run-all` (the actual fable-CLI dispatch, pool fan-out, and quorum
panel execution) are a deliberate follow-up slice -- not in this file yet.
See appsec-review-process/README.md and TODO.md for status.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"

# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_manifest() -> dict[str, Any]:
    return load_json(ROOT / "process-manifest.json")


def process_order() -> list[str]:
    manifest = load_manifest()
    order = manifest.get("process_order")
    if isinstance(order, list) and order:
        return [str(x) for x in order]
    # fall back to directory scan, sorted, same rule run_process.py uses
    return sorted(p.name for p in ROOT.iterdir() if p.is_dir() and p.name[:2].isdigit() and "-" in p.name)


def resolve_process(name: str) -> str:
    names = process_order()
    if name in names:
        return name
    matches = [n for n in names if n.startswith(name) or n[3:] == name]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"unknown process {name!r}; valid: {', '.join(names)}")
    raise SystemExit(f"ambiguous process {name!r}; matches: {', '.join(matches)}")


def run_dir(run_id: str) -> Path:
    return RUNS / run_id


def run_status(run_id: str) -> dict[str, Any]:
    return load_json(run_dir(run_id) / "run-status.json")


def manifest_for_run(run_id: str) -> dict[str, Any]:
    return load_json(run_dir(run_id) / "inputs" / "artifact-manifest.json")


def existing_path(p: str) -> Path | None:
    if not p:
        return None
    path = Path(p)
    return path if path.exists() else None


def latest_run_id() -> str | None:
    if not RUNS.exists():
        return None
    candidates = [p.name for p in RUNS.iterdir() if p.is_dir() and (p / "run-status.json").exists()]
    if not candidates:
        return None
    candidates.sort(key=lambda rid: (run_dir(rid) / "run-status.json").stat().st_mtime, reverse=True)
    return candidates[0]


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    add("python3", sys.version_info >= (3, 10), sys.version.split()[0])

    git_path = shutil.which("git")
    add("git", git_path is not None, git_path or "not found on PATH")

    fable_bin = args.fable_cli or "fable"
    fable_path = shutil.which(fable_bin)
    add(
        "fable CLI",
        fable_path is not None,
        fable_path or f"{fable_bin!r} not found on PATH -- set --fable-cli or FABLE_CLI env var once known",
    )

    manifest = load_manifest()
    add("process-manifest.json parses", bool(manifest.get("process_order")), f"{len(manifest.get('process_order') or [])} lanes in process_order")

    lane_dirs_ok = all((ROOT / lane).is_dir() for lane in process_order())
    add("all process_order lanes exist as directories", lane_dirs_ok, "")

    RUNS.mkdir(parents=True, exist_ok=True)
    # Write-only probe with a fixed name (no unlink): on the device-bridge sandbox,
    # deleting inside a connected folder is a separate, user-granted permission from
    # writing -- an unlink failure there is not evidence the directory is unwritable.
    try:
        probe = RUNS / ".write-check"
        probe.write_text("ok", encoding="utf-8")
        add("runs/ writable", True, str(RUNS))
    except Exception as exc:  # pragma: no cover
        add("runs/ writable", False, str(exc))

    ok = all(c["ok"] for c in checks)
    print(json.dumps({"ok": ok, "checks": checks}, indent=2))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# next-lane
# ---------------------------------------------------------------------------


def evidence_healthy(manifest: dict[str, Any]) -> tuple[bool, str]:
    core = manifest.get("core_artifacts") or {}
    job_status_json = existing_path(core.get("job_status_json", ""))
    job_status_md = existing_path(core.get("job_status_md", ""))
    if not job_status_md and not job_status_json:
        return False, "job-status.md/json not present in artifact manifest"
    if job_status_json:
        data = load_json(job_status_json)
        status = str(data.get("status") or data.get("Status") or "").upper()
        if status and status != "OK":
            return False, f"job-status.json status={status!r}, not OK"
        if not status:
            return False, "job-status.json present but has no status field"
    missing_core = [k for k, v in core.items() if not v]
    if missing_core:
        return False, f"missing core artifacts: {', '.join(missing_core)}"
    return True, "core artifacts present and job status OK"


def component_map_present(manifest: dict[str, Any]) -> tuple[bool, str]:
    derived = manifest.get("derived_artifacts") or {}
    p = existing_path(derived.get("component_purpose_map_json", ""))
    if not p:
        return False, "component-purpose-map.json not present"
    data = load_json(p)
    if not data:
        return False, "component-purpose-map.json present but empty/unparseable"
    return True, "component-purpose-map.json present"


def cmd_next_lane(args: argparse.Namespace) -> int:
    run_id = args.run_id
    status = run_status(run_id)
    if not status:
        raise SystemExit(f"no run-status.json for run {run_id!r}; run_process.py --start first")

    if status.get("failed_process"):
        result = {
            "run_id": run_id,
            "recommended_lane": None,
            "blocked": True,
            "ambiguous_recovery_needed": True,
            "reason": (
                f"process {status['failed_process']!r} is FAILED. This is a recovery decision, "
                "not a routing decision -- read runs/<run_id>/run-status.md and the lane's "
                "runs/<run_id>/processes/<lane>/status.json message, decide whether to retry, "
                "skip, or escalate to a human/LLM judgment call per initiate.md, then rerun "
                "run_process.py --mark-ok/--fail-immediately accordingly before calling next-lane again."
            ),
        }
        print(json.dumps(result, indent=2))
        return 2

    order = process_order()
    completed = set(status.get("completed_processes") or [])
    candidate = next((lane for lane in order if lane not in completed), None)

    manifest = manifest_for_run(run_id)
    reason_chain: list[str] = []
    if candidate is None:
        result = {"run_id": run_id, "recommended_lane": None, "blocked": False, "ambiguous_recovery_needed": False, "reason": "all lanes in process_order are complete"}
        print(json.dumps(result, indent=2))
        return 0

    # Rule from initiate.md step 10: if evidence isn't healthy, prioritize pregather,
    # unless pregather itself is the candidate or intake hasn't run yet.
    if candidate not in ("00-intake-recovery", "02-evidence-pregather"):
        healthy, why = evidence_healthy(manifest)
        if not healthy:
            reason_chain.append(f"evidence not healthy ({why}) -> overriding to 02-evidence-pregather")
            candidate = "02-evidence-pregather" if "02-evidence-pregather" not in completed else candidate

    # Rule from initiate.md step 11: if evidence is healthy but no component map, prioritize L0A.
    if candidate not in ("00-intake-recovery", "02-evidence-pregather", "01-component-characterization"):
        present, why = component_map_present(manifest)
        if not present:
            reason_chain.append(f"no component-purpose-map ({why}) -> overriding to 01-component-characterization")
            candidate = "01-component-characterization" if "01-component-characterization" not in completed else candidate

    if not reason_chain:
        reason_chain.append(f"next in process_order not yet completed: {candidate}")

    result = {
        "run_id": run_id,
        "recommended_lane": candidate,
        "blocked": False,
        "ambiguous_recovery_needed": False,
        "reason": "; ".join(reason_chain),
    }
    print(json.dumps(result, indent=2))
    return 0


# ---------------------------------------------------------------------------
# budget
# ---------------------------------------------------------------------------

def _split_row(line: str) -> list[str]:
    cells = line.strip().strip("|").split("|")
    return [c.strip().strip("`") for c in cells]


def _num_or_none(v: str) -> int | None:
    """Numeric cap if the cell is a plain integer; None for anything else
    ("all", "bounded by lane", free text, etc.) -- those are non-numeric
    policy statements, not caps this script can enforce, and are kept
    verbatim in the parallel *_raw field so nothing is silently lost."""
    try:
        return int(v)
    except ValueError:
        return None


def parse_budget_policy() -> dict[str, dict[str, Any]]:
    """Parse the Default Budgets table straight out of budget-policy.md so the
    thresholds here can never silently drift from the documented policy.
    Row-by-row cell split rather than a fixed-shape regex, because some cells
    (e.g. full's "bounded by lane") are free text, not a bare number/"all"."""
    lines = (ROOT / "budget-policy.md").read_text(encoding="utf-8").splitlines()
    header_idx = next((i for i, l in enumerate(lines) if l.strip().lower().startswith("| budget")), None)
    if header_idx is None:
        raise SystemExit("could not find the Default Budgets table header in budget-policy.md -- did its format change?")

    table: dict[str, dict[str, Any]] = {}
    for line in lines[header_idx + 2 :]:  # skip header + separator row
        if not line.strip().startswith("|"):
            break
        cells = _split_row(line)
        if len(cells) < 5:
            continue
        tier, clusters, components, files, out_lines = cells[:5]
        if tier not in ("probe", "standard", "full"):
            continue
        table[tier] = {
            "max_clusters": _num_or_none(clusters),
            "max_clusters_raw": clusters,
            "max_components": _num_or_none(components),
            "max_components_raw": components,
            "max_source_files": _num_or_none(files),
            "max_source_files_raw": files,
            "max_output_lines": _num_or_none(out_lines),
            "max_output_lines_raw": out_lines,
        }
    if not table:
        raise SystemExit("could not parse Default Budgets table out of budget-policy.md -- did its format change?")
    return table


def _measure(data: Any, keys: list[str]) -> tuple[int | None, str]:
    if isinstance(data, list):
        return len(data), "top-level list length"
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                return len(v), f"len(data[{k!r}])"
            if isinstance(v, dict):
                return len(v), f"len(data[{k!r}].keys())"
        # fall back: dict of id -> record is a common shape for these artifacts
        if data:
            return len(data), "len(data.keys()) -- no known key matched, best-effort fallback"
    return None, "not found"


def measure_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    core = manifest.get("core_artifacts") or {}
    derived = manifest.get("derived_artifacts") or {}

    clusters_path = existing_path(core.get("correlated_findings_json", ""))
    components_path = existing_path(derived.get("component_purpose_map_json", ""))
    files_path = existing_path(core.get("coverage_ledger_json", ""))

    measurements: dict[str, Any] = {}
    for label, path, keys in (
        ("clusters", clusters_path, ["clusters", "correlated_findings", "findings"]),
        ("components", components_path, ["components", "component_purpose_map"]),
        ("source_files", files_path, ["source_files", "files", "covered_files"]),
    ):
        if path is None:
            measurements[label] = {"count": None, "confidence": "unknown", "source": None, "detail": "artifact not present in manifest / not on disk yet"}
            continue
        data = load_json(path) if path.suffix == ".json" else {}
        count, detail = _measure(data, keys)
        confidence = "medium" if count is not None and "best-effort fallback" not in detail else ("unknown" if count is None else "low")
        measurements[label] = {"count": count, "confidence": confidence, "source": str(path), "detail": detail}
    return measurements


def cmd_budget(args: argparse.Namespace) -> int:
    table = parse_budget_policy()
    run_id = args.run_id
    status = run_status(run_id)
    manifest = manifest_for_run(run_id)
    measurements = measure_manifest(manifest)

    requested = args.requested or str(status.get("default_budget") or "") or None
    notes: list[str] = []

    any_unknown = any(m["count"] is None for m in measurements.values())

    def fits(tier: str) -> bool:
        caps = table[tier]
        for label, cap_key in (("clusters", "max_clusters"), ("components", "max_components"), ("source_files", "max_source_files")):
            cap = caps[cap_key]
            count = measurements[label]["count"]
            if cap is not None and count is not None and count > cap:
                return False
        return True

    # A None count is "we don't know yet", not "0" -- it must never be treated
    # as satisfying every cap. Only compute cheapest-that-fits when every
    # metric was actually measured; otherwise this would silently recommend
    # 'probe' purely because pregather/component-characterization hasn't run
    # yet, which is a false-confidence bug, not a real recommendation.
    cheapest_that_fits = next((tier for tier in ("probe", "standard", "full") if fits(tier)), "full") if not any_unknown else None

    if requested:
        if requested not in table:
            raise SystemExit(f"unknown budget {requested!r}; valid: probe, standard, full")
        recommended = requested
        if any_unknown:
            pass  # nothing comparable to say yet; the any_unknown note below covers it
        elif not fits(requested):
            notes.append(f"requested budget {requested!r} will likely truncate work and hit its stop rule for at least one metric -- see measurements vs. caps below")
        elif requested != cheapest_that_fits and ("probe", "standard", "full").index(requested) > ("probe", "standard", "full").index(cheapest_that_fits):
            notes.append(f"requested budget {requested!r} is more than the measured evidence needs -- {cheapest_that_fits!r} would already cover it without truncation; consider downgrading to save spend")
    elif any_unknown:
        recommended = str(status.get("default_budget") or "probe")
        notes.append(f"evidence counts unknown -- cannot compute a fitted recommendation yet, falling back to the run's default_budget ({recommended!r})")
    else:
        recommended = cheapest_that_fits
        notes.append("no requested budget given -- recommending the cheapest tier whose caps are not exceeded by measured evidence")

    if any_unknown:
        notes.append("one or more evidence counts are unknown (artifact missing/not yet produced) -- any budget comparison above is provisional until pregather/component-characterization has run")

    result = {
        "run_id": run_id,
        "requested_budget": requested,
        "recommended_budget": recommended,
        "cheapest_tier_that_fits_measured_evidence": cheapest_that_fits,
        "caps": table,
        "measurements": measurements,
        "notes": notes,
    }
    print(json.dumps(result, indent=2))
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def cmd_status(args: argparse.Namespace) -> int:
    run_id = args.run_id or latest_run_id()
    if not run_id:
        raise SystemExit("no runs found under appsec-review-process/runs/")
    status = run_status(run_id)
    if not status:
        raise SystemExit(f"no run-status.json for run {run_id!r}")

    order = process_order()
    completed = set(status.get("completed_processes") or [])
    failed = status.get("failed_process")
    outputs_root = run_dir(run_id) / "outputs"

    lanes = []
    for lane in order:
        lane_status = "OK" if lane in completed else ("FAILED" if lane == failed else "PENDING")
        lane_out = outputs_root / lane
        entry: dict[str, Any] = {
            "lane": lane,
            "status": lane_status,
            "result_md_present": (lane_out / "result.md").exists(),
        }
        pool_dir = lane_out / "pool"
        if pool_dir.exists():
            worker_files = sorted(pool_dir.glob("worker-*.json")) + sorted(pool_dir.glob("worker-*.md"))
            pool_status = load_json(lane_out / "pool-status.json")
            expected = pool_status.get("pool_size")
            done = len({p.stem.split(".")[0] for p in worker_files})
            entry["pool"] = {
                "expected_workers": expected,
                "workers_with_output": done,
                "complete": (done >= expected) if isinstance(expected, int) else None,
            }
        lanes.append(entry)

    events_path = run_dir(run_id) / "events.jsonl"
    last_events = []
    if events_path.exists():
        lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-args.tail_events:]:
            try:
                last_events.append(json.loads(line))
            except Exception:
                continue

    result = {
        "run_id": run_id,
        "status": status.get("status"),
        "current_process": status.get("current_process"),
        "failed_process": failed,
        "resume_from": status.get("resume_from"),
        "completed_count": len(completed),
        "total_lanes": len(order),
        "lanes": lanes,
        "recent_events": last_events,
    }
    print(json.dumps(result, indent=2))
    return 0


# ---------------------------------------------------------------------------
# cost
# ---------------------------------------------------------------------------


def cmd_cost(args: argparse.Namespace) -> int:
    run_id = args.run_id or latest_run_id()
    if not run_id:
        raise SystemExit("no runs found under appsec-review-process/runs/")
    telemetry_path = run_dir(run_id) / "telemetry.jsonl"
    if not telemetry_path.exists():
        print(json.dumps({"run_id": run_id, "note": "no telemetry.jsonl yet -- populated once `run`/`run-all` (fable CLI dispatch) exists", "spans": 0}, indent=2))
        return 0

    by_lane: dict[str, dict[str, float]] = {}
    total_calls = 0
    for line in telemetry_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            span = json.loads(line)
        except Exception:
            continue
        total_calls += 1
        lane = str(span.get("lane") or "unknown")
        agg = by_lane.setdefault(lane, {"calls": 0, "duration_seconds": 0.0, "input_tokens": 0.0, "output_tokens": 0.0})
        agg["calls"] += 1
        agg["duration_seconds"] += float(span.get("duration_seconds") or 0)
        agg["input_tokens"] += float(span.get("input_tokens") or 0)
        agg["output_tokens"] += float(span.get("output_tokens") or 0)

    print(json.dumps({"run_id": run_id, "total_calls": total_calls, "by_lane": by_lane}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="review_cli.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="verify prerequisites")
    p_check.add_argument("--fable-cli", default="", help="name/path of the fable CLI binary (default: env FABLE_CLI or 'fable')")
    p_check.set_defaults(func=cmd_check)

    p_next = sub.add_parser("next-lane", help="deterministic next-lane picker")
    p_next.add_argument("--run-id", required=True)
    p_next.set_defaults(func=cmd_next_lane)

    p_budget = sub.add_parser("budget", help="deterministic budget picker")
    p_budget.add_argument("--run-id", required=True)
    p_budget.add_argument("--requested", choices=["probe", "standard", "full"], default="")
    p_budget.set_defaults(func=cmd_budget)

    p_status = sub.add_parser("status", help="aggregate run/lane/pool status from on-disk artifacts, no LLM calls")
    p_status.add_argument("--run-id", default="", help="defaults to the most recently updated run")
    p_status.add_argument("--tail-events", type=int, default=10)
    p_status.set_defaults(func=cmd_status)

    p_cost = sub.add_parser("cost", help="summarize runs/<run_id>/telemetry.jsonl")
    p_cost.add_argument("--run-id", default="", help="defaults to the most recently updated run")
    p_cost.set_defaults(func=cmd_cost)

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    import os

    if args.command == "check" and not args.fable_cli:
        args.fable_cli = os.environ.get("FABLE_CLI", "")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
