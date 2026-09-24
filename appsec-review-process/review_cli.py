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
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
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


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_manifest() -> dict[str, Any]:
    return load_json(ROOT / "process-manifest.json")


def load_model_config() -> dict[str, Any]:
    path = ROOT / "model-config.json"
    data = load_json(path)
    if not data:
        raise SystemExit(f"could not read/parse {path} -- model-config.json is required (see its _notes field)")
    return data


def load_job_template(lane: str) -> dict[str, Any]:
    return load_json(ROOT / "registry" / "job-templates" / f"{lane}.json")


def resolve_model(lane: str, budget: str, model_override: str = "", effort_override: str = "") -> dict[str, Any]:
    """Deterministic model/effort resolution, lowest precedence first:
    default -> budget_effort_floor (effort only) -> the lane's own job-template `model`
    field (if that job template exists) or, only when it doesn't yet exist,
    model-config.json's `unbuilt_job_defaults` bridge -> a per-call CLI override
    (--model/--effort on `run`), which always wins.

    Design (William, 2026-09-24): a job declares the model/effort it needs in its OWN
    registry job-template record, not in a lane-keyed table here -- the job, not the lane
    it happens to run in, knows what it needs. `unbuilt_job_defaults` exists only because a
    handful of lanes are referenced by the job graph before their job template is authored;
    once a job template exists, this function reads its `model` field and never consults
    `unbuilt_job_defaults` for that lane again, even if the job template leaves `model` unset
    (that is the job's own choice to take the process-wide default).

    The CLI override exists so a cheap model/effort can be used for a dev/mechanics-
    validation pass without editing model-config.json or a job template (the resolved
    `default`/job-declared value stays the real, intended-for-actual-review setting)."""
    cfg = load_model_config()
    default = cfg.get("default") or {}
    model = default.get("model", "")
    effort = default.get("effort", "")

    floor = (cfg.get("budget_effort_floor") or {}).get(budget)
    if floor:
        effort = floor

    template = load_job_template(lane)
    template_model = template.get("model") if isinstance(template.get("model"), dict) else None
    pending = None
    if template:
        if template_model:
            if template_model.get("model"):
                model = template_model["model"]
            if template_model.get("effort"):
                effort = template_model["effort"]
    else:
        pending = (cfg.get("unbuilt_job_defaults") or {}).get(lane) or {}
        if pending.get("model"):
            model = pending["model"]
        if pending.get("effort"):
            effort = pending["effort"]
        pending = pending or None

    if model_override:
        model = model_override
    if effort_override:
        effort = effort_override

    return {
        "lane": lane,
        "budget": budget,
        "model": model,
        "effort": effort,
        "source": {
            "default": default,
            "budget_effort_floor_applied": floor,
            "job_template_model_applied": template_model,
            "unbuilt_job_defaults_applied": pending,
            "cli_override_applied": {"model": model_override, "effort": effort_override} if (model_override or effort_override) else None,
        },
        "invocation": cfg.get("invocation"),
    }


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
    from execution_state import run_path
    return run_path(run_id)


def run_status(run_id: str) -> dict[str, Any]:
    return load_json(run_dir(run_id) / "run-status.json")


def manifest_for_run(run_id: str) -> dict[str, Any]:
    # Never downgrade a corrupt orchestrated manifest into the permissive legacy dispatcher.
    from execution_state import read_json
    value = read_json(run_dir(run_id) / "inputs" / "artifact-manifest.json")
    if not isinstance(value, dict):
        raise ValueError('artifact manifest must be an object')
    return value


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

    model_cfg = load_model_config()
    add("model-config.json parses", bool(model_cfg.get("default", {}).get("model")), f"default model={model_cfg.get('default', {}).get('model')!r} effort={model_cfg.get('default', {}).get('effort')!r}")

    invocation = model_cfg.get("invocation") or {}
    model_bin = invocation.get("binary", "")
    model_bin_path = shutil.which(model_bin) if model_bin else None
    add(
        f"model CLI ({model_bin!r})",
        model_bin_path is not None,
        (model_bin_path or f"{model_bin!r} not found on PATH -- see model-config.json's invocation.status")
        + " -- NOTE: this resolves against review_cli.py's own process PATH, which differs between the device-bridge sandbox and your real terminal; a pass here from the sandbox does not confirm your real environment, and a fail here does not mean your real environment lacks it.",
    )
    status = invocation.get("status", "")
    if status.startswith("PROVISIONAL"):
        add("model-config.json invocation.status", False, status)
    open_qs = invocation.get("open_questions") or []
    if open_qs:
        add("model-config.json invocation.open_questions", False, f"{len(open_qs)} unresolved: {'; '.join(open_qs)}")

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
# model
# ---------------------------------------------------------------------------


def cmd_model(args: argparse.Namespace) -> int:
    lane = resolve_process(args.lane)
    print(json.dumps(resolve_model(lane, args.budget), indent=2))
    return 0


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
    manifest = manifest_for_run(run_id)
    if manifest.get('orchestration_version') == 1:
        from phase1 import main as phase1_main
        return phase1_main(['status', '--run-id', run_id])
    status = run_status(run_id)
    if not status:
        raise SystemExit(f"no run-status.json for run {run_id!r}; run_process.py --start first")

    if status.get("failed_process"):
        # run-status.json's failed_process/resume_from pointer is shared
        # between FAILED and BLOCKED (see run_process.py's
        # update_run_for_process) -- look at the process's own status.json to
        # report which one it actually is, rather than assuming FAILED.
        stuck_lane = status["failed_process"]
        stuck_status_data = load_json(run_dir(run_id) / "processes" / stuck_lane / "status.json")
        real_state = stuck_status_data.get("status") or "FAILED"
        result = {
            "run_id": run_id,
            "recommended_lane": None,
            "blocked": True,
            "ambiguous_recovery_needed": True,
            "reason": (
                f"process {stuck_lane!r} is {real_state}. This is a recovery decision, "
                "not a routing decision -- read runs/<run_id>/run-status.md and the lane's "
                "runs/<run_id>/processes/<lane>/status.json message, decide whether to retry, "
                "skip, or escalate to a human/LLM judgment call per initiate.md, then rerun "
                "run_process.py --status OK/FAILED/BLOCKED/SKIPPED accordingly before calling "
                "next-lane again."
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
    manifest = manifest_for_run(run_id)
    if manifest.get('orchestration_version') == 1:
        import workflow
        if (workflow.root(run_id)/'status.json').exists():
            status=workflow.inspect_status(run_id)
            print(json.dumps(status,indent=2))
            return 0 if status['status']=='OK' else 1
        from phase1 import main as phase1_main
        return phase1_main(['status', '--run-id', run_id])
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
    total_cost_usd = 0.0
    for line in telemetry_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            span = json.loads(line)
        except Exception:
            continue
        total_calls += 1
        lane = str(span.get("lane") or "unknown")
        agg = by_lane.setdefault(lane, {"calls": 0, "duration_seconds": 0.0, "total_cost_usd": 0.0, "input_tokens": 0.0, "output_tokens": 0.0, "cache_read_input_tokens": 0.0, "cache_creation_input_tokens": 0.0})
        agg["calls"] += 1
        agg["duration_seconds"] += float(span.get("duration_seconds") or 0)
        cost = float(span.get("total_cost_usd") or 0)
        agg["total_cost_usd"] += cost
        total_cost_usd += cost
        for field in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
            agg[field] += float(span.get(field) or 0)

    print(json.dumps({"run_id": run_id, "total_calls": total_calls, "total_cost_usd": round(total_cost_usd, 4), "by_lane": by_lane}, indent=2))
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def lane_tools(lane: str) -> list[str]:
    cfg = load_model_config()
    lt = cfg.get("lane_tools") or {}
    return list(lt.get(lane) or lt.get("default") or ["Read", "Grep", "Glob", "Write"])


def _dispatch_streaming(argv: list[str], prompt_text: str, timeout: int, transcript_path: Path) -> dict[str, Any]:
    """Run `claude -p --output-format stream-json` and capture the full
    turn-by-turn exchange (every SDK event: system/init, assistant messages,
    tool_use, tool_result, the works) to transcript_path as JSONL, one event
    per line, as it arrives -- not just the compressed final summary. This is
    the SAME underlying API call as the old single-shot `--output-format
    json` (it costs nothing extra); stream-json just asks the CLI to also
    hand us every intermediate event locally instead of swallowing them.

    Returns a dict with keys: final_result (the terminal `type: "result"`
    event, shape-compatible with the old single-JSON-object response, or
    None if the stream never produced one), events (list of all parsed
    events), returncode, timed_out, stderr_text.
    """
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )

    events: list[dict[str, Any]] = []
    state: dict[str, Any] = {"final_result": None}

    def _pump_stdout() -> None:
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("w", encoding="utf-8") as tf:
            assert proc.stdout is not None
            for line in proc.stdout:
                tf.write(line if line.endswith("\n") else line + "\n")
                tf.flush()
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    ev = json.loads(stripped)
                except Exception:
                    continue
                events.append(ev)
                if isinstance(ev, dict) and ev.get("type") == "result":
                    state["final_result"] = ev

    def _feed_stdin() -> None:
        try:
            assert proc.stdin is not None
            proc.stdin.write(prompt_text)
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    reader = threading.Thread(target=_pump_stdout, daemon=True)
    writer = threading.Thread(target=_feed_stdin, daemon=True)
    reader.start()
    writer.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()

    writer.join(timeout=10)
    reader.join(timeout=10)

    stderr_text = ""
    try:
        if proc.stderr is not None:
            stderr_text = proc.stderr.read() or ""
    except Exception:
        pass

    return {
        "final_result": state["final_result"],
        "events": events,
        "returncode": proc.returncode,
        "timed_out": timed_out,
        "stderr_text": stderr_text,
    }


def build_claude_argv(lane: str, budget: str, run_id: str, model_override: str = "", effort_override: str = "") -> list[str]:
    resolved = resolve_model(lane, budget, model_override, effort_override)
    cfg = load_model_config()
    invocation = cfg.get("invocation") or {}
    usd = (cfg.get("budget_max_usd_per_call") or {}).get(budget)

    argv = [invocation.get("binary", "claude")] + list(invocation.get("fixed_flags") or ["-p", "--output-format", "json", "--no-session-persistence", "--permission-mode", "bypassPermissions"])
    argv += ["--model", resolved["model"], "--effort", resolved["effort"]]
    if usd is not None:
        argv += ["--max-budget-usd", str(usd)]
    argv += ["--fallback-model", cfg.get("default", {}).get("model", "claude-sonnet-5")]
    argv += ["--allowedTools", ",".join(lane_tools(lane))]

    # Scope --add-dir to what this lane actually needs to read/write: the run's
    # own directory (inputs/outputs) plus the target repo and engagement output
    # from the artifact manifest, when known. Real filesystem scoping, not a
    # prompt instruction -- narrower than "the whole machine" even in this
    # unpooled slice.
    manifest = manifest_for_run(run_id)
    add_dirs = [str(run_dir(run_id))]
    target_path = (manifest.get("target") or {}).get("repo_path", "")
    engagement_output = manifest.get("engagement_output", "")
    for p in (target_path, engagement_output):
        if p:
            add_dirs.append(p)
    for d in add_dirs:
        argv += ["--add-dir", d]

    return argv


LOCK_STALE_SECONDS = 3600  # a lock held longer than this is assumed abandoned
                           # (e.g. a killed/crashed process that never reached
                           # the `finally` release) and is reclaimed rather
                           # than waited on forever.


def acquire_run_lock(run_id: str, poll_seconds: int = 10, wait_timeout_seconds: int = 3600) -> Path:
    """Directory-based mutex so two `review_cli.py run` invocations against the
    same run-id can't race on outputs/<lane>/ archiving or run-status.json
    writes -- `Path.mkdir()` is atomic on both POSIX and Windows (it raises
    FileExistsError if the directory already exists), so no extra dependency
    is needed. Polls with a plain time.sleep(poll_seconds) while waiting; this
    is pure local wall-clock time -- no claude/API calls happen in this loop,
    so waiting here costs nothing beyond the wait itself. Always release with
    release_run_lock() in a `finally` block."""
    lock_dir = run_dir(run_id) / ".lock"
    lock_meta = lock_dir / "holder.json"
    waited = 0
    while True:
        try:
            lock_dir.mkdir(parents=True, exist_ok=False)
            write_json(lock_meta, {"pid": os.getpid(), "acquired_at": now()})
            return lock_dir
        except FileExistsError:
            age = None
            try:
                held = load_json(lock_meta)
                acquired_at = held.get("acquired_at", "")
                if acquired_at:
                    then = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - then).total_seconds()
            except Exception:
                pass
            if age is not None and age > LOCK_STALE_SECONDS:
                print(f"run lock at {lock_dir} is {age:.0f}s old (> {LOCK_STALE_SECONDS}s) -- "
                      f"assuming abandoned (a prior review_cli.py run likely crashed/was killed "
                      f"before releasing it), reclaiming", file=sys.stderr)
                shutil.rmtree(lock_dir, ignore_errors=True)
                continue
            if waited >= wait_timeout_seconds:
                raise SystemExit(
                    f"could not acquire run lock at {lock_dir} after {wait_timeout_seconds}s -- "
                    f"another review_cli.py run is likely still dispatching this run-id, or the "
                    f"lock is stale but younger than {LOCK_STALE_SECONDS}s; if you're sure nothing "
                    f"else is running, remove {lock_dir} by hand"
                )
            time.sleep(poll_seconds)
            waited += poll_seconds


def release_run_lock(lock_dir: Path) -> None:
    shutil.rmtree(lock_dir, ignore_errors=True)


def cmd_run(args: argparse.Namespace) -> int:
    if manifest_for_run(args.run_id).get('orchestration_version') == 1:
        if resolve_process(args.lane) != '00-intake-recovery':
            raise SystemExit('Downstream dispatch is not implemented for orchestrated runs; use the validated handoff.')
        from phase1 import main as phase1_main
        if args.dry_run:
            return phase1_main(['status', '--run-id', args.run_id])
        from launch_job import main as launch_main
        return launch_main(['--run-id', args.run_id, '--job', 'phase1_intake', '--wait'])
    run_id = args.run_id
    lane = resolve_process(args.lane)
    status = run_status(run_id)
    if not status:
        raise SystemExit(f"no run-status.json for run {run_id!r}; run_process.py --start first")
    budget = args.budget or str(status.get("default_budget") or "probe")

    handoff_path = run_dir(run_id) / "handoffs" / f"{lane}.md"
    handoff_cmd = [sys.executable, str(ROOT / "create_handoff.py"), "--run-id", run_id, "--process", lane, "--budget", budget]
    handoff_proc = subprocess.run(handoff_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if handoff_proc.returncode != 0:
        raise SystemExit(f"create_handoff.py failed:\n{handoff_proc.stdout}\n{handoff_proc.stderr}")
    if not handoff_path.exists():
        raise SystemExit(f"create_handoff.py reported success but {handoff_path} does not exist")
    prompt_text = handoff_path.read_text(encoding="utf-8")

    argv = build_claude_argv(lane, budget, run_id, args.model, args.effort)

    if args.dry_run:
        print(json.dumps({
            "run_id": run_id, "lane": lane, "budget": budget, "dry_run": True,
            "argv": argv, "stdin_source": str(handoff_path), "stdin_chars": len(prompt_text),
        }, indent=2))
        return 0

    out_dir = run_dir(run_id) / "outputs" / lane
    lock_dir = acquire_run_lock(run_id, wait_timeout_seconds=args.lock_wait_timeout)
    try:
        return _cmd_run_locked(args, run_id, lane, budget, argv, prompt_text, handoff_path, out_dir)
    finally:
        release_run_lock(lock_dir)


def _cmd_run_locked(
    args: argparse.Namespace, run_id: str, lane: str, budget: str, argv: list[str],
    prompt_text: str, handoff_path: Path, out_dir: Path,
) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Archive EVERY previous attempt's output file before dispatching again
    # -- not just the fixed result.md/status.json/raw-response.json set.
    # Originally this list was hardcoded to those three (later five, once
    # transcript.jsonl/stderr.log were added), which missed each lane's own
    # derived artifacts (e.g. component-purpose-map.json/.md for lane 01,
    # dfd-stride.md for lane 03, ...). A stale derived artifact left in
    # out_dir from a prior attempt does two bad things: (1) it mimics a
    # fresh self-report the same way a stale status.json did (see the
    # original comment/bug this replaces), and (2) worse, found for real on
    # 2026-09-18 -- when the lane's Write tool call hits an existing file it
    # hasn't Read first, it errors "File has not been read yet", which
    # pushed the model into an unreliable PowerShell-heredoc workaround loop
    # instead of a clean write, and directly preceded a run where the
    # required component-purpose-map.md was silently never produced despite
    # a self-reported OK. Archiving every plain file directly under out_dir
    # (never touching subdirectories like attempts//pool/) means every
    # dispatch starts from a genuinely empty output directory regardless of
    # which files a given lane happens to produce.
    prior_files = [p.name for p in out_dir.iterdir() if p.is_file()] if out_dir.exists() else []
    if prior_files:
        attempt_dir = out_dir / "attempts" / now().replace(":", "").replace("-", "")
        attempt_dir.mkdir(parents=True, exist_ok=True)
        for name in prior_files:
            (out_dir / name).replace(attempt_dir / name)

    mark_running = subprocess.run(
        [sys.executable, str(ROOT / "run_process.py"), "--run-id", run_id, "--process", lane, "--budget", budget, "--message", "dispatched via review_cli.py run"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if mark_running.returncode != 0:
        raise SystemExit(f"run_process.py (mark RUNNING) failed:\n{mark_running.stdout}\n{mark_running.stderr}")

    # transcript.jsonl captures the FULL turn-by-turn exchange (every event
    # the stream-json format emits: init, assistant messages, tool_use,
    # tool_result, the terminal result) as it happens -- not just the final
    # compressed summary. Same underlying API call as before, zero extra
    # cost; --output-format stream-json just asks the CLI to hand us the
    # intermediate events locally instead of swallowing them. Written fresh
    # each attempt (prior attempts already archived above).
    transcript_path = out_dir / "transcript.jsonl"

    started = time.time()
    dispatch = _dispatch_streaming(argv, prompt_text, args.timeout, transcript_path)
    duration_seconds = time.time() - started

    timed_out = dispatch["timed_out"]
    returncode = dispatch["returncode"]
    final_result = dispatch["final_result"]

    class _ProcShim:
        """Minimal stand-in for the old subprocess.run() CompletedProcess,
        so the rest of this function (which only reads .returncode) doesn't
        need to change."""
        def __init__(self, returncode):
            self.returncode = returncode

    proc = None if (timed_out and final_result is None and returncode is None) else _ProcShim(returncode)

    # raw-response.json keeps its old shape (the single terminal result
    # object, same fields as the old --output-format json response: is_error,
    # subtype, total_cost_usd, usage, result, num_turns, ...) so nothing
    # downstream that reads it needs to change. transcript.jsonl is the new,
    # additional artifact with everything in between.
    raw_path = out_dir / "raw-response.json"
    raw_path.write_text(json.dumps(final_result, indent=2) if final_result is not None else "", encoding="utf-8")

    if dispatch["stderr_text"]:
        (out_dir / "stderr.log").write_text(dispatch["stderr_text"], encoding="utf-8")

    parsed: dict[str, Any] = final_result if isinstance(final_result, dict) else {}
    result_text = ""
    parse_ok = False
    if isinstance(final_result, dict):
        for key in ("result", "output", "text", "response", "content"):
            if isinstance(final_result.get(key), str) and final_result[key].strip():
                result_text = final_result[key]
                parse_ok = True
                break
    if not parse_ok:
        # No terminal result event parsed (crash, timeout mid-stream, or a
        # stream-json format surprise) -- fall back to whatever raw text we
        # captured in the transcript so nothing is silently empty.
        try:
            result_text = transcript_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            result_text = ""

    VALID_STATES = ("OK", "FAILED", "BLOCKED", "SKIPPED")

    # The lane itself may have already written its own result.md/status.json
    # via its Write tool during the call (its prompt/config tells it to, and
    # Write is in --allowedTools). That self-report is authoritative -- it
    # can say BLOCKED or SKIPPED, which a bare claude-process exit code can
    # never tell us (exit 0 only means the CLI call itself succeeded, not
    # that the lane's actual outcome was "OK"). Never clobber it with a
    # synthesized version; only fill in when the lane didn't write one.
    self_status_path = out_dir / "status.json"
    self_status = load_json(self_status_path) if self_status_path.exists() else {}
    self_reported = isinstance(self_status.get("status"), str) and self_status["status"] in VALID_STATES

    if self_reported:
        final_status = self_status["status"]
        status_source = "lane self-reported (status.json it wrote itself)"
        # Leave the lane's own result.md/status.json exactly as it wrote them.
    else:
        final_status = "OK" if (not timed_out and proc is not None and proc.returncode == 0) else "FAILED"
        status_source = "synthesized from claude exit code (lane did not write its own status.json -- cannot infer BLOCKED/SKIPPED this way)"
        (out_dir / "result.md").write_text(result_text, encoding="utf-8")
        write_json(self_status_path, {
            "schema": "appsec-review-process/process-status/0.1",
            "run_id": run_id,
            "process": lane,
            "budget": budget,
            "status": final_status,
            "updated_at": now(),
            "message": ("timed out after %ss" % args.timeout) if timed_out else (f"claude exit={proc.returncode}" if proc is not None else "no process result"),
            "parse_ok": parse_ok,
            "status_source": status_source,
            "total_cost_usd": parsed.get("total_cost_usd") if isinstance(parsed, dict) else None,
            "duration_seconds": duration_seconds,
        })

    usage = parsed.get("usage") if isinstance(parsed, dict) else None
    usage = usage if isinstance(usage, dict) else {}
    telemetry_path = run_dir(run_id) / "telemetry.jsonl"
    with telemetry_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "lane": lane, "budget": budget,
            "model": resolve_model(lane, budget, args.model, args.effort)["model"],
            "effort": resolve_model(lane, budget, args.model, args.effort)["effort"],
            "duration_seconds": duration_seconds,
            "total_cost_usd": parsed.get("total_cost_usd") if isinstance(parsed, dict) else None,
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "cache_read_input_tokens": usage.get("cache_read_input_tokens"),
            "cache_creation_input_tokens": usage.get("cache_creation_input_tokens"),
            "exit_code": (proc.returncode if proc is not None else None),
            "timed_out": timed_out,
            "final_status": final_status,
            "status_source": status_source,
        }) + "\n")

    mark_cmd = [
        sys.executable, str(ROOT / "run_process.py"), "--run-id", run_id, "--process", lane, "--budget", budget,
        "--status", final_status, "--message", f"review_cli.py run: {status_source}",
    ]
    mark_result = subprocess.run(mark_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    print(json.dumps({
        "run_id": run_id, "lane": lane, "budget": budget, "final_status": final_status, "status_source": status_source,
        "status_json": str(self_status_path), "result_md": str(out_dir / "result.md"),
        "raw_response": str(raw_path), "transcript": str(transcript_path), "parse_ok": parse_ok,
        "run_process_output": json.loads(mark_result.stdout) if mark_result.stdout else None,
    }, indent=2))
    return 0 if final_status in ("OK", "SKIPPED") else 1


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="review_cli.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="verify prerequisites")
    p_check.set_defaults(func=cmd_check)

    p_model = sub.add_parser("model", help="resolve the effective model/effort for a lane+budget from model-config.json")
    p_model.add_argument("--lane", required=True)
    p_model.add_argument("--budget", required=True, choices=["probe", "standard", "full"])
    p_model.set_defaults(func=cmd_model)

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

    p_run = sub.add_parser("run", help="dispatch one lane to the real claude CLI (single-agent, unpooled -- see model-config.json invocation.open_questions for what's not yet wired)")
    p_run.add_argument("--run-id", required=True)
    p_run.add_argument("--lane", required=True)
    p_run.add_argument("--budget", choices=["probe", "standard", "full"], default="", help="defaults to the run's default_budget")
    p_run.add_argument("--timeout", type=int, default=1800, help="seconds before the claude subprocess is killed (default 1800)")
    p_run.add_argument("--model", default="", help="override the resolved model for this call only (e.g. claude-haiku-4-5 for a cheap dev/mechanics-validation pass) -- does not touch model-config.json's default")
    p_run.add_argument("--effort", default="", choices=["", "low", "medium", "high", "xhigh", "max"], help="override the resolved effort tier for this call only -- does not touch model-config.json's default")
    p_run.add_argument("--lock-wait-timeout", type=int, default=3600, help="max seconds to wait for another review_cli.py run against this run-id to release its directory lock before giving up (default 3600)")
    p_run.add_argument("--dry-run", action="store_true", help="build the handoff and the claude argv, print them, execute nothing")
    p_run.set_defaults(func=cmd_run)

    p_intake = sub.add_parser('intake', help='submit Phase 1 intake to Dagster and wait for its result')
    p_intake.add_argument('--run-id', required=True)
    p_intake.add_argument('--force', action='store_true')
    p_intake.add_argument('--launch-id', help='resume monitoring an existing Dagster launch')
    def intake_command(args):
        from launch_job import main as launch_main
        return launch_main(['--run-id', args.run_id, '--job', 'phase1_intake', '--wait'] + (['--force'] if args.force else [])
                           + (['--launch-id',args.launch_id] if args.launch_id else []))
    p_intake.set_defaults(func=intake_command)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
