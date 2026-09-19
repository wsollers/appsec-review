#!/usr/bin/env python3
"""Create a filled task handoff from templates and run state."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def process_names() -> list[str]:
    return sorted(p.name for p in ROOT.iterdir() if p.is_dir() and p.name[:2].isdigit() and "-" in p.name)


def resolve_process(name: str) -> str:
    names = process_names()
    if name in names:
        return name
    matches = [n for n in names if n.startswith(name) or n[3:] == name]
    if len(matches) == 1:
        return matches[0]
    raise SystemExit(f"unknown or ambiguous process {name!r}; valid: {', '.join(names)}")


def lane_depends_on(process: str) -> list[str]:
    """Read process-manifest.json's depends_on for this lane.

    Returns [] if the manifest has no depends_on section at all, or no entry
    for this lane -- either way, that means "no known upstream lane output
    dependency", not an error (older manifests, or a lane not yet mapped,
    should not crash handoff generation).
    """
    manifest = load_json(ROOT / "process-manifest.json")
    depends_on = manifest.get("depends_on")
    if not isinstance(depends_on, dict):
        return []
    deps = depends_on.get(process)
    if not isinstance(deps, list):
        return []
    return [d for d in deps if isinstance(d, str)]


def build_upstream_outputs_section(run_id: str, process: str) -> str:
    """Build the {{UPSTREAM_OUTPUTS}} handoff section for this lane.

    Per-lane cross-lane input wiring gap (found 2026-09-18): config.md's own
    "Required Inputs" sections for several lanes name another lane's real
    output as a required input (e.g. 08-blue-team-refutation needs
    07-red-team-adversarial's red-team claim), but nothing in the generated
    handoff ever pointed a lane at another lane's outputs/<lane>/ directory --
    the lane was left to discover and read it entirely on its own initiative,
    which a real dispatch (run 20260917T193147Z-2319a6, 08 at --budget
    standard) failed to do, self-reporting OK while never having read lane
    07's actual scenarios. This function is the fix: it names the exact real
    paths for every declared dependency, and flags (rather than crashes on)
    a dependency that hasn't run yet in this run.
    """
    deps = lane_depends_on(process)
    if not deps:
        return "No upstream lane outputs required for this process."

    run_status = load_json(ROOT / "runs" / run_id / "run-status.json")
    completed = run_status.get("completed_processes")
    completed_set = set(completed) if isinstance(completed, list) else set()

    lines = [
        "## Upstream Outputs",
        "",
        "This process depends on prior lanes' real outputs, per `process-manifest.json`'s",
        "`depends_on`. Read each one below before starting -- do not proceed as if an",
        "upstream lane's findings don't exist just because they weren't repeated in this",
        "handoff or the evidence package; those live under the engagement's evidence",
        "package, not under a prior lane's `outputs/` directory.",
        "",
    ]
    for dep in deps:
        status_path = f"appsec-review-process/runs/{run_id}/outputs/{dep}/status.json"
        result_path = f"appsec-review-process/runs/{run_id}/outputs/{dep}/result.md"
        if dep in completed_set:
            lines.append(f"- `{dep}` (completed in this run) -- read `{status_path}` and `{result_path}`")
        else:
            lines.append(
                f"- `{dep}` has NOT completed in this run yet (not in `completed_processes`). "
                f"If it later shows a completed output, read `{status_path}` and `{result_path}`; "
                "otherwise flag this dependency as missing in your own status.json rather than "
                "proceeding as if it doesn't exist or was never planned."
            )
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--process", required=True)
    ap.add_argument("--budget", choices=["probe", "standard", "full"], default="")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    process = resolve_process(args.process)
    from execution_state import run_path, data_path, atomic_bytes, beneath
    run_dir = run_path(args.run_id)
    from execution_state import read_json
    manifest = read_json(run_dir / "inputs" / "artifact-manifest.json")
    if manifest.get('orchestration_version') == 1:
        if process not in ('00-intake-recovery','02-evidence-pregather'):
            raise SystemExit('Downstream handoff dispatch is planned, not implemented; first consume the validated partition-discovery handoff.')
        from phase1 import handoff
        import uuid
        text = handoff(args.run_id)
        out = beneath(data_path(args.run_id), Path(args.out).absolute()) if args.out else data_path(args.run_id, 'handoffs', uuid.uuid4().hex + '.md')
        atomic_bytes(out, text.encode())
        print(json.dumps({'handoff': str(out), 'process': process, 'budget': args.budget or 'probe'}))
        return 0
    run_status = load_json(run_dir / "run-status.json")
    budget = args.budget or str(run_status.get("default_budget") or "probe")
    target = manifest.get("target", {}).get("repo_path", "")
    engagement = manifest.get("engagement_output", "")

    text = (ROOT / "templates" / "task-handoff.md").read_text(encoding="utf-8")
    replacements = {
        "{{RUN_ID}}": args.run_id,
        "{{PROCESS}}": process,
        "{{BUDGET}}": budget,
        "{{TARGET_PATH}}": target,
        "{{ENGAGEMENT_OUTPUT}}": engagement,
        "{{UPSTREAM_OUTPUTS}}": build_upstream_outputs_section(args.run_id, process),
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    out = Path(args.out) if args.out else run_dir / "handoffs" / f"{process}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(json.dumps({"handoff": str(out), "process": process, "budget": budget}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
