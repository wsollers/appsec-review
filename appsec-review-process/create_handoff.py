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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--process", required=True)
    ap.add_argument("--budget", choices=["probe", "standard", "full"], default="")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    process = resolve_process(args.process)
    run_dir = ROOT / "runs" / args.run_id
    manifest = load_json(run_dir / "inputs" / "artifact-manifest.json")
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

