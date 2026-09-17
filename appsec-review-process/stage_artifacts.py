#!/usr/bin/env python3
"""Stage an artifact manifest for a process run from an engagement output dir."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def existing(path: Path) -> str:
    return str(path) if path.exists() else ""


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--engagement-output", required=True)
    ap.add_argument("--compile-db", default="")
    ap.add_argument("--business-goal", default="")
    ap.add_argument("--platform", action="append", default=[])
    args = ap.parse_args()

    out = Path(args.engagement_output).resolve()
    target = Path(args.target).resolve()
    run_dir = ROOT / "runs" / args.run_id
    manifest_path = run_dir / "inputs" / "artifact-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    data = load_json(ROOT / "templates" / "artifact-manifest.template.json")
    data.update({
        "run_id": args.run_id,
        "project": args.project,
        "engagement_output": str(out),
    })
    data["target"] = {
        "repo_path": str(target),
        "compile_database": str(Path(args.compile_db).resolve()) if args.compile_db else "",
        "platforms": args.platform,
        "business_goal": args.business_goal,
    }
    data["core_artifacts"] = {
        "job_status_md": existing(out / "job-status.md"),
        "job_status_json": existing(out / "job-status.json"),
        "job_manifest_jsonl": existing(out / "job-manifest.jsonl"),
        "llm_input_md": existing(out / "llm" / "ENGAGEMENT_LLM_INPUT.md"),
        "coverage_ledger_json": existing(out / "llm" / "coverage-ledger.json"),
        "correlated_findings_json": existing(out / "llm" / "correlated-findings.json"),
        "deep_confirmation_json": existing(out / "llm" / "deep-confirmation.json"),
        "retrieval_plan_json": existing(out / "llm" / "retrieval-plan.json"),
    }
    derived = data.get("derived_artifacts", {})
    component_output = run_dir / "outputs" / "01-component-characterization"
    derived["component_purpose_map_json"] = existing(component_output / "component-purpose-map.json")
    derived["component_purpose_map_md"] = existing(component_output / "component-purpose-map.md")
    component_ir_dir = out / "llm" / "component-ir"
    derived["component_ir_dir"] = existing(component_ir_dir)
    derived["component_ir_summary_json"] = existing(component_ir_dir / "summary.json")
    data["derived_artifacts"] = derived

    missing = [k for k, v in data["core_artifacts"].items() if not v]
    data["notes"] = [f"missing core artifact: {k}" for k in missing]
    manifest_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "missing_core_artifacts": missing}, indent=2))
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
