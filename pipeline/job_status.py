#!/usr/bin/env python3
"""Summarize an engagement job's step status and expected artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"step": "manifest-parse-error", "exit_code": 1, "raw": line})
    return rows


def file_state(path: Path) -> dict:
    return {
        "path": str(path),
        "exists": path.exists(),
        "bytes": path.stat().st_size if path.exists() and path.is_file() else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--native-scratch", required=True)
    ap.add_argument("--llm-dir", required=True)
    ap.add_argument("--static-enabled", action="store_true")
    ap.add_argument("--native-enabled", action="store_true")
    ap.add_argument("--codeql-enabled", action="store_true")
    args = ap.parse_args()

    manifest = Path(args.manifest)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    static = Path(args.static_evidence)
    native = Path(args.native_scratch)
    llm = Path(args.llm_dir)

    steps = load_jsonl(manifest)
    failed_steps = [s for s in steps if int(s.get("exit_code", 1) or 0) != 0]

    expected: list[tuple[str, Path, bool]] = [
        ("llm-input", llm / "ENGAGEMENT_LLM_INPUT.md", True),
        ("coverage-ledger", llm / "coverage-ledger.json", True),
        ("correlated-findings", llm / "correlated-findings.json", True),
        ("retrieval-plan", llm / "retrieval-plan.json", True),
    ]
    if args.static_enabled:
        expected += [
            ("static-summary", static / "SUMMARY.md", False),
            ("static-manifest", static / "MANIFEST.json", False),
        ]
    if args.native_enabled:
        expected += [
            ("compile-db", native / "compile_commands.json", True),
            ("native-sast", native / "native-sast" / "native-sast-manifest.json", False),
            ("feasibility", native / "feasibility.json", True),
            ("feasibility-ir", native / "feasibility-ir.json", True),
            ("native-bundle", llm / "native-bundle.json", True),
        ]
    if args.codeql_enabled:
        expected += [
            ("codeql-manifest", native / "codeql" / "run-manifest.json", False),
            ("codeql-regular-cpp", native / "codeql" / "cpp.sarif", False),
            ("codeql-mythos", native / "codeql" / "mythos.sarif", False),
        ]

    artifacts = [{"name": name, "required": req, **file_state(path)} for name, path, req in expected]
    missing_required = [a for a in artifacts if a["required"] and not a["exists"]]
    missing_optional = [a for a in artifacts if not a["required"] and not a["exists"]]

    status = "OK"
    if failed_steps or missing_required:
        status = "DEGRADED"
    if not steps:
        status = "FAILED"

    report = {
        "schema": "appsec-review/job-status/0.1",
        "status": status,
        "manifest": str(manifest),
        "step_count": len(steps),
        "failed_steps": failed_steps,
        "missing_required_artifacts": missing_required,
        "missing_optional_artifacts": missing_optional,
        "artifacts": artifacts,
    }
    json_path = out / "job-status.json"
    md_path = out / "job-status.md"
    json_path.write_text(json.dumps(report, indent=1), encoding="utf-8")

    lines = ["# Engagement Job Status", "", f"Status: **{status}**", "", "## Steps"]
    if not steps:
        lines.append("- no manifest steps recorded")
    for step in steps:
        mark = "OK" if int(step.get("exit_code", 1) or 0) == 0 else "FAIL"
        lines.append(f"- {mark} `{step.get('step', '?')}` exit={step.get('exit_code')} seconds={step.get('seconds')} log=`{step.get('log', '')}`")
    lines += ["", "## Missing Required Artifacts"]
    lines += [f"- `{a['name']}` expected `{a['path']}`" for a in missing_required] or ["- none"]
    lines += ["", "## Missing Optional Artifacts"]
    lines += [f"- `{a['name']}` expected `{a['path']}`" for a in missing_optional] or ["- none"]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"status={status}")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0 if status == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
