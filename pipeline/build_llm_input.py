#!/usr/bin/env python3
"""Build an engagement LLM input index from static evidence and native outputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def count_semgrep(evidence: Path) -> tuple[int, int]:
    total = 0
    scanned = set()
    for p in sorted((evidence / "sast-multi").glob("semgrep*.json")):
        data = load_json(p)
        if not isinstance(data, dict):
            continue
        total += len(data.get("results", []) or [])
        paths = data.get("paths", {}) if isinstance(data.get("paths"), dict) else {}
        for s in paths.get("scanned", []) or []:
            scanned.add(s)
    return total, len(scanned)


def count_sarif(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    return sum(len(run.get("results", []) or []) for run in data.get("runs", []) or [])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--native-scratch", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--correlated-findings", default="")
    ap.add_argument("--retrieval-plan", default="")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    evidence = Path(args.static_evidence)
    scratch = Path(args.native_scratch)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    compdb = load_json(scratch / "compile_commands.json") or []
    compile_files = sorted({e.get("file") for e in compdb if isinstance(e, dict) and e.get("file")})
    feas = load_json(scratch / "feasibility.json") or {}
    emit_feas = load_json(scratch / "feasibility-ir.json") or {}
    pregather = load_json(scratch / "pregather-manifest.json") or {}
    native_sast = load_json(scratch / "native-sast" / "native-sast-manifest.json") or {}
    bundle = load_json(Path(args.bundle)) or {}
    corr_path = Path(args.correlated_findings) if args.correlated_findings else None
    corr = load_json(corr_path) if corr_path else {}
    retrieval_path = Path(args.retrieval_plan) if args.retrieval_plan else None
    static_manifest = load_json(evidence / "MANIFEST.json") or []
    semgrep_findings, semgrep_scanned = count_semgrep(evidence)

    coverage = {
        "project": args.project,
        "target": args.target,
        "static_evidence": str(evidence),
        "native_scratch": str(scratch),
        "compile_database": {
            "translation_units": len(compdb) if isinstance(compdb, list) else 0,
            "unique_files": len(compile_files),
        },
        "feasibility": {
            "syntax": {k: feas.get(k) for k in ("tier_recommendation", "pass_rate", "tu_total", "tu_pass", "tu_fail", "tu_timeout")},
            "emit_ir": {k: emit_feas.get(k) for k in ("tier_recommendation", "pass_rate", "tu_total", "tu_pass", "tu_fail", "tu_timeout")},
        },
        "static_tools": {
            "manifest_steps": len(static_manifest) if isinstance(static_manifest, list) else None,
            "semgrep_findings": semgrep_findings,
            "semgrep_paths_scanned": semgrep_scanned,
            "binskim_results": count_sarif(evidence / "binskim" / "binskim.sarif"),
        },
        "codeql": {
            "regular_cpp_security_extended_results": count_sarif(scratch / "codeql" / "cpp.sarif"),
            "custom_mythos_memory_results": count_sarif(scratch / "codeql" / "mythos.sarif"),
            "database": str(scratch / "codeql" / "db-cpp"),
        },
        "native_sast": native_sast,
        "native_bundle_counts": bundle.get("counts", {}),
        "correlated_findings": corr.get("counts", {}) if isinstance(corr, dict) else {},
        "pregather": pregather,
    }
    coverage_path = out_dir / "coverage-ledger.json"
    coverage_path.write_text(json.dumps(coverage, indent=1))

    static_summary = evidence / "SUMMARY.md"
    native_bundle_md = Path(args.bundle).with_suffix(".md")
    llm_md = out_dir / "ENGAGEMENT_LLM_INPUT.md"
    lines = [
        f"# Engagement LLM Input - {args.project}",
        "",
        "## Rule",
        "Use this as an evidence index. Do not infer that an unscanned file is clean. Do not promote a finding without a cited tool result, IR fact, verifier result, or explicit human observation.",
        "",
        "## Coverage Ledger",
        f"- JSON: `{coverage_path}`",
        f"- Compile DB unique files: {coverage['compile_database']['unique_files']}",
        f"- Syntax feasibility: {coverage['feasibility']['syntax']}",
        f"- IR feasibility: {coverage['feasibility']['emit_ir']}",
        f"- Semgrep findings / scanned paths: {semgrep_findings} / {semgrep_scanned}",
        f"- CodeQL regular/custom findings: {coverage['codeql']['regular_cpp_security_extended_results']} / {coverage['codeql']['custom_mythos_memory_results']}",
        f"- Native bundle counts: {coverage['native_bundle_counts']}",
        "",
        "## Primary Evidence Files",
        f"- Static evidence root: `{evidence}`",
        f"- Static summary: `{static_summary}`",
        f"- Native scratch root: `{scratch}`",
        f"- Native bundle JSON: `{args.bundle}`",
        f"- Native bundle markdown: `{native_bundle_md}`",
        f"- CodeQL regular C/C++ SARIF: `{scratch / 'codeql' / 'cpp.sarif'}`",
        f"- CodeQL custom memory SARIF: `{scratch / 'codeql' / 'mythos.sarif'}`",
        f"- CodeQL C/C++ database: `{scratch / 'codeql' / 'db-cpp'}`",
        f"- Correlated findings JSON: `{corr_path}`" if corr_path else "- Correlated findings JSON: not generated",
        f"- Correlated findings markdown: `{corr_path.with_suffix('.md')}`" if corr_path else "- Correlated findings markdown: not generated",
        f"- Retrieval plan JSON: `{retrieval_path}`" if retrieval_path else "- Retrieval plan JSON: not generated",
        f"- Retrieval plan markdown: `{retrieval_path.with_suffix('.md')}`" if retrieval_path else "- Retrieval plan markdown: not generated",
        f"- Native SAST manifest: `{scratch / 'native-sast' / 'native-sast-manifest.json'}`",
        "",
        "## Review Order For LLM",
        "1. Read the coverage ledger and identify tool failures or coverage gaps.",
        "2. Read the native bundle and preserve VERIFIED_PRIMITIVE / REFUTED / UNRESOLVED distinctions.",
        "3. Read the static summary and raw SAST outputs for corroborating findings.",
        "4. Read correlated findings to identify duplicates and corroboration across tools.",
        "5. Use the retrieval plan for risky files, candidate callers, semantic queries, and source searches.",
        "6. Correlate by file, function, rule/CWE, and source/sink when available.",
        "7. Ask for missing evidence rather than inventing it.",
        "",
    ]
    if corr_path and corr_path.with_suffix(".md").exists():
        lines += ["## Correlated Findings", "", corr_path.with_suffix(".md").read_text(encoding="utf-8", errors="replace")[:30000], ""]
    if retrieval_path and retrieval_path.with_suffix(".md").exists():
        lines += ["## Retrieval Plan", "", retrieval_path.with_suffix(".md").read_text(encoding="utf-8", errors="replace")[:20000], ""]
    if static_summary.exists():
        lines += ["## Static Evidence Summary", "", static_summary.read_text(encoding="utf-8", errors="replace")[:20000], ""]
    if native_bundle_md.exists():
        lines += ["## Native Bundle Summary", "", native_bundle_md.read_text(encoding="utf-8", errors="replace")[:20000], ""]
    llm_md.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {coverage_path} and {llm_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
