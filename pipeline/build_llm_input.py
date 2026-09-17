#!/usr/bin/env python3
"""Build an engagement LLM input index from static evidence and native outputs."""
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
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


def count_gitleaks(path: Path) -> int | None:
    data = load_json(path)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("findings", "results", "leaks"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
    return None


def count_osv(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    total = 0
    for result in data.get("results", []) or []:
        if isinstance(result, dict):
            packages = result.get("packages", []) or []
            for package in packages:
                if isinstance(package, dict):
                    total += len(package.get("vulnerabilities", []) or [])
    return total


def count_trivy_config(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    total = 0
    for result in data.get("Results", []) or []:
        if isinstance(result, dict):
            total += len(result.get("Misconfigurations", []) or [])
            total += len(result.get("Vulnerabilities", []) or [])
            total += len(result.get("Secrets", []) or [])
    return total


def count_checkov(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("results"), dict):
        failed = data["results"].get("failed_checks", [])
        return len(failed) if isinstance(failed, list) else 0
    total = 0
    for report in data.values():
        if isinstance(report, dict) and isinstance(report.get("results"), dict):
            failed = report["results"].get("failed_checks", [])
            total += len(failed) if isinstance(failed, list) else 0
    return total


def count_cppcheck(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        return sum(1 for _ in ET.parse(path).getroot().iter("error"))
    except ET.ParseError:
        return None


def count_clang_tidy(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    findings = data.get("findings")
    return len(findings) if isinstance(findings, list) else None


def count_codechecker(path: Path) -> int | None:
    data = load_json(path)
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("reports", "results", "findings"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
        reports = data.get("report_hash")
        if isinstance(reports, dict):
            return len(reports)
    return None


def count_sbom_components(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    components = data.get("components")
    return len(components) if isinstance(components, list) else None


def count_scancode(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    files = data.get("files")
    if isinstance(files, list):
        return sum(len(f.get("licenses", []) or []) for f in files if isinstance(f, dict))
    return None


def count_dependency_lifecycle_flags(path: Path) -> int | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    summary = data.get("summary")
    if isinstance(summary, dict):
        return summary.get("components_flagged_by_eol_reference")
    return None


def manifest_steps(static_manifest) -> dict[str, dict]:
    if not isinstance(static_manifest, list):
        return {}
    return {str(row.get("step")): row for row in static_manifest if isinstance(row, dict) and row.get("step")}


def tool_row(name: str, path: Path, count: int | None, *, ran: bool | None = None, note: str = "") -> dict:
    exists = path.exists()
    ran_value = exists if ran is None else bool(ran)
    return {
        "tool": name,
        "findings": count,
        "ran": ran_value,
        "evidence": str(path),
        "evidence_exists": exists,
        "note": note,
    }


def build_tool_counts(evidence: Path, scratch: Path, static_manifest) -> list[dict]:
    steps = manifest_steps(static_manifest)

    def step_ran(step: str) -> bool:
        row = steps.get(step)
        return bool(row and row.get("treatedOk", row.get("outputOk", False)))

    semgrep_count, semgrep_scanned = count_semgrep(evidence)
    semgrep_files = sorted((evidence / "sast-multi").glob("semgrep*.json"))
    rows = [
        tool_row("gitleaks", evidence / "secrets" / "gitleaks.json", count_gitleaks(evidence / "secrets" / "gitleaks.json"), ran=step_ran("secrets")),
        tool_row("osv-scanner", evidence / "sca" / "osv-scanner.json", count_osv(evidence / "sca" / "osv-scanner.json"), ran=step_ran("sca")),
        tool_row("trivy config", evidence / "iac" / "trivy-config.json", count_trivy_config(evidence / "iac" / "trivy-config.json"), ran=step_ran("iac")),
        tool_row("checkov", evidence / "iac" / "results_json.json", count_checkov(evidence / "iac" / "results_json.json"), ran=step_ran("iac")),
        tool_row("tfsec", evidence / "iac" / "tfsec.json", None, ran=step_ran("iac"), note="raw JSON shape varies; inspect evidence file directly"),
        tool_row("semgrep aggregate", evidence / "sast-multi", semgrep_count, ran=bool(semgrep_files), note=f"{semgrep_scanned} scanned path(s) reported"),
        tool_row("cppcheck static", evidence / "sast-cpp" / "cppcheck.xml", count_cppcheck(evidence / "sast-cpp" / "cppcheck.xml"), ran=step_ran("sast-cpp")),
        tool_row("BinSkim", evidence / "binskim" / "binskim.sarif", count_sarif(evidence / "binskim" / "binskim.sarif"), ran=step_ran("binskim")),
        tool_row("mobsfscan Android", evidence / "sast-mobile" / "mobsfscan-android.sarif", count_sarif(evidence / "sast-mobile" / "mobsfscan-android.sarif"), ran=step_ran("sast-mobile-android")),
        tool_row("mobsfscan iOS", evidence / "sast-mobile" / "mobsfscan-ios.sarif", count_sarif(evidence / "sast-mobile" / "mobsfscan-ios.sarif"), ran=step_ran("sast-mobile-ios")),
        tool_row("kube-linter", evidence / "iac-k8s" / "kube-linter.json", None, ran=step_ran("iac-k8s"), note="coverage/status evidence, count parser not implemented"),
        tool_row("dockerfile lint", evidence / "iac-docker", None, ran=step_ran("dockerfile-lint"), note="coverage/status evidence, count parser not implemented"),
        tool_row("clang-tidy native", scratch / "native-sast" / "findings-clang-tidy.json", count_clang_tidy(scratch / "native-sast" / "findings-clang-tidy.json")),
        tool_row("cppcheck native", scratch / "native-sast" / "cppcheck.xml", count_cppcheck(scratch / "native-sast" / "cppcheck.xml")),
        tool_row("Clang Static Analyzer / CSA", scratch / "csa" / "codechecker.json", count_codechecker(scratch / "csa" / "codechecker.json")),
        tool_row("CodeQL C/C++ security extended", scratch / "codeql" / "cpp.sarif", count_sarif(scratch / "codeql" / "cpp.sarif")),
        tool_row("CodeQL custom Mythos memory", scratch / "codeql" / "mythos.sarif", count_sarif(scratch / "codeql" / "mythos.sarif")),
        tool_row("syft SBOM (dependency + license inventory)", evidence / "sbom" / "sbom.cdx.json", count_sbom_components(evidence / "sbom" / "sbom.cdx.json"), ran=step_ran("sbom"), note="component count; per-component licenses are in this file, consumed by 06-cve-reachability's L1-broadened scope"),
        tool_row("ScanCode Toolkit (license/copyright/origin)", evidence / "license" / "scancode.json", count_scancode(evidence / "license" / "scancode.json"), ran=step_ran("scancode"), note="license-detections-per-file count; deeper/more authoritative than the SBOM's own license field on conflict"),
        tool_row("dependency-lifecycle (EOL/abandonware, L1 broadening)", evidence / "sbom" / "dependency-lifecycle.json", count_dependency_lifecycle_flags(evidence / "sbom" / "dependency-lifecycle.json"), ran=step_ran("dependency-lifecycle"), note="components flagged by the curated eol-reference.json table; unflagged means unknown, not confirmed current"),
    ]
    return rows


def markdown_tool_counts(rows: list[dict]) -> list[str]:
    lines = [
        "## Findings by tool (raw counts)",
        "",
        "| Tool | Ran | Raw findings | Evidence | Note |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for row in rows:
        findings = "n/a" if row["findings"] is None else str(row["findings"])
        ran = "yes" if row["ran"] else "no"
        evidence = row["evidence"]
        note = row.get("note") or ("file exists" if row.get("evidence_exists") else "missing evidence file")
        lines.append(f"| {row['tool']} | {ran} | {findings} | `{evidence}` | {note} |")
    return lines + [""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--static-evidence", required=True)
    ap.add_argument("--native-scratch", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--correlated-findings", default="")
    ap.add_argument("--deep-confirmation", default="")
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
    deep_path = Path(args.deep_confirmation) if args.deep_confirmation else None
    deep = load_json(deep_path) if deep_path else {}
    retrieval_path = Path(args.retrieval_plan) if args.retrieval_plan else None
    static_manifest = load_json(evidence / "MANIFEST.json") or []
    semgrep_findings, semgrep_scanned = count_semgrep(evidence)
    tool_counts = build_tool_counts(evidence, scratch, static_manifest)

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
        "tool_counts": tool_counts,
        "native_bundle_counts": bundle.get("counts", {}),
        "correlated_findings": corr.get("counts", {}) if isinstance(corr, dict) else {},
        "deep_confirmation": deep.get("counts", {}) if isinstance(deep, dict) else {},
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
        f"- Deep confirmation JSON: `{deep_path}`" if deep_path else "- Deep confirmation JSON: not generated",
        f"- Deep confirmation markdown: `{deep_path.with_suffix('.md')}`" if deep_path else "- Deep confirmation markdown: not generated",
        f"- Retrieval plan JSON: `{retrieval_path}`" if retrieval_path else "- Retrieval plan JSON: not generated",
        f"- Retrieval plan markdown: `{retrieval_path.with_suffix('.md')}`" if retrieval_path else "- Retrieval plan markdown: not generated",
        f"- Native SAST manifest: `{scratch / 'native-sast' / 'native-sast-manifest.json'}`",
        "",
    ]
    lines += markdown_tool_counts(tool_counts)
    lines += [
        "## Review Order For LLM",
        "1. Read the coverage ledger and identify tool failures or coverage gaps.",
        "2. Read the native bundle and preserve VERIFIED_PRIMITIVE / REFUTED / UNRESOLVED distinctions.",
        "3. Read the static summary and raw SAST outputs for corroborating findings.",
        "4. Read correlated findings to identify duplicates and corroboration across tools.",
        "5. Read deep confirmation for source/native/CodeQL/IR support and candidate caller context.",
        "6. Use the retrieval plan for risky files, candidate callers, semantic queries, and source searches.",
        "7. Correlate by file, function, rule/CWE, and source/sink when available.",
        "8. Ask for missing evidence rather than inventing it.",
        "",
    ]
    if deep_path and deep_path.with_suffix(".md").exists():
        lines += ["## Deep Confirmation", "", deep_path.with_suffix(".md").read_text(encoding="utf-8", errors="replace")[:25000], ""]
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
