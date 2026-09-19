#!/usr/bin/env python3
"""
summarize_evidence.py — deterministic markdown rollup of one
Invoke-VendorAuditPrePass.ps1 run: what ran, what didn't, and what looks
critical enough to look at first.

This is NOT a replacement for the playbook's Phase 1-8 LLM-driven findings
pipeline (Discovery -> ASVS assessment -> CVE reachability -> consolidation
-> executive summary). It reads the same evidence tree those phases would
eventually consume and produces a much cheaper, purely mechanical first
pass: tool-by-tool counts, MANIFEST status, and a best-effort "needs a human
look" list built from severity fields the tools already emit. Treat its
"Critical / High priority" section as a triage starting point, not a
verified findings list — every count here is un-deduplicated, untriaged
raw tool output (e.g. it will include the gitleaks/Terraform false
positives the playbook's own inspect-secrets.ps1 -Summary exists to sort
out).

Pure standard library, no pip installs — same "run anywhere, no Docker
required" philosophy as profile_repo.py. Run it directly on the Windows
host against an EvidencePath produced by Invoke-VendorAuditPrePass.ps1;
it does not need to run inside the toolbox container.

Usage:
    python3 summarize_evidence.py C:\\Barracuda\\evidence-infra -o C:\\Barracuda\\evidence-infra\\SUMMARY.md

Design notes:
  - Every parser is wrapped so a tool's evidence file that doesn't match the
    shape this script expects (a CLI flag changed, a tool version bumped its
    output schema) is reported as "could not parse — check the file by hand"
    rather than crashing the whole summary. Same "one bad file shouldn't
    kill the run" discipline as build_symbol_index.py.
  - Nothing here reads or prints secret VALUES. gitleaks evidence is
    consumed with --redact already applied upstream; this script only ever
    counts/labels, the same discipline inspect-secrets.ps1 follows.
  - MANIFEST.json's treatedOk is NOT trusted at face value for the steps the
    playbook already documents as silent-failure-prone (anything ending in
    `|| true` at the shell level) - this script flags those explicitly so a
    near-empty evidence file with treatedOk=true doesn't read as "clean."
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

# Steps whose Cmd ends in `|| true` at the shell level (per
# Invoke-VendorAuditPrePass.ps1's own .DESCRIPTION) - a genuine tool crash
# and "ran clean, found nothing" both land as treatedOk=true for these.
# Flagged separately regardless of exit code so a near-empty result doesn't
# get read as a clean scan without a human checking the .stderr.log.
SILENT_FAILURE_PRONE_STEPS = {
    "sast-php", "iac", "binskim", "iac-k8s", "dockerfile-lint",
    "docker-base-images", "joern-parse", "secrets-binary", "ast-grep-scan",
    "sast-mobile-android", "sast-mobile-ios", "sca", "sast-python",
    "sast-go", "sast-cpp", "sast-multi-semgrep", "sast-php-parse-coverage",
    "evidence-scrub",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "LOW", "NOTE", "INFO", "UNKNOWN"]


def sev_rank(s: str) -> int:
    s = (s or "UNKNOWN").upper()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else len(SEVERITY_ORDER)


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None


class ToolFinding:
    """One row in the per-tool findings table."""
    def __init__(self, tool: str, evidence_file: str, total: int,
                 by_severity: dict[str, int] | None = None, note: str = ""):
        self.tool = tool
        self.evidence_file = evidence_file
        self.total = total
        self.by_severity = by_severity or {}
        self.note = note


# ---------------------------------------------------------------------------
# Per-tool parsers. Each takes the evidence root Path and returns a
# ToolFinding, or None if the expected file simply doesn't exist (step
# wasn't run / produced nothing), or a ToolFinding with note="could not
# parse" if the file exists but doesn't match the expected shape.
# ---------------------------------------------------------------------------

def parse_gitleaks(root: Path) -> ToolFinding | None:
    p = root / "secrets" / "gitleaks.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None or not isinstance(data, list):
        return ToolFinding("gitleaks (secrets)", str(p), 0, note="could not parse — check the file by hand")
    by_rule: dict[str, int] = {}
    fingerprints = set()
    for hit in data:
        rule = hit.get("RuleID", "unknown-rule") if isinstance(hit, dict) else "unknown-rule"
        by_rule[rule] = by_rule.get(rule, 0) + 1
        fp = hit.get("Fingerprint") if isinstance(hit, dict) else None
        if fp:
            fingerprints.add(fp)
    note = (f"{len(fingerprints)} unique fingerprint(s) of {len(data)} total hit(s). "
            f"UNTRIAGED — run inspect-secrets.ps1 -Summary before treating any of these as real secrets; "
            f"this toolbox's own fsh-infra run found ~75% of a similar gitleaks batch to be false positives "
            f"(path/resource-ID strings matched by the generic-api-key rule).")
    return ToolFinding("gitleaks (secrets)", str(p), len(data), by_rule, note)


def parse_secrets_binary(root: Path) -> ToolFinding | None:
    p = root / "secrets" / "binary-cert-inventory.txt"
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    sections = re.split(r"=== .* ===", text)
    # sections[0] is preamble (empty); sections[1] = cert files, sections[2] = PEM grep hits
    cert_lines = [l for l in (sections[1].splitlines() if len(sections) > 1 else []) if l.strip()]
    pem_lines = [l for l in (sections[2].splitlines() if len(sections) > 2 else []) if l.strip()]
    total = len(cert_lines) + len(pem_lines)
    note = "Inventory only, not a scanner — each hit needs a manual validity/rotation check." if total else ""
    return ToolFinding("binary cert/key inventory", str(p), total,
                        {"cert-store-files": len(cert_lines), "PEM-private-key-files": len(pem_lines)}, note)


def parse_sarif(path: Path) -> tuple[int, dict[str, int]] | None:
    data = load_json(path)
    if data is None or "runs" not in data:
        return None
    by_level: dict[str, int] = {}
    total = 0
    for run in data.get("runs", []):
        for result in run.get("results", []):
            level = str(result.get("level", "none")).upper()
            by_level[level] = by_level.get(level, 0) + 1
            total += 1
    return total, by_level


def parse_sarif_tool(root: Path, name: str, relpath: str) -> ToolFinding | None:
    p = root / relpath
    if not p.exists():
        return None
    parsed = parse_sarif(p)
    if parsed is None:
        return ToolFinding(name, str(p), 0, note="could not parse as SARIF — check the file by hand, "
                                                    "or check the matching .stderr.log for a crash")
    total, by_level = parsed
    return ToolFinding(name, str(p), total, by_level)


def parse_semgrep(root: Path) -> ToolFinding | None:
    p = root / "sast-multi" / "semgrep.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None or "results" not in data:
        return ToolFinding("semgrep (multi-language SAST)", str(p), 0, note="could not parse — check the file by hand")
    by_sev: dict[str, int] = {}
    for r in data.get("results", []):
        sev = str(r.get("extra", {}).get("severity", "UNKNOWN")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    note = "Primary PHP SAST pass per the toolbox's own S6-1 finding — cross-check PHP findings here before trusting psalm/phpstan's 0-finding files."
    return ToolFinding("semgrep (multi-language SAST)", str(p), len(data.get("results", [])), by_sev, note)


def parse_bandit(root: Path) -> ToolFinding | None:
    p = root / "sast-python" / "bandit.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None or "results" not in data:
        return ToolFinding("bandit (Python SAST)", str(p), 0, note="could not parse — check the file by hand")
    by_sev: dict[str, int] = {}
    for r in data.get("results", []):
        sev = str(r.get("issue_severity", "UNKNOWN")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return ToolFinding("bandit (Python SAST)", str(p), len(data.get("results", [])), by_sev)


def parse_gosec(root: Path) -> ToolFinding | None:
    p = root / "sast-go" / "gosec.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None or "Issues" not in data:
        return ToolFinding("gosec (Go SAST)", str(p), 0, note="could not parse — check the file by hand")
    by_sev: dict[str, int] = {}
    for r in data.get("Issues", []) or []:
        sev = str(r.get("severity", "UNKNOWN")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return ToolFinding("gosec (Go SAST)", str(p), len(data.get("Issues", []) or []), by_sev)


def parse_cppcheck(root: Path) -> ToolFinding | None:
    p = root / "sast-cpp" / "cppcheck.xml"
    if not p.exists():
        return None
    try:
        tree = ET.parse(p)
    except ET.ParseError:
        return ToolFinding("cppcheck (C/C++ SAST)", str(p), 0, note="could not parse — check the file by hand")
    by_sev: dict[str, int] = {}
    total = 0
    for err in tree.getroot().iter("error"):
        sev = str(err.get("severity", "unknown")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        total += 1
    return ToolFinding("cppcheck (C/C++ SAST)", str(p), total, by_sev)


def parse_osv(root: Path) -> ToolFinding | None:
    p = root / "sca" / "osv-scanner.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return ToolFinding("osv-scanner (dependency CVEs)", str(p), 0, note="could not parse — check the file by hand")
    total = 0
    by_sev: dict[str, int] = {}
    for result in data.get("results", []) or []:
        for pkg in result.get("packages", []) or []:
            for vuln in pkg.get("vulnerabilities", []) or []:
                total += 1
                sevs = vuln.get("severity") or []
                sev = (sevs[0].get("type") if sevs else None) or "UNSPECIFIED"
                by_sev[str(sev).upper()] = by_sev.get(str(sev).upper(), 0) + 1
    note = "Raw CVE hit count, NOT reachability-triaged — the playbook's Phase 5 reachability tier (Confirmed-Reachable / Present-Unreachable / Present-Unused) still needs to run before these are reportable findings."
    return ToolFinding("osv-scanner (dependency CVEs)", str(p), total, by_sev, note)


def parse_php_parse_coverage(root: Path) -> ToolFinding | None:
    p = root / "sast-php" / "parse-coverage.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return ToolFinding("PHP parse coverage", str(p), 0, note="could not parse — check the file by hand")
    not_analyzed = data.get("not_analyzed", 0)
    total_files = data.get("total_php_files", 0)
    note = (f"{not_analyzed} of {total_files} PHP file(s) failed php -l entirely — zero SAST coverage from any "
            f"tool but semgrep on those files. Not a vulnerability by itself; a coverage gap worth closing.") if not_analyzed else ""
    return ToolFinding("PHP parse coverage (S6-1 ledger)", str(p), not_analyzed, {"NOT_ANALYZED": not_analyzed}, note)


def parse_checkov(root: Path) -> ToolFinding | None:
    # checkov -o json --output-file-path <dir>/ writes results_json.json under that dir
    candidates = list((root / "iac").glob("*checkov*.json")) + list((root / "iac").glob("results_json.json"))
    p = candidates[0] if candidates else None
    if not p or not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return ToolFinding("checkov (IaC)", str(p), 0, note="could not parse — check the file by hand")
    results = data.get("results", data) if isinstance(data, dict) else {}
    failed = results.get("failed_checks", []) if isinstance(results, dict) else []
    by_sev: dict[str, int] = {}
    for c in failed or []:
        sev = str((c or {}).get("severity") or "UNSPECIFIED").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return ToolFinding("checkov (IaC)", str(p), len(failed or []), by_sev)


def parse_tfsec(root: Path) -> ToolFinding | None:
    p = root / "iac" / "tfsec.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return ToolFinding("tfsec (IaC, deprecated upstream)", str(p), 0, note="could not parse — check the file by hand")
    results = data.get("results") or []
    by_sev: dict[str, int] = {}
    for r in results:
        sev = str(r.get("severity", "UNKNOWN")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    return ToolFinding("tfsec (IaC, deprecated upstream — see trivy config instead)", str(p), len(results), by_sev)


def parse_trivy_config(root: Path) -> ToolFinding | None:
    p = root / "iac" / "trivy-config.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return ToolFinding("trivy config (IaC)", str(p), 0, note="could not parse — check the file by hand")
    by_sev: dict[str, int] = {}
    total = 0
    for result in data.get("Results", []) or []:
        for m in result.get("Misconfigurations", []) or []:
            sev = str(m.get("Severity", "UNKNOWN")).upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            total += 1
    return ToolFinding("trivy config (IaC)", str(p), total, by_sev)


def parse_kube_linter(root: Path) -> ToolFinding | None:
    p = root / "iac-k8s" / "kube-linter.json"
    if not p.exists():
        return None
    data = load_json(p)
    if data is None:
        return None  # kube-linter writes nothing meaningful (often empty file) when there's no K8s content
    reports = data.get("Reports") if isinstance(data, dict) else None
    if reports is None:
        return None
    return ToolFinding("kube-linter (K8s/Helm)", str(p), len(reports))


def parse_hadolint(root: Path) -> ToolFinding | None:
    p = root / "iac-docker" / "hadolint.txt"
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    by_level: dict[str, int] = {}
    for m in re.finditer(r"\b(error|warning|info|style)\b:", text):
        lvl = m.group(1).upper()
        by_level[lvl] = by_level.get(lvl, 0) + 1
    total = sum(by_level.values())
    return ToolFinding("hadolint (Dockerfile lint)", str(p), total, by_level) if total or p.stat().st_size > 0 else None


def parse_base_images(root: Path) -> ToolFinding | None:
    p = root / "iac-docker" / "base-images.txt"
    if not p.exists():
        return None
    lines = [l for l in p.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip()]
    floating = [l for l in lines if re.search(r":latest\b", l) or not re.search(r"FROM\s+\S+:\S+", l, re.IGNORECASE)]
    note = f"{len(floating)} floating/untagged base image reference(s) — see the file for exact lines." if floating else ""
    return ToolFinding("Dockerfile base-image inventory", str(p), len(lines), {"floating-or-untagged": len(floating)}, note)


def parse_mobile_coverage(root: Path, platform: str) -> ToolFinding | None:
    p = root / "sast-mobile" / f"{platform}-coverage.txt"
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8", errors="replace")
    zero_scanned = "WARNING" in text
    note = "Zero matching source files — treat the matching SARIF as NOT-SCANNED, not clean." if zero_scanned else ""
    return ToolFinding(f"mobsfscan coverage ({platform})", str(p), 1 if zero_scanned else 0, note=note)


PARSERS = [
    parse_gitleaks,
    parse_secrets_binary,
    lambda r: parse_sarif_tool(r, "mobsfscan (Android)", "sast-mobile/mobsfscan-android.sarif"),
    lambda r: parse_sarif_tool(r, "mobsfscan (iOS)", "sast-mobile/mobsfscan-ios.sarif"),
    lambda r: parse_mobile_coverage(r, "android"),
    lambda r: parse_mobile_coverage(r, "ios"),
    parse_semgrep,
    parse_bandit,
    parse_gosec,
    parse_cppcheck,
    parse_osv,
    parse_php_parse_coverage,
    parse_checkov,
    parse_tfsec,
    parse_trivy_config,
    parse_kube_linter,
    parse_hadolint,
    parse_base_images,
    lambda r: parse_sarif_tool(r, "BinSkim (binary hardening)", "binskim/binskim.sarif"),
]


def load_manifest(root: Path) -> list[dict[str, Any]]:
    p = root / "MANIFEST.json"
    if not p.exists():
        return []
    data = load_json(p)
    return data if isinstance(data, list) else []


def render_manifest_table(manifest: list[dict[str, Any]]) -> str:
    if not manifest:
        return "_No MANIFEST.json found in this evidence directory — was Invoke-VendorAuditPrePass.ps1 actually run against it?_\n"
    lines = ["| Step | Status | Duration (s) | Exit code | Notes |", "|---|---|---|---|---|"]
    for entry in manifest:
        step = entry.get("step", "?")
        ok = entry.get("treatedOk")
        status = "OK" if ok else "**NEEDS REVIEW**"
        dur = entry.get("durationSec", "-")
        exit_code = entry.get("exitCode", "-")
        note = ""
        if step in SILENT_FAILURE_PRONE_STEPS:
            note = "silent-failure-prone step — a clean result and a crash can look identical here; check its `.stderr.log` before trusting it"
        lines.append(f"| {step} | {status} | {dur} | {exit_code} | {note} |")
    failed = [e for e in manifest if not e.get("treatedOk")]
    summary = f"\n**{len(manifest)} step(s) ran, {len(failed)} flagged `treatedOk: false`.**\n" if manifest else ""
    return "\n".join(lines) + "\n" + summary


def render_findings_table(findings: list[ToolFinding]) -> str:
    if not findings:
        return "_No parseable tool evidence found under this path._\n"
    lines = ["| Tool | Total | By severity/level | Note |", "|---|---|---|---|"]
    for f in findings:
        sev_str = ", ".join(f"{k}: {v}" for k, v in sorted(f.by_severity.items(), key=lambda kv: sev_rank(kv[0]))) or "-"
        note = f.note or "-"
        lines.append(f"| {f.tool} | {f.total} | {sev_str} | {note} |")
    return "\n".join(lines) + "\n"


def build_critical_section(findings: list[ToolFinding], manifest: list[dict[str, Any]]) -> str:
    lines = []

    failed_steps = [e.get("step") for e in manifest if not e.get("treatedOk")]
    if failed_steps:
        lines.append(f"- **{len(failed_steps)} step(s) did not complete cleanly**: {', '.join(failed_steps)}. "
                      f"Check each one's `.stderr.log` before trusting its evidence at all — see the run table above.")

    for f in findings:
        high_sev_keys = [k for k in f.by_severity if k in ("CRITICAL", "HIGH", "ERROR")]
        high_sev_count = sum(f.by_severity.get(k, 0) for k in high_sev_keys)
        if f.tool.startswith("gitleaks") and f.total:
            lines.append(f"- **{f.total} secret-scanner hit(s)** in `{f.evidence_file}` — UNTRIAGED, likely includes "
                          f"false positives. Run `inspect-secrets.ps1 -Summary` before acting on any of these.")
        elif f.tool.startswith("binary cert"):
            if f.total:
                lines.append(f"- **{f.total} binary credential store / private-key file(s)** found — see `{f.evidence_file}`. "
                              f"Each needs a manual validity/rotation check.")
        elif f.tool.startswith("PHP parse coverage"):
            if f.total:
                lines.append(f"- **{f.total} PHP file(s) have zero SAST coverage** (failed to parse) — see `{f.evidence_file}`.")
        elif f.tool.startswith("Dockerfile base-image"):
            floating = f.by_severity.get("floating-or-untagged", 0)
            if floating:
                lines.append(f"- **{floating} floating/untagged Docker base image reference(s)** — see `{f.evidence_file}`.")
        elif f.tool.startswith("mobsfscan coverage") and f.total:
            lines.append(f"- **{f.tool}**: {f.note} — see `{f.evidence_file}`.")
        elif high_sev_count:
            lines.append(f"- **{f.tool}: {high_sev_count} CRITICAL/HIGH/ERROR-level finding(s)** "
                          f"(of {f.total} total) — see `{f.evidence_file}`.")

    if not lines:
        return ("No CRITICAL/HIGH-severity signal surfaced by this mechanical pass. This does NOT mean the "
                "target is clean — it means nothing here crossed the raw severity thresholds the tools "
                "themselves report. Business-logic issues (auth bypass, client-authoritative trust decisions, "
                "etc.) never show up in this kind of tool output at all; they need the playbook's Phase 1-4 "
                "LLM-driven review to surface.\n")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence_path", type=Path, help="EvidencePath produced by Invoke-VendorAuditPrePass.ps1")
    ap.add_argument("-o", "--output", type=Path, default=None,
                     help="Output markdown path (default: <evidence_path>/SUMMARY.md)")
    ap.add_argument("--repo-label", default=None, help="Label for the scanned repo/target, for the report header (e.g. fsh-infra)")
    args = ap.parse_args()

    root = args.evidence_path.resolve()
    if not root.exists():
        sys.exit(f"Evidence path does not exist: {root}")

    out_path = args.output or (root / "SUMMARY.md")
    label = args.repo_label or root.name

    manifest = load_manifest(root)

    findings: list[ToolFinding] = []
    for parser in PARSERS:
        try:
            result = parser(root)
        except Exception as e:  # a parser bug should never take down the whole summary
            result = None
            print(f"WARNING: a parser raised {e!r} — skipping that tool's row", file=sys.stderr)
        if result is not None:
            findings.append(result)

    from datetime import datetime, timezone
    generated = datetime.now(timezone.utc).isoformat()

    parts = [
        f"# Vendor Audit Pre-Pass Summary — {label}\n",
        f"Generated {generated} by `summarize_evidence.py` from evidence at `{root}`.\n",
        "This is a mechanical rollup of raw tool output, not a triaged findings report. "
        "Every count below is un-deduplicated and unverified — see the playbook's Phase 1-8 "
        "for the actual review/triage/consolidation process this feeds into.\n",
        "## What ran\n",
        render_manifest_table(manifest),
        "## Critical / needs immediate attention\n",
        build_critical_section(findings, manifest),
        "## Findings by tool (raw counts)\n",
        render_findings_table(findings),
        "## Next steps\n",
        "- Triage secrets: `inspect-secrets.ps1 -Summary`\n"
        "- Anything flagged `NEEDS REVIEW` above: open the matching `<step>.stderr.log` under the evidence tree.\n"
        "- Only `_shareable/` under the evidence tree (produced by the `evidence-scrub` step) is safe to hand off "
        "outside this machine — this summary itself may reference file paths containing evidence that hasn't "
        "been scrubbed; don't forward this file externally without checking it first.\n"
        "- This summary does not replace Phase 1+ (LLM-driven discovery/ASVS assessment/CVE-reachability triage) "
        "— it's a fast first read of what the tools found, not a security review.\n",
    ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts), encoding="utf-8")
    print(f"Wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
