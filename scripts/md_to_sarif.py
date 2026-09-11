#!/usr/bin/env python3
"""
md_to_sarif.py — Convert the canonical YAML-frontmatter markdown finding
format (see the Vendor Code Audit Playbook, Phase 6/7) into SARIF 2.1.0.

Finding format expected in the input markdown file: one or more blocks of

    ---
    id: VEND-GAMESRV-014
    title: Client-authoritative currency balance accepted without server validation
    severity: Critical|High|Medium|Low|Info
    status: Open|Fixed|Accepted-Risk|False-Positive|Needs-Verification
    component: GAMESRV-ECON-02
    location: gameserver/econ/wallet.cpp:118
    category: Payment-IAP
    cwe: CWE-807
    asvs: N/A - see supplement: game-trust-integrity
    data_classes: [payment_token]
    regulatory: [GDPR]
    cve: []
    confidence: Confirmed|Likely|Needs-Verification
    discovered_by: llm-assisted
    ---
    ### Description
    ...
    ### Evidence
    ...
    ### Impact
    ...
    ### Likelihood
    ...
    ### Remediation
    ...
    ### References
    ...

separated by blank lines / additional `---` blocks. Multiple such blocks may
appear in the same file, back to back.

Usage:
    python3 md_to_sarif.py findings.md -o findings.sarif
    python3 md_to_sarif.py findings.md --split-by location -o out_dir/
        (writes one SARIF file per distinct `location`'s top-level component
        prefix — e.g. one file for Client, one for Game-Server, etc. — using
        the first path segment as the split key. Omit --split-by for a
        single combined SARIF file.)

Dependencies: none beyond the standard library and PyYAML.
    pip install pyyaml --break-system-packages
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.exit("This script requires PyYAML: pip install pyyaml --break-system-packages")

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Only treat a '---' delimited block as a finding's frontmatter if the very
# next line starts with 'id:' — this distinguishes the frontmatter open/close
# markers from any other horizontal-rule '---' that might appear in prose.
FRONTMATTER_OPEN_RE = re.compile(r"^---[ \t]*\n(?=id\s*:)", re.MULTILINE)
FRONTMATTER_CLOSE_RE = re.compile(r"\n---[ \t]*\n")

LOCATION_RE = re.compile(r"^(?P<path>[^\s:]+):(?P<line>\d+)(?:-(?P<end_line>\d+))?$")


def parse_findings(md_text: str) -> list[dict[str, Any]]:
    """Find every frontmatter block that opens a finding (a '---' line
    immediately followed by 'id:'), pair it with its closing '---' line, and
    treat everything up to the next such opening (or EOF) as that finding's
    body."""
    text = md_text
    opens = list(FRONTMATTER_OPEN_RE.finditer(text))
    findings = []
    for i, open_match in enumerate(opens):
        fm_start = open_match.end()
        close_match = FRONTMATTER_CLOSE_RE.search(text, fm_start)
        if not close_match:
            print("WARNING: frontmatter block with no closing '---' — skipping", file=sys.stderr)
            continue
        frontmatter_raw = text[fm_start:close_match.start()]
        body_start = close_match.end()
        body_end = opens[i + 1].start() if i + 1 < len(opens) else len(text)
        body = text[body_start:body_end]

        try:
            meta = yaml.safe_load(frontmatter_raw) or {}
        except yaml.YAMLError as e:
            print(f"WARNING: skipping a block — invalid YAML frontmatter: {e}", file=sys.stderr)
            continue
        if not isinstance(meta, dict) or "id" not in meta:
            continue
        meta["_body"] = body.strip()
        findings.append(meta)
    return findings


def location_to_region(location: str | None) -> tuple[str, dict[str, Any]]:
    """Parse 'path/to/file.cpp:118' or 'path/to/file.cpp:118-124' into
    (path, SARIF region dict)."""
    if not location:
        return "UNKNOWN", {"startLine": 1}
    m = LOCATION_RE.match(location.strip())
    if not m:
        # No line number given — just a path.
        return location.strip(), {"startLine": 1}
    path = m.group("path")
    start = int(m.group("line"))
    region = {"startLine": start}
    if m.group("end_line"):
        region["endLine"] = int(m.group("end_line"))
    return path, region


def body_section(body: str, heading: str) -> str:
    """Pull the text under a '### Heading' section out of the finding body."""
    pattern = rf"###\s*{re.escape(heading)}\s*\n(.*?)(?=\n###\s|\Z)"
    m = re.search(pattern, body, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else ""


def finding_to_result(meta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (sarif_rule, sarif_result) for one finding."""
    severity = str(meta.get("severity", "Medium")).lower()
    level = SEVERITY_TO_LEVEL.get(severity, "warning")

    rule_id = meta.get("cwe") or meta.get("category") or meta.get("id")
    title = meta.get("title", meta.get("id", "Untitled finding"))

    body = meta.get("_body", "")
    description = body_section(body, "Description") or title
    impact = body_section(body, "Impact")
    remediation = body_section(body, "Remediation")

    message_parts = [description]
    if impact:
        message_parts.append(f"\n\nImpact: {impact}")
    if remediation:
        message_parts.append(f"\n\nRemediation: {remediation}")
    message_text = "".join(message_parts)

    path, region = location_to_region(meta.get("location"))

    rule = {
        "id": str(rule_id),
        "name": re.sub(r"[^A-Za-z0-9]+", "", title)[:60] or str(rule_id),
        "shortDescription": {"text": title},
        "fullDescription": {"text": description or title},
        "helpUri": "",
        "properties": {
            "tags": [t for t in [meta.get("category"), meta.get("asvs")] if t],
            "security-severity": {
                "critical": "9.0", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0",
            }.get(severity, "5.0"),
        },
    }

    result = {
        "ruleId": str(rule_id),
        "level": level,
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": region,
                }
            }
        ],
        "properties": {
            "findingId": meta.get("id"),
            "severity": meta.get("severity"),
            "status": meta.get("status"),
            "confidence": meta.get("confidence"),
            "component": meta.get("component"),
            "asvs": meta.get("asvs"),
            "dataClasses": meta.get("data_classes") or [],
            "regulatory": meta.get("regulatory") or [],
            "cve": meta.get("cve") or [],
            "discoveredBy": meta.get("discovered_by"),
        },
    }
    return rule, result


def build_sarif(findings: list[dict[str, Any]], tool_name: str = "vendor-audit-playbook") -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for meta in findings:
        rule, result = finding_to_result(meta)
        rules[rule["id"]] = rule  # last write wins if the same CWE/category repeats; fine, rules are shared
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def split_key(meta: dict[str, Any]) -> str:
    """Grouping key for --split-by location: first path segment of `location`,
    falling back to `component`'s prefix, falling back to 'general'."""
    loc = meta.get("location") or ""
    path = loc.split(":")[0]
    if "/" in path:
        return path.split("/")[0]
    comp = meta.get("component") or meta.get("id") or "general"
    return str(comp).split("-")[0]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="Consolidated findings markdown file")
    ap.add_argument("-o", "--output", type=Path, required=True,
                     help="Output .sarif file, or a directory when --split-by is used")
    ap.add_argument("--split-by", choices=["location"], default=None,
                     help="Emit one SARIF file per top-level path/component group instead of one combined file")
    ap.add_argument("--tool-name", default="vendor-audit-playbook", help="SARIF tool.driver.name")
    args = ap.parse_args()

    md_text = args.input.read_text(encoding="utf-8")
    findings = parse_findings(md_text)
    if not findings:
        sys.exit(f"No findings parsed from {args.input} — check the YAML-frontmatter block format.")

    print(f"Parsed {len(findings)} finding(s) from {args.input}", file=sys.stderr)

    if args.split_by == "location":
        args.output.mkdir(parents=True, exist_ok=True)
        groups: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            groups.setdefault(split_key(f), []).append(f)
        for key, group in groups.items():
            sarif = build_sarif(group, args.tool_name)
            out_path = args.output / f"{key}.sarif"
            out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
            print(f"  wrote {len(group)} finding(s) -> {out_path}", file=sys.stderr)
    else:
        sarif = build_sarif(findings, args.tool_name)
        args.output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        print(f"  wrote {len(findings)} finding(s) -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
