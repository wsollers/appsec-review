#!/usr/bin/env python3
"""
analyze_dependency_lifecycle.py — broadens dependency evidence from CVE-only
reachability to the full design-v3.md L1 scope: dependency inventory, license
inventory, and best-effort EOL/abandonware signals.

Deliberately does NOT run any new scanner or network call: license and
dependency-inventory data already exist for free in evidence this pipeline
already gathers (syft's CycloneDX SBOM at sbom/sbom.cdx.json includes a
`licenses` array per component; the dedicated ScanCode Toolkit pass at
license/scancode.json is a deeper license/copyright/origin scan already run
by the `scancode` step). This script's only genuinely new contribution is
cross-referencing the SBOM's component list against a small, hand-maintained,
offline EOL/abandonware reference table (eol-reference.json) — see that
file's own header for why this is a curated table and not a live lookup
against an EOL-tracking API: a live call at evidence-gathering time would
make the pipeline's output non-deterministic run-to-run, which conflicts
with the pipeline's designed-for-reproducibility, no-caching, full-rebuild-
every-run model.

Anything not matched in the reference table is reported as "unknown", never
inferred as supported — the same "never infer that an unscanned file is
clean" discipline the rest of the pipeline applies to code coverage, applied
here to dependency lifecycle instead.

Usage:
    python3 analyze_dependency_lifecycle.py \\
        --sbom /evidence/sbom/sbom.cdx.json \\
        --eol-reference /opt/data/eol-reference.json \\
        --scancode /evidence/license/scancode.json \\
        -o /evidence/sbom/dependency-lifecycle.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WARNING: could not read/parse {path}: {exc}", file=sys.stderr)
        return None


def extract_license_inventory(sbom: dict) -> list[dict]:
    """Pull per-component license data straight out of the CycloneDX SBOM
    that syft already produces — no new tool, no new step needed for this
    part; it's already evidence, just not previously surfaced to any lane."""
    rows = []
    for component in sbom.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        licenses = []
        for lic_entry in component.get("licenses", []) or []:
            if not isinstance(lic_entry, dict):
                continue
            lic = lic_entry.get("license") or {}
            expr = lic_entry.get("expression")
            if expr:
                licenses.append(expr)
            elif isinstance(lic, dict):
                licenses.append(lic.get("id") or lic.get("name") or "unspecified")
        rows.append({
            "name": component.get("name"),
            "version": component.get("version"),
            "purl": component.get("purl"),
            "type": component.get("type"),
            "licenses": licenses or ["not declared in SBOM — cross-check license/scancode.json"],
        })
    return rows


def load_eol_reference(path: Path) -> list[dict]:
    data = load_json(path)
    if not isinstance(data, dict):
        return []
    entries = data.get("entries")
    return entries if isinstance(entries, list) else []


def match_eol(component_name: str, reference: list[dict]) -> dict | None:
    name_lower = (component_name or "").lower()
    for entry in reference:
        match = str(entry.get("match", "")).lower()
        if match and match in name_lower:
            return entry
    return None


def build_eol_signals(sbom: dict, reference: list[dict]) -> list[dict]:
    rows = []
    for component in sbom.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        name = component.get("name")
        entry = match_eol(name or "", reference)
        if entry:
            rows.append({
                "name": name,
                "version": component.get("version"),
                "purl": component.get("purl"),
                "status": entry.get("status", "known_eol"),
                "eol_date": entry.get("eol_date"),
                "reference_note": entry.get("note"),
            })
        else:
            rows.append({
                "name": name,
                "version": component.get("version"),
                "purl": component.get("purl"),
                "status": "unknown",
                "eol_date": None,
                "reference_note": "not in eol-reference.json — not evidence of currency, only that this "
                                   "curated table doesn't cover it yet. Add an entry if the review needs "
                                   "an authoritative answer for this component.",
            })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True, help="Path to sbom.cdx.json (CycloneDX, from the 'sbom' step)")
    ap.add_argument("--eol-reference", required=True, help="Path to eol-reference.json")
    ap.add_argument("--scancode", default="", help="Optional path to license/scancode.json for cross-reference note")
    ap.add_argument("-o", "--output", required=True, help="Output path for dependency-lifecycle.json")
    args = ap.parse_args()

    sbom = load_json(Path(args.sbom))
    if not isinstance(sbom, dict):
        sys.exit(f"Could not load SBOM at {args.sbom} — run the 'sbom' step first.")

    reference = load_eol_reference(Path(args.eol_reference))
    scancode_path = Path(args.scancode) if args.scancode else None
    scancode_available = bool(scancode_path and scancode_path.exists())

    license_inventory = extract_license_inventory(sbom)
    eol_signals = build_eol_signals(sbom, reference)

    known_eol = sum(1 for r in eol_signals if r["status"] not in ("unknown",))
    output = {
        "source_sbom": args.sbom,
        "eol_reference_table": args.eol_reference,
        "eol_reference_entry_count": len(reference),
        "scancode_evidence_available": scancode_available,
        "scancode_evidence_path": args.scancode or None,
        "summary": {
            "components_total": len(sbom.get("components", []) or []),
            "components_with_declared_license": sum(1 for r in license_inventory if r["licenses"] and r["licenses"][0] != "not declared in SBOM — cross-check license/scancode.json"),
            "components_flagged_by_eol_reference": known_eol,
            "components_unknown_lifecycle": len(eol_signals) - known_eol,
        },
        "license_inventory": license_inventory,
        "eol_signals": eol_signals,
        "coverage_note": "License data is sourced from syft's CycloneDX component metadata (basic per-package-manager "
                          "detection). license/scancode.json, when present, is a deeper dedicated license/copyright/"
                          "package-origin scan and should be treated as the more authoritative source on conflict. "
                          "EOL/abandonware signals are matched against a small, hand-curated, offline reference table "
                          "(see eol-reference.json header) — 'unknown' means not yet covered by that table, not "
                          "confirmed current.",
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} — {output['summary']['components_total']} component(s), "
          f"{known_eol} flagged by the EOL reference table, "
          f"{output['summary']['components_unknown_lifecycle']} unknown.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
