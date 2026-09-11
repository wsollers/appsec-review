#!/usr/bin/env python3
"""
build_layered_sbom.py — layered SBOM generation for a multi-deployable
vendor codebase: one CycloneDX SBOM per logical layer (server/service,
client-android, client-ios, management-plane, or whatever layers you define),
a rollup manifest tying them together, and osv-scanner run against each.

This does NOT replace a human pass for vendored native code that has no
package-manager manifest (see --seed-native-template below) — nothing
automates that part; see the playbook's Phase 0A notes on why.

Requires `syft` and (optionally) `osv-scanner` on PATH — both are already in
the Vendor Code Audit Playbook's Dockerfile. This script is a thin, testable
orchestration layer over them, not a reimplementation.

Layer config (JSON), e.g. layers.json:
    [
      {"name": "server-core-cpp",   "path": "fsh-server/Server/lib",         "type": "server"},
      {"name": "server-gm-java",    "path": "fsh-server/GM/gaiya/Restructure","type": "management-plane"},
      {"name": "server-web-php",    "path": "fsh-server/Server/www/gdip",    "type": "server"},
      {"name": "client-android",    "path": "fsh-client/UnityClient/Shelter","type": "client", "platform": "android"},
      {"name": "client-ios",        "path": "fsh-client/UnityClient/Shelter","type": "client", "platform": "ios"},
      {"name": "infra-tools",       "path": "fsh-infra/tools",               "type": "management-plane"}
    ]

Usage:
    # 1) generate one CycloneDX SBOM per layer + a rollup:
    python3 build_layered_sbom.py sbom --layers layers.json -o /evidence/sbom

    # 2) run osv-scanner against every layer SBOM just produced:
    python3 build_layered_sbom.py scan -o /evidence/sbom

    # 3) seed (or refresh) the manual-tracking template for vendored native
    #    dependencies that no package manager knows about — pre-populate it
    #    from build_symbol_index.py's directory listing if you have one, or
    #    just start from the blank template and fill it in by hand:
    python3 build_layered_sbom.py native-template -o /evidence/sbom \\
        --seed "Server/lib/libs/protobuf/protobuf-2.5.0:protobuf:2.5.0" \\
        --seed "Server/lib/libs/protobuf/protobuf-2.7.0:protobuf:2.7.0" \\
        --seed "前端文档/lua-5.3:lua:5.3"
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NATIVE_TEMPLATE_HEADER = [
    "path", "guessed_product", "guessed_version", "confidence",
    "purl_if_constructible", "cve_lookup_status", "notes",
]


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        sys.exit(f"'{name}' not found on PATH. It's part of the toolbox Dockerfile — run this inside that container, "
                  f"or install {name} locally.")


def run_syft(layer: dict[str, Any], repo_root: Path, out_dir: Path) -> Path | None:
    layer_path = repo_root / layer["path"]
    if not layer_path.exists():
        print(f"WARNING: layer '{layer['name']}' path does not exist: {layer_path} — skipping", file=sys.stderr)
        return None

    out_path = out_dir / f"{layer['name']}.cdx.json"
    cmd = ["syft", f"dir:{layer_path}", "-o", f"cyclonedx-json={out_path}"]
    print(f"==> syft: {layer['name']} ({layer_path})", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"WARNING: syft failed for layer '{layer['name']}' (exit {result.returncode}): {result.stderr.strip()[:500]}", file=sys.stderr)
        return None
    return out_path


def cmd_sbom(args: argparse.Namespace) -> None:
    require_tool("syft")
    layers = json.loads(Path(args.layers).read_text(encoding="utf-8"))
    repo_root = Path(args.repo_root)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    rollup: dict[str, Any] = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "layers": [],
    }
    for layer in layers:
        sbom_path = run_syft(layer, repo_root, out_dir)
        entry = {
            "name": layer["name"],
            "type": layer.get("type", "unspecified"),
            "platform": layer.get("platform"),
            "source_path": layer["path"],
            "sbom_file": sbom_path.name if sbom_path else None,
            "status": "generated" if sbom_path else "failed_or_missing",
        }
        if sbom_path:
            try:
                sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
                entry["component_count"] = len(sbom.get("components", []))
            except (json.JSONDecodeError, OSError):
                entry["component_count"] = None
        rollup["layers"].append(entry)

    (out_dir / "ROLLUP.json").write_text(json.dumps(rollup, indent=2), encoding="utf-8")
    total = sum(l.get("component_count") or 0 for l in rollup["layers"])
    print(f"\nWrote {out_dir / 'ROLLUP.json'} — {len(rollup['layers'])} layer(s), {total} component(s) total", file=sys.stderr)
    for l in rollup["layers"]:
        print(f"  {l['name']:20s} [{l['type']:16s}] {l['status']:18s} {l.get('component_count', '-')} components", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> None:
    require_tool("osv-scanner")
    out_dir = Path(args.output)
    rollup_path = out_dir / "ROLLUP.json"
    if not rollup_path.exists():
        sys.exit(f"No {rollup_path} — run the 'sbom' subcommand first.")
    rollup = json.loads(rollup_path.read_text(encoding="utf-8"))

    scan_dir = out_dir / "osv-results"
    scan_dir.mkdir(parents=True, exist_ok=True)

    for layer in rollup["layers"]:
        if layer["status"] != "generated":
            continue
        sbom_path = out_dir / layer["sbom_file"]
        result_path = scan_dir / f"{layer['name']}.osv.json"
        print(f"==> osv-scanner: {layer['name']}", file=sys.stderr)
        cmd = ["osv-scanner", f"--sbom={sbom_path}", "--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        result_path.write_text(result.stdout, encoding="utf-8")
        if result.stderr.strip():
            (scan_dir / f"{layer['name']}.osv.stderr.log").write_text(result.stderr, encoding="utf-8")
        # osv-scanner exits non-zero when it finds vulnerabilities — that's
        # expected and not a failure of this step.
        try:
            parsed = json.loads(result.stdout) if result.stdout.strip() else {}
            n = sum(len(r.get("packages", [])) for r in parsed.get("results", []))
            print(f"    {n} package result(s) with findings written to {result_path}", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"    (could not parse osv-scanner output as JSON — see {result_path})", file=sys.stderr)


def cmd_native_template(args: argparse.Namespace) -> None:
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    template_path = out_dir / "native-dependencies.csv"

    existing_rows: list[dict[str, str]] = []
    if template_path.exists():
        with template_path.open(newline="", encoding="utf-8") as f:
            existing_rows = list(csv.DictReader(f))

    existing_paths = {row["path"] for row in existing_rows}
    seeded = 0
    for seed in args.seed or []:
        parts = seed.split(":")
        if len(parts) != 3:
            print(f"WARNING: --seed '{seed}' isn't 'path:product:version' — skipping", file=sys.stderr)
            continue
        path, product, version = parts
        if path in existing_paths:
            continue
        existing_rows.append({
            "path": path,
            "guessed_product": product,
            "guessed_version": version,
            "confidence": "seeded — verify",
            "purl_if_constructible": f"pkg:generic/{product}@{version}",
            "cve_lookup_status": "not looked up yet",
            "notes": "",
        })
        seeded += 1

    with template_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NATIVE_TEMPLATE_HEADER)
        writer.writeheader()
        writer.writerows(existing_rows)

    print(f"Wrote {template_path} — {len(existing_rows)} row(s) total ({seeded} newly seeded this run).", file=sys.stderr)
    print("This file is not auto-populated beyond --seed entries you give it — walk Server/lib/libs (and equivalents) "
          "by hand, using build_symbol_index.py's file listing and the Phase A 'binary triage' strings/entropy pass "
          "for version banners, and add a row per vendored component with no package-manager manifest. Then look each "
          "one up against NVD/CVE.org by product+version — nothing here does that lookup automatically.", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p_sbom = sub.add_parser("sbom", help="Generate one CycloneDX SBOM per layer + a rollup manifest")
    p_sbom.add_argument("--layers", required=True, help="Path to the layers.json config")
    p_sbom.add_argument("--repo-root", default=".", help="Root directory layer paths are relative to (default: cwd)")
    p_sbom.add_argument("-o", "--output", required=True, help="Output directory")
    p_sbom.set_defaults(func=cmd_sbom)

    p_scan = sub.add_parser("scan", help="Run osv-scanner against every layer SBOM from a prior 'sbom' run")
    p_scan.add_argument("-o", "--output", required=True, help="Same output directory used for 'sbom'")
    p_scan.set_defaults(func=cmd_scan)

    p_native = sub.add_parser("native-template", help="Seed/update the manual native-dependency tracking CSV")
    p_native.add_argument("-o", "--output", required=True, help="Output directory")
    p_native.add_argument("--seed", action="append", help="path:product:version — repeatable")
    p_native.set_defaults(func=cmd_native_template)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
