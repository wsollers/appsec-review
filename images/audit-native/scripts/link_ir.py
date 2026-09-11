#!/usr/bin/env python3
"""
link_ir.py — llvm-link the per-project bitcode produced by
compile_feasibility_gate.py --emit-ir into one module per project, then
optionally run SVF's wpa on each. One project == one deployable == one
whole-program analysis scope; never link test projects into the product.

  link_ir.py --feasibility /scratch/feasibility-ir.json --out /scratch/linked \
             [--project notepadPlus ...] [--exclude-re '(?i)test'] [--wpa ander]
"""
import argparse, json, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--feasibility", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--project", action="append", default=[], help="only these projects (default: all not excluded)")
ap.add_argument("--exclude-re", default=r"(?i)(test|bench|example|sample)", help="regex of project names to skip")
ap.add_argument("--wpa", default=None, help="run wpa with this analysis on each linked module, e.g. ander, sfrander")
a = ap.parse_args()

f = json.load(open(a.feasibility))
by = defaultdict(list)
for r in f["per_tu"]:
    if r["status"] == "PASS" and r.get("bitcode"):
        by[r.get("project", "default")].append(r["bitcode"])
out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
summary = {}
for proj, bcs in sorted(by.items()):
    if a.project and proj not in a.project: continue
    if not a.project and re.search(a.exclude_re, proj):
        summary[proj] = {"skipped": "excluded by --exclude-re", "tus": len(bcs)}; continue
    mod = out / f"{proj}.bc"
    p = subprocess.run(["llvm-link", "-o", str(mod), *bcs], capture_output=True, text=True)
    rec = {"tus": len(bcs), "linked": p.returncode == 0, "module": str(mod), "bytes": mod.stat().st_size if mod.exists() else 0}
    if p.returncode != 0:
        rec["error"] = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else "llvm-link failed"
        summary[proj] = rec; print(f"{proj}: LINK FAILED {rec['error']}", file=sys.stderr); continue
    print(f"{proj}: {len(bcs)} TUs -> {mod} ({rec['bytes']//1024} KiB)")
    if a.wpa:
        log = out / f"{proj}.wpa-{a.wpa}.log"
        w = subprocess.run(["wpa", f"-{a.wpa}", "-stat=true", str(mod)], capture_output=True, text=True)
        log.write_text(w.stdout + w.stderr)
        rec["wpa"] = {"analysis": a.wpa, "ok": w.returncode == 0, "log": str(log)}
        print(f"  wpa -{a.wpa}: {'ok' if w.returncode == 0 else 'FAILED'} -> {log}")
    summary[proj] = rec
(out / "link-summary.json").write_text(json.dumps(summary, indent=1))
