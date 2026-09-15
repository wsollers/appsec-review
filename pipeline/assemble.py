#!/usr/bin/env python3
"""
assemble.py — Phase 2: turn pregather output into one high-confidence bundle for LLM lanes.
No LLM here either. Cross-platform (Python), so there is no bash/PowerShell twin.

  pipeline/assemble.py --scratch <dir> --out <bundle.json>

Does, in order:
  1. verify_candidate against every ir-facts-*.json (mythos SARIF + CSA findings)
  2. dedupe by (rule, file, line); attach verification status + evidence + needs
  3. rank: VERIFIED_PRIMITIVE first (by rule precision), then UNRESOLVED; REFUTED go to
     a separate section with their evidence (agents must not re-litigate them blind)
  4. attach context each lane needs: tier, TU pass rate, image digests, source hash,
     compile-command audit flags (analysis-only defines), allocator inventory if present
  5. emit bundle.json + bundle.md (human-readable) — the ONLY things handed to the LLM
"""
import argparse, json, subprocess, sys, glob, os, hashlib
from collections import Counter, defaultdict
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--scratch", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
a = ap.parse_args()
S = Path(a.scratch); OUT = Path(a.out)
facts = sorted(glob.glob(str(S / "ir-facts-*.json")))
sarifs = [p for p in (S / "codeql" / "mythos.sarif", S / "codeql" / "tablesize.sarif") if p.exists()]
csa = [p for p in (S / "csa" / "findings-csa.json",) if p.exists()]
if not facts: sys.exit("no ir-facts-*.json in scratch — run pregather first")

# 1. verify
ver = S / "verified.json"
cmd = [sys.executable, str(Path(a.repo) / "images/audit-native/scripts/verify_candidate.py"), "--out", str(ver)]
for f in facts: cmd += ["--ir-facts", f]
for f in sarifs: cmd += ["--sarif", str(f)]
for f in csa: cmd += ["--csa", str(f)]
if sarifs or csa:
    pr = subprocess.run(cmd, capture_output=True, text=True)
    if pr.returncode != 0: sys.exit("verify_candidate failed:\n" + pr.stderr[-2000:])
    print(pr.stdout.strip().splitlines()[0])
else:
    print("no findings to verify")
results = json.load(open(ver))["results"] if ver.exists() else []

# CSA emits many code-quality checkers (DeadStores, CastToStruct, PointerArithm ...). Only
# memory-safety checkers are candidates for the L3 lane; the rest are kept as informational
# so the bundle's "unresolved" section is not 500 lines of alpha.* noise (EASTL, 2026-09-15).
MEMSAFE_CSA = ("security.ArrayBound", "security.insecureAPI", "core.NullDereference", "core.uninitialized",
               "cplusplus.NewDelete", "cplusplus.NewDeleteLeaks", "unix.Malloc", "unix.MallocSizeof",
               "alpha.security.ArrayBound", "alpha.security.ReturnPtrRange", "alpha.security.taint",
               "alpha.unix.cstring", "optin.taint", "alpha.core.BoolAssignment", "core.StackAddressEscape",
               "cplusplus.Move", "alpha.cplusplus.IteratorRange", "alpha.security.MallocOverflow")
def is_candidate(r):
    return r["rule"].startswith("mythos/") or any(r["rule"].startswith(k) for k in MEMSAFE_CSA)
informational = [r for r in results if not is_candidate(r)]
results = [r for r in results if is_candidate(r)]

# 2. dedupe
seen, uniq = set(), []
for r in results:
    k = (r["rule"], r["file"].split("/")[-1], r["line"])
    if k in seen: continue
    seen.add(k); uniq.append(r)

# 3. rank
PREC = {"mythos/cpp/table-size-exceeds-array-length": 3, "mythos/cpp/constant-length-read-from-bounded-buffer": 2,
        "mythos/cpp/undersized-output-buffer-from-input-length": 2, "mythos/cpp/unchecked-table-index-from-input": 1,
        "security.ArrayBound": 1}
def rank(r):
    st = r["verification"]["status"]
    return (0 if st == "VERIFIED_PRIMITIVE" else 1 if st == "UNRESOLVED" else 2, -PREC.get(r["rule"], 0), r["file"], r["line"])
uniq.sort(key=rank)
verified = [r for r in uniq if r["verification"]["status"] == "VERIFIED_PRIMITIVE"]
unresolved = [r for r in uniq if r["verification"]["status"] == "UNRESOLVED"]
refuted = [r for r in uniq if r["verification"]["status"] == "REFUTED"]

# 4. context
ctx = {}
for name in ("pregather-manifest.json", "feasibility.json", "compile-command-audit.seed.json", "allocator-inventory.json"):
    p = S / name
    if p.exists():
        d = json.load(open(p))
        if name == "feasibility.json": d = {k: d[k] for k in ("tier_recommendation", "pass_rate", "tu_total", "tu_pass", "error_classes")}
        if name == "compile-command-audit.seed.json": d = {"analysis_only_defines": d.get("analysis_only_defines"), "flags": Counter(f["flag"] for f in d.get("flags", [])), "targets_not_evaluated": d.get("targets_not_evaluated")}
        ctx[name] = d
mods = {os.path.basename(f)[9:-5]: {k: len(v) for k, v in json.load(open(f)).items() if isinstance(v, list)} for f in facts}

bundle = {"schema": "mythos/bundle/0.1", "context": ctx, "modules": mods,
          "counts": {"verified_primitive": len(verified), "unresolved": len(unresolved), "refuted": len(refuted)},
          "instructions_for_lanes": {
              "verified_primitive": "Mechanism confirmed against IR. Your job: resolve `needs` (reachability from an untrusted source, range, witness) or refute with evidence from a different substrate. Do not re-derive what evidence already states.",
              "unresolved": "Candidate with no mechanical disposition. State what fact would decide it before reading code.",
              "refuted": "Closed mechanically. Do not re-open without new evidence; listed so you know what was excluded and why."},
          "verified_primitive": verified, "unresolved": unresolved, "refuted": refuted,
          "informational": {"note": "non-memory-safety checkers; not lane input", "count": len(informational),
                            "by_rule": dict(Counter(r["rule"] for r in informational).most_common()),
                            "items": [{"rule": r["rule"], "file": r["file"], "line": r["line"], "message": r["message"][:160]} for r in informational]}}
OUT.write_text(json.dumps(bundle, indent=1))

# 5. markdown twin
md = [f"# Mythos L3 bundle — {ctx.get('pregather-manifest.json',{}).get('project','?')}", "",
      f"Tier {ctx.get('feasibility.json',{}).get('tier_recommendation','?')} · TU pass {ctx.get('feasibility.json',{}).get('pass_rate','?')} · "
      f"verified {len(verified)} · unresolved {len(unresolved)} · refuted {len(refuted)}", "", "## VERIFIED_PRIMITIVE (work these)", ""]
for r in verified:
    v = r["verification"]; md.append(f"- **{r['rule'].split('/')[-1]}** `{r['file'].split('/')[-1]}:{r['line']}` — {r['message'][:120]}")
    md.append(f"  - evidence: `{json.dumps(v['evidence'])[:200]}`"); md.append(f"  - needs: {'; '.join(v.get('needs', []))}")
md += ["", "## UNRESOLVED", ""] + [f"- {r['rule'].split('/')[-1]} `{r['file'].split('/')[-1]}:{r['line']}` — {r['verification']['evidence'].get('reason', '')}" for r in unresolved]
md += ["", "## REFUTED (closed; evidence attached)", ""] + [f"- {r['rule'].split('/')[-1]} `{r['file'].split('/')[-1]}:{r['line']}` — {json.dumps(r['verification']['evidence'])[:120]}" for r in refuted]
OUT.with_suffix(".md").write_text("\n".join(md) + "\n")
print(f"bundle: {len(verified)} verified, {len(unresolved)} unresolved, {len(refuted)} refuted, {len(informational)} informational -> {OUT} / {OUT.with_suffix('.md')}")
