#!/usr/bin/env python3
"""
triage_taint.py — summarize svf-taint.json: counts by kind, by sink file, by base object;
dedupe by (kind, sink_loc); list candidates in files of interest.

  triage_taint.py scratch-npp/svf-taint-ptr-only.json [--files 'Utf8_16|CharDistribution|nsCodingStateMachine|Buffer\\.cpp'] [--top 25]
"""
import argparse, json, re
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("path"); ap.add_argument("--files", default=r"Utf8_16|CharDistribution|nsCodingStateMachine|Buffer\.cpp")
ap.add_argument("--top", type=int, default=25)
a = ap.parse_args()
r = json.load(open(a.path))
F = r["findings"]
def sinkfile(f):
    m = re.search(r'"fl": "([^"]+)"', f["sink_loc"]) or re.search(r"([A-Za-z0-9_./\\-]+\.(?:cpp|cxx|h|hpp|c))", f["sink_loc"])
    return (m.group(1) if m else f["sink_loc"][:40]).split("/")[-1].split("\\")[-1]
print(f"module: {r['module']}  svfg: {r.get('svfg','?')}  sources: {r['sources_seen']}  tainted values: {r['tainted_values']}  objects: {r['tainted_objects']}")
print(f"candidates: {len(F)} raw, {len({(f['kind'], f['sink_loc']) for f in F})} unique (kind, sink)")
print("\nby kind:"); [print(f"  {n:6d}  {k}") for k, n in Counter(f["kind"] for f in F).most_common()]
print("\nby base kind:"); [print(f"  {n:6d}  {k or '?'}") for k, n in Counter(f["base_kind"] for f in F).most_common()]
print(f"\ntop {a.top} sink files:"); [print(f"  {n:6d}  {k}") for k, n in Counter(sinkfile(f) for f in F).most_common(a.top)]
print(f"\ntop {a.top} global base objects (TAINTED_INDEX):")
[print(f"  {n:6d}  {k[:80]}") for k, n in Counter(f["base_object"] for f in F if f["kind"] == "TAINTED_INDEX").most_common(a.top)]
print("\nby source (call site that tainted the sink's input):")
[print(f"  {n:6d}  {k[:90]}") for k, n in Counter(f["source"]+"@"+f["source_function"] for f in F).most_common(10)]
rx = re.compile(a.files)
hits = [f for f in F if rx.search(f["sink_loc"]) or rx.search(f["sink_function"])]
seen = set()
print(f"\ncandidates in files matching /{a.files}/: {len(hits)}")
for f in hits:
    key = (f["kind"], f["sink_loc"]);
    if key in seen: continue
    seen.add(key)
    print(f"  {f['kind']:20s} {sinkfile(f)}  {f['sink_loc'][:70]}\n{'':24s}fn={f['sink_function'][:60]}  base={f['base_kind']}:{f['base_object'][:30].replace(chr(10),' ')} {f['base_bytes']}B/{f['base_elements']}el  src={f['source']}@{f['source_function'][:30]}")
