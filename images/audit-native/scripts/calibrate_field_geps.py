#!/usr/bin/env python3
"""calibrate_field_geps.py ir-facts.json — how well does the data+bound rule explain a codebase's
container indexing? On a library's own test suite (EASTLTest) nearly every field GEP should be
bounded; the unbounded remainder is the rule's false-positive ceiling. Prints per-struct counts
and the inferred (ptr field -> bound field) pairs."""
import json, sys
from collections import Counter, defaultdict
d = json.load(open(sys.argv[1])); fg = d.get("field_geps", []); pairs = d.get("field_pairs", {})
tot = len(fg); b = sum(1 for g in fg if g["bounded_by_fields"])
viaparam = [g for g in fg if not g["bounded_by_fields"] and "index_arg" in g]
allb = sum(1 for g in viaparam if g["callsites_unbounded"] == 0 and g["callsites_bounded"] > 0)
someu = sum(1 for g in viaparam if g["callsites_unbounded"] > 0)
nocall = sum(1 for g in viaparam if g["callsites_bounded"] + g["callsites_unbounded"] == 0)
arg = sum(1 for g in fg if not g["bounded_by_fields"] and "index_arg" not in g and g.get("index_depends_on_arg"))
print(f"field GEPs: {tot}  bounded in-function: {b} ({100*b/max(tot,1):.0f}%)")
print(f"  index is a parameter (accessor): {len(viaparam)} -> all call sites bounded: {allb}, some unbounded: {someu}, no call sites: {nocall}")
print(f"  unbounded, index from other args: {arg}   unbounded other: {tot-b-len(viaparam)-arg}")
print(f"  ==> effectively bounded: {b+allb} ({100*(b+allb)/max(tot,1):.0f}%)")
print("\nunbounded call sites (report these, not the accessor):")
n=0
for g in viaparam:
    for c in g["callsites"]:
        if not c["bounded"] and n < 20:
            n+=1; l=c.get("loc") or {}; print(f"  {str(l.get('file','?')).split('/')[-1]}:{l.get('line')}  {c['caller'][:60]}  -> {g['demangled'][:40]}")
by = defaultdict(lambda: [0, 0])
for g in fg: by[g["struct"]][0] += 1; by[g["struct"]][1] += bool(g["bounded_by_fields"])
print("\ntop structs (total, bounded, pairs used):")
for st, (n, nb) in sorted(by.items(), key=lambda kv: -kv[1][0])[:20]:
    print(f"  {n:5d} {nb:5d}  {st[:60]:60s} {dict(pairs.get(st, {}))}")
print("\nunbounded & arg-dependent sites (candidates):")
for g in [g for g in fg if not g["bounded_by_fields"] and g.get("index_depends_on_arg")][:25]:
    l = g.get("loc") or {}; print(f"  {str(l.get('file','?')).split('/')[-1]}:{l.get('line')}  {g['struct'][:40]}.f{g['ptr_field']}  in {g['demangled'][:50]}")
