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
site_b = sum(g.get("callsites_bounded", 0) for g in viaparam)
site_u = sum(g.get("callsites_unbounded", 0) for g in viaparam)
pair_explained = sum(1 for g in fg if any(k.startswith(f"{g['ptr_field']}:") for k in pairs.get(g["struct"], {})))
print(f"field GEPs: {tot}  bounded in-function: {b} ({100*b/max(tot,1):.0f}%)")
print(f"  index is a parameter (accessor): {len(viaparam)} -> all call sites bounded: {allb}, some unbounded: {someu}, no call sites: {nocall}")
print(f"  accessor call sites: bounded: {site_b}, unbounded: {site_u} ({100*site_b/max(site_b+site_u,1):.0f}% bounded)")
print(f"  learned ptr->bound field pair exists: {pair_explained} ({100*pair_explained/max(tot,1):.0f}%)")
print(f"  unbounded, index from other args: {arg}   unbounded other: {tot-b-len(viaparam)-arg}")
print(f"  ==> effectively bounded: {b+allb} ({100*(b+allb)/max(tot,1):.0f}%)")
print("\nunbounded call sites (report these, not the accessor):")
n=0
for g in viaparam:
    for c in g["callsites"]:
        if not c["bounded"] and n < 20:
            n+=1; l=c.get("loc") or {}; print(f"  {str(l.get('file','?')).split('/')[-1]}:{l.get('line')}  {c['caller'][:60]}  -> {g['demangled'][:40]}")
by = defaultdict(lambda: [0, 0, 0, 0, 0])
for g in fg:
    st = g["struct"]
    by[st][0] += 1
    by[st][1] += bool(g["bounded_by_fields"])
    by[st][2] += ("index_arg" in g and g["callsites_unbounded"] == 0 and g["callsites_bounded"] > 0)
    by[st][3] += ("index_arg" in g and g["callsites_unbounded"] > 0)
    by[st][4] += any(k.startswith(f"{g['ptr_field']}:") for k in pairs.get(st, {}))
print("\ntop structs (total, in-fn, all-sites, mixed-sites, pair-evidence, pairs used):")
for st, counts in sorted(by.items(), key=lambda kv: -kv[1][0])[:20]:
    n, in_fn, all_sites, mixed_sites, pair_seen = counts
    print(f"  {n:5d} {in_fn:5d} {all_sites:5d} {mixed_sites:5d} {pair_seen:5d}  {st[:52]:52s} {dict(pairs.get(st, {}))}")
print("\nunbounded & arg-dependent sites (candidates):")
for g in [g for g in fg if not g["bounded_by_fields"] and g.get("index_depends_on_arg")][:25]:
    l = g.get("loc") or {}; print(f"  {str(l.get('file','?')).split('/')[-1]}:{l.get('line')}  {g['struct'][:40]}.f{g['ptr_field']}  in {g['demangled'][:50]}")
