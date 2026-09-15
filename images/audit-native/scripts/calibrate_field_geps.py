#!/usr/bin/env python3
"""calibrate_field_geps.py ir-facts.json — how well does the data+bound rule explain a codebase's
container indexing? On a library's own test suite (EASTLTest) nearly every field GEP should be
bounded; the unbounded remainder is the rule's false-positive ceiling. Prints per-struct counts
and the inferred (ptr field -> bound field) pairs."""
import json, sys
from collections import Counter, defaultdict
d = json.load(open(sys.argv[1])); fg = d.get("field_geps", []); pairs = d.get("field_pairs", {})
tot = len(fg); b = sum(1 for g in fg if g["bounded_by_fields"]); arg = sum(1 for g in fg if not g["bounded_by_fields"] and g.get("index_depends_on_arg"))
print(f"field GEPs: {tot}  bounded in-function: {b} ({100*b/max(tot,1):.0f}%)  unbounded & arg-dependent: {arg}  unbounded other: {tot-b-arg}")
by = defaultdict(lambda: [0, 0])
for g in fg: by[g["struct"]][0] += 1; by[g["struct"]][1] += bool(g["bounded_by_fields"])
print("\ntop structs (total, bounded, pairs used):")
for st, (n, nb) in sorted(by.items(), key=lambda kv: -kv[1][0])[:20]:
    print(f"  {n:5d} {nb:5d}  {st[:60]:60s} {dict(pairs.get(st, {}))}")
print("\nunbounded & arg-dependent sites (candidates):")
for g in [g for g in fg if not g["bounded_by_fields"] and g.get("index_depends_on_arg")][:25]:
    l = g.get("loc") or {}; print(f"  {str(l.get('file','?')).split('/')[-1]}:{l.get('line')}  {g['struct'][:40]}.f{g['ptr_field']}  in {g['demangled'][:50]}")
