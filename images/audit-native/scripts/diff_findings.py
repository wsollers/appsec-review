#!/usr/bin/env python3
"""
diff_findings.py — before/after comparison of two findings-csa.json files
(design §19 validation: does a known fix remove a finding, does a known bug
produce one).

Matching is by (checker, file basename, message) rather than line, since line
numbers shift between versions. Prints removed (present before, gone after),
added, and unchanged counts; --filter restricts to files of interest.

  diff_findings.py --before /a/findings-csa.json --after /b/findings-csa.json \
                   [--filter 'Utf8_16|uchardet|Buffer\\.cpp'] [--out diff.json]
"""
import argparse, json, re
from collections import Counter
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--before", required=True); ap.add_argument("--after", required=True)
ap.add_argument("--filter", default=None); ap.add_argument("--out", default=None)
a = ap.parse_args()
rx = re.compile(a.filter) if a.filter else None

def load(p):
    fs = json.loads(Path(p).read_text())
    if rx: fs = [f for f in fs if rx.search(f["file"]) or rx.search(f["tu"])]
    return fs

def key(f): return (f["checker"], Path(f["file"]).name, f["message"])

before, after = load(a.before), load(a.after)
cb, ca = Counter(map(key, before)), Counter(map(key, after))
removed = {k: n for k, n in cb.items() if n > ca.get(k, 0)}
added = {k: n for k, n in ca.items() if n > cb.get(k, 0)}
common = sum(min(n, ca.get(k, 0)) for k, n in cb.items())

def show(title, d, src):
    print(f"\n== {title} ({sum(d.values())})")
    for k, n in sorted(d.items()):
        ex = next(f for f in src if key(f) == k)
        print(f"  {n}x  {k[0]}  {k[1]}:{ex['line']}  {k[2][:100]}")

print(f"before: {len(before)} findings   after: {len(after)} findings   unchanged: {common}")
show("REMOVED (in before, not in after)", removed, before)
show("ADDED (in after, not in before)", added, after)
if a.out:
    Path(a.out).write_text(json.dumps({
        "before": a.before, "after": a.after, "filter": a.filter,
        "counts": {"before": len(before), "after": len(after), "unchanged": common,
                   "removed": sum(removed.values()), "added": sum(added.values())},
        "removed": [{"checker": k[0], "file": k[1], "message": k[2], "count": n} for k, n in removed.items()],
        "added": [{"checker": k[0], "file": k[1], "message": k[2], "count": n} for k, n in added.items()],
    }, indent=1))
