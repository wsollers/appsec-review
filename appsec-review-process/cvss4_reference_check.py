#!/usr/bin/env python3
"""Compare ``cvss4.py`` with FIRST's reference CVSS v4.0 calculator (ADR-0020 open item).

Offline maintenance tool, not a pipeline job.  It reads a local checkout of
https://github.com/FIRSTdotorg/cvss-v4-calculator (the caller clones and pins it), evaluates the
reference ``cvss_lookup.js``, ``max_composed.js``, ``max_severity.js`` and ``cvss_score.js`` with
Node.js, and compares entry by entry:

* the 270-entry macrovector lookup table,
* the per-EQ maximal vectors and maximal severity distances,
* macrovector and score for every base vector (104,976) plus seeded random vectors that carry
  threat, environmental and supplemental metrics.

``--write-sample`` records a seeded subset of reference results as a JSON fixture so
``tests/test_cvss4.py`` can check the scorer offline against FIRST's own outputs.

    python3 cvss4_reference_check.py compare --first-checkout ../cvss-v4-calculator \
        [--random 100000] [--write-sample tests/fixtures/cvss4-first-reference-sample.json]
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

import cvss4

REFERENCE_FILES = ("cvss_lookup.js", "max_composed.js", "max_severity.js", "cvss_score.js")

_NODE_SCRIPT = r"""
const fs = require('fs'), vm = require('vm');
const dir = process.argv[1];
const ctx = {};
vm.createContext(ctx);
for (const f of ['cvss_lookup.js', 'max_composed.js', 'max_severity.js', 'cvss_score.js'])
  vm.runInContext(fs.readFileSync(dir + '/' + f, 'utf8'), ctx);
const lines = fs.readFileSync(0, 'utf8').split('\n').filter(Boolean);
const scores = lines.map(line => {
  ctx.sel = JSON.parse(line);
  ctx.mv = vm.runInContext('macroVector(sel)', ctx);
  return [ctx.mv, vm.runInContext('cvss_score(sel, cvssLookup_global, maxSeverity, mv)', ctx)];
});
fs.writeFileSync(1, JSON.stringify({lookup: ctx.cvssLookup_global, maxComposed: ctx.maxComposed,
                                    maxSeverity: ctx.maxSeverity, scores}));
"""


def _plain(value: Any) -> Any:
    """JSON round trip so int keys and JS string keys compare equal."""
    return json.loads(json.dumps(value, sort_keys=True))


def vector_string(selected: dict[str, str]) -> str:
    parts = [f"{m}:{selected[m]}" for m in cvss4.ORDER
             if m in cvss4.BASE_METRICS or selected.get(m, "X") != "X"]
    return cvss4.VERSION + "/" + "/".join(parts)


def candidate_vectors(random_count: int, seed: int) -> list[dict[str, str]]:
    """Every base vector, then ``random_count`` seeded vectors with optional metrics."""
    out = [dict(zip(cvss4.BASE_METRICS, combo))
           for combo in itertools.product(*(cvss4.BASE_VALUES[m] for m in cvss4.BASE_METRICS))]
    rng = random.Random(seed)
    for _ in range(random_count):
        vec = {m: rng.choice(cvss4.BASE_VALUES[m]) for m in cvss4.BASE_METRICS}
        for m, values in cvss4.OPTIONAL_VALUES.items():
            vec[m] = rng.choice(values) if rng.random() < 0.6 else "X"
        out.append(vec)
    return [{**{m: "X" for m in cvss4.OPTIONAL_VALUES}, **vec} for vec in out]


def run_reference(checkout: Path, vectors: list[dict[str, str]], node: str = "node") -> dict[str, Any]:
    stdin = "\n".join(json.dumps(v) for v in vectors)
    proc = subprocess.run([node, "-e", _NODE_SCRIPT, str(checkout)], input=stdin,
                          capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


def compare(reference: dict[str, Any], vectors: list[dict[str, str]]) -> dict[str, Any]:
    """Pure comparison of reference output with ``cvss4``; every mismatch is listed."""
    ref_lookup = {k: float(v) for k, v in reference["lookup"].items()}
    table = [{"macrovector": k, "cvss4_py": cvss4.LOOKUP.get(k), "first": ref_lookup.get(k)}
             for k in sorted(set(ref_lookup) | set(cvss4.LOOKUP)) if cvss4.LOOKUP.get(k) != ref_lookup.get(k)]
    scores = []
    for selected, (ref_mv, ref_score) in zip(vectors, reference["scores"]):
        vector = vector_string(selected)
        try:
            ours = (cvss4.macrovector(cvss4.parse(vector)), cvss4.score(vector))
        except cvss4.CVSSError as exc:
            ours = ("error", str(exc))
        if ours != (ref_mv, float(ref_score)):
            scores.append({"vector": vector, "cvss4_py": list(ours), "first": [ref_mv, ref_score]})
    return {
        "lookup_entries_compared": len(set(ref_lookup) | set(cvss4.LOOKUP)),
        "lookup_mismatches": table,
        "max_composed_equal": _plain(cvss4.MAX_COMPOSED) == _plain(reference["maxComposed"]),
        "max_severity_equal": _plain(cvss4.MAX_SEVERITY) == _plain(reference["maxSeverity"]),
        "vectors_compared": len(vectors),
        "score_mismatches": scores,
    }


def file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    cmp_ = sub.add_parser("compare")
    cmp_.add_argument("--first-checkout", type=Path, required=True)
    cmp_.add_argument("--node", default="node")
    cmp_.add_argument("--random", type=int, default=100000)
    cmp_.add_argument("--seed", type=int, default=4)
    cmp_.add_argument("--write-sample", type=Path)
    cmp_.add_argument("--sample-size", type=int, default=1500)
    args = parser.parse_args(argv)

    vectors = candidate_vectors(args.random, args.seed)
    reference = run_reference(args.first_checkout, vectors, args.node)
    result = compare(reference, vectors)
    result["reference_files"] = {name: file_sha256(args.first_checkout / name) for name in REFERENCE_FILES}
    result["lookup_sha256"] = cvss4.lookup_sha256()
    print(json.dumps(result, indent=1))
    if args.write_sample:
        rng = random.Random(args.seed)
        picks = sorted(rng.sample(range(len(vectors)), min(args.sample_size, len(vectors))))
        sample = {vector_string(vectors[i]): [reference["scores"][i][0], float(reference["scores"][i][1])]
                  for i in picks}
        args.write_sample.write_text(json.dumps({
            "schema": "appsec-review/cvss4-first-reference-sample/1.0",
            "source": "FIRST cvss-v4-calculator cvss_score.js macroVector() and cvss_score()",
            "reference_files": result["reference_files"],
            "vectors": sample,
        }, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    clean = not (result["lookup_mismatches"] or result["score_mismatches"]) \
        and result["max_composed_equal"] and result["max_severity_equal"]
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
