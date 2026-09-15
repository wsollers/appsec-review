#!/usr/bin/env python3
"""
verify_candidate.py — mechanical L7 verification of static-analysis candidates against
LLVM IR facts (ir-facts.json). No LLM, no re-reading of source: each finding's claim is
matched to the numbers the compiler recorded, and the result is one of

  VERIFIED_PRIMITIVE  the local mechanism is confirmed by the IR (evidence attached)
  REFUTED             the IR shows the claim cannot hold (evidence attached)
  UNRESOLVED          the IR facts don't decide it; says what would (range analysis, witness)

Input: one or more SARIF files (CodeQL, incl. queries/mythos-cpp) and/or findings-csa.json.
Matching is by (file basename, line) between the finding and the IR debug locations, with a
±2 line tolerance for statements spanning lines.

  verify_candidate.py --ir-facts /scratch/ir-facts.json --sarif /scratch/codeql/mythos.sarif \
                      [--sarif ...] [--csa findings-csa.json] --out /scratch/verified.json
"""
import argparse, json, re, sys
from collections import defaultdict
from pathlib import Path

def base(p): return (p or "").replace("\\", "/").split("/")[-1]

class Facts:
    def __init__(self, paths):
        self.globals, self.globals_dem = {}, {}
        self.by_loc = defaultdict(lambda: defaultdict(list))   # kind -> (file, line) -> [fact]
        for path in paths:
            d = json.load(open(path))
            for g in d["globals"]:
                self.globals.setdefault(g["name"], g); self.globals_dem.setdefault(g.get("demangled", ""), g)
            for st, votes in (d.get("field_pairs") or {}).items():
                self.pairs.setdefault(st, {}).update(votes)
            self.pairs = {}
        for kind in ("ctor_stores", "geps", "size_calls", "allocas", "field_geps"):
                for f in d[kind]:
                    l = f.get("loc") or {}
                    if "file" in l:
                        f["_module"] = d.get("module")
                        self.by_loc[kind][(base(l["file"]), int(l["line"]))].append(f)
    def near(self, kind, file, line, tol=2):
        out = []
        for dl in range(-tol, tol + 1):
            out += self.by_loc[kind].get((base(file), line + dl), [])
        return out
    def global_by_name(self, name):
        # source names arrive undecorated; IR names are MSVC-mangled (?name@@3...). Try both.
        if name in self.globals: return self.globals[name]
        for g in self.globals.values():
            if g["name"] == name or g["name"].startswith("?" + name + "@") or g.get("demangled", "").endswith(name):
                return g
        return None

def result(f, status, evidence, needs=None):
    r = dict(f); r["verification"] = {"status": status, "evidence": evidence}
    if needs: r["verification"]["needs"] = needs
    return r

# ---------------- per-rule verifiers ----------------

def v_table_size(f, F):
    # message: "[NAME](1) is declared with N entries but [size](2) ... is set to K here."
    m = re.search(r"\[([A-Za-z_0-9]+)\]\(1\) is declared with (\d+) entries but .* set to (\d+)", f["message"])
    if not m: return result(f, "UNRESOLVED", {"reason": "message did not parse"})
    name, n_q, k = m.group(1), int(m.group(2)), int(m.group(3))
    g = F.global_by_name(name)
    if not g: return result(f, "UNRESOLVED", {"reason": f"global {name} not in IR facts"})
    n_ir = g["elements"]
    # the SARIF points at the constructor's declaration; the store is in its body
    stores = [s for s in F.near("ctor_stores", f["file"], f["line"], tol=25) if s["value"] == k]
    ev = {"global": g["name"], "ir_elements": n_ir, "query_elements": n_q, "bound": k,
          "ctor_store_seen": bool(stores), "element_bytes": g.get("element_bytes")}
    if n_ir != n_q: ev["note"] = "query and IR disagree on element count; IR is authoritative"
    if k > n_ir and stores: return result(f, "VERIFIED_PRIMITIVE", ev)
    if k <= n_ir: return result(f, "REFUTED", ev)
    return result(f, "UNRESOLVED", ev, needs=["ctor store not matched at this line"])

def v_constant_length_read(f, F):
    calls = [c for c in F.near("size_calls", f["file"], f["line"]) if c.get("size_is_constant")]
    if not calls: return result(f, "UNRESOLVED", {"reason": "no constant-size call at this line in IR"})
    c = calls[0]
    src = c.get("src") or {}
    ev = {"callee": c["kind"], "size": c["size"], "src_base": src}
    # the claim: the pointer is derived from a parameter and the size is a literal.
    if src.get("kind") in ("argument", "other", "via_load") or src.get("via_load"):
        return result(f, "VERIFIED_PRIMITIVE", ev, needs=["bound_check: prove size <= remaining length on all paths (range analysis)"])
    if src.get("kind") in ("alloca", "global") and src.get("elements") and src.get("element_bytes"):
        avail = src["elements"] * src["element_bytes"]
        ev["src_bytes"] = avail
        return result(f, "REFUTED" if c["size"] <= avail else "VERIFIED_PRIMITIVE", ev)
    return result(f, "UNRESOLVED", ev)

def v_field_gep(f, F):
    """Container-agnostic rule: index through a pointer loaded from a struct field.
    REFUTED if the function compares the index/result against another field of the same struct
    (mpEnd, ArrayNum, mCapacity...); VERIFIED_PRIMITIVE if the struct has a known bound field
    (from field_pairs) that this site does not consult; else None (fall through)."""
    fg = F.near("field_geps", f["file"], f["line"])
    if not fg: return None
    g = fg[0]
    ev = {"struct": g["struct"], "ptr_field": g["ptr_field"], "bounded_by_fields": g["bounded_by_fields"],
          "index_depends_on_arg": g.get("index_depends_on_arg")}
    if g["bounded_by_fields"]:
        return result(f, "REFUTED", ev | {"reason": "index compared against a sibling field of the same struct in this function"})
    votes = F.pairs.get(g["struct"], {})
    known = sorted((int(k.split(":")[1]), n) for k, n in votes.items() if int(k.split(":")[0]) == g["ptr_field"])
    if known:
        ev["known_bound_fields"] = known
        return result(f, "VERIFIED_PRIMITIVE", ev, needs=["range: index vs bound field %s (used as the bound elsewhere in this struct's code) — not consulted here" % [k for k, _ in known]])
    return None

def v_unchecked_index(f, F):
    r = v_field_gep(f, F)
    if r: return r
    geps = F.near("geps", f["file"], f["line"])
    if not geps: return result(f, "UNRESOLVED", {"reason": "no non-constant GEP at this line in IR"})
    # pick the GEP whose base is a global/alloca array if any
    geps.sort(key=lambda g: 0 if g["base"].get("kind") in ("global", "alloca") else 1)
    g = geps[0]; b = g["base"]; idx = (g.get("indices") or [{}])[0]
    elems = b.get("elements") or g.get("source_elements")
    ev = {"base": b, "index": idx, "elements": elems}
    if elems and idx.get("unsigned_bounded") and idx.get("zext_from_bits") and 2 ** idx["zext_from_bits"] <= elems:
        ev["range"] = f"[0, {2 ** idx['zext_from_bits'] - 1}] by type"
        return result(f, "REFUTED", ev)
    if elems and idx.get("depends_on_arg"):
        return result(f, "VERIFIED_PRIMITIVE", ev, needs=["range: is index provably < %d? (value-range analysis or witness search)" % elems])
    if not elems and idx.get("depends_on_arg") and b.get("via_load"):
        # table reached through a pointer (this->model->table): mechanism confirmed, size not at the GEP
        return result(f, "VERIFIED_PRIMITIVE", ev, needs=["table_length: resolve the pointee array (global initializer of the pointed-to struct)",
                                                          "range: index bound vs that length"])
    return result(f, "UNRESOLVED", ev, needs=["index provenance unclear in IR"])

def v_undersized_buffer(f, F):
    allocs = [c for c in F.near("size_calls", f["file"], f["line"], tol=40) if c["kind"] in ("new[]", "new", "malloc") and c.get("size_depends_on_arg")]
    memw = F.near("geps", f["file"], f["line"])
    ev = {"allocations_from_arg_nearby": [{"line": a["loc"].get("line"), "size_expr": a["size_expr"][:120], "via": a.get("size_via")} for a in allocs][:3],
          "gep_at_write": bool(memw)}
    if allocs:
        return result(f, "VERIFIED_PRIMITIVE", ev, needs=["witness: input for which loop output > allocation (symbolic execution)"])
    return result(f, "UNRESOLVED", ev)

def v_csa_arraybound(f, F):
    return v_unchecked_index(f, F)

RULES = {
    "mythos/cpp/table-size-exceeds-array-length": v_table_size,
    "mythos/cpp/constant-length-read-from-bounded-buffer": v_constant_length_read,
    "mythos/cpp/unchecked-table-index-from-input": v_unchecked_index,
    "mythos/cpp/undersized-output-buffer-from-input-length": v_undersized_buffer,
    "security.ArrayBound": v_csa_arraybound,
}

def load_sarif(p):
    out = []
    for run in json.load(open(p))["runs"]:
        for r in run["results"]:
            l = r["locations"][0]["physicalLocation"]
            out.append({"source": str(p), "rule": r["ruleId"], "file": l["artifactLocation"]["uri"],
                        "line": int(l["region"].get("startLine", 0)), "message": r["message"]["text"]})
    return out

def load_csa(p):
    return [{"source": str(p), "rule": f["checker"], "file": f["file"], "line": int(f["line"] or 0), "message": f["message"]} for f in json.load(open(p))]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ir-facts", action="append", required=True, help="one per linked module; repeatable")
    ap.add_argument("--sarif", action="append", default=[])
    ap.add_argument("--csa", action="append", default=[]); ap.add_argument("--out", required=True)
    a = ap.parse_args()
    F = Facts(a.ir_facts)
    findings = [f for p in a.sarif for f in load_sarif(p)] + [f for p in a.csa for f in load_csa(p)]
    results = []
    for f in findings:
        v = RULES.get(f["rule"])
        results.append(v(f, F) if v else result(f, "UNRESOLVED", {"reason": "no verifier for this rule"}))
    counts = defaultdict(int)
    for r in results: counts[r["verification"]["status"]] += 1
    Path(a.out).write_text(json.dumps({"ir_facts": a.ir_facts, "counts": dict(counts), "results": results}, indent=1))
    print(f"{len(results)} findings: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    for r in results:
        v = r["verification"]
        if r["rule"].startswith("mythos/") or v["status"] != "UNRESOLVED":
            print(f"  {v['status']:19s} {r['rule'].split('/')[-1][:38]:38s} {base(r['file'])}:{r['line']}  {json.dumps(v['evidence'])[:110]}")

if __name__ == "__main__":
    main()
