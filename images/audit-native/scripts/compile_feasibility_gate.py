#!/usr/bin/env python3
"""
compile_feasibility_gate.py — decide the L3 tier (ADR-0001) by measurement.

Runs `clang-cl -fsyntax-only` (or, with --emit-ir, a real `-emit-llvm` compile)
over every entry in a compile_commands.json, in parallel, with a per-TU
timeout. Classifies each failing TU's first errors into buckets that map to
concrete remediation, and writes feasibility.json with:

  tier_recommendation : A | B | C           (see thresholds)
  tu_total / tu_pass / tu_fail / tu_timeout
  pass_rate
  error_classes       : counts + top offending headers/constructs
  per_tu              : one record per TU (status, seconds, first 3 diagnostics)

Thresholds (override with --tier-a-min / --tier-b-min):
  A : pass_rate >= 0.98
  B : pass_rate >= 0.40
  C : below B, or --emit-ir produced no bitcode at all

Run inside audit-native, network off:
  compile_feasibility_gate.py --compile-commands /scratch/compile_commands.json \
      --out /scratch/feasibility.json [--emit-ir --ir-dir /scratch/ir] [--jobs N]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ordered: first match wins
ERROR_CLASSES = [
    ("MISSING_HEADER",        re.compile(r"fatal error: '([^']+)' file not found")),
    ("MSVC_HEADER_REJECTED",  re.compile(r"(/msvc/|\\msvc\\|Windows Kits|VC\\Tools|VC/Tools)[^:(]*(:\d+:\d+|\(\d+,\d+\)): error")),
    ("MS_EXTENSION",          re.compile(r"(__declspec|__forceinline|__uuidof|__try|__except|__leave|__asm|__int64|__based|__interface|__super)")),
    ("SAL_ANNOTATION",        re.compile(r"\b_(In|Out|Inout|Ret|Check_return|Success|Printf_format_string|Deref)\w*_\b")),
    ("TEMPLATE_TWO_PHASE",    re.compile(r"(use of undeclared identifier|must be qualified|is not a template|dependent)")),
    ("NARROWING_OR_CONST",    re.compile(r"(narrowing conversion|cannot initialize|is not a constant expression)")),
    ("LINKAGE_OR_ATTR",       re.compile(r"(attribute|calling convention|__stdcall|__cdecl|__fastcall|__thiscall)")),
    ("DEPRECATED_CRT",        re.compile(r"(_s' is deprecated|is deprecated: This function or variable may be unsafe)")),
    ("UNKNOWN_PRAGMA_OR_FLAG",re.compile(r"(unknown pragma|unknown argument|unsupported option|unknown warning option)")),
    ("COMPILER_NOT_FOUND",    re.compile(r"error: compiler not found")),
    ("NO_INPUT_FILES",        re.compile(r"error: no input files")),
]
HEADER_RE = re.compile(r"fatal error: '([^']+)' file not found")
DIAG_RE = re.compile(r"^(.*?)(?::(\d+):(\d+)|\((\d+),(\d+)\)): (error|fatal error): (.*)$")


def run_one(entry: dict, timeout: int, emit_ir: bool, ir_dir: Path | None) -> dict:
    args = list(entry.get("arguments") or [])
    if not args:
        # "command" string form
        import shlex
        args = shlex.split(entry["command"])
    # Split at "--": everything before is options, after is the source file.
    # (Converter emits "--" so absolute paths like /workspace/... aren't parsed
    # as cl options; tolerate its absence for hand-written databases.)
    if "--" in args:
        i = args.index("--")
        opts, srcs = args[:i], args[i + 1:]
    else:
        opts, srcs = args[:-1], args[-1:]
    cleaned, skip = [], False
    for a in opts:
        if skip:
            skip = False
            continue
        if a in ("/c", "-c"):
            continue
        if a.startswith("/Fo") or a.startswith("-o"):
            if a == "-o":
                skip = True
            continue
        cleaned.append(a)
    src = entry["file"]
    # driver detection: clang-cl takes cl-style flags; clang/clang++/gcc/g++ take GNU style.
    gnu = not (cleaned and cleaned[0].endswith("clang-cl"))
    if emit_ir and ir_dir is not None:
        rel = Path(src)
        for anchor in ("/workspace",):
            try:
                rel = Path(src).relative_to(anchor)
            except ValueError:
                pass
        out = ir_dir / entry.get("project", "default") / (str(rel).replace("/", "__") + ".bc")
        out.parent.mkdir(parents=True, exist_ok=True)
        # /clang:-o<path> rather than /Fo: with "--" in the command clang-cl
        # dropped the /Fo output silently (verified 2026-09-11); /clang:-o works.
        if gnu:
            cmd = cleaned + ["-c", "-emit-llvm", "-g", "-O0", "-Xclang", "-disable-O0-optnone", "-o", str(out)]
        else:
            cmd = cleaned + ["/c", "/clang:-emit-llvm", "/clang:-g", "/clang:-O0",
                             "-Xclang", "-disable-O0-optnone", f"/clang:-o{out}"]
    else:
        cmd = cleaned + (["-fsyntax-only"] if gnu else ["/Zs"])
    if gnu:
        cmd += ["-ferror-limit=5"] + srcs          # GNU driver: absolute paths are fine, no "--" needed
    else:
        cmd += ["/clang:-ferror-limit=5", "--"] + srcs
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=entry.get("directory") or None, capture_output=True, text=True, timeout=timeout)
        status = "PASS" if p.returncode == 0 else "FAIL"
        err = p.stderr
    except subprocess.TimeoutExpired as e:
        status, err = "TIMEOUT", (e.stderr or "") if isinstance(e.stderr, str) else ""
    except FileNotFoundError as e:
        status, err = "FAIL", f"error: compiler not found: {e}"
    secs = round(time.time() - t0, 2)

    diags = []
    for line in err.splitlines():
        m = DIAG_RE.match(line)
        if m:
            line_no = int(m.group(2) or m.group(4))
            diags.append({"file": m.group(1), "line": line_no, "severity": m.group(6), "message": m.group(7)})
        if len(diags) >= 3:
            break
    classes = [name for name, rx in ERROR_CLASSES if rx.search(err)] if status != "PASS" else []
    if status == "FAIL" and not classes:
        classes = ["OTHER"]
    missing_headers = HEADER_RE.findall(err)
    rec = {"file": src, "project": entry.get("project", "default"), "status": status, "seconds": secs, "error_classes": classes,
           "missing_headers": missing_headers, "diagnostics": diags}
    if emit_ir and status == "PASS":
        try:
            with open(out, "rb") as fh:
                magic = fh.read(4)
            if magic[:2] != b"BC":
                status = "FAIL"
                rec_note = "output is not LLVM bitcode (COFF?)"
                classes.append("NOT_BITCODE")
            else:
                rec["bitcode"] = str(out)
        except OSError:
            status = "FAIL"; classes.append("NO_OUTPUT")
        rec["status"] = status; rec["error_classes"] = classes
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-commands", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=int, default=120, help="seconds per TU")
    ap.add_argument("--emit-ir", action="store_true", help="real compile to LLVM bitcode instead of syntax-only")
    ap.add_argument("--ir-dir", default="/scratch/ir")
    ap.add_argument("--tier-a-min", type=float, default=0.98)
    ap.add_argument("--tier-b-min", type=float, default=0.40)
    ap.add_argument("--limit", type=int, default=0, help="only first N TUs (smoke)")
    args = ap.parse_args()

    entries = json.loads(Path(args.compile_commands).read_text())
    if args.limit:
        entries = entries[: args.limit]
    ir_dir = None
    if args.emit_ir:
        ir_dir = Path(args.ir_dir)
        ir_dir.mkdir(parents=True, exist_ok=True)

    results = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(run_one, e, args.timeout, args.emit_ir, ir_dir) for e in entries]
        for i, f in enumerate(as_completed(futs), 1):
            results.append(f.result())
            if i % 50 == 0 or i == len(futs):
                print(f"  {i}/{len(futs)}", file=sys.stderr)

    results.sort(key=lambda r: r["file"])
    total = len(results)
    n_pass = sum(r["status"] == "PASS" for r in results)
    n_fail = sum(r["status"] == "FAIL" for r in results)
    n_to = sum(r["status"] == "TIMEOUT" for r in results)
    rate = (n_pass / total) if total else 0.0

    class_counts: dict[str, int] = {}
    header_counts: dict[str, int] = {}
    for r in results:
        for c in r["error_classes"]:
            class_counts[c] = class_counts.get(c, 0) + 1
        for h in r["missing_headers"]:
            header_counts[h] = header_counts.get(h, 0) + 1

    if total == 0:
        tier = "C"
        reason = "no translation units"
    elif rate >= args.tier_a_min:
        tier = "A"
        reason = f"pass rate {rate:.3f} >= {args.tier_a_min}"
    elif rate >= args.tier_b_min:
        tier = "B"
        reason = f"pass rate {rate:.3f} in [{args.tier_b_min}, {args.tier_a_min})"
    else:
        tier = "C"
        reason = f"pass rate {rate:.3f} < {args.tier_b_min}"

    out = {
        "generator": "compile_feasibility_gate.py",
        "mode": "emit-ir" if args.emit_ir else "syntax-only",
        "compile_commands": args.compile_commands,
        "tu_total": total, "tu_pass": n_pass, "tu_fail": n_fail, "tu_timeout": n_to,
        "pass_rate": round(rate, 4),
        "tier_recommendation": tier, "tier_reason": reason,
        "thresholds": {"tier_a_min": args.tier_a_min, "tier_b_min": args.tier_b_min},
        "error_classes": dict(sorted(class_counts.items(), key=lambda kv: -kv[1])),
        "top_missing_headers": dict(sorted(header_counts.items(), key=lambda kv: -kv[1])[:30]),
        "wall_seconds": round(time.time() - t0, 1),
        "jobs": args.jobs, "timeout_per_tu": args.timeout,
        "per_tu": results,
    }
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(f"TUs {total}: pass {n_pass} fail {n_fail} timeout {n_to}  rate {rate:.3f}  -> Tier {tier} ({reason})")
    if header_counts:
        print("top missing headers:", ", ".join(f"{h}({n})" for h, n in list(out["top_missing_headers"].items())[:8]))
    if class_counts:
        print("error classes:", out["error_classes"])


if __name__ == "__main__":
    main()
