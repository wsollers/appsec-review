#!/usr/bin/env python3
"""
run_csa.py — Clang Static Analyzer over a clang-cl compile_commands.json.

Drives `clang-cl --analyze` per TU in parallel (CodeChecker's own command
rewriting is built for clang/gcc flag syntax, not cl syntax, so the analysis is
not routed through it). Emits plist-multi-file per TU — CodeChecker's native
report format — then runs `CodeChecker parse` on the directory for a
normalized JSON export and an HTML report, and independently writes a compact
findings-csa.json from the plists so the result doesn't depend on CodeChecker.

  run_csa.py --compile-commands /scratch/compile_commands.json --out /scratch/csa \
             [--filter 'Utf8_16|uchardet|Buffer\\.cpp'] [--jobs N] [--timeout 600] \
             [--alpha] [--no-codechecker]

Checkers: clang's default set plus security.*, optin.taint.*, and (with
--alpha) alpha.security.* / alpha.core.*. Each finding records checker, file,
line, message, path length, issue hash, and the TU it was found in.
"""
from __future__ import annotations

import argparse, json, os, plistlib, re, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_CHECKERS = ["security", "optin.taint", "core", "cplusplus", "unix", "deadcode", "nullability"]
ALPHA_CHECKERS = ["alpha.security", "alpha.core", "alpha.cplusplus", "alpha.unix"]


def split_cmd(entry: dict) -> tuple[list[str], str]:
    args = list(entry.get("arguments") or [])
    if not args:
        import shlex
        args = shlex.split(entry["command"])
    if "--" in args:
        i = args.index("--")
        opts, src = args[:i], args[i + 1]
    else:
        opts, src = args[:-1], args[-1]
    cleaned, skip = [], False
    for a in opts:
        if skip:
            skip = False; continue
        if a in ("/c", "-c") or a.startswith("/Fo"):
            continue
        if a == "-o":
            skip = True; continue
        if a.startswith("-o") and len(a) > 2:
            continue
        cleaned.append(a)
    return cleaned, src


def analyze_one(entry: dict, out_dir: Path, checkers: list[str], timeout: int) -> dict:
    opts, src = split_cmd(entry)
    proj = entry.get("project", "default")
    rel = src[len("/workspace/"):] if src.startswith("/workspace/") else src
    plist = out_dir / proj / (rel.replace("/", "__") + ".plist")
    plist.parent.mkdir(parents=True, exist_ok=True)
    cmd = opts + ["--analyze", "-Xclang", "-analyzer-output=plist-multi-file",
                  # required by several alpha.* checkers; enabling their package without
                  # it is a hard error ("checker cannot be enabled with analyzer option
                  # 'aggressive-binary-operation-simplification' == false"), 2026-09-12
                  "-Xclang", "-analyzer-config", "-Xclang", "aggressive-binary-operation-simplification=true"]
    for c in checkers:
        cmd += ["-Xclang", f"-analyzer-checker={c}"]
    cmd += ["/clang:-o" + str(plist), "--", src]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=entry.get("directory") or None, capture_output=True, text=True, timeout=timeout)
        status = "OK" if p.returncode == 0 else "ERROR"
        err = p.stderr
    except subprocess.TimeoutExpired:
        status, err = "TIMEOUT", ""
    n = 0
    if plist.exists():
        try:
            with open(plist, "rb") as fh:
                n = len(plistlib.load(fh).get("diagnostics", []))
        except Exception:
            status = "BAD_PLIST"
    return {"file": src, "project": proj, "status": status, "seconds": round(time.time() - t0, 1),
            "plist": str(plist) if plist.exists() else None, "diagnostics": n,
            "stderr_tail": err.strip().splitlines()[-3:] if status != "OK" else []}


def collect_findings(results: list[dict]) -> list[dict]:
    findings = []
    for r in results:
        if not r.get("plist"):
            continue
        with open(r["plist"], "rb") as fh:
            pl = plistlib.load(fh)
        files = pl.get("files", [])
        for d in pl.get("diagnostics", []):
            loc = d.get("location", {})
            f = files[loc.get("file", 0)] if files else "?"
            findings.append({
                "checker": d.get("check_name"), "category": d.get("category"), "type": d.get("type"),
                "file": f, "line": loc.get("line"), "col": loc.get("col"),
                "message": d.get("description"), "path_length": len(d.get("path", [])),
                "issue_hash": d.get("issue_hash_content_of_line_in_context"),
                "tu": r["file"], "project": r["project"],
            })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-commands", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--filter", default=None, help="regex on source path; only matching TUs are analyzed")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--alpha", action="store_true", help="also enable alpha.* checkers (noisier)")
    ap.add_argument("--no-codechecker", action="store_true")
    a = ap.parse_args()

    entries = json.loads(Path(a.compile_commands).read_text())
    if a.filter:
        rx = re.compile(a.filter)
        entries = [e for e in entries if rx.search(e["file"])]
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    checkers = DEFAULT_CHECKERS + (ALPHA_CHECKERS if a.alpha else [])
    print(f"analyzing {len(entries)} TUs with {a.jobs} jobs; checkers: {', '.join(checkers)}")

    results, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(analyze_one, e, out / "plist", checkers, a.timeout) for e in entries]
        for i, f in enumerate(as_completed(futs), 1):
            results.append(f.result())
            if i % 25 == 0 or i == len(futs):
                print(f"  {i}/{len(futs)}", file=sys.stderr)
    results.sort(key=lambda r: r["file"])
    findings = collect_findings(results)

    by_checker: dict[str, int] = {}
    for f in findings:
        by_checker[f["checker"]] = by_checker.get(f["checker"], 0) + 1
    summary = {
        "generator": "run_csa.py", "compile_commands": a.compile_commands, "filter": a.filter,
        "checkers": checkers, "tu_total": len(results),
        "tu_ok": sum(r["status"] == "OK" for r in results),
        "tu_error": sum(r["status"] == "ERROR" for r in results),
        "tu_timeout": sum(r["status"] == "TIMEOUT" for r in results),
        "findings_total": len(findings),
        "by_checker": dict(sorted(by_checker.items(), key=lambda kv: -kv[1])),
        "wall_seconds": round(time.time() - t0, 1),
        "per_tu": results,
    }
    (out / "csa-summary.json").write_text(json.dumps(summary, indent=1))
    (out / "findings-csa.json").write_text(json.dumps(findings, indent=1))
    print(f"TUs {len(results)}: ok {summary['tu_ok']} error {summary['tu_error']} timeout {summary['tu_timeout']}; "
          f"findings {len(findings)} in {summary['wall_seconds']}s")
    for k, v in list(summary["by_checker"].items())[:12]:
        print(f"  {v:4d}  {k}")

    if not a.no_codechecker and findings:
        for fmt, dest in (("json", out / "codechecker.json"), ("html", out / "html")):
            p = subprocess.run(["CodeChecker", "parse", str(out / "plist"), "-e", fmt, "-o", str(dest)],
                               capture_output=True, text=True)
            ok = p.returncode in (0, 2)  # 2 == "reports found", CodeChecker's convention
            print(f"CodeChecker parse -e {fmt}: {'ok' if ok else 'FAILED'} -> {dest}" +
                  ("" if ok else "\n    " + "\n    ".join(p.stderr.strip().splitlines()[-3:])))


if __name__ == "__main__":
    main()
