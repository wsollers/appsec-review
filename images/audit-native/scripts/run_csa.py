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
DEFAULT_TAINT_CONFIG = str(Path(__file__).with_name("taint-win32.yaml"))
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


def analyze_one(entry: dict, out_dir: Path, checkers: list[str], timeout: int,
                taint_config: str | None = None, ctu_dir: Path | None = None) -> dict:
    opts, src = split_cmd(entry)
    proj = entry.get("project", "default")
    rel = src[len("/workspace/"):] if src.startswith("/workspace/") else src
    plist = out_dir / proj / (rel.replace("/", "__") + ".plist")
    plist.parent.mkdir(parents=True, exist_ok=True)
    gnu = not opts[0].endswith("clang-cl")   # GNU driver (Linux targets) vs cl driver
    cmd = opts + ["--analyze", "-Xclang", "-analyzer-output=plist-multi-file",
                  # required by several alpha.* checkers; enabling their package without
                  # it is a hard error ("checker cannot be enabled with analyzer option
                  # 'aggressive-binary-operation-simplification' == false"), 2026-09-12
                  "-Xclang", "-analyzer-config", "-Xclang", "aggressive-binary-operation-simplification=true"]
    for c in checkers:
        cmd += ["-Xclang", f"-analyzer-checker={c}"]
    if taint_config:
        cmd += ["-Xclang", "-analyzer-config", "-Xclang", f"optin.taint.TaintPropagation:Config={taint_config}"]
    if ctu_dir is not None:
        # Cross-TU with on-demand parsing: callee TUs are parsed from the invocation list
        # when first needed (no .ast dumps). Verified with cl-mode argv 2026-09-12.
        for kv in (f"experimental-enable-naive-ctu-analysis=true", f"ctu-dir={ctu_dir}",
                   f"ctu-invocation-list={ctu_dir / 'invocations.yaml'}"):
            cmd += ["-Xclang", "-analyzer-config", "-Xclang", kv]
    cmd += (["-o", str(plist), src] if gnu else ["/clang:-o" + str(plist), "--", src])
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
    if status != "OK" and err:
        plist.with_suffix(".stderr").write_text(err)   # full compiler/analyzer output for diagnosis
    errs = [l for l in err.splitlines() if "error:" in l][:5]
    return {"file": src, "project": proj, "status": status, "seconds": round(time.time() - t0, 1),
            "plist": str(plist) if plist.exists() else None, "diagnostics": n,
            "errors": errs, "stderr_tail": err.strip().splitlines()[-3:] if status != "OK" else []}


def prepare_ctu(all_entries: list[dict], ctu_dir: Path, jobs: int) -> dict:
    """Phase 1 of CTU: externalDefMap.txt (clang-extdef-mapping over every TU) and the
    on-demand invocation list. Uses ALL entries, not just the --filter subset, so
    callees anywhere in the program can be loaded.

    clang-extdef-mapping is a libTooling tool and rejects a compile DB with unknown
    keys ("json-compilation-database: Unknown key: project"), so a stripped copy is
    written under ctu_dir first."""
    ctu_dir.mkdir(parents=True, exist_ok=True)
    dbdir = ctu_dir / "db"; dbdir.mkdir(exist_ok=True)
    clean = [{k: v for k, v in e.items() if k in ("directory", "file", "arguments", "command", "output")} for e in all_entries]
    (dbdir / "compile_commands.json").write_text(json.dumps(clean))
    # On-demand parsing rebuilds each callee's invocation from this list WITHOUT the driver's
    # help: a bare `clang++` argv[0] leaves it unable to find the resource dir, so builtin
    # headers (stddef.h) are missing and every callee parse fails (EASTL, 2026-09-15).
    # Use the absolute compiler path and pin -resource-dir explicitly.
    import shutil
    def resdir(cc):
        try: return subprocess.run([cc, "-print-resource-dir"], capture_output=True, text=True, timeout=30).stdout.strip()
        except Exception: return ""
    cache = {}
    with open(ctu_dir / "invocations.yaml", "w") as fh:
        for e in all_entries:
            args, skip = [], False
            for a in (e.get("arguments") or []):
                if skip: skip = False; continue
                if a in ("/c", "-c"): continue
                if a == "-o": skip = True; continue
                if a.startswith("/Fo"): continue
                args.append(a)
            if args:
                cc = shutil.which(args[0]) or args[0]
                if cc not in cache: cache[cc] = resdir(cc)
                args[0] = cc
                if cache[cc] and not any(a.startswith("-resource-dir") for a in args):
                    args.insert(1, f"-resource-dir={cache[cc]}")
            fh.write(json.dumps(e["file"]) + ": " + json.dumps(args) + "\n")

    def one(e):
        p = subprocess.run(["clang-extdef-mapping", "-p", str(dbdir), e["file"]], capture_output=True, text=True, timeout=600)
        return e["file"], p.returncode, p.stdout, p.stderr.strip().splitlines()[-1:] if p.returncode else []
    lines, failed = [], []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        for f, rc, out, err in ex.map(one, all_entries):
            if rc == 0:
                lines.append(out)
            else:
                failed.append({"file": f, "error": err})
    # Dedupe: templates/inline functions are defined in many TUs and produce the same USR
    # from each; CTU rejects an ambiguous index ("multiple definitions are found for the
    # same key" — 113/126 EASTL TUs, 2026-09-15). Like CodeChecker, drop USRs with more
    # than one distinct definition location; keep the unambiguous rest.
    defs = {}
    for line in "".join(lines).splitlines():
        if not line.strip(): continue
        key, _, path = line.rpartition(" ")
        defs.setdefault(key, set()).add(path)
    unique = {k: next(iter(v)) for k, v in defs.items() if len(v) == 1}
    ambiguous = sum(1 for v in defs.values() if len(v) > 1)
    (ctu_dir / "externalDefMap.txt").write_text("".join(f"{k} {p}\n" for k, p in unique.items()))
    print(f"CTU: {len(unique)} external definitions mapped ({ambiguous} ambiguous dropped) from {len(all_entries) - len(failed)}/{len(all_entries)} TUs -> {ctu_dir}")
    return {"ctu_dir": str(ctu_dir), "extdefs": len(unique), "ambiguous_dropped": ambiguous, "tus_mapped": len(all_entries) - len(failed), "mapping_failed": failed}


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
    ap.add_argument("--ctu", action="store_true", help="cross-TU analysis (on-demand parsing over the WHOLE compile DB)")
    ap.add_argument("--taint-config", default=DEFAULT_TAINT_CONFIG,
                    help="optin.taint TaintPropagation YAML; 'none' for CSA's libc-only defaults")
    a = ap.parse_args()

    all_entries = json.loads(Path(a.compile_commands).read_text())
    entries = all_entries
    taint_config = None if a.taint_config == "none" else a.taint_config
    first = all_entries[0].get("arguments") or []
    if taint_config == DEFAULT_TAINT_CONFIG and first and not first[0].endswith("clang-cl"):
        taint_config = None   # Linux target: CSA's built-in libc sources apply; Win32 model would be inert
    if a.filter:
        rx = re.compile(a.filter)
        entries = [e for e in entries if rx.search(e["file"])]
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    checkers = DEFAULT_CHECKERS + (ALPHA_CHECKERS if a.alpha else [])
    ctu_info, ctu_dir = None, None
    if a.ctu:
        ctu_dir = out / "ctu-dir"
        ctu_info = prepare_ctu(all_entries, ctu_dir, a.jobs)
    print(f"analyzing {len(entries)} TUs with {a.jobs} jobs; checkers: {', '.join(checkers)}; "
          f"taint config: {taint_config or 'built-in libc only'}; CTU: {'on' if a.ctu else 'off'}")

    results, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = [ex.submit(analyze_one, e, out / "plist", checkers, a.timeout, taint_config, ctu_dir) for e in entries]
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
        "checkers": checkers, "taint_config": taint_config, "ctu": ctu_info, "tu_total": len(results),
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
