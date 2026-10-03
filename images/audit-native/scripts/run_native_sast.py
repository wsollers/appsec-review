#!/usr/bin/env python3
"""Run lightweight native SAST over a compile_commands.json before IR emission.

Outputs:
  <out>/clang-tidy.log
  <out>/findings-clang-tidy.json
  <out>/cppcheck.xml
  <out>/native-sast-manifest.json

The findings JSON is intentionally simple. It is evidence for later correlation,
not a final adjudication format.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SRC_EXTS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}
TIDY_RE = re.compile(r"^(.*?):(\d+):(\d+):\s+(warning|error):\s+(.*?)(?:\s+\[([^\]]+)\])?$")
OUTCOMES = ("timeout", "tool-missing", "tool-error", "compile-error")
MESSAGE_LIMIT = 240


def load_sources(compdb: Path) -> list[str]:
    entries = json.loads(compdb.read_text())
    seen: set[str] = set()
    out: list[str] = []
    for entry in entries:
        f = entry.get("file")
        if not f:
            continue
        if Path(f).suffix.lower() not in SRC_EXTS:
            continue
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def parse_tidy(text: str) -> list[dict]:
    findings = []
    for line in text.splitlines():
        m = TIDY_RE.match(line)
        if not m:
            continue
        findings.append({
            "tool": "clang-tidy",
            "file": m.group(1),
            "line": int(m.group(2)),
            "col": int(m.group(3)),
            "level": m.group(4),
            "message": m.group(5),
            "check": m.group(6) or "unknown",
        })
    return findings


def classify_tidy(rc: int, findings: list[dict]) -> str:
    """Per-TU clang-tidy outcome. 124 (timeout), 127 (missing tool) and any other failure are tool
    errors; rc 1 with an error-level compiler diagnostic (clang-diagnostic-error: missing header,
    unknown flag) is a compile error, and the TU's findings still count."""
    if rc in (0, 124, 127):
        return {0: "ok", 124: "timeout", 127: "tool-missing"}[rc]
    if rc == 1 and any(f["level"] == "error" for f in findings):
        return "compile-error"
    return "tool-error"


def first_error(findings: list[dict]) -> dict | None:
    """The first compiler error, bounded and stripped of control characters."""
    for f in findings:
        if f["level"] == "error":
            return {"file": f["file"][-MESSAGE_LIMIT:], "line": f["line"], "check": f["check"][:80],
                    "message": re.sub(r"[\x00-\x1f\x7f]+", " ", f["message"])[:MESSAGE_LIMIT]}
    return None


def run_tidy_one(src: str, compdb_dir: Path, checks: str, timeout: int) -> tuple[str, int, str]:
    cmd = ["clang-tidy", src, "-p", str(compdb_dir), f"--checks={checks}", "--warnings-as-errors="]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return src, p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        text = ""
        if isinstance(e.stdout, str):
            text += e.stdout
        if isinstance(e.stderr, str):
            text += e.stderr
        text += f"\nclang-tidy timeout after {timeout}s\n"
        return src, 124, text
    except FileNotFoundError as e:
        return src, 127, f"clang-tidy not found: {e}\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compile-commands", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--checks", default="bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*,-cppcoreguidelines-avoid-magic-numbers,performance-*,portability-*")
    args = ap.parse_args()

    compdb = Path(args.compile_commands)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    sources = load_sources(compdb)
    if args.limit:
        sources = sources[:args.limit]

    started = time.time()
    tidy_log = out / "clang-tidy.log"
    tidy_findings: list[dict] = []
    tidy_status: dict[str, int] = {}
    tidy_outcome: dict[str, str] = {}
    compile_errors: dict[str, dict | None] = {}
    with tidy_log.open("w", encoding="utf-8", errors="replace") as log:
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(run_tidy_one, src, compdb.parent, args.checks, args.timeout) for src in sources]
            for i, fut in enumerate(as_completed(futs), 1):
                src, rc, text = fut.result()
                found = parse_tidy(text)
                tidy_status[src] = rc
                tidy_outcome[src] = classify_tidy(rc, found)
                if tidy_outcome[src] == "compile-error":
                    compile_errors[src] = first_error(found)
                log.write(f"\n===== clang-tidy {src} exit={rc} outcome={tidy_outcome[src]} =====\n")
                log.write(text)
                tidy_findings.extend(found)
                if i % 25 == 0 or i == len(futs):
                    print(f"clang-tidy {i}/{len(futs)}", flush=True)
    # files_nonzero_exit stays the total; the outcome counts split it (P12).
    tidy_counts = {"files_nonzero_exit": sum(1 for rc in tidy_status.values() if rc != 0),
                   **{"files_" + name.replace("-", "_"): sum(1 for o in tidy_outcome.values() if o == name)
                      for name in OUTCOMES},
                   "first_compile_error": compile_errors[min(compile_errors)] if compile_errors else None}

    (out / "findings-clang-tidy.json").write_text(json.dumps({
        "tool": "clang-tidy",
        "checks": args.checks,
        "findings": tidy_findings,
        "files_attempted": len(sources),
        **tidy_counts,
    }, indent=1))

    cppcheck_xml = out / "cppcheck.xml"
    cpp_cmd = [
        "cppcheck", "--project=" + str(compdb), "--enable=warning,style,performance,portability",
        "--inconclusive", "--xml", "--xml-version=2", f"-j{args.jobs}",
    ]
    try:
        cpp = subprocess.run(cpp_cmd, capture_output=True, text=True, timeout=max(args.timeout, 300))
        cppcheck_xml.write_text(cpp.stderr or cpp.stdout or "", encoding="utf-8", errors="replace")
        cpp_rc = cpp.returncode
    except subprocess.TimeoutExpired as e:
        cppcheck_xml.write_text((e.stderr if isinstance(e.stderr, str) else "") + "\ncppcheck timeout\n", encoding="utf-8", errors="replace")
        cpp_rc = 124
    except FileNotFoundError as e:
        cppcheck_xml.write_text(f"cppcheck not found: {e}\n", encoding="utf-8")
        cpp_rc = 127

    manifest = {
        "generator": "run_native_sast.py",
        "compile_commands": str(compdb),
        "source_files": len(sources),
        "clang_tidy": {
            "checks": args.checks,
            "findings": len(tidy_findings),
            "files_attempted": len(sources),
            **tidy_counts,
            "log": str(tidy_log),
            "findings_file": str(out / "findings-clang-tidy.json"),
        },
        "cppcheck": {
            "exit_code": cpp_rc,
            "xml": str(cppcheck_xml),
        },
        "wall_seconds": round(time.time() - started, 1),
    }
    (out / "native-sast-manifest.json").write_text(json.dumps(manifest, indent=1))
    print(json.dumps({"clang_tidy_findings": len(tidy_findings), "cppcheck_exit": cpp_rc, "sources": len(sources)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
