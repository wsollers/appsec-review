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
    with tidy_log.open("w", encoding="utf-8", errors="replace") as log:
        with ThreadPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(run_tidy_one, src, compdb.parent, args.checks, args.timeout) for src in sources]
            for i, fut in enumerate(as_completed(futs), 1):
                src, rc, text = fut.result()
                tidy_status[src] = rc
                log.write(f"\n===== clang-tidy {src} exit={rc} =====\n")
                log.write(text)
                tidy_findings.extend(parse_tidy(text))
                if i % 25 == 0 or i == len(futs):
                    print(f"clang-tidy {i}/{len(futs)}", flush=True)

    (out / "findings-clang-tidy.json").write_text(json.dumps({
        "tool": "clang-tidy",
        "checks": args.checks,
        "findings": tidy_findings,
        "files_attempted": len(sources),
        "files_nonzero_exit": sum(1 for rc in tidy_status.values() if rc != 0),
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
            "files_nonzero_exit": sum(1 for rc in tidy_status.values() if rc != 0),
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
