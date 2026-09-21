#!/usr/bin/env python3
"""
capture_build_commands.py -- Tier B, pass 1 (command-line capture) of the
L12 native-vendored-dependency-inference job (see docs/design-v3.md §4.2).

Produces build-commands.jsonl: one JSON record per real compiler/linker
subprocess invocation, for extract_vendor_candidates.py to parse. Records
the REAL argv the toolchain would use -- not a guess, not a re-derivation
from source text -- by asking clang's own driver to print (not execute)
each subprocess command line via `-###`.

Why `-###` and not `-v`: both make the clang driver print the subprocess
commands it would run, but `-###` additionally suppresses execution of
those subprocesses (per clang's own docs: "Print (but do not run) the
commands to run for this compilation"). That keeps this step inside the
hostile-build boundary's "generate compile_commands.json... compile or
syntax-check" permitted list (design-v3.md §2.2) without going further --
it discovers the real command lines a build would use without actually
running any vendored build script, compiler-plugin, or linker against
untrusted input.

Two independent sources of records, either or both may be given:

1. --compile-db compile_commands.json (already a standard artifact this
   pipeline produces today via pipeline/normalize_compile_db.py). Each
   entry's compile command is re-invoked with `-###` appended to recover
   the exact `-cc1`/integrated-assembler subprocess argv clang would use --
   this is real -I/-isystem expansion (including anything a compiler
   wrapper, response file, or implicit search path would add), not just
   the raw flags already visible in the CDB entry.

2. --link-recipe link-recipe.json: a JSON array of {"argv": [...],
   "cwd": "..."} records giving the DRIVER-LEVEL link command(s) a real
   build actually used (e.g. the final `clang++ ... -o app` invocation).
   This script does not know how to discover those on its own -- that is
   a build-system-specific question (a ninja/make build graph query, an
   MSBuild verbose log, etc. -- see design-v3.md §4.2's open items) left
   to whatever produces this file. What this script adds is expanding
   each one via `-###` to the real `ld`/`lld`/`collect2` subprocess argv,
   which is what actually carries -L search paths and every positional
   .a/.so/.o/.lib the link pulled in, including anything an implicit
   default search path contributed that the driver-level command alone
   doesn't show.

Every record emitted is tagged with its source stage so a caller can tell
compile-time evidence from link-time evidence apart:
    {"kind": "compile"|"assemble"|"link"|"other",
     "stage": "driver"|"expanded",
     "argv": [...], "cwd": "...", "tu": "<path>|null",
     "source": "compile-db"|"link-recipe"}

Usage:
    python3 capture_build_commands.py \\
        --compile-db /scratch/compile_commands.json \\
        --link-recipe /scratch/link-recipe.json \\
        -o /scratch/native-build/build-commands.jsonl
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

LINK_PROGRAM_BASENAMES = {"ld", "ld.lld", "ld.gold", "ld.bfd", "lld", "lld-link", "link.exe", "collect2"}
ASSEMBLE_PROGRAM_BASENAMES = {"as", "llvm-mc"}


def classify_kind(argv: list[str]) -> str:
    if not argv:
        return "other"
    basename = Path(argv[0]).name.lower()
    if basename in LINK_PROGRAM_BASENAMES:
        return "link"
    if basename in ASSEMBLE_PROGRAM_BASENAMES:
        return "assemble"
    if "-cc1" in argv or "-cc1as" in argv:
        # -cc1 with -emit-obj is doing compile+assemble in one (the
        # integrated assembler); -cc1as specifically is the assemble step
        # when the integrated assembler is invoked as a distinct pass.
        return "assemble" if "-cc1as" in argv else "compile"
    return "other"


def parse_hash_hash_hash(stderr_text: str) -> list[list[str]]:
    """Parse clang's `-###` stderr output into a list of subprocess argv
    lists, skipping the driver's own banner lines (version/Target/Thread
    model/InstalledDir/"(in-process)")."""
    commands: list[list[str]] = []
    for line in stderr_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith('"'):
            continue
        try:
            argv = shlex.split(stripped)
        except ValueError as e:
            print(f"WARNING: could not shlex-parse -### line, skipping: {stripped[:120]!r} ({e})", file=sys.stderr)
            continue
        if argv:
            commands.append(argv)
    return commands


def run_hash_hash_hash(argv: list[str], cwd: str | None) -> tuple[list[list[str]], str]:
    """Append -### to argv (if not already a -### invocation) and run it.
    Returns (parsed subprocess argv lists, raw stderr) -- never executes
    the real compile/link, per -###'s own documented behavior."""
    call_argv = list(argv)
    if "-###" not in call_argv:
        call_argv.append("-###")
    try:
        result = subprocess.run(
            call_argv, cwd=cwd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"WARNING: -### invocation failed for {call_argv[:3]}...: {e}", file=sys.stderr)
        return [], ""
    return parse_hash_hash_hash(result.stderr), result.stderr


def load_compile_db(path: Path) -> list[dict[str, Any]]:
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        sys.exit(f"{path}: expected a JSON array (standard compile_commands.json shape)")
    return entries


def cdb_entry_argv(entry: dict[str, Any]) -> list[str]:
    if "arguments" in entry and entry["arguments"]:
        return list(entry["arguments"])
    if "command" in entry and entry["command"]:
        return shlex.split(entry["command"])
    return []


def process_compile_db(path: Path, records: list[dict[str, Any]], limit: int | None) -> None:
    entries = load_compile_db(path)
    print(f"Loaded {len(entries)} compile_commands.json entr{'y' if len(entries)==1 else 'ies'} from {path}", file=sys.stderr)
    if limit is not None:
        entries = entries[:limit]
        print(f"--limit set: processing only the first {len(entries)}", file=sys.stderr)

    ok = 0
    for i, entry in enumerate(entries):
        argv = cdb_entry_argv(entry)
        if not argv:
            print(f"WARNING: compile_commands.json entry {i} has no usable 'arguments'/'command', skipping", file=sys.stderr)
            continue
        cwd = entry.get("directory")
        tu = entry.get("file")

        # Record the driver-level command as given, for traceability.
        records.append({
            "kind": classify_kind(argv),
            "stage": "driver",
            "argv": argv,
            "cwd": cwd,
            "tu": tu,
            "source": "compile-db",
        })

        expanded, _raw = run_hash_hash_hash(argv, cwd)
        for sub_argv in expanded:
            records.append({
                "kind": classify_kind(sub_argv),
                "stage": "expanded",
                "argv": sub_argv,
                "cwd": cwd,
                "tu": tu,
                "source": "compile-db",
            })
        if expanded:
            ok += 1
    print(f"Expanded {ok}/{len(entries)} compile-db entries via -###", file=sys.stderr)


def process_link_recipe(path: Path, records: list[dict[str, Any]]) -> None:
    recipe = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(recipe, list):
        sys.exit(f"{path}: expected a JSON array of {{'argv': [...], 'cwd': ...}} records")
    print(f"Loaded {len(recipe)} link-recipe record(s) from {path}", file=sys.stderr)

    ok = 0
    for i, rec in enumerate(recipe):
        argv = rec.get("argv")
        if not argv:
            print(f"WARNING: link-recipe entry {i} has no 'argv', skipping", file=sys.stderr)
            continue
        cwd = rec.get("cwd")

        records.append({
            "kind": classify_kind(argv),
            "stage": "driver",
            "argv": argv,
            "cwd": cwd,
            "tu": None,
            "source": "link-recipe",
        })

        expanded, _raw = run_hash_hash_hash(argv, cwd)
        for sub_argv in expanded:
            records.append({
                "kind": classify_kind(sub_argv),
                "stage": "expanded",
                "argv": sub_argv,
                "cwd": cwd,
                "tu": None,
                "source": "link-recipe",
            })
        if expanded:
            ok += 1
    print(f"Expanded {ok}/{len(recipe)} link-recipe entries via -###", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--compile-db", help="Path to compile_commands.json")
    ap.add_argument("--link-recipe", help="Path to a JSON array of driver-level link commands: [{'argv': [...], 'cwd': '...'}]")
    ap.add_argument("-o", "--output", required=True, help="Output path for build-commands.jsonl")
    ap.add_argument("--limit", type=int, default=None, help="Only process the first N compile_commands.json entries (for a quick smoke test on a large target)")
    args = ap.parse_args()

    if not args.compile_db and not args.link_recipe:
        sys.exit("Give at least one of --compile-db or --link-recipe")

    records: list[dict[str, Any]] = []
    if args.compile_db:
        process_compile_db(Path(args.compile_db), records, args.limit)
    if args.link_recipe:
        process_link_recipe(Path(args.link_recipe), records)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    by_kind: dict[str, int] = {}
    for r in records:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    print(f"Wrote {out_path} -- {len(records)} record(s) ({by_kind})", file=sys.stderr)
    print("Next: extract_vendor_candidates.py --build-commands "
          f"{out_path} --repo-root <target repo root> -o <native-vendor-candidates.json>", file=sys.stderr)


if __name__ == "__main__":
    main()
