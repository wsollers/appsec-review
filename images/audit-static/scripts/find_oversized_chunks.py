#!/usr/bin/env python3
"""
find_oversized_chunks.py — diagnostic for build_semantic_index.py.

2026-09-08: written after a real run against fsh-server showed slice
[500:1000] balloon to 28.57GB/31.19GB memory and 2337% CPU on a single
500-chunk batch, after slice [0:500] had run cleanly at 170MB. Since each
--start/--limit slice already runs as its own fresh process (the fix
already shipped for the earlier ONNX-arena-growth OOM), a single slice
ballooning like that pointed at a DIFFERENT problem. Initial hypothesis (one
pathologically long single LINE forcing a quadratic attention blowup) was
run through this script against the real repo and DISPROVEN by the actual
data: the worst single line in that slice was 281 characters — unremarkable
for code. What this script's real output DID surface: a handful of unusually
large TOTAL chunks (up to 26,898 characters, from WOD's
Configuration/ControllerHtml.cs — generated-looking HTML-table "TableRaw"
render methods that hit the MAX_CHUNK_LINES=200 line cap with long lines
throughout, not one outlier line). The revised, evidence-based theory:
fastembed/ONNX Runtime pads every sequence in a batch to the length of the
LONGEST sequence in that batch before running self-attention (whose cost
scales roughly with batch_size * sequence_length^2) — so a handful of these
large chunks landing in the same --batch-size=64 batch would drag every
other, otherwise-ordinary chunk in that batch up to the same huge padded
length, multiplying the quadratic cost across the whole batch. This is why
this script ranks by chunk_chars (total chunk size) in addition to
max_line_chars (kept for completeness/future cases, but was not the actual
culprit here) — build_semantic_index.py was fixed accordingly with a new
MAX_CHUNK_CHARS cap; see that file's own docstring for the fix.

This script reads the exact same <file>.json output from build_symbol_index.py
that build_semantic_index.py reads, and reproduces its iter_chunks() logic
so the chunk ordering and 0-based chunk index reported here line up exactly
with build_semantic_index.py's own --start/--limit slicing scheme. That means
"chunk index 733" reported by this script is the SAME chunk
build_semantic_index.py would process at position 733 in a full (non-sliced)
run, and falls inside whichever --start slice range you're currently
debugging. ONE DELIBERATE DIVERGENCE from build_semantic_index.py's copy,
as of its MAX_CHUNK_CHARS fix: this script's iter_chunks() does NOT apply
that cap, so chunk_chars/max_line_chars reported here are the RAW,
pre-truncation sizes — that's the whole point of a diagnostic meant to find
what needs truncating in the first place. The cap only truncates chunk TEXT
and doesn't change which chunks are yielded or their order/count, so the
chunk indices still line up correctly despite this one difference; if
build_semantic_index.py's chunking logic changes in any OTHER way (new
skip conditions, different chunk boundaries, etc.), mirror that change here
too or the indices will drift.

This is read-only and does not touch Docker, the LanceDB table, or the
embedding model - it only reads JSON + source files already on disk, so it's
safe to run as many times as you like while narrowing down offending chunks.

Usage:
    python3 find_oversized_chunks.py /path/to/repo /evidence/symbol-index \\
        [--top N] [--min-line-chars N] [--min-chunk-chars N] \\
        [--slice-start N --slice-limit N] [--json-out FILE]

Run it the same way you'd run build_semantic_index.py - either directly with
a host Python 3 (stdlib only, no dependencies), or via the toolbox image
(which already has python3) with this file bind-mounted alongside the
existing repo/evidence mounts:

    docker run --rm \\
        -v <RepoPath>:/workspace:ro \\
        -v <EvidencePath>:/evidence \\
        -v <path-to-this-file>:/opt/scripts/find_oversized_chunks.py:ro \\
        vendor-audit-toolbox:latest \\
        python3 /opt/scripts/find_oversized_chunks.py /workspace /evidence/symbol-index --top 30
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator

MAX_CHUNK_LINES = 200  # kept identical to build_semantic_index.py - do not change independently of that file


def iter_chunks(repo_root: Path, index_dir: Path) -> Iterator[dict[str, Any]]:
    """Copied verbatim from build_semantic_index.py so chunk ordering (and
    therefore the 0-based chunk index this script reports) matches exactly.
    Do not "improve" this independently - if build_semantic_index.py's
    chunking logic ever changes, copy the change here too or the chunk
    indices reported by this script will silently stop lining up."""
    for json_path in index_dir.rglob("*.json"):
        if json_path.name in ("index.json", "summary.json"):
            continue
        try:
            record = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"WARNING: could not read {json_path}: {e}", file=sys.stderr)
            continue

        rel_path = record.get("path")
        language = record.get("language")
        if not rel_path or not language:
            continue

        src_path = repo_root / rel_path
        if not src_path.exists():
            continue
        try:
            lines = src_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        defs = sorted(
            record.get("definitions", []) + record.get("classes", []),
            key=lambda d: d["line"],
        )
        if not defs:
            continue

        for i, d in enumerate(defs):
            start = d["line"]
            end = defs[i + 1]["line"] - 1 if i + 1 < len(defs) else min(len(lines), start + MAX_CHUNK_LINES)
            end = min(end, start + MAX_CHUNK_LINES, len(lines))
            if end < start:
                end = start
            chunk_lines = lines[start - 1:end]
            text = "\n".join(chunk_lines).strip()
            if not text:
                continue
            yield {
                "id": f"{rel_path}:{start}-{end}:{d['name']}",
                "path": rel_path,
                "language": language,
                "definition_name": d["name"],
                "start_line": start,
                "end_line": end,
                "text": text,
            }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path, help="Repository root (same one passed to build_semantic_index.py)")
    ap.add_argument("index_dir", type=Path, help="Output directory build_symbol_index.py wrote to")
    ap.add_argument("--top", type=int, default=25, help="How many top offenders to print per ranking (default 25)")
    ap.add_argument("--min-line-chars", type=int, default=2000,
                     help="Flag a chunk if any single line inside it is at least this many characters (default 2000)")
    ap.add_argument("--min-chunk-chars", type=int, default=20000,
                     help="Flag a chunk if its total character count is at least this many (default 20000)")
    ap.add_argument("--slice-start", type=int, default=None,
                     help="Only report chunks with global index >= this (matches build_semantic_index.py --start)")
    ap.add_argument("--slice-limit", type=int, default=None,
                     help="Combined with --slice-start, only report chunks in [slice-start, slice-start+slice-limit)")
    ap.add_argument("--json-out", type=Path, default=None,
                     help="Optional: write the full flagged-chunk list as JSON to this path (for later "
                          "truncation/exclusion tooling)")
    args = ap.parse_args()

    repo_root = args.repo.resolve()
    all_chunks = list(iter_chunks(repo_root, args.index_dir))
    total = len(all_chunks)
    print(f"Read {total} total chunk(s) from {args.index_dir} (compare against build_semantic_index.py's own "
          f"index.json 'total_chunks_available' - these two numbers must match, or this script's chunk ordering "
          f"has drifted from the real one and its chunk indices below are not trustworthy).", file=sys.stderr)

    slice_lo = args.slice_start if args.slice_start is not None else 0
    slice_hi = (slice_lo + args.slice_limit) if (args.slice_start is not None and args.slice_limit is not None) else total

    rows = []
    for idx, c in enumerate(all_chunks):
        if idx < slice_lo or idx >= slice_hi:
            continue
        text = c["text"]
        chunk_chars = len(text)
        line_lens = [len(l) for l in text.split("\n")]
        max_line_chars = max(line_lens) if line_lens else 0
        flagged = (max_line_chars >= args.min_line_chars) or (chunk_chars >= args.min_chunk_chars)
        rows.append({
            "chunk_index": idx,
            "id": c["id"],
            "path": c["path"],
            "definition_name": c["definition_name"],
            "start_line": c["start_line"],
            "end_line": c["end_line"],
            "chunk_chars": chunk_chars,
            "max_line_chars": max_line_chars,
            "flagged": flagged,
        })

    flagged_rows = [r for r in rows if r["flagged"]]
    print(f"\nScanned chunk index range [{slice_lo}, {slice_hi}) — {len(rows)} chunk(s), "
          f"{len(flagged_rows)} flagged (max_line_chars >= {args.min_line_chars} "
          f"or chunk_chars >= {args.min_chunk_chars}).\n", file=sys.stderr)

    def _print_table(title: str, sorted_rows: list[dict]) -> None:
        print(f"=== {title} (top {min(args.top, len(sorted_rows))}) ===")
        print(f"{'chunk_idx':>9}  {'chunk_chars':>11}  {'max_line_chars':>14}  path (definition_name @ start_line-end_line)")
        for r in sorted_rows[:args.top]:
            print(f"{r['chunk_index']:>9}  {r['chunk_chars']:>11}  {r['max_line_chars']:>14}  "
                  f"{r['path']} ({r['definition_name']} @ {r['start_line']}-{r['end_line']})")
        print()

    _print_table("Top offenders by MAX SINGLE-LINE length (the likely quadratic-blowup trigger)",
                 sorted(rows, key=lambda r: r["max_line_chars"], reverse=True))
    _print_table("Top offenders by TOTAL CHUNK character count",
                 sorted(rows, key=lambda r: r["chunk_chars"], reverse=True))

    if flagged_rows:
        print(f"{len(flagged_rows)} chunk(s) in the scanned range exceed the flag thresholds. These are the "
              f"prime suspects for the OOM/CPU spike - especially any whose path lives under a vendor/generated "
              f"directory (e.g. 'vendor/', '/gen/', 'protobuf', 'node_modules').", file=sys.stderr)
    else:
        print("No chunk in the scanned range exceeded the flag thresholds - the oversized-single-line theory may "
              "not be the (whole) explanation here; consider re-running with lower --min-line-chars/--min-chunk-chars, "
              "or that something else (e.g. a genuinely huge cluster of merely-large chunks, or an unrelated "
              "resource issue) is responsible.", file=sys.stderr)

    if args.json_out:
        args.json_out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"\nWrote full per-chunk data for the scanned range to {args.json_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
