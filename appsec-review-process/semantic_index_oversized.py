#!/usr/bin/env python3
"""Oversized-chunk diagnostic for ``02-semantic-recall-index`` (moved from the legacy
``images/audit-static*/scripts/find_oversized_chunks.py``).

2026-09-08 history, kept: a legacy run against fsh-server ballooned one 500-chunk slice to
28.57 GB / 2337% CPU. The single-long-line theory was disproven (worst line 281 chars); the cause was
a handful of very large TOTAL chunks (up to 26,898 chars, generated "TableRaw" HTML renderers in
WOD's Configuration/ControllerHtml.cs) padding whole embedding batches. ``MAX_CHUNK_CHARS`` in
``semantic_index_build.py`` is the fix; this script ranks chunks by raw (pre-truncation) size so
the next such outlier is found from evidence, not guessed.

It no longer re-derives chunks itself (the legacy copy of ``iter_chunks`` had to be kept in step by
hand): it reads ``semantic-recall-chunks.jsonl``, the locator sidecar the worker publishes with each
attempt, whose rows carry ``raw_chars`` and ``max_line_chars`` measured before redaction and
truncation, and whose ``row_id`` is the row's position in the embedding plan. Read-only; stdlib only.

    python3 -B appsec-review-process/semantic_index_oversized.py \\
        <run>/data/jobs/02-semantic-recall-index/attempts/<attempt_id> --top 30
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SIDECAR = "semantic-recall-chunks.jsonl"


def rows(attempt: Path) -> list[dict[str, Any]]:
    with (Path(attempt) / SIDECAR).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def flagged(items: list[dict[str, Any]], min_line_chars: int, min_chunk_chars: int) -> list[dict[str, Any]]:
    return [row for row in items if row["max_line_chars"] >= min_line_chars or row["raw_chars"] >= min_chunk_chars]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attempt", type=Path, help="published 02-semantic-recall-index attempt directory")
    ap.add_argument("--top", type=int, default=25, help="how many top offenders to print per ranking (default 25)")
    ap.add_argument("--min-line-chars", type=int, default=2000, help="flag a chunk with a line at least this long")
    ap.add_argument("--min-chunk-chars", type=int, default=20000, help="flag a chunk at least this long in total")
    ap.add_argument("--json-out", type=Path, default=None, help="write the flagged rows as JSON to this path")
    args = ap.parse_args(argv)
    items = rows(args.attempt)
    print(f"Read {len(items)} chunk(s) from {args.attempt / SIDECAR}.", file=sys.stderr)

    def table(title: str, key: str) -> None:
        ranked = sorted(items, key=lambda row: row[key], reverse=True)[:args.top]
        print(f"=== {title} (top {len(ranked)}) ===")
        print(f"{'row_id':>8}  {'raw_chars':>9}  {'max_line_chars':>14}  file (symbol @ start_line-end_line)")
        for row in ranked:
            print(f"{row['row_id']:>8}  {row['raw_chars']:>9}  {row['max_line_chars']:>14}  "
                  f"{row['file']} ({row['symbol']} @ {row['start_line']}-{row['end_line']})")
        print()

    table("Top offenders by MAX SINGLE-LINE length", "max_line_chars")
    table("Top offenders by TOTAL CHUNK character count", "raw_chars")
    hits = flagged(items, args.min_line_chars, args.min_chunk_chars)
    print(f"{len(hits)} chunk(s) exceed the flag thresholds (embedded text is capped either way; "
          f"look for vendor/generated paths).", file=sys.stderr)
    if args.json_out:
        args.json_out.write_text(json.dumps(hits, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
