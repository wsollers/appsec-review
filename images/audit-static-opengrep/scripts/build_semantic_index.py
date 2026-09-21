#!/usr/bin/env python3
"""
build_semantic_index.py — semantic (vector) retrieval layer on top of the
structural tree-sitter index from build_symbol_index.py.

This is the RAG-style complement to build_symbol_index.py, not a
replacement: that script gives you exact definitions and candidate call
sites by name; this one lets you retrieve code by meaning — "session token
handling," "cryptographic key generation," "IAP receipt validation" — when
you don't know the exact identifier the vendor used. Use it to select which
evidence to hand a Phase 4 ASVS-assessment prompt on a codebase too large to
paste in wholesale. Do NOT use it to establish CVE reachability or to cite a
finding directly — semantic similarity is a recall tool, not proof; keep
exact file:line citation on the structural/call-graph side, per the
playbook's evidence discipline.

Pipeline:
  1. Read the per-file JSON that build_symbol_index.py already wrote
     (one <file>.json per source file, containing "definitions" with a
     `name` and starting `line`).
  2. For each definition, slice out its source text as a chunk — from the
     definition's start line to either the next definition's start line or
     a fixed max-line window, whichever comes first (tree-sitter gives exact
     end-of-node byte offsets too; this script uses the cheaper start-line
     heuristic to avoid re-parsing every file a second time here — swap in
     exact node boundaries if you need tighter chunks).
  3. Embed each chunk with an open, code-aware embedding model via
     `fastembed` (default: jinaai/jina-embeddings-v2-base-code — a real,
     currently-available open-weights code embedding model; check the
     current code-retrieval leaderboard before treating this as "the best,"
     that ranking moves — the model name is a CLI flag specifically so you
     can swap it without touching this script).
  4. Store chunk text + metadata (path, language, definition name, line
     range, byte-ish chunk id) + the embedding vector in a LanceDB table —
     an embedded, file-based vector store that lives in your /evidence tree
     next to everything else this pipeline produces, no server required.

Usage:
    pip install lancedb fastembed --break-system-packages

    # 1) build_symbol_index.py must have already run:
    python3 build_symbol_index.py /path/to/repo -o /evidence/symbol-index

    # 2) then:
    python3 build_semantic_index.py /path/to/repo /evidence/symbol-index \\
        -o /evidence/semantic-index --model jinaai/jina-embeddings-v2-base-code

Query afterward with query_semantic_index.py.

Processing a very large chunk set (2026-09-08, updated 2026-09-16):
this script writes each embedded batch to LanceDB as soon as that batch is
produced. Do not reintroduce a whole-run `vectors` accumulator — a real EASTL
run showed the old shape could climb toward Docker's memory limit before the
table write ever happened. Keep --batch-size small first; then use
--start/--limit only if the embedding runtime itself still grows across a
long run and needs fresh process boundaries. The first slice (--start 0, the
default) creates the table fresh; any later slice (--start > 0) appends to
the existing table instead of recreating it.

2026-09-08 (second, independent OOM cause, found via find_oversized_chunks.py
against a real fsh-server run): even with --start/--limit slicing in place
(so the arena-growth issue above is no longer in play), a SINGLE 500-chunk
slice spiked to 28.57GB/31.19GB memory and 2337% CPU on one embedding batch
and had to be stopped manually. find_oversized_chunks.py confirmed the total
chunk count (54855) matched exactly (so its chunk ordering/index is
trustworthy) and found no single pathologically long LINE in that slice
(worst was 281 characters — unremarkable for code) but did find a handful of
unusually large TOTAL chunks (up to 26,898 characters — from WOD's
Configuration/ControllerHtml.cs, generated-looking "TableRaw" HTML-table
render methods that hit the MAX_CHUNK_LINES=200 cap with long lines
throughout, not one outlier line). The mechanism: fastembed/ONNX Runtime
pads every sequence in a batch to the length of the LONGEST sequence in that
batch before running self-attention, whose memory cost scales roughly with
batch_size * sequence_length^2. With the default --batch-size=64, several of
these large ~5,000-27,000-character chunks landed in the same batch,
dragging every other (otherwise ordinary) chunk in that batch up to the same
huge padded length and multiplying the quadratic attention cost across the
whole batch — plausible, order-of-magnitude explanation for a memory spike
that size. MAX_CHUNK_CHARS below is the fix: an independent cap on total
chunk character count (not just line count), so no single definition —
however many lines it spans — can force an entire embedding batch to pad up
to a pathological length. Kept deliberately conservative (well under what
the embedding model's own context window supports) since a chunk exists to
capture ONE definition's semantic gist for retrieval, not to reproduce it
byte-for-byte — the structural/exact-line evidence for any real finding
still comes from build_symbol_index.py's own per-file JSON, never from this
truncated text.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterator

try:
    import lancedb
    from lancedb.index import FTS
    from fastembed import TextEmbedding
except ImportError:
    sys.exit(
        "This script requires lancedb + fastembed:\n"
        "  pip install lancedb fastembed --break-system-packages"
    )

DEFAULT_MODEL = "jinaai/jina-embeddings-v2-base-code"
MAX_CHUNK_LINES = 200  # cap a single definition's chunk length (huge generated functions, minified vendor code)
MAX_CHUNK_CHARS = 4000  # 2026-09-08: independent cap on TOTAL chunk character count, regardless of line count -
                        # see the module docstring's second 2026-09-08 note for the real incident (a batch of
                        # long-but-not-crazy-per-line chunks, up to 26,898 chars each, spiked memory to
                        # 28.57GB/2337% CPU via batch-padding-driven quadratic self-attention cost) and the
                        # reasoning behind this specific value. This truncates the TEXT ONLY - it does not add or
                        # rename any field in the row dict below, so it stays schema-compatible with any table
                        # already partially populated by an earlier run of this script before this fix existed.


def iter_chunks(repo_root: Path, index_dir: Path) -> Iterator[dict[str, Any]]:
    """Read every <file>.json under index_dir and yield one chunk per
    definition (function/method/class), with its source text sliced from
    the actual file on disk."""
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

        # Merge definitions + classes, sorted by line, to compute chunk boundaries.
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
            if len(text) > MAX_CHUNK_CHARS:
                print(
                    f"  truncating oversized chunk {rel_path}:{start}-{end}:{d['name']} "
                    f"({len(text)} chars -> {MAX_CHUNK_CHARS})",
                    file=sys.stderr,
                )
                text = text[:MAX_CHUNK_CHARS]
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
    ap.add_argument("repo", type=Path, help="Repository root (same one passed to build_symbol_index.py)")
    ap.add_argument("index_dir", type=Path, help="Output directory build_symbol_index.py wrote to")
    ap.add_argument("-o", "--output", type=Path, required=True, help="LanceDB directory to create/update")
    ap.add_argument("--table", default="chunks", help="LanceDB table name (default: chunks)")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"fastembed model name (default: {DEFAULT_MODEL})")
    ap.add_argument("--batch-size", type=int, default=64)
    ap.add_argument("--start", type=int, default=0,
                     help="Start processing at this chunk index (0-based). Combine with --limit to process the "
                          "whole chunk set across several fresh process invocations instead of one long-lived "
                          "process — see the module docstring's OOM-mitigation note. Default 0 (start of the list, "
                          "and this slice (re)creates the table).")
    ap.add_argument("--limit", type=int, default=None,
                     help="Process at most this many chunks starting at --start. Omit to process everything from "
                          "--start to the end of the list in one invocation (the default, single-process behavior).")
    args = ap.parse_args()

    repo_root = args.repo.resolve()
    all_chunks = list(iter_chunks(repo_root, args.index_dir))
    if not all_chunks:
        sys.exit(f"No chunks produced from {args.index_dir} — did build_symbol_index.py run against this repo first?")

    total = len(all_chunks)
    end = total if args.limit is None else min(total, args.start + args.limit)
    if args.start < 0 or args.start > total:
        sys.exit(f"--start {args.start} is out of range for {total} total chunk(s).")
    chunks = all_chunks[args.start:end]
    if not chunks:
        sys.exit(f"No chunks in slice [{args.start}:{end}] of {total} total chunk(s) — nothing to do.")

    is_first_slice = args.start == 0
    is_last_slice = end >= total

    print(f"Prepared {len(chunks)} chunk(s) — slice [{args.start}:{end}] of {total} total — from {args.index_dir}",
          file=sys.stderr)
    print(f"Loading embedding model {args.model} (downloads on first use)...", file=sys.stderr)
    model = TextEmbedding(model_name=args.model)

    args.output.mkdir(parents=True, exist_ok=True)
    db = lancedb.connect(str(args.output))

    table = None
    if is_first_slice:
        if args.table in db.table_names():
            db.drop_table(args.table)
    else:
        if args.table not in db.table_names():
            sys.exit(
                f"--start {args.start} > 0 but table '{args.table}' does not exist yet in {args.output} — "
                f"run the first slice (--start 0, or default) before any later slice."
            )
        table = db.open_table(args.table)

    rows_written = 0
    for i in range(0, len(chunks), args.batch_size):
        batch_chunks = chunks[i:i + args.batch_size]
        batch_texts = [c["text"] for c in batch_chunks]
        batch_vectors = [v.tolist() for v in model.embed(batch_texts)]
        rows = [
            {**{k: v for k, v in c.items()}, "vector": vec}
            for c, vec in zip(batch_chunks, batch_vectors)
        ]
        if table is None:
            create_kwargs = {"mode": "overwrite"} if is_first_slice else {}
            table = db.create_table(args.table, data=rows, **create_kwargs)
        else:
            table.add(rows)
        rows_written += len(rows)
        if i % (args.batch_size * 10) == 0:
            print(f"  embedded and wrote {i + len(rows)}/{len(chunks)}...", file=sys.stderr)

    if table is None:
        sys.exit(f"No rows were written for slice [{args.start}:{end}] of {total} total chunk(s).")

    if is_last_slice:
        # Cheap to (re)build once the run's data is settled; safe to call even
        # on a single-invocation (no --start/--limit) run, where is_first_slice
        # and is_last_slice are both true.
        try:
            table.create_index("text", config=FTS())
        except Exception as e:  # pragma: no cover - defensive, not expected in normal operation
            print(f"WARNING: could not (re)build FTS index: {e}", file=sys.stderr)

    row_count = table.count_rows()
    print(
        f"Wrote {rows_written} chunk(s) this run to LanceDB table '{args.table}' at {args.output} "
        f"(table now has {row_count} total row(s))",
        file=sys.stderr,
    )

    # Write/update a small JSON completion summary. This is deliberately NOT
    # the source of truth for querying (query_semantic_index.py still reads
    # the LanceDB table directly) — it exists because this toolbox's
    # orchestrator (Invoke-VendorAuditPrePass.ps1) checks for
    # semantic-index/index.json as this step's ExpectedOutput, and LanceDB
    # itself does not write a file by that name (it writes its own
    # version-dependent .lance data/manifest files instead) — confirmed by
    # reading this script's own table-creation logic above, not assumed.
    # Without this, even a fully successful run would still report
    # outputOk=false. Written after every invocation (including a single,
    # non-sliced run) so the check is satisfied regardless of whether
    # --start/--limit slicing is in use.
    summary_path = args.output / "index.json"
    summary = {
        "table": args.table,
        "output_dir": str(args.output),
        "model": args.model,
        "total_chunks_available": total,
        "rows_written_this_invocation": rows_written,
        "table_row_count_after_this_invocation": row_count,
        "slice_processed": [args.start, end],
        "complete": is_last_slice,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote completion summary to {summary_path}", file=sys.stderr)
    if not is_last_slice:
        print(
            f"NOT complete — {total - end} chunk(s) remaining. Run again with --start {end} "
            f"(and the same --limit, or omit --limit to finish the rest in one more invocation).",
            file=sys.stderr,
        )
    print("Query the table with query_semantic_index.py.", file=sys.stderr)


if __name__ == "__main__":
    main()
