#!/usr/bin/env python3
"""
query_semantic_index.py — query the LanceDB table built by
build_semantic_index.py. Prints the top-N matching code chunks for a plain
-language query, for use as evidence to attach to a Phase 4 ASVS-assessment
prompt (or Phase 1B vendor-trust triage, or Phase 6 dedup) instead of
hand-selecting files.

Usage:
    python3 query_semantic_index.py /evidence/semantic-index \\
        "session token generation and validation" --limit 10

    # filter to one language / component before ranking:
    python3 query_semantic_index.py /evidence/semantic-index \\
        "IAP receipt validation" --language csharp --limit 10

    # emit JSON instead of a human-readable listing, to pipe straight into
    # an LLM prompt as an attachment:
    python3 query_semantic_index.py /evidence/semantic-index \\
        "unvalidated client-supplied currency balance" --json > evidence.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import lancedb
    from fastembed import TextEmbedding
except ImportError:
    sys.exit(
        "This script requires lancedb + fastembed:\n"
        "  pip install lancedb fastembed --break-system-packages"
    )

DEFAULT_MODEL = "jinaai/jina-embeddings-v2-base-code"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("index_dir", type=Path, help="LanceDB directory built by build_semantic_index.py")
    ap.add_argument("query", help="Natural-language or code-shaped query")
    ap.add_argument("--table", default="chunks")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                     help="Must match the model build_semantic_index.py used — mixing embedding models gives meaningless distances")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--language", help="Restrict to one language (e.g. cpp, csharp, python, go, php)")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human-readable listing")
    args = ap.parse_args()

    db = lancedb.connect(str(args.index_dir))
    if args.table not in db.table_names():
        sys.exit(f"No table '{args.table}' in {args.index_dir} — run build_semantic_index.py first.")
    table = db.open_table(args.table)

    model = TextEmbedding(model_name=args.model)
    query_vec = list(model.embed([args.query]))[0].tolist()

    search = table.search(query_vec).limit(args.limit)
    if args.language:
        search = search.where(f"language = '{args.language}'")
    results = search.to_list()

    if args.json:
        # Strip the raw vector back out — it's dead weight in an LLM prompt attachment.
        for r in results:
            r.pop("vector", None)
        print(json.dumps(results, indent=2))
        return

    print(f"Top {len(results)} match(es) for: {args.query!r}\n")
    for r in results:
        dist = r.get("_distance")
        print(f"[{dist:.4f}] {r['path']}:{r['start_line']}-{r['end_line']}  ({r['language']}, {r['definition_name']})")
        preview = r["text"].splitlines()
        for line in preview[:6]:
            print(f"    {line}")
        if len(preview) > 6:
            print(f"    ... ({len(preview) - 6} more lines)")
        print()


if __name__ == "__main__":
    main()
