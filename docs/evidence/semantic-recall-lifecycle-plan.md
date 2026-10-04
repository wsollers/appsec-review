# LanceDB semantic recall lifecycle

`02-semantic-recall-index` (`appsec-review-process/semantic_recall_index.py`) is the run-owned
semantic recall producer. It replaces the legacy pre-pass scripts
`images/audit-static*/scripts/build_semantic_index.py`, `query_semantic_index.py`,
`run-semantic-index-batched.sh` and `find_oversized_chunks.py`, which were ported into
`semantic_index_build.py` (in-container builder) and `semantic_index_oversized.py` (diagnostic) and
deleted. It is not the full-text index: the run-owned SQLite FTS5 index (`02-evidence-index`) remains
lexical retrieval authority.

What the worker guarantees:

1. It consumes only the accepted `02-code-index` of the current source generation (pointer, envelope,
   attempt tree and database hashes) and binds the code index, CPG and IR-fact generations in its
   manifest. One chunk per distinct function span from `methods`/`ts_functions`; chunk bounds are the
   span. A file whose bytes differ from the hash the code index recorded is a `source-changed` gap.
2. The embedding model is preseeded and pinned by per-file sha256 and artifact hash in
   `data/embedding-models/jina-embeddings-v2-base-code.json`, fetched once per host into
   `data/feeds/embedding-models/` with
   `python3 -B appsec-review-process/semantic_recall_index.py fetch-model --revision <commit> [--pin]`.
   An unpinned, missing or mismatched model BLOCKS the job before any container runs; the container
   (network none) loads the model from a read-only mount (`specific_model_path`) and re-hashes it.
3. Every chunk passes the evidence redactor before embedding and is capped at 4000 chars (the
   locator keeps the full span); at most 200000 rows. Truncation, redactor withholds, unknown spans,
   missing or oversized files, the row cap and upstream code-index gaps are coverage gaps.
4. It publishes through an immutable attempt with the common envelope, `accepted.json`, permission
   and lineage receipts and newest-failure blocking. Validation re-derives the chunk plan from the
   bound inputs and re-hashes the LanceDB tree.
5. `semantic_recall_index.query(index_root, text, *, limit)` returns at most 100 locators
   `{file, start_line, end_line, symbol, score}`. `dereference` reads the cited lines only while the
   file still matches the indexed bytes. Vector distance is a ranking hint, never evidence,
   severity, or reachability.

Open: the image that runs the builder (`image_id` tunable, default `audit-static`) installs lancedb
and fastembed unpinned and is not yet a B16-registered image; a dedicated pinned tool image is the
intended home. Until it is registered the job BLOCKS with "has no current B16 record".
