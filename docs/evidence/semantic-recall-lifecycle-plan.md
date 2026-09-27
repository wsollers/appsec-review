# LanceDB semantic recall lifecycle plan

The repository already contains a working legacy LanceDB path in
`images/audit-static*/scripts/build_semantic_index.py` and `query_semantic_index.py`. It embeds
bounded source-definition chunks and ranks them by vector similarity. It is not the accepted
full-text index: the run-owned SQLite FTS5 index remains lexical retrieval authority.

The registered `semantic-recall-index` contract preserves that implementation without promoting
it prematurely. The lifecycle worker remains deliberately `implemented: false` until it can:

1. consume only accepted source, symbol, Joern CPG, and IR-fact generations;
2. use a preseeded embedding model pinned by artifact hash with analysis-time network disabled;
3. redact before embedding, enforce the closed row/chunk/result limits, and atomically retain a
   closed LanceDB tree manifest;
4. publish through an immutable attempt, common envelope, `accepted.json`, exact permission and
   lineage receipts, and newest-failure blocking; and
5. return locator candidates only. Every selected hit must be dereferenced against accepted source
   bytes or an accepted producer record before it can support a report claim. Vector distance is
   never evidence, severity, or reachability.

The existing legacy scripts must not be removed while this worker is built. Their first-use model
download behavior is incompatible with the accepted offline boundary, so they cannot be registered
as-is.
