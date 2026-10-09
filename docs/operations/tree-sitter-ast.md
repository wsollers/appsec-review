# Tree-sitter AST operations

Build `appsec-review/tool-tree-sitter:1.0.0` only after acquiring the ignored Linux asset cache as
documented in `containers/tools/tree-sitter/README.md`. The build must use the tracked
`assets.lock.json`, the digest-pinned base, `--pull=false`, `--network none`, and
`--provenance=false`. Record the final local image ID in `containers/catalog.toml` before running
the job.

The standalone `tree_sitter_ast` Dagster job is the manual dispatch path. In the review graph it
runs after accepted intake/catalog planning and independently from build, compiled AST/IR, SAST,
and inference branches. CodeQL waits for its accepted handoff before composing the later retrieval
view. Dagster maps accepted scopes concurrently; application receipts, immutable shards, the
accepted handoff, and the central run log remain authoritative.

For recovery, inspect scope dispositions in the accepted Tree-sitter artifact and central pipeline
log. Rerunning a partial attempt reuses hash-verified successful scope shards and retries failed or
invalidated scopes. Do not delete locks, edit accepted pointers, or remove successful shards to
force recovery. An unsupported grammar or bounded parse is a named gap, not clean coverage.

Live acceptance must verify the cataloged image ID, run with network disabled and the target mounted
read-only, parse the multi-project/multi-language fixture, publish at least one searchable AST shard,
and demonstrate that an injected sibling grammar failure produces `COMPLETED_WITH_GAPS` while the
successful shard remains accepted.
