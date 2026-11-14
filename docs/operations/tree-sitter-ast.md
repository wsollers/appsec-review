---
title: "Tree-sitter AST operations"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Tree-sitter AST operations

Build `appsec-review/tool-tree-sitter:1.0.0` only after acquiring the ignored Linux asset cache as
documented in `containers/tools/tree-sitter/README.md`. The build must use the tracked
`assets.lock.json`, the digest-pinned base, `--pull=false`, `--network none`, and
`--provenance=false`. Record the final local image ID through the host-owned pin workflow,
not in the recipe catalog; see [image-pin verification](image-pin-verification.md).

A rebuilt offline image from this context supports C, C++, C#, Go, Java, JavaScript, Kotlin, PHP,
PowerShell, Python, Ruby, Rust, Shell, TSX, and TypeScript. Shell files use the hash-locked upstream Bash grammar.
Swift and any other cataloged language without a lock remain explicit `UNAVAILABLE`
dispositions; operators must not interpret those gaps as clean coverage.

The standalone `tree_sitter_ast` Dagster job is the manual dispatch path. In the review graph it
runs from admitted intake/catalog inputs, with an admitted language-build lane for generated
sources when available. It does not consume compiled AST/IR, SAST or inference results.
Enabled scheduling follows the typed contracts, not an unconditional claim of independence from
language builds. The [canonical job page](job_tree_sitter_ast.md) supplies the generated input
and placement declarations. CodeQL waits for its accepted handoff before composing the later retrieval
view. Dagster maps accepted scopes concurrently; application receipts, immutable shards, the
accepted handoff, and the central run log remain authoritative.

For recovery, inspect scope dispositions in the accepted Tree-sitter artifact and central pipeline
log. Rerunning a partial attempt reuses hash-verified successful scope shards and retries failed or
invalidated scopes. Do not delete locks, edit accepted pointers, or remove successful shards to
force recovery. An unsupported grammar or bounded parse is a named gap, not clean coverage.

For source-only navigation, call `query_syntax` with an accepted `source_file` identity and mode
`definitions`, `calls`, `imports` or `references`; optionally filter an exact written `name`.
Pass a returned AST identity to `read_excerpt`, or as a syntax subject to narrow to that node's
span. Package source-file grants work even without a CodeQL database. The tool reads accepted
`analysis` shards only. Projection coverage is separately partial (explicit syntax subsets) or
unavailable; raw AST parse completeness never means resolved calls or exhaustive symbols.
The host adds projections using existing pinned grammar output, so no grammar/image rebuild or
new asset pin is required. Swift stays unavailable; PowerShell and Shell currently expose raw AST
only. Reusing an old scope fingerprint cannot skip the new projection version.

Live acceptance must verify the frozen host-bound image ID, run with network disabled and the target mounted
read-only, parse the multi-project/multi-language fixture, publish at least one searchable AST shard,
and demonstrate that an injected sibling grammar failure produces `COMPLETED_WITH_GAPS` while the
successful shard remains accepted.

If every runnable scope reports container exit 1, inspect a scope's protected raw stderr. A
`PermissionError` for `/scratch/request.json` indicates a stale producer that did not make the
atomic request readable by the effective application/container UID. Current producers set the scope directory to `0733` and the
completed request to `0644` before starting the network-disabled container. Keeping the owner-write
bit avoids Docker Desktop input/output errors caused by Windows read-only file attributes while the
container user still has read-only access.
