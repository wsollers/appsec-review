# Python and retrieval architecture

Retrieval is a core application capability. Producers publish immutable, independently
fingerprinted SQLite/FTS shards; application jobs call `appsec_review.retrieval` directly; the
`appsec_review.mcp` package is only a read-only transport and authorization adapter.

## Accepted index sets

One run may contain source, observations, components, build, compiled, analysis, and evidence
shards. A producer rebuilds only the shards whose fingerprints change. A fingerprint binds the
target snapshot, producer artifacts, tool/image/rule identity, parser and normalizer identities,
mapping implementation, schema, and upstream manifests. Thus an observation change does not
invalidate an unrelated compile or AST shard, while a composed evidence index or finding package
can include the observation manifest as an upstream dependency.

The current catalog job produces source, component, build, and bounded declaration-analysis
shards. Static evidence collection builds one observations shard per producer as soon as that
producer is normalized. Physical identity is the composite `(logical name, shard_id)`, so Gitleaks,
Semgrep, Syft, Checkov, and every other configured producer can publish independently without a
global index-build barrier. The final manifest only verifies receipts and shard hashes and composes
them with the accepted catalog manifest. A shard is inference authority only after that manifest is
bound to an accepted handoff. Later CodeQL/IR branches use the same contract and may overlap
unrelated scanners and indexers.

The target analysis planner adds a separately fingerprinted `analysis` shard with shard id
`target-analysis-plan`. It indexes accepted component routing, scanner reasons, and non-executable
build topology. The shard keeps the catalog manifest as an explicit upstream and is queryable by
the existing bounded `search`, `find`, `trace`, and `coverage` MCP filters; no filesystem search or
new write-capable interface is exposed.

The C++ compiled-analysis job adds one physical build shard, Clang AST shard, LLVM IR shard,
CodeQL-observation shard, Joern-observation shard, and binary/symbol shard per accepted case. A
blocked producer still publishes an unavailable-coverage shard with zero observations, so absence
cannot be mistaken for clean coverage. Compile and linker relationships that lack an exact output
map are explicitly non-exact and carry their ambiguity reason.

`runs/<run-id>/data/indices/accepted.json` binds one manifest to an accepted job handoff. Before
opening a database, retrieval verifies the pointer, handoff status and hash, manifest membership in
the handoff artifact list, manifest content hash, each shard hash, and each shard's embedded schema,
name, and fingerprint. SQLite is opened read-only with immutable mode. Missing, corrupt, stale, or
incomplete inputs are gaps or integrity failures, never an empty-result proof that the target is
clean.

## Identity and location contract

Logical identities are versioned hashes of entity kind, target snapshot, and producer-native
identity. Supported kinds are source files and spans, symbols, components, projects, build actions,
compile units, objects, libraries, executables, AST nodes, IR entities, tool observations, evidence
artifacts, and finding packages. Relations use the fixed vocabulary `DECLARES`, `DEFINES`,
`REFERENCES`, `CALLS`, `CONTAINS`, `GENERATED_FROM`, `COMPILES_TO`, `LINKS_INTO`, `DEPENDS_ON`,
`OBSERVED_AT`, `DERIVED_FROM`, `SUPPORTS`, and `CONTRADICTS`.

A resolving source location binds the target snapshot, normalized relative path, file hash,
byte/line/column span, producer-native location, mapping method, confidence, and ambiguity.
Heuristic relationships must be marked non-exact and carry an ambiguity explanation. Excerpt reads
re-hash the current target file and fail with an explicit gap when it changed after indexing.

## Query boundary

The public surface is six bounded tools: `search`, `find`, `read_excerpt`, `trace`,
`resolve_evidence`, and `coverage`. The MCP process is pinned at startup to one run and optionally
one exact manifest hash. It has no shell, write, glob, grep, arbitrary SQL, arbitrary regular
expression, or caller-supplied filesystem-path operation.

All responses include the run and manifest identity, physical index identities, resolving source
or artifact identity, pagination, coverage gaps, truncation, and duration. Cursors are opaque and
authenticated. Limits cover result count, response bytes, traversal depth, excerpt bytes, and
execution time. Compile/link arguments and environment-like producer payloads are bounded and
redacted before indexing.

Retrieval deterministically fans out over accepted shards sorted by logical name and shard id.
Opaque cursors are bound to the accepted manifest and complete request identity. Coverage reports
shard identities and shard-local gaps, and concurrent readers open every SQLite shard read-only and
immutable.

Every MCP transport call records exactly one `MCP_TOOL_STARTED`/`MCP_TOOL_COMPLETED` pair. Nested
`find`/`trace` work used by `read_excerpt` and `resolve_evidence` is recorded as child
`RETRIEVAL_SUBOP_COMPLETED` spans with the top-level invocation id, so tool-use metrics do not
double-count. Direct core calls retain `RETRIEVAL_QUERY`. Events store hashes, filters, counts,
gaps, truncation, and duration; they never store query or source text.

Keep the adapter in the main package until a distinct privilege boundary, dependency conflict,
independent scaling/restart need, or external versioned consumer is demonstrated.
