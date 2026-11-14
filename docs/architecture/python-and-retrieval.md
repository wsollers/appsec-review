---
title: "Python and retrieval architecture"
kind: "architecture"
subsystem: "runtime interchange"
status: "current"
jobs: []
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Python and retrieval architecture

Retrieval is a core application capability. Producers publish immutable, independently
fingerprinted SQLite/FTS shards; application jobs call `appsec_review.retrieval` directly; the
`appsec_review.mcp` package is only a read-only transport and authorization adapter. Review cells do not
use that transport: see [`retrieval-surfaces.md`](retrieval-surfaces.md) for which consumer reaches the
retrieval core how.

## Accepted index sets

The closed index-name vocabulary is `INDEX_NAMES` in
[`retrieval/index.py`](../../src/appsec_review/retrieval/index.py). Physical identity is the
composite `(logical name, shard_id)`: different producers or bounded scopes can publish separate
shards without a global index-build barrier. Each shard declares its own fingerprint and source
identity. The exact fingerprint inputs and reuse unit are producer-specific, not a guarantee
that every producer binds the same set of settings or artifacts.

The [generated inventory](../generated/inventory.json) is the declaration map for indexes,
datasets and retrieval routes. The [code-intelligence dive](code-intelligence.md),
[scanner dive](scanners-and-evidence-collection.md) and
[canonical job pages](../operations/README.md) explain actual production and invalidation.
These replace a second hand-maintained producer inventory here. In particular, artifact
indexing has both admitted catalog/source inputs and build-produced inputs; it is not restricted
to one language-build handoff.

An accepted manifest verifies and composes physical shard identities and upstream references.
It does not prove that every declared producer ran, every language is covered or every artifact
is queryable. Raw/protected payloads and sanitized inventory metadata have distinct access
boundaries. Producer-local coverage and canonical outcomes must be inspected together; an empty
query is not a clean-coverage result.

`runs/<run-id>/data/indices/accepted.json` binds one manifest to an accepted job handoff. Before
opening a database, retrieval verifies the pointer, handoff status and hash, manifest membership in
the handoff artifact list, manifest content hash, each shard hash, and each shard's embedded schema,
name, and fingerprint. SQLite is opened read-only with immutable mode. Missing, corrupt, stale, or
incomplete inputs are gaps or integrity failures, never an empty-result proof that the target is
clean.

An attempt can instead use its claim-bound input manifest through
[`resolve_context_manifest`](../../src/appsec_review/retrieval/core.py). It verifies that
manifest's retained path and digest rather than silently switching to a newer accepted pointer.
The helper falls back to the accepted-pointer path only when the context has no manifest pin;
the applicable [input contract](job-input-contracts.md) still governs runtime reads.

## Identity and location contract

Logical identities are versioned hashes of entity kind, target snapshot and producer-native
identity. `EntityKind` and `RelationKind` in
[`retrieval/model.py`](../../src/appsec_review/retrieval/model.py) own the closed vocabularies.
Relations preserve exactness or explicit ambiguity; a shared graph format does not turn a
heuristic association into proof.

A resolving source location binds the target snapshot, normalized relative path, file hash,
byte/line/column span, producer-native location, mapping method, confidence, and ambiguity.
Heuristic relationships must be marked non-exact and carry an ambiguity explanation.
Locations can be absent; not every normalized entity is a source span.
[`read_source_bytes`](../../src/appsec_review/retrieval/source_resolution.py) verifies the
appropriate source domain: target files are re-hashed, generated source requires its accepted
backing and detached-object identity, and binary pseudo-source requires its separate accepted
backing. Missing, changed or invalid backing fails explicitly instead of becoming a guessed path.

## Query boundary

The common public surface includes `search`, `find`, `read_excerpt`, `trace`,
`resolve_evidence`, `coverage`, `query_artifacts`, and `query_build_security`, with bounded
domain-specific query tools where an accepted producer publishes those shards. The MCP process is pinned at startup to one run and optionally
one exact manifest hash. It has no shell, write, glob, grep, arbitrary SQL, arbitrary regular
expression, or caller-supplied filesystem-path operation.

`query_artifacts` is the single cross-language artifact query. It uses parameterized exact filters
over accepted artifact and evidence shards and never exposes raw bytes or protected producer
streams. Catalog, member, relationship, observation, and vulnerability shards remain independently
identified in responses; absent, stale, partial, corrupt, or unavailable coverage cannot be
collapsed into a clean result. Artifact relationships reuse the canonical typed graph, so build
actions, source/build units, containment, package membership, linked artifacts, observations, and
CVE evidence preserve exactness or explicit ambiguity rather than being inferred by the adapter.

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
