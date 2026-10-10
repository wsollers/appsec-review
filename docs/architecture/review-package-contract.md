# Pre-adjudication review packages

The sole machine-readable contract is [review-packages.schema.json](../schemas/review-packages.schema.json),
version `appsec-review/review-package/1`. It defines `finding_lead` and `hunt` packages. Reported
scanner severity orders review; it is not an adjudicated technical severity. The separate
post-adjudication finding package is defined in [inference security review](inference-security-review.md).

## Accepted inputs and deterministic assembly

`appsec_review.review_packages` resolves the accepted index pointer and verifies the manifest,
source snapshot and every physical shard through `RetrievalCore`. It reads the accepted
`scanner_correlation` lead, menu and audit facts directly from the pinned precomputed shard.
Worker-facing MCP pagination is not used for exhaustive assembly. Each accepted source-SAST
observation gets exactly one finding-lead package. The producer's High/Critical and unknown menus
become bounded hunt partitions. Suppressed, duplicate and ambiguous-location leads retain their
original observation identity and state.

Package identity is the SHA-256 of canonical package content excluding `package_id`. It includes
the accepted manifest, sorted upstream shard identities, rule version, partition and lead identities.
The run-owned package manifest records package hashes, accepted input hash, counts and gaps.
Reassembly from the same accepted inputs is byte-identical. A changed accepted shard invalidates
the manifest and package identities. `verify_review_packages` checks manifest and package bytes
before consumption; a mismatch blocks use.

The validator requires all accepted lead IDs in finding-lead packages exactly once and every
High/Critical and unknown lead in a hunt menu. It rejects invented menu IDs, cross-component
members, duplicate membership and disagreement with the accepted scanner-correlation audit.
Coverage from accepted shards is copied as named gaps. Missing scanner-correlation facts or an
audit failure block package publication rather than producing a clean empty menu.

The schema carries typed metric vectors, evidence provenance, safe ordered build commands and
classified environment facts. The assembler joins accepted metric vectors and safe build-action
facts by exact source path. A missing source match becomes a named gap; empty vectors must not be
interpreted as zero measurements or a safe build. The package carries bounded retrieval grants,
not raw source, argv, environment values or scanner output. The current join is path-scoped and
does not prove a build action caused a particular observation.

## Worker access

`ScopedRetrievalMcpAdapter` verifies an HMAC capability on every call. The grant binds run and
accepted manifest, package ID and hash, role, round, expiry, permitted tools, indexes, query sets,
entity IDs and page bounds. It admits only exact-identity `find`, `read_excerpt`, and
subject-scoped `query_precomputed`. It denies all other MCP tools. Cursor signatures
bind the capability and query, so a cursor cannot be reused across packages or queries. Results
with an entity identity outside the grant are rejected. The unrestricted
`RetrievalMcpAdapter` remains an operator interface and must not be given to review workers.

The current slice does not start red, blue or verifier workers. A later inference handoff must
project separate role views, seal blind-verifier output, and independently verify consequential
claims before adjudication. It must refine build-action links beyond exact source-path matching.
