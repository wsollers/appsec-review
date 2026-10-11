# Pre-adjudication review packages

The sole machine-readable contract is [review-packages.schema.json](../schemas/review-packages.schema.json),
version `appsec-review/review-package/2`. It defines `finding_lead` and `hunt` packages. Reported
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

`job_review_package_assembly` is the terminal `wave1_review` job. It starts after the accepted
`job_review_data_indexing` handoff and refuses a manifest from another producer. Its publication
unit verifies the complete content-addressed package directory before the job handoff is accepted;
that handoff records the hash of every package file. A later index publication requires a new
package attempt against the new accepted manifest.
The indexing inventory closes before package assembly and audits upstream producers only; it
does not report the future package job as unavailable coverage.

The schema carries typed metric vectors, evidence provenance, safe ordered build commands,
classified environment facts, matching tag assignments, a package-local tag cloud, and Clang
function-declaration references. The assembler resolves a lead to a unique accepted function
span by source path, file hash and line. It includes that function's metric vector plus file-level
metrics, excluding other functions in the same file. A missing or ambiguous span becomes a named
gap. The tag cloud counts only assignments attached to the lead observation or its source file;
it is not the run-wide display cloud. Each tag and Clang reference retains an accepted shard
identity and a retrieval grant.

Build commands are selected only when their safe source-input token names the lead's source
file. Each lead has a binding to its resolved function span and matching build-action IDs; multiple
actions are explicitly ambiguous. A file-level compile command applies to a function through its
source file but does not establish runtime reachability or that a suspected issue is real. The
Clang references identify accepted post-expansion AST declarations when their mapped lines fall
inside the function span. They do not contain a full expanded function body; missing references
are named gaps. The package carries bounded retrieval grants, not raw source, argv, environment
values or scanner output. Empty context must not be interpreted as evidence of safety.

## Worker access

`ScopedRetrievalMcpAdapter` verifies an HMAC capability on every call. The grant binds run and
accepted manifest, package ID and hash, role, round, expiry, permitted tools, indexes, query sets,
entity IDs and page bounds. It admits only exact-identity `find`, `read_excerpt`, and
subject-scoped `query_precomputed`. It denies all other MCP tools. Cursor signatures
bind the capability and query, so a cursor cannot be reused across packages or queries. Results
with an entity identity outside the grant are rejected. The unrestricted
`RetrievalMcpAdapter` remains an operator interface and must not be given to review workers.

The current slice does not start red, blue or verifier workers. Package assembly preserves
suspicions, context and open proof obligations; it does not resolve whether a suspected issue is
real. The red, blue and blind-verifier pools gather and challenge evidence, including applicable
compiled views. Evidence-qualified adjudication then decides the claim state. A later inference
handoff must project separate role views, grant bounded access to accepted compiled evidence,
and seal blind-verifier output before adjudication.
