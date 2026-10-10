# Review package and finding-lead contract

Status: implementation contract proposed on local `main` at `3db440f9`; no review-package
assembler, worker scope enforcement, or inference job is implemented here. The locally cached
`origin/design/indexing-query-mcp` ref is `77932f6d` (PR #103 merge, including `f17963d1`).
The local `origin/main` also remains `3db440f9`. A remote check failed because GitHub was
unreachable, so this document does not assert GitHub's current `main` state. Reconcile refs
before integrating code. The older `design/indexing-query-mcp` local branch points to
`594e7ab9`, before PR #103.

This contract specializes [inference security review](inference-security-review.md). Its
machine-checkable shape is [review-packages.schema.json](../schemas/review-packages.schema.json).
The broad `review-input-package.schema.json` exists only at the cached design ref and is not
yet an assembler contract. Both package kinds here are pre-adjudication inputs: scanner
severity is *reported* severity for ordering, never an adjudicated finding severity.

## Source of each field

| Contract field | Accepted source and current query |
|---|---|
| `run_id`, `manifest_sha256`, `target_snapshot` | `resolve_accepted_manifest` and `load_verified_manifest` in `retrieval/core.py` and `retrieval/index.py`; verify each shard and the source snapshot before assembly. |
| `scope`, `source_ids`, `artifact_ids` | Catalog component, source, build-unit and artifact entities; `find`, `query_artifacts`. No synthetic trust boundary: use `null` until an accepted producer provides it. |
| `lead_menu` | Cached branch `indexing/sast.py::build_scanner_correlation`: accepted `tool_observation` rows classified as `source_sast`, with native severity, `normalize_reported_severity`, rule, suppression, duplicate and flow identities. `query_observations` and `query_precomputed(scanner_correlation)` expose the accepted records on that branch. |
| `evidence`, `context_ids` | Accepted observation, priority, CodeQL, source, build and precomputed shard identities; `find`, `trace`, `resolve_evidence`, `query_codeql`, `query_hotspots`, `query_precomputed`. A cited relation is a nomination until it resolves to a source line or hash-verified run artifact. |
| `proof_obligations` | Deterministic rule table keyed by lead class and observed prerequisites: affected construct, input control, reachability, guard/configuration state, and impact. Missing predicates stay open; model prose cannot close them. |
| `coverage_gaps` | Accepted index coverage, dataset inventory, query-set and language/build-unit cells; `coverage`, `query_dataset_inventory` on the cached design ref. A failed, absent or skipped producer is a named gap. |
| `retrieval` | Intersection of accepted package identities, available index names, query sets and configured caps. These are grants proposed by assembly, not an MCP authorization token. |

`input_fingerprint` hashes canonical JSON of the accepted manifest hash, package scope, all
sorted referenced shard hashes, lead IDs, rule version and resolved cap settings. `package_id`
is the kind plus SHA-256 of the canonical package body without `package_id`. Arrays of IDs,
evidence and gaps sort by stable identity; no timestamps or completion order enter identity.
Reassembly from the same accepted inputs must produce byte-identical packages. The schema
closes object keys and bounds structural types; a semantic validator must additionally verify
hashes, sorted uniqueness, cited identities, page/byte caps and membership invariants.

## Assembly and admission gates

1. Resolve one accepted pointer and verify the run-owned handoff, manifest, target snapshot,
   physical shards and embedded identities. A changed hash, escaped path, conflicting shard,
   failed dataset publication audit or contradictory schema blocks package publication.
2. Read the accepted dataset inventory and language/build-unit matrix. Select only source-SAST
   observations classified by the versioned normalization rule. Never infer zero findings from
   an unavailable observation or scanner-correlation shard.
3. Create one `finding_lead` package for each accepted source-SAST observation, including
   suppressed, duplicate, unresolved-location and unknown-severity records. Preserve the
   original observation ID and native severity. Duplicate/suppression state is context, not a
   reason to remove the package. Other lead families can be added by a new versioned rule.
4. Partition hunts by accepted component, then accepted trust boundary if known, build unit and
   stable entity range. Each hunt has a bounded lead menu, context identities and open
   obligations; it does not embed source or raw scanner output. Split oversized menus into
   numbered partitions and expose `next_partition`. A bound that cannot be partitioned creates
   a `truncated` gap and blocks the High/Critical membership gate.
5. Form the expected set `E` of *all* accepted source-SAST observation IDs with normalized
   reported severity High or Critical, including suppressed and duplicate IDs. Form `F` from
   finding-lead packages and `H` from hunt menus. Require `E ⊆ F` and `E ⊆ H`, exactly one
   finding-lead package per ID, and no invented menu ID. Compare per severity, scanner,
   component and shard counts to the accepted `scanner_correlation` audit. Unknown severity
   has its own complete menu and gate; do not silently downgrade it to low priority.
6. Publish a run-owned manifest listing every package hash, accepted input hash, gap and count.
   The review job consumes this manifest only after it verifies all package bytes. Producer
   failure may publish explicit gaps; membership or integrity failure blocks the handoff.

The cached branch already implements the lead facts and partitioned High/Critical and unknown
menus in `indexing/sast.py`; it raises `LeadAuditError` if accepted observations disappear from
those menus. It does **not** implement steps 3–6 for review packages. Its `query_observations`
has a candidate bound and can return a gap instead of a complete page; the assembler must use
the accepted scanner-correlation shard and audit for exhaustive enumeration, not page through
an MCP endpoint and assume an empty result is complete.

## Bounded retrieval and producer dependencies

| Slice | Current accepted producer/index | Query or precompute | Missing dependency and required gap |
|---|---|---|---|
| All languages, source | target catalog `source`; Tree-sitter `analysis` where grammar/scope succeeds | `search`, `find`, `read_excerpt`, `trace`, `symbol_links` on cached branch | Parse failure or unsupported grammar is per language/scope; no symbol/call graph inference from syntax alone. |
| C/C++ build units | language build, compiled analysis, clangd symbols; `build`, `compiled`, `analysis` | `query_build_security`, `query_artifacts`, `symbol_links` | LLVM direct-call and Clang AST are partial. No Joern graph edge until a bounded, source-mapped export is accepted. |
| Go, Java/Kotlin, C#, JavaScript/TypeScript, Python, Rust build units | accepted build/artifact shards; CodeQL `observations` only for successfully executed scopes | `query_artifacts`, `query_codeql`, `build_provenance`, `scanner_correlation` | Build/CodeQL absence is per unit and language. CodeQL path steps do not become general call/dataflow graph edges. |
| PHP, shell and other catalog languages | source/Tree-sitter and applicable SAST observations | `query_observations`, `scanner_correlation`, `search` | CodeQL, compiled and symbol lanes unavailable unless a matching accepted shard exists. |
| Cross-cutting build, CI, history, control and intelligence | accepted artifact, CI, history, priority, OWASP and pinned reference shards | `query_artifacts`, `query_ci_configuration`, `query_change_context`, `query_hotspots`; cached branch products `artifact_inventory`, `dependency_advisories`, `ci_trust`, `history_context`, `control_evidence`, `reference_intelligence` | Missing input/feed, stale feed or partial source yields a named query-set gap, not complete coverage. |

The cached branch's `matrix.py` computes language and build-unit cells from accepted shards;
`input_matrix.py` reconciles producer declarations against them. Stage-1 products there are
`build_provenance`, `artifact_inventory`, `dependency_advisories`, `scanner_correlation`,
`ci_trust`, `history_context`, `control_evidence`, `reference_intelligence` and `symbol_links`.
The five link families are `representation`, `finding_source`, `package_advisory`,
`symbol_syntax` and `history_code`. The graph products `call_graph`, `control_flow`,
`dataflow`, `sarif_correlation`, `ast_ir_cpg_mapping`, `guards_ranges`, `entrypoint_paths`,
`hotspot_context` and `review_package` remain planned. `job_cpg_analysis` retains a Joern
binary artifact, not accepted graph export. The optional SQLite FTS image validates a derived
text stream; accepted in-process shards remain retrieval authority.

## Role-specific views and capability enforcement

The application creates a signed or MAC-protected, short-lived capability binding **run ID,
manifest hash, package ID and hash, role, round, tool allowlist, index and query-set allowlists,
entity scope, page/byte/depth caps and expiry**. MCP verifies the binding on every call before
dispatch, then intersects request filters and result identities with the package grant. A cursor
is bound to the same capability and query hash. The current `RetrievalMcpAdapter` checks tool
names and argument keys but has no such role/package scope; this is planned work. Do not hand
workers an unrestricted adapter while this gate is absent.

| View | Package content | Tool reach |
|---|---|---|
| Red discovery (`hypothesis_hunter`, `red_team_analyst`) | Hunt slice and lead menu, accepted context and gaps; no adjudicated labels | Bounded `search`, `find`, `read_excerpt`, `trace`, `coverage`, `query_observations`, `query_precomputed` and relevant domain queries inside the package scope. |
| Blue refutation | One normalized claim, original cited evidence, open obligations, relevant finding-lead package and scope; may seek counterevidence | Same bounded read routes for that claim's package, including contradicting evidence. No other claim transcript. |
| Blind verifier | One normalized claim and original evidence IDs plus the minimum scope; no red/blue narratives, scores, dispositions or actor/cache IDs | Independent fresh retrieval context and the same read-only scope. Seal its result before joining red and blue records. |

No role receives arbitrary filesystem paths, shell, SQL, regex, target guidance, evaluator roots,
raw argv/environment, network access or writes. Current MCP routes on `main` are core search,
find, excerpt, trace, resolve, coverage and artifact/build/CI/CodeQL/change/OWASP queries.
`query_hotspots`, `query_precomputed`, `query_observations` and `query_dataset_inventory` exist
only at the cached design ref. Add no graph query route before accepted graph shards exist.

## Validation and Dagster handoff

Fixtures should include two languages and two build units; accepted High/Critical, unknown,
suppressed and duplicate SAST observations; a partial CodeQL scope; an unavailable Tree-sitter
scope; an ambiguous source mapping; a stale feed; a CPG binary without graph export; and
same-line contradictory evidence. Focused tests must prove schema rejection of extra fields,
stable package hashes under shuffled input, exact High/Critical and unknown membership across
partitions, unchanged lead IDs through suppression/deduplication, gap propagation, source-line
resolution, manifest/hash tampering rejection, package-scoped MCP denial, blind-view isolation,
cursor rebinding denial and reuse invalidation when one upstream shard changes. An empty query
with partial coverage must remain a gap.

Dagster should expose `accept_manifest → assemble_scope → assemble_packages → red fan-out →
normalize → blue and blind-verifier fan-out → adjudicate → publish` as visible dependencies.
Assembly and publication use immutable application attempts and a serialized accepted handoff;
Dagster schedules and records node outcomes. Every expected worker cell has one terminal record.
Ordinary producer/worker failures become scoped gaps; integrity and membership failures stop
publication. Resume fingerprints depend on accepted manifest, package bytes, guidance and
configuration so an upstream change invalidates only affected packages and worker cells.

## Ordered implementation

1. Reconcile Git refs and the branch schema; merge this contract with the branch's broad schema
   deliberately, then add semantic package validation and fixture-based High/Critical gates.
2. Add deterministic package assembly over accepted shards, plus manifest publication and a
   single Dagster handoff. Prove one complete lead and one hunt partition end to end.
3. Add capability-scoped MCP dispatch and red, blue and blind projections; test denied cross-
   package queries and sealed verifier independence before running workers.
4. Add per-language/build-unit dependency selection and gap accounting; extend graph products
   only after Joern/LLVM source-mapped export is accepted and tested.
5. Add full inference fan-out, adjudication and downstream accepted finding publication using
   the existing inference design's evidence and independence gates.
