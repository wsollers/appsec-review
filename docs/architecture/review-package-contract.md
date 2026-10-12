# Review package and finding-lead contract

Status: implementation contract, schema version 2. Accepted-manifest scope assembly, lane A
finding-lead packages for every lead family, lane B review-unit ranking and hunt packages,
membership audits and the package manifest are implemented in `src/appsec_review/review/`
(`scope.py`, `lead_families.py`, `units.py`, `packages.py`). Worker scope enforcement and the
inference job that consumes these packages are not implemented yet.

This contract specializes [inference security review](inference-security-review.md). Its
machine-checkable shape is [review-packages.schema.json](../schemas/review-packages.schema.json).
The broad [review-input-package.schema.json](../schemas/review-input-package.schema.json) exists
but is not yet an assembler contract. Both package kinds here are pre-adjudication inputs: scanner
severity is *reported* severity for ordering, never an adjudicated finding severity.

## Source of each field

| Contract field | Accepted source and current query |
|---|---|
| `run_id`, `manifest_sha256`, `target_snapshot` | `resolve_accepted_manifest` and `load_verified_manifest` in `retrieval/core.py` and `retrieval/index.py`; verify each shard and the source snapshot before assembly. |
| `scope`, `source_ids`, `artifact_ids` | Catalog component, source, build-unit and artifact entities; `find`, `query_artifacts`. No synthetic trust boundary: use `null` until an accepted producer provides it. |
| `lead_menu` | `review/lead_families.py`: one versioned rule per lead family (see gate 3). Source-SAST and CodeQL reuse `normalize_reported_severity` and the accepted `scanner_correlation` lead facts of `indexing/sast.py` for suppression, duplicate and flow identities. Each lead keeps its accepted identity, scanner, rule, bounded `message`, `rule_cwe`, native severity, reported severity, `severity_rule` and `severity_basis`. |
| `lane`, `lead_family`, `rank` | `finding_lead` packages are lane `lead` with a non-null family and `rank: null`. `hunt` packages are lane `hunt` with `lead_family: null` and carry the unit's `review-unit-rank/1` rank and basis. |
| `persona`, `stack_profile` | Always `null` at assembly. Routing fills them later; assembly never guesses them. |
| `evidence`, `context` | Accepted observation, priority, CodeQL, source, build and precomputed shard identities; `find`, `trace`, `resolve_evidence`, `query_codeql`, `query_hotspots`, `query_precomputed`. A cited relation is a nomination until it resolves to a source line or hash-verified run artifact. |
| `proof_obligations` | Deterministic rule table keyed by lead class and observed prerequisites: affected construct, input control, reachability, guard/configuration state, and impact. Missing predicates stay open; model prose cannot close them. |
| `coverage_gaps` | Accepted index coverage, dataset inventory, query-set and language/build-unit cells; `coverage`, `query_dataset_inventory`. A failed, absent or skipped producer is a named gap. |
| `retrieval` | Intersection of accepted package identities, available index names, query sets and configured caps. These are grants proposed by assembly, not an MCP authorization token. |

Each `context` entry is typed `{id, kind, role}`. `kind` is the retrieval entity kind of `id`.
`role` is one of `source`, `artifact`, `component`, `build_unit`, `duplicate_of`, `flow`,
`priority`, `history`, `hotspot` or `tag`. Bare identity lists are not accepted.

`input_fingerprint` hashes canonical JSON of the accepted manifest hash, package scope, all
sorted referenced shard hashes, lead IDs, rule versions (assembly, obligations, rank and every
lead-family rule) and resolved cap settings. `package_id` is `<kind>-<sha256>` over the
canonical package body without `package_id`. Arrays of IDs,
evidence and gaps sort by stable identity; no timestamps or completion order enter identity.
Reassembly from the same accepted inputs must produce byte-identical packages. The schema
closes object keys and bounds structural types; a semantic validator must additionally verify
hashes, sorted uniqueness, cited identities, page/byte caps and membership invariants.

## Assembly and admission gates

1. Resolve one accepted pointer and verify the run-owned handoff, manifest, target snapshot,
   physical shards and embedded identities. A changed hash, escaped path, conflicting shard,
   failed dataset publication audit or contradictory schema blocks package publication.
   `scope.accept_manifest` uses `resolve_accepted_manifest` and `load_verified_manifest`,
   re-checks each shard's row counts and snapshot against its embedded metadata, and raises
   `IntegrityError` on any mismatch. `AcceptedScope.verify` re-hashes every shard before
   assembly returns.
2. Build the evidence map: available and missing coverage per producer, components, build
   units, languages and reference-intelligence freshness. An absent producer shard is a
   `missing` gap and a stale feed a `stale` gap, with ids from `make_id("gap", 1, ...)`. Then
   normalize every accepted lead of every family with its versioned rule
   `appsec-review/lead-family/<family>/1`:

   | Family | Accepted records | Reported severity |
   |---|---|---|
   | `source_sast` | `tool_observation` classified `source_sast` | `normalize_reported_severity`; suppression, duplicate and flows from accepted `scanner_correlation` lead facts |
   | `codeql` | CodeQL observations | the same rule; `security_severity` bands first |
   | `artifact_scanner` | `job_artifact_security_analysis` observations | CVSS band, else native label |
   | `dependency_advisory` | dependency-class observations (OSV, Grype) | the advisory's own CVSS band, else its severity label |
   | `ci_rule` | `job_ci_configuration_analysis` observations | native label |
   | `post_build_hardening` | deterministic `build_security` checks with status `FAIL` | native label if published, else `unknown` |
   | `owasp_control` | `control_evidence` facts with status `not_satisfied` | native label if published, else `unknown` |

   A family whose accepted producer shard is absent is a `missing` gap, never an empty list.
   Without an accepted `scanner_correlation` shard, duplicate state is recomputed with
   `build_scanner_correlation`, suppression is `unknown`, and a `partial` gap is recorded. When
   the shard is present, its lead facts must cover exactly the accepted source-SAST
   observations and agree with the severity rule, and its audit counts per severity must match;
   a contradiction is an integrity failure. The assembler enumerates accepted shards
   exhaustively and never pages through a bounded MCP route such as `query_observations`.
3. **Lane A.** Admit every lead whose reported severity is in `admit_severities` (default
   `critical`, `high`, `unknown`) from every family, and create exactly one `finding_lead`
   package per admitted lead, including suppressed, duplicate, unresolved-location and
   unknown-severity records. Preserve the original identity and native severity.
   Duplicate and suppression state is context, not a reason to remove the package.
4. **Lane B.** Partition review units by accepted component, then accepted trust boundary if
   known (none is accepted yet, so it is `null`), build unit and stable range of sorted source
   paths (`unit_max_files`). Rank units by `review-unit-rank/1`: the sum of the available signals
   in integer points 0–1000 (LPS, SII, hotspot, tag density, and medium/low/info lead hints), then
   the count of known signals, then unit key. A missing signal is `unknown` with reason
   `producer_unavailable` or `no_record`, never zero. The top `hunt_max_units` units receive hunt
   packages; every other unit is a `skipped` gap with reason `below_hunt_cutoff`. A hunt menu
   lists every lead of its unit by reported severity then identity, and embeds no source or raw
   scanner output. Menus split into numbered partitions by `hunt_menu_partition_size` and then
   by `max_package_bytes`; `next_partition` names the following partition key. Context beyond
   `max_context_entries`, or beyond the byte bound of a single-lead package, is omitted with a
   `truncated` gap and `omitted_context`. Leads are never truncated: a package that cannot fit
   one lead without context blocks the membership gate with an integrity failure.
5. Form the expected set `E` of all admitted leads, including suppressed and duplicate IDs, and
   `F` from finding-lead packages. Require `E ⊆ F` per family and severity, exactly one package
   per ID, and no invented ID. Each hunted unit's partitions list every lead of the unit exactly
   once; the leads of a unit below the cutoff are accounted for by its `below_hunt_cutoff` gap.
   Any violation raises `IntegrityError`.
6. Publish a run-owned manifest (`appsec-review/review-package-manifest/1`) listing every
   package id, kind, lane, family, partition, SHA-256 and size; the accepted input shard hashes;
   the evidence-map hash; ranked units with their basis and hunt state; every gap; per-family and
   per-severity counts; and both audits. `publish_packages` writes and verifies the bytes, and
   the review job consumes the manifest only after `verify_package_manifest` succeeds. Producer
   failure publishes explicit gaps; membership or integrity failure blocks the handoff.

## Bounded retrieval and producer dependencies

| Slice | Current accepted producer/index | Query or precompute | Missing dependency and required gap |
|---|---|---|---|
| All languages, source | target catalog `source`; Tree-sitter `analysis` where grammar/scope succeeds | `search`, `find`, `read_excerpt`, `trace`, `query_precomputed(symbol_links)` | Parse failure or unsupported grammar is per language/scope; no symbol/call graph inference from syntax alone. |
| C/C++ build units | language build, compiled analysis, clangd symbols; `build`, `compiled`, `analysis` | `query_build_security`, `query_artifacts`, `symbol_links` | LLVM direct-call and Clang AST are partial. No Joern graph edge until a bounded, source-mapped export is accepted. |
| Go, Java/Kotlin, C#, JavaScript/TypeScript, Python, Rust build units | accepted build/artifact shards; CodeQL `observations` only for successfully executed scopes | `query_artifacts`, `query_codeql`, `build_provenance`, `scanner_correlation` | Build/CodeQL absence is per unit and language. CodeQL path steps do not become general call/dataflow graph edges. |
| PHP, shell and other catalog languages | source/Tree-sitter and applicable SAST observations | `query_observations`, `scanner_correlation`, `search` | CodeQL, compiled and symbol lanes unavailable unless a matching accepted shard exists. |
| Cross-cutting build, CI, history, control and intelligence | accepted artifact, CI, history, priority, OWASP and pinned reference shards | `query_artifacts`, `query_ci_configuration`, `query_change_context`, `query_hotspots`; `query_precomputed` products `artifact_inventory`, `dependency_advisories`, `ci_trust`, `history_context`, `control_evidence`, `reference_intelligence` | Missing input/feed, stale feed or partial source yields a named query-set gap, not complete coverage. |

`indexing/matrix.py` computes language and build-unit cells from accepted shards;
`input_matrix.py` reconciles producer declarations against them. Stage-1 products are
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
find, excerpt, trace, resolve, coverage, artifact/build/CI/CodeQL/change/OWASP queries, and
`query_hotspots`, `query_precomputed`, `query_observations` and `query_dataset_inventory`
(`mcp/schema.py`). Add no graph query route before accepted graph shards exist.

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

1. Done: schema version 2, deterministic assembly over accepted shards for both lanes,
   membership audits and manifest publication in `src/appsec_review/review/`. The fixture tests
   live in `tests/review/`, and the fixture builder is `tests/fixtures/inference_review/builder.py`.
2. Add the single Dagster handoff that consumes the verified package manifest, and prove one
   complete lead and one hunt partition end to end.
3. Add capability-scoped MCP dispatch and red, blue and blind projections; test denied cross-
   package queries and sealed verifier independence before running workers.
4. Add per-language/build-unit dependency selection and gap accounting; extend graph products
   only after Joern/LLVM source-mapped export is accepted and tested.
5. Add full inference fan-out, adjudication and downstream accepted finding publication using
   the existing inference design's evidence and independence gates.
