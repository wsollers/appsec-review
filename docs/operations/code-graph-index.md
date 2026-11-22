---
title: "Code-graph index"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_review_data_indexing", "job_review_prioritization", "job_security_tagging", "job_tree_sitter_ast"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Code-graph index

`job_code_graph_index` turns the accepted CodeQL graph exports into the `graph` retrieval index
that `query_code_graph` serves. Current behavior is summarized in
[code intelligence](../architecture/code-intelligence.md) and the
[canonical job page](job_code_graph_index.md); the original D4 decision remains in the historical
[design record](../architecture/code-graph-precomputation.md).
The job runs no analyzer and reads no target tree beyond the source files the
accepted CodeQL plan names, each verified against its accepted SHA-256.

## Inputs

| Input | Where it comes from | How it is verified |
|---|---|---|
| Per-scope export records | `outputs["execution.scopes"].graph_export_artifact` in the accepted `job_codeql_analysis` result (`appsec-review/codeql-graph-exports/1`), not the compact handoff output projection | The artifact, the result and the plan must be bound to the accepted handoff by path and SHA-256 |
| Raw exports | `data/codeql/scopes/<scope>/exports/` | `export-manifest.json` must equal the manifest identity bound to the accepted handoff, then `codeql.runtime.load_graph_exports` checks every file. The CodeQL job's own `export-checkpoint.json` is never read |
| Scope files | The accepted CodeQL plan (`plan.inventory`) | Bytes are read from the target root and must match the planned SHA-256 |
| clangd, LLVM IR, Clang AST and tree-sitter shards | `analysis` shards of `job_cpp_symbol_index` (`clangd-*`), `job_cpp_compiled_analysis` (`branch` `ir` and `ast`) and `job_tree_sitter_ast` (one per component, build unit and language; the `tree-sitter-coverage-*` shard is not a producer), from the accepted manifest or, when the `job_codeql_analysis` manifest rewrite dropped them, from those jobs' own accepted handoffs (`restored_secondary` in the load output) | Accepted manifest verification; a restored shard's handoff manifest is re-verified and the shard must be produced by that handoff's job |
| Source dispositions | `settings.source_dispositions`, the review's T-165 table frozen into this job by the loader (`config/first_party.py`) | A table that differs from `jobs.job_inference_security_review.settings.source_dispositions` fails loading |
| CodeQL observations | Accepted `observations` shards `codeql-<language>-<scope>-*` | Accepted manifest verification |
| Prioritization flow steps | Accepted `priority` shards of `job_review_prioritization`, when present | Accepted manifest verification |
| Catalog and columns | Supplied `rules/codeql-graph-export/catalog.json` and `columns.json` | Catalog shape and export contracts are checked; the catalog release must match frozen `review_policy.releases.graph_catalog`. Missing bound configuration or a contradictory release fails. Reuse requires declared graph catalog, columns, normalizer and validation releases, not fresh customer-evidence hashes of supplied files. |

Each clangd, IR, AST and tree-sitter shard serves exactly one CodeQL scope: the scope whose planned
files hold most of the shard's located paths, with ties broken by scope id. A shard is never shared
between two scopes, and a scope without one of its own is cross-checked as `not_covered`.

On smoke-cpp run `2026-11-14-0005` no shard was assigned at all: the clangd job had indexed nothing
because `job_cpp_compiled_analysis` marked the only build unit `BLOCKED_BY_COMPILE` on a single
low-confidence build-output heuristic gap (a build that completed with named gaps is usable since
T-5016, as the CodeQL planner already treated it), the Clang AST and IR shards were empty for the same
reason, and the three populated tree-sitter shards were not a producer. Tree-sitter now is one
(`graph-cross-check/1`, producer `tree-sitter`): a CodeQL `call_site` whose exact span equals a syntax
`call_expression` agrees when the written callee name matches, is `partial` when the written text
differs (syntax resolves nothing, so it never contradicts), and a syntax call in a file CodeQL covers but
at a span CodeQL reports no call for becomes a bounded `secondary_only` fact.

## First-party scoping

The graph producers spend their budgets on first-party code first and keep every exclusion as a count
(T-5016). `job_tree_sitter_ast` orders each scope's files first-party first before chunking and the
container's per-scope node budget; a vendored file the budget did not reach is counted in
`counts.dispositions.excluded_files`, never a gap. `job_cpp_symbol_index` admits symbols first-party first
under `max_symbols_per_scope` (`symbols_by_disposition`, `excluded_symbols_by_disposition`; only a
first-party exclusion is the `clangd symbol limit reached` gap). `job_codeql_analysis` still builds the
database over the whole unit, so calls into vendored code resolve, but query results located in a
non-first-party file are counted per query (`excluded_results`) and not published. This job's
`normalize.scopes` drops facts located in non-first-party files with per-family `excluded_<disposition>`
counts on the coverage row: a path survives when its source or its sink is first-party and keeps that
sink site as its boundary, and every function `symbol` stays so a first-party call into vendored code
keeps its callee. The disposition table is part of each scope's checkpoint identity.

## Graph quality scorecard

`acceptance.publish_handoff` writes `graph-quality-scorecard.json`
(`appsec-review/graph-quality-scorecard/1`, closed schema
`docs/schemas/graph-quality-scorecard.schema.json`, dataset `code_graph_scorecard`) and a one-screen
`graph-quality-scorecard.txt` beside `code-graph-summary.json`. Per scope it lists every first-party
function once with its call edges by cross-check verdict (`agree`, `disagree`, `partial`, `not_covered`
= CodeQL only, `secondary_only`) and the producers that agreed; every dataflow path with its endpoints,
classes, direct eligibility and SARIF correlation state (`bridged`, `partial`, `broken`,
`uncorrelated`); sink classification coverage with the unclassified APIs; the cross-check producers
attached; and the first-party exclusion counts. The report renders the text in its coverage section
(`reporting/graph_quality.py`). It is a measurement of the published graph, never evidence about the
target. [Smoke runs](test-targets.md#smoke-runs) says how to read it.

Function and path detail arrays are bounded samples (5,000 functions and 1,000 paths per scope).
Run totals count all analyzed functions and eligible paths, not just displayed rows; the
`functions_omitted` and `paths_omitted` counts describe display omissions.
SARIF correlation requires monotonically ordered step matches, including endpoints. An exact span
found earlier in a candidate path does not corroborate a reversed scanner trace. Integer range
bounds are parsed as integers directly, including values outside binary floating-point precision.

## Alternate graph context

The optional `analysis/alternate-cpg` shard is a context projection, not a replacement for the
primary graph's admissibility rules (T-5098/T-5099).

- `enabled=false` bypasses input harvesting and synthesis and publishes an empty shard with an
  explicit disabled gap. Primary graph work is unaffected.
- Tree-sitter fallback consumes the actual normalized `syntax`, `grammar_native_type`, `cfg`,
  `cfg_nodes` and `cfg_edges` fields. Distinct CFG node identities remain distinct even when
  they refer to one AST location.
- clangd variable symbols stay non-call symbols. `REFERENCES` stays a reference; only `CALLS`
  contributes invocation reachability, and each available occurrence keeps its producer location.
  Missing occurrences, unresolved overloads and ambiguous enclosing/guard contexts are gaps.
- Canonical nested `result.caller` and `result.callee` identities determine calls. Each occurrence
  keeps its own location and guards; a caller/callee pair alone never merges two branch conditions.
  Original producer, coverage, cross-check and admissibility qualifiers survive projection and
  SQLite round-tripping. A resolution tier alone never makes a disputed edge exact.
- A syntactic sink in `finally` can execute in several CFG contexts at one source occurrence.
  Each `FN_TO_SINK` edge retains its context identity and guards, so guarded and unguarded paths
  remain distinct. The shared sink exposes only guards common to every context, joined by their
  original guard AST identity when available; these source-level guard anchors are not an
  arbitrary context's CFG node.
- Flat SARIF steps are grouped by flow/thread and ordered by ordinal. Unmapped steps break the
  projected chain rather than introducing a flow across missing evidence.
- Source hashes come only from accepted source locations/catalog rows. Original bytes, coordinates
  and backing metadata are retained. Line-only projections are ambiguous; absent identities
  publish no fabricated source location and carry `source_identity_unavailable`.
- Alternate JSONL files live under `data/code-graph/alternate-cpg/<content-fingerprint>/`; the
  SQLite name also uses a content fingerprint covering graph content, source identities and
  synthesis settings. Publication never unlinks a previously named SQLite shard.
- Indexed records retain the legacy JSON-string representation when it fits the index's existing
  sanitizer unchanged. Larger or redacted records use additive structured payload fields instead
  of truncated JSON strings. Any structural redaction/truncation is a named
  `alternate_cpg_projection_limited` gap and cannot retain an exact projected edge/path; the full
  portable JSONL artifact remains available. Readers accept both representations under the same
  declared schema version.
- Path traversal bounds are 1,024 visited states, 1,024 frontier states and 16,384 edge inspections,
  independent of configured path/hop limits. Slice seeds obey the node bound; reaching depth,
  node, path or work bounds records cut metadata and named gaps. Counts describe unexamined
  branches, not a claimed count of all omitted complete paths.
- Slice admission follows breadth distance, path, source line and node identity before applying
  the node cap. A bounded candidate heap completes each breadth layer before admitting its
  ordered prefix. Growing a cursor's budget therefore extends the same result order, including
  traversal-discovered nodes, without duplicating or losing earlier rows. Existing node, frontier,
  edge-work and response caps remain unchanged.

The summary records synthesis cuts and publication gaps. Query adapters retain the most restrictive
saved `max_slice_depth` when composing accepted shards, check the query deadline during loading and
Python traversal, and forward cut gaps and truncation even when no path was found. Slice query
pagination cannot enlarge the traversal beyond 1,024 nodes. Legacy shards without saved limits
remain readable using the pre-existing query bounds; missing evidence qualifiers are never treated
as exactness.

## Units

| Unit | Work |
|---|---|
| `load.accepted_inputs` | Loads and verifies the inputs above and computes each scope's checkpoint identity. It reuses every scope whose checkpoint and shards still verify. A changed export, export manifest or source is an `IntegrityError` that fails the unit |
| `normalize.scopes` | `graph.normalize.normalize_scope` for each scope that has to be rebuilt |
| `crosscheck.scopes` | `graph.crosscheck.cross_check` with only the scope's own secondary shards. Disagreements and `secondary_only` call sites make the scope's `call_site` row `partial` |
| `correlate.scopes` | `graph.correlate.correlate` with the scope's observations and the prioritization shard. Every broken flow becomes a named `dataflow_path` gap. The unit then publishes the shards and the scope checkpoint |
| `acceptance.publish_handoff` | Composes the graph shards and any restored secondary shards onto the current accepted manifest and replaces only this job's earlier shards. It fails if a shard the graph was built from has left the accepted set |

Intermediate fact sets pass between units as `data/code-graph/scopes/<scope>/work/*.json`.

## Shards and coverage

The job publishes one `graph` shard, `graph-<scope_id>-<family>`, for each CodeQL scope and fact
family. CodeQL-export `symbol` entities ride in the `call_site` shard, and each relation goes in the
shard of its fact endpoint. The shard producer carries `job`, `unit`, `family`, `language`,
`scope_id`, `build_unit_id`, `rule` and `catalog_release`. Consumers select shards by these keys.

Every shard has one coverage row, `graph:<scope_id>:<family>`, with the section 7.4 state. A scope
whose export is `SKIPPED`, `FAILED` or `NOT_APPLICABLE` still publishes all seven shards. Each holds
only an `unavailable` row that names the export status and reason, and no entities, so the
inventory audit reports these shards as `unavailable` rather than missing.

## Producer neighborhoods

Beside the card the job publishes one `producer_neighborhood` shard per scope,
`graph-<scope_id>-producers`. It holds the flow (`ir_entity`), diagnostic (`tool_observation`) and
linked clangd `symbol` rows of the seeded Clang AST/IR, Clang-Tidy/Static Analyzer and clangd producers,
bounded per kind with `limit_reached` gaps, and each card carries
`producers: [{name, state, seeded, depth, gaps}]`. When a producer's own secondary shard was dropped by
the upstream selection, the job restores it from that producer's accepted handoff. A producer with no
accepted output is a `producer_not_run` gap. The shard also carries the `cpg` rows of an enabled Joern job.

## Analyzer sinks

`crosscheck.scopes` passes the accepted `clang-static` diagnostics to `graph.analyzers.apply_analyzer_sinks`
(rule `graph-analyzer-sinks/1`). A diagnostic whose check is in the reviewed check-to-sink-class table and
whose line lies inside an exact CodeQL `sink_site` of the same class adds `clang-static` as an agreeing
cross-check producer to that fact. Any other mapped diagnostic becomes an analyzer-only `sink_site` fact
(inexact, `partial`, never direct-eligible; at most 500 per scope, `analyzer_sinks_limit`). Unmapped checks
and unlocated diagnostics are counted in `analyzer_checks_unmapped` and `analyzer_diagnostics_unlocated`
gaps on the `sink_site` coverage row; the per-scope summary is under `cross_check.analyzer_sinks`. See
`docs/architecture/seeded-neighborhoods.md` section 9.

## Sink classification

`normalize.scopes` classifies every `sink_site` once, through the catalog
(`rules/codeql-graph-export/catalog.json`, `appsec-review/graph-catalog/1` revision 2): API rules first,
then CodeQL model rules. A `dataflow_path` copies its sink site's `sink_class` and `cwe_family` into
`result.sink` and is `direct_eligible` exactly when that sink site is classified; the path does not
classify again, so the two can never disagree. Since T-5017 the network and file output sinks `send`,
`sendto`, `sendmsg`, `write`, `writev` (`network_output`) and `fwrite` (`file_write`) are classified; on
smoke-cpp run `2026-11-14-0005` they were the only unclassified sinks (`send` 7, `write` 2) and the 10
`src/request.cpp` paths into `send` were the only ineligible paths. A remote-flow sink outside those APIs
stays `unclassified` and is published ineligible with an `unclassified_sink` gap; C++ stream writes are
not exported as sinks (member functions), which is a named limitation of the pack. A catalog change
re-pins every language's `export_query_packs` entry and `asset_lock_sha256`, and the changed packs must be
recompiled with `scripts/compile-codeql-queries.sh --language cpp` before the next review run.

## Resume and invalidation

A scope's checkpoint (`data/code-graph/scopes/<scope>/checkpoint.json`) binds:

- the scope's identity, root, build unit, database identity and export status
- the export-manifest hash and the export pack
- the planned file hashes
- the declared graph catalog and columns releases
- the rule versions: `graph-normalize/2`, `graph-cross-check/1`, `graph-sarif-correlation/1` and
  `graph-fact-admissibility/1`
- the `GraphSettings` bounds and the CodeQL version
- the identities of every secondary, observation and prioritization shard read
- the declared graph normalizer release

A rerun with unchanged eligible identities reuses its scope without normalizing again. Missing
required releases disables scope reuse. A changed catalog declaration requires a new frozen run;
do not infer arbitrary cross-run database/export reuse from the local graph key. CodeQL's
explicit predecessor admission is a separate boundary. If a local output checkpoint
matches but its shards no longer verify, the job deletes it and rebuilds the scope.

## Configuration

`[jobs.job_code_graph_index]` declares the five steps, `settings.workers` (the number of scopes
processed at once in each unit) and `settings.graph`, which holds the `GraphSettings` bounds from
`graph/contract.py`. `settings.source_dispositions` is not written in the TOML: the loader copies the
review's table into this job, `job_tree_sitter_ast`, `job_cpp_symbol_index` and `job_codeql_analysis`
(`config/first_party.py`), and refuses a producer table that differs. The same `settings.graph` table, read from the run-bound resolved configuration
(`graph/settings.py::run_graph_settings`), sets the caps `query_code_graph` enforces for review
cells, scoring and MCP sessions; contract defaults apply only when a run binds no such table.

## Orchestration

In Dagster `wave1_review`, the job runs after `job_codeql_analysis`, `job_cpp_compiled_analysis`,
`job_clang_static_analysis`, `job_cpp_symbol_index`, `job_tree_sitter_ast` and
`job_review_prioritization`. The export it consumes is bounded by
`jobs.job_codeql_analysis.settings.export_queries` (`row_limit`, `max_bytes`, `timeout_seconds`),
not by `settings.graph`. It runs before
`job_security_tagging` and `job_review_data_indexing`, which keeps the manifest publishers in one
chain. Its units run in the `index` pool. The CLI graph (`appsec-review start`, `resume`,
`plan-resume`) runs it between `job_review_prioritization` and `job_review_data_indexing`, and
`--force-from job_code_graph_index` is accepted.

Enabled predecessor edges are projected from typed input/scheduling contracts; the
[generated job declaration](job_code_graph_index.md) is the inventory reference. When admitted,
SVF contributes qualified alias cross-checks in addition to the call-edge producers above.
Its module coverage and root accounting differ as recorded in [T-159](../TODO.md);
neither an empty aggregate gap list nor an unavailable secondary is a negative graph fact.

## Verification

Offline: `tests/test_code_graph_index_job.py` (staged accepted run) and
`tests/integration/test_code_graph_end_to_end.py` (the real CodeQL job with an injected executor,
this job, indexing and the inference review). Both use recordings
(`tests/fixtures/graph/codeql_export/`); the C/C++ native recording is copied from a live export.
The live tier `tests/live/test_code_graph_live.py` needs the pinned CodeQL image, which builds from
this repository on any Linux Docker host (`containers/tools/codeql/README.md`).
