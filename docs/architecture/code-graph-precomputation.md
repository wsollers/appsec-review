# Code-graph precomputation for direct review evidence

Status: approved strategy and implementation/test plan; nothing in this document is implemented
yet. It is the single authority for "item 2": precomputing code-graph facts so that the inference
review can obtain **direct** evidence for `source_to_sink_reachability`,
`attacker_input_control` and `missing_or_ineffective_guard` instead of relying on tool
observations and model prose. It resolves the conflict between the Joern/LLVM `query_precomputed`
plan in [`indexing-and-query-reuse.md`](indexing-and-query-reuse.md) ("plan A") and the
CodeQL-first `query_dataflow` plan in
[`evidence-sources-and-dataflow-retrieval.md`](evidence-sources-and-dataflow-retrieval.md)
("plan B"). Where those documents described the graph batch, they now defer here. The admissibility
rules it changes are restated in [`inference-security-review.md`](inference-security-review.md) R3.

This document describes review-worker evidence and repository implementation work. It is not a
prompt for review workers, and nothing here widens worker authority: every record a worker sees
is data with a producer, a resolving location and named gaps.

## 1. Current producer reality

Every decision below is grounded in what the code does today, not in what earlier designs hoped a
producer would do. The table names the file that establishes each fact.

| Producer | What it publishes today | What it cannot give the review | Established by |
|---|---|---|---|
| `job_codeql_analysis` | One immutable database per accepted scope and language (`data/codeql/scopes/<scope-id>/database`), one SARIF per query profile, normalized `observations` shards whose results keep ordered `code_flow`/`thread_flow` steps with source-resolved locations. Live acceptance: C/C++ 2/2, Java/Kotlin 7/7, JavaScript/TypeScript 12/12, Python 8/8, Actions 1/1 scopes succeeded; Go 0/7 (accepted recipes never compiled); C# and Rust are planning gaps; PHP is `NOT_APPLICABLE`. Executor actions are only `inventory`, `database` and `query`; `query` emits SARIF through a pinned `--suite` or `--suite-path` with `--max-paths 4`. A custom C/C++ pack (`cert-cpp`) is already hash-pinned and executed as an extra profile, so the hash-pinned custom-pack path exists. | No call graph, summaries, guards, ranges or entry-point catalog: only path-problem results that a shipped query happened to report, capped at four paths per result. | `jobs/job_codeql_analysis/job.py` (`_query_profiles`, `_query_one`), `codeql/runtime.py::CodeQLExecutor.execute`, `jobs/job_codeql_analysis/sarif.py`, `containers/tools/codeql/assets.lock.json` (`custom_query_packs = ["cpp"]`), `docs/operations/codeql-analysis.md` |
| `job_cpg_analysis` (Joern) | Runs `c2cpg` per accepted C/C++ scope and retains `cpg.bin` as a hash-identified artifact; publishes a `BLOCKED` `observations` shard with zero observations and `unavailable` coverage. No exporter, no source mapping, no fixtures. | Nothing retrievable. A retained binary is not graph coverage. | `jobs/job_cpg_analysis/job.py` (`JOERN_GAP`), `indexing/matrix.py` (`cpg_graph` lane is always `unavailable`), `docs/TODO.md` "Joern bounded export and acceptance" |
| `job_cpp_compiled_analysis` LLVM IR branch | Replays each TU with `-emit-llvm -S -g -O0`, then indexes `define` lines as `ir_entity` and uniquely resolvable direct `call @name` lines as exact `CALLS`. Basic blocks and instructions are only counted. Every IR entity's location is the whole TU, marked `ambiguous=True`, method `debug-or-tu-fallback`; the `!dbg` metadata the replay produces is never read. | CFG, def-use, dominators, guards, ranges, source-exact locations, indirect/virtual dispatch. | `jobs/job_cpp_compiled_analysis/job.py::_ir_index`, `containers/tools/native-cpp/native.py:154` |
| `job_cpp_compiled_analysis` Clang AST branch | Bounded JSON AST walk (≤ 4096 declarations per TU) indexing `FunctionDecl`, `CXXMethodDecl`, `CallExpr`, `DeclRefExpr` and a few other kinds as `ast_node` with line/column locations. | Resolved callee identity for calls (only `referencedDecl` payload), CFG, dataflow. | `jobs/job_cpp_compiled_analysis/job.py::_ast_index` |
| `job_cpp_symbol_index` (clangd) | `symbol` entities with exact locations (`clangd-uri-exact-path`), aggregated `CALLS`/`REFERENCES` edges between accepted symbols with occurrence counts and bounded locations; external symbols counted, not indexed. | Dispatch method, dataflow, guards. | `jobs/job_cpp_symbol_index/`, `docs/operations/cpp-index-jobs.md` |
| `job_tree_sitter_ast` | Concrete syntax nodes with exact spans for every supported grammar. | Semantic symbols, resolved calls, dataflow. | `docs/architecture/tree-sitter-ast.md` |
| `job_review_prioritization` | `review_flow_step` entities with `FLOWS_TO` relations for the shortest CodeQL path per source/sink (`codeql-semantic-paths` shard). | General graph edges; it reuses CodeQL SARIF only. | `docs/architecture/review-prioritization.md` "CodeQL source-to-sink paths" |
| `job_review_data_indexing` | Stage-1 `precomputed` products including `symbol_links` (symbol → syntax node links plus `calls_in`/`calls_out` counts); every graph set is published as a `pending_graph_batch` follow-up. | Any graph fact. | `indexing/products.py` (`FIRST_STAGE_SETS`), `jobs/job_review_data_indexing/job.py::GRAPH_FOLLOW_UP` |

Retrieval and review facts that constrain the design:

- `query_precomputed(query_set, subject?, path?, limit?, cursor?)` is the only product query. `path`
  is in `review/capability.py::FORBIDDEN_PARAMETERS`, so a review cell can address a product only by
  exact subject identity. The tool has no direction, depth, mode or class filter
  (`retrieval/core.py::query_precomputed`, `mcp/schema.py`).
- `trace` expands relations in both directions across every granted index, with no directional or
  per-kind semantics and a flat result bound (`retrieval/core.py::trace`).
- `precomputed_fact` is in `review/evidence.py::REFERENCE_KINDS`: **indirect for every predicate**.
  A graph fact published as a `precomputed_fact` can never satisfy an obligation, whatever its
  content. The only entity kinds that can satisfy an obligation are the `DIRECT_KINDS` constructs
  and `tool_observation` for the predicates in
  `jobs/job_inference_security_review/job.py::TOOL_RULE_PREDICATES` (`codeql` →
  `affected_construct`, `source_to_sink_reachability`).
- `guidance/routing.py::STRATEGY_SOURCES` already unlocks `sink_up` from `source_sink_facts` or
  `symbol_links`, and `entry_down` from `entry_point_catalog`. The job computes `available_sources`
  only from `symbol_links` and `control_evidence` (`job_inference_security_review/job.py`), so
  `entry_down` is never launched today and `sink_up` runs on symbol links that contain no source or
  sink facts.
- Role tool allowlists are in `pipeline/guidance/registry.json`; `independent_verifier` has only
  `find`, `read_excerpt`, `resolve_evidence`, `trace`, and `blue_team_refuter` lacks
  `query_precomputed`. A second, narrower allowlist exists in `mcp/capability.py::_ROLE_TOOLS` for
  the (not yet used) MAC-protected MCP token.
- Review packages carry typed `context` entries whose `role` vocabulary is `source`, `artifact`,
  `component`, `build_unit`, `duplicate_of`, `flow`, `priority`, `history`, `hotspot`, `tag`
  (`review-packages.schema.json` v3, `review/packages.py`).

## 2. Decisions

Each decision is final unless listed under [open questions](#11-risks-open-questions-and-what-is-deliberately-not-done).

### D1 Producer strategy: CodeQL is the primary producer of every fact family, for every language it has a database for

Reasons grounded in section 1:

1. CodeQL is the only producer that exists, runs, is hash-pinned, is licensed for custom query
   trees, and already has accepted databases for C/C++, Java/Kotlin, JavaScript/TypeScript and
   Python. Its libraries compute the exact facts R4 needs with source-exact locations: call graph
   with dispatch resolution (`Call.getTarget()`, `VirtualDispatch`), global taint tracking with
   path graphs, `GuardCondition` dominance, `SimpleRangeAnalysis`, and modeled remote/local flow
   sources and sinks. None of that must be invented.
2. Joern has no exporter, no source mapping and no fixtures; building them is a separate project
   (`docs/TODO.md`). LLVM IR indexing is a regex over `.ll` text with TU-level locations; a real
   CFG/dominator/range extraction needs an `opt` pass plus debug-location decoding and would still
   only cover C/C++ at `-O0`. Neither can give source-resolved guard or range facts in this
   batch without more new infrastructure than the CodeQL export itself.
3. One primary producer per family keeps fact identity, soundness gaps and invalidation simple.
   Disagreement is still represented, but between a primary fact and a cross-checking producer,
   never by merging two graphs into one.

Secondary (cross-checking) producers, C/C++ only in this batch:

| Fact family | Primary | Cross-check producers | Cross-check semantics |
|---|---|---|---|
| `call_site` (call graph) | CodeQL export | clangd `CALLS` edges (`analysis` shards), LLVM IR unique direct `CALLS` (`analysis` IR shard), Clang AST `CallExpr` nodes | agreement/disagreement per resolved edge, by exact caller/callee symbol identity (clangd) or callee name within the same TU (IR, AST) |
| `sink_site`, `entry_point`, `flow_summary`, `dataflow_path`, `guard_fact`, `range_fact` | CodeQL export | none in this batch | the fact carries `cross_check.state = not_covered` |

Disagreement representation (never silently merged, never dropped):

- Every graph fact carries `cross_check = {rule: "graph-cross-check/1", producers: [...],
  state: agree | disagree | not_covered | partial}` and, on `disagree`, a `CONTRADICTS` relation
  from the fact to the contradicting secondary entity (the clangd `symbol` edge source, the
  `ir_entity`, or the `ast_node`) with `exact=false` and the ambiguity explanation.
- A `disagree` state sets `admissibility.direct_eligible = false` (section 6). The fact remains
  queryable and citable as indirect evidence, and R5 row 3 (`unresolved_contradiction`) applies
  when red and blue cite the two sides.
- A secondary edge with no CodeQL counterpart is published as its own `call_site` fact with
  `producer = clangd` (or `llvm-ir`), `dispatch = secondary_only`, `direct_eligible = false`.
  Missing coverage on the CodeQL side is reported as the fact's gap, never as "CodeQL says no call".

Joern is **not** a producer in this plan. `job_cpg_analysis` keeps retaining the CPG and publishing
its `BLOCKED` shard; the `cpg_graph` matrix lane stays `unavailable`. LLVM IR extension (CFG,
def-use, guards) is explicitly out of scope (section 9).

### D2 Retrieval surface: one new typed tool, `query_code_graph`; graph families leave `query_precomputed`

Decision: add exactly one model-facing tool, `query_code_graph`, over a new accepted index named
`graph`. The seven graph query sets (`call_graph`, `control_flow`, `dataflow`,
`sarif_correlation`, `ast_ir_cpg_mapping`, `guards_ranges`, `entrypoint_paths`) are **retired from
`QUERY_SETS`** and from `query_precomputed`; `hotspot_context` and `review_package` stay in
`query_precomputed` as later composition products that may embed graph identities.

Why a typed tool rather than more `query_precomputed` sets:

1. Admissibility. `precomputed_fact` is indirect for every predicate by design (it is the right
   default for joins over feeds and scanners). Graph facts must be first-class entities of their
   own kinds so that `review/evidence.py::classify` can make them direct for mapped predicates
   (section 6) and the validator can re-resolve them through `find` like any other entity.
2. Parameters. `query_precomputed` addresses a product by subject identity or path; `path` is
   never grantable to a cell. Callers/callees need direction and depth, sinks need a class filter,
   paths need the sink or entry point as subject, SARIF correlation needs an observation as
   subject. Encoding every (subject, direction, depth, class) combination as separate precomputed
   subjects would multiply shard size and still leave the model guessing subject kinds.
3. One surface, not two. `trace` stays the generic relation walker, `find`/`read_excerpt` stay the
   resolvers, and every graph question goes through `query_code_graph`. No second graph tool is
   added later for Joern or LLVM: a future producer publishes into the same `graph` index with its
   own `producer` and cross-check state.

Why not keep both `query_precomputed(call_graph)` and `query_code_graph`: two routes to the same
facts would need two admissibility rules and two capability grants for one evidence class, which is
exactly the ambiguity AGENTS.md forbids ("one model-facing surface").

The tool keeps every AGENTS.md rule: it accepts only closed enums and exact identities (no `path`,
SQL, regex, glob or host path), it reads only accepted hash-verified `graph` shards, it never runs
an analyzer, every row retains source identity and resolving evidence, and truncation or missing
coverage is returned as a gap. Full specification in section 5.

### D3 Model-facing fact families are only those an R4 predicate needs

`control_flow` (basic blocks, branch edges) and `ast_ir_cpg_mapping` (cross-representation node
links) are **not** model-facing families. Dominance and CFG are inputs the producer uses to compute
guard facts; representation links are inputs the cross-checker uses. Publishing raw CFG to a model
would invite reconstruction of reachability by prose, which R3 forbids anyway. Section 4 defines the
seven families that remain.

### D4 Job topology: raw export in `job_codeql_analysis`, normalization in a new `job_code_graph_index`

`job_codeql_analysis` gains an `export.scopes` step that runs the hash-pinned export query pack
against each successful database and retains bounded raw JSON exports as run-owned artifacts. A
new job, `job_code_graph_index`, consumes those artifacts plus the accepted clangd, LLVM IR, Clang
AST, Tree-sitter, CodeQL observation and prioritization shards, and publishes the `graph` index.
`job_review_data_indexing` accounts for both and gains a `code_graph` matrix lane. Section 7 gives
the DAG, fingerprints and Dagster placement. Extending `job_cpg_analysis` is rejected (no
producer), and putting normalization inside `job_review_data_indexing` is rejected because graph
rule changes must not rerun the inventory audit and because the audit must see the graph job as an
ordinary producer.

### D5 Rollout: C/C++ first, then Java/Kotlin, JavaScript/TypeScript, Python; Go/C#/Rust when their CodeQL scopes succeed; PHP never through this plan

Section 8 gives the order and the evidence for it.

## 3. Vocabulary and identities (the shared contract)

The contract below is what the shared-contract chunk (section 10, C0) commits before any other
chunk starts. Names are final; chunks import them and never edit them.

### 3.1 Entity kinds and relation kinds

Additions to `retrieval/model.py::EntityKind`:

| Kind | One record is | Location |
|---|---|---|
| `call_site` | one call expression in an accepted function with its resolved or unresolved callee | the call expression span |
| `sink_site` | one catalog-classified dangerous use (call argument, write, conversion) | the sink expression span |
| `entry_point` | one catalog-classified input source (parameter, call result, field read) with its source class | the source expression or parameter span |
| `flow_summary` | one function's intraprocedural dataflow summary | the function definition span |
| `dataflow_path` | one bounded ordered source→sink path with its steps, guards and sanitizers | the sink span (steps carry their own locations) |
| `guard_fact` | one condition's dominance relation to one sink, with polarity | the condition span |
| `range_fact` | the computed interval of one sink operand | the operand span |

Addition to `RelationKind`: `GUARDS` (`guard_fact` → `sink_site`). Existing kinds are reused:
`CONTAINS` (function `symbol` → `call_site`/`sink_site`/`entry_point`), `CALLS` (`call_site` →
callee `symbol`), `FLOWS_TO` (`entry_point` → `sink_site`, payload `path_id`), `DERIVED_FROM`
(fact → the CodeQL `tool_observation`, `review_flow_step`, clangd `symbol`, `ir_entity` or
`ast_node` it was correlated with), `SAME_AS` (SARIF step ↔ path step, always with the mapping
method; `exact=false` unless byte spans are equal), `CONTRADICTS` (cross-check disagreement).

Graph facts for a language that has no accepted `symbol` producer (every CodeQL language except
C/C++ today) are contained by a `symbol` entity that the graph job itself publishes into the
`graph` shard from CodeQL's function export, with `producer = codeql-export`, exact location and
`mapping_method = codeql-location-exact`. Symbol identities therefore differ from clangd's for the
same C/C++ function; the cross-checker publishes `SAME_AS` with `exact=true` only when the
definition byte span is equal, otherwise `ambiguous` with the method `name-and-file`.

### 3.2 Closed vocabularies (`graph/contract.py`)

| Vocabulary | Values |
|---|---|
| `FAMILIES` | `call_site`, `sink_site`, `entry_point`, `flow_summary`, `dataflow_path`, `guard_fact`, `range_fact` |
| `MODES` | `callers`, `callees`, `sinks`, `entry_points`, `paths`, `guards`, `ranges`, `summary`, `sarif_path` |
| `DISPATCH` | `direct`, `virtual_resolved`, `function_pointer_resolved`, `template_instantiation`, `unresolved_indirect`, `external_undefined`, `secondary_only` |
| `SINK_CLASSES` | `memory_write`, `memory_read`, `allocation_size`, `format_string`, `command_execution`, `path_access`, `sql_query`, `code_injection`, `deserialization`, `integer_conversion`, `crypto_misuse`, `log_output` |
| `SOURCE_CLASSES` | `remote`, `local_user`, `argv`, `environment`, `file`, `ipc`, `database`, `internal` |
| `GUARD_STATES` | `dominating`, `non_dominating`, `post_dominating_only`, `none` |
| `GUARD_POLARITY` | `true_branch`, `false_branch`, `unknown` |
| `CROSS_CHECK_STATES` | `agree`, `disagree`, `not_covered`, `partial` |
| `COVERAGE` | `complete`, `partial`, `unavailable` (shared with every other index) |
| `PRODUCERS` | `codeql-export`, `clangd`, `llvm-ir`, `clang-ast` |

Sink and source classes are assigned by the versioned catalog `rules/codeql-graph-export/catalog.json`
(`appsec-review/graph-catalog/1`), which maps CodeQL model identities (for C/C++: the
`cpp-all` `FlowSource`/`RemoteFlowSource` classes, `ArrayFunction`, `FormattingFunction`,
`AllocationFunction`, `strcpy`/`memcpy` family models, and the CERT pack's sink predicates) and
explicit API names to one class and, for sinks, a CWE family. A sink or source CodeQL reports that
the catalog does not classify is published with class `unclassified` and is never
`direct_eligible`.

### 3.3 Identities

`LogicalIdentity.derive(kind, target_snapshot, native_identity)` with these native identities:

| Kind | `native_identity` |
|---|---|
| `call_site` | `{scope_id, caller_symbol, path, start_byte, end_byte, callee_name}` |
| `sink_site` | `{scope_id, path, start_byte, end_byte, sink_class, argument_index}` |
| `entry_point` | `{scope_id, path, start_byte, end_byte, source_class}` |
| `flow_summary` | `{scope_id, function_symbol, rule_version}` |
| `dataflow_path` | `{scope_id, source_identity, sink_identity, step_locations_sha256}` |
| `guard_fact` | `{scope_id, sink_identity, condition_path, condition_start_byte, condition_end_byte}` |
| `range_fact` | `{scope_id, sink_identity, operand_index}` |

For the explicit `guard_state = none` fact, which has no condition, the condition fields are the
sink's own path and byte span (`contract.none_guard_native`). This gives exactly one `none` fact
per sink, distinct from every real condition.

`scope_id` is the CodeQL scope identity (language + build unit + database identity), so a rebuilt
database yields new facts and the old ones disappear with the old shard. Native CodeQL element
ids, clangd USRs and IR register names never enter an identity or a payload; they stay in the
protected raw export.

### 3.4 Fact payload (`appsec-review/graph-fact/1`)

```json
{
  "schema": "appsec-review/graph-fact/1",
  "family": "dataflow_path",
  "producer": {"name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "…",
               "catalog_version": "appsec-review/graph-catalog/1", "rule_version": "graph-normalize/1"},
  "scope": {"scope_id": "…", "language": "c/c++", "build_unit_id": "…", "component_id": "…"},
  "exact": true,
  "coverage_status": "complete",
  "gaps": [],
  "cross_check": {"rule": "graph-cross-check/1", "state": "not_covered", "producers": []},
  "admissibility": {"rule": "graph-fact-admissibility/1", "direct_eligible": true,
                    "ineligibility_reasons": []},
  "result": { "…family-specific, see section 4…" },
  "upstream": [{"index": "observations", "shard_id": "codeql-cpp-…", "sha256": "…"}],
  "authority": "computed from accepted run-owned evidence; a graph fact is not a tool finding"
}
```

`admissibility.direct_eligible` is computed deterministically by the producer under
`graph-fact-admissibility/1`: true only when (a) the fact's own location and every embedded step,
condition or operand location is `exact` with `confidence = 1.0`, (b) `coverage_status =
complete` for the fact (no truncated step list, neighbor list or path set *for this fact*),
(c) `cross_check.state ∈ {agree, not_covered}`, and (d) for `sink_site`/`entry_point`/`dataflow_path`
the class is not `unclassified`, and (e) for `range_fact` the operand has an applicable interval
(a `not_applicable` operand, such as a pointer or floating value, gives `range_not_applicable`). Every false condition is named in `ineligibility_reasons`. The
review validator re-checks the flag at citation time (section 6); a model cannot set it.

## 4. Fact families: semantics, producers, soundness gaps, predicates

Common rules for all families: every fact names its scope, producer identities and upstream shard
hashes; every location resolves against the accepted snapshot or is `ambiguous` with its method;
a bound that was hit is a gap on the fact *and* on the shard coverage row; an empty family for a
scope whose export failed is `unavailable`, never an empty complete result.

### 4.1 `call_site` (call graph)

- **Producer.** CodeQL export query `CallSites.ql`: every `Call` in an accepted function with
  `getTarget()` resolution; C++ virtual calls resolved through `VirtualDispatch` list every
  possible target as separate facts with `dispatch = virtual_resolved` and the candidate count;
  function-pointer calls with a resolved target set use `function_pointer_resolved`; calls whose
  target set is empty are published as `unresolved_indirect`; calls to declared-but-undefined
  functions (system libraries) as `external_undefined` with the declared name.
- **Cross-check (C/C++).** clangd `CALLS` edges by exact caller/callee symbol spans; LLVM IR and
  Clang AST by callee name within the same TU. Section 2 D1 gives the states.
- **Result.** `{caller: {symbol, display}, callee: {symbol|null, display, dispatch,
  candidate_count}, argument_count, in_loop: bool|unknown, cross_check}`.
- **Soundness gaps it must publish.** Unresolved indirect calls are listed, not dropped; the
  per-function neighbor bound (`max_neighbors_per_function`) truncates deterministically by
  identity and records `truncated_neighbors`; inline assembly and macro-generated calls CodeQL
  does not model are a scope-level gap; functions outside the accepted sources are
  `external_undefined`.
- **R4 predicates.** Direct for `affected_construct` when the call is the construct the claim
  names. Indirect for every other predicate (one hop is not reachability).

### 4.2 `callers` / `callees` to depth N in one bounded call

Not a stored family: the tool computes the bounded closure at query time over `call_site` facts and
`CALLS` relations in the accepted shard, which is a bounded index read, not analysis. Depth ≤
`max_call_depth` (default 3, configured in TOML and enforced in `RetrievalCore` like
`limits.max_depth`), total rows ≤ `limit`, deterministic order `(depth, identity)`. Every
`unresolved_indirect` call site encountered on the frontier is returned as a row so that the
reviewer sees where the closure is unsound; reaching any bound returns `truncated: true` and a
gap naming the bound. The response never claims "no callers": an empty closure is accompanied by
the scope's coverage row.

### 4.3 `sink_site` and `entry_point` (source/sink/sanitizer catalog)

- **Producer.** `SinkSites.ql` and `SourceSites.ql` over the catalog (section 3.2); sanitizers are
  not a family of their own: each `dataflow_path` lists the sanitizer call sites CodeQL's
  configuration recognized on the path, and `SinkSites.ql` emits, per sink, the count of
  catalog-recognized sanitizer calls that dominate it.
- **Result (`sink_site`).** `{sink_class, cwe_family, api: {display, declared_in}, argument_index,
  enclosing_function: {symbol}, dominating_sanitizer_count, catalog_rule}`.
- **Result (`entry_point`).** `{source_class, api_or_parameter: {display}, enclosing_function:
  {symbol}, exposure: {basis: "codeql-model" | "catalog-api" | "declared-contract", contract_id:
  null}, catalog_rule}`. `exposure.basis = declared-contract` is reserved for a future
  `job_interface_contracts` join; until then the only bases are the CodeQL model class and the
  catalog API name.
- **Soundness gaps.** Unclassified sinks/sources are published with `unclassified` class;
  the catalog version is part of the fact; frameworks CodeQL has no model for leave sources
  undetected, which is published as the scope gap `source_model_coverage: codeql-cpp-all/<version>`.
- **R4 predicates.** `sink_site`: direct for `affected_construct`. `entry_point`: direct for
  `attacker_input_control` only when `source_class ∈ {remote, local_user, argv, environment, file,
  ipc}` (the catalog's attacker-reachable classes; see open question 2) and indirect for
  `internal` and `database`.

### 4.4 `flow_summary` (function dataflow summaries)

- **Producer.** `FlowSummaries.ql`: per accepted function, the set of (input, output) pairs with
  input ∈ {parameter i, `*parameter i` (one level), global g} and output ∈ {return, `*parameter j`,
  global g, internal sink class}, computed intraprocedurally with CodeQL's local dataflow plus one
  level of field access; `k_limited: true` when the configured pair bound was hit.
- **Result.** `{function: {symbol}, pairs: [{from, to, kind: data | taint}], sanitizes:
  [sanitizer api], k_limited, recursion_collapsed}`.
- **Soundness gaps.** Pair bound, field depth 1, recursion collapsed to the function itself, calls
  to `external_undefined` functions treated as opaque (listed in `opaque_calls`).
- **R4 predicates.** Indirect for every predicate (a summary is a building block; the path family
  carries the admissible claim). It may qualify.

### 4.5 `dataflow_path` (entry → sink reachability)

- **Producer.** `Paths.ql`: a `TaintTracking::Global` configuration whose sources are the catalog
  `entry_point` set and sinks the catalog `sink_site` set, exported as path rows (`PathGraph`
  edges flattened into ordered steps) with at most `max_paths_per_sink` shortest paths per sink
  (ties by step-location hash) and `max_path_steps` steps per path. Guards and sanitizers on the
  path are joined from the same database (`Guards.ql` rows for the path's sink and the
  configuration's `isBarrier`/`isSanitizer` hits).
- **Result.** `{source: {entry_point, source_class}, sink: {sink_site, sink_class, cwe_family},
  steps: [{n, location, role: source | step | call | return | sink, symbol, display}],
  hop_count, call_depth, guards: [guard_fact ids], sanitizers: [{location, api}],
  truncated_steps: bool, selection: "shortest-k"}`. Each step location is a full
  `SourceLocation`.
- **Soundness gaps.** Paths beyond the per-sink bound are counted in `omitted_paths` on the sink's
  coverage row ("other paths exist" is reported, their shape is not); a path with any ambiguous
  step location is `exact=false`; CodeQL's own `--max-paths`-style limits are superseded by the
  export's explicit bounds; unmodeled external calls on the path are listed as
  `opaque_steps`.
- **R4 predicates.** Direct for `source_to_sink_reachability` (support) and, when the path's
  `source_class` is attacker-reachable (4.3), direct for `attacker_input_control` (support). A
  path can never contradict reachability; absence of a path is a gap, never `not_reachable`
  evidence (see 4.8).

### 4.6 `guard_fact` (guard/dominator facts at sinks)

- **Producer.** `Guards.ql`: for each `sink_site`, every `GuardCondition` that controls the sink's
  basic block (`controls(block, polarity)`), with the condition expression display, the compared
  operand when it is the sink operand or an alias CodeQL's local flow connects to it, and the
  dominance state; plus one `none` fact per sink with no controlling guard.
- **Result.** `{sink: {sink_site}, guard_state, polarity, condition: {display, location},
  constrains_sink_operand: true | false | unknown, comparison: {operator, bound_display} | null}`.
- **Soundness gaps.** Guards on operands CodeQL cannot connect to the sink operand are
  `constrains_sink_operand = unknown`; conditions inside macros map to the expansion site with
  `exact=false`; `post_dominating_only` guards (checks after the sink) are listed separately and
  are never `direct_eligible` for a *present* guard claim.
- **R4 predicates.** Direct for `missing_or_ineffective_guard`: a `none` or `non_dominating` fact
  supports it; a `dominating` fact with `constrains_sink_operand = true` contradicts it. The
  validator records the relation the citing role chose; R5 decides. Indirect for other
  predicates (may qualify `attacker_input_control`).

### 4.7 `range_fact` (range facts at sinks)

- **Producer.** `Ranges.ql` over `SimpleRangeAnalysis`: for each sink operand of integral type,
  `lowerBound`, `upperBound`, signedness, bit width, and the conversion chain (promotion,
  sign change, narrowing) from the operand's definition to the sink.
- **Result.** `{sink: {sink_site}, operand_index, type: {display, signed, bits}, interval:
  {lower, upper} | "unknown", conversions: [{kind, from_type, to_type, location}], analysis:
  "codeql-simple-range-analysis"}`.
- **Soundness gaps.** `unknown` is stated, never omitted; the analysis is intraprocedural and
  widening-based, published as `precision: may_over_approximate`; floating-point and pointer
  operands are `not_applicable`.
- **R4 predicates.** Direct for `missing_or_ineffective_guard` (a bounded interval that fits the
  destination contradicts; an unbounded interval or a sign-changing conversion supports); indirect
  (qualify) for `attacker_input_control`.

### 4.8 SARIF ↔ graph correlation

Not a family: a deterministic correlation rule (`graph-sarif-correlation/1`) in
`job_code_graph_index` that maps every accepted CodeQL path-problem observation's ordered
`code_flow` steps to `dataflow_path` facts of the same scope. For each observation and
`code_flow`: the sink step must match a `sink_site` location exactly and the source step an
`entry_point` location exactly; intermediate steps are matched by exact byte span, then by
line-only (ambiguous). The result is a `DERIVED_FROM` relation from the `dataflow_path` to the
`tool_observation` with payload `{code_flow, matched_steps, ambiguous_steps, unmatched_steps,
state: bridged | partial | broken}`, and `SAME_AS` relations between `review_flow_step` entities
(when the prioritization shard is accepted) and path steps. `broken` correlations are published,
so a CodeQL alert whose flow the export cannot reproduce is visible as such. The `sarif_path` mode
(section 5) returns the correlated paths with their states.

Correlation is not evidence of anything by itself; it lets the verifier move from a
`tool_observation` (direct for reachability only by its rule mapping) to a `dataflow_path` whose
steps, guards and ranges are inspectable.

### 4.9 Absence and negative conclusions

No family can state "no path", "no caller" or "no sink". Every negative is a scoped coverage row
(`graph:<scope_id>:<family>` with `complete | partial | unavailable`), and `coverage` must be
consulted before a negative conclusion, as R3 already requires. A `complete` coverage row plus an
empty `paths` result for a sink means "no path within the catalog, bounds and model coverage of
this export", which the response states verbatim in its gap text.

## 5. `query_code_graph` specification

### 5.1 Schema (added to `mcp/schema.py::TOOLS`, mirrored in `docs/schemas/retrieval-mcp-tools.json`)

```json
{"name": "query_code_graph",
 "description": "Query accepted, hash-verified code-graph facts (calls, sinks, entry points, paths, guards, ranges, summaries) by mode and exact subject identity; no analysis runs during retrieval and every bound reached is a gap.",
 "inputSchema": {"type": "object", "additionalProperties": false, "required": ["mode", "subject"],
  "properties": {
   "mode": {"type": "string", "enum": ["callers", "callees", "sinks", "entry_points", "paths", "guards", "ranges", "summary", "sarif_path"]},
   "subject": {"type": "string", "pattern": "^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$"},
   "depth": {"type": "integer", "minimum": 1, "maximum": 4},
   "sink_class": {"type": "string", "enum": ["memory_write", "memory_read", "allocation_size", "format_string", "command_execution", "path_access", "sql_query", "code_injection", "deserialization", "integer_conversion", "crypto_misuse", "log_output", "unclassified"]},
   "source_class": {"type": "string", "enum": ["remote", "local_user", "argv", "environment", "file", "ipc", "database", "internal", "unclassified"]},
   "limit": {"type": "integer", "minimum": 1, "maximum": 100},
   "cursor": {"type": "string", "maxLength": 4096}}}}
```

No `path`, `name`, `language` or free text: subject kinds carry scope. `depth` is accepted only
for `callers`/`callees` and is capped at `min(4, settings.max_call_depth)`; other modes reject it
(`schema_violation`). `sink_class` applies to `sinks` and `paths`; `source_class` to
`entry_points` and `paths`.

### 5.2 Modes

| Mode | Accepted subject kinds | Returns | Order |
|---|---|---|---|
| `callers` | `symbol` | `call_site` rows whose callee is the subject, then their callers' callers, to `depth`; each row carries `depth`; unresolved call sites on the frontier are rows with `dispatch = unresolved_indirect` | `(depth, identity)` |
| `callees` | `symbol` | `call_site` rows contained by the subject function, transitively to `depth` | `(depth, identity)` |
| `sinks` | `symbol` (function), `source_file`, `component`, `review_unit` | `sink_site` rows in that scope, optionally filtered by `sink_class` | `identity` |
| `entry_points` | `symbol`, `source_file`, `component`, `review_unit` | `entry_point` rows, optionally filtered by `source_class` | `identity` |
| `paths` | `sink_site`, `entry_point`, `symbol` (paths with a step in the function), `source_file` | `dataflow_path` rows, with embedded steps | `(hop_count, identity)` |
| `guards` | `sink_site` | `guard_fact` rows for that sink, including the `none` fact | `(guard_state, identity)` |
| `ranges` | `sink_site` | `range_fact` rows for that sink's operands | `(operand_index, identity)` |
| `summary` | `symbol` | the function's `flow_summary` row | — |
| `sarif_path` | `tool_observation` (CodeQL) | correlated `dataflow_path` rows with the correlation state per `code_flow`; a `broken` correlation returns the state and a gap, not a fabricated path | `(code_flow, identity)` |

A subject kind the mode does not accept is a `schema_violation` denial, not an empty result.

### 5.3 Bounds, pagination, determinism

- Reads only shards of the `graph` index whose `producer.family` matches the mode's family, in the
  capability's index allowlist; the core uses the existing `_request_hash` cursor binding so a
  cursor is valid only for the identical request and manifest.
- `limit` ≤ `limits.max_results`; `depth` ≤ `limits.max_depth` and `settings.max_call_depth`;
  closure expansion is bounded by `limit + 1` rows and a per-call deadline, like `trace`.
- Every response carries the scope coverage rows for the subject's scope and family
  (`coverage_gaps`), the shard identities read, and `truncated` when any bound was reached. A
  subject whose scope has no accepted `graph` shard yields `[]` with the gap
  `accepted graph <family> index is unavailable for <scope or language>`.
- Results are entity records in the standard envelope (`identity`, `kind`, `native_id`, `name`,
  `payload`, `location`, `index`, `shard_id`) so that a cell can cite any returned identity and
  the validator can re-resolve it through `find`.

### 5.4 Capability and roles

- `review/capability.py::TOOL_INDEXES["query_code_graph"] = {"graph"}`; `subject` is already in
  `IDENTITY_PARAMETERS`, so entity-scope checks apply unchanged.
- `pipeline/guidance/registry.json` role tools: add `query_code_graph` to `hypothesis_hunter`,
  `red_team_analyst`, `blue_team_refuter` and `independent_verifier`. The verifier needs it to
  independently re-derive a path and its guards (R6: at least one supporting relation per
  predicate from its own retrieval). `mcp/capability.py::_ROLE_TOOLS` gets the same addition.
- Package `retrieval.query_sets` is complemented by `retrieval.graph_families` listing the families
  accepted for the package's scope, so a cell knows what it may ask before spending queries.

### 5.5 Mapping to EntityKinds and RelationKinds

| Response row | `kind` | Relations the row's shard holds (reachable through `trace`) |
|---|---|---|
| callers/callees | `call_site` | `CONTAINS` from caller `symbol`; `CALLS` to callee `symbol`; `CONTRADICTS`/`DERIVED_FROM` to cross-check entities |
| sinks | `sink_site` | `CONTAINS` from function `symbol`; `GUARDS` from `guard_fact`s; `FLOWS_TO` from `entry_point`s |
| entry_points | `entry_point` | `CONTAINS`; `FLOWS_TO` to `sink_site`s (payload `path_id`) |
| paths | `dataflow_path` | `DERIVED_FROM` to `tool_observation` (correlation); `SAME_AS` to `review_flow_step` |
| guards | `guard_fact` | `GUARDS` to `sink_site` |
| ranges | `range_fact` | `DERIVED_FROM` to `sink_site` |
| summary | `flow_summary` | `DERIVED_FROM` to function `symbol` |

## 6. R3 admissibility: precise update

The R3 table in [`inference-security-review.md`](inference-security-review.md) gains one row and
`review/evidence.py` gains one classification branch, versioned `evidence-admissibility/2`:

| Admissibility | Cited entity kinds |
|---|---|
| direct only for the predicate the graph-fact family's versioned mapping names (`graph-fact-predicates/1`), and only when the re-resolved fact's `admissibility.direct_eligible` is `true` | `call_site`, `sink_site`, `entry_point`, `dataflow_path`, `guard_fact`, `range_fact` |
| indirect for every predicate | `flow_summary`, and every graph kind above whose `direct_eligible` is `false` |

`graph-fact-predicates/1` (a constant in `review/obligations.py`, next to the predicate enum):

| Family | Direct for | Condition beyond `direct_eligible` |
|---|---|---|
| `call_site` | `affected_construct` | — |
| `sink_site` | `affected_construct` | — |
| `entry_point` | `attacker_input_control` | `result.source_class` in the attacker-reachable set of the catalog version |
| `dataflow_path` | `source_to_sink_reachability`; `attacker_input_control` | the second only when `result.source.source_class` is attacker-reachable |
| `guard_fact` | `missing_or_ineffective_guard` | — |
| `range_fact` | `missing_or_ineffective_guard` | — |

Rules:

1. `classify(kind, predicate, rule_predicates, fact_payload)` returns
   `DIRECT_FOR_MAPPED_PREDICATE` only when all three hold: the kind is a graph kind, the predicate
   is mapped for the family (with the family's condition), and the **re-resolved** payload (not the
   model's copy) has `direct_eligible = true`. Otherwise `INDIRECT`. The payload is read inside
   `resolve_relation` from the `find` result, so a model-supplied flag has no effect.
2. `precomputed_fact` stays in `REFERENCE_KINDS` (indirect for every predicate). `hotspot_context`
   and `review_package` facts that embed graph identities are search aids; the embedded identity
   must be cited itself.
3. A `tool_observation` from CodeQL keeps its `tool-rule-predicates/1` mapping. Red cells are
   expected, and the verifier is required by its task prompt, to cite the correlated
   `dataflow_path` (through `sarif_path`) rather than the observation alone when one exists; this
   is guidance, not a validator rule, because a `broken` correlation must not make a real alert
   inadmissible.
4. Contradiction is symmetric data: a `guard_fact` cited with `CONTRADICTS` on
   `missing_or_ineffective_guard` by blue, and a `guard_fact` cited with `SUPPORTS` by red, are both
   direct; R5 row 3 yields `insufficient_evidence` with `unresolved_contradiction`, which is the
   intended outcome until a human or a later rule ranks guard semantics.
5. Absence of a graph fact is never a relation. A blue cell arguing `not_reachable` must cite a
   `dominating` guard or a bounded `range_fact` (direct contradictions of
   `missing_or_ineffective_guard`), or nothing: R5 row 4 (`not_reachable`) can therefore only be
   reached through a direct contradiction on `source_to_sink_reachability`, which no graph family
   provides, so `not_reachable` remains reserved for future dynamic or deployment evidence. This is
   deliberate: static absence is a gap.

The triage gate (lane B) counts predicates with direct support in the proposed citations. With
graph kinds mapped, a hypothesis that cites a `dataflow_path`, its `sink_site` and a `none`
`guard_fact` scores three of four required construct predicates before any model prose, which is
the intended ordering effect.

## 7. Job topology, scheduling and consumption

### 7.1 Units

```text
job_codeql_analysis
  plan.inventory -> database.scopes -> query.scopes -> normalize.scopes
                                    \-> export.scopes (new) ------------\
                                                                         \
job_code_graph_index (new)                                                \
  load.accepted_inputs -> normalize.scopes -> crosscheck.scopes -> correlate.scopes -> acceptance.publish_handoff
      ^ accepted: codeql (exports + observations), cpp_symbol_index, cpp_compiled_analysis (AST, IR),
        tree_sitter_ast, review_prioritization (flow steps), target_catalog (source hashes)

job_review_data_indexing
  matrix.coverage gains the `code_graph` lane; audit sees job_code_graph_index datasets;
  GRAPH_FOLLOW_UP becomes computed from accepted graph coverage instead of a constant list.
```

`export.scopes` depends on `database.scopes` only and runs concurrently with `query.scopes`
under the job's `concurrency` bound; an export failure is a scope-level gap that never invalidates
the database or the SARIF profiles (and the reverse). The export action is a new
`CodeQLExecutor` action `export` that runs `codeql database run-queries` for the pinned pack and
`codeql bqrs decode --format=json` per query with an explicit row bound, writes
`data/codeql/scopes/<scope-id>/exports/<query-id>.json` and an `export-manifest.json` (per-query
row count, truncation, SHA-256, decode duration), and is retained as a run-owned artifact with
disposition `artifact_only` (safe metadata indexed by the inventory; the raw rows hold CodeQL
internal ids and are never served).

### 7.2 Product DAG and invalidation

| Product | Keyed by | Rebuilt when | Not rebuilt when |
|---|---|---|---|
| CodeQL database | unchanged (`_database_identity`) | source, build recipe, extractor, runtime change | export pack or catalog change |
| Raw export (`export-checkpoint.json`) | database identity + tree sha, export pack sha and version, `export_queries` settings (row bounds, timeouts), runner version | export pack, catalog query text, bounds change | SARIF suite change |
| `graph` shard per `(scope, family)` | export artifact hashes, catalog sha, `graph-normalize/1`, `graph-cross-check/1`, `graph-sarif-correlation/1`, `graph-fact-admissibility/1`, the exact upstream shard identities read (clangd, IR, AST, observations, priority), bounded settings | any of those | SARIF suite or prioritization heuristics that do not change the shards read |
| `code_graph` matrix lane, follow-ups | accepted `graph` shard identities | graph shards change | — |
| `hotspot_context`, `review_package` (stage 3, later) | their declared inputs including `graph` shard identities | graph shards change | — |

Publication reuses `indexing/derive.py::publish_derived` semantics: fingerprint over the inputs,
checkpoint next to the shard, hash re-verified on reuse, unverifiable leftovers deleted. The
graph job composes its manifest onto the current accepted manifest and replaces only its own
earlier shards, like `job_cpp_symbol_index`.

### 7.3 Resume fingerprints and Dagster visibility

- `job_code_graph_index` scopes are the CodeQL scopes of the accepted handoff; the scope
  checkpoint identity binds scope id, database identity, export manifest hash, every secondary
  shard identity, rule versions, settings and the job implementation hash (the same pattern as
  `cpp_index_scopes.checkpoint_identity`). A changed accepted CodeQL handoff fails the load unit
  with an integrity error rather than silently mixing exports from two attempts.
- Dagster `wave1_review`: `job_code_graph_index` depends on `job_codeql_analysis`,
  `job_review_prioritization` and, when registered, `job_cpp_symbol_index`,
  `job_cpp_compiled_analysis` and `job_tree_sitter_ast`; `job_review_data_indexing` adds it as a
  dependency. Each unit is a visible op; per-scope results are op metadata with counts and gaps.

### 7.4 Coverage and gap accounting

Per `(language, build unit / scope, family)` coverage row in the `graph` shard and as a
`code_graph` lane cell in `job_review_data_indexing`'s matrices:

| State | Meaning |
|---|---|
| `complete` | database succeeded, export succeeded within bounds, every fact of the family exact, no cross-check disagreement |
| `partial` | export truncated rows, facts with ambiguous locations, unresolved indirect calls present, cross-check disagreements, catalog `unclassified` facts, or omitted paths |
| `unavailable` | no database for the scope, export failed or timed out, language without an export pack, scope below the catalog's minimum model coverage |

The `input_source` matrix rows keep their count; `codeql_sarif` becomes the primary graph
producer, `llvm_ir_binary_infer`, `clangd_symbols` and `clang_ast` become cross-check inputs, and
`joern_cpg` stays `artifact_only` with the reason "not a graph producer; see
code-graph-precomputation.md".

### 7.5 Inference consumption

- **Packages (schema v4).** `context` gains roles `entry_point`, `sink`, `path`, `guard`, `range`
  bounded by `max_context_entries`; lead packages for CodeQL leads embed the correlated
  `dataflow_path` ids (state `bridged` or `partial`) and the sink's `guard_fact`/`range_fact` ids;
  hunt packages embed, per unit, the `sink_site` identities by class (bounded), `entry_point`
  identities by class (bounded) and the counts beyond the bound as `omitted_context`. Package
  `coverage_gaps` carry the unit's `code_graph` lane state.
- **Lane B availability.** `available_sources` gains `source_sink_facts` when the unit's scope has
  an accepted `sink_site` family (any state but `unavailable`) and `entry_point_catalog` when it
  has an accepted `entry_point` family. This unlocks `entry_down` for the first time and makes
  `sink_up` depend on real sink facts; the `symbol_links` alternative in `STRATEGY_SOURCES` is
  removed (open question 3 records the alternative of keeping it as a weaker fallback).
- **Triage predicate counting.** Unchanged code path; graph kinds now count through
  `classify` (section 6).
- **Capabilities.** Section 5.4.

## 8. Language rollout, scope, fallbacks

Order and the evidence for it:

1. **C/C++** — the only language with cross-check producers, a hash-pinned custom pack path
   (`cert-cpp`), a native build-capture fixture (`tests/fixtures/build_toolchains/native`), two
   successful live scopes, and the `cpp-all` libraries for guards and ranges. Memory-safety sink
   classes are where guard and range facts matter most.
2. **Java/Kotlin, JavaScript/TypeScript, Python** — successful live scopes (7/7, 12/12, 8/8),
   mature `RemoteFlowSource` models; no cross-check producer (facts are `not_covered`); range
   facts are `not_applicable` for JS/Python and intraprocedural `RangeAnalysis` only for Java.
   Each is its own export pack and catalog section; a language ships only when its recorded
   fixture passes the acceptance suite.
3. **Go, C#, Rust** — blocked by producer reality: Go databases fail because accepted recipes only
   download modules (and the configured Go `security-extended` profile is not in the lock); C#
   lacks an accepted .NET environment; Rust lacks Cargo locks in the fixture. They inherit the
   generic export mechanism once a database succeeds; nothing in this plan is language-specific
   beyond the pack and catalog.
4. **Actions** — not a code graph target; excluded.

Explicitly out of scope: Joern export, LLVM CFG/def-use/dominator extraction, points-to/alias
facts (`aliases` mode of plan B), `contract_enforcement` (`job_interface_contracts`),
`deployment_exposure` (`job_deployment_topology`), `reachability` promotion of `declared` to
`enforced`, dynamic traces, PHP (no CodeQL extractor; it keeps source, Tree-sitter and SAST lanes
only), `hotspot_context` and `review_package` composition (stage 3, after this batch).

Fallbacks when a producer is unavailable, each a named gap and never a clean result:

| Situation | Published state |
|---|---|
| Scope has no CodeQL database (planning gap, failed build) | every family `unavailable` with the CodeQL scope gap; packages carry `code_graph: unavailable`; `sink_up`/`entry_down` fall back to `persona_sweep` with `required_source_unavailable` |
| Export query timed out or exceeded `max_export_bytes` | families from that query `unavailable`; other families from the same database stay usable |
| clangd/IR/AST shard absent for a C/C++ scope | `cross_check.state = not_covered`; facts stay `direct_eligible` (cross-check is a second opinion, not a prerequisite) |
| Export pack or catalog hash differs from the lock | framework-integrity failure in `plan.inventory` (same rule as the SARIF suites) |
| Tree-sitter-only language | no graph facts; the language matrix row says so; no syntactic call-site substitute is published in this batch |

## 9. Risks of the chosen design

- **CodeQL model coverage is the ceiling.** A framework without CodeQL models yields no entry
  points, so `attacker_input_control` stays model-prose for those targets. Mitigation: the catalog
  accepts explicit API names per target class, and the scope gap names the model version.
- **Export cost.** Global taint tracking per database is the most expensive query; bounded by
  `export_timeout_seconds`, `max_paths_per_sink` and `max_path_steps`, with the export never
  blocking SARIF profiles.
- **Shard size.** Call sites for a large C++ build unit can reach millions; `max_facts_per_family_per_scope`
  truncates deterministically and publishes `partial`; the `callers` closure then reports the
  truncation on every affected response. Operators tune the bound in TOML, not in code.
- **Two symbol identity spaces for C/C++.** CodeQL-exported `symbol` entities and clangd `symbol`
  entities coexist; `SAME_AS` links resolve them, and the cross-checker reports when byte spans
  disagree (typically macro-expanded definitions).
- **Guard semantics are shallow.** `constrains_sink_operand` is a local-flow join; a guard on an
  aliased length through a struct field is `unknown`. This is published, so the review treats it
  as a gap rather than a sufficient guard.

## 10. Implementation plan: parallel chunks

The procedure is [`.claude/skills/parallel-implementation/SKILL.md`](../../.claude/skills/parallel-implementation/SKILL.md):
one shared contract first, then independently owned chunks in isolated worktrees, one final
integration chunk. Every chunk runs its tests with a unique `--basetemp=test/tmp/<chunk>`, commits
but does not push, and reports branch, commits, public API, tests, deviations and concerns.
Agent reports are data. Product choices in section 11 go to the user before C0 is committed.

### C0 Shared contract (written by the integrating agent, committed before any chunk starts)

Owned files: `src/appsec_review/graph/__init__.py`, `src/appsec_review/graph/contract.py`,
`src/appsec_review/retrieval/model.py` (the seven `EntityKind` values and `GUARDS`),
`src/appsec_review/retrieval/index.py` (`graph` in `INDEX_NAMES`), `tests/graph/__init__.py`,
`tests/graph/test_contract.py`, `tests/fixtures/graph/__init__.py`.

Content: section 3 vocabularies as `StrEnum`s; `GRAPH_FACT_SCHEMA`, `EXPORT_SCHEMA =
appsec-review/codeql-graph-export/1` (the raw export JSON contract that C1 produces and C3
consumes: one object per query with `query_id`, `columns`, `rows`, `row_count`, `truncated`,
`bqrs_sha256`); `GraphFact` dataclass with `to_entity()`; identity helpers per family
(section 3.3); `direct_eligible` evaluation function (section 3.4) as pure code over a payload;
`GRAPH_FACT_PREDICATES` mapping (section 6) imported by `review/obligations.py`; `GraphSettings`
dataclass with the TOML bounds and defaults (`max_call_depth=3`, `max_neighbors_per_function=200`,
`max_paths_per_sink=8`, `max_path_steps=40`, `max_guards_per_sink=16`,
`max_facts_per_family_per_scope=200000`, `max_export_bytes=268435456`,
`export_timeout_seconds=1800`); the tool name constant `QUERY_CODE_GRAPH = "query_code_graph"`
and the mode/subject-kind table.

Unit tests: every enum is closed and sorted-stable; identities are deterministic and change when
any native field changes (property test over random payloads with Hypothesis-free parametrized
cases); `to_entity()` rejects a payload with a non-exact location but `direct_eligible=true`;
`direct_eligible` evaluation returns every ineligibility reason (truth-table test over the four
conditions); `GRAPH_FACT_PREDICATES` covers exactly the six families and the predicate enum
values; `EXPORT_SCHEMA` validator rejects extra keys, unsorted rows, and `row_count != len(rows)`
unless `truncated`.

### C1 CodeQL export pack, catalog and runner action (depends on C0 for the export JSON contract only)

Owned files: `rules/codeql-graph-export/README.md`, `rules/codeql-graph-export/catalog.json`,
`rules/codeql-graph-export/catalog.schema.json`, `rules/codeql-graph-export/cpp/qlpack.yml`,
`rules/codeql-graph-export/cpp/*.ql` (`CallSites`, `SinkSites`, `SourceSites`, `FlowSummaries`,
`Paths`, `Guards`, `Ranges`), `rules/codeql-graph-export/cpp/graph-export.qls`,
`containers/tools/codeql/codeql_runner.py` (`export` action), `containers/tools/codeql/assets.lock.json`
(`custom_query_packs.cpp` gains the export pack; `asset_lock_sha256` updated in TOML by C2),
`src/appsec_review/codeql/runtime.py` (`export` in the action set and timeout table),
`tests/test_codeql_export_runner.py`, `tests/fixtures/graph/codeql_export/native/**` (recorded
exports for `tests/fixtures/build_toolchains/native`), `tests/fixtures/graph/codeql_export/synthetic/**`
(hand-authored exports exercising unresolved calls, virtual dispatch, two paths to one sink, a
dominating and a non-dominating guard, an unknown range, a sign-changing conversion, an
unclassified sink, a macro-mapped condition).

Unit tests (offline): runner argv construction for `export` (`run-queries` then `bqrs decode
--format=json --rows <bound>` per query, bounded output, no network); decode of a recorded `bqrs`
JSON into `EXPORT_SCHEMA` objects with `truncated` set when the row bound is hit; catalog schema
validation (every class in the closed vocabularies; every entry names a CodeQL model class or an
API with a declared-in filter; no duplicate rule ids); lock equality check between the pack tree
hash and the lock entry; a tamper test that flips one byte of a recorded export and expects the
manifest hash check to fail. Live tier (`tests/live/test_codeql_graph_export_live.py`, skipped
without the pinned image): the pack compiles, every query runs on the native fixture database,
the decoded rows equal the recorded fixture byte-for-byte (this is how recordings are refreshed:
the test prints the diff and fails until the recording is updated in the same change as the pack).

### C2 `job_codeql_analysis` export step (depends on C0, C1's action name and layout)

Owned files: `src/appsec_review/jobs/job_codeql_analysis/job.py` (unit `export.scopes`,
`_export_one`, export checkpoint identity), `src/appsec_review/jobs/job_codeql_analysis/datasets.py`
(new `codeql_graph_export` dataset, disposition `artifact_only`), `src/appsec_review/jobs/job_codeql_analysis/planning.py`
(lock equality for the export pack), `appsec-review.toml` (`[jobs.job_codeql_analysis.settings.export_queries]`,
`[[...languages.cpp.export_queries]]`, step `export`), `src/appsec_review/config/` typed settings for
the export block, `tests/test_codeql_export_step.py`.

Unit tests: with an injected executor that returns the recorded fixture, the step writes
`exports/*.json` and `export-manifest.json`, publishes the handoff output with hashes, and reuses
the checkpoint on rerun (`export_reused=True`, no executor call); a changed database identity or
pack sha invalidates only the export checkpoint (database and query checkpoints untouched, asserted
by their identities); an executor timeout or non-zero exit yields a scope gap and a `terminal_status`
of `COMPLETED_WITH_GAPS` without touching sibling scopes; a changed export file after checkpoint is
a `FrameworkIntegrityError`; config topology validation rejects a missing `export` step; the
dataset declaration is audited by the existing inventory test harness.

### C3 Graph normalizer (depends on C0 and the C1 fixture format)

Owned files: `src/appsec_review/graph/normalize.py`, `src/appsec_review/graph/catalog.py`,
`tests/graph/test_normalize.py`.

Behavior: `EXPORT_SCHEMA` objects + accepted source file hashes + catalog → `GraphFact`s per
family with `SourceLocation`s mapped through the CodeQL scope's workspace paths (the same prefix
rules as `sarif.py::map_location`, reused not copied), classification through the catalog,
per-fact gaps, `direct_eligible` evaluation, and per-family coverage rows; bounds from
`GraphSettings`.

Unit tests: the synthetic fixture yields the expected fact multiset (golden JSON under
`tests/fixtures/graph/expected/synthetic/`) and is byte-identical across two runs and across
shuffled input rows; a path with one line-only step is `exact=false` and `direct_eligible=false`
with reason `ambiguous_step_location`; an `unresolved_indirect` call is published, counted and
makes the scope coverage `partial`; `unclassified` sink is published and ineligible; the
`max_paths_per_sink` bound keeps the shortest paths by `(hop_count, step hash)` and records
`omitted_paths`; `max_neighbors_per_function` truncation is deterministic by identity; a file
hash mismatch between export and accepted snapshot rejects the scope (`IntegrityError`); no
CodeQL element id string survives into any payload (regex scan of serialized facts); range facts
with `unknown` are present, never omitted; a `post_dominating_only` guard is never eligible for
`guard_state = dominating`.

### C4 Cross-check and SARIF correlation (depends on C0)

Owned files: `src/appsec_review/graph/crosscheck.py`, `src/appsec_review/graph/correlate.py`,
`tests/graph/test_crosscheck.py`, `tests/graph/test_correlate.py`,
`tests/fixtures/graph/secondary/**` (small accepted-style clangd, IR, AST and CodeQL observation
shards built with `IndexBuilder` in a fixture builder, reusing `tests/fixtures/inference_review/builder.py`
patterns).

Unit tests (cross-check): agreement by exact byte span yields `agree`; a clangd edge absent from
CodeQL yields a `secondary_only` fact that is ineligible; a CodeQL edge contradicted by clangd
(different callee symbol at the same call span) yields `disagree`, a `CONTRADICTS` relation with
`exact=false` and an ambiguity text, and `direct_eligible=false`; IR name-only agreement is
`agree` with method `ir-name-same-tu`; AST `CallExpr` without `referencedDecl` is `not_covered`;
absent secondary shards give `not_covered` on every fact and no gap on eligibility.
Unit tests (correlation): a flow whose source and sink steps match exactly and whose middle steps
match by span is `bridged`; one line-only middle step is `partial` with the step listed; a flow
whose sink matches no `sink_site` is `broken` and still published; `SAME_AS` to
`review_flow_step` is emitted only when the priority shard is present; ordering of `code_flow`
indexes is preserved; identical inputs produce identical relation ids.

### C5 `job_code_graph_index` (depends on C0, C3, C4; wave 2)

Owned files: `src/appsec_review/jobs/job_code_graph_index/{__init__,job,datasets,scopes}.py`,
`src/appsec_review/runtime/registry.py` (registration line), `appsec-review.toml`
(`[jobs.job_code_graph_index]` with steps `load`, `normalize`, `crosscheck`, `correlate`,
`acceptance` and the `GraphSettings` bounds), `src/appsec_review/orchestration/dagster/adapter.py`
(wave dependencies), `docs/operations/code-graph-index.md`, `tests/test_code_graph_index_job.py`.

Unit tests: with the C1 recorded export and C4 secondary fixtures staged into a fake accepted run
(the `tests/fixtures/inference_review/builder.py` style), the job publishes one `graph` shard per
`(scope, family)` with coverage rows, composes the accepted manifest without dropping upstream
shards, and its handoff passes `store.accepted_handoff`; rerun reuses every scope checkpoint;
changing the catalog sha rebuilds only graph shards (export checkpoints untouched); a tampered
export file fails the load unit with an integrity error; a scope with a failed database publishes
`unavailable` rows for all seven families and no entities; Dagster op list and dependencies match
the TOML topology (existing adapter tests pattern); `datasets.py` declarations pass the inventory
audit for every output kind, including the `unavailable` path.

### C6 Retrieval tool (depends on C0)

Owned files: `src/appsec_review/retrieval/graph.py` (query implementation),
`src/appsec_review/retrieval/core.py` (`query_code_graph` method delegating to it),
`src/appsec_review/mcp/schema.py`, `src/appsec_review/mcp/adapter.py` (dispatch),
`docs/schemas/retrieval-mcp-tools.json`, `src/appsec_review/review/capability.py`
(`TOOL_INDEXES`), `src/appsec_review/mcp/capability.py` (`_ROLE_TOOLS`),
`tests/test_retrieval_code_graph.py`.

Unit tests: every mode on a fixture `graph` shard built with `IndexBuilder` from C0 facts; subject
kind validation per mode (`schema_violation` for a `source_file` subject in `guards`); `depth`
rejected outside `callers`/`callees` and capped by settings; `callers` closure returns rows ordered
`(depth, identity)`, includes `unresolved_indirect` frontier rows, and stops with `truncated: true`
and a named gap at `limit`; cursor bound to request hash (a cursor replayed with a different
`sink_class` is rejected); the unavailable-shard gap text names the family and scope; coverage rows
accompany every response; the JSON schema document equals `TOOLS` (existing equality test
extended); capability denial of `path`-like values in `subject`; `limits.max_results` enforced;
response byte bound truncation recorded as a gap.

### C7 Review integration (depends on C0; C6's tool name from the contract)

Owned files: `src/appsec_review/review/evidence.py` (`evidence-admissibility/2`, graph branch),
`src/appsec_review/review/obligations.py` (re-export of `GRAPH_FACT_PREDICATES`),
`src/appsec_review/review/packages.py` and `docs/schemas/review-packages.schema.json` (v4 context
roles, `retrieval.graph_families`), `src/appsec_review/jobs/job_inference_security_review/job.py`
(`available_sources` from graph families; policy hash includes the new rule versions),
`src/appsec_review/guidance/routing.py` (`STRATEGY_SOURCES` per section 7.5),
`pipeline/guidance/registry.json` (role tools), `pipeline/prompt-fragments/roles/independent_verifier.md`
and `hypothesis_hunter.md` (bounded sentence: cite the correlated path and its guards when
available), `tests/review/test_graph_admissibility.py`, `tests/review/test_packages_graph_context.py`.

Unit tests: `classify` truth table over (kind × predicate × `direct_eligible` × source class) with
the exact expected admissibility for every cell; `resolve_relation` reads `direct_eligible` from
the re-resolved entity and ignores a model-supplied payload (a fixture where the cited identity
resolves to `direct_eligible=false` while the citation claims true → `INDIRECT`); an unknown graph
kind is default-deny; `satisfies` requires completeness; policy hash changes when the mapping
changes; packages embed graph context bounded by `max_context_entries` with deterministic
`omitted_context`; package ids are stable under shuffled graph input; `available_sources`
contains `entry_point_catalog` only when the unit's scope has an accepted `entry_point` family;
`hunt_panel` launches `entry_down` in that case and falls back with `required_source_unavailable`
otherwise; the triage gate orders a hypothesis citing a `dataflow_path` + `sink_site` + `none`
`guard_fact` above one citing prose only; registry role tools include `query_code_graph` for the
four roles and exclude it for scorer/adjudicator; a verifier cell's R6 check accepts a path it
retrieved itself through `query_code_graph`.

### C8 Indexing accounting (depends on C0; C5's dataset names from the contract)

Owned files: `src/appsec_review/indexing/matrix.py` (`code_graph` lane), `src/appsec_review/indexing/input_matrix.py`
(cell text only; row count unchanged), `src/appsec_review/retrieval/precomputed.py` (retire the
seven graph sets from `QUERY_SETS`), `src/appsec_review/indexing/products.py` (assert the
remaining sets), `src/appsec_review/jobs/job_review_data_indexing/job.py` (`GRAPH_FOLLOW_UP`
computed from graph coverage; the constant list shrinks to the stage-3 and planned sets),
`src/appsec_review/jobs/job_review_data_indexing/datasets.py`, `docs/architecture/indexing-and-query-reuse.md`
matrix cells, `tests/test_review_data_indexing.py` additions.

Unit tests: the matrix test's row-count assertion still holds; `code_graph` lane is `complete`
only for a language with accepted `graph` shards and `unavailable` with the right basis text
otherwise; `cpg_graph` remains `unavailable`; follow-up rows name `hotspot_context`,
`review_package`, `redacted_secret_exposure`, `contract_enforcement`, `deployment_exposure`,
`test_intent` only; `query_precomputed("call_graph")` is now a schema error (enum) rather than an
unavailable gap, and the schema document reflects it; the inventory audit accepts the graph job's
`artifact_only` export dataset only with its named reason.

### C9 Integration and acceptance (after C1–C8 merge)

Owned files: `tests/integration/test_code_graph_end_to_end.py`, `tests/live/test_code_graph_live.py`,
`deploy/dagster/verification/code-graph-acceptance.json` (produced by a live run),
`docs/reviews/code-graph-precomputation-implementation.md`, final doc truth-up of
`docs/operations/codeql-analysis.md`, `docs/operations/review-data-indexing.md`,
`docs/architecture/review-package-contract.md`.

Offline end-to-end (CI, no CodeQL/Joern image): stage the native and synthetic recorded exports
through the real `job_codeql_analysis` (injected executor), `job_code_graph_index`,
`job_review_data_indexing`, package assembly and an injected-worker `job_inference_security_review`;
assert that a lead whose CodeQL observation correlates `bridged` reaches `supported` with direct
relations on `affected_construct`, `source_to_sink_reachability` and `missing_or_ineffective_guard`
from graph kinds, that a hunt unit with sink and entry-point facts launches `sink_up` and
`entry_down`, that the completeness ledger names the `code_graph` lane for an uncovered language,
and that a byte flip in any `graph` shard fails `scope.accept_manifest`.

Live tier (operator-run, skipped in CI): real pinned CodeQL image on
`tests/fixtures/build_toolchains/native` and, when the operator provides it, the
`appsec-multi-vuln` workspace; verifies export execution per scope, recording equality for the
native fixture, at least one `dataflow_path` with ≥ 2 steps and a `guard_fact` on the
multi-vuln C/C++ scope, `query_code_graph` responses for every mode over the accepted manifest,
and reports per-language export/gap counts into the verification JSON.

Regression: the full suite compared against the base commit; only pre-existing failures may remain
and are listed as such.

## 11. Risks, open questions and what is deliberately not done

### Decisions recorded (user, 2026-10-12)

The six questions this plan raised were answered by accepting the plan's recommendation:

1. **Export mechanism:** `bqrs decode --format=json` per query through a new runner `export`
   action; SARIF stays untouched.
2. **Attacker-reachable source classes:** `remote`, `local_user`, `argv`, `environment`, `file`,
   `ipc`; `internal` and `database` are not. This is `ATTACKER_REACHABLE_SOURCES` in
   `graph/contract.py`.
3. **`sink_up` unlock:** `symbol_links` no longer unlocks `sink_up`; only accepted sink facts do.
4. **Verifier access:** `independent_verifier` is granted `query_code_graph`.
5. **Old graph query sets:** the seven sets are retired from `QUERY_SETS` and `query_precomputed`,
   not kept as deprecated members.
6. **Rollout gate:** C/C++ ships first; Java/Kotlin, JavaScript/TypeScript and Python packs follow
   in separate changes, each with its own recorded fixtures.

### Deliberately not done

- No Joern exporter; `job_cpg_analysis` stays as is.
- No LLVM pass; the IR shard remains a cross-check input only.
- No `aliases` mode, no points-to facts.
- No contract, deployment or test-intent promotion; `entry_point.exposure.contract_id` stays `null`.
- No `hotspot_context` or `review_package` composition; they remain stage-3 follow-ups and will
  embed graph identities when built.
- No new skill, persona or prompt authority: role prompt edits are one bounded sentence each.
- No change to the predicate vocabulary (R4) or the adjudication table (R5).
