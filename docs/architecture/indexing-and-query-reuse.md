# Source and code-graph indexing for retrieval

Status: design and inventory. The MCP contract in this document is implemented; the new
precomputation producers are a separate task. A missing product is reported as unavailable.
This document describes review-worker evidence, not instructions to review workers.

## Goal and authority

One accepted run should let retrieval resolve a hotspot to source bytes, syntax, build context,
compiled representations, observed findings, and bounded graph paths. A score or graph edge
prioritizes investigation; it is not a vulnerability finding. Every returned source location must
resolve against the run's accepted target snapshot, and every non-source fact must name a run-owned
artifact and producer. Unresolved mappings and missing coverage are explicit gaps.

The immutable index manifest remains the authority boundary. Jobs may reuse accepted upstream
shards and artifacts whose hashes and configuration identities match. Retrieval must never parse
raw source, LLVM IR, or a CPG during an inference call.

## Current material and missing links

| Material | Current producer and accepted index | What is indexed now | Next indexable addition |
|---|---|---|---|
| Source snapshot | `job_target_catalog`, `source` | file identity, hash, excerpt location | link all representations to the exact snapshot file |
| Tree-sitter syntax | `job_tree_sitter_ast`, `analysis` | bounded AST nodes, spans, parent relations across configured grammars | stable symbol/call-site links and parse-gap coverage |
| C/C++ compiled syntax | `job_cpp_compiled_analysis`, `analysis` AST shard | selected Clang AST records | resolved definitions, references, template and macro origin links |
| C/C++ symbol graph | `job_cpp_symbol_index`, `analysis` | accepted clangd symbols, `CALLS` and `REFERENCES` | bridge symbols to syntax, IR, CPG, and priority items |
| LLVM IR | `job_cpp_compiled_analysis`, `analysis` IR shard | function definitions and uniquely resolved direct `CALLS` | basic blocks, CFG, def-use, memory operations, guards, source mapping |
| Joern CPG | `job_cpg_analysis`, run-owned artifact and unavailable observation shard | retained binary CPG; no retrievable nodes or edges | bounded export of calls, CFG, PDG, data dependencies, and source mappings |
| CodeQL flows | `job_codeql_analysis` observations; `job_review_prioritization`, `priority` | SARIF paths, ordered source-resolved `review_flow_step` nodes and `FLOWS_TO` edges | correlate path steps to symbols, AST, IR, and CPG nodes |
| History and ranking | `job_source_history_analysis`, `job_change_context_analysis`, `job_review_prioritization` | metrics, SII, ranked hotspot items, evidence, one-hop import context | bounded graph context package per selected hotspot |

The AST and IR rows describe their present **partial** extraction. A successful producer run must
not be interpreted as complete semantic or control/data-flow coverage. PHP has no configured
CodeQL extractor; a language without a compiler or CPG branch still gets source and Tree-sitter
coverage when its grammar is supported.

## Reusable job boundaries

1. **Acquire and parse once.** Reuse the accepted catalog, build capture, Tree-sitter, Clang AST,
   LLVM IR, clangd, CodeQL, and Joern outputs. Each extraction job is keyed by snapshot, exact
   input artifact hashes, language/tool identity, typed configuration, and versioned mapping rules.
2. **Normalize per representation.** Publish bounded AST, IR, CPG, and symbol shards independently.
   Preserve native IDs, exact or ambiguous source mapping, edge kind and direction, confidence,
   producer artifact, and parse/extraction bounds. A CPG binary alone is an artifact reference,
   not graph coverage.
3. **Bridge representations.** A separate linker consumes accepted shards. Exact byte spans,
   compiler debug/source maps, and resolved symbol identities can establish links. Name-only or
   line-only matches remain ambiguous and carry their method; no prompt may silently promote them.
4. **Precompute query products.** Independent jobs consume the normalized graph and publish one
   `precomputed` shard per query set and scope. A changed query rule rebuilds its product, while
   unchanged source/AST/IR/CPG shards are reused. The immutable accepted manifest includes every
   product and its gaps. Query jobs never execute target code.
5. **Assemble hotspot context.** Join selected priority items with bounded source excerpts,
   ownership/complexity features, import neighbors, calls, flow paths, guards, and findings through
   accepted identities. Keep the ranking and the supporting evidence distinguishable.

Run outputs remain under `runs/<run-id>/data/`. Configuration, limits, timeouts, and worker pools
belong in central TOML. Producers publish independently testable handoffs; skipped and failed
scopes publish unavailable or partial coverage instead of empty-success records.

## Precomputed query sets for the next task

Each set is an allowlisted `query_set`, with a versioned producer, an exact subject identity or
source path, a bounded result, upstream hashes, and a coverage row named for the set. Products
should reuse the current `IndexBuilder`, `IndexIdentity`, and accepted-manifest publication path.

| Query set | Reused inputs | Suggested bounded fact | Essential gap |
|---|---|---|---|
| `symbol_links` | Tree-sitter, Clang AST, clangd, build maps | declarations, definitions, references, call sites per symbol | unresolved overload, generated source, or parse error |
| `call_graph` | clangd, LLVM direct calls, CPG calls, CodeQL | callers and callees with dispatch method and provenance | unresolved indirect/virtual calls and tool disagreement |
| `control_flow` | LLVM CFG, CPG CFG, syntax | basic blocks, branch edges, exits, exception paths | missing TU, inline asm, or non-exact source map |
| `dataflow` | CPG PDG, LLVM def-use, CodeQL | bounded def-use and source-to-sink subgraphs | unmodeled external call, aliasing, path/step limit |
| `entrypoint_paths` | ingress catalog, summaries, call/dataflow graph | shortest bounded entrypoint-to-sink paths | path depth/count bound and unresolved dispatch |
| `guards_ranges` | CFG dominators, AST conditions, LLVM values | dominating guards, branch polarity, operand width/range | unknown range, optimization, non-exact mapping |
| `sarif_correlation` | CodeQL observations and normalized graphs | each SARIF step mapped to graph nodes/edges | broken or ambiguous hop |
| `ast_ir_cpg_mapping` | source spans, Clang AST, LLVM IR, Joern CPG | cross-representation node links with method/confidence | missing debug/origin information |
| `hotspot_context` | priority, history, all accepted graph products | bounded evidence package around a ranked file/function | per-source missing coverage and context truncation |

The next task should implement these in stages: source/symbol links and calls first; CFG and
dataflow next; then reachability, guards/ranges, correlation, and hotspot packages. It must verify
each language's available producer path and name unsupported combinations. It should test reuse
by changing one query rule and proving unrelated upstream shards are not rebuilt.

## Fact and MCP contract

The `precomputed` index holds `precomputed_fact` entities. An accepted shard's manifest producer
contains its `query_set`. Each fact payload carries
`schema = appsec-review/precomputed-fact/1`, the same `query_set`, `subject_identity` and/or
`subject_path`, bounded computed result, basis, upstream identities, and coverage status. A source
location is attached when it resolves; otherwise the artifact reference and mapping gap remain.
Facts do not inherit the authority of tool findings or source observations.

`query_precomputed(query_set, subject?, path?, limit?, cursor?)` reads only accepted shards for an
allowlisted set. It reports unavailable sets and incomplete coverage. It cannot run analyzers,
accept SQL or graph programs, or scan target files. `query_hotspots(scope?, path?, min_score?,
limit?, cursor?)` returns ranked priority items with metric vectors and evidence links. Existing
`find`, `search`, `trace`, `read_excerpt`, and `coverage` remain the tools for exact nodes,
relationships, source bytes, and gap inspection. Retrieval responses stay run and manifest pinned,
size/time bounded, auditable, and cursor bound to the exact request.

## Acceptance checks for the next task

- Every supported language has a catalog-to-source-to-AST route; compiled/CPG coverage is scoped
  to languages and build units that actually produce it.
- A source-resolved graph path contains ordered nodes and typed edges, not just endpoint line
  numbers. Every missing or ambiguous hop is visible.
- Joern output is decoded by a pinned, bounded exporter into accepted graph shards; a binary-only
  CPG continues to report unavailable graph coverage.
- A fact can be traced back through exact upstream identities and hashes; stale or mismatched
  source mappings are rejected.
- Re-running an unchanged input reuses immutable shards; changes invalidate only dependent
  products. MCP queries read the accepted set and report missing sets truthfully.
