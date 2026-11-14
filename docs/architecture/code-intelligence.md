---
title: "Code intelligence"
kind: "architecture"
subsystem: "code intelligence"
status: "current"
jobs: ["job_binary_evidence_indexing", "job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpg_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_svf_alias_analysis", "job_tree_sitter_ast"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Code intelligence

## As built today

The subsystem converts accepted source, build and binary evidence into bounded, independently
identified retrieval products. It is not one interchangeable “code graph.” The distinction between
written syntax, compiler-resolved relationships, modeled dataflow and scanner judgments survives
normalization and retrieval. This T-132 current-state dive is grounded in the producer handlers;
the dated designs below explain decisions, not additional implemented capability or live acceptance.

**Evidence classes and production boundaries**

| Product | Actual producer path | What the product supports | What it does not establish |
| --- | --- | --- | --- |
| Syntax | Tree-sitter scope planning, locked parsing and host projection | Located AST nodes, containment, written definitions/calls/imports/identifier occurrences | Type/name/module resolution, semantic references, resolved call targets or dataflow |
| Compile and symbol relationships | Accepted compiled catalogs, clangd, Clang AST and LLVM IR | Build/source/output identities; located symbols and supported call/reference/control-flow facts | Complete dynamic dispatch or a vulnerability verdict |
| CodeQL observations | Database/query execution and SARIF normalization | Scanner judgment with exact native-result references and located flow support where resolvable | An adjudicated finding or an exhaustive graph export |
| Graph facts | CodeQL exports normalized by the graph job | Calls, sinks, entry points, summaries, paths, guards and ranges within the exported scope and bounds | Whole-program coverage outside a seeded neighborhood, or automatic independent corroboration |
| Alias cross-check | SVF module planning and normalization | Points-to, indirect targets and memory-object accessors over accepted bitcode | A safe negative when the module/site is open-world, incomplete or truncated |
| Binary-derived context | Frozen decompilation publication indexing | Functions, calls, imports and strings; native pseudo-C backing when permitted | Original-source equivalence; located native pseudo-C for managed code |
| Optional CPG context | Enabled Joern generation and seeded export | Retained CPG bytes and, when exported, bounded per-function context | General usable CPG/PDG coverage merely because a binary was retained |

Tree-sitter is an independent source lane. Its
[planner](../../src/appsec_review/jobs/job_tree_sitter_ast/model.py) partitions accepted files by
component, translation scope, language and bounded chunk. Its
[execution boundary](../../src/appsec_review/jobs/job_tree_sitter_ast/scope_execution.py) separates
target and generated-source mounts and verifies grammar/image identities. The
[projection](../../src/appsec_review/jobs/job_tree_sitter_ast/projection.py) attaches selected
syntax fields to existing nodes without resolving names. Parse coverage and projection coverage
are separate: a valid tree can have only partial or unavailable syntax projection.

Native analysis starts from accepted language-build receipts, not an arbitrary compile command
found during review. The [compiled producer](../../src/appsec_review/jobs/job_cpp_compiled_analysis/job.py)
verifies materialized workspaces/source maps, normalizes compile/link data, and runs its separate
compiled, AST, IR, Infer and binary branches. The
[scope helper](../../src/appsec_review/jobs/cpp_index_scopes.py) is the common input boundary for
clangd, Clang static analysis, Joern and SVF. Unsupported compile inputs are separate skip
decisions, not failed supported translation units. Infer and Clang diagnostics stay scanner
observations even when their traces help graph analysis.

The [CodeQL handler](../../src/appsec_review/jobs/job_codeql_analysis/job.py) has configured
`plan`, `execution` and `acceptance` steps. Inside execution, ready scopes independently advance
through database creation, query profiles, normalization and optional export. Query suites and
graph export are distinct consumers of a verified database. Failed-query SARIF can be retained as
incomplete diagnostic evidence without producing successful observations; zero observations is
explicitly not a clean classification. Manual database creation uses admitted replay/environment
identities rather than inventing a build command.

The [graph producer](../../src/appsec_review/jobs/job_code_graph_index/job.py) reads accepted exports,
normalizes them with the graph catalog and source mapping, cross-checks available native producers,
and correlates scanner code flows. Its seven fact families are defined in the
[graph contract](../../src/appsec_review/graph/contract.py). It publishes family shards, database
cards and [bounded producer neighborhoods](../../src/appsec_review/jobs/job_code_graph_index/producers.py).
These neighborhoods retain their producer-specific kinds and origins; adding an analyzer diagnostic
or a Joern function row does not make it an independent primary dataflow result.

Cross-checking is specific, not a generic vote. The
[call cross-check](../../src/appsec_review/graph/crosscheck.py) uses supported clangd/AST/IR evidence;
the [SVF cross-check](../../src/appsec_review/graph/svf_crosscheck.py) distinguishes closed-world
contradiction from open-world absence. Uncovered and secondary-only sites remain explicit.
Disagreement can remove direct eligibility; incomplete sources do not refute an otherwise positive
fact. Seeded mode records seeds, unresolved selections, depth/frontier bounds and omitted extent.
No-seed execution is not whole-program fallback, and a seeded neighborhood is not complete coverage.

**Publication, retrieval and non-facts**

Each accepted producer publishes immutable artifacts and index identities. Availability in a
composed manifest is not permission to read it: see
[input contracts](job-input-contracts.md#admission-and-read-receipts) and
[accepted index sets](python-and-retrieval.md#accepted-index-sets). Source locations bind a snapshot,
path, bytes and mapping/ambiguity; generated and binary-derived evidence use explicit retained
backing rather than a similarly named target file. A missing/failed scope may publish coverage
without facts. An artifact-only database, CPG, JSONL or protected compile command is not automatically
an indexed model-readable result.

The actual [MCP schemas](../../src/appsec_review/mcp/schema.py) expose bounded reads:

- `query_syntax` reads written syntax within an exact source/AST identity. Its references mode is
  identifier occurrences, not semantic binding.
- `query_code_graph` reads accepted graph facts by exact subject and bounded mode/depth.
- `list_codeql_databases` and `query_codeql_neighborhood` expose database cards and precomputed
  neighborhoods, including selected producer context.
- `query_observations` reads scanner judgments; `query_precomputed` covers its declared non-graph
  sets. There is no separate symbol-query capability invented by this architecture.

No query starts parsing, compilation or analysis, and a filename is not a capability grant.
[Retrieval](python-and-retrieval.md#query-boundary) owns cursor, result/byte/time and source-resolution
contracts. [Image pinning](../operations/image-pin-verification.md) and
[signing](../operations/signing.md) own launch verification; [runtime](jobs-and-runtime.md#wave-1-resumability)
owns admitted attempt/unit reuse. Per-producer checkpoints add narrower source/database/tool/
normalizer/seed identities, not permission to bypass those gates.

**Coverage rows versus canonical status**

SQLite coverage, nested scope results and root canonical outcomes are distinct products. In SVF,
[normalization reasons](../../src/appsec_review/jobs/job_svf_alias_analysis/job.py#L410) join module
coverage at lines 424–425, but only tool-supplied module gaps enter the returned gap list at line
426. The [scope status](../../src/appsec_review/jobs/job_svf_alias_analysis/job.py#L452) accounts for
partial module rows; the [aggregate](../../src/appsec_review/jobs/job_svf_alias_analysis/job.py#L499)
recomputes success from returned gap strings, without projecting nested scope statuses as root
dispositions. Thus an analyzed open-world scope with no tool gaps can remain partial in published
SQLite/nested results while its aggregate declares success.

The root does **not** silently repair that discrepancy:
[outcome projection](../../src/appsec_review/runtime/handoff.py#L196) reads each configured unit's
explicit gap/status/dispositions fields, and
[publication](../../src/appsec_review/runtime/runner.py#L965) calls it over configured unit IDs.
It does not traverse nested `scopes` or open SQLite coverage. Published module coverage survives;
canonical aggregate coverage can understate it. This is a source-demonstrated propagation
limitation, not a live-run reproduction or proof that the underlying alias facts were lost.

Similarly, the compiled producer's
[missing exact compile/link relationship](../../src/appsec_review/jobs/job_cpp_compiled_analysis/job.py#L510)
is a partial coverage row while that branch returns an empty declared-gap list. Its
[summary](../../src/appsec_review/jobs/job_cpp_compiled_analysis/job.py#L1256) intentionally joins
declared branch gaps, not every shard's coverage. That narrower summary must not be used as proof
of complete relationship coverage; changing what should become a canonical gap is separate from
documenting the current projection.

## Decisions

Dates below are dates of the linked original implementation or decision records, not newly granted
validation authority. Historical records retain their original scope and terminology.

| Date | Decision retained in the current structure | Original record |
| --- | --- | --- |
| 2026-10-08 | Keep Tree-sitter a locked, independent source-syntax producer rather than compiler semantics | [Introduction commit](https://github.com/wsollers/appsec-review/commit/a84867f29527299385313aa4887f16c42cfb32d2) and [syntax contract](tree-sitter-ast.md) |
| 2026-10-08 | Use one cross-language CodeQL implementation with independent database/query identities | [Introduction commit](https://github.com/wsollers/appsec-review/commit/9c31ee652dddb4bc092b70366ee5fa1cc4a8b5a3); older stage names are superseded by the current handler |
| 2026-10-12 | Make CodeQL primary for graph families, separate export from normalization, expose typed graph retrieval and retain explicit admissibility | [Implementation decision record](../reviews/code-graph-precomputation-implementation.md#2-decisions) and [historical design](code-graph-precomputation.md) |
| 2026-10-14 | Run Clang static analysis as an independent accepted-compile-scope observation producer | [Introduction commit](https://github.com/wsollers/appsec-review/commit/3bc1dcea724b8317c8c58169ac2a245b25995029) and [producer design](clang-static-analysis.md) |
| 2026-10-16 | Analyze outward from seeds, preserve bounded/absent neighborhoods, and expose producer context without a new fact family | [Seeded-neighborhood decision](seeded-neighborhoods.md#1-decision) |
| 2026-10-16 | Use SVF as an independent points-to cross-check; only qualified closed-world negatives contradict | [SVF decisions](svf-alias-producer.md#2-decisions) |

The 2026-10-12 record's Joern deprecation is not a claim that today's optional seeded exporter is
absent. The [current handler](../../src/appsec_review/jobs/job_cpg_analysis/job.py) retains that
bounded path while still publishing zero security observations and no general CPG/PDG completeness.

## Named gaps

The registry is [docs/TODO.md](../TODO.md); the following are scoped references, not another backlog.
No item or known limitation automatically joins a walk's user-approved expected-gap list.

- **T-014, T-016:** measurement and remaining extension of seeded CodeQL and Clang neighborhoods.
  Their presence does not authorize assuming full-program scope or running live measurements here.
- **T-017, T-019:** remaining platform/accepted-build coverage and the CodeQL checkpoint identity
  matrix. Supplied runtime/query declarations and successful fixtures are not a universal language
  or deployment guarantee.
- **T-020:** proposed graph modes such as aliases/slices/layouts are not added to the current
  model-facing schema merely because SVF or LLVM holds related facts.
- **T-021:** retained/deprecated general Joern export/acceptance work; not an active promise of
  broad CPG coverage. **T-023:** clangd scale/resource work beyond its implemented scope index.
- **T-115, T-118–T-123:** recorded export provenance, language live tiers, catalog decisions,
  fixture replacement and a live acceptance record. Historical “implemented” prose is not proof
  those current obligations passed.
- **T-124, T-125:** named Rust flow/sanitizer limitations. **T-126:** the multi-producer graph/dataflow
  strategy; current native cross-checking is not independent dataflow verification for every language.
- **T-025:** evidence/contract/deployment lane work beyond the implemented graph path.
  **T-032:** remaining binary-decompilation review integration/validation boundaries.
- **T-147, T-157:** missing exact task/dataset and language/applicability metadata; generated
  inventory cells are declarations, not execution evidence.

The SVF aggregate propagation detail above has no exact dedicated TODO at this source boundary.
It is reported for coordinator triage, not silently assigned to T-126 or repaired by this document.

## Jobs and pages

| Job page | Producer responsibility |
| --- | --- |
| [Tree-sitter AST](../operations/job_tree_sitter_ast.md) | Locked syntax, generated-source backing and bounded syntax projection |
| [C/C++ compiled analysis](../operations/job_cpp_compiled_analysis.md) | Compile/link catalogs, Clang AST, LLVM IR, Infer and binary-symbol branches |
| [C/C++ symbol index](../operations/job_cpp_symbol_index.md) | clangd definitions/declarations and supported call/reference edges |
| [Clang static analysis](../operations/job_clang_static_analysis.md) | Diagnostic judgments and seeded placement |
| [CodeQL analysis](../operations/job_codeql_analysis.md) | Databases, independent query profiles, native SARIF and raw graph exports |
| [Code graph index](../operations/job_code_graph_index.md) | Graph normalization, cross-checks, correlation, database cards and neighborhoods |
| [SVF alias analysis](../operations/job_svf_alias_analysis.md) | Module-scoped points-to/indirect-call/accessor context |
| [CPG analysis](../operations/job_cpg_analysis.md) | Optional retained CPG and bounded seeded function export |
| [Binary evidence indexing](../operations/job_binary_evidence_indexing.md) | Intake-frozen decompilation tables and detached native pseudo-C |

[Scanners and evidence collection](scanners-and-evidence-collection.md) owns the broader scanner,
artifact, dependency and imported execution-evidence story; shared mechanisms remain linked above.

## Dataflow

```mermaid
flowchart LR
  source["accepted intake / catalog / generated-source backing"] --> syntax["job_tree_sitter_ast"]
  builds["accepted language builds + compile/source custody"] --> compiled["job_cpp_compiled_analysis"]
  compiled --> symbols["job_cpp_symbol_index"]
  compiled --> clang["job_clang_static_analysis"]
  compiled --> svf["job_svf_alias_analysis"]
  compiled --> cpg["job_cpg_analysis: optional"]
  source --> codeql["job_codeql_analysis"]
  builds --> codeql
  codeql --> sarif["native SARIF + scanner observations"]
  codeql --> exports["raw bounded graph exports + seed ledger"]
  exports --> graph["job_code_graph_index"]
  compiled -->|AST / IR cross-check| graph
  symbols --> graph
  clang -->|diagnostics / sink corroboration| graph
  svf -->|qualified alias cross-check| graph
  cpg -->|bounded seeded function context| graph
  sarif -->|flow correlation| graph
  binary["intake-frozen decompilation publication"] --> binindex["job_binary_evidence_indexing"]
  syntax --> manifest["accepted immutable retrieval manifests"]
  graph --> manifest
  binindex --> manifest
  manifest --> queries["bounded syntax / graph / neighborhood / observation reads"]
  exports -. "absent / failed / seeded / truncated" .-> coverage["coverage-only rows + explicit gaps"]
  svf -. "module coverage distinct from root status" .-> coverage
  coverage --> manifest
  builds -. "changed accepted identity" .-> stop["integrity failure; not clean coverage"]
  raw["protected commands / raw databases / retained CPG bytes"] -. "not automatic payload access" .-> manifest
```
