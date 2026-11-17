---
title: "Task plan T-169: Synthesize universal alternate CPG and CFG from Tree-sitter and CodeQL"
kind: "task"
subsystem: "code intelligence"
status: "current"
jobs: ["job_code_graph_index", "job_codeql_analysis", "job_cpp_symbol_index", "job_debug_symbol_indexing", "job_inference_security_review", "job_tree_sitter_ast"]
last reconciled: "7dce146454df1a220fe6e1772207503aa655ef43"
---
# Task plan T-169: Synthesize universal alternate CPG and CFG from Tree-sitter and CodeQL

This plan implements **T-169** (`docs/TODO.md`, blocked by `T-168`): synthesizing an always-on,
universal **Alternate Code Property Graph (CPG) and Control Flow Graph (CFG)** inside
`job_code_graph_index` by fusing `job_tree_sitter_ast` syntactic AST/CFGs with `job_codeql_analysis`
semantic call/taint/barrier exports, `job_cpp_symbol_index` (clangd), and
`job_debug_symbol_indexing` (DWARF/PDB).

## Problem and motivation

- `job_code_graph_index` previously relied primarily on CodeQL neighborhoods seeded around SAST
  findings (3–4 hops), leaving blind spots when:
  1. SAST emitted **zero findings** on an exposed handler containing a business-logic, auth-bypass,
     or custom-API vulnerability (starving Lane B hunters of graph neighborhoods), or
  2. A compiled C/C++, Java, or C# build degraded partially, leaving files without semantic CodeQL
     tuples and without a unified graph fallback.
- Replacing Joern and SVF requires a memory-bounded, deterministic CPG/CFG fusion engine that
  **always** produces queryable AST + CFG + Call + DFG/PDG slices across all nine target languages.

## Technical design and dataflow changes

1. **Dual-seeded neighborhood construction (`job_code_graph_index`):**
   - Seed graph extraction from **both**:
     - **Sink seeds:** SAST/CodeQL/Clang observations and `sink_site` models, AND
     - **Entry & hotspot seeds:** HTTP/RPC/CLI/FFI/deserializer `entry_point` nodes, Tree-sitter
       public entry handlers, and `job_review_prioritization` hotspots—so Lane B hunters always
       have precomputed CPG/CFG neighborhoods even when SAST is silent.
2. **Four-layer Alternate CPG/CFG fusion with explicit provenance tiers:**
   - **Layer 1 (`syntactic_treesitter`, universal):** Intra-procedural basic-block CFGs, branch
     guard predicates (`dominates_sink`), and written call/import edges from `job_tree_sitter_ast`
     for 100% of first-party files.
   - **Layer 2 (`semantic_codeql`, when CodeQL DBs succeed or run in buildless/extractor fallback):**
     Resolved polymorphic call targets, `dataflow_path`, `flow_summary`, `sink_site`, `range_fact`,
     and `guard_fact` barriers from `job_codeql_analysis` across C/C++, Java, JS/TS, Python, Ruby,
     Go, C#, Rust, and PHP/extractor-supported packs.
   - **Layer 3 (`symbol_clangd`, C/C++):** Virtual-method override tables, function-pointer type
     targets, and macro expansion spans from `job_cpp_symbol_index`.
   - **Layer 4 (`debug_dwarf_pdb`, native binaries):** Exact struct member byte offsets, array/stack
     frame buffer sizes, and integer signedness/widths from `job_debug_symbol_indexing`.
3. **Extended reachability, backward/forward slicing, and query modes:**
   - Increase bounded inter-procedural call/taint reachability from 3–4 hops to **8–12 configurable
     hops** (`max_call_depth = 10` default) with shortest-path entry-to-sink witness chains.
   - Add bounded intra/inter-procedural **backward sink slices** (expressions/parameters feeding a
     sink) and **forward parameter slices** plus **dominating guard summaries** to `query_code_graph`.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/alternate-cpg/1            (unified CPG/CFG nodes, typed edges, slices, provenance)
- appsec-review/code-graph-shard/2         (preserves replay reader compatibility with /1 shards)

Telemetry & metrics recorded per attempt:
- code_graph.cpg_nodes_by_kind, code_graph.cpg_edges_by_provenance,
  code_graph.entry_seeded_neighborhoods, code_graph.sink_seeded_neighborhoods,
  code_graph.entry_to_sink_witness_paths, code_graph.fallback_syntactic_units,
  code_graph.max_hop_truncations, code_graph.synthesis_duration_ms
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../architecture/code-graph-precomputation.md`](../architecture/code-graph-precomputation.md),
   [`../architecture/code-intelligence.md`](../architecture/code-intelligence.md),
   [`../operations/code-graph-index.md`](../operations/code-graph-index.md),
   [`../operations/codeql-analysis.md`](../operations/codeql-analysis.md), `docs/docs-ledger.json`,
   and regenerate job contract blocks via `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Publish unified CPG/CFG shards in `data/indices/`
   consumable via `query_code_graph`, `query_codeql_neighborhood`, and `trace` by both
   `job_review_prioritization` and `job_inference_security_review`.
3. **Fast, isolated unit tests (`<10s`):** Add deterministic unit tests under
   `tests/unit/job_code_graph_index/` covering: (a) full CodeQL + Tree-sitter + clangd + DWARF
   fusion; (b) Tree-sitter-only degraded build fallback; (c) 10-hop entry-to-sink witness discovery
   on a zero-SAST-finding unit; (d) dominating guard-polarity attachment; and (e) backward/forward
   variable slices—zero Docker/CodeQL CLI execution, `<10s` per test.
4. **Common querying & indexing skills doc alignment:** Document `query_code_graph` slice,
   reachability, and provenance-tier semantics in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Align `evidence-and-graph-querying` and
   review-cell prompts so models distinguish `semantic_codeql` paths from `syntactic_treesitter`
   nominations requiring `read_excerpt` confirmation.
6. **Metrics & telemetry:** Emit per-provenance edge counts, witness-path counts, and syntactic
   fallback ratios in job telemetry and handoff metrics.
7. **Proper schema versioning:** Enforce `alternate-cpg` v1 validation at shard publication while
   maintaining replay support for prior `code_graph` shards.
