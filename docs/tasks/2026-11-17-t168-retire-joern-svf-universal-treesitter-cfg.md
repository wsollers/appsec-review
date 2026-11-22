---
title: "Task plan T-168: Retire Joern and SVF active paths and standardize universal Tree-sitter CFG extraction"
kind: "task"
subsystem: "code intelligence"
status: "current"
jobs: ["job_cpg_analysis", "job_image_pin_verification", "job_svf_alias_analysis", "job_tree_sitter_ast"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Task plan T-168: Retire Joern and SVF active paths and standardize universal Tree-sitter CFG extraction

This plan implements **T-168** (`docs/TODO.md`, superseding `T-021`, `T-022`, and `T-159`):
retiring OOM-prone Joern (`job_cpg_analysis`, `tool-joern`) and SVF (`job_svf_alias_analysis`,
`tool-svf`) from active review runs and default host image pinning while upgrading
`job_tree_sitter_ast` to extract structured intra-procedural Control Flow Graphs (CFGs), branch
guard polarities, and written call edges across every supported target language.

## Problem and motivation

- Joern (`c2cpg` / `joern-export`) and SVF (`wpa` whole-program LLVM bitcode pointer analysis)
  exhaust JVM heap and host memory on large C/C++ and multi-module repositories, stalling runs or
  forcing brittle per-target memory tuning.
- Meanwhile, `job_tree_sitter_ast` runs fast, deterministically, in-process, and buildlessly across
  all nine smoke target languages (C/C++, Java, JavaScript/TypeScript, Python, Ruby, Go, C#, Rust,
  PHP), yet today emits only flat symbol definitions, imports, and token-level call occurrences
  without basic-block control flow or branch guard semantics.

## Technical design and dataflow changes

1. **Retire Joern and SVF from active execution and default image verification:**
   - Keep `job_cpg_analysis` and `job_svf_alias_analysis` registered in `builtin_registry()` with
     `enabled = false` in `appsec-review.toml` so historical run replay and documentation
     identifier checks remain intact; emit an explicit structured skip summary (`retired_by_policy_oom`)
     when disabled.
   - Set `manual = true` on `tool-joern` and `tool-svf` in `containers/catalog.toml` (matching the
     opt-in catalog pattern tested in `tests/unit/job_image_pin_verification/test_configuration.py`)
     so `configured_pins()` and `containers/build.py` skip Joern/SVF during standard host builds
     and `job_image_pin_verification` while offline tool-closure unit tests continue to pass.
2. **Universal Tree-sitter intra-procedural CFG and guard extraction (`job_tree_sitter_ast`):**
   - Extend the AST walker per function/method across C, C++, Java, JavaScript/TypeScript, Python,
     Ruby, Go, C#, Rust, and PHP to emit:
     - **CFG basic-block & control nodes:** `entry`, `statement_block`, `branch`, `loop`, `switch`,
       `try`, `catch`, `finally`, `return`, `throw`, `exit`.
     - **Directed CFG edges:** `unconditional`, `true_branch`, `false_branch`, `back_edge`,
       `exception_edge`, `early_exit`.
     - **Guard condition extraction & polarity classification:** normalize condition ASTs on
       `if` / `match` / `switch` / ternary / early-return guards (`null_check`, `bounds_check`,
       `length_check`, `auth_or_role_check`, `error_status_check`, `type_check`) with `dominates_sink`
       reachability helpers.
     - **Enclosing-function written call edges:** caller symbol ID -> callee expression/name +
       argument count + receiver token + line/column span + guarding branch IDs.
3. **Shard indexing and `query_syntax` retrieval expansion:**
   - Store CFG blocks, CFG edges, guard predicates, and caller-scoped call sites in the `syntax`
     shard produced by `job_tree_sitter_ast` and expose bounded CFG/guard modes in
     `src/appsec_review/retrieval/syntax.py` (`query_syntax`).

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/tree-sitter-cfg/1          (per-function CFG nodes, edges, guards, and call sites)
- appsec-review/tree-sitter-syntax-shard/2 (backward-compatible reader for /1 shards on replay)

Telemetry & metrics recorded per attempt:
- tree_sitter.files_parsed, tree_sitter.functions_cfg_extracted, tree_sitter.cfg_nodes_total,
  tree_sitter.cfg_edges_total, tree_sitter.guards_classified_by_kind,
  tree_sitter.parse_error_recoveries, tree_sitter.duration_ms
- producer-gap/1 emitted only on bounded file/node cap truncation, never on disabled Joern/SVF
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../architecture/code-intelligence.md`](../architecture/code-intelligence.md),
   [`../operations/tree-sitter-ast.md`](../operations/tree-sitter-ast.md),
   [`../operations/job_cpg_analysis.md`](../operations/job_cpg_analysis.md),
   [`../operations/job_svf_alias_analysis.md`](../operations/job_svf_alias_analysis.md),
   `docs/docs-ledger.json`, and regenerate contracts via `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Every extracted CFG block, guard predicate, and
   caller-to-callee edge is written into `data/indices/` shards with `producer.job = "job_tree_sitter_ast"`
   and consumable by `job_code_graph_index` (`T-169`) and `query_syntax`.
3. **Fast, isolated unit tests (`<10s`):** Add code-level unit tests under
   `tests/unit/job_tree_sitter_ast/` and `tests/unit/job_image_pin_verification/` covering all 9
   smoke language grammars, early-return guard polarity, loop back-edges, exception blocks,
   `query_syntax` CFG queries, and `manual = true` catalog exclusion—zero Docker or subprocess
   calls, `<10s` per test under `-n 8 --shuffle-seed`, registered in `tests/job-test-map.json`.
4. **Common querying & indexing skills doc alignment:** Reconcile `query_syntax` modes and guard
   polarity semantics in [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Document how `evidence-and-graph-querying`
   instructs review cells to inspect `query_syntax` intra-procedural guards when semantic CodeQL
   databases are degraded, without widening worker authority.
6. **Metrics & telemetry:** Verify structured CFG node/edge/guard counters and parse-recovery
   telemetry on `job_tree_sitter_ast` publication summaries.
7. **Proper schema versioning:** Validate the `tree-sitter-cfg` v1 contract at publication and preserve v1 syntax-shard replay compatibility.
