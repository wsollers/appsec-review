---
title: "Code-graph index"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_clang_static_analysis", "job_code_graph_index", "job_codeql_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_review_data_indexing", "job_review_prioritization", "job_security_tagging", "job_tree_sitter_ast"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
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
| clangd, LLVM IR and Clang AST shards | `analysis` shards of `job_cpp_symbol_index` (`clangd-*`) and `job_cpp_compiled_analysis` (`branch` `ir` and `ast`), from the accepted manifest or, when the `job_codeql_analysis` manifest rewrite dropped them, from those jobs' own accepted handoffs (`restored_secondary` in the load output) | Accepted manifest verification; a restored shard's handoff manifest is re-verified and the shard must be produced by that handoff's job |
| CodeQL observations | Accepted `observations` shards `codeql-<language>-<scope>-*` | Accepted manifest verification |
| Prioritization flow steps | Accepted `priority` shards of `job_review_prioritization`, when present | Accepted manifest verification |
| Catalog and columns | Supplied `rules/codeql-graph-export/catalog.json` and `columns.json` | Catalog shape and export contracts are checked; the catalog release must match frozen `review_policy.releases.graph_catalog`. Missing bound configuration or a contradictory release fails. Reuse requires declared graph catalog, columns, normalizer and validation releases, not fresh customer-evidence hashes of supplied files. |

Each clangd, IR and AST shard serves exactly one CodeQL scope: the scope whose planned files hold
most of the shard's located paths, with ties broken by scope id. A shard is never shared between two
scopes, and a scope without one of its own is cross-checked as `not_covered`.

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
`graph/contract.py`. The same `settings.graph` table, read from the run-bound resolved configuration
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
