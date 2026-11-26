---
title: "C/C++ index jobs: clangd symbol index and Joern CPG"
kind: "operations"
subsystem: "code intelligence"
status: "current"
jobs: ["job_clang_static_analysis", "job_codeql_analysis", "job_cpg_analysis", "job_cpp_compiled_analysis", "job_cpp_symbol_index"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# C/C++ index jobs: clangd symbol index and Joern CPG

Two independent jobs index accepted C/C++ projects after `job_cpp_compiled_analysis` completes.
Joern (`job_cpg_analysis`) is deprecated and shipped disabled
(`jobs.job_cpg_analysis.settings.enabled = false`): the direct CLI and Dagster planners leave a
disabled job out of the graph entirely, so of these two jobs only clangd runs by default and
no Joern rows or artifacts are written. CodeQL also waits for its other enabled declared
predecessors; it is not solely gated by clangd. The third consumer of the same
index scopes, `job_clang_static_analysis`, is documented in
[`clang-static-analysis.md`](clang-static-analysis.md).

| Job | Tool image | Publishes |
| --- | --- | --- |
| `job_cpp_symbol_index` | `tool-clangd-indexer` (clangd 23.1.0) | `analysis` shards: symbols with exact locations, plus call/reference edges |
| `job_cpg_analysis` (deprecated; off by default) | `tool-joern` (Joern 4.0.630, c2cpg) | no run artifacts when disabled; when enabled, `observations` shards with a `BLOCKED` disposition and the retained CPG as evidence |

```text
job_cpp_compiled_analysis (accepted handoff)
  |-- job_cpp_symbol_index   load.accepted_cpp -> index.scopes    -> acceptance.publish_handoff
  `-- job_cpg_analysis       load.accepted_cpp -> generate.scopes -> acceptance.publish_handoff
```

Neither job depends on the other. In the Dagster wave, each depends only on
`job_cpp_compiled_analysis`, and `job_codeql_analysis` waits for enabled declared predecessors.
Each publication composes its admitted input manifest and replaces its own earlier shards;
it does not read an unpinned latest pointer to capture concurrently finishing siblings.
CodeQL retains admitted sibling manifests as upstream references, and later graph/review-data
indexing restores accepted producer shards when necessary. See the generated declarations in
the [symbol](job_cpp_symbol_index.md) and [CPG](job_cpg_analysis.md) job pages.

## Index scopes: the generic input

Both jobs use `appsec_review/jobs/cpp_index_scopes.py`, which turns the accepted C++ handoff into
**index scopes**. A scope is a set of accepted files plus the exact compile commands that build
them:

1. The accepted `job_cpp_compiled_analysis` handoff, result, and index manifest are loaded and
   verified. The post-build job uses the same loader.
2. Every `catalog.projects` entry with terminal status `SUCCEEDED` and at least one compile command
   becomes a scope. Any other project becomes a named `unavailable` coverage entry with the
   upstream reason.
3. Before a tool runs:
   - the accepted compile database is re-hashed;
   - its decoded rows must equal the accepted command context, and retained build files
     (including generated headers) must match their accepted hashes;
   - every materialized source file under `data/cpp/projects/<case>/source/` is re-hashed against
     the accepted mapping;
   - a mismatch fails the job.
4. The scope ID hashes the case, its case snapshot, and its compile database, so any source or
   command change yields a new scope, and therefore new checkpoints.
5. Only compile units a Clang frontend can process (`.c`, `.cc`, `.cpp`, `.cxx`, `.c++`, `.m`,
   `.mm`, `.i`, `.ii`; declared once as `clang:compile-unit` in `appsec_review.tool_inputs`) are
   written to the container compile database. Assembly, CUDA, resource, and other entries are
   `SKIPPED_NA` in each scope's `not_applicable_inputs`, never a missing-translation-unit gap. A
   scope with no supported unit is not launched and is listed in `not_applicable_scopes`.

Tools see only the run-owned case root, mounted read-only at `/target`, plus a read-write
`/scratch`. The compile commands are rewritten to `/target/source/...` and `/target/build/...` paths
(driver normalized to `clang`/`clang++`, MSVC-style flags preserved) and written to
`/scratch/compile_commands.json`. Each accepted source/build working directory is preserved.
Only path operands are rebased; a macro value containing a similar prefix remains compiler data.
The tool runs as the application/Dagster uid and gid. Execution follows the central container
policy: no network, read-only root, all capabilities dropped, `no-new-privileges`, and
bounded memory, CPU, PIDs, time, and output.

## `job_cpp_symbol_index`

For each scope:

1. **Run the indexer.**
   `clangd-indexer --executor=all-TUs --format=yaml /scratch/compile_commands.json`.
2. **Parse its output.** `jobs/job_cpp_symbol_index/clangd_yaml.py` parses the YAML strictly: only
   the subset clangd emits. Anything else, or a document cut off mid-way, is a named gap, never a
   guess.
3. **Index symbols.** Each symbol whose definition (or, failing that, canonical declaration) is in
   an accepted source becomes a `symbol` entity with an exact `SourceLocation`. clangd's 0-based
   UTF-16 positions are resolved to exact byte spans in the hash-verified UTF-8 source, using
   mapping method `clangd-uri-utf16-verified-bytes`. Invalid or saturated coordinates, split
   surrogate pairs and unavailable accepted-byte locations are gaps, not whole-file spans. Symbols
   declared only outside the accepted sources (system, SDK, or engine headers) are counted as
   `external_symbols`, not indexed.
4. **Index edges.** References whose `Container` (the enclosing function) and target are both
   accepted symbols become edges. The edge is `CALLS` when clangd's `RefKind` has the call bit,
   otherwise `REFERENCES`; recursive self-calls remain `CALLS`, while declaration self-references
   add no edge. Repeated references are aggregated into one edge, with an occurrence
   count and a bounded number of locations.
5. **Record coverage.** Coverage is per project: `complete` when the indexer exits 0, processes
   every unambiguous compile context, and the output parses and accounts for documents within
   bounds; `partial` with named gaps otherwise; `unavailable` when the run failed without symbols.
   Filename-only processing markers cannot distinguish multiple commands for one file.
   Missing system headers, explicit processing errors, omitted contexts and truncated stderr
   prevent those contexts from being credited as processed. Unknown document tags, unsupported
   symbol/reference shapes and conflicting duplicate symbol IDs also remain explicit gaps.

Bounds live in `[jobs.job_cpp_symbol_index.settings]`: `workers` (concurrent scopes),
`max_documents_per_scope`, `max_symbols_per_scope`, `max_relations_per_scope`, and
`locations_per_relation`. Index output above the tool's output bound is truncated and recorded as a
gap. Per-TU batching for very large projects is tracked in `docs/TODO.md`.

## `job_cpg_analysis`

For each scope:

1. **Run c2cpg.**
   `c2cpg.sh /target/source --output /scratch/cpg.bin --compilation-database /scratch/compile_commands.json`.
2. **Retain the CPG.** A successful CPG within `max_cpg_bytes` is retained at
   `data/code-index/joern/<scope>/run/cpg.bin`, with its SHA-256 and size, as run-owned evidence.
   It is never served over MCP.
3. **Publish the available evidence.** Every scope retains a `BLOCKED` evidence entity with zero
   security observations. Whole-program CPG retention has unavailable coverage; the enabled
   seeded path described below can add bounded per-function facts with partial coverage, not
   general source-mapped CPG/PDG completeness. The marker names the generated CPG, or the
   reason none was produced: timeout, OOM, non-zero exit, empty output, or over the bound.
   Generating a CPG is not CPG coverage.

Settings in `[jobs.job_cpg_analysis.settings]`:
- `enabled` (default `false`). Joern is deprecated, and no review fact depends on it; see "Why
  Joern is deprecated" in
  [`../architecture/code-graph-precomputation.md`](../architecture/code-graph-precomputation.md).
  When `false`, the job is not planned at all, so no Joern container runs and no rows are
  published (the in-job disabled path that writes `unavailable` rows is unreachable from the
  planners). The `cpg_graph` coverage lane is always `unavailable` in the coverage matrix.
- `workers` (1 until a per-tool resource profile is reviewed).
- `max_cpg_bytes`.

The Joern image ships zstd-jni's native library, copied at build time from the hash-pinned JAR, and
points the JVM at it. Without it, writing a CPG fails, because the runtime `/tmp` is `noexec`.

## Seeded mode

`job_cpg_analysis` (enabled path only; the disabled state is unchanged and runs no container) builds the
CPG of the seeded translation units only: the subset compile database holds the selected units and c2cpg
is told to skip every other C/C++ source (`jobs/job_cpg_analysis/seeded.py`). With no seeds no container
runs. After c2cpg the job runs `joern-export --repr all --format neo4jcsv` on the CPG (a second execution
of `tool-joern`, argv[0] allowed by `additional_executables` in its `tool.toml`) into a fresh scratch
directory, and `jobs/job_cpg_analysis/export.py` reduces the CSV to one bounded row per function of the
seeded files: signature, lines, calls matched by callee name (`callee_resolved` records whether Joern
resolved the target), branches with their condition expressions, operator-call count and reaching-definition
edge count. c2cpg exports no call-graph or control-flow edge files, so those are the named gaps
`cpg_calls_name_matched` and `cpg_no_cfg_edges`; coverage is `partial` (`cpg_export_partial`). A failed or
oversized export publishes no rows, is coverage `unavailable` with `cpg_export_unavailable`, and the CPG stays
run-owned evidence. The raw CSV tree is not retained. The ledger states which seeds the CPG covers. `job_cpp_symbol_index` is unchanged (whole
tree); its symbols are read through the seeded neighborhood (`include=["symbols"]` on
`query_codeql_neighborhood`). Contract: `docs/architecture/seeded-neighborhoods.md`.

## Files each job stores

All of these live under `runs/<run-id>/` and are never committed.

| Path | Content |
| --- | --- |
| `data/code-index/clangd/<scope>/<identity>/execution-NNNN/run/compile_commands.json` | The container compile database the tool read. |
| `data/code-index/clangd/<scope>/<identity>/execution-NNNN/run/raw/{stdout,stderr}.bin`, `execution.json` | Bounded tool output and the hash-bound execution receipt; fresh generations preserve earlier evidence. |
| `data/code-index/clangd/<scope>/checkpoint.json` | Scope result plus identity (scope, tool image and manifest, normalizer, bounds). |
| `data/code-index/joern/<scope>/run/cpg.bin` | The retained CPG (evidence; not served over MCP). |
| `data/code-index/joern/<scope>/run/…`, `checkpoint.json` | As for clangd. |
| `data/indices/analysis/*.sqlite`, `data/indices/observations/*.sqlite` | Fingerprinted shards, including one coverage shard per attempt. |
| `data/indices/manifests/{clangd,joern}-<attempt>.json` | The composed, verified manifest each job publishes. |

**Checkpoint reuse.** A rerun of either job reuses a scope's checkpoint only when its identity
matches and its shard still hash-verifies. The identity covers:

- the scope (files, compile database, case snapshot);
- the tool's catalog identity (tag, version, expected image ID, manifest hash);
- the normalizer or adapter version;
- the bounds;
- for Joern, the blocked-reason text.

Clangd additionally verifies the original execution receipt and both raw-stream hashes before
normalization and checkpoint reuse. Changed, missing or symlinked matching evidence is an
integrity failure, not a cache miss; it is never repaired by hashing the replacement bytes.
All-inapplicable scopes retain explicit disposition metadata in an empty analysis shard, not
measured or unavailable coverage.

## Verification

- **Unit and fixture tests:** `tests/test_cpp_index_jobs.py` runs the real upstream pipeline with
  fake tool executors. It covers:
  - symbol and location normalization, call/reference aggregation, and coverage states;
  - CPG retention and failure gaps;
  - independence in both completion orders;
  - checkpoint reuse;
  - rejection of tampered sources;
  - the strict YAML parser.
- **Live run** (2026-10-10, before the Joern deprecation; real `tool-clangd-indexer` and `tool-joern` images through the real
  `ContainerExecutor`, on the native fixture):
  - clangd indexed `main` at `native/main.cpp:1:5`, processed 1 of 1 translation units, and
    reported `complete` coverage;
  - c2cpg produced a 28 KB CPG, retained with its hash and published as `BLOCKED`;
  - the final accepted manifest composed both jobs with every upstream producer.


## Tuning and whole-job recovery: `job_cpg_analysis`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.max_cpg_bytes` | `2147483648` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.seeded_bounds.include_scan_files` | `4000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.seeded_bounds.unit_limit` | `64` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.workers` | `1` | execution | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_cpg_analysis/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `settings.enabled` | Changes dispatch, required evidence, retry policy not explicitly declared, or selected feature behavior; not an execution capacity. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.generate.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.


## Tuning and whole-job recovery: `job_cpp_symbol_index`

Defaults below are the checked-in base recipe; the admitted profile/overlay may override them.
Only the exact declared leaves are mutable; unknown and mixed material changes are refused.

| Exact path relative to this job (unless global) | Base default | Category | Bounds |
| --- | --- | --- | --- |
| `settings.locations_per_relation` | `8` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_documents_per_scope` | `2000000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_relations_per_scope` | `2000000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.max_symbols_per_scope` | `500000` | coverage | positive integer; exact parser/cross-field bounds† |
| `settings.workers` | `2` | execution | positive integer; exact parser/cross-field bounds† |

† The [executing job/parser](../../src/appsec_review/jobs/job_cpp_symbol_index/job.py) remains the bounds authority, including hard maxima, numeric types and cross-field checks; compatibility never widens it. A type-only range in this table is not permission to bypass stricter parser limits.

Execution changes affect only new attempts. Coverage changes preserve accepted results with their original limits and gaps; expanded coverage requires an explicit whole-job rerun and reconsideration of affected downstream jobs. New/failed attempts execute every unit, without salvaging earlier cells. Retained accepted jobs are validated with their original configuration. Global scheduler/resource tuning does not alter tool/sandbox authority or resize active leases. See [general tuning](../architecture/runtime-interchange.md#operational-configuration-compatibility-and-attempt-ownership).

### Specifically excluded candidates

| Exact setting | Technical reason it remains material |
| --- | --- |
| `workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.load.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.index.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |
| `steps.acceptance.workers` | Structural plan metadata, not a job-local pool control; use the listed pool/scheduler settings. |

Source/rule/tool/schema identities, model/provider/reasoning, input selection and signing/authorization remain material even when not numeric.
