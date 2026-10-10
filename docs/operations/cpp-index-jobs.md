# C/C++ index jobs: clangd symbol index and Joern CPG

Two independent jobs index accepted C/C++ projects after `job_cpp_compiled_analysis` completes:

| Job | Tool image | Publishes |
| --- | --- | --- |
| `job_cpp_symbol_index` | `tool-clangd-indexer` (clangd 23.1.0) | `analysis` shards: symbols with exact locations, plus call/reference edges |
| `job_cpg_analysis` | `tool-joern` (Joern 4.0.630, c2cpg) | `observations` shards: a `BLOCKED` disposition and the retained CPG as evidence |

```text
job_cpp_compiled_analysis (accepted handoff)
  |-- job_cpp_symbol_index   load.accepted_cpp -> index.scopes    -> acceptance.publish_handoff
  `-- job_cpg_analysis       load.accepted_cpp -> generate.scopes -> acceptance.publish_handoff
```

Neither job depends on the other. In the Dagster wave, each depends only on
`job_cpp_compiled_analysis`, and `job_codeql_analysis` waits for both. Each job's publication
composes the latest accepted manifest and replaces only its own earlier shards, so the two can
finish in either order without dropping each other's evidence. CodeQL composes both as sibling
producers.

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
   - every materialized source file under `data/cpp/projects/<case>/source/` is re-hashed against
     the accepted mapping;
   - a mismatch fails the job.
4. The scope ID hashes the case, its case snapshot, and its compile database, so any source or
   command change yields a new scope, and therefore new checkpoints.

Tools see only the run-owned case root, mounted read-only at `/target`, plus a read-write
`/scratch`. The compile commands are rewritten to `/target/source/...` paths (driver normalized to
`clang`/`clang++`, MSVC-style flags preserved) and written to `/scratch/compile_commands.json`.
That file is made world-readable, because the tool runs as uid 10001. Execution follows the central
container policy: no network, read-only root, all capabilities dropped, `no-new-privileges`, and
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
   positions are converted to 1-based, using mapping method `clangd-uri-exact-path`. Symbols
   declared only outside the accepted sources (system, SDK, or engine headers) are counted as
   `external_symbols`, not indexed.
4. **Index edges.** References whose `Container` (the enclosing function) and target are both
   accepted symbols become edges. The edge is `CALLS` when clangd's `RefKind` has the call bit,
   otherwise `REFERENCES`. Repeated references are aggregated into one edge, with an occurrence
   count and a bounded number of locations.
5. **Record coverage.** Coverage is per project: `complete` when the indexer exits 0, processes
   every translation unit, and the output parses within bounds; `partial` with named gaps
   otherwise; `unavailable` when the run failed without producing symbols.

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
3. **Publish a blocked shard.** Bounded CPG/PDG export, source mapping, functional fixtures, and
   security acceptance are not implemented yet. So every scope publishes a `BLOCKED` evidence
   entity with zero observations and `unavailable` coverage. It names the generated CPG, or the
   reason none was produced: timeout, OOM, non-zero exit, empty output, or over the bound.
   Generating a CPG is not CPG coverage.

Settings in `[jobs.job_cpg_analysis.settings]`: `workers` (1 until a per-tool resource profile is
reviewed) and `max_cpg_bytes`.

The Joern image ships zstd-jni's native library, copied at build time from the hash-pinned JAR, and
points the JVM at it. Without it, writing a CPG fails, because the runtime `/tmp` is `noexec`.

## Files each job stores

All of these live under `runs/<run-id>/` and are never committed.

| Path | Content |
| --- | --- |
| `data/code-index/clangd/<scope>/run/compile_commands.json` | The container compile database the tool read. |
| `data/code-index/clangd/<scope>/run/raw/{stdout,stderr}.bin`, `execution.json` | Bounded tool output and the hash-bound execution receipt. |
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

## Verification

- **Unit and fixture tests:** `tests/test_cpp_index_jobs.py` runs the real upstream pipeline with
  fake tool executors. It covers:
  - symbol and location normalization, call/reference aggregation, and coverage states;
  - CPG retention and failure gaps;
  - independence in both completion orders;
  - checkpoint reuse;
  - rejection of tampered sources;
  - the strict YAML parser.
- **Live run** (2026-10-10, real `tool-clangd-indexer` and `tool-joern` images through the real
  `ContainerExecutor`, on the native fixture):
  - clangd indexed `main` at `native/main.cpp:1:5`, processed 1 of 1 translation units, and
    reported `complete` coverage;
  - c2cpg produced a 28 KB CPG, retained with its hash and published as `BLOCKED`;
  - the final accepted manifest composed both jobs with every upstream producer.
