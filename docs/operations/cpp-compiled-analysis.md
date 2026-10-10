# C/C++ compiled-analysis operations

`job_cpp_compiled_analysis` consumes the accepted `job_language_build` handoff and discovers native
projects from successful generic build receipts at any normalized target-relative root. There is no
repository-specific project list, required `projects/` prefix, or expected count. Each project keeps
the generic build-unit identity and
independent checkpoints inside project-batched graph tasks.

The real Dagster graph is:

```text
accepted generic language-build handoff
  -> verify native workspace manifests, artifacts, recipes, images, and source mappings
  -> copy accepted source/build products into analysis scratch
  -> normalize compile/link records and catalog objects/libraries/executables
  -> compiled index | Clang AST | LLVM IR | Infer | binary/symbol index
  -> verified composite manifest and accepted handoff
     -> (independent consumers) job_cpp_symbol_index (clangd) | job_cpg_analysis (Joern)
```

The generic native executor described in [`language-build.md`](language-build.md) owns the accepted
build. The compiled-analysis job does not rerun that build for AST, IR, Infer, or binary analysis.
The clangd symbol index and the Joern CPG run as independent jobs over this job's accepted handoff;
see [`cpp-index-jobs.md`](cpp-index-jobs.md). The separate cross-language `job_codeql_analysis` owns traced rebuilds and CodeQL
evidence for this and every other supported language; see
[`codeql-analysis.md`](codeql-analysis.md). The pipeline never runs target executables or tests.

CMake supplies `compile_commands.json` directly. Other native systems must supply an accepted
compile database or an equivalent future generic capture adapter; missing capture is a named gap.
Compiler logs are not heuristically parsed. Normalization accepts only bounded compilation
semantics needed by Clang replay, removes output/dependency-generation actions, maps source paths,
and binds every unit to the case, source snapshot, command hash, compiler image, and source hash.

A build or analysis-tool failure is returned as a terminal gap. Sibling projects and branches keep
running, and their immutable shards remain usable. Corrupt source mappings, escaped paths, changed
artifact hashes, malformed compile databases, duplicate shards, or invalid manifests are framework
integrity failures and stop publication.

## Infer decision

Infer 1.3.0 is an enabled compiled-analysis branch. Its immutable MIT-licensed Linux release is
hash-pinned in `containers/tools/infer/assets.lock.json`, packaged without build-time network
access, and executed under the central scanner boundary. The adapter rewrites the normalized
compilation database to stable read-only container paths and uses Infer's bundled LLVM/Clang 21
frontend. It does not rerun the target build or execute target binaries.

The producer retains Infer's JSON report, execution receipt, compilation database, and log as
run-owned artifacts. Each observation resolves through the accepted source mapping and is indexed
as tool evidence rather than an adjudicated finding. A capture-count mismatch, invalid report,
timeout, OOM, nonzero exit, or unmapped result path is an explicit coverage gap.

## Blind evaluation boundary

The target is scanned without evaluator answers. Target-specific ground truth, expected detections,
source-to-sink mappings, and remediation notes live only in the separate evaluator-guide
repository, outside the target and `runs/` roots. The framework retains only the repository,
commit, and artifact hashes in
[`../reviews/native-evaluator-guide.lock.json`](../reviews/native-evaluator-guide.lock.json).
Tests reject answer-bearing target paths or prose and reject evaluator-guide material in run-owned
artifacts. Evaluators may read the guide only after a blind run completes; it is never mounted into
review workers, tool containers, retrieval indexes, MCP, or prompts.

The Linux calibration workspace is an original, concept-only implementation informed by the
hash-pinned CMU SEI CERT Secure Coding Standards revision recorded in the external guide. No source
example was copied, and no MISRA Example Suite or CodeQL test source was used. No rule identifiers,
weakness labels, or local defect map is present in the scan root.

## Joern status

Joern no longer runs inside this job. The independent `job_cpg_analysis` consumes this job's
accepted handoff, runs the pinned `tool-joern` c2cpg frontend per accepted project, and retains each
CPG as run-owned evidence. Until bounded CPG/PDG export, source mapping, functional fixtures, and
security acceptance exist, it publishes a `BLOCKED` shard with zero observations and `unavailable`
coverage per project. See [`cpp-index-jobs.md`](cpp-index-jobs.md) and
`containers/tools/joern/README.md`.

## Evidence and recovery

Bulk products live under ignored `runs/<run-id>/`. Accepted `build`, `compiled`, `analysis`, and
`observations` shards are queryable through the existing bounded MCP `search`, `find`,
`read_excerpt`, `trace`, `resolve_evidence`, and `coverage` interfaces. Build artifacts and tool
observations are evidence, not adjudicated findings.

Resume the same application run. Completed unit receipts and immutable fingerprinted shards are
reused. Generic build reuse is decided upstream from source, recipe, dependency, image, probe,
executor, capture, and handoff identities. An Infer image or adapter change affects Infer
fingerprints only; a compile identity invalidates the dependent compiled, AST, IR, Infer, and binary
branches, and, through the accepted scope identity, the independent clangd and Joern jobs. Cross-language CodeQL has its own database and query checkpoints.
