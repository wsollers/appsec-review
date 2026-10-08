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
  -> compiled index | Clang AST | LLVM IR | Infer | CodeQL | Joern | binary/symbol index
  -> verified composite manifest and accepted handoff
```

The job never reruns CMake, Make, Autotools, a compiler, or a linker. Those actions belong to the
generic native executor described in [`language-build.md`](language-build.md). This job verifies the
generic workspace file set and hashes, then uses `tool-native-cpp` only for bounded AST, IR, and
binary/symbol extraction. The pipeline never runs target executables or tests. The run-owned source
copy is hashed back to the accepted target source before use.

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

## CodeQL decision

As checked on 2026-10-08, the [GitHub CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
license the CLI per user and restrict use outside the expressly listed open-source, research,
demonstration, and query-testing cases; commercial GitHub Code Security licensing changes some of
those restrictions. The [official CLI documentation](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
also states that private organization repositories require the applicable GitHub Code Security
entitlement. This environment exposes no CodeQL CLI/bundle, pinned query pack, or relevant
entitlement signal. The producer therefore emits a precise `BLOCKED` coverage shard and does not
download, install, execute, or imply authorization. Supplying an approved entitlement and a
hash-pinned offline bundle/query closure is required to enable it.

## Joern decision

Joern is Apache-2.0 according to its [upstream repository](https://github.com/joernio/joern) and
publishes platform archives, but the current distribution is roughly 1.67 GiB and releases are
frequent. No reviewed, hash-pinned Joern/c2cpg closure is present locally. The contract therefore
emits a `BLOCKED` CPG shard instead of downloading a moving release during a review. Enabling it
requires a fixed archive, exact byte/hash/signature provenance, its JDK/dependency closure, a
non-root offline image, and fixture-verified bounded exports for files, methods, calls, identifiers,
types, control/data-flow edges, and source locations. Full CPGs remain run-owned; MCP receives only
bounded typed records.

## Evidence and recovery

Bulk products live under ignored `runs/<run-id>/`. Accepted `build`, `compiled`, `analysis`, and
`observations` shards are queryable through the existing bounded MCP `search`, `find`,
`read_excerpt`, `trace`, `resolve_evidence`, and `coverage` interfaces. Build artifacts and tool
observations are evidence, not adjudicated findings.

Resume the same application run. Completed unit receipts and immutable fingerprinted shards are
reused. Generic build reuse is decided upstream from source, recipe, dependency, image, probe,
executor, capture, and handoff identities. A CodeQL query-pack change affects CodeQL fingerprints
only; an Infer image or adapter change affects Infer fingerprints only; a compile identity invalidates the dependent
compiled, AST, IR, Infer, CodeQL, Joern, and binary branches.
