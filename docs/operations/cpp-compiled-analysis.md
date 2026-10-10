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
  -> compiled index | Clang AST | LLVM IR | Infer | Joern | binary/symbol index
  -> verified composite manifest and accepted handoff
```

The generic native executor described in [`language-build.md`](language-build.md) owns the accepted
build. The compiled-analysis job does not rerun that build for AST, IR, Infer, Joern, or binary
analysis. The separate cross-language `job_codeql_analysis` owns traced rebuilds and CodeQL
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

Completed: the immutable Joern/c2cpg runtime closure. `tool-joern` in `containers/catalog.toml`
pins Joern `v4.0.630`, with Apache-2.0 provenance. The asset lock records the exact byte size,
SHA-256, and upstream SHA-512 of `joern-cli-linux-x86_64.zip`. No archive signature is published,
and the checksum sidecar is not counted as one. The image installs only the reviewed core and
`c2cpg` closure from `inventory.json` on the pinned `base-jre` (Java 21). It is built with no
network and runs as `10001:10001` under the central read-only, no-network, drop-all policy. See
`containers/tools/joern/README.md` for the construction flow and `LICENSE.md` for the license and
advisory review and its open items.

Still blocked, and the C++ job's Joern branch therefore still emits a `BLOCKED` shard with zero
observations and `unavailable` coverage:

- a bounded exporter;
- the CPG/PDG index contract;
- source mapping to accepted snapshot locations;
- slicing;
- security probes for the exporter path;
- live functional acceptance on fixtures;
- job integration.

Runtime availability is not CPG coverage. Full CPGs remain run-owned; MCP receives only bounded
typed records.

## Evidence and recovery

Bulk products live under ignored `runs/<run-id>/`. Accepted `build`, `compiled`, `analysis`, and
`observations` shards are queryable through the existing bounded MCP `search`, `find`,
`read_excerpt`, `trace`, `resolve_evidence`, and `coverage` interfaces. Build artifacts and tool
observations are evidence, not adjudicated findings.

Resume the same application run. Completed unit receipts and immutable fingerprinted shards are
reused. Generic build reuse is decided upstream from source, recipe, dependency, image, probe,
executor, capture, and handoff identities. An Infer image or adapter change affects Infer
fingerprints only; a compile identity invalidates the dependent compiled, AST, IR, Infer, Joern,
and binary branches. Cross-language CodeQL has its own database and query checkpoints.
