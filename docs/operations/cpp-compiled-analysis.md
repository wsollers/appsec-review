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

Compiles captured from other families (phpize under `buildenv-php`, setuptools under
`buildenv-python`) keep their absolute system include directories, such as
`/usr/include/php/20230831/main` and `/usr/include/python3.12`. `tool-native-cpp` installs the same
PHP and Python development packages at the versions those build environments pin, so these paths
resolve to the same headers in the replay; see `containers/tools/native-cpp/README.md`. Joined
`-isystem`, `-iquote` and `-idirafter` forms are retained like `-I`.

The AST and IR replays write a per-unit receipt. When only some units fail, the job indexes the
others and records one gap per failed unit: a missing header is named
(`<path>: ast replay header not found in tool-native-cpp: php.h (...)`), and other failures carry
the exit code and the first compiler error line. A missing header is never read as an empty or
clean unit.

A build or analysis-tool failure is returned as a terminal gap. Sibling projects and branches keep
running, and their immutable shards remain usable. Corrupt source mappings, escaped paths, changed
artifact hashes, malformed compile databases, duplicate shards, or invalid manifests are framework
integrity failures and stop publication.

## Infer decision

Infer 1.3.0 is an enabled compiled-analysis branch. Its immutable MIT-licensed Linux release is
hash-pinned in `containers/tools/infer/assets.lock.json`, packaged without build-time network
access, and executed under the central scanner boundary. The adapter rewrites the normalized
compilation database to stable read-only container paths and uses Infer's bundled LLVM/Clang 21
frontend. It does not rerun the target build or execute target binaries. That frontend parses each
unit against the system C/C++ headers, so the Infer image is built `FROM` the shared
`appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1` (catalog dependency
`buildenv-native-toolchain`; `containers/tools/infer/Dockerfile`), the same toolchain headers the
family build images use, rather than the bare Ubuntu base, where every unit failed with
`'stdio.h' file not found`. Open question: `containers/tools/infer/tool.toml` still names
`dependency = "appsec-review/tool-native-cpp:1.0.0"`.

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

Joern is deprecated and shipped disabled (`jobs.job_cpg_analysis.settings.enabled = false`), so it
is absent from the default graph; `job_clang_static_analysis` and `job_cpp_symbol_index` are the
consumers of this handoff that run by default. When enabled, the independent `job_cpg_analysis` consumes this job's
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

The acceptance task writes `cpp-compiled-summary.json` (schema
`appsec-review/cpp-compiled-analysis/2`, described by
[`../schemas/cpp-compiled-analysis.schema.json`](../schemas/cpp-compiled-analysis.schema.json)).
It records `branch_count` 5 and one `<case-id>:<branch>` disposition per project and branch, either
`SUCCEEDED` or `COMPLETED_WITH_GAPS`; a project blocked upstream is recorded as
`COMPLETED_WITH_GAPS` with its named gap. With no accepted native project the plan step is
`NOT_APPLICABLE` and the disposition map is empty.

Resume the same application run. Completed unit receipts and immutable fingerprinted shards are
reused. Generic build reuse is decided upstream from source, recipe, dependency, image, probe,
executor, capture, and handoff identities. An Infer image or adapter change affects Infer
fingerprints only; a compile identity invalidates the dependent compiled, AST, IR, Infer, and binary
branches, and, through the accepted scope identity, the independent clangd and Joern jobs. Cross-language CodeQL has its own database and query checkpoints.
