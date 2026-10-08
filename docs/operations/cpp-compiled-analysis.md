# C/C++ compiled-analysis operations

`job_cpp_compiled_analysis` consumes the accepted target-analysis plan and exposes one C++
toolchain lane. For `targets/appsec-multi-vuln` that lane contains thirteen independently resumable
case actions: ten CMake roots, one Make root, and one Autotools root. `configure.ac` and
`Makefile.am` at the same root describe one Autotools action, not two projects.

The real Dagster graph is:

```text
accepted C++ plan
  -> prepare case copy and exact source mapping
  -> configure/generate
  -> compile
  -> validate compile database and catalog objects/libraries/executables
  -> compiled index | Clang AST | LLVM IR | CodeQL | Joern | binary/symbol index
  -> verified composite manifest and accepted handoff
```

Each case uses an allowlisted `cmake`, `make`, or `autotools` profile. Target build files execute
only in `tool-native-cpp`, with no network, a read-only container root and target mount, one bounded
run-owned writable scratch mount, non-root UID/GID 10001, dropped capabilities,
`no-new-privileges`, and central CPU, memory, PID, timeout, tmpfs, and output limits. The pipeline
never runs target executables or tests. The run-owned source copy is hashed back to the accepted
target source before use.

CMake supplies `compile_commands.json` directly. Make and Autotools use Bear compiler interception;
the MSBuild case is represented explicitly as unavailable because the pinned Linux image does not
contain MSBuild, and all six of its branch shards retain that named coverage gap.
compiler logs are not heuristically parsed. Normalization accepts only bounded compilation
semantics needed by Clang replay, removes output/dependency-generation actions, maps source paths,
and binds every unit to the case, source snapshot, command hash, compiler image, and source hash.

A build or analysis-tool failure is returned as a terminal gap. Sibling cases and branches keep
running, and their immutable shards remain usable. Corrupt source mappings, escaped paths, changed
artifact hashes, malformed compile databases, duplicate shards, or invalid manifests are framework
integrity failures and stop publication.

## Blind evaluation boundary

The target is scanned without evaluator answers. Target-specific ground truth, expected detections,
source-to-sink mappings, and remediation notes live only in the separate evaluator-guide
repository, outside the target and `runs/` roots. The framework retains only the repository,
commit, and artifact hashes in
[`../reviews/native-evaluator-guide.lock.json`](../reviews/native-evaluator-guide.lock.json).
Tests reject answer-bearing target paths or prose and reject evaluator-guide material in run-owned
artifacts. Evaluators may read the guide only after a blind run completes; it is never mounted into
review workers, tool containers, retrieval indexes, MCP, or prompts.

The neutral native workspace was independently adapted from the NIST SARD Juliet C/C++ 1.3 suite,
whose published archive SHA-256 is pinned by the external guide. The target carries only the
general public-domain/CC0 attribution required to document that origin. No upstream case labels or
local defect map is present in the scan root.

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
reused. A CodeQL query-pack change affects CodeQL fingerprints only; a compile identity change
invalidates the dependent compiled, AST, IR, CodeQL, Joern, and binary branches.
