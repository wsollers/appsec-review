# Architecture TODOs

## Complete the Linux execution vertical before expanding platforms

Use `targets/appsec-multi-vuln` as the acceptance target until the generic execution path is
solid, repeatable, and queryable. Do not make the later Windows or large-repository work a
prerequisite for this stage.

The Linux vertical is complete only when:

- accepted static dispatches are consumed as executable `tool + build-unit` shards, while global
  scanners run once and static work remains independent of build probes;
- every successful or reused probe can dispatch a generic real build using the accepted recipe and
  exact derived image, without a repository-specific Dagster graph;
- native, Rust, Go, Java, Node/TypeScript, .NET, Python, PHP, and WASM build units publish explicit
  success, gap, or not-applicable receipts without discarding successful siblings;
- real builds retain bounded protected command provenance for compilers, assemblers, linker
  drivers, linkers, archivers, code generators, transpilers, bundlers, package builders, and
  post-link tools, plus sanitized searchable records and exact input/output identities;
- generated sources, objects, libraries, executables, bytecode, packages, debug data, link maps,
  and statically observed loader dependencies are cataloged without executing target binaries;
- the C++ AST, LLVM IR, Infer, binary, and post-build branches consume the generic native-build
  handoff instead of maintaining a separate project build path or fixed case list;
- compiled-language CodeQL traces the exact accepted clean build, interpreted-language CodeQL uses
  the accepted source snapshot, and both publish bounded database/query/SARIF identities and gaps;
- component dependencies determine build-unit ordering, while unrelated build units and analysis
  branches remain concurrent;
- unchanged recipe, dependency, image, source, tool, and query identities reuse only the valid
  checkpoints they actually cover; and
- unit tests, failure/resume tests, MCP integration tests, and a live Dagster acceptance run prove
  dispatch, execution, provenance capture, indexing, gaps, and selective reuse end to end.

Current status: the generic Linux native/CMake, Rust/Cargo, JVM Java/Kotlin (Maven, Gradle, and direct compiler), Go, manifest-declared Node/JavaScript/TypeScript, manifest-declared PHP/Composer, Linux-capable .NET SDK, and WebAssembly output-family adapters now cover
accepted dispatch validation, real build execution, protected compiler/link provenance, artifact catalogs, dependency ordering,
failure isolation, checkpoint reuse, default-image-first probing, three bounded inference-guided
dependency-image repairs, successful Dockerfile/image reuse, and dynamic C++/post-build
consumption. The Go adapter supports accepted modules/workspaces, vendor mode, package targets,
build tags, and cgo; uses the same syscall-authoritative capture and generic reconciliation as
native, Rust, and .NET; and catalogs modules, packages, generated sources, binaries, build IDs, and
sanitized retrieval records. One parameterized contract now checks successful/failed/redacted exec,
envp/connect facts, wrapper reconciliation, malformed input, and cap/loss behavior across all four
descriptors; adding another compiled language must extend that descriptor contract rather than copy
capture orchestration. The .NET adapter
allows declared dependency restore, catalogs MSBuild/Roslyn and
managed/native outputs, and reports Windows-only/.NET Framework units as explicit platform gaps.
The Rust adapter accepts Cargo workspaces/packages and bounded target/profile/features/lock
choices; retains rustc, linker, archiver, build-script, and proc-macro provenance; catalogs Cargo
metadata and resolve edges plus generated sources, rlib/rmeta, native libraries, binaries, and debug
metadata; and publishes sanitized build evidence without executing tests or produced programs.
Its current Docker fixture gate verifies dependency egress, standardized syscall/envp/connect
records, exact-name redaction, gitleaks findings, complete output files, Cargo dependency and
intermediate artifacts, loader facts, default plus security-extended CodeQL profiles, and truthful
zero-result SARIF. Recipe inference is a separate opt-in model gate and never contributes capture
authority. Rust compiler-native AST and IR producers remain unimplemented; tree-sitter and CodeQL
must not be described as substitutes for those missing branches.
The native adapter now uses the same syscall/envp/connect/gitleaks boundary as Rust and .NET.
Successful exec events alone establish tool provenance; compile databases and CMake link records are
exact-match enrichment only. Docker-backed fixture acceptance covers complete streams,
compiler/linker/archiver provenance, compile database, objects, static library, executable, split
debug data, link map, loader facts, Clang AST, LLVM IR, secret removal, and raw-trace cleanup. This
lower-level acceptance has not been promoted to a Dagster run while language work remains batched.
The Node adapter accepts npm, pnpm, and Yarn identities; allows dependency egress while denying application/test
execution; treats lifecycle scripts as sandboxed target code; and catalogs generated code, bundles,
maps, packages, and native addons with protected command/stream evidence and sanitized retrieval.
The PHP adapter accepts `composer.json` with an optional lockfile, prepares dependencies in the pinned derived image with
plugins/scripts disabled, applies explicit sandbox policy to real Composer build work, catalogs
package and dependency metadata, generated autoload/code, archives, and native extensions, and
keeps exact argv and streams out of retrieval-visible evidence.
The WebAssembly adapter consumes accepted Rust, native/Emscripten/WASI, Node/AssemblyScript, WAT,
and explicitly configured producer recipes without duplicating source discovery; catalogs modules,
components, bindings, interface/debug metadata, side modules, packages, and dependency evidence;
and never instantiates produced modules. Focused host tests cover protected stream truncation,
sanitized MCP retrieval, checkpoint reuse, tamper rejection, and sibling failure isolation. The
prior standalone WebAssembly deployment receipt predates integration into `job_language_build`
and is not acceptance evidence for the current tree. A fresh integrated Dagster run
(`d51d396c-4f0f-4386-a503-859b399f1449`, application run `2026-10-08-0081`) completed all 248
orchestration steps and accepted the shared language-build handoff with one native and seven JVM
successes, nine explicit .NET recipe gaps, and truthful non-selection for Go, Node, Python, PHP,
Rust, and WebAssembly. The composed retrieval manifest and an MCP query resolved sanitized JVM
class evidence while retaining the unrelated catalog build shard. Producer-positive fixture and
live-record coverage is tracked per language; a new integrated Dagster run remains required before
the Linux vertical can be closed.
The pinned cross-language CodeQL job and exact `query_codeql` MCP surface are implemented and have
fresh live acceptance on `appsec-multi-vuln`: producer Dagster run
`e596f2f0-3b47-4263-973e-e0bc0362fe5a`, application run `2026-10-09-0007`, and CodeQL attempt
`attempt_0006` completed all seven selected steps. Exact-tree verification run
`0958c6ff-907d-43fc-b82a-004243f3a573` then reused that accepted attempt and also completed all
seven selected steps. Thirty of 37 profile scopes completed real
database and query execution and published 30 normalized observations across Actions, C/C++,
Java/Kotlin, JavaScript/TypeScript, and Python. The seven Go scopes preserve explicit database and
query gaps because their exact accepted recipes download modules without compiling source; C# is
blocked by the accepted build environment, and Rust by missing accepted Cargo locks. PHP and raw
WebAssembly are explicitly not applicable. Static dispatch execution, pinned loader-dependency
parsing, broader MCP integration, and producer-positive live coverage for the remaining
language-build families are still required. Retained Dagster records describe only the revisions
and selected target recipes they captured.

Probe policy must be centrally configurable per build unit as `configure`, `selected-target`, or
`full-build`. This keeps the default test target rigorous without forcing future large repositories
through an unnecessary full probe before every instrumented or traced build.

## Implement conditional build-capture controls

The agreed semantics and the 18-row `appsec-multi-vuln` fixture mapping are documented in
[`architecture/build-environments-and-execution-capture.md`](architecture/build-environments-and-execution-capture.md),
using nested corpus commit `7c10536389c3cfb20a27d7a6a78943267ea43b3f`. Current status:

- implemented: independent typed central controls for build execution capture and
  compiler-artifact collection with `required`, `auto`, and `disabled` values;
- implemented: canonical immutable per-run resolution and binding into handoff, job-configuration,
  and resume identities;
- implemented: one deterministic descriptor-backed applicability evaluator and canonical
  `SUCCEEDED`, `SKIPPED_NA`, `SKIPPED_POLICY`, and `GAP` processing dispositions, without another
  syscall parser or reconciliation loop;
- implemented: CodeQL's typed capability model accepts `build`, `source`, `auto`, and `disabled`,
  with one-way load-time normalization of legacy `manual`/`none` values; executor receipts retain
  `manual`/`none` after deterministic capability selection;
- implemented: parameterized schema/path/applicability coverage for every matrix row and focused
  transitions for syntax-only versus material lifecycles, mixed native facts, missing inventory,
  unsupported capability, failed processing, and incomplete evidence; and
- remaining: specialized live Kotlin, Android SDK, Composer lifecycle, phpize, mixed-language
  CodeQL, and WebAssembly toolchain acceptance. Their absence is a validation gap, not a changed
  applicability decision.

Conditional policy dispatch and dispositions are implemented. Do not describe specialized live
toolchain acceptance as complete until the remaining gates above run. Executor-level CodeQL
receipts continue to use `manual`/`none` after the canonical decision selects build/source.

## Scale native acceptance from fixtures to a game-sized build

Advance native testing through explicit gates rather than moving directly from the synthetic
multi-language target to a full game project:

1. `appsec-multi-vuln` remains the functional acceptance target for dispatch, failure isolation,
   provenance, indexing, MCP retrieval, and selective resume across supported languages.
2. EASTL is the next native target. Use it to validate template- and header-heavy C++, custom
   allocators and containers, cross-translation-unit relationships, compile-database fidelity,
   static-library outputs, AST/IR scale, compiler-specific flags, and deduplication of findings
   emitted through many template instantiations.
3. The Unreal Engine Lyra sample project is the later game-scale target, after the required Windows
   and Unreal build capabilities are available. Use it to validate project/plugin/module/target
   discovery, UBT/UAT orchestration, generated headers and sources, C# build tooling, shader and
   asset-build provenance, native compiler/linker capture, selective configurations, traced
   CodeQL, large-index retrieval, and bounded resumption.

Externally obtained target and engine source remains under ignored `targets/` storage and is never
committed or copied wholesale into documentation, fixtures, prompts, or indexes. Retain only the
bounded derived evidence permitted by the index contract plus the source revision, acquisition
provenance, applicable capability state, and accepted run-owned artifact identities needed to
reproduce and verify a test.

## Add Windows and large native-build coverage after the Linux acceptance gate

Once the Linux vertical above passes against `appsec-multi-vuln`, add a first-class disposable
Windows executor rather than extending Linux recipes with platform-specific exceptions.

The follow-on work should:

- bootstrap an ephemeral Windows image or VM from centrally configured, hash-identified tooling;
- support MSVC, clang-cl, MSBuild, CMake/Ninja, and UBT/UAT-style modular build orchestration;
- capture `cl`, `clang-cl`, `link`, `lib`, `rc`, `cvtres`, `midl`, shader compilers, code generators,
  signing tools, and other build-time compiler/transpiler actions through the same protected
  provenance contract used on Linux;
- wrap the exact accepted Windows build for compiled-language CodeQL database creation when the
  required pinned assets and runtime capability are available;
- inventory installed compiler, SDK, build-system, extractor, and query-pack versions and hashes
  without copying redistributable tool payloads into this repository or run indexes;
- shard large repositories by component, module, plugin, target, platform, configuration, and
  dependency topology instead of producing project-named horizontal Dagster graphs;
- allow selective target/configuration matrices and centrally bounded concurrency, storage, and
  time budgets; and
- validate the executor with synthetic fixtures first, then representative larger native projects,
  while preserving gaps for unsupported platform or toolchain combinations.

## Add Android, iOS, and Unity application coverage

After the Linux execution vertical is accepted, extend the same discovery, recipe, provenance,
artifact, indexing, and gap contracts to mobile applications and Unity projects. Keep source-only
analysis useful before the corresponding platform build executor is available.

Android work should:

- discover Gradle/Android Gradle Plugin projects, modules, variants, manifests, resources, Java,
  Kotlin, JNI/NDK, native libraries, dependency catalogs, signing configuration references, and
  generated sources without retaining signing secrets;
- run selected source scanners, including the existing pinned `tool-mobsfscan` lane, before a build
  is available;
- build accepted variants in a pinned Linux Android SDK/NDK/JDK image, capture Gradle, Java/Kotlin,
  native compiler/linker, resource, DEX, packaging, and signing-tool provenance, and retain APK/AAB,
  mapping, symbol, manifest, SBOM, and native-library artifacts;
- add bounded APK/AAB MobSF artifact analysis when a reviewed full MobSF runtime is available; and
- correlate mobile, JVM, native, dependency, manifest, exported-component, permission, and binary
  observations through shared component and source identities.

iOS work should:

- discover Xcode projects/workspaces, schemes, targets, Swift packages, CocoaPods, Objective-C,
  Swift, C/C++, entitlements, privacy manifests, resources, frameworks, and extensions;
- keep source scanning and configuration assessment available on non-macOS workers;
- use an ephemeral, centrally configured macOS executor for accepted `xcodebuild`, Clang, Swift,
  linker, asset compiler, interface builder, package, archive, and codesign-metadata capture;
- retain bounded IPA/app/framework, symbol, dependency, entitlement, privacy, and signing-metadata
  evidence without retaining signing credentials or executing the application; and
- publish an explicit platform gap when the required macOS/Xcode capability is unavailable.

Unity work should:

- recognize projects from `Assets`, `Packages`, `ProjectSettings`, assembly definitions, package
  manifests, scripting backend, platform targets, plugins, native libraries, and recorded editor
  version;
- statically analyze C#, shaders, scripts, configuration, packages, managed assemblies, native
  plugins, and IL2CPP-generated C++ when those artifacts already exist;
- capture Unity batch-build, compiler, linker, shader compiler, asset pipeline, managed assembly,
  IL2CPP, packaging, and platform-tool invocations through the generic protected provenance model;
- shard evidence by project, assembly, package, scene, plugin, platform, configuration, and build
  target without exposing project assets to inference unnecessarily; and
- require a centrally configured licensed Unity runtime for builds. If that capability is absent,
  publish a named build-coverage gap while continuing source, package, configuration, and available
  artifact analysis.

Acceptance requires synthetic Android, iOS, and Unity fixtures; failure/resume and unavailable-
platform tests; bounded MobSF/MobSFScan integration tests; and live Dagster runs on workers that
actually provide each enabled platform capability.

## Close the SEI CERT rule-pack execution and coverage gaps

The pack (`rules/sei-cert/`) validates and evaluates cleanly under Semgrep 1.178.0 and OpenGrep
1.30.2 on fixtures and on `appsec-multi-vuln`, but these remain open:

- build and smoke-test the new `tool-opengrep` image and run one live evidence-collection
  acceptance with both engines; the image definition was validated statically only;
- verify the Sigstore signature that OpenGrep publishes for its release binary;
- verify live resolution of the canonical CERT URLs, which were derived from the official
  repository's content paths;
- run the Dagster definition tests with the new `opengrep_*` evidence tasks;
- re-read the drafted summaries and analysis classes of unimplemented entries against their
  official pages before promoting them, starting with entries flagged `pattern_candidate`;
- add Kotlin and Android-manifest analysis only after an applicable official rule and a capable
  engine exist; both are currently explicit gaps.

## Add `grype_db_sync` to `job_third_party_data_sync`

The archived pre-refactor tree was inspected for a reusable Grype database. It contains a Grype
executable archive and image/build records, but no database snapshot with a verifiable database
schema version, listing metadata, content hashes, source provenance, or freshness identity. Those
bytes are therefore not a usable database snapshot and were not copied.

Future work should add an independent `grype_db_sync` step to `job_third_party_data_sync`, alongside
the NVD, OSV, and MITRE branches. It must use Grype's supported database update mechanism, record the
Grype tool/image identity and upstream database schema/build identity, enforce download and
extraction bounds, hash every published file, validate the database with the pinned Grype version,
publish immutably with a last-known-good pointer, and expose a bounded lookup/consumer interface.
The step must fail truthfully when provenance, validation, or freshness cannot be established.

## Optimize produced-artifact Grype without reducing coverage

Future artifact Grype work must deduplicate accepted artifacts by content hash and cache only by
artifact hash plus exact Grype image, vulnerability-database digest, and policy identity. It should
reuse hash-verified accepted SBOMs, filter unsupported formats before launch, and use bounded
concurrency with partitioned resumability. Telemetry must report artifact/byte throughput, avoided
launches, and saved work. Acceptance tests must prove that deduplication, filtering, cache reuse,
resume, and sibling failure cannot suppress expected coverage or convert any gap into a clean result.

## Close the remaining CodeQL platform and accepted-build gaps

Cross-language CodeQL now provides hash-pinned offline extractors and query packs, exact protected
compiled-build replay, source/no-build analysis, bounded SARIF normalization, independent
database/query checkpoints, and accepted MCP retrieval. Remaining work is deliberately narrower:
provide an accepted .NET build environment for C#, accepted Cargo locks and analyzer prerequisites
for Rust, and Go recipes that perform the real accepted compilation rather than dependency download
alone. Visual Basic, F#, Ruby, and Swift remain explicit unsupported-platform gaps. Preserve the
current selective invalidation boundary: query-pack changes must not rebuild Clang AST, LLVM IR,
or an otherwise reusable CodeQL database.

## Define and test the CodeQL checkpoint identity matrix

Document a matrix of identity inputs against the derived image, database, query, normalization,
index, and publication checkpoints. It should cover CodeQL CLI and extractor versions, source
bytes, accepted build recipes and replay commands, compiler/toolchain identities, base and derived
image identities, runtime policy and resource limits, query packs and suites, custom queries,
normalizer versions, and output schemas. For each change, state the smallest affected scope and
whether the expected action is reuse, database rebuild, query-only rerun, renormalization, or
republication.

Separate semantic execution inputs from provenance-only representation. A changed recipe or
Dockerfile that resolves to a different compiler, toolchain, filesystem, runtime policy, or output
image must invalidate dependent work; a textual refactor that produces the same verified effective
environment should retain provenance without forcing unrelated databases or queries to rerun.
Back the matrix with table-driven tests that change one dimension at a time and prove both required
invalidation and required reuse across unrelated languages, projects, scopes, and query profiles.

## Joern bounded export and acceptance

Done:

- the pinned, reviewed, offline Joern/c2cpg runtime closure (`tool-joern`);
- the independent `job_cpg_analysis`, which runs c2cpg per accepted C/C++ scope over the exact
  accepted compile commands and retains each CPG as hash-identified, run-owned evidence;
- the `noexec` `/tmp` zstd JNI fix in the image.

The job still publishes a `BLOCKED` shard with zero observations per scope. Remaining work:

- a bounded CPG/PDG exporter (a repository-owned `joern --script`; scripts compile and run fully
  offline in the image);
- the index contract and source mapping;
- slicing;
- exporter security probes;
- live functional fixtures.

Then replace the blocked shard with real observations. Also resolve the per-tool resource profile
(Joern needs far more than 1 GiB at scale) and license attribution for JARs without embedded
metadata. Do not put the full CPG into MCP responses.

## Evaluate additional Joern language frontends

The pinned `v4.0.630` archive is verified whole, but `tool-joern` installs only the core and
`c2cpg`. The other thirteen frontend directories are excluded until a job needs them: `javasrc2cpg`,
`jimple2cpg`, `kotlin2cpg`, `jssrc2cpg`, `pysrc2cpg`, `php2cpg`, `rubysrc2cpg`, `gosrc2cpg`,
`csharpsrc2cpg`, `swiftsrc2cpg`, `rust2cpg`, `abap2cpg`, and `ghidra2cpg`. For each language that a
job will consume:

1. State the job and coverage the frontend serves, and why CodeQL or an existing producer does not
   already cover it.
2. Review the frontend's added JARs and any native AST generator, recording provenance, licenses,
   and advisories in `containers/tools/joern/LICENSE.md`. The native AST generators are
   `astgen-linux`, `SwiftAstGen-linux`, `goastgen-linux`, `dotnetastgen-linux`,
   `rust_ast_gen-linux`, and `abapgen-linux`; `php2cpg` also bundles a PHP parser `.phar`.
3. Prove that native AST generators and any interpreter dependency, such as a PHP runtime, run
   offline as uid 10001 under the read-only, no-network, drop-all policy without writing outside
   scratch.
4. Add the paths to `[closure].include` in `containers/tools/joern/tool.toml`, regenerate
   `inventory.json`, and update `tests/test_joern_tool.py`, which currently asserts that no other
   frontend or ELF binary is installed.
5. Add bounded-export fixtures and keep each language's coverage `unavailable` until they pass.

Do not enable all frontends wholesale: that adds about 2 GB and six unreviewed native binaries.
`ghidra2cpg` is binary analysis and belongs with the binary-analysis decomposition decision, not
source CPG coverage.

## Scale the clangd symbol index

Done: the pinned `tool-clangd-indexer` closure, and the independent `job_cpp_symbol_index`. Per
accepted C/C++ scope it runs clangd-indexer over the exact accepted compile commands. It then
normalizes symbols with exact source locations, and aggregated call/reference edges between
accepted symbols, into `analysis` shards with per-scope coverage and verified checkpoints. A live
run against the real image indexed the fixture completely. Remaining work:

- content-keyed, bounded TU batches with per-TU checkpoints, so Unreal-scale scopes fit the tool
  output bound (index output above it is currently a named truncation gap);
- symbols declared only in headers outside the accepted sources (SDK, engine, system) are counted,
  not indexed; decide how header-only symbols are emitted once across scopes;
- mount licensed MSVC and Windows SDK headers read-only for clang-cl commands;
- a reviewed per-tool resource profile for large compilation databases.

Resolve the open items in `containers/tools/clangd-indexer/LICENSE.md` first: confirming the LLVM
source ref, and an advisory match for the LLVM binary.

## Replace the Python build-capture tool wrapper with a static Go binary

`containers/build-capture/tool-wrapper.py` runs for every `PATH`-resolved build tool (cc, c++, ld,
ar, ninja, cmake and others). Measured cost, inside the executor's container boundary with
`--seccomp-bpf` capture:

- about 40 ms per call;
- 45 calls added about 1.8 s to a 0.65 s fixture build;
- about +9 s (+49%) on an 18 s zstd build.

At AAA scale (tens of thousands of compiler and linker calls) that is tens of CPU-minutes per
build. The wrapper also forces `python3` into every build image.

1. First confirm the wrapper still earns its place. strace already records every exec's argv,
   resolved executable and environment authoritatively. The wrapper's unique outputs are per-tool
   stdout/stderr and tool-call records, which reconciliation treats as optional secondary
   evidence. It also misses compilers invoked by absolute path, which Unreal's build tool does.
2. If it stays, reimplement it as a static Go binary (`CGO_ENABLED=0`) with byte-identical
   behaviour:
   - call ordinal locking and the call limit;
   - per-call record, stdout/stderr retention and envp redaction;
   - `exec` of the real tool.
3. Build it offline from a pinned Go toolchain image with locked modules (standard library only,
   if possible). Install it through the capture assets; never commit a binary.
4. Keep the tool-call record schema stable, and bump the capture identities so that changed
   captures invalidate build checkpoints.
5. Re-run the capture benchmark (plain, wrapped, captured) and record per-call cost before and
   after.
## Build the dataflow, contract, and deployment evidence lanes

Implement the planned jobs and queries in
[`architecture/evidence-sources-and-dataflow-retrieval.md`](architecture/evidence-sources-and-dataflow-retrieval.md),
starting with CodeQL-exported C/C++ dataflow summaries and `query_dataflow`. Unresolved indirect
calls, unmodeled externals, and path/depth limits must be published as gaps.

## Acquire dynamic execution evidence

Coverage profiles, sanitizer logs, fuzz corpora, and IAST traces are not yet available. Define
either a hash-verified import of externally produced artifacts or a separately authorized,
isolated execution job. Positive traces may support reachability; zero coverage is a gap and never
refutes a claim.

## Add Perforce history to source history analysis

`job_source_history_analysis` implements local Git and optional GitHub enrichment only. Perforce is
designed in [`architecture/source-history-analysis.md`](architecture/source-history-analysis.md)
but not built. Implement it as a second history source behind the same signals, ranking, `history`
shard, and plan `history_priority` contract:

- export mode first: consume an operator-produced, SHA-256-pinned `p4 -ztag -Mj` bundle with no
  network or credentials in the review;
- then server mode in a pinned `tool-p4` image whose only egress is the configured `P4PORT`, with a
  pinned changelist, configured `ssl:` trust fingerprint, a ticket from an environment-variable
  secret, and target `P4CONFIG`/`P4ENVIRO`/`.p4config` ignored;
- bind every inventory file to `@N` with `p4 fstat -Ol` digests, reporting `ktext`, purged, and
  protections-hidden paths as per-path gaps;
- use `p4 describe -ds` for churn, `p4 fixes` for exact fix classification, and bounded
  `filelog -i` integration following;
- review the Helix Core CLI license before cataloging the image, and add the history identity probe
  inputs (server identity, depot scope, changelist, bundle hash) so resume reruns on any change.

## Consider following Git submodules in source history analysis

Submodule gitlinks are currently a `submodule_history_not_followed` gap. Decide whether each
submodule should become an independent history source bound to its gitlink commit, how its signals
roll up into the parent's components, and how its own `.git` (often under the parent's
`.git/modules/`, outside the submodule path) is resolved without leaving the target root.

## Finish deferred source history signals

- Exact security-fix classification needs an OSV index of `fixed` Git events keyed by commit id;
  extend the OSV sync index and match walked commits against it.
- Commit subjects are not indexed. Index them only after a gitleaks redaction pass, with a named gap
  when redaction is unavailable.
- PR open-to-merge and deployment timing are named unavailable signals. Acquire them only from
  authoritative sources (GitHub PR timestamps, deployment records), never from commit timestamps.
- Function-level history uses snapshot Tree-sitter spans, so renamed or moved functions keep their
  snapshot identity and deleted functions are not represented. Follow symbol identity across
  history if consumers need it.
- Cognitive complexity does not detect recursion. Add live grammar probes that pin the
  complexity node-type table to the locked Tree-sitter language pack.
- Add an exact-filter `query_history` MCP tool if consumers need more than `find(kind="hotspot")`.
