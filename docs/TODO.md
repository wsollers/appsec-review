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
using nested corpus commit `7c10536389c3cfb20a27d7a6a78943267ea43b3f`. The documentation is
ahead of runtime configuration in these explicit ways:

- add independent typed central controls for build execution capture and compiler-artifact
  collection with `required`, `auto`, and `disabled` values;
- resolve those values immutably per run and include them in receipt and checkpoint identities;
- add deterministic applicability classifiers and explicit policy/not-applicable dispositions,
  without introducing another syscall parser or reconciliation loop;
- migrate CodeQL from the current `manual`/`none` modes and always-enabled parser contract to a
  typed capability model that can express build replay, source/no-build, automatic selection, and
  disabled policy, or retain the current names and document an exact stable mapping; and
- add parameterized tests for every matrix row, including the Rust corpus/parent CodeQL mismatch,
  Python and Node mixed native scopes, specialized-toolchain unavailability, and the distinction
  between syntax-only and material interpreted-language lifecycles.

Until those items land, do not describe conditional capture as deployed. Existing standardized
capture remains mandatory only on the adapters that explicitly call it, and existing CodeQL
receipts must use `manual`, `none`, `NOT_APPLICABLE`, and named gaps as implemented.

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

## Supply a pinned Joern/c2cpg closure

The C++ job now publishes a producer-local Joern shard and precise blocked disposition. Enable it
only after reviewing and locking one platform archive and its complete JDK/dependency closure, then
add bounded CPG export fixtures and security probes. Do not put the full CPG into MCP responses.
