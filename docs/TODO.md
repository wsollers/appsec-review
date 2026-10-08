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

Current status: the generic Linux native/CMake, Rust/Cargo, JVM Java/Kotlin (Maven, Gradle, and direct compiler), Go, lockfile-bound Node/JavaScript/TypeScript, lockfile-bound PHP/Composer, Linux-capable .NET SDK, and WebAssembly output-family adapters now cover
accepted dispatch validation, real build execution, protected compiler/link provenance, artifact catalogs, dependency ordering,
failure isolation, checkpoint reuse, default-image-first probing, three bounded inference-guided
dependency-image repairs, successful Dockerfile/image reuse, and dynamic C++/post-build
consumption. The Go adapter supports accepted modules/workspaces, vendor mode, package targets,
build tags, and cgo; retains bounded `go -x` provenance and stream artifacts; and catalogs modules,
packages, generated sources, binaries, build IDs, and sanitized retrieval records. The .NET adapter
additionally enforces locked restore, catalogs MSBuild/Roslyn and
managed/native outputs, and reports Windows-only/.NET Framework units as explicit platform gaps.
The Rust adapter accepts Cargo workspaces/packages and bounded target/profile/features/locked/offline
choices; retains rustc, linker, archiver, build-script, and proc-macro provenance; catalogs Cargo
metadata and resolve edges plus generated sources, rlib/rmeta, native libraries, binaries, and debug
metadata; and publishes sanitized build evidence without executing tests or produced programs.
The Node adapter accepts npm, pnpm, and Yarn identities; denies network and application/test
execution; treats lifecycle scripts as sandboxed target code; and catalogs generated code, bundles,
maps, packages, and native addons with protected command/stream evidence and sanitized retrieval.
The PHP adapter requires `composer.lock`, prepares dependencies in the pinned derived image with
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
class evidence while retaining the unrelated catalog build shard. Producer-positive live coverage
for Rust, Go, Node, .NET, Python, PHP, and WASM remains required before the Linux vertical can be
closed; focused executor tests cover those family contracts in this revision.
The full Linux vertical remains open: static dispatch execution, entitled CodeQL, pinned
loader-dependency parsing, broader MCP integration, and cross-language live acceptance are still
required. Retained Dagster records describe only the revisions and selected target recipes they
captured.

Probe policy must be centrally configurable per build unit as `configure`, `selected-target`, or
`full-build`. This keeps the default test target rigorous without forcing future large repositories
through an unnecessary full probe before every instrumented or traced build.

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

## Supply a pinned CodeQL closure

The C++ job now publishes a producer-local CodeQL shard and precise blocked disposition. Enabling
database creation and queries still requires a configured runtime capability plus a hash-pinned
offline CLI, extractor, query-pack, and license-notice closure. Include both traced compiled builds
and no-build interpreted-language databases. Preserve the current selective invalidation boundary:
query-pack changes must not rebuild Clang AST, LLVM IR, or an otherwise reusable CodeQL database.

## Supply a pinned Joern/c2cpg closure

The C++ job now publishes a producer-local Joern shard and precise blocked disposition. Enable it
only after reviewing and locking one platform archive and its complete JDK/dependency closure, then
add bounded CPG export fixtures and security probes. Do not put the full CPG into MCP responses.
