# Generic language-build operations

`job_language_build` consumes only the accepted, hash-verified `job_project_build` handoff. The
current execution implementations include Linux native, Rust/Cargo, JVM/Java/Kotlin, Go,
Node/JavaScript/TypeScript, Python packaging, PHP/Composer, Linux-capable .NET SDK projects and
solutions, and WebAssembly output producers. Accepted Windows-only and .NET Framework projects
publish explicit `NOT_APPLICABLE` receipts.
Native CMake dispatches use the validated deterministic marker command recipe. A failed default
project-build probe may add only validated apt packages through the bounded image-repair workflow;
model output cannot change the accepted command, path, dependency, environment, or output contract.

For every native unit the job revalidates the target snapshot, successful probe identity, recipe,
dependency hashes, build-unit root, derived image identity, and dependency edges. It then copies
the bounded source root into `runs/<run-id>/data/build/native/units/<build-unit-id>/workspace/` and
executes the accepted configure/build argv without a shell. The pinned container uses Docker's
bridge network so declared package-manager dependencies can be downloaded,
runs non-root with dropped capabilities and `no-new-privileges`, has a read-only root, and receives
central CPU, memory, PID, timeout, tmpfs, and output limits. Target binaries and tests are never run.

Receipts catalog generated sources, compile databases, objects, static/shared libraries,
executables, LLVM bitcode/IR, debug data, and link maps. Loader dependencies remain an explicit gap
until a pinned parser is available. Exact recipe and compiler/linker argv are retained only under
the unit's `protected-commands/` directory; searchable records retain argv hashes, sanitized
environment facts, resolved inputs/outputs, artifact hashes, and mapping confidence. A complete
workspace manifest protects the handoff consumed by later language-specific analysis.

The JVM adapter accepts Maven, Gradle, and direct `javac` recipes, including mixed Java/Kotlin
sources assigned to one accepted build topology. `mvnw` and `gradlew` recipe names are resolved to
the pinned system Maven or Gradle in the verified image; repository wrapper payloads are never
executed. Maven commands must explicitly disable tests, and Gradle application/test/check tasks are
rejected. Real builds remain non-root and may resolve declared dependencies over the network.

The adapter instruments available `javac`, `kotlinc`, annotation/code-generator, archiver, and
related JVM tools and retains exact nested argv only in a protected trace. It catalogs class files,
generated Java/Kotlin sources, resources and dependency metadata, Kotlin module/source-map data,
and JAR/WAR/EAR packages. When a build tool performs compiler or packaging work in-process and no
nested invocation is observable, the receipt reports a provenance gap instead of inventing a
command. Maven/Gradle build-driver commands and their separate stdout/stderr artifacts always retain
hashes, original and retained sizes, configured bounds, truncation and diagnostic-tail state,
exit/timeout state, duration, image, command, and attempt identities.

The Go adapter preserves the accepted module/workspace root, package targets, build tags, and cgo
choice. It prefers an existing vendor tree when present and otherwise permits module resolution, and
adds `-x` only to obtain the toolchain trace. Compiler, assembler, linker, cgo, package-builder,
generator, and post-link invocations are retained with exact argv in protected artifacts and only
hashes plus sanitized facts in receipts and retrieval. A bounded `go list -deps -json` catalog
records package/module relationships without running packages or tests. Module/workspace files,
vendored metadata, generated Go/assembly sources, archives, ELF outputs, build IDs, and the status of
embedded debug data are hash-bound to the workspace manifest.

The Rust adapter accepts bounded Cargo workspace/package, target triple, profile, feature,
`--locked`, and `--offline` choices. Central policy permits dependency download and can still
require a lockfile when configured. Recipes requesting tests, examples, benchmarks, `cargo run`, or installation are
rejected before execution. A protected wrapper layer records rustc, linker-driver, and archiver
argv; Cargo verbose output records build-script/code-generator execution, while Cargo metadata
identifies proc-macro targets, workspace packages, and exact resolve relationships. Generated Rust
sources, rlib/rmeta files, static/shared libraries, binaries, and debug/dependency metadata are
cataloged without executing target programs.

Each command stream is a separate protected artifact with its SHA-256, original and retained byte
counts, configured limit, truncation state, exit/timeout state, duration, image, command, and attempt
identities. When a stream is truncated, a bounded diagnostic tail is retained separately. Neither
stream bytes nor exact argv are placed in pipeline events, retrieval shards, or MCP responses.

The Node adapter accepts npm, pnpm, or Yarn when `package.json` is present; a single matching
lockfile is used when available. Dependency installation may occur in the derived image or the
network-enabled build sandbox with lifecycle scripts disabled. Build lifecycle scripts are untrusted target code and keep
the same non-root, read-only-root, capability, PID, CPU, memory, timeout, and stream limits as every
other build. Install, test, start, publish, `npx` download, and direct Node application commands do
not enter this path.

Successful direct commands and simple package-script invocations retain exact argv only in
protected command artifacts. Diagnostic traces additionally capture compiler, transpiler,
code-generator, bundler, native-addon, assembler, linker, archiver, package-builder, and post-link
commands when the invoked tool emits them. The catalog records generated JavaScript/TypeScript and
declarations, bundles and assets, source maps with bounded source relationships, packages, native
addons, and native intermediates. Complex shell-composed scripts or tools that do not emit nested
invocations produce explicit provenance gaps; they are never inferred as observed.

The Python adapter accepts package builds rooted by `pyproject.toml`, `setup.py`, or `setup.cfg`.
Poetry, Pipfile, and requirements inputs may bind dependency resolution in the derived image;
real builds may download declared dependencies and PEP 517 build-isolation dependencies.
Only package frontends, `compileall`, and bounded legacy setuptools build verbs are accepted—module
imports, application entry points, tests, and arbitrary Python scripts are rejected. Build hooks
remain untrusted target code inside the same pinned, non-root container boundary.

Receipts record the selected build backend, wheel and sdist contents, generated sources, package
metadata, bytecode, native extensions and intermediates, and declared package/workspace
relationships. Package-builder and backend invocations are exact by construction; compiler,
transpiler, generator, assembler, linker, and archiver commands are retained when the package tool
emits them. Exact argv and stream bytes stay protected, while the `build` retrieval shard exposes
only hashes, outcomes, bounded stream facts, and artifact identities.

.NET restore may resolve packages declared by the accepted project inputs; build, publish, and pack
commands may perform their normal implicit restore. The adapter never runs tests or target
applications. It catalogs C#/VB/F# assemblies, portable PDBs, generated sources, NuGet packages,
dependency/runtime configuration, native/AOT outputs, project/package/reference topology, and
compiler, generator, resource, linker/trimmer, AOT, packaging, and native-tool invocations exposed
by MSBuild diagnostic streams. Exact argv and stdout/stderr remain protected run artifacts. A
sanitized `build` retrieval shard exposes command hashes, status, bounded stream metadata, and
artifact identities without exposing those protected bytes.

Rust command, artifact, Cargo-package, and dependency evidence is published through the same
sanitized `build` shard. Raw Cargo output, exact argv, wrapper captures, environment values, and
diagnostic tails remain run-owned protected artifacts and are never returned through retrieval or
MCP.

The PHP adapter requires `composer.json`; `composer.lock` is used when present. Composer dependency
installation may occur while deriving the pinned project image or during the network-enabled build,
with plugins and scripts disabled. Central policy controls Composer plugins and
scripts independently. Plugins default to disabled; enabled scripts remain untrusted target build
code and receive the same non-root, read-only-root, capability, resource, timeout, and stream
bounds as every other accepted command. Application entry points and tests are never run.

Receipts retain Composer package/version metadata, lock content identity, root and transitive
dependency relationships, script definitions as hashes, generated autoload files and PHP sources,
distributable archives, native extensions, and observed top-level build-tool provenance. Exact argv,
environment values, stdout/stderr, and diagnostic tails remain protected. The sanitized `build`
retrieval shard exposes only command hashes and outcomes, bounded stream facts, package/artifact
identities, and dependency relationships.

Build-unit dependencies execute in topological layers. A failed dependency blocks its dependents,
but unrelated units continue in the configured worker pool. A checkpoint is reusable only when its
target snapshot, recipe, dependency hashes, image, executor/capture identity, toolchain, probe, and
upstream handoff are unchanged and every retained artifact still verifies.

Inspect `data/logs/pipeline.jsonl` for `LANGUAGE_BUILD_STARTED`, `BUILD_COMMAND_COMPLETED`,
`LANGUAGE_BUILD_COMPLETED`, and `LANGUAGE_BUILD_REUSED`. Events intentionally contain identities,
counts, dispositions, gap counts, and durations—not command text or environment values.

## Live acceptance

Dagster run `d51d396c-4f0f-4386-a503-859b399f1449` (application run
`2026-10-08-0081`) completed all 248 orchestration steps successfully against
`targets/appsec-multi-vuln`. The accepted language-build handoff was
`COMPLETED_WITH_GAPS`: one native unit and seven direct-Java units succeeded, with 19 native and 15
JVM artifacts and protected command/stream evidence. Nine .NET units were explicitly `BLOCKED`
because no validated inference recipe was accepted. Go, Node, Python, PHP, Rust, and WebAssembly had
no accepted recipe on this target and were reported as not selected, not as clean builds. The
composed `build` retrieval manifest retained the pre-existing catalog shard and the new
`language-build` shard; a pinned MCP query resolved the JVM class artifacts by hash without exposing
protected argv or stream bytes. The hash-bearing record is
`deploy/dagster/verification/wave1-live-acceptance.json`.

Historical verification records apply only to the revisions and graph shapes they identify. A
canceled, partial, historical, or standalone WASM run is not acceptance for the integrated graph.
