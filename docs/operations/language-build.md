# Generic language-build operations

`job_language_build` consumes only the accepted, hash-verified `job_project_build` handoff. The
current execution implementations include Linux native, Rust/Cargo, JVM/Java/Kotlin, Go,
Node/JavaScript/TypeScript, Python packaging, PHP/Composer, Linux-capable .NET SDK projects and
solutions, and WebAssembly output producers. Accepted Windows-only and .NET Framework projects
publish explicit `NOT_APPLICABLE` receipts.
A planned unit that `job_project_build` probed but could not build (for example its build image is
unavailable) is never an absent lane: its family publishes a `BLOCKED` receipt with
`upstream_failure` (`job_id`, `terminal_status`, `reason`) and a gap naming the unit, the failure and
`job_project_build`, so the job is `COMPLETED_WITH_GAPS`. `NOT_APPLICABLE` means the target has no
planned unit of that family.
Bundler is intentionally not an execution lane: an accepted `Gemfile` produces a named gap stating
that no pinned Ruby build profile or executor exists and that gem installation, lifecycle hooks,
packaging, and native extensions were not run. Ruby source-mode Tree-sitter and CodeQL coverage do
not imply Bundler or target-code execution.
Each load lane revalidates only the accepted dispatch families it can consume. Handoff hashes,
the target snapshot, workflow envelopes, and unique build-unit identities remain shared integrity
checks; probe, image, recipe, descriptor, and dependency validation is lane-owned. An invalid
recipe therefore fails its consuming family without aborting unrelated language loads.
Native, Rust, and .NET commands share one captured-build driver and the generic
`reconcile_captured_build` successful-exec reconciliation through `CapturedBuildDescriptor`
instances; the descriptors classify observed tools and map language-specific inputs, outputs,
artifacts, and metadata. Go runs under the same executor/collector boundary and standardized
syscall capture records but reconciles them in its own `go.capture_invocations`, with the same
authority rule: only successful process-exec events establish that a tool ran.

## Conditional-capture operator flow

The authoritative control semantics and fixture matrix live in
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md).
The tri-state build-capture and compiler-artifact controls described there are implemented in the
typed central configuration and frozen resolved-run snapshot. Build capture defaults to `required`
and can be overridden only for `job_project_build` or `job_language_build`. Compiler-artifact
collection defaults to `required` in `job_language_build` and accepts overrides only for the fixed
language families documented in the configuration reference. The runtime applicability evaluator
applies the two controls independently:

1. For `required`, run the applicable capture or collection path. Unavailability, failure, or
   incomplete evidence is a coverage gap and cannot be reported as clean.
2. For `disabled`, do not run it and record `SKIPPED_POLICY` with the exact resolved configuration
   identity.
3. For `auto`, evaluate only the bounded accepted manifests, recipe, classifier, and toolchain
   facts. If they establish package hooks, generation, transpilation/bundling, native extensions,
   or compiler/linker work, run the applicable path.
4. For an interpreted project with only a syntax command (`python -m py_compile`, `php -l`, or
   `node --check`), record evidence-supported `SKIPPED_NA`; do not treat the syntax check as a
   material build.
5. For an interpreted project with a package lifecycle, build hook, generator, transpiler,
   bundler, or native extension, treat the lifecycle as material and apply `required` or `auto` as
   resolved. A skip or not-applicable result is never a clean-security claim.

CodeQL central configuration uses `build`, `source`, `auto`, and `disabled`. The executor retains
`manual` for exact accepted build replay and `none` for source/no-build creation; the evaluator
selects that capability before execution. `auto` is descriptor-driven and `disabled` produces
`SKIPPED_POLICY` without creating a database.

The reason codes operators will see are `POLICY_REQUIRED`, `POLICY_DISABLED`,
`MATERIAL_BUILD_CONFIRMED`, `MATERIAL_BUILD_ABSENT`, `INVENTORY_UNAVAILABLE`,
`ARTIFACT_CAPABILITY_CONFIRMED`, `ARTIFACT_CAPABILITY_ABSENT`, `CODEQL_BUILD_SELECTED`,
`CODEQL_SOURCE_SELECTED`, `CODEQL_NOT_APPLICABLE`, `CAPABILITY_UNSUPPORTED`,
`TOOLCHAIN_UNAVAILABLE`, `PROCESSING_FAILED`, `EVIDENCE_INCOMPLETE`,
`ARTIFACT_VALIDATION_FAILED`, and `PROCESSING_SUCCEEDED`. Inventory/configuration identity errors
are framework-integrity failures; ordinary unavailable tools and failed processing remain `GAP`.

Native CMake dispatches use the validated deterministic marker command recipe. A failed default
project-build probe may add only typed repairs through the bounded image-repair workflow: apt
packages, allowlisted environment variables, a pinned package manager, and restores of accepted
manifests (see [`project-build.md`](project-build.md)); model output cannot change the accepted
command, path, dependency-file, or output contract.

For every native unit the job revalidates the target snapshot, successful probe identity, recipe,
dependency hashes, build-unit root, derived image identity, and dependency edges. It then copies
the bounded source root into the receipt-bound native build workspace and
executes the accepted configure/build argv without a shell. The pinned container uses Docker's
bridge network so declared package-manager dependencies can be downloaded,
runs non-root with dropped capabilities and `no-new-privileges`, has a read-only root, and receives
central CPU, memory, PID, timeout, tmpfs, and output limits. Target binaries and tests are never run.
The capture driver creates a fresh owner-only scratch directory inside the run-owned workspace for
each command and binds `TMPDIR`, `TMP`, and `TEMP` to it. Compiler and build-system temporaries,
including MSBuild response files, therefore remain inside the workspace boundary until capture can
retain their bounded content. MSBuild's tool-temporary preservation switch prevents it from deleting
response files before that snapshot. A target collision cannot select this directory because creation is
atomic; a response path outside the workspace, an over-limit or removed response file, or malformed
response identity is an explicit coverage gap or integrity failure rather than silently omitted
provenance.

### Raw strace retention (debug period)

`build_capture.retain_raw_traces` (shipped `true` globally and in both build jobs' overrides) keeps
each command's raw per-process `strace` files instead of discarding them after normalization. They
are copied to `raw-traces/trace.<pid>` beside `record.json` in the run-owned
`execution-capture/command-NNN/` directory, up to `build_capture.raw_trace_bytes_limit` bytes per
command (shipped 64 MiB; 1 byte to 1 GiB). A file that crosses the bound keeps only whole lines below
it, and every later file is listed as not retained; each entry in `record.json`'s `raw_traces`
records the source size, retained bytes and lines, a `truncated` flag and, when retained, its
SHA-256 (taken after redaction). Values of `envp_redact_names` variables are redacted on copy, and
each full raw trace is part of the capture's gitleaks corpus; a finding (or a failed scan) redacts the
retained copy through the same path as the other retained capture files. Raw traces are debug
material, never evidence: truncation is not a coverage gap. A collector row the normalizer cannot
parse is still a named coverage gap and now names its location, for example
`unparsed openat row: trace.21:2 (retained as raw-traces/trace.21 line 2)`, or says why the raw
trace was not retained. Set `retain_raw_traces = false` to return to discarding raw traces.

Receipts catalog generated sources, compile databases, objects, static/shared libraries,
executables, LLVM bitcode/IR, debug data, and link maps. Loader dependencies of ELF executables and
shared libraries are read from the dynamic section by a bounded in-repository parser that loads and
executes nothing. Every name must terminate inside the `DT_STRSZ`-declared string table, and the
interpreter inside its `PT_INTERP` segment; a file it cannot parse that strictly is a named gap, never
a resolved dependency list. Successful process-exec syscall events are the only authority that a
native compiler, assembler, linker driver, linker, archiver, generator, post-link tool, or build
driver executed. Validated compile databases and link files may enrich input/output mappings only
after an exact argv match to such an event; they never establish tool provenance. Every command
carries argv/envp/connect capture and a gitleaks receipt. Capture loss, a redacted exec, an unmatched
wrapper call, or an unobserved compiler is a named gap, makes provenance incomplete, and prevents
checkpointing. Exact recipe and compiler/linker argv are retained only under
the unit's `protected-commands/` directory; searchable records retain argv hashes, sanitized
environment facts, resolved inputs/outputs, artifact hashes, and mapping confidence. A complete
workspace manifest protects the handoff consumed by later language-specific analysis.

Every catalogued artifact's `kind` comes from one typed vocabulary,
`ArtifactKind` in `src/appsec_review/jobs/artifact_kinds.py`; a kind outside it fails the receipt.
A kind names the artifact's role (`object`, `executable`, `shared-library`, `static-library`,
`jvm-class`, `dex`, and so on), never a raw format tag. Machine-code roles come from bounded header
bytes rather than the file name: the ELF `e_type` and `PT_INTERP` program header (so a PIE
executable and `libx.so.1` are told apart), the `ar` magic, PE characteristics, and the Mach-O file
type. Build bookkeeping is left out of the catalog and counted instead: CMake compiler
identification, ABI detection, `try_compile` and Find-module probe trees (in every family), and,
for Rust, Cargo fingerprints, incremental caches, dependency-info files and build-script records.
The receipt's `excluded_bookkeeping` (`appsec-review/build-bookkeeping-exclusions/1`) gives the
count per typed reason with up to five example paths, and native compile databases omit CMake probe
compiles the same way (`src/appsec_review/jobs/build_bookkeeping.py`). Files inside a configured
`[build_outputs]` exclusion or a classified dependency tree are not bookkeeping-counted, so a
FetchContent target reports lower CMake bookkeeping counts than before; see
[Build-output dispositions](#build-output-dispositions).

Captured tool rows name the command whose execution capture observed them (`parent_command_id`,
from the row's `execution-capture:command-NNN` origin), and their relative output paths resolve
against the working directory the kernel recorded for that exec (`make -C`, the CMake build tree, a
Cargo member package), not the recipe directory. An output a row names therefore resolves to its
producing action in [`artifact-indexing.md`](artifact-indexing.md); an artifact no row names stays an
ambiguous producer mapping and a gap.

The JVM adapter accepts Maven, Gradle, and direct `javac` recipes, including mixed Java/Kotlin
sources assigned to one accepted build topology. `mvnw` and `gradlew` recipe names are resolved to
the pinned system Maven or Gradle in the verified image; repository wrapper payloads are never
executed. Maven commands must explicitly disable tests, and Gradle application/test/check tasks are
rejected. Real builds remain non-root and may resolve declared dependencies over the network.

Android application descriptors using `com.android.application` are a deterministic specialization
of that JVM path. Nested Gradle modules collapse into the accepted root unit; bounded descriptor
facts select the dedicated `android` profile before inference. The request carries that required
profile, the bounded descriptor contents, and the validator-derived Gradle task policy. Project-build
then preserves the accepted inferred recipe and resolves the dedicated Android image. The immutable
profile is locked by image ID and
contains JDK 17, Gradle 8.9, Android command-line tools, Platform 35, Build Tools 35.0.0, and
platform-tools. JVM instrumentation prepends its wrappers to the configured path for the accepted
profile, so Android retains the pinned Gradle and SDK directories rather than inheriting the generic
Java path. Gradle and Android mutable homes live on the Android executor's writable executable
`/tmp` mount; the image root and dependency cache remain read-only. Successful acceptance
requires a non-empty ZIP-valid APK containing `AndroidManifest.xml` and `resources.arsc`.
Android intermediate and output metadata are cataloged without executing the application.
Project-build acceptance and language-build execution use the same Maven/Gradle command-policy
validator. The Android profile's only accepted task suffixes are `assemble` and `assembleDebug`.
Test, connected-test, install, run, and non-APK Gradle tasks remain rejected before execution.

The existing Java/Kotlin CodeQL path layers its pinned payload onto that accepted Android image;
CodeQL is not installed in the build image. Manual replay receives fresh run-owned Gradle/Android
caches, then the configured default and security-extended suites operate on the Java database.

The adapter instruments available `javac`, `kotlinc`, annotation/code-generator, archiver, and
related JVM tools and retains exact nested argv only in a protected trace. Each wrapper exec writes
its own record file under `/appsec-jvm-evidence/invocations.d/`, so parallel compilations never
interleave. For every readable, non-symlink `@argfile` the record also keeps the file's path, the
directory the tool ran in, and its first 1 MiB of contents with NUL bytes stripped, because Maven
and Gradle delete their argument files once the compiler exits. One javac-compatible tokenizer
expands them. Relative arguments resolve against that recorded `/workspace` directory, or else
against the recipe source directory. `javac` rows add hash-resolved class outputs
(`javac-derived-class`, including nested and anonymous classes) derived from `-d` and each source's
package and types. A missing argfile or an unreadable source is a named gap. Argfile contents stay in
the protected record, and receipts carry `argfile_sha256` and `expanded_argv_sha256`.
Maven compilation is forked through the PATH `javac` wrapper.
It catalogs class files, generated Java/Kotlin sources, resources and dependency metadata, Kotlin
module/source-map data, DEX files, APK packages, and JAR/WAR/EAR packages. When a build tool
performs compiler or packaging work in-process and no nested invocation is observable, the receipt
reports a provenance gap instead of inventing a command.

Gradle compiles Java and Kotlin inside its own JVM, so every language-build Gradle command (plain
and Android) runs with a run-owned init script,
`/appsec-jvm/gradle/appsec-provenance.init.gradle`, generated from
`job_language_build/gradle_provenance.py`. The accepted tasks are validated first. Execution then
appends only options: `--no-daemon`, `--no-build-cache`, `--no-configuration-cache`,
`-Pkotlin.compiler.execution.strategy=out-of-process`, and `--init-script <path>`. It removes recipe
`--daemon`, `--build-cache`, and `--configuration-cache` flags, because a reused daemon, a cache hit,
or a configuration-cache replay would hide compilation. The command receipt's `instrumentation`
field records the operator-declared instrumentation release and every added or removed argument,
not a hash of the supplied script.

Supplied wrappers and scripts live in the reserved run-owned JVM unit's `instrumentation/`
directory, mounted read-only at `/appsec-jvm`.
Generated execution records have a separate writable mount at `/appsec-jvm-evidence`; the
executor closes that write window on completion or failure. Neither mount overlaps `/workspace`.
Target snapshots therefore retain target-owned lookalike paths without hashing the supplied
instrumentation. Generated records remain verified evidence; transient JDK mirrors are removed
and excluded from review payload hashing. JVM/Wasm reuse requires declared platform,
validation, build-toolchain and `jvm_instrumentation`/`wasm_instrumentation` releases; missing
declarations disable reuse rather than falling back to supplied-file hashes.

- **Java (`JavaCompile`, including AGP's `compile*JavaWithJavac`).** Each task's `javaCompiler` is
  replaced lazily by a mirror of the JDK the task would have used: an explicit task toolchain, the
  `java` extension toolchain, or the Gradle JVM. The mirror, under `/appsec-jvm-evidence/jdk/<id>/`,
  links every entry of that JDK except `bin/javac` and `bin/java`, which are the recording wrappers.
  Gradle therefore probes a complete JDK of the same version, and its fork-executable validation
  (which compares the canonical home of `forkOptions.executable` with the `javaCompiler` home)
  passes. The replacement uses Gradle's own internal `SpecificInstallationToolchainSpec`.
  - *When it is replaced.* `JavaCompile` declares `javaCompiler` `finalizeValueOnRead`: the first
    read fixes the value, and later changes fail with `IllegalStateException`. The task graph reads
    it, so `taskGraph.whenReady` is always too late. AGP reads it too, inside the configure action of
    its lazily registered variant task (it chooses the JDK whose `jlink` builds its JDK image from
    it), and that action runs at task realization, after `projectsEvaluated`. A replacement made only
    after evaluation therefore found AGP's toolchain already final: the task compiled in-process, and
    AGP's `jlink` ran from the real JDK. The init script now replaces the toolchain twice. The first
    replacement is registered from `gradle.beforeProject` through `plugins.withId('java-base')`, so
    it runs right after java-base sets its `javaCompiler` convention and before the configure action
    of any task a plugin registers later (Gradle runs configure actions in registration order). The
    second runs after all projects are evaluated and wraps an explicit toolchain a build script set
    later. Wrapping a mirror again is a no-op. The task record lists the phases that took effect
    (`replacement_phases`) and the phases that found the value final (`replacement_errors`).
  - *Forking.* Immediately before the task's own compile action, after every build-owned `doFirst`
    action, the task is set to `fork = true` with `forkOptions.executable` set to the mirror `javac`.
    A target action that resets the fork options therefore cannot undo it. If Gradle's internal task
    action cannot be identified, the hook falls back to `doFirst` (`pre_compile_hook` records which).
    Gradle then runs the command-line compiler with its exact `@argfile`, and that compilation is an
    observed exec. The mirror is removed after the build.
  - *What cannot be observed.* A plugin that sets `javaCompiler` explicitly and reads it in the same
    configure action, or that calls `finalizeValue()` or `disallowChanges()` on it before the first
    replacement, leaves no point at which the toolchain can be replaced. Forking to the mirror `javac`
    without replacing the toolchain fails Gradle's validation, and the real JDK cannot be
    instrumented in place. Such a task compiles in-process. It is recorded as `fork-unavailable`, with
    the `reason` that the toolchain was final before it could be replaced, and stays a declared
    record with a named gap.
  - The pinned Gradle 8.9 and Gradle 8.14 were verified offline. On another version the fallback
    below applies.
- **Kotlin (KGP `KotlinCompile`, including kapt stub tasks).** The init script sets
  `compilerExecutionStrategy` to `OUT_OF_PROCESS`. When the Kotlin toolchain is the Gradle JVM,
  which means the `java` extension toolchain is unset or has the same major version, the init script
  points `kotlinJavaToolchain` at the mirror. The `java ... K2JVMCompiler @argfile` exec is then
  recorded and typed as an observed `kotlinc` invocation with `launcher: java`. A different
  toolchain version is left untouched and reported.
- **Declared task records.** Every compile task and every Android D8/R8 dex task
  (`com.android.build.*` `Dex*`/`D8*`/`L8Dex*`/`R8*` tasks) also writes a JSON record to
  `/appsec-jvm-evidence/gradle-tasks.jsonl`. A record holds the task path and type, configured compiler
  arguments, sources, destination, classpath count, release/target settings, toolchain home,
  instrumentation outcome, and `did_work`. Records are bounded by the JVM `trace_bytes` and
  `provenance_count_limit` settings. They become receipt `declared_compilations` rows with
  `evidence_kind: build-tool-declared`, `mapping: gradle-init-script-task-record`, and confidence
  0.5. Observed rows in `tool_invocations` carry `evidence_kind: observed-exec` and confidence 1.0.
  A declared row is linked to an observed exec only through the same parent command, compiler, and
  resolved `-d` destination (`observed_invocation_ordinals`). Exact declared arguments stay in the
  protected invocation file, and the receipt keeps only their hash.

The following are named gaps: a compile task that did work without a matching observed exec (for
example, when forking or the toolchain replacement was unavailable); a Gradle command whose init
script never reported; and every Android dex task. D8 and R8 run in-process in Gradle workers, so
the receipt records their declared outputs and input count, never an invocation. Artifact-transform
dexing of external libraries is not recorded at all. An Android build that dexes therefore completes
with gaps. NO-SOURCE and up-to-date tasks (`did_work: false`) compiled nothing and are not gaps.
`tests/test_gradle_provenance.py` covers this with fakes. It also runs a real offline build of a
synthetic java-library and application project, with and without `--parallel`, when
`APPSEC_GRADLE_HOME` names a Gradle distribution. That build includes two modules that configure a
`JavaCompile` the AGP way, without AGP (which needs the network). One reads its toolchain during
late realization and resets the fork options in configuration and in a `doFirst` action; it must
still fork through the mirror. The other sets and reads its toolchain in one configure action; it
must remain a declared record with a named gap.
Maven/Gradle build-driver commands and their separate stdout/stderr artifacts always retain
hashes, original and retained sizes, configured bounds, truncation and diagnostic-tail state,
exit/timeout state, duration, image, command, and attempt identities.

The Go adapter preserves the accepted module/workspace root, package targets, build tags, and cgo
choice. It prefers an existing vendor tree when present and otherwise permits module resolution.
Recipes may run `go build`, `go generate`, and `go mod download|verify|vendor`; toolchain or tree
substitution (`-toolexec`, `-exec`, `-overlay`, `-C`, `-modfile`, also through `GOFLAGS`) and an
output path outside the build unit are refused before execution. Every accepted command and the
bounded `go list -deps -json` package catalog run under the standardized execution capture
described in
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md);
each command receipt carries a hash-verified `execution_capture` identity and its gitleaks findings
identity. Successful process-exec syscall events at image-owned paths, reconciled with PATH
tool-call records, are the only evidence for compiler, assembler, linker, cgo, C-driver, and
package-builder execution. `-x` is still added, but its stderr trace is a retained diagnostic
stream and is not parsed for provenance. Exact argv stays in protected artifacts; receipts and
retrieval keep hashes plus sanitized facts. The package catalog records package/module
relationships without running packages or tests. The Go build ID, toolchain version, module
dependencies, and the status of embedded debug data are read from each ELF output by a bounded
in-repository parser; no produced file is executed or handed to a toolchain command. Module and
workspace files, vendored metadata, generated Go/assembly sources, archives, and ELF outputs are
hash-bound to the workspace manifest. Capture caps, scanner failure, redacted or argv-truncated
exec events, unreconciled tool-call records, an unobserved compiler, an executable without an
observed linker, an unparseable catalog, and an unparseable output are named gaps; a unit with an
incomplete capture or incomplete tool provenance is not checkpointed.

The Rust adapter accepts bounded Cargo workspace/package, target triple, profile, feature,
`--locked`, and `--offline` choices. Central policy permits dependency download and can still
require a lockfile when configured. Cargo incremental compilation is disabled for probes and builds:
its owner-only session locks would be unreadable to the orchestrating user that hashes the workspace. Recipes requesting tests, examples, benchmarks, `cargo run`, or installation are
rejected before execution. Cargo metadata and every accepted Cargo command run under the
standardized execution capture described in
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md);
each command receipt carries a hash-verified `execution_capture` identity and its gitleaks findings
identity. Successful process-exec syscall events, reconciled with PATH tool-call records, are the
evidence for rustc, linker-driver, linker, archiver, and build-script/code-generator execution;
Cargo output is retained as a diagnostic stream and is not parsed for provenance. Cargo metadata
identifies proc-macro targets, workspace packages, and exact resolve relationships. Generated Rust
sources, rlib/rmeta files, static/shared libraries, binaries, and debug/dependency metadata are
cataloged without executing target programs. A captured `rustc` row names its outputs the way rustc
names them, from `--crate-name`, `--crate-type`, `--emit`, `-C extra-filename`, `--target`, and
`--out-dir` or `-o` (rlib, rmeta, static or shared library, executable, dependency info). Cargo's
uplifted copy outside `deps/` is named as the same row's output only when its digest equals rustc's
output (`cargo-uplift-identical-digest`). A tool-call record without a matching successful
process-exec event is never tool provenance. Capture caps, scanner failure, redacted exec events,
unreconciled tool-call records, and an unobserved compiler are named gaps; a unit with an
incomplete capture or incomplete tool provenance is not checkpointed.

Each build-driver command stream is a complete run-owned protected file with its SHA-256, byte
count, exit/timeout state, duration, image, command, and attempt identities. The configured
`output_bytes` value limits only an in-memory parser/event preview; the receipt records that preview
limit and whether the preview omitted bytes, while `truncated` remains false for the complete file.
Failure handling reads a bounded diagnostic tail from the complete file on demand. Neither stream
bytes nor exact argv are placed in pipeline events, retrieval shards, or MCP responses.

The Node adapter accepts npm, pnpm, or Yarn when `package.json` is present; a single matching
lockfile is used when available. Dependency installation may occur in the derived image or the
network-enabled build sandbox with lifecycle scripts disabled. Build lifecycle scripts are untrusted target code and keep
the same non-root, read-only-root, capability, PID, CPU, memory, timeout, and stream limits as every
other build. Install, test, start, publish, `npx` download, and direct Node application commands do
not enter this path.

Before any Node command runs, the lifecycle policy resolves the whole package-script graph the
recipe's commands reach and classifies every script body with the same rules at every depth. The
graph follows npm, pnpm, and Yarn script runs (`run <script>`, the bare pnpm/Yarn script form,
and `test`/`start` aliases), directory changes (`--prefix`, `--dir`, `-C`, `--cwd`), workspace
members (npm `-w`/`--workspace`/`--workspaces`, `pnpm -r` and `--filter` name, path, and `...`
dependency selectors over `pnpm-workspace.yaml`, `yarn workspace <name>`,
`yarn workspaces foreach`/`run`), `run-s`/`run-p`/`npm-run-all` groups, and the `pre`/`post` hooks
of every script it reaches (for every package manager, which is stricter than pnpm and Yarn
defaults). A simple command that runs `node`, `tsx`, or `ts-node` without `--check` blocks the
unit with `package lifecycle script <script> may execute a target application`, and a test runner
blocks it with `... requests a test runner`. Each gap names the full chain from the requested
script to the command, for example
`package.json#scripts.build → backend/package.json#scripts.build → node scripts/copy-assets.mjs`,
so a workspace root is blocked for the same repository code as the member that contains it. A
cycle, a chain deeper than eight scripts, more than 256 script visits, an unknown workspace or
filter, a directory that escapes the workspace, or an unparseable script is its own named gap,
never a pass. Commands outside these forms are classified as leaves; they are not followed.

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
compiler, generator, resource, linker/trimmer, AOT, packaging, and native-tool invocations established
by successful process-exec syscall events. Managed SDK tools hosted by `dotnet`, including Roslyn
compiler DLLs, are classified from the argv of that observed host exec. Wrapper records add status
and stream hashes only after reconciliation to a successful exec; diagnostic output is never tool
provenance. Each command carries hash-verified syscall/envp/connect evidence and a gitleaks result.
Capture loss, a redacted exec, an unmatched wrapper record, or an unobserved compiler is a named gap
and prevents a checkpoint. Exact argv, envp values, syscall rows, and stdout/stderr remain protected
run artifacts. A sanitized `build` retrieval shard exposes command and capture hashes, status,
bounded stream metadata, provenance counts, and artifact identities without exposing those protected
bytes.

Rust command, artifact, Cargo-package, and dependency evidence is published through the same
sanitized `build` shard, together with the capture record, event, and findings hashes. Raw Cargo
output, exact argv, syscall events, tool-call records, environment values, and diagnostic tails
remain run-owned protected artifacts and are never returned through retrieval or MCP.

The pre-Dagster Rust fixture gate uses a fixed reviewed Cargo recipe for capture acceptance and a
separate configured-model test for recipe inference. The fixed path verifies dependency-image
egress, Cargo metadata and build execution, successful rustc/linker/build-script process-exec
evidence, complete streams, standardized records, envp redaction, gitleaks findings, executable and
intermediate artifacts, loader facts, and checkpoint-safe hash identities. Model output never enters
the fixed capture test. The configured-model test remains opt-in through
`APPSEC_RUN_LIVE_INFERENCE=1` because it sends bounded target planning metadata to the configured
authenticated model transport.

The JVM suite has a matching opt-in Android inference diagnostic. It prints every model recipe,
requires a valid accepted Android-profile recipe, and runs before
project-build selects the recipe's Android image. This makes recipe-selection drift visible
without confusing a model proposal with the command ultimately executed.

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
target snapshot, recipe, dependency hashes, image, executor/capture identity, toolchain, probe,
`[build_outputs]` policy identity, and upstream handoff are unchanged and every retained artifact
still verifies. Checkpoint namespaces
are run-private and require operator-declared `platform`, `build_toolchain` and `validation`
releases. A missing declaration emits `CHECKPOINT_MISSED` with `missing_release_identity` and
reruns the applicable build; changing any required release invalidates the checkpoint without
fingerprinting installed software. Unrelated query-pack declarations do not invalidate it.

### Build-output dispositions

C/C++ builds leave no reliable install record, so the generic executor classifies whole build-output
trees once per unit, after the build, before it catalogues files
(`src/appsec_review/jobs/build_output_scope.py`,
`src/appsec_review/jobs/job_language_build/native_outputs.py`). The design is
[`native-build-output-discovery.md`](../architecture/native-build-output-discovery.md). The walk
covers the generic families (native, Go, .NET, Python, Rust); the JVM and WebAssembly adapters do
not use it.

**Configured exclusions.** Every `[[build_outputs.exclusions]]` rule whose `families` include the
unit's family is applied by name. Each excluded path is recorded once under
`configured_exclusions` as `{path, name, pattern, scope: "build_outputs", files}`. This is a
declared scope decision, never a coverage gap. A directory rule wins over every root beneath it,
and file rules also apply inside classified roots.

**Native layout discovery.** For `native` units only, bounded readers read what the build already
wrote. Nothing extra is executed (no `make -pn`, no `ninja -t`). In order of authority:

1. the recipe's `build_dir`;
2. execution capture: a directory whose build-system file a fetcher (`curl`, `wget`, `tar`, `unzip`,
   `git`, `patch`, `cmake -P`/`-E tar`, `meson ... subprojects` and similar) wrote, and where most
   created files were fetcher-written, plus the ExternalProject `-build`, `-stamp` and `tmp`
   siblings beside it;
3. `CMakeCache.txt`, and the CMake file API codemodel reply. For CMake units, the job writes a
   stateless query to `<build_dir>/.cmake/api/v1/query/client-appsec-review/query.json` before
   configure and records it on the receipt as
   `prepared_inputs: [{path, sha256, purpose: "cmake-file-api-query"}]`;
4. Meson `meson-info/` introspection;
5. vcpkg `vcpkg/status` and `info/*.list` (an installer record);
6. static `build.ninja` edges, read only when there is no CMake cache and no `meson-info`;
7. MSBuild project properties and Conan generator directories;
8. the directory-name heuristic, last.

`compile_commands.json` only corroborates. MSBuild `OutDir`/`IntDir` are resolved but nothing
consumes them on the Linux lanes. Only content created during the build is reclassified;
committed vendored source stays target content.

**Dispositions.** A classified root is `supply_chain` (one root per dependency tree), `excluded`,
`evidence` (CMake FetchContent and ExternalProject bookkeeping) or `per_file`. Pruned roots are
counted with `stat` and not hashed. A `supply_chain` root keeps only its linked outputs
(executables, shared and static libraries), up to `max_kept_per_root`, as catalogue rows with
`scope_role: build_dependency` and `build_output_root`. A dependency's linked output in a mixed
directory is tagged `build_output_tag: dependency-sourced-output` instead of being rooted. When fact
sources conflict on one root, its files stay `per_file` target rows and a gap is recorded. A
heuristic root has basis `heuristic`, a `confidence` and always a `build-output-heuristic` gap: at
or above `heuristic_min_confidence` (shipped `medium`) it becomes `supply_chain`; below it, its
files stay per-file target rows. Pruning changes catalogue rows only; the workspace manifest
stays complete.

The receipt field `build_output_dispositions` (`appsec-review/build-output-dispositions/1`) has
`schema`, `policy_identity`, `layout_sources[{kind, path, sha256}]`,
`roots[{root, disposition, basis, confidence, name, reason, evidence_ref, pattern, scope,
scope_role, files, bytes, kept, examples}]`, `configured_exclusions` and `bookkeeping`. `kept` is a
list of workspace-relative paths. `excluded_bookkeeping` and the receipt schema
`language-build-receipt/1` are unchanged. The executor identity is
`appsec-review/generic-language-build-executor/4` plus the delivery-scope policy identity.

Classification gaps:

| Gap | Meaning |
| --- | --- |
| `dependency-content-summarized: ...` | one per evidence source: the dependency trees it recorded were routed to `supply_chain` review, not per-file target review |
| `build-output-heuristic: <root> ...` | a root classified by directory name, with its confidence |
| `build-output-classification-conflict: <root>` | fact sources disagreed; the files stay per-file target content |
| `build-output-kept-bound-exceeded: ...` / `build-output-root-bound-exceeded: ...` | more linked files or roots than `max_kept_per_root` / `max_layout_roots`; the rest stay counted only, or per-file |
| `cmake-file-api-reply-missing: ...` | a query was written but CMake left no reply; layout comes from the cache only |
| `build-output-layout-source-bound-exceeded`, `-unreadable`, `-malformed`, `-limit` | a layout source over `max_layout_source_bytes`, unreadable, not parseable, or beyond `max_layout_sources` |
| `build-output-ninja-edge-bound-exceeded` | `build.ninja` has more edges than `max_ninja_edges` |
| `build-output-msbuild-directory-unresolved` | an MSBuild output directory could not be resolved |
| `build-output-capture-incomplete: ...` | capture was incomplete, so capture-based classification is off; layout facts and the heuristic still apply |

`node.catalog` and `php.catalog` accept the dispositions but do not walk them yet. Node and PHP
units therefore apply no `[build_outputs]` rule in this job (the shipped `node-bundler-cache` rule
takes effect in project-build probes only), and their dispositions and counts are empty. Their
installer-record classifiers are separate work.

### Immutable retry publication

Fresh generic, JVM, and WASM builds use the attempt-scoped execution root
`data/build/<family>/units/<build-unit-id>/attempts/<attempt-id>/` within the run, with `workspace/`,
workspace manifests, protected commands, and JVM instrumentation/evidence under that attempt.
Execution capture keeps its existing
`data/build/<family>/units/<build-unit-id>/attempts/<attempt-id>/execution-capture/` path; the
attempt segment must not be added twice.

Attempt isolation applies even when a sibling unit failed: forcing a later attempt does not rewrite
workspace manifests, artifacts, or other bytes bound by an earlier accepted partial handoff.
Successful checkpoint reuse verifies and returns the prior pinned workspace and artifact references
rather than copying a previously accepted workspace into a new mutable unit directory. Read the
receipt's workspace reference rather than constructing a path from the latest attempt ID.
Existing `build_workspaces` protected dataset declarations cover these family trees.

Inspect `data/logs/pipeline.jsonl` for `LANGUAGE_BUILD_STARTED`, `BUILD_COMMAND_COMPLETED`,
`BUILD_OUTPUT_CLASSIFIED`, `LANGUAGE_BUILD_COMPLETED`, and `LANGUAGE_BUILD_REUSED`. Events
intentionally contain identities, counts, dispositions, gap counts, and durations—not command text
or environment values. `BUILD_OUTPUT_CLASSIFIED` is written once per generic-executor unit that
reaches cataloguing, with `supply_chain_trees`, `excluded_trees`, `excluded_files`, `kept_rows`,
`heuristic_dispositions`, `conflicts`, `layout_sources_read`, `target_rows` (catalogue rows in the
`target` analysis lane) and `duration_ms` (classification plus the catalogue walk). The same counts
are added to `LANGUAGE_BUILD_COMPLETED`. `aggregate_run_metrics` does not sum them.

## Settings reference

`[jobs.job_language_build.settings]` is validated by `config/loader.py`; unknown keys fail
loading. Values below are the shipped `appsec-review.toml` defaults. Global capture limits live in
`[build_capture]` (see the configuration section of
[`../architecture/build-environments-and-execution-capture.md`](../architecture/build-environments-and-execution-capture.md));
`settings.build_capture` overrides a subset for this job (shipped: `event_count_limit = 250000`,
`retain_raw_traces = true`, `raw_trace_bytes_limit = 67108864`).

| Key | Default | Meaning |
| --- | --- | --- |
| `command_timeout_seconds` | 1800 | per-command timeout; positive |
| `output_bytes` | 8388608 | in-memory stream preview only; complete files are retained |
| `artifact_count_limit` | 10000 | cataloged artifacts per unit; positive |
| `compiler_artifact_collection_mode` | `required` | `required`, `auto`, or `disabled` |
| `compiler_artifact_collection_overrides` | native/go/dotnet/rust `required` | per-family mode for `native`, `go`, `dotnet`, `node`, `python`, `rust`, `php`, `java`, `wasm` |

Per-family tables. `diagnostic_tail_bytes` (shipped 32768) bounds the on-demand failure-tail read;
it is 0-1 MiB for Go, Python, Rust, PHP, and Node and positive for JVM:

| Table | Keys (shipped value) | Constraints |
| --- | --- | --- |
| `go` | `offline` (false), `package_catalog` (true), `inspect_build_id` (true) | Booleans |
| `python` | `frontend` (`pip`), `require_locked_dependencies` (false), `offline` (false), `capture_native_tools` (true) | `frontend` is `build`, `pip`, or `setuptools` |
| `dotnet` | `require_locked_restore` (false), `capture_msbuild_diagnostics` (true), `generated_sources` (true), `allow_publish`/`allow_pack`/`allow_aot` (true) | validator requires the first three as shipped |
| `rust` | `toolchain` (`stable`), optional `target`, `profile` (`dev`), `features` ([]), `locked` (false), `offline` (false), `capture_linker` (true) | names match `[A-Za-z0-9_.-]{1,64}` |
| `php` | `composer_plugins` (`disabled`), `composer_scripts` (`sandboxed`), `require_lockfile` (false) | policies are `disabled` or `sandboxed` |
| `node` | `package_managers`, `require_lockfile` (false), `network` (`allowed`), `lifecycle_scripts` (`sandboxed`), `capture_source_maps` (true) | validator accepts only the shipped values |
| `jvm` | `trace_bytes` (8388608), `provenance_count_limit` (20000), `diagnostic_tail_bytes`, `system_paths` table keyed by `java` and `android`, `tool_paths` table | limits positive; every path segment absolute; `tool_paths` names exactly `javac`, `kotlinc`, `kapt`, `ksp`, `java`, `jar`, `javadoc`, `protoc` |
| `wasm` | `workspace_file_limit` (100000), `producers.<name>` with `families`, `tools`, `indicators` arrays | at least one producer; limit positive |

The WebAssembly adapter reuses the job-level timeout, `output_bytes`, and `artifact_count_limit`.
Project images, probes, and recipes come from `job_project_build`; see
[`project-build.md`](project-build.md).

### `[build_outputs]`

A top-level table (`src/appsec_review/config/build_outputs.py`) shared by `job_project_build`,
`job_language_build` and `job_sanitizer_build`. Unknown keys fail loading, and so does a
`jobs.<id>.build_outputs` or `jobs.<id>.settings.build_outputs` table. Without the table, the
discovery defaults apply with no exclusion rules. Its canonical SHA-256 is the policy identity:
it is part of the language-build checkpoint fingerprint and the accepted-probe identity, and the
sanitizer summary records it as `build_outputs_policy`.

| Key | Shipped value | Meaning |
| --- | --- | --- |
| `heuristic_min_confidence` | `medium` | `high`, `medium`, `low` or `off`; a heuristic root below it stays per-file, and `off` lets no heuristic reclassify |
| `discovery.cmake_file_api` | `true` | write the CMake file API query for native CMake units |
| `discovery.max_layout_sources` | 64 | layout files read per unit |
| `discovery.max_layout_source_bytes` | 16777216 | bytes read per layout file |
| `discovery.max_layout_roots` | 512 | classified roots per unit |
| `discovery.max_ninja_edges` | 200000 | `build.ninja` edges read |
| `discovery.max_kept_per_root` | 256 | linked outputs kept per `supply_chain` root |

Every `discovery` bound is a positive integer. Each `[[build_outputs.exclusions]]` rule has a
unique `name` matching `[a-z0-9-]+`, a non-empty `reason`, at least one pattern in `patterns` with
the same semantics as `[exclusions]` (matched against the workspace-relative path), and optional
`families` (`native`, `go`, `dotnet`, `node`, `python`, `rust`, `php`, `java`, `wasm`; absent means
every family). Shipped rules:

| Name | Families | Patterns |
| --- | --- | --- |
| `cmake-fetchcontent-subbuild` | `native` | `*-subbuild/` |
| `node-bundler-cache` | `node` | `node_modules/.cache/`, `*/node_modules/.cache/`, `node_modules/.vite/`, `*/node_modules/.vite/` |

## Live acceptance

The bounded non-Dagster Rust fixture acceptance is current for this tree: both the ordinary and
synthetic-secret language-build runs succeed without capture gaps, and the pinned CodeQL Rust
source/no-build database executes the default `rust-security-and-quality` and independently hashed
`rust-security-extended` suites. The benign fixture produces zero normalized CodeQL observations;
that is recorded as a zero-result query execution, not a clean-security claim. Rust compiler-native
AST and IR production are not implemented. No Dagster run is claimed by this fixture gate.

Dagster run `34cd763a-8798-4dc7-a27c-34cc6006c9e5` (application run
`2026-10-09-0012`) is the accepted .NET/C# fixture run. All 284 selected orchestration steps
succeeded. The .NET language receipt is `SUCCEEDED` with `gaps=[]`, 23 process-exec events, 23
envp-bearing exec events, 184 connect events, complete compiler/build-driver provenance, two
successful gitleaks scans with zero findings, and 23 generated artifacts. Build-driver and wrapper
stdout/stderr are complete files; the 11,274,715-byte diagnostic build stdout verifies despite
exceeding the optional 8 MiB in-memory preview. CodeQL created one C# database and completed both
the pinned default and `security-extended` profiles with zero gaps and one normalized observation
from each. The strict hash-resolving report is
`deploy/dagster/verification/dotnet-capture-live-acceptance.json`. The application-wide completion
status remains `COMPLETED_WITH_GAPS` because unrelated generic evidence/artifact capabilities name
their normal scope gaps; the required project-build, language-build, and CodeQL jobs are
`SUCCEEDED` and the .NET/CodeQL acceptance paths have no gaps.

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
