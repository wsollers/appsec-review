# Build environments, execution capture, and secret scanning

This page describes the architecture that prepares build environments, derives dependency-bearing
project images, executes accepted build commands, captures their process behavior, and scans the
resulting evidence with gitleaks. It documents the active implementation outside `old/`; it is not
guidance for review workers.

## Scope and current integration

There are three distinct image and execution layers. They have different authorities and must not
be treated as one container lifecycle:

1. The catalog-driven container packager builds shared base and tool images, including the narrow
   `tool-gitleaks` scanner.
2. `ProjectImageResolver` may derive a project-specific dependency image from a configured
   language-family build image and one validated build recipe.
3. `BuildContainerExecutor` starts a fresh build container for each accepted command and, when
   `execute_captured` is used, surrounds that command with process capture and a post-command
   gitleaks scan.

Captured execution is an acceptance requirement for `job_project_build` probes and for every
command of the native C/C++, Rust/Cargo, and .NET SDK adapters in `job_language_build`. The remaining `job_language_build`
adapters still use their family-specific execution and provenance paths; they must not be described
as producing the standardized syscall/envp/secret-scan record until they are explicitly migrated
and tested. The current capture backend is in-container
`ptrace` through `strace`. Configuration reserves `ebpf` as a future backend, but the executor
rejects it because a safe, build-cgroup-scoped implementation has not been completed.

```text
catalog + locked assets                 accepted target catalog + build recipe
          |                                             |
          v                                             v
shared base/tool image build              resolve configured family image by SHA-256
          |                                             |
          |                                  derive/cache project dependency image
          |                                             |
          +-----------------------+---------------------+
                                  |
                                  v
                     fresh non-root build container
                     network: bridge for dependencies
                     root filesystem: read-only
                                  |
                     build-driver.sh under strace
                     PATH tool wrappers + exact streams
                                  |
                                  v
                    temporary raw capture corpus
                                  |
                                  v
                 isolated tool-gitleaks container
                 network: none; report redaction: 100%
                                  |
                     +------------+-------------+
                     |                          |
                 sanitize retained data     normalize findings
                     |                          |
                     +------------+-------------+
                                  v
                  hash-verified run-owned execution record
```

## Building shared container images

`containers/catalog.toml` is the packaging inventory. Enabled entries declare their build context,
Dockerfile, versioned tag, dependencies, and—where applicable—an asset lock and tool manifest.
`containers/build.py` validates catalog topology before mutation. For enabled images it rejects
moving `latest` bases, remote curl-to-shell patterns, missing final `USER 10001`, incomplete base
provenance, and incomplete asset metadata.

External assets are fetched over HTTPS before the Docker build. Their declared byte count and
SHA-256 must match `assets.lock.json`; the Docker build then runs with `--network=none` and
`--pull=false`. This separation keeps network retrieval out of Dockerfile execution. Build order is
derived from declared image dependencies, and each run writes logs plus an
`appsec-review/container-build-summary/1` record under `runs/container-builds/<run-id>/`.

Startup, functional, and security acceptance use `containers/runtime-policy.toml`: non-root
`10001:10001`, read-only root filesystem, all capabilities dropped, `no-new-privileges`, bounded
CPU, memory, PIDs, time and output, a read-only target, one writable scratch mount, and no network
for static tool execution. `containers/tools/gitleaks/tool.toml` applies this policy to gitleaks and
fixes its executable and version.

The language-family images referenced by `jobs.job_project_build.settings.profiles` are a separate
current-state concern. Each profile declares a local tag, immutable image ID, and numeric non-root
user. `BuildContainerExecutor.resolve` refuses to run when the local tag no longer resolves to the
configured image ID. The corresponding legacy build-environment entries in `containers/catalog.toml`
remain marked `deferred`; therefore the enabled catalog packager is not yet the authoritative
producer of every configured family image. A future migration must enable narrow, reproducible
language-only images before removing this explicit local-image contract.

## Deriving dependency-bearing project images

The accepted build recipe determines whether the family image can be used directly or requires a
derived project image. `ProjectImageResolver` computes the project-image identity from:

- the operational recipe, excluding explanatory text;
- the configured base image ID;
- hashes of every accepted dependency descriptor;
- platform and architecture; and
- the project Dockerfile generator identity.

Only normalized dependency files that resolve beneath the accepted target root enter the build
context. The generated Dockerfile starts from the configured family tag, temporarily becomes root
to create fixed directories and install a validated bounded apt package set, copies dependency
descriptors by hash-bound identity, then returns to the configured non-root user. Supported package
managers receive deterministic restore commands. Examples include `cargo fetch`, `go mod download`,
`dotnet restore`, script-disabled Node or Composer installs, and bounded Python requirements.

Project-image construction uses `docker buildx build --load --pull=false --network default` because
its purpose is to download declared dependencies. This is intentionally different from building
shared tool images, which is offline after locked-asset fetch. The derived image retains dependency
caches below `/opt/project-deps`; the later build container receives matching typed environment
paths. Lifecycle scripts are disabled where the package manager supports that policy.

The project-image cache is keyed by the full recipe identity. Reuse requires the manifest, retained
Dockerfile hash, and current local image ID to agree. A missing or changed image, Dockerfile, or
manifest rejects the cache entry. Docker daemon mutation is narrowly serialized, while unrelated
family work can remain parallel.

## Executing an accepted build

`job_project_build` copies the bounded source scope into a run-owned workspace and invokes only the
validated configure/build argv. The executor does not interpolate a command string or introduce a
shell around the accepted command. The build sandbox has Docker bridge networking so package
managers can reach dependency services, but it remains non-root with all capabilities dropped,
`no-new-privileges`, a read-only container root, bounded resources, and a writable run-owned source
copy. Produced applications and test suites are not executed.

For captured execution, the container entrypoint is the thin
`containers/build-capture/build-driver.sh`. The driver prepends generated wrappers to `PATH`, saves
the original tool path, and runs the command under `strace --seccomp-bpf -ff -y`. Capture is
process-tree-local: it observes descendants of the authorized build command rather than unrelated
host processes.

`--seccomp-bpf` makes the kernel stop the tracee only on traced syscalls instead of on every
syscall. On the benchmark below it cut capture overhead by more than half while recording identical
exec, fork and open events. `-y` makes strace print the path behind every file descriptor,
including `AT_FDCWD` (the process's current directory) and the descriptor a successful open
returns, so relative paths resolve without guessing.

The required syscall event families are:

- `clone`, `clone3`, `fork`, and `vfork` for process creation;
- `execve` and `execveat` for the kernel-resolved executable path, argv, envp, and result;
- `exit` and `exit_group` for process completion;
- `open`, `openat`, `openat2`, and `creat` for file-open evidence (`file_open`), with the
  requested path, the base directory, the resolved path of a successful open, the open flags with
  derived `access` (`read`, `write` or `read-write`) and `creates`, and the result and errno;
- `chdir` and `fchdir` for working-directory changes (`directory_change`);
- `rename`, `renameat`, and `renameat2` (`file_rename`), `link` and `linkat` (`file_link`), and
  `unlink` and `unlinkat` (`file_unlink`), so temp-then-rename outputs and deleted inputs are
  visible; and
- `connect` for mandatory egress evidence.

Docker's default seccomp profile rejects `clone3` with `ENOSYS`; glibc then falls back to `clone`.
With `--seccomp-bpf`, those rejected attempts are no longer printed. They never produced
process-fork events, and the successful `clone`/`vfork` events are unchanged.

PATH wrappers complement syscall capture for known build tools such as compilers, linkers,
archivers, package managers, build systems, and language toolchains. A wrapper resolves the real
executable from the saved path, runs it without a shell, tees complete stdout and stderr files, and writes
an `appsec-review/build-tool-call/1` record containing argv, environment, status, stream sizes,
truncation state, URIs, and hashes. Absolute-path tool execution can bypass a PATH wrapper, but it
cannot bypass process-exec observation by the syscall collector.

The build driver's own stdout and stderr are not storage-capped. The executor connects them
directly to run-owned files instead of pipe-buffering the complete streams in memory, and receipts
hash those complete files. `output_bytes` bounds only the optional in-memory preview used by
parsers and event summaries; it is recorded as `preview_limit_bytes` and never truncates or replaces
the retained file. Failed-build diagnostics read a bounded tail from that complete file on demand.
Wrapper-call count remains independently capped and configurable. Every retained wrapper call keeps
complete stream files; reaching the call-count cap is a named provenance gap rather than permission
to treat unrecorded calls as absent.

A process-exec event keeps `executable` (the path passed to the kernel, which the caller cannot
relabel the way it can `argv[0]`) and `result`. A PATH search that misses produces failed `execve`
rows; only an event with `result` zero is evidence that a tool ran.

## Post-build file evidence

Nothing is hashed during the build. After the traced command exits, the executor derives file
evidence from the normalized events (`container_runtime/capture_files.py`):

1. **Path resolution.** Each file event resolves to an absolute container path. It uses strace's
   directory annotation when present, otherwise the process's working directory reconstructed
   from fork inheritance and successful directory changes, starting from the command's working
   directory. A successful open uses the resolved path strace printed for the returned descriptor.
2. **Response files.** For every successful exec, an `@file` argument that the same process then
   opened for reading is copied into `response-files/` in the capture *before* the secret scan, so
   the scan covers its contents. A response file outside the workspace, removed before the
   snapshot, or over `response_file_bytes_limit` is a named coverage gap, as is reaching
   `response_file_count_limit`.
3. **File inventory** (`files.jsonl`, schema `appsec-review/build-file-inventory/1`), built *after*
   the secret scan from sanitized events, so redacted paths never enter it:
   - successful file events are deduplicated by path; failed opens (include-path probes) are
     counted and never listed;
   - workspace files are keyed by workspace-relative path, because every review builds in a new
     directory. A file the build did not write, whose size and mtime still match the pre-build
     workspace snapshot that `job_project_build` already hashes, reuses that SHA-256. Every other
     workspace file is hashed once;
   - files on the read-only image filesystem are identified by image ID plus path and never
     hashed. Ephemeral tmpfs paths are listed without hashes; capture-own and virtual
     (`/proc`, `/sys`, `/dev`) paths are only counted;
   - a workspace file modified after a process read it is flagged `modified_after_read` and
     counted. Build systems routinely rewrite files they read, so this is not a coverage gap, but
     consumers must not treat its post-build hash as what was read;
   - counts, hashed bytes, and `resolve`/`hash`/`total` timings are recorded in the execution
     record's `file_inventory`, so the real cost is visible on large builds. Reaching
     `file_inventory_count_limit` is a named coverage gap.

`verify_capture_record` hash-verifies `files.jsonl` and every retained response file like any other
capture member. Changing this format bumped every family's capture identity, so earlier captures
invalidate build checkpoints instead of being reused.

The benchmark behind these choices runs the repository's own driver and wrapper inside the
executor's container flags. Medians of 3 runs:

| Workload | Plain build | PATH wrappers only | Previous capture | `--seccomp-bpf` | Current capture (`--seccomp-bpf -y`, extended syscalls) |
| --- | --- | --- | --- | --- | --- |
| Repository native fixture (CMake, 2 TUs) | 0.6 s | 2.6 s | 7.3 s | 3.3 s | 3.5 s |
| zstd 1.5.7 static library (CMake + Ninja) | 17.9 s | 26.5 s | 48.3 s | 30.8 s | 31.8 s |
| Synthetic C++ library, 300 heavy-STL TUs (CMake + Ninja), mean of 2 | 291.8 s | 300.6 s | 446.5 s | 302.4 s | 303.8 s |

The extended syscall set and `-y` annotation add about 3% over `--seccomp-bpf` alone. On the
compile-heavy synthetic workload, the previous capture cost +53%, and the current capture costs +4%
over an uncaptured build. On a real
capture of the fixture, the post-build pass resolved 6,311 opens to 553 unique paths (1,135 failed
probes dropped, 429 image files identified without hashing) and hashed 27 workspace files in 7 ms.

The Python PATH wrapper costs about 40 ms per wrapped tool call. `docs/TODO.md` tracks replacing it
with a static Go binary.

## Envp capture and configured redaction

Envp capture is typed in the global `[build_capture]` table and defaults on. `strace -v` records the
environment presented to each `execve`/`execveat`, not merely the environment with which the top
driver started. Consequently, a shell or build system that exports variables and later launches a
compiler or helper produces those variables on the later process-exec event.

Envp evidence is bounded independently by entry count and encoded bytes. Retained entries preserve
the variable name, value, and a redaction flag. `envp_redact_names` is an exact, case-sensitive list
of environment variable names. A matching value becomes `<redacted>` before it is written to
`events.jsonl` or a tool-call record. Exact-name policy avoids both accidental substring matches
and hidden policy in wrapper code. Disabling `capture_envp` omits retained envp values and tells
wrappers not to persist their environment.

Configured name redaction is the first protection layer, not a secret detector. Unknown variable
names, secrets passed in argv, and secrets printed by build tools are handled by the gitleaks pass.

## Per-command gitleaks scan

After the build command terminates, the recorder flushes normalized events and assembles a
temporary scan corpus containing:

- raw strace files, which include pre-redaction argv and envp;
- a raw top-level invocation object containing argv and supplied environment;
- normalized `events.jsonl`;
- top-level stdout and stderr; and
- retained tool-call records plus their stdout and stderr; and
- retained response-file snapshots.

The cataloged gitleaks image is resolved to an immutable local image ID before execution. It runs in
a second container with no network, a read-only input mount, a writable run-owned scratch mount,
non-root identity, read-only root, dropped capabilities, `no-new-privileges`, and catalog resource
limits. Gitleaks scans in directory mode with JSON output, exit code `1` meaning findings, and
`--redact=100`. Exit codes `0` and `1` are successful scanner dispositions.

The full gitleaks result set drives sanitization even when the configured finding-retention cap is
reached. The cap limits stored normalized findings; it never limits secret removal. A finding in a
retained process-exec event redacts that event's executable path, argv, and envp values while
preserving valid JSONL; a finding in any file event (open, rename, link, unlink, directory change)
redacts all of its path fields. A finding in a retained response file replaces its contents.
A finding in a tool-call record redacts argv and environment. A finding in a retained stream
replaces its contents and repairs the owning stream hash and retained-byte metadata. A finding in
the top invocation redacts the command argv stored in the execution record. The executor returns
the sanitized stream bytes so later project-build logs cannot reintroduce a detected secret.

If gitleaks is unavailable, times out, exits with any code other than `0` or `1`, writes no report,
returns an invalid report, or otherwise fails, the path fails closed: all retained executable
paths, argv, envp, file-open paths, tool environments, and captured streams are conservatively
redacted, the raw corpus is removed, and the execution record contains an explicit coverage gap.
A report written by a scanner that then failed is not used.
Scanner failure writes an empty normalized findings artifact only alongside the explicit failure
gap; it is never treated as a successful zero-findings result or clean coverage. After either a
successful or failed scan, all raw strace files and the temporary corpus are deleted.

## Run-owned records and validation

Each captured command owns a directory similar to:

```text
execution-capture/command-001/
  record.json
  events.jsonl
  stdout
  stderr
  tool-calls/
    00000001-cmake/
      record.json
      stdout
      stderr
  secret-scan/
    execution.json
    gitleaks.json
    findings.json
    stdout
    stderr
```

`record.json` uses `appsec-review/build-execution-record/1`. It binds run, job, attempt, build-unit,
and family scope; collector and image identity; resolved limits; command outcome; syscall-event
counts and hash; top streams; tool-call record hashes; gitleaks execution and finding hashes; and a
coverage disposition. Syscall rows use `appsec-review/build-syscall-event/1`. Normalized secret
findings use `appsec-review/build-capture-secret-findings/1`, and the scanner receipt uses
`appsec-review/build-capture-secret-scan-execution/1`.

Acceptance uses one shared verifier, `verify_capture_record`, for both jobs. The caller states the
run, job, attempt, build unit, and family it executed; the verifier resolves every URI below the run
root and verifies its SHA-256. It also validates scope identity, record and syscall-event schemas,
retained event and tool-call counts, nested tool stream identities, secret-finding count
consistency, and scanner stream/report identities. Escaped paths, symlinks, changed hashes, invalid
schemas, a foreign scope, or inconsistent coverage are framework-integrity failures. Event,
tool-call, or finding caps and collector/scanner failures are named coverage gaps. A gitleaks
finding is evidence to retain and route; by itself it is not a capture-coverage gap.

## Conditional build-capture control model

Build execution capture, compiler-artifact collection, and CodeQL execution are separate controls.
They belong in typed central configuration and the resolved immutable run configuration; prompts,
target guidance, inferred recipes, and worker output cannot select or widen them. The agreed logical
values are:

| Control | Logical values | Required semantics |
| --- | --- | --- |
| Build execution capture | `required`, `auto`, `disabled` | `required` must capture an applicable material build or name an explicit coverage gap. `auto` runs only when a bounded deterministic classifier finds a material lifecycle. `disabled` is an explicit policy skip. |
| Compiler-artifact collection | `required`, `auto`, `disabled` | `required` must collect and verify the declared compiler/build artifacts or name a gap. `auto` collects only artifacts selected by the bounded descriptor policy. `disabled` records a policy skip; it does not imply that no compiler ran. |
| CodeQL execution capability | `build`, `source`, `auto`, `disabled` | `build` requires an accepted replayable build, `source` prohibits build replay, `auto` selects between those capabilities deterministically, and `disabled` records an explicit policy skip. |

`required` never degrades silently: unavailable tools, failed capture, incomplete provenance, or
missing required artifacts remain gaps and cannot support a clean-security statement. `auto` is
not model discretion; applicability is a deterministic function of accepted manifests, recipes,
toolchain facts, and descriptor policy. Package installation, package-manager lifecycle hooks,
code generation, transpilation or bundling, native-extension work, and actual compiler or linker
activity can establish a material build lifecycle. Syntax-only commands such as
`python -m py_compile`, `php -l`, and `node --check` do not establish one by themselves.

Processing controls now use one canonical disposition vocabulary: `SUCCEEDED` means applicable
processing ran and its required evidence validated; `SKIPPED_NA` means bounded accepted evidence
proved non-applicability; `SKIPPED_POLICY` means the immutable resolved configuration disabled the
feature; and `GAP` means required or applicable processing could not run or validate. Producer
execution receipts may retain narrower operational statuses such as `FAILED` or a platform
`NOT_APPLICABLE`; the attached processing decision is authoritative for applicability and
completeness. A skip is never clean-security evidence, and any `GAP` blocks a clean claim.

### Implemented decision path

Central TOML now accepts and strictly types all three control vocabularies. Build capture has a
global `required` default and bounded overrides for `job_project_build` and `job_language_build`.
Compiler-artifact collection has a `required` language-build default and fixed language-family
overrides. CodeQL has an `auto` job default and fixed per-language overrides using only `build`,
`source`, `auto`, or `disabled`. Legacy CodeQL `manual` and `none` values are accepted only at the
load boundary and normalize to `build` and `source`; resolved configuration never retains the old
vocabulary. Unknown targets, invalid case, wrong types, conflicting enablement, and malformed
tables fail loading.

The canonical resolved document and hash are retained under each run's `data/configuration/` and
are bound into handoff, job-configuration, and resume identities. The checked-in overrides retain
the verified behavior: native C/C++, Go, .NET, and Rust capture/artifact collection remain
`required`; C/C++, Go, Java/Kotlin, and C# CodeQL remain build-replay capable; and
JavaScript/TypeScript, Python, Rust, and Actions remain source/no-build capable.

The shared evaluator consumes the resolved policy, project/language identity, accepted descriptor
package, declared artifact types and CodeQL capabilities, and exact descriptor path/hash
identities. It records the inspected facts, selected capability, reason code, action, disposition,
and configuration SHA-256 in `appsec-review/applicability-decision/1`. Project build, language
build, and CodeQL all use that record. Applicability facts and decisions participate in probe,
language-build, database, handoff, implementation, and resume identities.

`auto` recognizes only bounded descriptor facts: known compiled-project markers, package lifecycle
or build hooks, native-extension declarations, transpilers, bundlers, code generation, Android
Gradle configuration, and WebAssembly compiler declarations. Descriptor-package failure is
`INVENTORY_UNAVAILABLE` and therefore `GAP`; confirmed absence is the positive evidence needed for
`SKIPPED_NA`. Wrapper output, logs, inferred prose, and generated model text are never inputs.
CodeQL maps a selected `build` capability to the executor's `manual` database mode and a selected
`source` capability to `none`; `auto` and `disabled` are resolved before a scope reaches the
executor.

## `appsec-multi-vuln` project-type coverage matrix

The authoritative corpus mapping is
[`support/project-matrix.json`](../../targets/appsec-multi-vuln/support/project-matrix.json),
documented by the [corpus guide](../../targets/appsec-multi-vuln/README.md), at nested-repository
commit `7c10536389c3cfb20a27d7a6a78943267ea43b3f`. Every path below was resolved at that commit.
The capture and artifact columns are covered by the deterministic matrix contract. CodeQL entries
below retain executor/receipt names
`manual` and `none`; the central configuration names are now `build` and `source`, and
`unavailable` is the corpus capability label rather than a configured parent mode.

| Project type | Exact fixture path(s) | Build or validation command | Capture expectation | Compiler-artifact expectation | CodeQL mode / capability | Expected applicability | Specialized toolchain | Fixture role |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C/C++ | `projects/native/case-083`; `projects/native/linux-calibration` | `cmake -S . -B build && cmake --build build`; calibration: `cmake --preset baseline && cmake --build --preset baseline` | `required` | `required`: `build/case083`; calibration executables `build/default/observer_a` and `observer_b` | `manual` / C/C++ supported | `applicable-required`; calibration is `applicable-required-calibration-only` | CMake plus C/C++ compiler and linker | vulnerability fixture; calibration fixture |
| Rust | `projects/rust/case-004` | `cargo build` | `required` | `required`: `target/debug/case-004` | Corpus: `unavailable` / `not-supported`; parent runtime: `none` source/no-build. This mismatch is a matrix-integration gap. | `applicable-required` | Rust toolchain and Cargo | vulnerability fixture |
| Go | `projects/go/case-007` | `go build ./...` | `required` | `required`: `case-007` executable | `manual` / supported | `applicable-required` | Go toolchain | vulnerability fixture |
| .NET | `projects/dotnet/case-014` | `dotnet build case-014.csproj` | `required` | `required`: `bin/Debug/net8.0/case-014.dll` | `manual` / C# supported | `applicable-required` | .NET 8 SDK | vulnerability fixture |
| JVM Java | `projects/java/case-016` | `javac src/Main.java` | `required` | `required`: `src/Main.class` | `manual` / Java-Kotlin supported | `applicable-required` | JDK with `javac` | vulnerability fixture |
| JVM Kotlin | `projects/kotlin/case-084` | `./build.sh` | `required` | `required`: `build/case-084.jar` | `manual` / Java-Kotlin supported | `applicable-required` | JDK plus `kotlinc` | vulnerability fixture |
| Plain Python | `projects/python/case-073` | `python3 -m py_compile main.py` | `disabled`; syntax-only is not a material lifecycle | `disabled`: none | `none` / Python supported without a build | `not-applicable-syntax-only` | Python 3 | syntax-only control containing source vulnerability material |
| Python native extension/build hook | `projects/python-package/case-085` | `python3 -m pip wheel . --no-deps --wheel-dir dist` | `required` | `required`: matching wheel in `dist/` containing the `case085` native module | Corpus: `manual` / supported as Python plus C/C++ analyses; parent has `none` for Python and `manual` for C/C++, but mixed-scope wiring remains to be proved. | `applicable-required-native-build` | Python, pip/build backend, C compiler, Python development headers | vulnerability fixture |
| Plain JavaScript | `projects/javascript/case-010` | `node --check index.js` | `disabled`; syntax-only is not a material lifecycle | `disabled`: none | `none` / JavaScript-TypeScript supported without a build | `not-applicable-syntax-only` | Node.js | syntax-only control containing source vulnerability material |
| TypeScript compilation | `projects/typescript/case-012` | `npm install && npm run build` | `auto` when the accepted manifest resolves the material transpile | `auto`: `dist/index.js` | `none` / JavaScript-TypeScript supported without capture replay | `applicable-auto-material-transpile` | Node.js, npm, TypeScript compiler | vulnerability fixture |
| JavaScript bundler | `projects/javascript-bundler/case-086` | `npm ci && npm run build` | `auto` when the locked bundle script is applicable | `auto`: `dist/bundle.js` | `none` / JavaScript-TypeScript supported without capture replay | `applicable-auto-material-bundle` | Node.js, npm, esbuild | vulnerability fixture |
| Node native addon | `projects/node-addon/case-087` | `npm ci && npm run build` | `required` | `required`: `build/Release/case087.node` | Corpus: `manual` / supported as JavaScript-TypeScript plus C/C++ analyses; parent mixed-scope wiring remains to be proved. | `applicable-required-native-build` | Node.js, npm, node-gyp, Python, C++ compiler | vulnerability fixture |
| Node lifecycle hook | `projects/node-lifecycle/case-088` | `npm ci && npm run build` | `auto` when the accepted package lifecycle hook is enabled by policy | `auto`: `.build/postinstall.marker` | `none` / JavaScript-TypeScript supported without capture replay | `applicable-auto-lifecycle` | Node.js and npm | vulnerability fixture with a safe lifecycle marker |
| Plain PHP | `projects/php/case-018` | `php -l index.php` | `disabled`; syntax-only is not a material lifecycle | `disabled`: none | `unavailable` / not supported | `not-applicable-syntax-only` | PHP CLI | syntax-only control containing source vulnerability material |
| Composer project/scripts | `projects/php-composer/case-089` | `composer install --no-interaction && composer run build` | `auto` when the accepted Composer script lifecycle is enabled by policy | `auto`: `.build/composer.marker` | `unavailable` / not supported | `applicable-auto-lifecycle` | PHP CLI and Composer | vulnerability fixture with a safe lifecycle marker |
| PHP native extension | `projects/php-extension/case-090` | `./build.sh` | `required` | `required`: `modules/case090.so` | `manual` C/C++ source / PHP unavailable; C source supported | `applicable-required-native-build` | PHP development headers, `phpize`, Autoconf, C compiler | vulnerability fixture |
| WebAssembly | `projects/wasm/case-091` | `./build.sh` | `required` | `required`: `build/case091.wasm` | `manual` C/C++ source / C source supported; emitted Wasm artifact is not analyzed by CodeQL | `applicable-required` | Clang with WebAssembly target support | vulnerability fixture |
| Android Hello World | `projects/android/case-092` | `gradle --no-daemon :app:assembleDebug` | `required` | `required`: `app/build/outputs/apk/debug/app-debug.apk` | `manual` / Java-Kotlin supported when the Android SDK is available | `applicable-required-sdk-gated` | JDK, Gradle, Android SDK Platform and Build Tools 35 | vulnerability fixture |

The pinned corpus commit validates the matrix structure and every referenced path. Its focused build
evidence covers the new CMake C, Python native-extension, WebAssembly, JavaScript bundle, Node
lifecycle, and Node native-addon fixtures. It does not claim Kotlin compilation, Android assembly,
Composer lifecycle execution, or a phpize build because those specialized toolchains were absent
on the validation host. Those absences remain named fixture-validation gaps, not evidence that the
expected applicability is wrong or that the projects are clean.

Adding a language or project type does not add another syscall parser, wrapper reconciler, or
capture loop. It supplies a small descriptor/classifier/artifact policy, registers that descriptor
with the shared reconciler when syscall-authoritative capture is required, and adds a parameterized
fixture entry such as those above. Applicability classification, artifact expectations, and
CodeQL capability are descriptor policy; capture collection and reconciliation remain shared.

## Generic captured-build extension contract

The compiled-language path has one driver, one collector boundary, and one reconciliation
algorithm. `job_language_build` passes each accepted argv to the shared container executor. The
executor applies the PATH wrappers, launches the arbitrary command under the syscall collector,
retains complete stdout and stderr files, normalizes exec/exit/connect/envp and configured
supplemental events, and scans retained streams, argv, and envp through gitleaks. The job verifies
that record before it interprets any language-specific tool.

`capture.py` owns the typed `CapturedBuildDescriptor` and `reconcile_captured_build` contract used
by .NET, Go, native C/C++, and Rust. Successful process-exec is the sole authority that a tool ran.
The generic reconciler attaches an optional wrapper record only after matching it to that exec,
counts failed and redacted execs, redacted and unreconciled wrappers, connect and envp facts,
malformed inputs, capture loss, and row truncation, and emits the same evidence and mapping shape
for every descriptor. Build output, wrapper records, compile databases, and model text cannot create
a tool row. The language descriptor supplies only the capture/provenance identities, executable and
argv classifier, input/output mapping, link-kind selection, and mandatory-tool gap text. Recipe
validation, fixed command shaping, artifact classification, metadata, and analysis capabilities
remain small language-adapter functions called by the generic build job; none may reimplement
capture or reconciliation.

To add a captured language:

1. Define the fixed recipe validation/argv shaping, artifact rules, and metadata readers in one
   language module; keep inference separate from fixed capture acceptance.
2. Add one `CapturedBuildDescriptor` with a classifier and invocation row builder. Do not add a
   language reconciliation loop or a new executor/collector path.
3. Register the descriptor once in `CAPTURE_DESCRIPTORS`; use the shared driver for every build,
   catalog, and inspection command that can affect accepted evidence.
4. Add the descriptor to the parameterized reconciliation contract, then add tests only for its
   distinct recipe, classifier, artifact, metadata, and CodeQL/AST/IR behavior.
5. Prove the fixed fixture retains complete streams and standardized capture, artifact, and secret
   scan records; run the focused live container gate before changing an acceptance claim.

## Native C/C++ language-build integration

Every accepted native configure and build command runs through the standardized capture boundary.
Successful process-exec events are the sole authority for compiler, assembler, linker-driver,
linker, archiver, code-generator, post-link, and build-driver provenance. Compile databases and
CMake `link.txt` files are hostile secondary metadata: after complete validation they may resolve
inputs and outputs only for an exact argv match to a successful captured execution. They cannot
create an invocation or satisfy the mandatory compiler check.

Each native receipt publishes `appsec-review/native-capture-provenance/1` facts and hash-bound
capture identities. Capture loss, redacted execs, unmatched wrapper calls, or an unobserved compiler
make provenance incomplete and prevent checkpointing. The native fixture acceptance verifies a
compile database, objects, a static library, executable, split debug data, link map, loader facts,
Clang AST, LLVM IR, complete streams, gitleaks artifacts, envp evidence, and the absence of raw
traces and scan inputs. AST and IR are separate analysis-stage outputs when they are not part of
the accepted language-build recipe.

## Rust language-build integration

`job_language_build` runs Cargo metadata and every accepted Cargo configure/build command through
`execute_captured` with the job's resolved `BuildCaptureConfig` and a `CaptureScope` naming the real
run, `job_language_build`, attempt, build unit, and `rust` family. An executor without captured
execution, a missing record, or a record that fails verification stops the unit as a
framework-integrity failure instead of producing a receipt. Each command is stored beside, never
inside, the build workspace:

```text
data/build/rust/units/<build-unit-id>/attempts/<attempt-id>/execution-capture/command-NNN/
```

Each Rust command receipt carries an `execution_capture` identity: the record path, hash, size, and
scope; the event-file hash and counts; collector kinds; envp enablement; tool-call counts; and the
hashes of the normalized findings, the scanner execution receipt, and the gitleaks report. The
`build` retrieval shard exposes only the record, event, and findings hashes, completeness, and
finding count.

Rust tool provenance is derived from the verified records, not from Cargo output. Only a successful
process-exec event establishes that `rustc`, a C linker driver, a linker, an archiver, or a
Cargo build script ran, including the toolchain compiler Cargo starts by absolute path. PATH
tool-call records are reconciled onto an invocation the collector observed and add exit and stream
identities; a launcher, a toolchain proxy, and the resolved binary collapse into one row. A
tool-call record with no matching successful process-exec event never becomes an invocation, cannot
satisfy a provenance check, and is reported as a gap. The former
`RUSTC_WRAPPER`, linker, and archiver shims and the `Running` line parser were removed because they
recorded nothing the syscall evidence lacks. Exact argv stays in the unit's protected compile
commands; receipts keep argv hashes, the classified tool, mapped inputs and outputs, and the
evidence identities. The job writes nothing into the Cargo `target/` tree, which the non-root
container user owns; the Rust link database is stored beside the workspace.

Lost evidence is reported rather than reconstructed. Capture gaps appear in the receipt as
`execution capture command N: ...`; an exec event redacted by the scan removes that tool's
provenance and names a gap. A complete capture is also the authority for what did not run: `rustc`
writes rlibs in-process and a library-only build never links, so the receipt records the observed
tool kinds and an absent linker driver or archiver is a fact, not a gap. Absence becomes a named gap
only when the capture lost evidence and `capture_linker` is set; an unobserved compiler is always a
gap. When the scan redacts the top invocation, the protected command artifact stores the redacted
argv and environment instead of reintroducing them, and Cargo metadata that was truncated or
redacted is a gap. A unit whose capture or tool provenance is incomplete is never checkpointed; a
reused checkpoint re-verifies every retained capture against the scope and hashes its receipt
recorded and republishes the gaps that receipt named.

The bounded Rust fixture acceptance derives a dependency-bearing project image with Cargo egress,
runs metadata and build commands through the capture boundary, and verifies an executable, rlib,
rmeta, dependency metadata, ELF loader facts, Cargo packages/resolve edges, rustc, a linker driver,
and dependency build-script execution. It also proves exact-name envp redaction, gitleaks removal of
a synthetic secret, complete retained streams, raw-trace cleanup, and default plus
`security-extended` Rust CodeQL execution. Rust CodeQL remains source/no-build analysis layered onto
the accepted Rust image so its semantic analyzer can load Cargo metadata; it is not compiler replay.
There is no Rust compiler-native AST or IR producer in the current graph. Tree-sitter supplies a
separate concrete-syntax source view when selected, and the missing compiler AST/IR branches remain
an explicit coverage gap rather than being implied by CodeQL or the build artifact catalog.

## .NET language-build integration

The .NET adapter uses the same standardized capture boundary for every accepted `dotnet restore`,
`build`, `publish`, `pack`, or `msbuild` command. Captured .NET runs disable persistent MSBuild and
Roslyn servers plus optional CLI telemetry and workload-advertising background work so the tracer
owns the complete command process tree. Those settings affect capture lifecycle only; accepted
build argv and target code are unchanged.

Successful process-exec events are the sole authority for .NET tool provenance. The classifier
recognizes the `dotnet` host and native tools directly and identifies hosted SDK tools such as
`MSBuild.dll`, `csc.dll`, `vbc.dll`, `fsc.dll`, ILLink, Crossgen2, and NativeAOT from the argv of the
observed host execution. PATH records enrich only a matching successful exec with status and stream
hashes. A wrapper record without that exec is counted as unreconciled, names a gap, and never becomes
a tool invocation. MSBuild diagnostic text remains a protected diagnostic stream and is not parsed
or regex-matched as evidence.

Each receipt includes `appsec-review/dotnet-capture-provenance/1` facts: capture completeness,
command and exec counts, failed or redacted execs, connect and envp events, exact-name envp
redactions, tool-call reconciliation, and observed tool kinds. The compiler is mandatory: an
unobserved compiler makes provenance incomplete and prevents checkpoint publication. Capture caps,
scanner/collector failures, redacted execs, and unreconciled wrapper records have the same effect.
Assemblies, portable PDBs, generated sources, NuGet metadata/packages, dependency and runtime
configuration, native/AOT outputs, and project/package/reference topology remain hash-bound output
evidence. The .NET link database is stored beside the container-owned workspace.

## Configuration ownership

All implemented capture configuration is typed and centralized in `appsec-review.toml`. Global
settings define the
backend, syscall/argv/envp/path/tool-call/stream/finding limits, envp enablement, and exact redaction
names. A job may override a bounded subset such as `event_count_limit`; omitted values inherit the
global configuration. The resolved immutable configuration is copied into the run like every other
job setting.
The preceding conditional tri-state model is the intended extension to this ownership rule; its
fields are not yet present in the typed schema.

The main implementation surfaces are:

- `containers/build.py` and `containers/catalog.toml` — shared image packaging;
- `src/appsec_review/container_runtime/project_images.py` — dependency-image derivation and cache;
- `src/appsec_review/container_runtime/build_executor.py` — sandbox launch and gitleaks pass;
- `containers/build-capture/build-driver.sh` — process-tree syscall driver;
- `containers/build-capture/tool-wrapper.py` — exact known-tool calls and streams;
- `src/appsec_review/container_runtime/build_capture.py` — normalization, execution record, and
  the shared record verifier;
- `src/appsec_review/jobs/job_project_build/job.py` — project-build run integration;
- `src/appsec_review/jobs/job_language_build/capture.py` — the typed descriptor and sole generic
  successful-exec reconciliation algorithm;
- `src/appsec_review/jobs/job_language_build/job.py`, `native.py`, `go.py`, `rust.py`, and
  `dotnet.py` — shared routing plus language-specific recipes, classification, artifacts, and
  metadata; and
- `tests/test_build_capture.py`, `tests/test_build_container_executor.py`,
  `tests/test_captured_build_reconciliation.py`, `tests/test_project_build.py`,
  `tests/test_go_language_build.py`, `tests/test_rust_language_build.py`,
  `tests/test_language_build.py`, and `tests/test_live_build_toolchains.py` — unit and live
  contracts. `tests/capture_fakes.py` replaces
  only the Docker CLI, so unit fakes exercise the real normalizer, scan, sanitizer, and recorder.

## Acceptance sequence

Changes advance in language order with small fixture projects. For a family, focused unit tests must
first prove configuration, parsing, caps, redaction, failure behavior, hash repair, and job
acceptance. A live container test then proves real configure/build output, observed compiler argv,
envp capture, mandatory connect instrumentation, gitleaks execution, raw-trace removal, and expected
artifacts. A synthetic secret test proves detection and absence from retained files. Only after the
language fixtures and downstream CodeQL/AST/IR evidence checks are successful should a fresh
Dagster acceptance workflow be used as integrated evidence. Historical, interrupted, or partially
covered runs do not satisfy that gate.
