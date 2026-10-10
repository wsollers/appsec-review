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
the original tool path, and runs the command under `strace -ff`. Capture is process-tree-local: it
observes descendants of the authorized build command rather than unrelated host processes.

The required syscall event families are:

- `clone`, `clone3`, `fork`, and `vfork` for process creation;
- `execve` and `execveat` for the kernel-resolved executable path, argv, envp, and result;
- `exit` and `exit_group` for process completion;
- `openat` and `openat2` for file-open evidence; and
- `connect` for mandatory egress evidence.

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
- retained tool-call records plus their stdout and stderr.

The cataloged gitleaks image is resolved to an immutable local image ID before execution. It runs in
a second container with no network, a read-only input mount, a writable run-owned scratch mount,
non-root identity, read-only root, dropped capabilities, `no-new-privileges`, and catalog resource
limits. Gitleaks scans in directory mode with JSON output, exit code `1` meaning findings, and
`--redact=100`. Exit codes `0` and `1` are successful scanner dispositions.

The full gitleaks result set drives sanitization even when the configured finding-retention cap is
reached. The cap limits stored normalized findings; it never limits secret removal. A finding in a
retained process-exec event redacts that event's executable path, argv, and envp values while
preserving valid JSONL; a finding in a file-open event redacts its path.
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

All capture policy is typed and centralized in `appsec-review.toml`. Global settings define the
backend, syscall/argv/envp/path/tool-call/stream/finding limits, envp enablement, and exact redaction
names. A job may override a bounded subset such as `event_count_limit`; omitted values inherit the
global configuration. The resolved immutable configuration is copied into the run like every other
job setting.

The main implementation surfaces are:

- `containers/build.py` and `containers/catalog.toml` — shared image packaging;
- `src/appsec_review/container_runtime/project_images.py` — dependency-image derivation and cache;
- `src/appsec_review/container_runtime/build_executor.py` — sandbox launch and gitleaks pass;
- `containers/build-capture/build-driver.sh` — process-tree syscall driver;
- `containers/build-capture/tool-wrapper.py` — exact known-tool calls and streams;
- `src/appsec_review/container_runtime/build_capture.py` — normalization, execution record, and
  the shared record verifier;
- `src/appsec_review/jobs/job_project_build/job.py` — project-build run integration;
- `src/appsec_review/jobs/job_language_build/job.py`, `native.py`, `rust.py`, and `dotnet.py` — native, Rust, and .NET
  capture routing, receipt identities, and capture-derived tool provenance; and
- `tests/test_build_capture.py`, `tests/test_build_container_executor.py`,
  `tests/test_project_build.py`, `tests/test_rust_language_build.py`, `tests/test_language_build.py`, and
  `tests/test_live_build_toolchains.py` — unit and live contracts. `tests/capture_fakes.py` replaces
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
