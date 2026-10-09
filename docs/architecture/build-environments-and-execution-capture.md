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

Captured execution is currently an acceptance requirement for `job_project_build` probes. The
generic `job_language_build` adapters still use their family-specific execution and provenance
paths; they must not be described as producing the standardized syscall/envp/secret-scan record
until they are explicitly migrated and tested. The current capture backend is in-container
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
- `execve` and `execveat` for executable argv and envp;
- `exit` and `exit_group` for process completion;
- `openat` and `openat2` for file-open evidence; and
- `connect` for mandatory egress evidence.

PATH wrappers complement syscall capture for known build tools such as compilers, linkers,
archivers, package managers, build systems, and language toolchains. A wrapper resolves the real
executable from the saved path, runs it without a shell, tees bounded stdout and stderr, and writes
an `appsec-review/build-tool-call/1` record containing argv, environment, status, stream sizes,
truncation state, URIs, and hashes. Absolute-path tool execution can bypass a PATH wrapper, but it
cannot bypass process-exec observation by the syscall collector.

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
retained process-exec event redacts that event's argv and envp values while preserving valid JSONL.
A finding in a tool-call record redacts argv and environment. A finding in a retained stream
replaces its contents and repairs the owning stream hash and retained-byte metadata. A finding in
the top invocation redacts the command argv stored in the execution record. The executor returns
the sanitized stream bytes so later project-build logs cannot reintroduce a detected secret.

If gitleaks is unavailable, times out, returns an invalid report, or otherwise fails, the path fails
closed: all retained argv, envp, tool environments, and captured streams are conservatively
redacted, the raw corpus is removed, and the execution record contains an explicit coverage gap.
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

Project-build acceptance resolves every URI below the run root and verifies its SHA-256. It also
validates scope identity, schemas, nested tool stream identities, secret-finding count consistency,
and scanner stream/report identities. Escaped paths, symlinks, changed hashes, invalid schemas, or
inconsistent coverage are framework-integrity failures. Event, tool-call, or finding caps and
collector/scanner failures are named coverage gaps. A gitleaks finding is evidence to retain and
route; by itself it is not a capture-coverage gap.

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
- `src/appsec_review/container_runtime/build_capture.py` — normalization and execution record;
- `src/appsec_review/jobs/job_project_build/job.py` — run integration and hash verification; and
- `tests/test_build_capture.py`, `tests/test_build_container_executor.py`,
  `tests/test_project_build.py`, and `tests/test_live_build_toolchains.py` — unit and live contracts.

## Acceptance sequence

Changes advance in language order with small fixture projects. For a family, focused unit tests must
first prove configuration, parsing, caps, redaction, failure behavior, hash repair, and job
acceptance. A live container test then proves real configure/build output, observed compiler argv,
envp capture, mandatory connect instrumentation, gitleaks execution, raw-trace removal, and expected
artifacts. A synthetic secret test proves detection and absence from retained files. Only after the
language fixtures and downstream CodeQL/AST/IR evidence checks are successful should a fresh
Dagster acceptance workflow be used as integrated evidence. Historical, interrupted, or partially
covered runs do not satisfy that gate.
