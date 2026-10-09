# Build execution capture restart handoff — 2026-10-09

## User objective

Replace compiler-log inference with direct build execution evidence. `connect`/egress capture is
mandatory. Limits must be typed and configurable globally in TOML with per-job overrides. Use
small per-language fixtures and make quick/live tests pass before any Dagster acceptance run. Work
in this order: C++, Rust, .NET, then the remaining languages. Emit a standardized JSON job record
with exact command/tool argv, environment evidence, exit status, stdout/stderr artifact URIs, and
syscall/process evidence.

## Current state

All changes below are **uncommitted**. `git status --short` immediately before this note showed:

```text
 M appsec-review.toml
 M src/appsec_review/config/__init__.py
 M src/appsec_review/config/loader.py
 M src/appsec_review/container_runtime/__init__.py
 M src/appsec_review/container_runtime/build_executor.py
 M tests/test_build_container_executor.py
 M tests/test_config.py
 M tests/test_live_build_toolchains.py
?? containers/build-capture/
?? src/appsec_review/container_runtime/build_capture.py
?? tests/test_build_capture.py
```

Implemented:

- Typed global `[build_capture]` configuration and optional
  `[jobs.<job>.settings.build_capture]` overrides.
- Global defaults currently use `backend = "ptrace"` with bounded syscall events, argv count and
  bytes, path bytes, tool-call count, and per-tool stdout/stderr retained bytes.
- Both `job_project_build` and `job_language_build` override the event cap to 250,000.
- `BuildContainerExecutor.execute_captured(...)` runs a thin in-container driver under the same
  non-root user, `--cap-drop ALL`, `no-new-privileges`, read-only container boundary, and
  `--network bridge` dependency egress as ordinary builds.
- `containers/build-capture/build-driver.sh` runs `strace` against only its child build tree and
  captures fork/clone, exec, exit, `openat`/`openat2`, and `connect`.
- PATH-prepended wrappers in `containers/build-capture/tool-wrapper.py` record bounded tool calls:
  exact argv, a redacted environment, exit status, and hashed stdout/stderr artifacts. The wrapper
  streams output through to the parent while retaining only the configured byte limit.
- `src/appsec_review/container_runtime/build_capture.py` emits:
  - `record.json` using schema `appsec-review/build-execution-record/1`;
  - bounded `events.jsonl` using schema `appsec-review/build-syscall-event/1`;
  - per-tool `record.json` files using schema `appsec-review/build-tool-call/1`;
  - explicit coverage gaps for caps, drops, malformed collector output, or forced collector errors.
- The syscall trace normalizer reads structured `strace` output, not compiler/MSBuild logs.
- .NET captured execution disables persistent MSBuild/Roslyn servers with
  `DOTNET_CLI_USE_MSBUILD_SERVER=0`, `MSBUILDDISABLENODEREUSE=1`, and
  `UseSharedCompilation=false`. This is necessary so the traced process tree terminates after a
  successful build.

## eBPF decision and evidence gap

A pinned bpftrace prototype image was built locally, but the proposed Docker Desktop launch needed
host PID visibility, BPF/PERFMON/SYS_PTRACE, unconfined seccomp, and the host tracing filesystem.
The approval system rejected that because it could observe unrelated host process, file-open, and
network activity rather than only the authorized build. Do not try to bypass that restriction.

The safe first backend is therefore in-container `ptrace`/`strace`, which can observe only its own
build process tree. The typed config permits `ebpf` as a future backend, but the current executor
intentionally rejects it because a cgroup-scoped implementation has not been safely implemented or
verified. The temporary bpftrace Dockerfile/script were removed; only the safe driver/wrapper files
remain under `containers/build-capture/`.

## Tests completed successfully

Focused unit suite:

```text
python -m pytest tests/test_build_capture.py tests/test_build_container_executor.py tests/test_config.py -q --basetemp=test/tmp/capture-unit-3
11 passed, 1 skipped
```

Live fixture verification, each independently green:

```text
C++ captured configure + compile: 1 passed
Rust captured cargo build:        1 passed
.NET captured restore + build:    1 passed
```

The C++ test verifies real CMake configure/compile, the final executable, complete standardized
records, mandatory `connect` instrumentation, process exec/open evidence, and retained tool-call
records. Rust and .NET use the same contract. The second .NET run completed in about 26 seconds
after persistent compiler servers were disabled.

## Interrupted work at restart

The following full captured language-fixture matrix was started and then interrupted by the user
after about 28 seconds:

```text
python -m pytest "tests/test_live_build_toolchains.py::test_live_language_build_syscalls_are_captured_in_standard_records" -q --basetemp=test/tmp/capture-all-languages
```

At the time this note was written, a Java build container was still running:

```text
dbe6983ebcc6 ef678af17b8b Up ... "/bin/sh /workspace/..."
```

The machine restart should remove that transient `--rm` container. After restart, first check
`docker ps` and remove/stop only this exact stale test container if it somehow remains. Do not treat
the interrupted matrix as a pass or failure.

## Next steps after restart

1. Inspect `git status --short` and preserve all files listed above.
2. Run the focused unit suite again.
3. Run the captured fixture matrix one language at a time in this order to isolate failures:
   Go, Java, TypeScript, Python, PHP, WebAssembly. C++, Rust, and .NET are already independently
   green but should be included once in the final full matrix.
4. For any failure, inspect only the run-owned `record.json`, tool-call records, and trace row named
   by the coverage gap. Do not return to regex parsing compiler/MSBuild diagnostic logs.
5. Add assertions that C++ exec events contain compiler argv even when CMake invokes an absolute
   compiler path; PATH wrappers cannot intercept every absolute-path exec, but syscall exec evidence
   now parses the argv array.
6. Integrate `execute_captured(...)` into the real `job_project_build` and `job_language_build`
   handlers and place records under the run-owned job attempt tree. This integration is **not yet
   done**; current coverage is executor/unit/live-fixture level only.
7. Remove or replace the catastrophic .NET diagnostic-log invocation parser in
   `src/appsec_review/jobs/job_language_build/dotnet.py`; the new direct records should become its
   source of execution provenance. The old parser previously stalled on a 5.5 MB diagnostic log.
8. Run focused job tests, then the broader non-live suite, then all live build/CodeQL/AST/IR tests.
9. Only after all of those pass, run a fresh Dagster acceptance workflow. Do not reuse the canceled
   runs `2026-10-09-0014` or `2026-10-09-0015` as success evidence.
10. Inspect repository-root hygiene, commit the coherent change to `main`, and do not push unless
    the user asks.

## Prior verified baseline

Before this uncommitted capture work, the repository had already verified live fixture builds for
all configured languages, live CodeQL databases/default queries for supported languages, the C++
CERT extended suite, C# database/query/SARIF output, and 9/11 AST parser coverage. The latest
committed fixes are:

```text
3c21e38 Verify build and CodeQL toolchains live
905e6bf Fix live dependency image orchestration
83edf7a Normalize lockless Node build recipes
127234eb Expose image dependencies to Node builds
d8c7e63 Normalize target build discovery
5b3fd88 Keep Maven runtime dependency cache writable
78b7499 Make Rust compiler capture writable
```

No Dagster acceptance run has passed after these fixes. Missing or interrupted coverage remains a
named gap, not evidence that the workflow is correct.
