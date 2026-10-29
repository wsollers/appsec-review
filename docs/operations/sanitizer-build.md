# Operating the sanitizer build

`job_sanitizer_build` rebuilds each accepted **native C/C++** build unit with AddressSanitizer and
UndefinedBehaviorSanitizer instrumentation, in its own workspace, and publishes a hash-bound handoff
that catalogues the instrumented outputs and states, per output, whether the instrumentation took
effect. It exists because static tools do not see every memory error: an unbounded `memcpy` into a
fixed field or a 32-bit size wrap feeding `malloc` is reported precisely only by an instrumented
build that is later run on a crafted input. This job produces that build as a pipeline artifact. It
does not run it.

```text
job_language_build -> job_sanitizer_build -> job_review_data_indexing
```

It depends on the accepted `job_language_build` handoff, is a sibling of `job_cpp_compiled_analysis`,
and no job consumes its output. The dataset inventory job closes the graph after every leaf, so it
waits for this one and audits its files, but it reads nothing from it. The graph keeps exactly one
terminal job. Its central configuration must define this exact topology:

```text
load.accepted_native -> build.units -> acceptance.publish_handoff
```

Setting `jobs.job_sanitizer_build.settings.enabled = false` makes the job transparent: it is absent
from direct and Dagster execution plans. It is shipped enabled.

## What it builds

For every receipt of the accepted language build whose family is `native`, the job:

1. checks that the accepted build succeeded and that its `build_system` is one of the configured
   `build_systems`;
2. reads the exact configure and build commands the accepted build ran from their hash-verified
   protected argv documents (the same replay set `job_codeql_analysis` uses). A command the secret
   scan redacted, or a missing or incomplete command set, cannot be replayed and is a gap;
3. copies the accepted source into a fresh workspace, `data/sanitizer/<build-unit-id>/workspace`.
   The normal build's `data/build/native/units/<build-unit-id>/workspace` is neither reused nor
   altered, and `build` directories are never copied, so CMake configures from scratch;
4. replays the commands in the accepted build image through `BuildContainerExecutor`, the container
   policy the normal build uses (non-root, all capabilities dropped, `no-new-privileges`, read-only
   root, 2 CPUs, 4 GiB, 1024 processes), with these environment variables added to the recorded
   environment of every command:

   | Variable | Value |
   | --- | --- |
   | `CFLAGS`, `CXXFLAGS`, `LDFLAGS` | `-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1`, followed by any flags the accepted recipe already set in that variable |
   | `ASAN_OPTIONS` | `detect_leaks=0` |

   CMake takes `CFLAGS`/`CXXFLAGS`/`LDFLAGS` on the first configure of a fresh build directory,
   which is why a fresh workspace needs no build-directory rewrite. The flags are
   `-fsanitize=<settings.sanitizers>` plus `settings.extra_flags`. `ASAN_OPTIONS` comes from
   `settings.build_environment`; it keeps LeakSanitizer, which needs `ptrace`, from failing a helper
   program the build itself runs inside the capability-dropped container;
5. catalogues the produced objects, executables and shared libraries (build-system probe programs
   such as CMake's compiler identification are counted under `excluded_bookkeeping`, not listed),
   and reads each one's ELF for the sanitizer runtime. Before cataloguing, the job replays the
   accepted language build's `build_output_dispositions` roots (all except `per_file` ones) onto
   the identical rebuild layout and applies the current `[build_outputs]` rules. Dependency trees
   are pruned entirely, including the linked outputs the language build kept, because they are not
   part of the target's instrumentation verdict. The job does not rediscover the layout.

The compiler is the one the accepted recipe resolves. In `audit-buildenv-cpp:local` that is
`/usr/bin/c++`, GCC 13.3, whose `libasan` and `libubsan` are present. The image also carries
`clang++-18` but not its compiler-rt sanitizer runtime, so a recipe that selects clang fails to link
and is reported as a missing runtime (below), not skipped.

## The no-execution invariant

`docs/operations/post-build-security-assessment.md` states that target binaries are never loaded or
executed. This job keeps that rule: it runs only the accepted recipe's build tools (CMake, make,
compilers, linkers). It never runs a produced file, not even `--version`, and runs no tests. A build
that runs its own generator during compilation does so exactly as the normal build does, inside the
same sandbox.

Instrumentation is verified by **reading** the file with the bounded, dependency-free ELF reader in
`jobs/job_language_build/elf.py`, which reads only section headers, `.dynsym`/`.dynstr`,
`.symtab`/`.strtab` and `DT_NEEDED`. An output references the AddressSanitizer runtime when its
symbol tables hold `__asan_*` names (`__asan_init`, `__asan_report_*`, `__asan_memcpy`) or it names
`libasan`/`libclang_rt.asan`; it references the UBSan runtime for `__ubsan_*` names or
`libubsan`/`libclang_rt.ubsan`. The normal build's file at the same workspace path is read the same
way as a control (`baseline`), so the record shows the plain build lacks the runtime. A stripped
file has no symbol tables and proves nothing either way; it is reported as `no_symbol_tables`.

## Settings

All keys are required in `[jobs.job_sanitizer_build.settings]`; unknown keys are rejected and the
code has no fallback.

| Setting | Shipped value | Controls |
| --- | --- | --- |
| `enabled` | `true` | a disabled job is omitted from execution plans |
| `workers` | 2 | build units rebuilt concurrently (one container at a time per unit) |
| `sanitizers` | `["address", "undefined"]` | sanitizers named in `-fsanitize=`; drawn from `address`, `undefined` |
| `extra_flags` | `["-fno-omit-frame-pointer", "-g", "-O1"]` | flags after `-fsanitize=`; none may select a sanitizer |
| `required_evidence` | `["address"]` | sanitizers whose runtime every linked output must reference; a subset of `sanitizers` |
| `build_systems` | `["cmake", "autotools", "meson", "make"]` | accepted `build_system` values that are rebuilt |
| `build_environment` | `{ASAN_OPTIONS = "detect_leaks=0"}` | extra environment for every replayed command; may not set the three flag variables or secret-like names |
| `command_timeout_seconds` | 1800 | per replayed command |
| `output_bytes` | 8388608 | retained bytes of each command's stdout and stderr log; longer output is truncated and marked `truncated` (the total is recorded) |
| `artifact_count_limit` | 10000 | catalogued outputs per unit (and the workspace manifest bound) |
| `max_units` | 32 | native units rebuilt per run; the rest are a named gap |

`UBSan` is recorded per output but is not in `required_evidence`: a translation unit with nothing
for UBSan to check references no `__ubsan_*` handler, and treating that as a failed build would be a
false gap.

## Output layout

Everything the job writes under `data/` is claimed by its dataset declarations
(`jobs/job_sanitizer_build/datasets.py`); the dataset publication audit would otherwise fail the run
with `unaccounted_file`.

| Path | Dataset | Disposition |
| --- | --- | --- |
| `data/sanitizer/<build-unit-id>/workspace/` | `sanitizer_build_workspaces` | protected: the instrumented source copy and build tree, including the binaries |
| `data/sanitizer/<build-unit-id>/protected-commands/replay.json` | `sanitizer_build_workspaces` | protected: the exact argv and environment replayed |
| `data/sanitizer/<build-unit-id>/logs/NNN.stdout`, `NNN.stderr` | `sanitizer_build_workspaces` | protected: full command streams |
| `data/sanitizer/<build-unit-id>/workspace-manifest.json` | `sanitizer_build_workspaces` | protected: SHA-256 of every file after the build |
| `data/jobs/job_sanitizer_build/attempts/*/steps/acceptance/tasks/publish_handoff/sanitizer-build-summary.json` | `sanitizer_build_summary` | artifact only: the sanitized handoff |

Instrumented binaries are protected artifact-only evidence, never indexed text, and no existing job
reads them: the C/C++ analysis, CodeQL and the Clang jobs keep seeing exactly the normal build.

## Reading the result

The handoff schema is `appsec-review/sanitizer-build-handoff/1`. Its top level carries `counts`
(`planned_units`, `instrumented_units`, `instrumented_outputs`, `not_applicable_units`,
`omitted_units`, `gap_count`), `flags`, `build_outputs_policy` (the `[build_outputs]` policy
identity), `gaps`, and:

- `units[]`: one per planned native unit, with `terminal_status` (`SUCCEEDED`,
  `COMPLETED_WITH_GAPS` or `FAILED`), the boolean `instrumented`, the accepted `recipe_identity`,
  `image`, `network_required` as the accepted recipe recorded it, the replayed `commands` (argv
  hash, exit code, stream hashes), the `workspace` and its manifest hash, `outputs_sha256`,
  `build_output_dispositions` (the replayed roots and configured exclusions), and `gaps`;
- `units[].outputs[]`: `path` and `workspace_path`, `sha256`, `size_bytes`, `kind`
  (`executable`, `shared-library`, `object`), the boolean `instrumented`, `evidence`
  (`sanitizers.address|undefined.runtime_referenced`, up to eight symbol names, runtime libraries,
  symbol tables read) and `baseline`;
- `not_applicable_units[]`: accepted units of other families (`SKIPPED_NA`, not gaps);
- `omitted_units[]`: native units beyond `max_units`.

The job status is `SUCCEEDED` only when every planned unit is instrumented. Otherwise it is
`COMPLETED_WITH_GAPS`; with no native unit it is `NOT_APPLICABLE`. A unit is `instrumented` when it
has no gap and at least one output, and an output is `instrumented` when its runtime evidence was
read and every `required_evidence` sanitizer is referenced.

## Gaps

A gap is never a silent skip and never a clean result. The unit's `gaps` and the job's `gaps` name
the reason:

| Gap text | Meaning |
| --- | --- |
| `the accepted native build did not succeed, so there is no recipe to instrument` | the normal build failed; there is nothing to replay |
| `build system '<x>' is not enabled for sanitizer rebuilds` | the unit's build system is not in `build_systems` |
| `not replayable: ...` | the protected argv is missing, redacted or incomplete |
| `sanitizer flags cannot be injected through the environment: ...` | the recipe pins flags on its command line (`-DCMAKE_CXX_FLAGS=`, `-DCMAKE_EXE_LINKER_FLAGS=`, `CXXFLAGS=...`, Meson `-Dc_args=`, any `-fsanitize`) or in its environment (a `-fsanitize` in `CFLAGS`/`CXXFLAGS`/`LDFLAGS`); the environment would be masked or contradicted, so nothing is built |
| `the accepted build image is unavailable or changed` | the pinned build image no longer resolves to the accepted image id |
| `instrumented build command N exited C` / `timed out` | the instrumented build failed; the unit is `FAILED` and no outputs are catalogued |
| `...; the build image lacks the sanitizer runtime libclang_rt.asan-x86_64.a` | the linker could not find a sanitizer runtime in the build image |
| `<path>: no address sanitizer runtime reference ...; the build did not take the flags` | the build succeeded but an output does not reference the runtime, for example because the build system ignored the environment |
| `<path>: no symbol tables (stripped) ...` / `ELF was not parseable ...` | instrumentation could not be proven |
| `the instrumented build produced no native objects, executables or shared libraries` | nothing to catalogue |
| `unit bound of N reached; this native build unit was not rebuilt` | more native units than `max_units` |

A target changing during the build is a framework integrity failure, not a gap: the unit fails.

## Plugging in a later execution stage

Running the instrumented binaries is a separate, separately authorized stage; this job is only its
input. Such a stage would take the accepted `job_sanitizer_build` handoff, require its
`upstream.language_build_handoff_sha256` and each output's `sha256` and workspace manifest to match
the files under `data/sanitizer/`, and run only outputs with `instrumented: true`. It must carry its
own execution sandbox, input and time bounds and crash-report handling (`ASAN_OPTIONS`,
`UBSAN_OPTIONS`), declare `job_sanitizer_build` in its `CONSUMES`, and publish its own datasets. The
no-execution rule above applies to this job and to the existing build and assessment jobs; it does
not extend to a stage that is authorized to run code.

## Not covered by this job

- The container policy is the language build's: network follows `BuildContainerExecutor`, not the
  recipe's `network_required` flag, which the handoff only records.
- Families other than `native` (Go, Rust, Node, Python and others) are `SKIPPED_NA`; sanitizing them
  needs their own toolchain flags.
- The instrumented build's compiler and optimization level differ from the normal build's; do not
  compare the two binaries beyond their sanitizer evidence.

## Verification

Offline tests (fake Docker CLI under the real `BuildContainerExecutor`):

```bash
python -m pytest --basetemp=test/tmp/<session> tests/test_sanitizer_build.py
```

The live tier skips unless Docker and `audit-buildenv-cpp:local` are present. It builds
`targets/cpp-multivuln` with and without the environment and reads both `relay` binaries:

```bash
python -m pytest --basetemp=test/tmp/<session> tests/live/test_sanitizer_live.py
```
