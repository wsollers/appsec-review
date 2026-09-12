# audit-native

Mythos L3 worker: clang-cl / LLVM IR / SVF / CSA / CodeChecker / cppcheck / Joern.
Runs only inside the hostile-build boundary (`run.sh`). Every version is pinned and every
download URL was verified live on 2026-09-11 (see comments in the Dockerfile).

| Tool | Version | Source |
|---|---|---|
| LLVM/Clang (RTTI) | 21.1.0 | bjjwwang/SVF-LLVM prebuilt (the one SVF-3.3 builds against) |
| clang-tidy, lld | 21 | apt.llvm.org jammy |
| SVF | SVF-3.3 | git tag, built with the LLVM above |
| Z3 | 4.8.8 | prebuilt (what SVF-3.3 build.sh downloads) |
| Joern | v4.0.625 | joern-cli-linux-x86_64.zip, JDK 21 |
| CodeChecker | 6.29.0 | pip |
| cppcheck | 2.21.1 | source |
| xwin | 0.10.0 | prebuilt binary (never run during image build) |
| bear | 3.1.3 | Ubuntu 22.04 apt |

## Build

```
docker build -t audit-native:local images/audit-native
```

The SVF build is the slow layer (several minutes).

Build log, 2026-09-11 (Zarathustra): first attempt on ubuntu:22.04 failed in the SVF
layer — SVF-3.3's `CMakeLists.txt` requires CMake ≥ 3.23 and jammy ships 3.22. Fixed by
moving the base to ubuntu:24.04 (which is what SVF's own Dockerfile uses with this same
tarball), adopting its dependency list, and adding the `libz3.so.4` symlink it creates.
Remaining first-build risks, in order: (1) the apt.llvm.org `noble` repo for
`clang-tidy-21`/`lld-21`, (2) SVF `build.sh` behavior when `LLVM_DIR`/`Z3_DIR` are
pre-set, (3) the `wpa` binary name/location under `Release-build/bin`.

## Source patches to upstream tools (`patches/`)

| Patch | Why | Status |
|---|---|---|
| `svf-3.3-vfg-setdef-diagnostic.py` | SVF's `VFG::setDef` asserts "a ValVar can only have unique definition" on the linked Notepad++ module (MSVC target), in both full and pointer-only SVFG. Patched to keep the first definition and print both with a `[SVF-PATCH]` prefix. | Diagnostic; root cause open (2026-09-12). Count occurrences per run; any result from a patched SVFG is recorded as such. |

## MSVC headers (ADR-0003 — default: xwin)

On a networked host:

```
images/audit-native/scripts/fetch-msvc-xwin.sh ./msvc 17 x86_64,x86
```

Produces `./msvc/{crt,sdk}` plus `PROVENANCE.txt` with a tree hash. Mount it read-only at
`/msvc`. The converter and smoke test detect this layout and emit `-imsvc` flags (xwin's
documented form); a real Visual Studio layout (`<root>/VC/...`) is detected and passed via
`/winsysroot` instead. The hash goes into `build-isolation-manifest.json`.

## Steps (each is a static script; the orchestrator calls one per `docker run`)

```
# 0. smoke: proves the toolchain end to end on a 20-line Win32 TU
run.sh <ws> ./msvc <scratch> -- /opt/scripts/smoke-test.sh

# 1. .vcxproj -> compile_commands.json + compile-command-audit seed (§23.4)
run.sh <ws> ./msvc <scratch> -- /opt/scripts/vcxproj_to_compile_commands.py \
    --root /workspace --config Release --platform x64 --msvc-root /msvc \
    --toolset-compat 19.44 \
    --out /scratch/compile_commands.json --audit /scratch/compile-command-audit.seed.json

# 2. feasibility gate -> tier (ADR-0001)
run.sh <ws> ./msvc <scratch> -- /opt/scripts/compile_feasibility_gate.py \
    --compile-commands /scratch/compile_commands.json --out /scratch/feasibility.json

# 2b. same, but actually emit bitcode for the TUs that pass (Tier A/B input to SVF)
run.sh <ws> ./msvc <scratch> -- /opt/scripts/compile_feasibility_gate.py \
    --compile-commands /scratch/compile_commands.json --out /scratch/feasibility-ir.json \
    --emit-ir --ir-dir /scratch/ir

# 3. llvm-link one module per product project (tests excluded), run SVF Andersen on each
run.sh <ws> ./msvc <scratch> -- /opt/scripts/link_ir.py \
    --feasibility /scratch/feasibility-ir.json --out /scratch/linked --wpa ander

# 4. Clang Static Analyzer over every TU (plist per TU, CodeChecker parse -> json + html,
#    plus findings-csa.json independent of CodeChecker). --filter narrows to a regex.
#    --ctu = cross-TU (on-demand parsing over the whole compile DB); the Win32 taint
#    source config (scripts/taint-win32.yaml) is on by default. Both are required for
#    security.ArrayBound to report input-derived indices into tables in other TUs.
run.sh <ws> ./msvc <scratch> -- /opt/scripts/run_csa.py \
    --compile-commands /scratch/compile_commands.json --out /scratch/csa --ctu [--alpha]

# 6. SVF whole-program taint on a linked module (see svf-taint/README.md; build first)
run.sh . - <scratch> -- /scratch/svf-taint-build/svf-taint -sources=ReadFile:1 \
    -out=/scratch/svf-taint.json /scratch/linked/<project>.bc

# 5. before/after: same TUs in two versions, matched by (checker, file, message)
diff_findings.py --before <v-before>/csa/findings-csa.json --after <v-after>/csa/findings-csa.json \
    --filter 'Utf8_16|uchardet|Buffer\.cpp'
```

CSA is driven directly rather than through `CodeChecker analyze`: CodeChecker rewrites
command lines assuming clang/gcc flag syntax and there is no evidence it handles cl-style
`/D` `/I` `/EHsc`. `CodeChecker parse` on the plist directory gives its exports, store
and baseline-diff without that dependency.

## Validation result — Notepad++ v8.5.6, 2026-09-11 (Zarathustra)

Full Tier A, end to end, inside the `run.sh` boundary (`--network none`, read-only
workspace, cap-drop ALL):

| Step | Result |
|---|---|
| `vcxproj_to_compile_commands.py` | 320 TUs from 6 projects, 0 missing sources, 2 unresolved macros (`UserRootDir`, self-referential `ExternalIncludePath` — both expected) |
| `compile_feasibility_gate.py` (syntax) | **320/320 pass → Tier A** |
| `compile_feasibility_gate.py --emit-ir` | 320 bitcode files, all verified `BC` magic, 133 MB |
| `link_ir.py` | 3 product modules linked (notepadPlus 101 TUs, Scintilla 38, Lexilla 134); 3 test projects excluded |
| `wpa -ander` on notepadPlus module | completed; 341,452 unique points-to sets. Module contains `Utf8_16.cpp` (CVE-2023-40031/40036/40164/40166) |

Progression during the session: 0/320 → 191 → 249 → 320. Every step of that
progression was one of the gotchas below.

## Windows-on-Linux gotchas (each cost a debugging round; the vendor tree will hit them too)

1. **Absolute source paths are parsed as cl options.** `/workspace/foo.cpp` matches
   `/wo<n>` and the TU vanishes ("no input files"). Always put `--` before the source.
   Result of missing it: 0/320.
2. **`-emit-llvm` is silently ignored in cl mode** ("unknown argument ignored") and a
   COFF `.obj` is written under the `.bc` name. Use `/clang:-emit-llvm`. The gate now
   checks the `BC` magic of every output so this cannot recur silently.
3. **`/Fo` is dropped once `--` is present.** Use `/clang:-o<path>` for the output.
4. **UCRT secure-overload templates don't compile under clang.** With
   `_CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES` defined, `corecrt_wstdio.h:1109` re-declares
   `_vsnwprintf` at block scope with `__inline`; MSVC allows it, clang doesn't. The
   converter adds `/D_NO_CRT_STDIO_INLINE` to every TU (recorded as
   `ANALYSIS_ONLY_MACRO_DIFFERENCE`). Cost: 74 TUs.
5. **MSBuild's default `ExceptionHandling` is `Sync`.** An absent tag means `/EHsc`, not
   nothing. Scintilla/Lexilla rely on the default. Cost: 34 TUs.
6. **`IncludePath` / `ExternalIncludePath` are include paths.** VS2019+ projects declare
   third-party headers there (Notepad++: scintilla, lexilla, tinyxml, json in
   `notepadPlus.Cpp.props`), not in `AdditionalIncludeDirectories`. Map to `/I` and
   `-imsvc`. Cost: 71 TUs.
7. **Path case.** `..\src\tinyxml` vs on-disk `TinyXml`; `#include "subdir/header.h"` vs
   `SubDir/Header.h`. Windows resolves both, Linux resolves neither. The converter
   resolves `.vcxproj` paths case-insensitively itself and emits a clang VFS overlay
   (`case-sensitive: false`, full tree enumerated) so `#include` directives resolve too.
8. **Same source in two projects.** Scintilla's `src/*.cxx` are compiled by both
   `Scintilla.vcxproj` and its `UnitTester.vcxproj`; name-based bitcode files overwrote
   each other (298 of 320) and linking everything together fails on duplicate symbols.
   Bitcode is stored per project (id = vcxproj path, since two `UnitTester.vcxproj`
   exist) and `link_ir.py` links one module per project.

Two more from the image/runtime side, recorded in `run.sh` and the Dockerfile:

- Docker tmpfs defaults to `noexec`; Joern's zstd-jni must `dlopen` a `.so` it extracts
  into `java.io.tmpdir`. `/tmp` stays `noexec`; the JVM alone gets an exec tmpfs at
  `/tmp/jvm` via `JAVA_TOOL_OPTIONS`.
- With `--network none` the container hostname doesn't resolve and every JVM start logs
  a log4j error. `--add-host <hostname>:127.0.0.1`.

## What the converter does NOT do

It is not MSBuild. `.targets` files, `Directory.Build.props`, and conditions other than
`'$(Configuration)|$(Platform)'` are reported in the audit seed, not evaluated. If the
vendor build relies on those for include paths or defines, the compilation database is
wrong in a way the audit seed will show you (`targets_not_evaluated`,
`directory_build_props_present`, `unresolved_macros`). That is the point: the database
starts `UNTRUSTED` and the orchestrator promotes it.
