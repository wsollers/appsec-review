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

The SVF build is the slow layer (several minutes). The image has **not** been built in a live
daemon by the author; the first build will tell you which of the SVF build.sh assumptions
holds. Expected first-build risks, in order: (1) `libtinfo5` availability on jammy, (2)
SVF-3.3 `build.sh` wanting a specific `LLVM_DIR` layout, (3) `wpa --version` not existing
(harmless; falls through to `ls`).

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
```

Tested on 2026-09-11 against Notepad++ v8.5.6 (no MSVC headers available in the authoring
environment): the converter produced 320 TUs from 6 projects with 0 missing sources after
adding case-insensitive path resolution and wildcard expansion; the gate ran clang-cl 21.1.0
from the pinned tarball and classified all failures as `MISSING_HEADER` (windows.h etc.),
which is the expected result without `/msvc`.

## What the converter does NOT do

It is not MSBuild. `.targets` files, `Directory.Build.props`, and conditions other than
`'$(Configuration)|$(Platform)'` are reported in the audit seed, not evaluated. If the
vendor build relies on those for include paths or defines, the compilation database is
wrong in a way the audit seed will show you (`targets_not_evaluated`,
`directory_build_props_present`, `unresolved_macros`). That is the point: the database
starts `UNTRUSTED` and the orchestrator promotes it.
