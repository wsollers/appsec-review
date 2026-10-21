# Windows host build runner

Status: scripts implemented and proven on a canary; pipeline integration not started.

The Windows project builds and analyzes C/C++ natively on the Windows host that already runs the
Dagster stack, with the Visual Studio toolchain installed on that host. This replaces the throwaway-VM
backend in [`windows-native-analysis-vm.md`](windows-native-analysis-vm.md) for this deployment: the
owner decided on 2026-10-21 to use the Windows host directly instead of a VM (the host is Windows 11
Home, which has no Hyper-V). The VM design remains the reference for the interface, evidence, and
license gates; its isolation sections do not apply to this runner and are not claimed by it.

## What a host-native build does and does not give

| | VM design | Host-native runner |
| --- | --- | --- |
| Target build code runs as | a separate standard guest account | the invoking host user |
| Network during the build | none | **not blocked** |
| Files the build can reach | the guest only | everything the user can read and write |
| Clean state per run | restored snapshot | fresh copy of the source and a fresh run directory only |
| Cleanup | VM deleted | run directory remains until removed |

A C/C++ build executes target-controlled code: CMake `execute_process`, MSBuild tasks and pre/post-build
events, custom commands, and code generators all run during configure and build. On the host that code
runs as the user, with their files, credentials, and network. The runner therefore:

- refuses any source other than the repository canary unless `-AcceptHostRisk` is passed, and records
  that acceptance in the result;
- builds a copy of the source in a fresh, empty run directory, never the original;
- starts the build from a minimal environment (no inherited variables, an empty per-run user profile,
  `TEMP` inside the run) with the toolchain's developer variables added;
- enforces a wall-clock limit and kills the whole process tree on timeout; and
- never runs a produced binary. Sanitizer evidence is read from the binary's imports.

Hardening that would make host builds acceptable for untrusted targets is **not implemented**: a
dedicated low-privilege local build account with NTFS denies on the user profile, an outbound firewall
rule scoped to that account, and a job object with memory and process limits. Build only sources you
would run yourself until that exists.

## Toolchain

The runner uses what Visual Studio provides, located with `vswhere`: MSVC `cl`/`link`, `clang-cl` and
`clang-tidy` (the Clang component), MSBuild, the bundled CMake and Ninja, the Windows SDK, and the MSVC
AddressSanitizer runtime. `deploy/windows/Test-BuildToolchain.ps1` records the version and SHA-256 of each
executable actually resolved and builds the repository canary with MSVC, `clang-cl`, and MSVC ASan.
Visual Studio Community's license terms and eligibility are the operator's to confirm; this repository
does not install or redistribute Visual Studio.

On the owner's host the check reported Visual Studio Community 2026 (18.6), MSVC 19.51, clang-cl 20.1.8,
CMake 4.2.3, Ninja 1.13.2, and MSBuild 18.6.

## Build runner

`deploy/windows/Invoke-NativeBuild.ps1 -Source <dir> -RunDirectory <empty dir>` builds with CMake and
Ninja (default) or MSBuild (`-BuildSystem msbuild -Project <sln|vcxproj>`), with `-Compiler cl|clang-cl`
and `-Sanitize address`. It writes `result.json` (`appsec-review/windows-host-build/1`):

- status (`SUCCEEDED`, `FAILED`, `TIMED_OUT`), the request, and the Visual Studio identity;
- every step with tool SHA-256, argv, exit code, duration, and the hashes of its stdout and stderr;
- the exact commands the build ran: `ninja -t commands` output for CMake, the MSBuild binary log for
  MSBuild, each hashed; and
- a SHA-256 inventory of produced `.exe`, `.dll`, `.lib`, `.obj`, `.pdb`, and `.json` files, and, for
  sanitizer builds, whether each executable or DLL references the sanitizer runtime.

A produced binary that lacks the sanitizer runtime, a missing executable, or a truncated inventory is a
named gap (exit code 2), not a success.

Proven on the canary: CMake with `clang-cl`, CMake with MSVC and ASan, and MSBuild with MSVC, MSVC and
ASan, and `clang-cl`, each building and the two ASan builds referencing the runtime.

## Not done

- **Pipeline integration.** The Dagster code location runs in a Linux container and cannot start a host
  process. Integration needs a host-side service that accepts a run request, invokes the runner, and
  returns the result and artifacts, and a Windows family in `job_language_build`.
- **Capture.** Linux builds record commands with `strace`. Here the build graph (`ninja -t commands`,
  MSBuild binary log) is the record; it does not capture commands a custom step runs outside the build
  tool.
- **Analysis of the output.** clang-tidy, CodeQL, and Semgrep on Windows source and the PDB-based symbol
  work in the VM design have no implementation yet.
- **Low-privilege account and network block**, as above.
