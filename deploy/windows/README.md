# Windows host build runner

PowerShell 7 scripts that build C/C++ natively on the Windows host with the installed Visual Studio
toolchain. Design, limits, and what is not done: `docs/architecture/windows-host-runner.md`.

```powershell
# Is the toolchain ready? Builds the canary with MSVC, clang-cl and MSVC AddressSanitizer; runs nothing.
pwsh -File deploy/windows/Test-BuildToolchain.ps1 -OutputDirectory test/tmp/windows-readiness

# Build a source tree into an empty run directory (CMake/Ninja by default).
pwsh -File deploy/windows/Invoke-NativeBuild.ps1 -Source <dir> -RunDirectory test/tmp/windows-build/run1 `
    -Compiler clang-cl -Sanitize address -AcceptHostRisk
```

`-AcceptHostRisk` is required for any source except `deploy/windows/canary`: the build is not sandboxed.
Keep run directories under `test/tmp/`.
