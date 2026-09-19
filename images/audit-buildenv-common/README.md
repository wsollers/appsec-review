# Audit Build Environments

These images are language-specific build, LSP, and MCP-capable workers for repo discovery and
bounded validation.

Runtime boundary:

- `/workspace` is mounted read-only.
- `/scratch` is the only writable bind mount.
- Docker capabilities are dropped.
- Network is disabled by default. Set `ALLOW_NETWORK=1` only for explicitly authorized dependency
  restore or tool bootstrap work.
- Debugger attach capabilities are disabled by default. Set `DEBUG_CAPS=1` only for approved
  ptrace/debugging sessions that need `SYS_PTRACE` and an unconfined seccomp profile.

Common wrapper:

```bash
images/audit-buildenv-common/run.sh audit-buildenv-python:local <workspace> <scratch> -- python --version
```

```powershell
.\images\audit-buildenv-common\run.ps1 audit-buildenv-python:local <workspace> <scratch> -- python --version
```

MCP support means each image has Node.js and Python available so stdio MCP servers/adapters can be
installed at build time or mounted/run from `/scratch`. The repository-specific skills under
`appsec-review-process/agent-skills/` describe how agents should use these workers.

The dedicated binary analysis worker is `audit-binary-analysis:local`. Use it for PE, ELF, DWARF,
PDB, symbol, call-graph, and binary triage work. It includes Ghidra headless, angr, RetDec,
cwe_checker/check_cwe, FLOSS, DIE, YARA, Syft/Grype/Trivy, ssdeep/TLSH, QEMU user emulation,
Android APK helpers, ILSpy, and Frida support for approved deeper reverse-engineering and pregather
intelligence passes. Keep
input binaries under `/workspace` and write all derived output under `/scratch`.
