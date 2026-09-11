# ADR-0002: Orchestrator is Python, not PowerShell

Status: Accepted 2026-09-11

## Context

The previous toolbox orchestrator (`Invoke-VendorAuditPrePass.ps1`) drives `docker.exe` from
PowerShell. PowerShell → docker.exe argv marshalling silently corrupted compound commands in
four separate steps (joern-parse, ast-grep-scan, sast-php, dockerfile-lint), each fixed by
moving the command into a baked-in script. The host may be a Linux server with no
PowerShell at all.

## Decision

`mythos-orchestrator` is Python (design §17). It is the only writer of the canonical ledger,
validates lane contracts, hashes and registers imported artifacts, and regenerates
`run-state.json` from the ledger. The PowerShell scripts are retained as reference for step
semantics and evidence layout until parity is reached.

## Consequences

- Tool invocations remain static scripts in each image, invoked as argv arrays from
  Python (`subprocess.run([...])`), never shell strings.
- Windows hosts run the orchestrator under Python for Windows or WSL; no PowerShell path
  is maintained.
