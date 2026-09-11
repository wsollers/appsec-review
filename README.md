# appsec-review

Static/offline application-security review system ("Mythos v3" design): multi-agent
discovery → refutation → independent verification → cross-lane synthesis, backed by an
append-only hash-chained ledger and machine-enforced lane contracts.

Design authority: `docs/design-v3.md` (exported from the Google Doc on 2026-09-11; the Doc
remains the editing surface until this repo takes over — see `docs/decisions/ADR-0004`).

## Layout

| Path | Contents |
|---|---|
| `docs/` | Design doc, review notes, ADRs, migration notes |
| `images/audit-static/` | Existing toolbox Dockerfile (Semgrep, gitleaks, syft, trivy, IaC linters, Joern, BinSkim, PHP analyzers) — copied as-is, see `MIGRATION.md` |
| `images/audit-native/` | **To build.** Pinned LLVM/clang-cl, SVF, CSA/CodeChecker, cppcheck, Joern, CMake/Ninja, bear, xwin. Runs only inside the hostile-build boundary. |
| `images/audit-iac/`, `audit-container/`, `audit-report/`, `mythos-orchestrator/` | Planned; empty except README |
| `orchestrator/` | Python: ledger writer + hash chain, contract validator, artifact registry, run-state regeneration |
| `scripts/` | Existing toolbox scripts (PowerShell + Python + sh), copied as-is |
| `schemas/` | JSON Schema for findings, contracts, component-purpose-map, index-manifest, compile-command-audit, patch-policy |
| `contracts/` | One YAML lane contract per lane (L0–L15, L0A, L6A/B) |
| `prompts/skills/`, `prompts/lanes/` | Reusable agent skills and per-lane prompts |
| `validation/` | Ground-truth corpus manifest and harnesses (Notepad++ v8.5.6 → v8.5.7 first) |

## Operating assumption

Plan for a **Linux server with no Windows and no Visual Studio**. That is the lowest common
denominator across the candidate hosts (Windows workstation / Windows Server / Linux server)
and the one the container isolation model in design §2.2 actually fits. A Windows host, if
one appears, is a bonus (native `cl` builds for release/analysis diffing), not a dependency.

## Build order

1. `images/audit-native` Dockerfile + smoke test (trivial Win32 TU against mounted MSVC headers)
2. Compile-feasibility gate (`.vcxproj` → `compile_commands.json` → `clang-cl --syntax-only` pass rate) — decides the L3 tier (ADR-0001)
3. `orchestrator/` skeleton: ledger, contracts, artifact registry
4. `audit-static` refactor: strip native tooling out, pin the remaining floating installs
5. `audit-container`, `audit-iac`, `audit-report`
6. Prompts in dependency order: `lane-contract`, `finding-schema` skills → L0/L0A → L3 → L7 → L14 → discovery lanes

## Non-negotiables carried over from the previous toolbox

- Every tool version is pinned at first write. No `@latest`, no `curl | sh` from `main`.
- Every tool invocation is a static script baked into the image, invoked as a two-element
  command array. No shell strings assembled at runtime (this bug was fixed four separate
  times in the previous orchestrator).
- `/workspace` is mounted read-only. Build workers never write canonical evidence.
