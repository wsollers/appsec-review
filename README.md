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
| `images/audit-codeql/` | CodeQL bundle (pinned), offline; pre-engagement security-extended suites per language; license gate (ADR-0006) |
| `images/audit-iac/`, `audit-container/`, `audit-report/`, `mythos-orchestrator/` | Planned; empty except README |
| `orchestrator/` | Python: ledger writer + hash chain, contract validator, artifact registry, run-state regeneration |
| `scripts/` | Existing toolbox scripts (PowerShell + Python + sh), copied as-is |
| `schemas/` | JSON Schema for findings, contracts, component-purpose-map, index-manifest, compile-command-audit, patch-policy |
| `contracts/` | One YAML lane contract per lane (L0–L15, L0A, L6A/B) |
| `prompts/skills/`, `prompts/lanes/` | Reusable agent skills and per-lane prompts |
| `validation/` | Ground-truth corpus manifest and harnesses (Notepad++ v8.5.6 → v8.5.7 first) |
| `targets/` | Ignored local target checkouts, such as EASTL, kept out of git |
| `scratch/` | Ignored local run outputs, databases, bitcode, logs, and LLM packages |

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

## WSL-local target workflow

For real runs on Windows/WSL, use a repo checkout on the WSL ext4 filesystem, not under
`/mnt/c` or `/mnt/f`. Keep cloned targets under the ignored repo-local `targets/` directory
and write outputs under ignored `scratch/` so Docker bind mounts stay on fast WSL storage.
The default engagement path is bash + Docker. The PowerShell static prepass remains available
for Windows + Docker runs via `--static-runner powershell`.

```bash
cd ~/projects/appsec-review
mkdir -p targets scratch
git clone --depth 1 https://github.com/electronicarts/EASTL targets/eastl
cmake -S targets/eastl -B targets/eastl/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

export CODEQL_LICENSE_BASIS=oss
bash pipeline/engagement_job.sh \
  --project eastl \
  --target "$PWD/targets/eastl" \
  --compile-db "$PWD/targets/eastl/build/compile_commands.json" \
  --out "$PWD/scratch/eastl-engagement" \
  --msvc -

cat scratch/eastl-engagement/job-status.md
```

## Non-negotiables carried over from the previous toolbox

- Every tool version is pinned at first write. No `@latest`, no `curl | sh` from `main`.
- Every tool invocation is a static script baked into the image, invoked as a two-element
  command array. No shell strings assembled at runtime (this bug was fixed four separate
  times in the previous orchestrator).
- `/workspace` is mounted read-only. Build workers never write canonical evidence.
