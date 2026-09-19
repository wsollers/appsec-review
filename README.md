# appsec-review

Static/offline application-security review system ("Mythos v3" design): deterministic
evidence gathering → LLM-assisted discovery → refutation → independent verification →
cross-lane synthesis. The current implementation combines Dockerized scanner/native
evidence jobs with a tracked prompt/process harness under `appsec-review-process/`.

Design authority: `docs/design-v3.md` (exported from the Google Doc on 2026-09-11; the Doc
remains the editing surface until this repo takes over — see `docs/decisions/ADR-0004`).

Agent entrypoints live in [`AGENTS.md`](AGENTS.md). Agents should use
[`docs/agent-reader.md`](docs/agent-reader.md) to find the current Dagster, run-output, persona,
registry and evidence-retrieval docs before operating on a run.

## Submit a job

Follow the [job submission guide](docs/dagster-launching.md) to create and stage a Linux-owned
engagement, submit from the host, inspect results, reconnect, recover or cancel. For a staged run:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --wait
python -B appsec-review-process/review_cli.py status --run-id <run_id>
```

The default is `engagement_workflow`: intake, parallel scope/native-plan/handoff preparation,
then a validated final join. Use `--job phase1_intake` only when requesting intake alone.

Use `--job build_discovery` for the first build-discovery integration. `--job full_review` exposes
all lifecycle and registry jobs with explicit blockers for missing workers. See
[build discovery and readiness](docs/build-discovery-integration.md).

Job requirements, queue semantics, monitoring, run-owned output locations and persona/registry
lookups are documented in [Dagster launching](docs/dagster-launching.md) and the
[agent reader](docs/agent-reader.md).

## Layout

Phase 1 stateful intake is [accepted through A01-A16](docs/phase-1-acceptance.md).
Use the [Dagster launcher](docs/dagster-launching.md) to submit staged intake to the running service.
The default [engagement workflow](docs/dagster-workflow.md) queues concurrent engagements and runs
independent preparation steps in separate processes, with a validated final join.
Dagster resolves configuration and owns the pre/work/post transitions; Python performs the bounded
work. The shared adapter provides immutable attempts, freshness-checked reuse, explicit
pre/work/post gates and run-owned `data/`. Freeciv21 qualification covered intake and recovery;
downstream collection and review dispatch remain planned. The scratch-based scanner workflows
below are legacy workflows, with explicit imports required for new orchestrated runs.

| Path | Contents |
|---|---|
| `docs/` | Design doc, review notes, ADRs, migration notes |
| `images/audit-static/` | Existing toolbox Dockerfile (Semgrep, gitleaks, syft, trivy, IaC linters, Joern, BinSkim, PHP analyzers) — copied as-is, see `MIGRATION.md` |
| `images/audit-native/` | Pinned native-analysis image for clang-tidy/cppcheck, compile feasibility, IR emit/link, `ir-facts`, and CSA/CTU. Runs only inside the hostile-build boundary. |
| `images/audit-codeql/` | CodeQL bundle (pinned), offline; pre-engagement security-extended suites per language; license gate (ADR-0006) |
| `images/audit-iac/` | Terraform/Kubernetes/Helm/Kustomize policy scanning (checkov, tfsec, trivy config, kube-linter) — split out of `audit-static` 2026-09-17 |
| `images/audit-container/` | Dockerfile linting + base-image inventory (Hadolint, docker-base-images) — split out of `audit-static` 2026-09-17 |
| `images/audit-report/` | LaTeX -> PDF report build, adapted from the LRA governance project's standalone LaTeX image; report format/styleguide still undecided (see TODO) |
| `images/mythos-orchestrator/` | Planned; empty except README |
| `orchestrator/` | Python: ledger writer + hash chain, contract validator, artifact registry, run-state regeneration |
| `scripts/` | Existing toolbox scripts (PowerShell + Python + sh), copied as-is |
| `schemas/` | JSON Schema for findings, contracts, component-purpose-map, index-manifest, compile-command-audit, patch-policy |
| `contracts/` | One YAML lane contract per lane (L0–L15, L0A, L6A/B) |
| `prompts/skills/`, `prompts/lanes/` | Reusable agent skills and per-lane prompts |
| `appsec-review-process/` | Tracked manual LLM process harness: initiation/recovery prompt, lane folders, configs, subprompts, budgets, ignored logs, ignored run state |
| `validation/` | Ground-truth corpus manifest and harnesses (Notepad++ v8.5.6 → v8.5.7 first) |
| `targets/` | Ignored local target checkouts, such as EASTL, kept out of git |
| `scratch/` | Ignored local run outputs, databases, bitcode, logs, and LLM packages |

The persona catalog and intelligence/job catalog live under
[`docs/persona-catalog.md`](docs/persona-catalog.md) and
[`docs/intelligence-sources-and-jobs.md`](docs/intelligence-sources-and-jobs.md). The root files
with those names are compatibility pointers.

## Current Architecture

Dagster is the normal orchestration layer. It queues jobs, serializes submissions for the same
engagement, runs independent preparation steps in parallel and records failures/recovery. The
[current workflow](docs/dagster-workflow.md) implements intake and preparation; downstream scanner
and specialist execution remains planned.

The separate legacy deterministic evidence layer is run by:

- `pipeline/engagement_job.sh` on Bash/WSL/Linux
- `pipeline/engagement_job.ps1` on Windows PowerShell/Docker

It writes static evidence, native scratch artifacts, CodeQL/CSA/IR results, correlated findings,
deep confirmation, retrieval plans, a coverage ledger, and `llm/ENGAGEMENT_LLM_INPUT.md`.

The LLM process layer is run from `appsec-review-process/`. It starts with `initiate.md`, stages
evidence into an ignored `runs/<run_id>/` directory, creates lane handoffs, records failures and
resume points, and validates lane outputs.

See `docs/appsec-review-architecture-and-jobs-2026-09-16.md` for the historical scanner/prompt
architecture and the current guides above for Dagster submission.

## Operating assumption

Plan production-scale runs for a **Linux or WSL host with Docker** where target and scratch I/O stay
on a native Linux filesystem. That remains the fastest and simplest container isolation model.

Windows PowerShell + Docker is now a supported and validated host path for parity, smoke tests,
and smaller engagements. It can bind-mount WSL UNC paths and run the same high-level engagement
shape, but it is slower for heavy `ir-facts` and CodeQL work.

## Build / Validation Order

1. Build Docker images: `scripts/build-audit-images.sh` (WSL/Linux, preferred) or `scripts/Build-AuditImages.ps1` (native Windows PowerShell). Builds audit-static, audit-native, audit-codeql, audit-iac, audit-container, and audit-report from one entrypoint; `--only`/`-Only` builds a subset.
2. Run static prepass smoke (`cloc`) to validate Docker mounts.
3. Run native pregather without CodeQL/CSA to validate compile DB normalization, native SAST, feasibility, IR, link, and `ir-facts`.
4. Run CodeQL-enabled pregather to validate regular security-extended and custom Mythos CodeQL.
5. Run CSA/CTU or enable `--csa`/`-Csa` for full native analyzer coverage.
6. Regenerate assemble/correlation/deep-confirmation/retrieval/LLM input after adding evidence.
7. Run `appsec-review-process` probe lanes before full LLM review.

## Legacy WSL-local scanner workflow

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

## Legacy Windows PowerShell + Docker scanner workflow

The Windows runner supports WSL UNC targets and writes the same output shape:

```powershell
.\pipeline\engagement_job.ps1 `
  -Project eastl `
  -Target '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl' `
  -CompileDb '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl\build\compile_commands.json' `
  -Out scratch\eastl-windows-codeql `
  -StaticRunner powershell `
  -StaticSteps cloc

Get-Content scratch\eastl-windows-codeql\job-status.md
```

The bounded `-StaticSteps cloc` form is for plumbing validation. Omit it for a full broad static
prepass.

Windows validation against EASTL completed with:

- native syntax feasibility Tier A, `126/126`
- IR feasibility Tier A, `126/126`
- linked bitcode and `ir-facts`
- CodeQL security-extended and custom Mythos CodeQL
- CSA/CTU verified through the native Docker wrapper and folded into regenerated LLM artifacts

## Non-negotiables carried over from the previous toolbox

- Every tool version is pinned at first write. No `@latest`, no `curl | sh` from `main`.
- Every tool invocation is a static script baked into the image, invoked as a two-element
  command array. No shell strings assembled at runtime (this bug was fixed four separate
  times in the previous orchestrator).
- `/workspace` is mounted read-only. Build workers never write canonical evidence.

## Evidence retrieval

Submit `evidence_index` through Dagster to collect accepted source/discovery evidence, compute
ssdeep fingerprints and publish a cited SQLite full-text index. See the
[LLM tooling addendum](appsec-review-process/tooling/llm-retrieval-addendum.md) for CLI/MCP queries,
language servers, capability probes and recovery, and [qualification](docs/evidence-retrieval.md).
