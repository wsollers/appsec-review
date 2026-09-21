# appsec-review

Static/offline application-security review system ("Mythos v3" design): deterministic
evidence gathering → LLM-assisted discovery → refutation → independent verification →
cross-lane synthesis. The current implementation combines Dockerized scanner/native
evidence jobs with a tracked prompt/process harness under `appsec-review-process/`.

Design authority: `docs/architecture/design-v3.md` (exported from the Google Doc on 2026-09-11; the Doc
remains the editing surface until this repo takes over — see `docs/decisions/ADR-0004`).

Agent entrypoints live in [`AGENTS.md`](AGENTS.md). Agents should use
[`docs/agent-reader.md`](docs/agent-reader.md) to find the current Dagster, run-output, persona,
registry and evidence-retrieval docs before operating on a run.

## Submit a job

Follow the [job submission guide](docs/dagster/dagster-launching.md) to create and stage a Linux-owned
engagement, submit from the host, inspect results, reconnect, recover or cancel. For a staged run:

```powershell
python -B appsec-review-process/launch_job.py --run-id <run_id> --wait
python -B appsec-review-process/review_cli.py status --run-id <run_id>
```

The default is `engagement_workflow`: intake, parallel scope/native-plan/handoff preparation,
then a validated final join. Use `--job phase1_intake` only when requesting intake alone.

Use `--job build_discovery` for the first build-discovery integration. `--job full_review` exposes
all lifecycle and registry jobs with explicit blockers for missing workers. See
[build discovery and readiness](docs/build-discovery/build-discovery-integration.md).

Use `--job critical_findings_sarif` after staging validated finding Markdown at
`runs/<run_id>/inputs/critical-findings.md`. The job is a format transform, not finding
verification; it publishes only after strict input, SARIF, freshness and hash checks pass.

Use `--job ossf_scorecard` only after staging a fixed project list and granting
`network:api.scorecard.dev`. It ingests published OpenSSF Scorecard JSON2 results with immutable
response provenance; it is not a live repository scan or a finding verdict. See
[the Scorecard job guide](docs/evidence/ossf-scorecard-job.md).

Job requirements, queue semantics, monitoring, run-owned output locations and persona/registry
lookups are documented in [Dagster launching](docs/dagster/dagster-launching.md) and the
[agent reader](docs/agent-reader.md).

## Layout

Phase 1 intake was accepted through A01-A16 on 2026-09-19 (run `20260919T104300Z-ba7b4c`).
Use the [Dagster launcher](docs/dagster/dagster-launching.md) to submit staged intake to the running service.
The default [engagement workflow](docs/dagster/dagster-workflow.md) queues concurrent engagements and runs
independent preparation steps in separate processes, with a validated final join.
Dagster resolves configuration and owns the pre/work/post transitions; Python performs the bounded
work. The shared adapter provides immutable attempts, freshness-checked reuse, explicit
pre/work/post gates and run-owned `data/`. Freeciv21 qualification covered intake and recovery;
downstream collection and review dispatch remain planned. The scratch-based scanner workflows
below are legacy workflows, with explicit imports required for new orchestrated runs.

| Path | Contents |
|---|---|
| `docs/` | Design doc, review notes, ADRs, migration notes |
| `images/audit-static/` | Existing toolbox Dockerfile (Semgrep, gitleaks, syft, trivy, IaC linters, Joern, BinSkim, PHP analyzers) — copied as-is, see `docs/architecture/migration.md` |
| `images/audit-native/` | Pinned native-analysis image for clang-tidy/cppcheck, compile feasibility, IR emit/link, `ir-facts`, and CSA/CTU. Runs only inside the hostile-build boundary. |
| `images/audit-codeql/` | CodeQL bundle (pinned), offline; pre-engagement security-extended suites per language; license gate (ADR-0006) |
| `images/audit-iac/` | Terraform/Kubernetes/Helm/Kustomize policy scanning (checkov, tfsec, trivy config, kube-linter) — split out of `audit-static` 2026-09-17 |
| `images/audit-container/` | Dockerfile linting + base-image inventory (Hadolint, docker-base-images) — split out of `audit-static` 2026-09-17 |
| `images/audit-report/` | LaTeX -> PDF report build, adapted from the LRA governance project's standalone LaTeX image; report format/styleguide still undecided (see `appsec-review-process/TODO.md`) |
| `images/mythos-orchestrator/` | Planned; empty except README |
| `orchestrator/` | Python: ledger writer + hash chain, contract validator, artifact registry, run-state regeneration |
| `scripts/` | Legacy toolbox compatibility scripts. Do not add new review-work logic here; port active review work into `pipeline/` or Dagster/run-owned workers, qualify it, then delete the old script outright -- no thin compatibility wrapper. |
| `schemas/` | JSON Schema for findings, contracts, component-purpose-map, index-manifest, compile-command-audit, patch-policy |
| `contracts/` | One YAML lane contract per lane (L0–L15, L0A, L6A/B) |
| `prompts/skills/`, `prompts/lanes/` | Reusable agent skills and per-lane prompts |
| `appsec-review-process/` | Tracked manual LLM process harness: initiation/recovery prompt, lane folders, configs, subprompts, budgets, ignored logs, ignored run state |
| `validation/` | Ground-truth corpus manifest and harnesses (Notepad++ v8.5.6 → v8.5.7 first) |
| `targets/` | Ignored local target checkouts, such as EASTL, kept out of git |
| `scratch/` | Ignored local run outputs, databases, bitcode, logs, and LLM packages |

Top-level process docs now live under `docs/`:

- [`docs/architecture/migration.md`](docs/architecture/migration.md)
- [`docs/personas-and-registry/persona-catalog.md`](docs/personas-and-registry/persona-catalog.md)
- [`docs/evidence/intelligence-sources-and-jobs.md`](docs/evidence/intelligence-sources-and-jobs.md)
- [`docs/design-parity/design-parity-completion-plan.md`](docs/design-parity/design-parity-completion-plan.md)
- [`docs/dagster/critical-findings-sarif-job.md`](docs/dagster/critical-findings-sarif-job.md)

The active process TODO list is [`appsec-review-process/TODO.md`](appsec-review-process/TODO.md).
Machine-readable implementation readiness lives in
[`appsec-review-process/design-parity-manifest.json`](appsec-review-process/design-parity-manifest.json).
Validate it with `python -B appsec-review-process/validate_design_parity.py`; generated stable
views are the [parity report](docs/design-parity/design-parity-report.md),
[lifecycle graph](docs/design-parity/full-review-workflow.mmd), and
[operator readiness table](docs/design-parity/design-parity-readiness.md). The shared terminal result/state
contract and read-only validation boundary are described in
[the worker-result envelope](docs/adapters/worker-result-envelope.md).

Script migration policy: review-work scripts currently under `scripts/` should be treated as
temporary compatibility surfaces. The target home for deterministic review work is `pipeline/` for
legacy engagement assembly or `appsec-review-process/` Dagster workers for run-owned jobs. Once a
replacement is qualified and callers are updated, remove the old script rather than continuing to
maintain two implementations.

## Current Architecture

Dagster is the normal orchestration layer. It queues jobs, serializes submissions for the same
engagement, runs independent preparation steps in parallel and records failures/recovery. The
[current workflow](docs/dagster/dagster-workflow.md) implements intake and preparation; downstream scanner
and specialist execution remains planned.

The separate legacy deterministic evidence layer is run by:

- `pipeline/engagement_job.sh` on Bash/WSL/Linux
- `pipeline/engagement_job.ps1` on Windows PowerShell/Docker

It writes static evidence, native scratch artifacts, CodeQL/CSA/IR results, correlated findings,
deep confirmation, retrieval plans, a coverage ledger, and `llm/ENGAGEMENT_LLM_INPUT.md`.

The LLM process layer is run from `appsec-review-process/`. It starts with `initiate.md`, stages
evidence into an ignored `runs/<run_id>/` directory, creates lane handoffs, records failures and
resume points, and validates lane outputs.

The pre-Dagster scanner/prompt architecture is in git history (`docs/appsec-review-architecture-and-jobs-2026-09-16.md`,
removed 2026-09-21); the current guides above cover Dagster submission.

## Operating assumption

Plan production-scale runs for a **Linux or WSL host with Docker** where target and scratch I/O stay
on a native Linux filesystem. That remains the fastest and simplest container isolation model.

Windows PowerShell + Docker is now a supported and validated host path for parity, smoke tests,
and smaller engagements. It can bind-mount WSL UNC paths and run the same high-level engagement
shape, but it is slower for heavy `ir-facts` and CodeQL work.

## Build / Validation Order

1. Build Docker images: `python -B images/image_build.py list` shows every build declared in `images/<name>/image.json`; `python -B images/image_build.py build <image_id> [<image_id> ...]` builds one or more, each with its own lock, logs and result under `images/.build-state/`. Options: `--no-cache`, `--force`, `--tag`, `--build-arg K=V`, `--docker-context`, `--timeout-seconds`. Build `audit-native` before `audit-codeql-native` and `audit-buildenv-cpp`; an unchanged image is reused. Needs Python 3 and Docker on PATH; Linux is the tested host.
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
language servers, capability probes and recovery, and [qualification](docs/evidence/evidence-retrieval.md).
