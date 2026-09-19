# Manual Orchestration Runbook

This runbook describes how to operate the prompt process before a full orchestrator exists.

## Start A Run

```bash
python3 appsec-review-process/run_process.py --start
```

Record the returned `run_id`.

## Stage Inputs

Prefer the helper:

```bash
python3 appsec-review-process/stage_artifacts.py \
  --run-id <run_id> \
  --project <project> \
  --target <target_path> \
  --engagement-output <scratch/project-engagement> \
  --compile-db <compile_commands.json> \
  --business-goal "<goal>"
```

This creates or updates:

```text
appsec-review-process/runs/<run_id>/inputs/artifact-manifest.json
```

At minimum, include:

- target path
- engagement output path
- job status path
- LLM input path
- coverage ledger path
- deep confirmation path
- retrieval plan path

## Normalize WSL Results Into Repo-Local Paths

If evidence collection ran in WSL but prompt/lane work will happen from this repo checkout, first
copy the source and engagement artifacts into the ignored repo-local layout:

```bash
scripts/sync-wsl-engagement-to-repo.sh \
  --project <project> \
  --source-url <git-url> \
  --source-ref <branch-or-commit> \
  --engagement-dir <wsl-scratch/project-engagement> \
  --run-id <run_id> \
  --business-goal "<goal>"
```

If the source is already cloned in WSL, use `--source-dir <wsl-target>` instead of
`--source-url`. The script writes:

```text
targets/<project>/
scratch/<project>-engagement/
appsec-review-process/runs/<run_id>/inputs/artifact-manifest.json
```

Use this normalized manifest for LLM lanes so exact source review and deterministic artifacts are
both available under repo-local paths.

## Authoritative Native Test And Fix Retest

For C/C++ verification and remediation, use the same Docker/native image and compile database
environment that produced the engagement evidence. Prefer WSL + Docker for large targets, then sync
the resulting `targets/` and `scratch/` artifacts back into this repo with
`scripts/sync-wsl-engagement-to-repo.sh`.

From Windows, invoke the native image through `images/audit-native/run.ps1` instead of compiling
with a host compiler:

```powershell
.\images\audit-native\run.ps1 `
  <repo-root> `
  - `
  <scratch-dir> `
  -- bash -lc '<clang/llvm/test command>'
```

Host compiler runs such as MinGW/MSVC/ad hoc Clang are useful smoke checks, but they are
non-authoritative. Do not mark a native finding verified, refuted, fixed, or `verified-locally`
based only on host-compiler evidence.

## Run A Lane

Start:

```bash
python3 appsec-review-process/run_process.py --run-id <run_id> --process <process>
```

Create a handoff prompt:

```bash
python3 appsec-review-process/create_handoff.py \
  --run-id <run_id> \
  --process <process> \
  --budget probe
```

Create a new task with the generated handoff. It includes:

- `templates/task-handoff.md`
- the lane `prompt.md`
- the lane `config.md`
- relevant subprompt, if any
- artifact manifest

When the lane finishes successfully:

```bash
python3 appsec-review-process/run_process.py --run-id <run_id> --process <process> --mark-ok --message "<short result>"
```

Then validate the lane output shape:

```bash
python3 appsec-review-process/validate_lane_output.py \
  --run-id <run_id> \
  --process <process>
```

When it fails:

```bash
python3 appsec-review-process/run_process.py --run-id <run_id> --process <process> --fail-immediately --message "<why>"
```

## Resume After Crash

Inspect:

```bash
cat appsec-review-process/runs/<run_id>/run-status.md
```

Then run the recorded `rerun_command`.

## Recommended First Full Sequence

For a large game-code repo:

1. `00-intake-recovery`
2. `02-evidence-pregather`
3. `01-component-characterization`
4. `03-threat-model-dfd-stride`
5. `04-asvs-masvs`
6. `05-native-memory`
7. `06-cve-reachability`
8. `07-red-team-adversarial`
9. `08-blue-team-refutation`
10. `09-independent-verification`
11. `11-remediation-proposal` for verified findings where the user wants a proposed fix and retest
12. `10-synthesis-report`

Run `05` and `06` in parallel only after component characterization exists.

## Evidence Job Commands

Bash/WSL/Linux:

```bash
bash pipeline/engagement_job.sh \
  --project <project> \
  --target <target_path> \
  --compile-db <compile_commands.json> \
  --out <scratch/project-engagement> \
  --msvc -
```

Windows PowerShell:

```powershell
.\pipeline\engagement_job.ps1 `
  -Project <project> `
  -Target <target_path> `
  -CompileDb <compile_commands.json> `
  -Out <scratch\project-engagement> `
  -StaticRunner powershell
```

For bounded plumbing tests, add `-StaticSteps cloc`. For a full broad static pass, omit it.

## Composable Pregather Jobs

The registry under `appsec-review-process/registry/job-templates/` defines bounded pregather jobs
that can be rendered into future handoffs once `create_job_handoff.py` exists. Current job
templates include:

- `02-dev-project-discovery`
- `02-devops-project-discovery`
- `02-sre-operations-topology`
- `02-doc-intelligence-ingest`
- `02-api-collection-intelligence-ingest`
- `02-test-intelligence-ingest`
- `02-standards-source-ingest`
- `02-binary-intelligence-ingest`

Until job rendering is automated, use these records as the source of truth for persona, role,
domain, tooling-profile, output-contract, required inputs, and output files. Binary intelligence
jobs should use `audit-binary-analysis:local` through `images/audit-buildenv-common/run.*`, keep
targets mounted read-only, and write derived evidence under `scratch/<project>-engagement/binary-intel`.
Static binary analysis is allowed by default; runtime execution, debugger attach, Frida
instrumentation, and networked vulnerability database updates require explicit authorization.

## EASTL Windows Validation Baseline

The Windows PowerShell path was validated with:

```powershell
.\pipeline\engagement_job.ps1 `
  -Project eastl `
  -Target '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl' `
  -CompileDb '\\wsl.localhost\Ubuntu-24.04\home\wsollers\targets\eastl\build\compile_commands.json' `
  -Out scratch\eastl-windows-codeql `
  -StaticRunner powershell `
  -StaticSteps cloc
```

CSA/CTU was then run through `images/audit-native/run.ps1` against the same normalized scratch and
the LLM package was regenerated. See:

```text
scratch/eastl-windows-codeql/job-status.md
scratch/eastl-windows-codeql/llm/ENGAGEMENT_LLM_INPUT.md
```

## EASTL WSL Sync Example

After a WSL EASTL run such as `~/scratch/eastl-engagement`, normalize it into the repo with:

```bash
scripts/sync-wsl-engagement-to-repo.sh \
  --project eastl \
  --source-url https://github.com/electronicarts/EASTL.git \
  --source-ref master \
  --engagement-dir ~/scratch/eastl-engagement \
  --run-id <run_id> \
  --business-goal "Probe EASTL before running the large game repo."
```

That leaves prompt lanes pointed at `targets/eastl` and `scratch/eastl-engagement` instead of a
WSL UNC path.
