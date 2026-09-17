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
11. `10-synthesis-report`

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
