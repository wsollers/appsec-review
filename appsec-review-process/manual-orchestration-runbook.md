# Manual Orchestration Runbook

This runbook describes how to operate the prompt process before a full orchestrator exists.

## Start A Run

```bash
python3 appsec-review-process/run_process.py --start
```

Record the returned `run_id`.

## Stage Inputs

Create or update:

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

Create a new task with:

- `templates/task-handoff.md`
- the lane `prompt.md`
- the lane `config.md`
- relevant subprompt, if any
- artifact manifest

When the lane finishes successfully:

```bash
python3 appsec-review-process/run_process.py --run-id <run_id> --process <process> --mark-ok --message "<short result>"
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

