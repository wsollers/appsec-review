# Dev-mode restart (operator view)

ADR-0024. Prod fingerprints are the evidence rule: any change to a job's code, contract or upstream
attempt reruns it and everything after it. That is right for a deliverable and wrong while you edit
and rerun. Dev mode decides from **data**. It is for iteration only: **a dev result is never
evidence**.

## Turning it on

| What | How |
|---|---|
| Mode of the Dagster code location (where the work runs) | start it with `APPSEC_RUN_MODE=dev orchestrator/dagster/code-location.sh`. Unset or `prod` is prod; any other value refuses to start work. |
| Mode of a launch | `launch_job.py --mode dev ...` (default: `$APPSEC_RUN_MODE`, else prod). The run is tagged `appsec/run_mode=dev`, and the item executor refuses a run whose tag and process mode disagree. |
| Preview, no submission | `launch_job.py --run-id R --job full_review --mode dev --explain` |
| Rerun one job regardless | `--force <job-id>` (dev, repeatable). Plain `--force` still reruns everything, as before. |

## What dev decides, per job, in graph order

`--explain` prints one line per job: `REUSE` / `RERUN` / `REWIND`, the cause, and what prod would do
on code alone. For example:

```
RERUN  02-operations-doc-ingest: own static_intelligence_core.py changed; prod would have invalidated because code hash of static_intelligence_core.py changed
REUSE  02-evidence-index: early cutoff: 02-operations-doc-ingest reran with byte-identical output
```

1. Each consumed input artifact gets a **content hash** and a **shape hash**. The shape covers the
   JSON keys and value types, where an array's shape is the set of its element shapes. Values, key
   order and array length do not affect it.
2. All input content unchanged since the job's last accepted run: **REUSE**.
3. Some input content changed but every shape is the same: **RERUN**.
4. An input's shape differs from what the job recorded: **REWIND**. The producer of that input reruns
   first (and, since every job is checked, so does any producer whose own input shape changed). Then
   the pass continues forward. `--explain` names the rewind point. Only item producers rewind: a
   legacy producer's prod fingerprint already covers all its code, so its output is never stale.
5. **Early cutoff:** a rerun that publishes byte-identical output leaves every downstream input
   unchanged, so downstream jobs REUSE.
6. A job's own config, contract, schema, prompt and implementation files count as inputs. Shared
   runtime (`SHARED_RUNTIME`) and other jobs' implementation files do not.

## Which jobs follow these rules

Only jobs that run through the generic item executor (`job_executor.py`, `appsec-review-process/items/`).
Every other (legacy) job keeps its own prod fingerprint **in both modes**. Their inputs pin upstream
attempt ids, so they have no early cutoff. `--explain` predicts them from their recorded code hashes
and upstream reruns ("legacy fingerprint: ..."). Porting a job to the executor is what brings it
under the dev rules. Legacy fingerprints were deliberately not changed: any edit to them would
change prod fingerprints.

## Guard rails

- Every executor receipt carries `mode` and `evidence_grade`. A dev receipt is always `mode: "dev"`,
  `evidence_grade: false`.
- A prod run never reuses a dev-published result. It recomputes: the dev and prod fingerprints differ
  by mode, and the executor also refuses a dev receipt.
- `final_publication.publish` refuses a dev process, and refuses any run with an accepted dev result.
  `launch_job.py --mode dev --job final_publication_gate` is refused. After a dev loop, relaunch in
  prod: the dev results are recomputed.
- Dev never relaxes scanning rules. A tool that did not run, or a partial scan, is a gap and never
  "no findings", in either mode.
