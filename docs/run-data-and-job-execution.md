# Run-owned data and reliable job execution

Status: implemented for Phase 1 intake; downstream lane/scanner migration remains explicit.
See [operations](phase-1-operations.md) for supported execution and recovery boundaries.
The [Phase 1 implementation prompt](../appsec-review-process/phase-1-implementation-prompt.md)
defines implementation and acceptance. This supersedes shared project scratch as the authoritative
location for new orchestrated-run data; existing runs remain readable without destructive migration.

## Ownership and layout

```text
appsec-review-process/runs/<run_id>/
  inputs/artifact-manifest.json
  run-status.json
  run-status.md
  events.jsonl
  handoffs/
  processes/
  outputs/                         # compatibility summaries, referencing accepted attempts
  data/
    source/                        # snapshot or pinned source identity manifest
    imports/<import_id>/            # explicit immutable imports with lineage and hashes
    jobs/<job_id>/<scope_id>/
      accepted.json                # atomic pointer plus validated artifact hashes
      attempts/<attempt_id>/
        inputs.json
        evidence/
        extracted/
        build/
        outputs/
        validation/
        logs/stdout.log
        logs/stderr.log
        logs/events.jsonl
        status.json
    acceptance/                    # prompt review and Phase 1 acceptance evidence
```

All generated engagement data belong to their run. Large scanner databases, bitcode, extraction
outputs and build products are included. Tool images and immutable download caches may be shared
only with pinned identity; mutable build/evidence state cannot be shared across runs. Run records
stay ignored by Git. Dagster instance metadata uses persistent service storage separately and
links execution IDs to engagement run IDs. It is not the only copy of evidence or recovery state.

## Repeatability

Idempotent does not mean stateless or overwriting the previous directory. A job invocation resolves
the stable run/job/scope identity and an input fingerprint covering source state, upstream hashes,
configuration, prompts/composition, schema and executable/image versions. An existing accepted
attempt may be reused only if its artifacts still validate. Record reuse explicitly. Changed inputs
or an explicit forced rerun create another attempt and invalidate affected downstream acceptance.
Never select an old successful result silently after a newer required attempt fails.

New runs begin with empty data roots. Importing old evidence is explicit, hash-checked and recorded;
do not scan `scratch/` for the newest matching project output. Preserve earlier attempts and use
atomic writes, locks, unique attempt IDs and validated publication. Restart resumes recorded state;
it does not reset history. Starting over means a new run ID, not deleting shared directories.

## Validation, errors and logging

Each job executes pre-validation -> bounded work -> post-validation -> publish accepted artifacts.
Failed checks block dependent work. Validation jobs have the same logging/error envelope, with
nonrecursive bootstrap validation. Inputs and paths are validated before side effects. Required
inputs cannot be satisfied by unexplained skips. Keep source scope distinct from Dagster partitions.

Persist separate stdout/stderr and structured UTC events per attempt, including validation jobs,
and expose correlations in Dagster. Streams must drain concurrently. Retain partial outputs on
failure. Handle exceptions, process exits/signals, timeouts, cancellations, worker loss, corrupted
state, disk errors and log-write errors explicitly. Fail closed if evidence cannot be recorded.
Use emergency stderr diagnostics if durable storage fails; do not fabricate a persisted status.
Map execution states explicitly to existing terminal statuses, retain causes and resume commands,
and bound retries. Redact secrets in command records and UI exports; raw evidence remains local.

The canonical state writer must synchronize CLI, file and Dagster views without allowing independent
writers to race. A green process exit or Dagster step alone does not certify accepted evidence.
