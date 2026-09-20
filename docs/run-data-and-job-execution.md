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

The shared v1.0 terminal boundary is implemented by `worker_result.py` and
`validate_job_output.py`. Validation is read-only and fail-closed: the common envelope must match
the staged input fingerprint; every artifact must be a normalized path beneath its immutable
attempt with a matching hash; registry-required files must be declared; and `SKIPPED` must name a
reason allowed by the exact consumer edge. Opted-in output contracts name exactly one result
artifact and result schema. The validator also enforces required status fields and explicit
Scorecard/discovery semantics, including bounded repository-relative citation freshness,
cross-record IDs, and negative secret-leak checks. It never repairs worker output. Contracts that
opt into the result-schema boundary may also declare a claim class. The three current declarations
limit output to published posture evidence, supplied structure/routing, or supplied project/build
discovery and reject finding, severity, and observed-runtime promotion. Contracts that predate the
optional declarations remain readable. Existing workers retain their
legacy shapes until explicitly migrated and qualified; this contract does not retroactively
certify them.

`publish_job_output.py` consumes that read-only validation result and atomically updates the
accepted pointer only for the newest `CURRENT` envelope. Attempt allocation first writes a
non-current `PENDING` pointer, so invalid, corrupt, stale, canceled, blocked, or failed newer work
cannot fall back to an older accepted result. This boundary is adopted only by
`02-ossf-scorecard`, supplied `02-repository-partition-discovery`, and
`10-critical-findings-sarif`; historical attempts remain untouched. Those three adopted paths also
use the same collision-safe allocator and terminal non-current recorder. Allocation persists
inputs and `RUNNING` status before moving the
`PENDING`/`latest.json` view, recovers an abandoned pending attempt to an immutable `FAILED`
envelope before replacement, and retries bounded UUID collisions. `BLOCKED`, `FAILED`, and
`CANCELED` results are hashed, newest-attempt checked, and recorded without rewriting a durable
candidate envelope that failed validation. For the same three paths, a common coordinator now owns
the per-job lock, reusable admission, interrupted-attempt recovery/allocation, and terminal
exception routing. Preflight blockers, post-allocation work/validation failures, and
`KeyboardInterrupt` become `BLOCKED`, `FAILED`, and `CANCELED` respectively, and the original
exception is re-raised so Dagster failure behavior is unchanged. Execution, timeout, child cleanup,
streams, logs, and payload production otherwise remain worker-local; this is not yet a general
worker controller. Scorecard and the critical-findings SARIF transform are the bounded exceptions:
they use the versioned argv-only
`deterministic_child.py` sub-contract with a fixed executable/prefix, explicit environment,
one-MiB retained limits for each diagnostic stream, timeout/cancellation recording, and complete
Windows Job Object or POSIX process-session cleanup. Repository partition discovery has no child
process and is deliberately not routed through it. No other worker inherits this behavior yet.

The same three paths use common success and reuse transitions. Reuse requires a common accepted
pointer with the expected run, job, input fingerprint and newest-attempt identity, then rechecks
the immutable attempt tree, envelope hash and full output contract. A corrupt matching pointer
fails closed; it is not silently converted into a cache miss. Final `OK`, `OK_WITH_GAPS`, and
edge-authorized `SKIPPED` status, artifact hashes and envelope persistence share one ordered path.
If a worker stops after the `CURRENT` envelope is durable but before `accepted.json` advances from
`PENDING`, the next non-forced invocation validates worker-specific semantics before publishing
that same immutable attempt. It does not allocate a replacement or rerun payload production.
