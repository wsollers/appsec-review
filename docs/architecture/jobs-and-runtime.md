# Jobs and runtime

## Wave 1 resumability

An ordered application graph sits above the existing semantic `JobRunner`. Each successful attempt
publishes `handoff.json` inside its immutable attempt directory and updates the job's small
`latest.json` pointer only after output validation. The handoff binds result artifacts, upstream
handoff hashes, resolved and job-local configuration hashes, target fingerprint, implementation,
schema, validator, tool identity, timestamps, and resolving paths.

The generic resume planner walks jobs in graph order. Once a job cannot be reused, it schedules that
job and invalidates the transitive downstream closure. It never treats time as proof of freshness.
The graph holds a kernel-backed per-run claim lock across planning and execution so two resume
processes cannot claim the same run concurrently.

Wave 1 exercises this mechanism with `job_review_intake` followed by `job_target_catalog`. Both are
registered through the same semantic registry used by the generic Dagster adapter. Later review jobs
extend the ordered graph without changing the accepted-handoff format.

Each orchestrated graph launch also publishes an immutable run-level orchestration receipt. This
keeps the current Dagster run linked to the application run even when every job is reused and the
accepted job receipts correctly remain linked to their original launch.

## Global events

Every job and unit event is mirrored through one process-safe writer to
`runs/<run-id>/data/logs/pipeline.jsonl`, while attempt-local event logs remain available. Sequence
allocation and append occur under the same kernel lock. Records have bounded/redacted details, and a
torn final line is truncated under that lock before the next append, preserving a readable total
order after a writer crash.

The runtime composes each job from one handler and explicit input/output validator lists. Specific
jobs do not subclass the runtime and cannot replace its attempt, status, logging, or publication
lifecycle.

```text
src/appsec_review/
  runtime/       composed Job, registry, runner and context
  config/        typed TOML loading
  observability/ structured execution events
  storage/       atomic writes, run allocation and locks
  jobs/
    job_third_party_data_sync/
      steps/
        nvd_sync/
```

Stable hierarchy is `job -> step -> task`. Every identifier is a descriptive lowercase snake-case
name. Add step or task modules only when the work actually has independently validated or
dispatchable units; do not make empty structural classes.

Configuration uses nested stable ids:

```toml
[jobs.job_third_party_data_sync]
name = "third_party_data_sync"

[jobs.job_third_party_data_sync.schedule]
enabled = true
cron = "0 0 * * *"
timezone = "UTC"

[jobs.job_third_party_data_sync.steps.nvd_sync.tasks.fetch]
workers = 1
```

Step/task overrides use
`[jobs.<job_name>.steps.<step_name>.tasks.<task_name>]`; for example, the NVD step declares
`fetch`, `process`, and `publish` tasks.

## NVD synchronization

`job_third_party_data_sync.nvd_sync` is a standalone, network-enabled reference publisher. It bootstraps from the official
NVD CVE 2.0 yearly feeds and then consumes bounded CVE API last-modified windows. Raw source bytes
and a compact CVE metadata JSONL projection are stored as content-addressed gzip blobs. An immutable
manifest links each snapshot to its parent; `current.json` advances only after complete validation.

The schedule declaration is midnight UTC. Direct CLI invocations enter `JobRunner` with an explicit
trigger:

```powershell
python -m appsec_review run job_third_party_data_sync --trigger manual
python -m appsec_review run job_third_party_data_sync --trigger schedule
```

The Dagster adapter under `src/appsec_review/orchestration/dagster/` enumerates `JobRegistry` and
generates one single-op Dagster job for every registered semantic job. It also generates schedule
definitions from the TOML declarations; cron expressions, time zones, and enabled state are never
duplicated in Python. Both console launches and daemon schedule ticks call the generated dispatch op,
which builds the registered job and hands it to `JobRunner`. The runner therefore retains run
allocation, immutable configuration binding, validation, locking, events, evidence paths, and status
publication. Dagster owns only scheduling, launch visibility, and its own orchestration history.

The adapter intentionally exposes one Dagster execution op. The application runtime currently owns
the only safe whole-job transaction boundary; representing application tasks as independently
executable Dagster ops would duplicate lifecycle and dependency ownership. The dispatch op instead
publishes structured Dagster metadata for every application unit receipt, step and unit status,
published snapshot identity, count, gap, and resolving run-owned receipt path.

Dagster run UUIDs and application run ids are separate identities. The adapter passes the Dagster
UUID into `JobRunner` as orchestration correlation, and the runner records it in terminal
`status.json`. After a successful return, the adapter adds the application run and attempt ids to
the Dagster run tags. This creates a checked bidirectional trace without allowing Dagster to write
application receipts or allocate application ids.

Deployment layout and exact operator commands are documented in
[`deploy/dagster/README.md`](../../deploy/dagster/README.md). The job uses a kernel lock, so a manual
invocation and scheduled invocation cannot publish concurrently.
