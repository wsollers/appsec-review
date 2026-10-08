# Jobs and runtime

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
`fetch`, `process`, and `build` tasks.

## NVD synchronization

`job_third_party_data_sync.nvd_sync` is a standalone, network-enabled reference publisher. It bootstraps from the official
NVD CVE 2.0 yearly feeds and then consumes bounded CVE API last-modified windows. Raw source bytes
and a compact CVE metadata JSONL projection are stored as content-addressed gzip blobs. An immutable
manifest links each snapshot to its parent; `current.json` advances only after complete validation.

The schedule declaration is midnight UTC. A host scheduler invokes the same
manual entry point with a different trigger:

```powershell
python -m appsec_review run job_third_party_data_sync --trigger manual
python -m appsec_review run job_third_party_data_sync --trigger schedule
```

The repository records the schedule and command but does not install an operating-system service.
Deployment will bind that declaration to the selected scheduler. The job uses a kernel lock, so a
manual invocation and scheduled invocation cannot publish concurrently.
