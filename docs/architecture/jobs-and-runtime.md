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
    job_0001_nvd_sync/
```

Stable hierarchy is `job -> step -> task`. A job gets a numbered package. Add numbered step or task
modules only when the work actually has independently validated or dispatchable units; do not make
empty structural classes.

Configuration uses nested stable ids:

```toml
[jobs.job_0001]
name = "nvd_sync"

[jobs.job_0001.schedule]
enabled = true
cron = "0 0 * * *"
timezone = "UTC"
```

Future step/task overrides use
`[jobs.job_####.steps.step_###.tasks.task_####]`. Slugs remain display metadata rather than part of
the stable configuration key.

## NVD synchronization

`job_0001` is a standalone, network-enabled reference publisher. It bootstraps from the official
NVD CVE 2.0 yearly feeds and then consumes bounded CVE API last-modified windows. Raw source bytes
and a compact CVE metadata JSONL projection are stored as content-addressed gzip blobs. An immutable
manifest links each snapshot to its parent; `current.json` advances only after complete validation.

The schedule declaration is midnight UTC. A host scheduler invokes the same
manual entry point with a different trigger:

```powershell
python -m appsec_review run job_0001 --trigger manual
python -m appsec_review run job_0001 --trigger schedule
```

The repository records the schedule and command but does not install an operating-system service.
Deployment will bind that declaration to the selected scheduler. The job uses a kernel lock, so a
manual invocation and scheduled invocation cannot publish concurrently.
