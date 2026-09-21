# Submit jobs to Dagster

This is the operator entry point for the current process. Run commands from the repository root
on the host. The launcher connects to the repo-local Dagster service at http://127.0.0.1:3000;
job execution occurs in its Linux code-server. Do not run the host launcher inside the code-server.

The default job is **`engagement_workflow`**: configuration, atomic intake, three parallel
preparation branches, then a validated final join. Dagster allows two runs globally and one per
engagement; up to three preparation steps can run within each workflow.

```mermaid
flowchart LR
  S[Submit from host] --> Q[Dagster queue]
  Q --> C[Resolve configuration]
  C --> I[Intake: pre / Python work or reuse / post]
  I --> A[Scope check]
  I --> B[Native-plan check]
  I --> D[Discovery handoff preparation]
  A --> J[Validate all results and publish]
  B --> J
  D --> J
```

The branches prepare validated views and work requests. They do not execute partition discovery,
specialist reviews, scanners, target builds or LLMs. See [workflow internals and evidence](dagster-workflow.md)
for dependencies, locking and qualification.

## 1. Check the service

```powershell
docker compose -f orchestrator/dagster/compose.yaml ps
```

For initial setup, or to rebuild after dependency/image changes:

```powershell
python orchestrator/dagster/setup.py
docker compose -f orchestrator/dagster/compose.yaml up -d --build
```

The PostgreSQL, code-server, webserver and daemon services should be healthy. An already-running
stack does not need a rebuild for each submission. Preserve its volumes and the stopped legacy stack.

## 2. Create and stage an engagement

Create the run **inside the code-server** so its execution platform and paths are Linux-owned.
This PowerShell example captures the returned engagement ID:

```powershell
$created = docker compose -f orchestrator/dagster/compose.yaml exec -T code-server python -B /opt/process/run_process.py --start | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Run creation failed" }
$runId = $created.run_id

docker compose -f orchestrator/dagster/compose.yaml exec -T code-server python -B /opt/process/stage_artifacts.py --run-id $runId --project freeciv21 --target /targets/freeciv21 --business-goal "Bounded intake and preparation" --platform Linux --platform Windows --budget probe --execution-environment dagster-read-only-linux
if ($LASTEXITCODE -ne 0) { throw "Input staging failed" }
```

For Bash, run the same Docker commands, copy the returned `run_id`, and substitute it for `$runId`
in later examples. `--platform` describes the target platforms; it does not choose the execution OS.
Add repeated `--include`, `--exclude` or `--permission` options when needed. The default permission
is `read-source`; initial intake does not require scanner output or a compile database.

Freeciv21 is already mounted read-only at `/targets/freeciv21`. For another target, first add an
explicit read-only target bind mount to the shared runtime in
[compose.yaml](../../orchestrator/dagster/compose.yaml), apply the Compose change when jobs are idle,
and stage its **container path**. A host path such as `F:\targets\project` is not a container path.
Do not repurpose a Windows-owned run for Dagster; create a Linux-owned run and explicitly import
legacy evidence when needed. See [legacy imports](operations.md#legacy-compatibility).

## 3. Submit the workflow

Submit and wait for the terminal result:

```powershell
python -B appsec-review-process/launch_job.py --run-id $runId --wait
```

Submit and return immediately after Dagster accepts the request:

```powershell
python -B appsec-review-process/launch_job.py --run-id $runId
```

The JSON response includes `launch_id`, `dagster_run_id`, `status` and a browser `url`. Save the
engagement ID and launch ID. A submission response such as `QUEUED` or `STARTED` is not completion.
With `--wait`, `SUCCESS` exits zero and failure/cancellation exits nonzero. The default monitoring
limit is 600 seconds; change it with `--timeout 1200`. A timeout or interrupted terminal stops
monitoring but leaves server execution running.

| Job | How to select it | Scope |
|---|---|---|
| `engagement_workflow` | Default, or `--job engagement_workflow` | Intake plus parallel preparation and final join |
| `phase1_intake` | `--job phase1_intake` | Intake only, with four visible config/pre/work/post ops |
| `build_discovery` | `--job build_discovery` | Intake and cited discovery of build requirements/commands; no build execution |
| `build_execution` | `--job build_execution` | One sandboxed configure step after accepted build discovery; records compile database evidence when produced |
| `evidence_index` | `--job evidence_index` | Accepted searchable source/discovery evidence for LLM retrieval |
| `critical_findings_sarif` | `--job critical_findings_sarif` | Strict run-owned conversion of independently verified finding Markdown to accepted SARIF 2.1.0 |
| `full_review` | `--job full_review` | All lifecycle/registry jobs; currently stops at the first unimplemented worker |

`python -B appsec-review-process/review_cli.py intake --run-id $runId` selects the intake-only
job and waits. Direct `phase1.py intake` remains an explicit host adapter diagnostic, not the normal
workflow submission path. The launcher accepts the registered jobs listed above; it does not accept
arbitrary scripts. See [build discovery and full-graph readiness](../build-discovery/build-discovery-integration.md)
before selecting `full_review`.

## 4. Check status and results

```powershell
python -B appsec-review-process/review_cli.py status --run-id $runId
```

For an engagement with workflow state, this reports workflow status and the Dagster URL. Non-OK
workflow states return nonzero. It validates recorded artifact integrity and upstream acceptance,
but does not perform a new source-freshness scan. Before workflow state exists, or for intake-only
runs, use the launch response/reattachment and Dagster UI to inspect queued or active execution.

| Identifier | Meaning |
|---|---|
| `run_id` / engagement ID | The staged target, scope and run-owned data |
| `launch_id` | One submission request; use it to reconnect without submitting again |
| `dagster_run_id` | The server execution shown in the Dagster UI |
| `attempt_id` | One immutable intake or branch work attempt; reuse can preserve it across launches |

All engagement files live under `appsec-review-process/runs/<run_id>/`:

| Relative path | Contents |
|---|---|
| `inputs/artifact-manifest.json` | Staged scope, permissions and source configuration |
| `data/orchestration/launches/<launch_id>/request.json` | Submission state, server ID, URL and reconnect argv |
| `data/workflows/engagement/status.json` | Current workflow generation and outcome |
| `data/workflows/engagement/accepted.json` | Aggregate acceptance after the final join |
| `data/jobs/00-intake/whole/attempts/<attempt_id>/` | Intake evidence, validation and separate stdout/stderr |
| `data/jobs/00-workflow-preparation/<branch>/attempts/<attempt_id>/` | Branch inputs, result, validation and separate stdout/stderr |
| `data/jobs/00-workflow-preparation/build_execution/attempts/<attempt_id>/build/discovery/compile_commands.json` | Compile database from `build_execution`, only when the configure step produced one |
| `data/jobs/02-evidence-index/whole/accepted.json` | Accepted evidence index pointer for retrieval |
| `data/jobs/10-critical-findings-sarif/whole/accepted.json` | Accepted SARIF pointer; immutable output is under its referenced attempt |

`run-status.json` retains the intake/lane view; it is not proof that the whole workflow succeeded.
Workflow `OK` means bounded intake and preparation passed, not that a full security review finished.

## 4.1 Job requirements and boundaries

Every Dagster job requires:

- a staged run manifest under `appsec-review-process/runs/<run_id>/inputs/artifact-manifest.json`
- an execution platform matching the run owner; create Linux-owned runs in the code-server for
  Dagster work
- a matching `engagement_run_id` tag for service submissions
- immutable attempt output under the run's `data/jobs/.../attempts/<attempt_id>/`
- validation through the job's declared output contract before publication

Do not use old `scratch/<project>-engagement/` directories as implicit inputs for new workflows.
Import legacy evidence explicitly into a new run if it is needed. Do not delete locks, reset Dagster
volumes, or mark files OK by hand to recover a job.

Current job boundaries matter:

- `engagement_workflow` performs intake and preparation only. It does not run target builds,
  scanners, partition discovery, specialist review lanes or LLMs.
- `build_discovery` reads accepted intake evidence and cites build instructions; it does not run
  package managers, target scripts or compilers.
- `build_execution` depends on an accepted `build_discovery` result and runs one restricted CMake
  configure step inside the selected build environment. Its compile database, when present, lives
  at `data/jobs/00-workflow-preparation/build_execution/attempts/<attempt_id>/build/discovery/compile_commands.json`.
- `full_review` exposes the lifecycle graph for dependency qualification. Many workers are
  intentionally blocked until implemented and qualified.

## 4.2 Personas and registry jobs

Dagster worker configuration is registry-driven. Registry jobs compose a persona, role, domain,
tooling profile and output contract. Use these references before adding or dispatching work:

- [persona catalog](../personas-and-registry/persona-catalog.md) for human-readable reviewer stances
- [registry README](../../appsec-review-process/registry/README.md) for record types and dispatch rules
- `appsec-review-process/registry/personas/` for machine persona records
- `appsec-review-process/registry/job-templates/` for registered job compositions
- [intelligence sources and jobs](../evidence/intelligence-sources-and-jobs.md) for doc/API/test/binary
  intelligence ingestion

Personas are a review stance and scope contract, not evidence by themselves. A completed persona
job still needs cited artifacts, a valid status, and any downstream verification required by the
lane.

## 5. Reconnect, recover or cancel

Reconnect to an existing launch without creating another execution:

```powershell
python -B appsec-review-process/launch_job.py --run-id $runId --launch-id <launch_id> --wait
```

Reattachment preserves the original job selection, including older intake-only requests. It does
not retry a failed or canceled terminal job. After correcting a failure, submit a **new launch**:

```powershell
python -B appsec-review-process/launch_job.py --run-id $runId --wait
```

The workflow rechecks freshness, reuses unchanged successful attempts, and reruns missing or invalid
work. Independent branches may finish after a sibling fails; the join remains blocked until every
required branch passes. Automatic retries are disabled. To deliberately replace otherwise reusable
work, append `--force`. Repeat `--force` when reconnecting to a launch originally created with it.
For a clean engagement, create and stage a new run ID.

Cancel queued or running execution in the Dagster UI using the returned run URL. Canceling a queued
duplicate does not cancel the active engagement. Failure/cancellation sensors reconcile workflow
state after worker loss; this is eventual, so consult Dagster as well as local status after a crash.

If a submission response was lost, reconnect using the recorded launch ID. The client searches
Dagster history for that request. If its outcome remains uncertain, inspect history before making
another launch; the client does not blindly resubmit. Never delete locks or reset volumes to recover.

## Submit through the Dagster UI

Open http://127.0.0.1:3000, select **`engagement_workflow`**, and use this run configuration:

```yaml
resources:
  workflow_settings:
    config:
      engagement_run_id: <linux_run_id>
      force: false
```

Add a run tag named **`engagement_run_id`** with the same ID. This tag enforces per-engagement
queue serialization; a missing or mismatched tag fails before work. The engagement must already
be created and staged. For `phase1_intake`, use `session` instead of `workflow_settings` and keep
the matching tag. Prefer a new full workflow launch for recovery, which validates and reuses work;
do not bypass generation setup with isolated step selection.

## Further reading

For searchable source and accepted discovery evidence, submit:

```sh
python -B appsec-review-process/launch_job.py --run-id <linux_run_id> --job evidence_index --wait
```

This job prepares/reuses intake and build discovery automatically. Query via the
[CLI or read-only MCP server](../../appsec-review-process/tooling/llm-retrieval-addendum.md).
The UI uses the same `workflow_settings` configuration and engagement tag shown above.
Its independent acceptance lives under `data/jobs/02-evidence-index/whole/`, not the preparation
workflow's aggregate status. After abrupt worker loss, consult Dagster and retry the job; the
worker preserves the interrupted attempt and writes a recovery receipt before allocating another.

For explicitly authorized published OpenSSF Scorecard evidence, stage
`inputs/ossf-scorecard-projects.json`, include `network:api.scorecard.dev` in the run permissions,
and submit:

```sh
python -B appsec-review-process/launch_job.py --run-id <linux_run_id> --job ossf_scorecard --wait
```

The accepted pointer is under `data/jobs/02-ossf-scorecard/whole/`. This fetches published JSON2;
it does not run the Scorecard CLI against the repository. See
[the job contract](../evidence/ossf-scorecard-job.md).

- [Workflow architecture, parallelism and qualification](dagster-workflow.md)
- [Runtime limits, imports and adapter diagnostics](operations.md)
- [Service lifecycle and preserved smoke job](../../orchestrator/dagster/README.md)

## Historical intake-only launcher verification

Verified on 2026-09-19 in run `20260919T113744Z-fe2cdc`: 40 host tests and 44 Linux tests
passed, including Dagster config/work/post failure transitions. Actual service API submissions
qualified Freeciv21 intake, reattachment to the same Dagster run, a second run reusing immutable
accepted output, and missing-permission failure before work. The live GraphQL graph matched all
three dependency edges. The stopped legacy stack was unchanged.

See [service qualification evidence](../../appsec-review-process/runs/20260919T113744Z-fe2cdc/data/verification/launcher-qualification.json)
for exact tested file hashes, run IDs and command results, and
[verification summary](../../appsec-review-process/runs/20260919T113744Z-fe2cdc/data/verification/summary.json)
for test and documentation hashes. These are ignored local evidence files. Initial interrupted
test batches are preserved separately; the passing Linux result is `tests-linux-final`.
