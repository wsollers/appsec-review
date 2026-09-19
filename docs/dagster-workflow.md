# Dagster engagement workflow

`launch_job.py` now submits `engagement_workflow` by default. Dagster owns the queue, dependency
graph, multiprocessing, cancellation and run history. Python functions and subprocesses perform
bounded units of work. See the [Mermaid graph](dagster-workflow.mmd) and the machine
[workflow plan](../appsec-review-process/workflow-plan.json).

```powershell
python -B appsec-review-process/launch_job.py --run-id <linux_run_id> --wait
```

Create and stage a Linux-owned run using the [launch instructions](dagster-launching.md). The
launcher adds the matching `engagement_run_id` run tag, which is required by this workflow.
Keep using the returned launch ID to reconnect to the same Dagster run. `--job phase1_intake`
and `review_cli.py intake` retain the smaller intake-only job for diagnostics and compatibility.

## Execution and concurrency

The persistent Dagster queue admits at most **two runs across this deployment** and **one run
per engagement ID**. A duplicate submission waits, then performs validated reuse. Jobs for other
engagements can run concurrently. These limits are configured in
[`dagster.yaml`](../orchestrator/dagster/dagster.yaml), mounted read-only into each service.
The workflow requires its engagement tag to match its config; missing tags fail before work.

The workflow graph runs:

1. `workflow_config`: check staged configuration and reserve a workflow generation.
2. `workflow_intake`: execute the shared intake adapter's pre-validation, Python worker or
   validated reuse, and post-validation in one process. Its OS lock never crosses a process boundary.
3. Three independent preparation ops in separate processes: `scope_check`, `native_plan_check`,
   and `discovery_handoffs`. Each has its own branch lock, immutable attempt, pre/post checks,
   restricted worker environment, configured timeout and separate stdout/stderr.
4. `workflow_publish`: require all three branches, verify their artifacts and upstream generation,
   recheck source/config freshness, then atomically publish the combined result.

The multiprocessing executor permits at most three steps per workflow. Combined with the run
queue, at most six workflow step processes can run at once, plus their bounded Python children
and Dagster service processes. This is a concurrency bound, not a CPU/memory quota. Add dedicated
resource pools and isolated worker images before introducing heavy scanners or target builds.

Scope and native checks derive validated views of accepted intake. Discovery handoffs resolve
configured persona/role/domain/tooling/output contracts and preserve partition-before-specialist
dependencies. They prepare work requests only. Partition discovery, developer/DevOps/SRE review,
scanners and target builds are still planned; this workflow does not execute them or claim findings.

## State and recovery

Each branch owns:

```text
runs/<run_id>/data/jobs/00-workflow-preparation/<branch>/
  job.lock
  latest.json
  accepted.json
  attempts/<attempt_id>/inputs.json, pre.json, output.json, post.json, status.json, logs/
```

Workflow state and publication live under `data/workflows/engagement/`. Every Dagster execution
has its own `attempts/<dagster_run_id>/` configuration and result/failure record. Starting another
workflow invalidates the aggregate acceptance until its final join passes. Failed work never
falls back to an old aggregate result. The intake acceptance remains separate from workflow
acceptance and does not imply that pregather or a full security review has finished.

`python -B appsec-review-process/review_cli.py status --run-id <run_id>` reports workflow state
when one exists, including a branch failure even if intake succeeded. It checks recorded artifact
integrity and upstream acceptance; it does not perform a new source-freshness scan. Execution's
final join does that scan and rechecks the upstream pointer under the publication lock, while
holding the branch locks, so concurrent restaging cannot publish an old generation.

If one branch fails, other independent branches can finish, but the join cannot run. Correct the
cause and make a **new launch** with the same engagement ID. The full graph checks freshness and
reuses unchanged successful branch attempts; only invalid or missing work reruns. Use this path,
or Dagster's full-job reexecution, rather than selecting isolated steps and bypassing generation
setup. `--force` deliberately creates new intake and branch attempts.

Op failures record the workflow failure and propagate to Dagster. Run monitoring detects failed
workers; failure/cancellation sensors reconcile durable Dagster state into workflow state, including
when an op hook could not run. Interrupted branch attempts are marked failed after their OS lock is
released and the next execution acquires it. Sensor reconciliation is eventual, so inspect Dagster
status as well as the local status file after abrupt worker loss. Automatic retries/resumes are
disabled; partial diagnostics and successful sibling attempts remain preserved.

Use the Dagster UI to cancel a queued or running job. A timeout or interruption of the launcher
only stops monitoring; it does not cancel server execution. Reattach with `--launch-id` to inspect
the existing execution. Never delete lock files or reset Dagster volumes to recover an engagement.

These controls use Dagster's documented [run queue and executor concurrency mechanisms](https://docs.dagster.io/guides/operate/managing-concurrency).

## Qualification

```powershell
python -B appsec-review-process/qualify_workflow.py --run-id <qualification_run_id>
```

The qualification uses the actual service API and multiprocessing executor, not
`execute_in_process`. It records queue samples and run timing, checks distinct branch processes
and overlapping attempts, injects a branch write failure, verifies recovery reuses successful
siblings, and runs bounded Freeciv21 preparation. All fixtures and evidence stay under the owning
run's `data/`; the stopped legacy stack is checked for changes.

The 2026-09-19 qualification passed in run `20260919T123919Z-0b9e70`:
[live queue/parallelism/recovery/Freeciv21 report](../appsec-review-process/runs/20260919T123919Z-0b9e70/data/qualification/workflow-11a97950/report.json).
The complete initial suites passed 45 host and 49 Linux tests. The final publication/status
hardening was then covered by seven focused workflow tests on each platform and another actual
service execution/status check. The [verification summary](../appsec-review-process/runs/20260919T123919Z-0b9e70/data/verification/summary.json)
records both tested identities and the follow-up changes. Evidence is ignored local run data.
