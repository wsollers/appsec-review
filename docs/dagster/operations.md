# Phase 1 operations

Phase 1 implements deterministic engagement intake and a validated handoff to pregather. Its
acceptance (A01–A16, 2026-09-19) is recorded in run `20260919T104300Z-ba7b4c`'s acceptance report.
Partition discovery, specialist collection and characterization remain planned graph nodes;
no full review, target build, scanner, network probe or LLM is dispatched by this qualification.

## Normal execution: submit to Dagster

Follow [Dagster launching](dagster-launching.md) to create and stage a run on the POSIX host (Linux, or
WSL on Windows; ADR-0011) and execute:

```bash
PY=~/.venvs/appsec-review-dagster/bin/python
$PY -B appsec-review-process/launch_job.py --run-id <run_id> --wait
```

The launcher only submits and monitors. Its default [engagement workflow](dagster-workflow.md)
adds queued engagement concurrency and parallel preparation after intake. Dagster owns transitions.
`review_cli.py intake` uses the smaller intake-only service job; use `launch_job.py --job phase1_intake`
to select it explicitly.

## Explicit host adapter diagnostics

```bash
$PY -B appsec-review-process/run_process.py --start
$PY -B appsec-review-process/stage_artifacts.py --run-id <run_id> --project freeciv21 --target targets/freeciv21 --business-goal "Bounded intake" --platform Linux --platform Windows
$PY -B appsec-review-process/phase1.py intake --run-id <run_id>
$PY -B appsec-review-process/phase1.py status --run-id <run_id>
$PY -B appsec-review-process/create_handoff.py --run-id <run_id> --process 02-evidence-pregather --budget probe
```

Add repeated `--include`, `--exclude` and `--permission` options when staging. The default scope
is every non-`.git` file and default permission is `read-source`. Goal, platforms, budget,
environment and granted permissions are fingerprinted. Restaging preserves run history and
invalidates derived references when inputs change. Missing scanner output is expected initially;
`phase1.py validate-pregather --run-id <run_id>` requires the complete supplied evidence package.
A compile database is conditional on native evidence collection, not intake readiness.

The trusted worker hashes all files (including dirty, untracked and ignored inputs), parses static
markers, and reads Git revision/index metadata without invoking target hooks or clean filters.
It never imports target Python or executes target scripts. Source and output are checked before
publication. Per-snapshot bounds are 100,000 files, 4 GiB and 120 seconds; work has a 120-second
limit. Symlinks are recorded without following; Linux reparse points unavailable on Windows are
fingerprinted as raw link data and reported as scope caveats. Keep the source quiescent: boundary
checks detect observed changes, but cannot detect a transient edit that is reverted between checks.

## Service and UI submission

```bash
python3 orchestrator/dagster/setup.py
docker compose -f orchestrator/dagster/compose.yaml up -d --build
orchestrator/dagster/code-location.sh start      # separate terminal
orchestrator/dagster/code-location.sh reload     # after every code-location (re)start
docker compose -f orchestrator/dagster/compose.yaml ps
$PY -B appsec-review-process/run_process.py --start
$PY -B appsec-review-process/stage_artifacts.py --run-id <run_id> --project freeciv21 --target targets/freeciv21 --business-goal "Bounded intake" --platform Linux --platform Windows
```

Prefer the host launcher above, which supplies the queue tag automatically. To submit in the UI,
open http://127.0.0.1:3000, select `engagement_workflow`, and use:

```yaml
resources:
  workflow_settings:
    config:
      engagement_run_id: <run_id>
      force: false
```

Add the run tag `engagement_run_id: <run_id>` with the same ID. The workflow rejects a
missing or mismatched tag. Its graph is configuration -> atomic intake -> three parallel
preparation branches -> validated final join; see the [workflow diagram](dagster-workflow.mmd).
Work metadata points to distinct stdout/stderr files. Dagster execution IDs are recorded in
attempt and workflow state. Each locked work unit runs in one process; independent branches use
the multiprocessing executor. The retained `phase1_intake` job instead uses `resources.session`
and its four config/pre/work/post ops run in process under one intake lock. Since ADR-0011 ops run as host
processes under the operator's account, so source is no longer protected by read-only container
mounts: it is protected by what the workers do (the trusted intake worker hashes and parses files
and never executes target code; anything that runs target code must go through the pinned-container
adapter, B13). No container has a Docker socket or host credentials mounted. The intake worker
subprocess receives an allow-listed environment (`PATH` and locale only), not the service secrets
the code location itself holds.
This is a code-defined visual graph, not a drag-and-drop editor.

```bash
docker compose -f orchestrator/dagster/compose.yaml stop
docker compose -f orchestrator/dagster/compose.yaml up -d
docker compose -f orchestrator/dagster/compose.yaml restart
```

Never use `down --volumes` for engagement start-over. PostgreSQL and compute logs have dedicated
persistent volumes. Rotation is 10 MiB times three files per service; grace period is 30 seconds.
This project only starts, stops and reports on its own Compose project (`appsec-review`); other
projects' containers on the same Docker engine are outside its scope and are never inspected. The webserver (3000) and
PostgreSQL (`${APPSEC_PG_PORT:-55432}`, for the host code location) are published on loopback
only; the host code location listens on port 4000 (see ADR-0011's addendum for its exposure).
Stopping the containers does not stop the code location: stop it with Ctrl+C in its terminal. Dagster/Python dependencies and base images are pinned; Debian package versions are
recorded by qualification. A changed runtime contract invalidates accepted intake reuse.

## Ownership, reuse and recovery

Authoritative paths are `appsec-review-process/runs/<run_id>/data/`. Each work attempt has its
own evidence, extraction, build, output, validation and log directories. Successful publication
writes an atomic `accepted.json` pointer after hashes, semantics and required state are durable.
Prior attempt bytes are never moved or overwritten. A forced rerun uses `--force`; a clean start
uses a new run ID. Identical accepted inputs are hash/contract checked and reused without work.
A failed newer required attempt never silently falls back to an older success.

Each run is bound to the Windows or Linux executor that staged it. Do not concurrently access
one run through Windows and Docker's Linux filesystem locks. Create a new run for a different
platform and import evidence explicitly. Job locks are kernel-held, fail fast on duplicate
execution, and release when their owner exits. Never delete a lock file or use a time-based lease
steal. On restart, acquiring the released lock marks interrupted attempts FAILED before creating
a new attempt. Unfinished attempts cannot be cache hits.

For workflow jobs, inspect the Dagster run URL, `review_cli.py status`,
`data/workflows/engagement/status.json`, and the relevant attempt's `status.json` and `logs/stderr.log`.
Reconnect to a still-running submission with its `--launch-id`. After correcting a failed job,
submit a new launch from the host:

```bash
$PY -B appsec-review-process/launch_job.py --run-id <run_id> --wait
```

The workflow revalidates intake and reuses unchanged successful branches. `run-status.json` and
`run-status.md` retain the intake/lane view; they do not establish whole-workflow success.
Direct `phase1.py intake` resume commands are for explicit adapter diagnostics, not normal
workflow recovery. Cancellation maps to FAILED with a cancellation cause; absent
prerequisites map to BLOCKED. READY/RUNNING are transient run states. An accepted intake leaves
the whole engagement READY at pregather; it does not mark the full engagement OK. Missing required
or enabled optional results block consumers. Only explicitly permitted skip reasons satisfy edges.
The intake retry policy is one execution attempt per invocation: no blind automatic retry. An
operator resume creates another auditable attempt after diagnosing transient infrastructure loss.

Disk, permission or diagnostic-write failures fail closed and emit `EMERGENCY_EVIDENCE_FAILURE`
to stderr. If storage cannot record status, the diagnostic is the only immediate evidence; once
storage returns, resume under the lock to reconcile the interrupted attempt. Windows Job Objects
and the POSIX owner-pipe watchdog terminate child trees on timeout, cancellation and worker loss.
Raw logs remain ignored locally. Command records redact credential flags and URL user-info.

## Legacy compatibility

Populated legacy runs are not converted in place. Stage into a new run with:

```bash
$PY -B appsec-review-process/stage_artifacts.py --run-id <new_run_id> --project <project> --target <target> --business-goal "Recover legacy evidence" --platform <platform> --engagement-output scratch/<project>-engagement --import-legacy
```

This copies into a unique run-owned `data/imports/` directory and records origin plus every file
hash. It rejects links and detects changing import sources. Nothing in old scratch is moved or
deleted. Compatibility CLI/status/handoff/validation interfaces route orchestrated manifests to
the adapter. Manual status overrides and unwired downstream dispatch are rejected on new runs.
Legacy lane dispatch remains available only on legacy manifests.

The Bash and PowerShell evidence pipelines use the common Python separate-stream step runner.
With `--run-id/--attempt-id` (PowerShell `-RunId/-AttemptId`), their output path is checked by
the same adapter and dispatch is BLOCKED before writes because evidence assembly is still planned.
Full scanner dispatch and its contracts are downstream work, not Phase 1's qualification. Legacy direct scratch invocations are explicitly legacy examples, not a new-run
cache or an accepted-input discovery mechanism.

## Qualification

```bash
$PY -B appsec-review-process/qualify_phase1.py --run-id <qualification_run_id>
```

Run it on the host with the stack and the host code location up (`code-location.sh start`, then
`reload`) and the target checkout present. The target defaults to the `hello-autotools` fixture
(`fixtures/populate-targets.sh`); pass `--target <path> --project <name> [--platform ...]` for
another. Since ADR-0011 the Linux test pass and the live-Dagster checks (`qualify_dagster.py`) run
through `orchestrator/dagster/code-location.sh run`, i.e. in the same environment, instance and
run root as the jobs, instead of `docker compose exec` into the retired code-server container.

The command records argv, exit codes, hashes, tested code identity, limits, gate results and resume
commands under the run's `data/acceptance/`.

Gate A01 also needs `data/acceptance/prompt-vetting.json` on the qualification run, recording a
review of `phase-1-implementation-prompt.md` at its **current** SHA-256. The hash binds a review to
the exact text reviewed, so any edit to the spec (even a moved link) invalidates it. After a
maintenance edit, carry the review forward with `appsec-review-process/attest_prompt.py`: it shows the
diff since the reviewed revision and writes the new record only with `--approve`, a named
`--approved-by` and a `--classification` of why the diff changes no requirement. A substantive
change to the spec needs a real re-review instead. It performs bounded tests and Freeciv21 intake only.
Use `phase1.py graph --check` to verify `docs/design-parity/job-graph.mmd` against `job-graph.json`.
