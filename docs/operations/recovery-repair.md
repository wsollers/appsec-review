# Recovery and repair admission

Recovery is **fail -> inspect bounded evidence -> reproduce in a focused unit test -> repair ->
build a release -> inspect admission -> restart**. Inspection does not run tests, captured
commands, workers, Docker builds, or models.

## Release and deployment identity

`release-dependencies.json` declares job packages, shared application code and package resources,
container catalogs/query packs/adapters, validators/schema assets, bundled reference fixtures,
runtime guidance/rules, dependency locks, the image recipe, and scripts. The release
builder follows static cross-job helper imports as well. It rejects a release lacking shared
code or validator coverage, or an absent explicitly named dependency. At build time:

```sh
python -m appsec_review.runtime.release            # direct (non-Dagster) runs: beside the sources
python -m appsec_review.runtime.release --root /opt/app --verify-assets --exec dagster code-server start ...
                                                   # Dagster code-location start: onto /var/dagster/release
```

This creates byte-deterministic `implementation-release.json`; it is generated, not source. In the
Dagster deployment the code-location's start command runs this builder against the mounted checkout
and then execs the code server; the `test` image stage runs it at build time because it is the one
stage that carries sources. Job handlers never scan or hash installed platform payloads as customer
evidence. They read the bounded generated manifest at the configured location.
Changing a source/helper/schema/script and rebuilding changes the appropriate identity even
when operator release labels are unchanged. Labels can invalidate an identity, but cannot
replace source provenance. Missing manifests disable reuse, including successful-unit reuse.
Dynamic imports outside the declared source closure must be added to the manifest before release.

Set `APPSEC_REVIEW_IMAGE_ID=sha256:<64 hex digits>` in the deployed application's environment
to record the actual immutable image identity. Source and image identities are separate.
An omitted image identity is recorded as `null`, **not** proof of a verified image. Changing an
image, script manifest, or Python runtime is a deployment change requiring repair admission.

Application code is **mounted, not baked**: the Dagster image holds tooling only, Compose mounts
the checkout read-only at `/opt/app`, and the code-location start measures
`implementation-release.json` from the mounted tree onto `/var/dagster/release/`
(`APPSEC_REVIEW_RELEASE_MANIFEST`; see
[Deployment image and source mount](../architecture/deployment-image-and-source-mount.md)). The
repair cycle is therefore: stop, edit the checkout, `lifecycle.py reload` (re-signs the sources and
recreates the image services in seconds), `plan-repair`, `admit-repair`, `resume`. No `docker build`
occurs unless a dependency, tool or the signing verifier changed. Preserve active-run freezes: the
signed envelope fails closed on edited modules until the next reload, and every attempt pins its
own copy of the release manifest under `data/recovery/releases/`, so a reload never rewrites the
identity an active attempt recorded. Source identity (`implementation-release.json`) and image
identity (`APPSEC_REVIEW_IMAGE_ID`, the tooling image) are separate components of
`deployment_identity`; a code edit changes the first only.

## Inspect, stop, and admit

```sh
appsec-review failure-replay --run-id RUN --job-id JOB --attempt-id attempt_0001
appsec-review select-job-tests --job JOB --kind unit
appsec-review plan-resume --run-id RUN --target TARGET --force-from JOB
```

`failure-replay` emits at most 256 verified references to existing configuration, inputs,
claims, command/stream artifacts, terminal receipts and handoffs. Diagnostic contents and
ambient environment values are not copied. Environment requirements contain names and
`[REDACTED]` placeholders. Referenced diagnostics remain untrusted data, not instructions.
Large manifests fail explicitly instead of silently truncating coverage. No captured command
is automatically executed. The [test selector](job-test-selection.md) keeps unit, integration,
acceptance and live coverage distinct and reports missing mappings.

Stop existing work using the existing operator commands (`review-stop-id`, or the applicable
native lifecycle), and verify cleanup with the existing resource-admission facilities. Do not
manually delete leases to make repair pass. First-error stopping remains opt-in. Native
first-error cancellation is **not commissioned** and is not enabled by these commands.

For Dagster, a failed step alone is not proof that the run worker stopped:

```sh
docker compose --env-file deploy/dagster/.env -f deploy/dagster/compose.yaml -f deploy/dagster/compose.claude.yaml \
  exec -T code-location python -m appsec_review verify-repair-stop --run-id RUN --dispatch-id DAGSTER_UUID
```

It runs inside the application container because it needs the configured Dagster instance (the
host virtualenv has none); `DAGSTER_UUID` is the dispatch the failed attempt's `claim.json` names,
also the suffix of `runs/metadata/stepwise/<run>/checks/<job>-<uuid>.json`. It uses the launcher's
worker-health API, without cancellation. The stack's `DefaultRunLauncher` has no such API: its run
workers are subprocesses of the code-location server, so the verifier asks that server (the address
in the run's `.dagster/grpc_info` tag) whether it still executes the dispatch — `GetCurrentRuns` on a
plain server, `CanCancelExecution` through the `dagster code-server start` proxy the stack uses,
which does not implement the former. A terminal run the server no longer holds has a stopped worker
(`NOT_FOUND`), one it still holds is refused, and an unreachable server is refused. Not covered: a
code-location reload from the Dagster UI between the failure and the check (the proxy then fronts a
new server while the old one finishes); the stack's own `lifecycle reload` recreates the container. The receipt lands in
`data/recovery/dispatches/<uuid>.json`. It refuses a missing/wrong/nonterminal run, a live/unknown
worker, and any other launcher without health support. Retained resource leases and uncertain controller permits still block admission.
Registered local workers are checked by process generation and PID namespace; foreign or
unverifiable workers fail closed. Historical receipts without worker identity are uncertainty,
even when they say `FAILED` or `SUCCEEDED`: they do not prove that independent workers stopped.

After the stopped deployment has been replaced with the repaired release:

```sh
appsec-review plan-repair --run-id RUN --target TARGET > repair-plan.json
appsec-review admit-repair --run-id RUN --target TARGET --plan repair-plan.json
appsec-review resume --run-id RUN --target TARGET
```

The plan is deterministic and contains compatibility version, old binding identity, exact
replacement release/deployment identity, attempt snapshots, every job decision, unit checkpoint
decisions and refusal reasons. Review it before admission. `admit-repair` rederives it while
holding the run and admission locks; stale or simultaneous claims cannot both win. This command
only records admission. It does not execute the restart.

### Rewind an existing stepwise walk after admission

For an existing operator walk, apply the **exact already admitted plan** before resuming:

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py rewind --app-run RUN --plan repair-plan.json
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run RUN
# Inspect the check and its comparison, then accept this job individually as usual.
.venv/bin/python deploy/dagster/bin/stepwise.py accept --app-run RUN --job JOB --tag CORPUS_TAG
```

`rewind` neither admits a plan nor launches jobs. Under the existing run/admission locks, it
verifies the plan digest, immutable admission and current binding, deployed release and
configuration, unchanged topology, planned attempt snapshots and current operator decisions.
A read-only code-location probe checks registered workers, cleanup receipts and leases, plus
Dagster dispatches and worker health, including queued dispatches not yet recorded in the walk.
Foreign, unadmitted, stale, live or uncertain work is refused; there is no force option.
Keep operator actions serialized; `next`, `check`, `accept` and `rewind` share a walk lock.

Only previously touched `RUN`/`INVALIDATE` decisions return to `pending` (meaning **to rerun**,
with explicit `replays` metadata). Independent `REUSE` acceptances and untouched pending jobs
stay unchanged. Before resetting, immutable hash-checked evidence under
`runs/metadata/stepwise/RUN/rewinds/PLAN_SHA/` retains the entire prior state, plan, admission
binding, check reports, accepted normalized keys, provenance and original claims.
Repeating the same rewind verifies that evidence without resetting completed replay work.

Each replay of an accepted job must have a fresh dispatch and a committed publication under
that admission. `check` and `accept` compare against the **preserved key**, not a replacement
corpus file. Existing normalization and diff rules apply, without broad environmental
reclassification: semantic output, coverage, findings, gaps and artifact-content differences
fail acceptance. The report separately names two narrowly verified claim bookkeeping changes:
the admitted repair reference and checkpoint decisions matching that plan (or the runner's
conservative no-reuse fallback). Only when the rest of the normalized claim is identical may
its content signature account for those changes; unrelated claim changes still fail.
Successful reacceptance writes an immutable receipt with the new provenance and comparison,
while retaining the original key, provenance, seed and rewind evidence. A changed corpus
key/provenance is refused rather than silently overwritten.

This is host-side operator tooling; it does not change measured runtime sources, release
scoping, job policies, frozen configuration or admission/signing enforcement. The three early
gates still declare `always_execute=True` and `propagate_handoff=False`; the release still
includes each job package's static cross-job import closure and shared common/validator/script
dependencies. Unit regressions for the rewind are in `tests/test_stepwise_rewind.py`.

The original configuration, target fingerprint, review policy and evidence are retained.
Configuration changes and schema/dataset-contract changes are not compatible source repairs.
Host image bindings are a hashed configuration layer, not a source repair: changing
`deploy/dagster/host-pins.toml` requires a fresh authorized run. Its old run-owned copy remains
immutable. The T-051 cutover preserves `2026-11-10-0002` and starts a fresh c094 run by explicit
operator decision; it does not promise uninterrupted reuse across that cutover.
An unchanged job may reuse an accepted predecessor only after full artifact verification.
Actual DAG ancestors determine input handoffs in both drivers; independent branches survive,
live gates always run, and `COMPLETED_WITH_GAPS` survives warm reuse. Dagster also accepts the
`appsec/force_from` tag for every job in its enabled graph.

Successful portable units from a failed attempt can enter a **fresh** attempt only after
explicit repair admission, with identical configuration, implementation, deployment, input
and dependency identities. Checkpoints bind the old claim, successful terminal receipt and
result. Validators still run. Path-coupled artifacts, process/workspace state, budget state,
missing/corrupt checkpoints, and units whose dependencies are not admitted rerun rather than
being transplanted. Old attempt receipts remain untouched. Model budgets are not copied or reset
by recovery; their old receipts remain in their original attempt.

Shared computation receipts have a separate provenance check: an unchanged cache key does not
authorize reusing a computation from an incompatible implementation, configuration or deployment.
Repair-scoped lookups reuse compatible producers and recompute incompatible ones; publication
checks the same rule even if a caller bypasses lookup. Resume also checks the origins of reused
shared computations, retaining genuinely independent branches. Missing or corrupt original
release snapshots reject admission; those snapshots are control-plane metadata, not indexed
customer evidence.

A named cache cannot silently relabel an incompatible producer as unknown legacy provenance.
Regenerate it under a new computation identity, preserving the original artifact, or use a
successor run when it cannot be regenerated in place. Verified public-feed bytes remain data
inputs rather than being mistaken for application computations.

Publication has an explicit final commit marker binding the handoff and terminal status.
A crash between outcomes, handoff, index/latest pointers, events and that marker never admits
partial output on recovery. A newer rejected or interrupted attempt prevents falling back to
an older accepted attempt as though the newer failure had not happened.

## Historical and permanently stopped runs

An unmeasured historical implementation needs `--historical-rerun`; none of its unverified
successes are imported. If the immutable first-error controller UUID cannot be reopened, or
an operator wants an explicit successor:

```sh
appsec-review plan-repair --run-id OLD --target TARGET --historical-rerun --successor > successor-plan.json
appsec-review admit-repair --run-id OLD --target TARGET --plan successor-plan.json
```

The returned successor has the same resolved review configuration and a versioned reference
to the original plan/run. **All jobs rerun; imported successes are explicitly empty.** Original
evidence remains in the source run. Stopped-worker/cleanup checks are not bypassed. A successor
from an older runtime that recorded no worker identity remains refused rather than treating
terminal status as shutdown proof. The automatic historical route supports unmeasured releases
whose worker shutdown can actually be verified.
A successor
requiring first-error safety must be submitted with a fresh, authorized execution-safety envelope
through the existing Dagster submission path; this command does not silently install one.

## Manual validation

Focused regressions are in `tests/test_repair_admission.py`, `tests/test_wave1_resume.py`,
`tests/test_job_runtime.py`, `tests/test_handoff_interchange.py`, and related CLI/driver contracts.
Integration and acceptance paths remain excluded from implicit pytest collection.

The following are **manual and were not run as implementation gates**:

```sh
.venv/bin/python -m pytest tests/integration/test_repair_workflow.py --basetemp=test/tmp/repair-integration-manual
.venv/bin/python -m pytest tests/acceptance/test_repair_fixture_review.py --basetemp=test/tmp/repair-acceptance-manual
```

Integration prerequisites: Linux/Python 3.12, checkout-local `.[test,dagster]`, no live models
or Docker builds. It uses real local worker/process and Dagster lifecycle execution while faking
only external launcher health/telemetry. Acceptance additionally requires an isolated fixture
configuration (`APPSEC_REPAIR_ACCEPTANCE_CONFIG`) and its matching generated implementation-release
manifest, with all required jobs enabled, nonproduction
`runs_dir`, prebuilt pinned tool images/data, a fixture target
(`APPSEC_REPAIR_ACCEPTANCE_TARGET`), and complete offline recordings
(`APPSEC_REVIEW_MODEL_REPLAY_DIR`). Model recording mode is forced to `replay` with no live
fallback. The fixture must contain a deliberate, non-retriable coverage gap.
