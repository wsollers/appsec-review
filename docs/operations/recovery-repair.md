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

For Dagster, a failed step alone is not proof that the run worker stopped. In a stepwise walk,
prefer `stepwise.py recover --app-run RUN` below: **every** recorded dispatch needs current
worker-stop verification, including successful replays, not only the failed dispatch.
The single-dispatch primitive remains available:

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

### One command for a `wave1_review` run

For an application run launched with `review-start`, `scripts/review-recover` runs the single-step
commands above in this order, from the host, and stops at the first one that refuses:

```sh
scripts/review-recover.sh RUN --dry-run     # read-only checks, then the ordered commands; executes none
scripts/review-recover.sh RUN               # asks once before admission and resume; --yes pre-confirms
```

1. every recorded Dagster dispatch of `RUN` must be terminal, and the active-run guard must pass;
2. the terminal `SUBMITTED` submission intent of `RUN` is reconciled (`review_run.py reconcile`);
3. worker stop is verified for every recorded dispatch, inside the code-location container, with
   the same probe `stepwise.py recover` sends (it writes the same
   `data/recovery/dispatches/<uuid>.json` receipts as `verify-repair-stop`);
4. `plan-repair` runs in the container and its summary is printed: jobs reused, jobs re-run,
   refusal reasons;
5. after one confirmation, `admit-repair` receives exactly that plan, then
   `review-start --run-id RUN` resumes the run.

**It adds no new authority.** Each step is the existing command's logic with the existing
refusals; the script does not weaken, skip, retry around or automate past any of them. A failed
step is still not proof that a worker stopped, an unreconciled submission still blocks a launch,
an inadmissible plan is still not admitted, and `--force` still overrides only the active-run
guard for *other* reviews: never this run's own non-terminal dispatch, never a refusal, never the
confirmation. Everything the script does can be done, and inspected, with the single commands; use
them when a step needs a closer look. When no job of the run has an accepted handoff the script
plans no repair and prints the command for a fresh `review-start` instead. Options, exit codes and
the per-step refusals are in [operator scripts](operator-scripts.md#recovering-a-failed-run).

`plan-repair` and `admit-repair` run in the code-location container because the plan binds the
deployed release manifest and deployment identity (`APPSEC_REVIEW_RELEASE_MANIFEST`,
`APPSEC_REVIEW_IMAGE_ID`), which the host does not have. The script passes the profile and overlay
the run recorded in `data/configuration/manifest.json`, so the plan resolves the run's own frozen
configuration; a mismatch is a plan refusal, as it is by hand.

### Serial recovery of an existing stepwise walk

Keep the job-driven loop serial. These are manual operator actions, not automatic repair gates:

```sh
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run RUN
# After stopped-source integration/reload, inspect plan-repair and explicitly admit the exact plan.
# Neither recover invocation admits it or launches any jobs.
.venv/bin/python deploy/dagster/bin/stepwise.py recover --app-run RUN --plan repair-plan.json
.venv/bin/python deploy/dagster/bin/stepwise.py next --app-run RUN
# Inspect the check and its comparison, then accept this job individually as usual.
.venv/bin/python deploy/dagster/bin/stepwise.py accept --app-run RUN --job JOB --tag CORPUS_TAG
```

Without `--plan`, `recover` verifies stops only. It gathers current and archived walk dispatches,
all attempt claims, and all Dagster runs tagged with this application run (including queued or
untracked runs). Inside the code-location namespace it rechecks each worker's current health and
uses `verify_dispatch_stop` to create any missing immutable stop receipt. Existing receipts are
not overwritten or treated as live health proof. Active, absent, foreign or uncertain dispatches,
registered workers and retained leases refuse recovery. If a later dispatch refuses, any already
verified stop receipts remain useful evidence; no operator acceptance is reset.

With `--plan`, `recover` performs that same verification and then applies the **exact already
admitted plan** using `rewind`. This deliberately leaves an inspection/admission break between
the two commands. It never implicitly admits, cancels, launches, accepts, or runs a graph.
`check`/`accept` on a replay repeat full stop verification before comparing the preserved key, so
a newly completed successful replay cannot leave its missing receipt to block the next repair.

The lower-level `rewind` still requires preexisting stop receipts and never writes them.
Under the existing run/admission locks, it
verifies the plan digest, immutable admission and current binding, deployed release and
configuration, unchanged topology, planned attempt snapshots and current operator decisions.
A read-only code-location probe checks registered workers, cleanup receipts and leases, plus
Dagster dispatches and worker health, including queued dispatches not yet recorded in the walk.
Foreign, unadmitted, stale, live or uncertain work is refused; there is no force option.
Keep operator actions serialized; `next`, `check`, `accept`, `recover` and `rewind` share a walk lock.

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

As a **temporary workaround for a producer/key-normalization defect**, the model-preflight
reports from `model_connectivity` and `review_intake` additionally allow
unrelated advertised-model inventory drift in `providers.<provider>.listed`. Both raw artifact
references and normalized content signatures must resolve and verify first. Configured and
checked model sets, their results, and every other report field must remain unchanged; adding
or removing a checked/configured model from the advertised list still fails. The comparison
receipt and CLI report exact inventory additions/removals and old/new counts, with references
to the unchanged raw evidence. Only these two named report artifacts receive this accounting;
there is no general hash, environment or volatile reclassification, and old keys stay intact.

The T-057 inventory workaround is not a permanent comparison policy. Advertised inventory is
volatile diagnostic evidence and should not enter these jobs' compared accepted content.
The intended fix belongs at the publication/key-normalization boundary of
[pass 01](../tasks/2026-11-08-job-pass-01-model-connectivity.md) and
[pass 04](../tasks/2026-11-08-job-pass-04-review-intake.md): preserve the raw inventory in an
explicitly non-compared diagnostic section or artifact, while comparing configured/checked
model identities and results, provider errors, transport and gaps strictly. Merely moving
the list is insufficient if its content hash still participates in the compared key.
Once corrected, new keys must not need the inventory comparison exemption; existing immutable
keys/evidence must not be rewritten or silently reaccepted. The publication fix is not
implemented by this operator-only change.

Source-history replay also has a closed, evidence-checked mount-path comparison. It covers only
`acquire.git_history`'s `log` and `messages` executions and `resolve_sources.bind_snapshot`'s
`tree` execution: `/target` read-only, `/scratch` writable, and `/gitdir` read-only. The original
key, provenance, claim and accepted publication must resolve; both attempts' claims must retain
the same repository/target, source fingerprint and configuration. Each affected JSON artifact's
raw reference must match its publication, and its original normalized signature must reproduce
from those exact bytes, including the preserved key's digests.

The verified execution receipts bind logical `source` paths to their recorded `runtime_source`
paths. Either side may use the exact native checkout root or a Docker Desktop alias. Accounting
permits Desktop/native changes in either direction and unchanged mounts (including a native
target alongside changed scratch/gitdir mounts), but not Desktop-to-different-Desktop remaps.
Within each attempt, each logical root must map consistently, and any Desktop roots must be
distinct and from one distribution. Both sides retain exact claim-owned relative suffixes.
Path shape alone is not proof. The embedded
execution copies must match their pinned unit results; the separately published `log` and
`messages` receipts must also agree with those copies. The `tree` execution's retained proof is
its hash-pinned `bind_snapshot/result.json` copy, not an unpinned scratch file.

Only the qualifying structured `mounts[].runtime_source` fields are projected for comparison.
All four affected normalized artifact signatures are accounted for only after **every** proof
succeeds and the remaining normalized artifact content matches. Unknown roots, traversal,
different suffixes/sources/targets/permissions, missing or corrupt pins, conflicting copies and
partial proofs cannot establish equivalence. Other path strings and semantic changes still
fail. Reports retain `verified_mount_path_changes` with raw old/new paths, logical and runtime
roots, relative suffixes, claim/provenance references, raw artifact references and both unmodified
signatures. This checks recorded evidence, not current Docker state; it neither rewrites a key
nor constitutes operator acceptance.

The same proof also covers exactly the Azure, Bitbucket and GitLab Checkov branches of
`job_ci_configuration_analysis`: each `ci_analysis.<provider>_checkov_scan` result, its
`ci_normalization.<provider>_checkov_normalize` result, and their shared, pinned
`artifacts/ci/<scan-unit-sha256-prefix>/raw-observations.json`. Each has exactly one
`tool-checkov` execution, with `/target` read-only and `/scratch` writable at the scan unit's
`scratch/file_0001`. All three execution copies must agree, and both result references must
resolve to the exact raw artifact published for that scan unit. Raw observation content outside
`executions` (including definitions, records, gaps, status and image identity) must match exactly;
execution image, argv and environment identities also remain exact. The remaining normalized
content of all nine artifacts must match before any comparison adjustment is applied. Other
CI providers, tools, units, artifacts or scratch suffixes receive no additional equivalence.

Current comparison accounting is closed, not a producer-wide exemption:

| Producer/artifact | Accounted-for difference | Everything else |
| --- | --- | --- |
| Any replay's `claim.json` | Verified current admission reference and admitted checkpoint decisions/conservative runner fallback, only if the rest of the normalized claim matches | Strict existing normalized diff |
| `job_model_connectivity`, `steps/connectivity/tasks/verify_models/model-connectivity.json` | Temporary pass-01 workaround: only unrelated names added/removed from `providers.<provider>.listed`, after raw-reference and normalized-signature proof | Strict; configured/checked models, results, provider set, transport, errors and gaps cannot change |
| `job_review_intake`, `steps/model_preflight/tasks/verify_models/model-preflight.json` | Temporary pass-04 workaround: the identical inventory-only rule for this named artifact | Strict, as above |
| `job_source_history_analysis`, `acquire.git_history` and `resolve_sources.bind_snapshot` result JSON, plus the published `log`/`messages` execution JSON | Only the proved Desktop/native mount aliases described above, in either direction with unchanged mounts permitted, including their dependent normalized signatures | Strict; all raw pins and the rest of each normalized artifact must match |
| `job_ci_configuration_analysis`, Azure/Bitbucket/GitLab Checkov scan and normalization results and their three pinned raw observation artifacts | Only the same proved mount aliases and dependent signatures, with exact execution-copy/reference agreement | Strict; all other raw observation content and remaining normalized artifact content must match |
| Every other artifact/producer | No additional equivalence rule | Strict existing normalized diff |

Comparison receipts retain both `unadjusted_differences` and the final `differences`, alongside
the exact admitted control, inventory and mount-path changes and their resolving evidence. Accounting for a
verified difference never deletes its raw artifact, prior key or provenance.

This is host-side operator tooling; it does not change measured runtime sources, release
scoping, job policies, frozen configuration or admission/signing enforcement. The three early
gates still declare `always_execute=True` and `propagate_handoff=False`; the release still
includes each job package's static cross-job import closure and shared common/validator/script
dependencies. Unit regressions for the rewind are in `tests/test_stepwise_rewind.py` and
`tests/test_stepwise_mount_paths.py`; the closed CI extension is in `tests/test_stepwise_ci_mount_paths.py`.

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
