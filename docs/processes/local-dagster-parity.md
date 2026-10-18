# Local and Dagster parity, one job at a time

Status: approved 2026-10-18, with model replay (section 6).

## Goal

Run every `wave1_review` job singly, in graph order, through both entry points against the same
project, from the same starting state, and prove that both produce the same output. Start with
one small blind C++ corpus, `targets/cpp-multivuln`. Add corpora only after the whole chain has
matched on it.

**Match** means:

- both runs exit successfully, with the same job status (`SUCCEEDED` or `COMPLETED_WITH_GAPS`)
  and the same handoff status;
- the normalized outputs are identical: findings, gaps, unit dispositions, steps, outputs and
  artifact signatures (`appsec_review.acceptance.normalize`, compared by `diff_job_outputs`);
- only the classes the normalizer already masks may differ: run, attempt and Dagster ids,
  timestamps and durations, absolute repository, run and target paths, image ids and digests,
  randomized scratch names, pids and container names.

Any other difference stops the walk. The tool prints the difference, and a person decides whether
it is a bug to fix or a volatile field the normalizer missed.

## What the code already establishes

1. **One implementation, two drivers.** The Dagster `begin` op calls `JobRunner.begin_attempt`,
   one op per unit calls `execute_or_reuse_unit`, and a `finalize` op calls `finalize_attempt`
   (`orchestration/dagster/adapter.py`). `appsec-review run JOB` calls `JobRunner.run`, which runs
   the same units in process, one after another. Parity therefore tests the drivers (claim
   inputs, unit scheduling, environment), not two implementations.
2. **The configuration is path-free.** The resolved configuration hash of the host checkout and
   of the Dagster code location are identical (`78bbf5bf…` for run `2026-10-17-0003`), so a local
   run can continue a run tree Dagster created without failing `_bind_configuration`.
3. **Both sides run as uid/gid 1000** (`deploy/dagster/.env`), so the existing write audit applies
   unchanged to local runs.
4. **Seeds restore only under their original run id** (`stepwise.seed_run`): the id is inside
   hashed artifacts. Two copies of one starting state cannot coexist in one checkout.
5. **The local CLI cannot yet run a mid-graph job.** `appsec-review run` passes neither a target
   root nor upstream handoffs. Dagster takes both from `APPSEC_REVIEW_TARGET`, from a hard-coded
   set of target-consuming jobs in `adapter.py`, and from the `appsec/upstream_handoffs` run tag.

## Design

### 1. Corpus identity

`stepwise.py accept` requires the target's git tag to equal the acceptance directory name. The
target is therefore tagged `cpp-multivuln-v1`, and its answer key moves to
`test/acceptance/cpp-multivuln-v1/expectations.toml`. Baselines, provenance and seed manifests
land beside it, as they do for `AcceptanceTest`.

### 2. One definition of a job's inputs

- Move the set of target-consuming jobs out of `adapter.py` into the topology/registry, so the
  Dagster op and the CLI read the same definition.
- Add to `appsec-review run`:
  - `--target PATH`, passed as `target_root`, with its source fingerprint, for target-consuming jobs;
  - `--upstream-from-run`, which resolves each declared upstream job's handoff digest from
    `runs/<id>/data/jobs/<job>/latest.json`. This is the same rule `stepwise.launch_next` uses to
    build the Dagster tag, factored into one shared function.
- A local claim records `orchestration = {"system": "local"}`. That is masked like the Dagster id.

### 3. `stepwise.py parity --tag TAG --job JOB`

Each step runs alone in this checkout, never at the same time as another, because both runs share
one run id, one Docker daemon and one host. Running them in parallel would also let resource
contention cause timeouts that look like differences.

1. **Restore** the seed taken after the previous job (`--replace`). For the first job, restore the
   empty initial seed (section 4).
2. **Dagster run:** launch the job with the existing `launch_next`, then `check` and normalize it.
   Save the normalized output to `runs/metadata/stepwise/parity/<run>/<job>/dagster.json` and
   snapshot the post-run tree as a candidate seed.
3. **Restore** the same previous seed again.
4. **Local run:** `appsec-review run JOB --run-id <run> --target <host target> --upstream-from-run`,
   followed by the same write audit and normalization, saved to `local.json`.
5. **Preflight identity.** The two handoffs must agree on `implementation_identity`,
   `resolved_config_sha256`, `validation_identity`, `schema_identity`, `input_identity` and
   `upstream_handoff_sha256`. A disagreement means the comparison is invalid: for example, the
   code-location image was built from another commit. It is reported as such, never as a parity
   difference.
6. **Compare** with `diff_job_outputs(dagster, local)`.
   - No failing differences: print `PARITY OK`.
   - Otherwise: print every failing difference grouped by class, write the report, and exit 3.
     The walk stops for a decision.
7. **Accept.** After a person reviews the job, restore the Dagster candidate seed and run the
   existing `accept`. The Dagster output becomes the baseline and the starting seed for the next
   job.

The report records:
- both exit statuses and both handoff identities;
- finding, gap and unit counts for each side;
- tool identities;
- every difference, with its class.

### 4. Initial seed

The first job allocates the application run. `parity` handles it this way:

1. `init` runs the first job in Dagster, which allocates run `X`.
2. Before that job writes anything, an empty `after-none` seed of `X` is snapshotted: the bound
   configuration and nothing else.
3. The local side restores that seed and runs the first job with `--run-id X`.

### 5. Answer key report

After each accepted job, the tool lists the `expectations.toml` defects whose producers ran in that
job as found, missed or spurious. It is informative and never gates parity: the docs' Decision 2
already says a missed defect is a corpus failure, not a parity failure.

### 6. Model record and replay (decided 2026-10-18)

Model output is not deterministic, so the local run replays the model responses the Dagster run
recorded. A parity difference in a model-backed job then always means the drivers differ, never
that the model answered differently. Model variance is out of scope for parity.

- **Where.** Every job reaches a model only through `appsec_review.inference.infer`, which the job
  registry hands to jobs. Record and replay wrap that one callable in the registry. Providers and
  jobs are untouched.
- **Switch.** The mode comes from the process environment
  (`APPSEC_REVIEW_MODEL_RECORDING=record|replay`), never from `appsec-review.toml`. A
  configuration change would change `resolved_config_sha256`, so the two sides would no longer be
  the same run.
- **Key.** A recording is keyed by the SHA-256 of the canonical request after the same masks the
  normalizer applies (repository, target and run roots). The `/opt/app` and host spellings of one
  request therefore produce one key.
- **Recording.** The Dagster side writes each request, key and `ModelResult` to
  `runs/<run>/data/inference-recordings/<job>/<key>.json`. Before the second restore, `parity`
  copies the recordings to `runs/metadata/stepwise/parity/<run>/<job>/recordings/`, and the local
  side replays from that copy.
- **Fail closed.** A replay miss means the local driver built a different request. It raises,
  the job fails, and the parity report names the unmatched key and the masked request, so the
  difference is visible rather than answered by a live model.
- **Coverage.** This applies to `job_target_analysis_plan`, `job_project_build`,
  `job_dependency_intelligence`, `job_post_build_security_assessment`,
  `job_review_prioritization`, `job_review_data_indexing` and `job_inference_security_review`, the
  jobs that reference the inference layer.

## Risks and open questions

1. **Recording writes are new run-owned files.** They stay out of the job's handoff artifacts, so
   they don't change normalized output. The write audit has to accept the
   `inference-recordings` root when recording is on.
2. **Host and container toolchains.** Jobs that do host-side work (git, tree-sitter, sqlite) run
   in the host venv locally (Python 3.12.3) and in the code-location image under Dagster. A version
   difference shows up as a parity difference. The report records tool identities so it can be
   recognized.
3. **Unit scheduling.** Dagster runs units in parallel pools, while the local run is sequential.
   Output that depends on completion order is a determinism bug in the producer, to be fixed
   there, not masked.
4. **The shared Dagster stack.** Reviewing `cpp-multivuln` needs
   `APPSEC_REVIEW_TARGET=/opt/app/targets/cpp-multivuln` in `deploy/dagster/.env` and a recreated
   stack. Any other session using the stack on this host has to be told first.
5. **The Docker daemon is not running** on this host as of 2026-10-18. Nothing in the walk can run
   until it is.

## Implementation chunks

1. One shared definition of a job's target and upstream inputs, plus `run --target` and
   `--upstream-from-run`. Tests: the CLI resolves the same upstream digests and the same
   target-consuming set as the Dagster op.
2. `stepwise.py parity` with its report and preflight. Tests run against a fake runner and a fake
   Dagster client: identical outputs pass; a finding difference, a gap difference and an identity
   mismatch fail with the right class.
3. The `after-none` initial seed.
4. Model record and replay at the registry's `infer`. Tests: a recorded request replays
   identically; a request differing only in masked roots hits the same key; a miss raises.
5. Retag the target to `cpp-multivuln-v1`, move the answer key, and update
   `acceptance-and-regression-testing.md`.
6. The walk itself, job by job on `cpp-multivuln-v1`, stopping at each difference.
