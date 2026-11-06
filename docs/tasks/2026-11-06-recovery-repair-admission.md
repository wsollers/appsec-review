# DEVELOPMENT PACKAGE 01 - RECOVERY AND REPAIR ADMISSION

The following development package is preserved verbatim before implementation.

DEVELOPMENT PACKAGE 01 - RECOVERY AND REPAIR ADMISSION

User authorization, quoted verbatim: "I agree with 1,2,3,4,5 and the mcp / skill recomendations. please create a detailed instruction prompt for each  to implement them on independent working trees. They should be fully covered with unit tests. There should be intergration and acceptance tests (but do not run them due to time constraints). when complete and tested the code should be merged back to local main. These tasks can run as top level independent chats and do not need to be monitored or supervised. Ensure all of these are included in their respective development package. Run those chats/tasks/workers on the Model GPT 6 Astra High 1M context window."

You own recommendation 1: dependable fail -> reproduce -> focused unit test -> repair -> admitted restart. Implement end-to-end, not merely a plan. Before editing, preserve this entire development package in docs/tasks/2026-11-06-recovery-repair-admission.md in your own worktree. Append the final implementation, verification and integration record there. Remain an independent top-level session; do not report to or seek supervision from the originating chat. Runtime settings requested by the user are GPT-6 Astra, high reasoning, long context (the API's large-context option); use the same settings if a necessary bounded subagent is used. Do not create extra projects, PRs, remote pushes, or live review runs.

Baseline and execution environment
- Repository: wsollers/appsec-review. Reviewed baseline: 528b3fa681d9e33113932c9fc4abf9ddbc53b6e5. Verify this is an ancestor of your assigned branch; newer main is acceptable. Read current code, root AGENTS.md, and .claude/skills/multi-session-coordination/SKILL.md. Claims below are source findings, not a replacement for current inspection.
- Implement and test in an isolated Linux/WSL Linux-filesystem worktree with its own environment, per repository policy. Ubuntu-22.04 is installed on the initiating machine. A Windows-mounted checkout/venv is not a Linux development workspace. Preserve the assigned branch and provenance if a Linux companion worktree is required. Do not run builds/tests in the shared primary checkout.
- Canonical configured local main is F:\XBOX-Repositories\appsec-review, not a newly created mirror's main. Final integration must reach that actual local main through the permitted existing local integration procedure. Observe any active source freeze and existing integration ownership.

Scope and ownership
Own runtime/job.py, runtime/resume.py, runtime/graph.py, runtime/runner.py, runtime/launch.py, recovery portions of cli.py, new release/repair contracts and narrowly necessary configuration changes, and job-to-unit-test selection tooling. All source paths are under src/appsec_review unless otherwise specified. Do not redesign model loops: package 03 owns inference recording, cell retries and budget enforcement. Package 02 owns pyproject/CI/global test configuration; 04 owns prompts; 05 owns telemetry reporting and retention; 06 owns MCP/development skills. Preserve public APIs, use narrow integration edits, and do not depend on an unpublished sibling API.

Verified problems to address
1. Job.identities uses declared job/platform and validation releases. Resume explicitly refuses undeclared identities. Shipped config omits platform/validation, so accepted-job reuse is disabled by default. Conversely valid declarations left unchanged across code changes permit stale reuse if other checks match. Updating declarations changes frozen configuration, so ordinary resume rejects it. A forced rerun does not by itself repair implementation provenance.
2. GraphRunner builds reused outcomes without original completion status, so an all-reused gap-bearing suffix can become SUCCEEDED. Resume invalidation currently walks a linear suffix and accumulates prior handoffs rather than selecting actual DAG dependents. CLI --force-from excludes POST_INDEX_JOB_IDS.
3. Successful units of a failed attempt have no uniform new-attempt reuse contract. Failure/replay inputs, test selection, stop state, and implementation repair are not one operator workflow. First-error stop is opt-in; native first-error cancellation is intentionally not commissioned. Do not falsely enable unsupported cancellation.

Required implementation
- Produce deterministic implementation identities at build/release time from a declared dependency manifest covering job code, shared code, schemas/validators and separately mounted scripts as applicable. Preserve image identity separately. Do not scan/hash installed platform payloads as customer evidence during review. Hashing only a job package is insufficient for shared-helper changes.
- Add explicit repair admission for a new immutable attempt while retaining the original target/policy/config and old evidence. Define versioned compatibility decisions, exact repaired implementation, affected jobs, reusable predecessors, and the reason each reuse is admitted or rejected. Fail closed for incompatible changes. If an explicit successor-run import is the only compatible route for a historical run, implement and expose that route truthfully; never mutate old config to pretend an unchanged run.
- Make CLI and Dagster use consistent dependency/input projections and recovery decisions. Invalidate actual dependents, preserve independent branches, rerun live gates, retain gaps on warm reuse, and support forcing every enabled graph job. Return a deterministic explain/plan representation before repair execution.
- Provide a bounded failure/replay manifest referencing existing input/command/stream/handoff artifacts and redacted environment requirements. Never dump ambient credentials, replay arbitrary captured commands automatically, or treat raw diagnostics as trusted instructions.
- Implement explicit job-to-focused-unit-test metadata and a development test selector using existing pytest conventions; distinguish unit, integration, acceptance, and live selectors. Do not move hundreds of tests. Inspection/planning must not execute tests.
- Wire a discoverable recovery workflow using existing stop/lease mechanisms. Verify stopped workers before replacement attempts; surface unsupported native cancellation and cleanup uncertainty. No live cancellation or review execution is authorized for this implementation task.
- Document deployment coupling: current application code is baked into images. Do not claim hot reload exists. Preserve active-run freezes and record repaired image/script identity rather than silently changing running code.

Unit verification requirements - run these and all directly affected existing unit tests
Use tiny synthetic job DAGs and fake external boundaries, not a live Dagster review. Cover undeclared identities, unchanged declared identities, job/shared-helper/validator/script identity changes, byte-deterministic manifests, config mismatch, approved and refused repairs, historical runs, corruption/missing artifacts, rejected publication, failed job with an older accepted attempt, branch-selective invalidation, disabled and post-index force selectors, preserved COMPLETED_WITH_GAPS on reuse, successful-unit admission into a fresh attempt, cancellation/cleanup refusal, manifest redaction, test selector exactness, and concurrent repair claims. Inject failures between publication stages and prove recovery does not accept partial outputs. Extend tests/test_wave1_resume.py and relevant CLI/Dagster contract tests rather than replacing useful assertions. The recording exception and token/retry fixes are package 03's implementation, but recovery must preserve their public contracts.

Write integration and acceptance tests, but DO NOT RUN them
Add clearly separated tests under tests/integration and tests/acceptance for a real local worker/Dagster fail-repair-resume scenario, cross-driver parity, process interruption during publication, a repaired shared dependency, and a full fixture review preserving useful predecessors and explicit gaps. No live models, Docker image builds, actual target scans, or heavyweight acceptance execution in this task. Ensure those paths remain excluded from implicit unit collection. List exact future manual commands and prerequisites in the package; do not claim they passed.

Completion and local-main integration
- Run the smallest focused unit commands in your own Linux worktree, with unique --basetemp under test/tmp. Record exact tested SHA/content identity, command, elapsed time, outcome and any genuine pre-existing failure. No weakened assertions, broad skips or inflated timeouts to obtain green results.
- Commit the complete implementation, tests, docs and package record. Integrate latest local main into your own branch as needed, resolve only understood conflicts, and rerun affected units on the combined tree.
- You are responsible for landing your package, not leaving a ready branch stranded. All six independent packages share one serialized integration gate: use the existing repository integration lock/procedure; if none exists, use an OS-backed advisory lock named appsec-independent-main-integration.lock in the canonical main repository's Git common directory. Hold it only for final main inspection/update/verification, not development. Never bypass a dirty main, existing integration owner or active-run freeze; never use destructive reset, forced checkout, force-push, or automatic ours/theirs conflict resolution. No periodic merge monitor.
- Merge your tested branch into the actual local main one package at a time and verify the ready SHA is an ancestor of local main. Record resulting main SHA, files, focused test results and integration/acceptance tests NOT RUN. If safe integration is genuinely blocked, preserve commits and state the exact blocker in this independent session; do not claim completion or ask the origin chat to supervise.

## Implementation, verification and integration record

Baseline ancestry confirmed at
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5`. The isolated Linux companion is
`/home/wsollers/appsec-worktrees/recovery-repair-9d893e6a` in Ubuntu-22.04,
on the assigned `william-sollers-xbox-recovery-and-repair-admission` branch.
It was cloned from a local bundle of that branch, not from a remote.
The canonical main remains the configured Windows repository, not this companion.

### Implemented contracts

- Build-time `release-dependencies.json` and `runtime.release` produce deterministic source,
  shared-helper, validator, script and deployment provenance. Release labels cannot stand in
  for measured source identities. The application Dockerfile generates the manifest; no image
  was built during this task.
- Versioned repair plans/admissions preserve frozen configuration, target/policy and original
  attempts. Atomic admission publication, kernel locks, worker-generation/namespace checks,
  existing resource-lease inspection and Dagster launcher health verification fail closed.
- CLI and Dagster use matching graph/input projections, including disabled vertices, post-index
  force selectors, live gates and gap-preserving reuse. Newer failed attempts do not disappear
  behind older accepted handoffs.
- Successful portable unit checkpoints can be selected explicitly into a fresh attempt.
  The inspected checkpoint, original claim and result/receipt hashes remain authoritative;
  path-coupled, budget/process/workspace and retriable producer state is not transplanted.
- Publication has a final commit marker; partial pointer publication is not reusable.
  The bounded failure manifest contains references and redacted environment names, never
  automatic command replay.
- The development selector provides exact unit/integration/acceptance/live metadata for all
  registered jobs, keeping common contracts distinct from handler-specific coverage.
  `job_document_issue_analysis` still has an explicit handler-unit coverage gap.
- Historical unmeasured implementations require explicit rerun admission. Successors retain
  source-run provenance but import no unverified successes. Permanently stopped first-error
  controllers require a new authorized envelope; native cancellation is not commissioned.

Operator instructions and manual prerequisites are in
[`../operations/recovery-repair.md`](../operations/recovery-repair.md).
Application code remains baked into images. No hot-reload/mount deployment is claimed.

### Development verification log

These are pre-commit repair-loop results on the isolated companion based on `528b3fa6`.
Several commands exposed failures while the implementation was being developed; they do not
claim to validate the final frozen tree. Exact post-integration-base SHA verification is recorded
below when performed. Commands use `.venv/bin/python -m pytest` and are shown without that repeated
prefix.

| Command suffix | Elapsed | Outcome |
| --- | --- | --- |
| `tests/test_runtime_launch.py tests/test_wave1_resume.py --basetemp=test/tmp/recovery-baseline -q` | More than 120 s; interrupted | In-progress implementation run stopped after premature fixture/protocol failures; not a baseline result |
| `-q tests/test_repair_admission.py --basetemp=test/tmp/recovery-repair-01 --tb=short` | 23.230 s | 22 passed |
| `-q tests/test_wave1_resume.py tests/test_job_runtime.py tests/test_runtime_launch.py tests/test_handoff_interchange.py tests/test_review_run_cli.py --basetemp=test/tmp/recovery-existing-01 --tb=short --maxfail=12` | 210.517 s | 37 passed, 12 failed; measured-identity fixtures required migration; two unrelated baseline failures also exposed |
| `-q tests/test_wave1_resume.py::test_corrupt_or_missing_artifact_and_force_from_invalidate_downstream tests/test_job_runtime.py tests/test_handoff_interchange.py tests/test_repair_admission.py --basetemp=test/tmp/recovery-focused-02 --tb=short --maxfail=8` | 144.900 s | 136 passed, 2 failed; artifact-damage explanations subsequently corrected |
| `-q tests/test_repair_admission.py tests/test_job_runtime.py tests/test_handoff_interchange.py tests/test_review_run_cli.py tests/test_wave1_resume.py tests/test_runtime_launch.py --basetemp=test/tmp/recovery-combined-03 --tb=short --maxfail=8` | 290.908 s | 169 passed, 2 verified pre-existing failures |
| `-q tests/test_repair_admission.py tests/test_repair_dagster_contract.py --basetemp=test/tmp/recovery-hardening-04 --tb=short` | 27.802 s | 40 passed |
| `-q tests/test_job_test_selection.py --basetemp=test/tmp/job-test-selection-66e4291a-01` | 2.855 s | 78 passed, 1 failed; a target-dependent project-build test was initially misclassified as integration instead of live |
| `-q tests/test_job_test_selection.py --basetemp=test/tmp/job-test-selection-66e4291a-02` | 4.402 s | 79 passed after correcting that classification |
| `-q tests/test_job_test_selection.py --basetemp=test/tmp/job-test-selection-66e4291a-03` | 4.554 s | 83 passed |
| `-q tests/test_job_test_selection.py --basetemp=test/tmp/job-test-selection-66e4291a-followup-01` | 6.963 s | 104 passed |

The two pre-existing failures were independently reproduced at the exact unmodified baseline
`528b3fa681d9e33113932c9fc4abf9ddbc53b6e5` in the disposable
`test/tmp/recovery-baseline-src` checkout with its own Linux virtual environment:

```sh
.venv/bin/python -m pytest -q \
  tests/test_wave1_resume.py::test_catalog_path_index_accepts_structured_inventory_gaps \
  tests/test_runtime_launch.py::test_every_registered_job_outside_the_target_set_is_named \
  --basetemp=test/tmp/recovery-baseline-confirm --tb=short
```

Elapsed **11.122 s**, **2 failed**. The first expects a `node_modules` inventory gap but receives
an empty list. The second has an outdated explicit set missing build-iteration, OpenVEX,
remediation and dossier jobs. Their assertions were not weakened and their unrelated behavior
was not changed.

The actual build-time manifest generator was also exercised against the application source
without persisting a release or running a review: 756 files, 46 jobs, 25.269 s at that intermediate
source state. Python syntax checks parsed 22 runtime/CLI/adapter files successfully.

### Manual tests authored, NOT RUN

```sh
.venv/bin/python -m pytest tests/integration/test_repair_workflow.py \
  --basetemp=test/tmp/repair-integration-manual
.venv/bin/python -m pytest tests/acceptance/test_repair_fixture_review.py \
  --basetemp=test/tmp/repair-acceptance-manual
```

Integration covers real local process interruption during publication, Dagster failure followed
by admitted local repair, and a repaired shared dependency across driver boundaries. External
launcher health and unrelated telemetry are the only simulated integration boundaries.
Acceptance uses the complete configured fixture graph, isolated nonproduction run storage,
prebuilt/pinned tools and **offline model recordings**, with a required explicit retained gap.
Set `APPSEC_REPAIR_ACCEPTANCE_CONFIG`, `APPSEC_REPAIR_ACCEPTANCE_TARGET` and
`APPSEC_REVIEW_MODEL_REPLAY_DIR` as documented in the operations guide. No live model fallback,
Docker image build or acceptance execution occurred.

### Integration ownership

Canonical integration owner discovered through the existing owner:
`f9628e8e-873f-4f72-8aca-3069fb9fe4af`. The earlier build-topology hold was released; Stage B
had not started. The owner now serializes updates with
`appsec-independent-main-integration.lock`. This session does not create a competing gate or
mutate the canonical main checkout directly. Exact ready SHA/tree and focused evidence will be
handed to that owner after validation on the latest available main base. No origin-chat
supervision, remote push, pull request, live cancellation or review launch is involved.

### Frozen implementation verification

The initial implementation was committed, then rebased before publication onto canonical main
`0d2c6d7b8830436bda7eed3e2c66f89c6525a17d` (including package 02). No conflicts occurred.
Frozen candidate `0fcc429d611d4e7c762135e52bf2f217d70380cc`,
tree `4aaba81ab74a72755a0ae5083d53cd8cc7b7076c`, was checked with the incoming pinned quality
environment (`.[test,dagster,quality]`; Python 3.12, pytest 8.4.2).

Configured `ruff check` on all 24 changed Python paths passed in **0.076 s**.
`.venv/bin/python -m mypy src/appsec_review/runtime/job.py` passed in **10.593 s**.
The following frozen-tree focused command took **278.312 s**: **284 passed, 10 failed**,
then stopped at the requested diagnostic failure bound. The worktree remained clean.

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py tests/test_repair_dagster_contract.py tests/test_job_test_selection.py \
  tests/test_job_runtime.py tests/test_handoff_interchange.py tests/test_review_run_cli.py \
  tests/test_wave1_resume.py tests/test_runtime_launch.py tests/test_managed_admission.py \
  tests/test_shared_artifacts.py tests/test_source_history_analysis.py \
  tests/orchestration/dagster/test_definitions.py::test_definitions_reject_registry_config_drift \
  tests/orchestration/dagster/test_definitions.py::test_job_level_disabled_setting_is_transparent_to_dagster \
  tests/orchestration/dagster/test_definitions.py::test_wave1_exposes_real_producer_shard_topology \
  tests/orchestration/dagster/test_definitions.py::test_environment_dependency_is_required_or_transparently_disabled \
  tests/orchestration/dagster/test_definitions.py::test_owasp_follows_tag_cloud_and_precedes_hunt_in_both_graphs \
  --basetemp=test/tmp/recovery-final-0fcc --tb=short --maxfail=10
```

One new regression was found: checkpoint portability classified malformed producer declarations
too early, replacing a publication rejection with a unit exception. The predicate was corrected
to refuse checkpoint portability without changing the original execution/publication contract.
The two previously confirmed baseline failures remained. Seven failures came from an older
handwritten managed-handoff fixture; their baseline comparison and the remaining selected
checks are recorded below once complete. No assertions or coverage were weakened.

Candidate `7cce9a1d3d7471eb2dfefed4bb8bb7daf82ea79d`
(tree `6bffb5bd52fbfa62e1479fb76e8bc20dbc3b4bf6`) was then checked with:

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py tests/test_repair_dagster_contract.py tests/test_job_test_selection.py \
  tests/test_handoff_interchange.py::test_invalid_producer_declarations_publish_rejected_verified_execution_not_success \
  tests/test_managed_admission.py tests/test_shared_artifacts.py tests/test_source_history_analysis.py \
  tests/orchestration/dagster/test_definitions.py::test_definitions_reject_registry_config_drift \
  tests/orchestration/dagster/test_definitions.py::test_job_level_disabled_setting_is_transparent_to_dagster \
  tests/orchestration/dagster/test_definitions.py::test_wave1_exposes_real_producer_shard_topology \
  tests/orchestration/dagster/test_definitions.py::test_environment_dependency_is_required_or_transparently_disabled \
  tests/orchestration/dagster/test_definitions.py::test_owasp_follows_tag_cloud_and_precedes_hunt_in_both_graphs \
  --basetemp=test/tmp/recovery-final-7cce --tb=short
```

Elapsed **453.876 s**: **239 passed, 31 failed, 11 setup errors**; clean worktree afterward.
All new recovery/selector tests and the corrected malformed-producer regression passed.
The history warm-reuse fixture also needed a generated release manifest; its actual warm-reuse
and invalidation assertions are retained.

The baseline comparison ran this exact command in the unchanged `528b3fa6` checkout:

```sh
.venv/bin/python -m pytest -q tests/test_managed_admission.py tests/test_shared_artifacts.py \
  tests/test_source_history_analysis.py --basetemp=test/tmp/recovery-baseline-provenance --tb=short
```

Elapsed **387.680 s**: **83 passed, 29 failed, 11 setup errors**. These same 40 failing/error
selectors also fail on the implementation tree. Most use an obsolete handcrafted managed
handoff; existing source-history retention/invalidation expectations also fail at baseline.
These are genuine coverage gaps, not passing admission tests. The separately selected Dagster
topology assertion expects intake immediately after image verification and omits the already
present target-acquisition gate; its explicit baseline check initially could not collect because
the baseline environment lacked Dagster (`1 skipped`, exit 4). The missing optional dependency
was restored rather than treating that skipped collection as success.
