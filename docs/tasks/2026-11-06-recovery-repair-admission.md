---
title: "DEVELOPMENT PACKAGE 01 - RECOVERY AND REPAIR ADMISSION"
kind: "task"
subsystem: "testing and operations"
status: "historical"
jobs: ["job_document_issue_analysis"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
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

The restored baseline Dagster check:

```sh
.venv/bin/python -m pytest -q \
  tests/orchestration/dagster/test_definitions.py::test_wave1_exposes_real_producer_shard_topology \
  --basetemp=test/tmp/recovery-baseline-topology-restored --tb=short
```

failed at the same intake/target-acquisition assertion in **7.350 s** at `528b3fa6`.

### Ready combined tree

All unpublished package commits were rebased without conflicts onto canonical main
`dc263b305e500df398b19398260e619253e855a7`, which includes the already landed packages.
The final code/test candidate is **`e20947f60bc39983cac3acc10b4bf9bb70a48796`**,
tree **`c61c37b6be4e622a9482cfc12ae75aa8c8a66bac`**.

The following focused command passed **299 tests** in **365.393 s**. The two explicitly
deselected tests were already run repeatedly, failed on this branch and the unmodified
baseline, and remain unchanged; this is not a claim that the complete repository suite is green.
The broader managed/shared/history baseline failures and the stale Dagster assertion remain
the named gaps above. No integration, acceptance, live-review or image-build command ran.

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py tests/test_repair_dagster_contract.py tests/test_job_test_selection.py \
  tests/test_job_runtime.py tests/test_handoff_interchange.py tests/test_review_run_cli.py \
  tests/test_wave1_resume.py tests/test_runtime_launch.py \
  tests/test_source_history_analysis.py::test_job_binds_mainline_history_ranks_by_sii_and_feeds_the_plan \
  tests/orchestration/dagster/test_definitions.py::test_definitions_reject_registry_config_drift \
  tests/orchestration/dagster/test_definitions.py::test_job_level_disabled_setting_is_transparent_to_dagster \
  tests/orchestration/dagster/test_definitions.py::test_environment_dependency_is_required_or_transparently_disabled \
  tests/orchestration/dagster/test_definitions.py::test_owasp_follows_tag_cloud_and_precedes_hunt_in_both_graphs \
  --deselect=tests/test_wave1_resume.py::test_catalog_path_index_accepts_structured_inventory_gaps \
  --deselect=tests/test_runtime_launch.py::test_every_registered_job_outside_the_target_set_is_named \
  --basetemp=test/tmp/recovery-final-e209 --tb=short
```

The worktree was clean before and after this command. Configured Ruff correctness checks passed
on the 25 changed Python paths (**0.063 s**), and
`.venv/bin/python -m mypy src/appsec_review/runtime/job.py` passed (**3.165 s**).
Every new/manual test module was syntax-parsed, not executed as an integration/acceptance gate.

Two invocations of the real build-time release generator over this exact source tree produced
identical canonical bytes: **1,333 files**, **46 jobs**, **46.444 s** combined.
Release content identity:
`8d52cc8dddb47709a59647fe192d19d82a367e6237d40aecd5b80650fab406cd`.
The generated verification artifact stays in `test/tmp/recovery-release-verification.json`;
it is not committed and is not represented as a built/deployed image.

At the initial handoff, the only change after this tested code SHA was the verification record.
The handoff included its descendant commit, the exact tested source identity, the complete
owned-path list, LF/whitespace checks and the explicit manual-validation gaps.

### Integration-owner transition and final stop-proof check

The ready tip `2831c9986018388c82b2af03704f3d52e781f7b0` was imported into canonical Git
storage and the assigned app branch, without native Windows development, builds or tests.
Delivery to the previously confirmed integration owner failed because that session had been
archived. Its surviving predecessor was no longer messageable. The only surviving session
listed on the main checkout (`309f832c-bef7-46f0-8e9a-6c8a1f68b4eb`) explicitly declined ownership:
its older task prohibited commits, and it confirmed no active work/freeze of its own. No
unpermitted main update was attempted.

During that transition, the legacy-worker boundary was tightened: **any** historical claim
without worker identity is unverified, including a `FAILED` or `SUCCEEDED` receipt. A terminal
job receipt is not proof that older independent workers have stopped. Four focused regressions
cover those legacy states; the operations guide now names the resulting historical admission
limitation. The earlier ready tip was withdrawn before landing.

The final stop-proof code is committed at **`28a07335b0e4a54993b29ea43a1dd4bbf6674d94`**,
tree **`b2d641dd37e848cf1134814073e66074b0bcb473`**. Its directly affected regressions passed
**167 tests in 120.042 s**, with no skips or deselections:

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py tests/test_repair_dagster_contract.py tests/test_job_runtime.py \
  tests/test_handoff_interchange.py \
  tests/test_wave1_resume.py::test_interrupted_running_attempt_is_not_accepted_and_is_retried \
  tests/test_wave1_resume.py::test_concurrent_resume_attempts_cannot_claim_same_run \
  tests/test_wave1_resume.py::test_warm_graph_preserves_gap_completion_status \
  --basetemp=test/tmp/recovery-final-28a0 --tb=short
```

Configured Ruff checks on the changed stop-proof code/tests passed in **0.049 s**.
The actual release generator again produced identical bytes twice over **1,333 files/46 jobs**
in **47.726 s**. Final source-release identity:
`86f1ca0790481c508dc7ad0772fa23225027c38595b2895a3b296ced4841ae68`.
This supersedes the earlier release identity; it still does not claim a built or deployed image.

### Verified canonical local-main integration

A bounded integration worker was created for this package in the existing project, on the
canonical checkout, after the older owners became unavailable. It performed Git-only integration,
not native Windows development, builds or tests. It verified clean `main`, exact checkout/common
directory identity, no operation markers, and no current canonical review processes, live run
directories, conflicting ownership reservation or source freeze. Packages 03 and 05 and the
surviving target-addition owner directly confirmed no lock/reservation/freeze.

The worker fast-forwarded **actual `F:\XBOX-Repositories\appsec-review` local main**:

- Before: `dc263b305e500df398b19398260e619253e855a7`.
- Landed ready SHA and resulting main/HEAD:
  **`305a39d993bbd68b4678d309eef0e81463fd01fd`**.
- Resulting tree: **`a9c5417de4ba76c4b6631ddcf58aafd6b2adb45d`**.
- Both ready-tip and previous-main ancestry checks returned zero. The checkout remained on
  `main` and clean, including untracked status.
- The existing `.git\appsec-independent-main-integration.lock` was held from
  `2026-11-06T11:11:07.9651916Z` to `2026-11-06T11:11:15.8623834Z`, using
  `FileStream(OpenOrCreate, ReadWrite, FileShare.None)`, and released in `finally`.
  Its empty file was preserved.

Exact landing command:

```sh
git -c core.hooksPath=NUL -c gc.auto=0 -c maintenance.auto=false \
  merge --ff-only --no-edit --no-overwrite-ignore 305a39d993bbd68b4678d309eef0e81463fd01fd
```

No new merge commit, source edits, branch switch, destructive reset, forced checkout,
cherry-pick, remote push or pull request occurred. All six package commits retain the requested
Copilot trailer. Diffcheck passed before and after landing. All 33 changed paths were
`i/lf w/lf`; `git hash-object --no-filters` matched each checked-out file to its ready blob.
The ready tree differs from tested `28a07335b0e4a54993b29ea43a1dd4bbf6674d94` only in this
package's verification document. Linux verification was inherited by exact content identity,
not misrepresented as tests rerun on Windows.

Landed files:

```text
.gitignore
README.md
deploy/dagster/Dockerfile
docs/operations/job-test-selection.md
docs/operations/recovery-repair.md
docs/tasks/2026-11-06-recovery-repair-admission.md
release-dependencies.json
src/appsec_review/cli.py
src/appsec_review/development/__init__.py
src/appsec_review/development/test_selection.py
src/appsec_review/orchestration/dagster/adapter.py
src/appsec_review/orchestration/topology.py
src/appsec_review/runtime/checkpoints.py
src/appsec_review/runtime/dependencies.py
src/appsec_review/runtime/failure_replay.py
src/appsec_review/runtime/graph.py
src/appsec_review/runtime/job.py
src/appsec_review/runtime/launch.py
src/appsec_review/runtime/release.py
src/appsec_review/runtime/repair.py
src/appsec_review/runtime/resume.py
src/appsec_review/runtime/runner.py
tests/acceptance/test_repair_fixture_review.py
tests/integration/test_repair_workflow.py
tests/job-test-map.json
tests/release_support.py
tests/test_handoff_interchange.py
tests/test_job_runtime.py
tests/test_job_test_selection.py
tests/test_repair_admission.py
tests/test_repair_dagster_contract.py
tests/test_source_history_analysis.py
tests/test_wave1_resume.py
```

Integration/acceptance/live validations remain **NOT RUN**. The baseline failures above remain
explicit gaps. A separate package has reported a newer WSL-master custody instruction and a
sync refusal involving nine untracked NVD provenance files. The Windows integration worker did
not inspect or mutate that master, and this record does **not** claim that it was synchronized.
Those files must be preserved and any separate sync resolved through that checkout's owner.

### WSL master preservation and unresolved landing gate

Package 05 relayed the user's clarification verbatim:

> I'm confused WSL \~/projects/appsec-review is what we have been considering the master repo. Any work in the window repo must sync to there

Two fresh, read-only inspections confirmed the Ubuntu-22.04 repository at
`/home/wsollers/projects/appsec-review`, common directory
`/home/wsollers/projects/appsec-review/.git`, is on `main` at
`dc263b305e500df398b19398260e619253e855a7`. There are no tracked changes, but nine untracked
NVD provenance files still block the strict clean-tree integration gate. Their producing/data
custody owner is not established. No exception to that gate was authorized, so no files were
staged, stashed, moved, deleted or hidden with ignore changes, and WSL `main` was not advanced.

To preserve the completed work in the master repository without bypassing that gate, the bounded
worker imported the verified local bundle into Git object storage and atomically created the
previously absent **`refs/remotes/package-01/ready`**, pointing to
**`5c62c1d45df10d1b93c0db7336e8dd3b5d1f2402`** (tree
`28eef358e6df17d2ed4d4588ba6bfb9aa99074a4`). It used `git bundle unbundle` and
`git update-ref --no-deref` with an expected all-zero old SHA; no existing ref was overwritten.
Bundle SHA-256:
`8cc0cfa112090ecfb780bf397cf4d424294271f416b75b8d1568724584067434`.

Before/after protected snapshots were identical: current branch, HEAD, `refs/heads/main`, raw
HEAD file, index bytes/metadata, status paths, all other refs, FETCH_HEAD, and all nine file hashes.
Index SHA-256: `c4d83fbd8c9099287c05c34b5cc37f9d1faa07aaa7408f67aebf56a753b382d2`.
NUL-delimited porcelain status SHA-256:
`d99b7d21f8afc33b57689e4b7eff55a42c0b7edd44cc739d6519faf6a76da580`.
Each provenance file's content hash equals its filename stem, unchanged before/after.
Git optional locks, fsmonitor, hooks and automatic maintenance were disabled; no main/index/
worktree update, integration-owner takeover, merge, test or build occurred.

Exact remaining untracked paths:

```text
data/feeds/nvd/provenance/sha256-043a85b6911198e6/27749a75513307c695d4bfac76bd00964058a236416492321269cc7b201c0362.json
data/feeds/nvd/provenance/sha256-1469bd3d33eb4026/7eca6c16e6e826c04ed9032e1d332c74eb5d71be9af14ee5a099362caf714fc4.json
data/feeds/nvd/provenance/sha256-82b0d4a335e49053/a722a111f0f5416a884f49af7f066a940113b05c3489b9d5aaa419b9f9056672.json
data/feeds/nvd/provenance/sha256-a4372f6ee319d62c/4ab663164a8322e5a9c8c94acfa1eb425a338a41de000b3f53929446c058f8f7.json
data/feeds/nvd/provenance/sha256-c9b29a6b2c3d3dd9/c5b5c84591dc83c927ce30aad2c814bbee593f1df526f4fed7efbd352c844923.json
data/feeds/nvd/provenance/sha256-ddc9f6d711fe276d/23b33002ad1633fcfca3a3f90fc4082ef79e305996eecd007d69a87d6628a693.json
data/feeds/nvd/provenance/sha256-dfa1d05817d8d858/b5abd3ac85a3600c288246ab89452191ed158b76d9d855615286df4d3b246456.json
data/feeds/nvd/provenance/sha256-dff574e49f810a38/48bdb2882c2e120c2fb767e05ba5c7977b893afd3db6b63d293848b4240853d6.json
data/feeds/nvd/provenance/sha256-e38cf684c7b1a798/aeb9c8c99f014ff413e786c1a75258b0bde11a19a424e8f72f96b264b226de91.json
```

**WSL-main landing remains blocked, not complete.** The preserved ready commit is present in the
WSL repository but is not an ancestor of its unchanged `main` (ancestry exit 1). An authorized
data-custody resolution or an explicit, preservation-only exception to the dirty-main gate is
needed before advancing that master. The Windows landing and passing Linux unit results are not
represented as WSL-main synchronization or as passing the unrun manual validation suites.

### Provenance-closure follow-up while the master gate is blocked

Four additional focused regressions exposed concrete gaps in the initial implementation:
a repaired job selected an old shared computation despite changed measured code; an unaffected
predecessor reused after its original release snapshot was removed; an explicitly named missing
build dependency was silently omitted; and the Docker build had not copied the declared recipe
and locks into the release generator's root.

The reproducer command was:

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py::test_repair_does_not_relabel_an_old_shared_computation_as_new_code \
  tests/test_repair_admission.py::test_missing_original_release_evidence_rejects_predecessor_reuse \
  tests/test_repair_admission.py::test_explicit_release_dependency_cannot_be_silently_missing \
  tests/test_repair_admission.py::test_application_image_stages_declared_release_inputs \
  --basetemp=test/tmp/recovery-provenance-closure --tb=short
```

It failed all four cases in **5.875 s**. The fixes add a repair-scoped shared-computation admission
guard, verify original release evidence independently of customer artifacts, follow reused
computation origins during resume/publication, refuse incompatible named-cache legacy fallbacks,
reject missing literal build dependencies, and stage the required recipe/locks before generating
the image's manifest. The manifest also covers non-Python package resources, bundled container
assets, reference fixtures and all scripts. No model-loop or public cache API was redesigned.

Focused follow-up commands, still on the changing development tree:

```sh
.venv/bin/python -m pytest -q tests/test_repair_admission.py tests/test_repair_dagster_contract.py \
  tests/test_job_runtime.py tests/test_handoff_interchange.py \
  --basetemp=test/tmp/recovery-provenance-closed --tb=short --maxfail=4
.venv/bin/python -m pytest -q tests/test_repair_admission.py \
  --basetemp=test/tmp/recovery-shared-admission --tb=short
```

Results: **168 passed in 81.106 s**, followed by **54 passed in 32.292 s** after adding compatible
cache reuse, bypassed-publication rejection, actual shared-producer dependency and named-cache
regressions. The expanded real source manifest covered **1,612 files/46 jobs** in **23.707 s**
at that intermediate state. Final committed verification is recorded below when complete.

Package03 subsequently reported a second independent WSL-master blocker: an existing
`.git/rebase-apply` operation with 19 state files and `applying`. Its read-only metadata showed
`next=1`, `last=1`, `abort-safety=78f43d9d1d5802e6b2ed4a9354d432e3749baee9`, and a leading mailbox
header for `abb49695449d8f6c66859755d7c31dcaa7105d79`. That October 27 capacity-overlay commit is
already an ancestor of WSL main, but this does not authorize clearing someone else's operation.
Neither this session nor its integration worker ran `git am` or changed those state files.
Its owner must resolve that operation; an untracked-file exception alone would not permit
landing. The nine provenance files remain protected.

The provenance-closure fixes are committed at
**`61162de502ea75c8d8a9be3a151f9a2325a82756`**, tree
**`950504c9a8761c8bf38a3b592889be21eb1e7226`**. The final frozen-tree command below passed
**333 tests in 248.126 s**, with the same two independently proven baseline failures explicitly
deselected. The worktree was clean before and after; no integration, acceptance or live test ran.

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py tests/test_repair_dagster_contract.py tests/test_job_test_selection.py \
  tests/test_job_runtime.py tests/test_handoff_interchange.py tests/test_review_run_cli.py \
  tests/test_wave1_resume.py tests/test_runtime_launch.py \
  tests/test_source_history_analysis.py::test_job_binds_mainline_history_ranks_by_sii_and_feeds_the_plan \
  tests/test_shared_artifacts.py::test_same_request_can_preserve_different_results_and_pins_selection \
  tests/test_shared_artifacts.py::test_concurrent_writers_deduplicate_without_rebinding_receipts \
  tests/test_shared_artifacts.py::test_interrupted_publication_retains_complete_bytes_and_retries_idempotently \
  tests/test_shared_artifacts.py::test_missing_or_tampered_shared_state_never_silently_recomputes \
  tests/test_shared_artifacts.py::test_publication_rejects_noncanonical_or_escaping_paths \
  tests/test_shared_artifacts.py::test_publication_and_consumption_reject_symlinks_even_with_matching_bytes \
  tests/test_shared_artifacts.py::test_wrong_existing_object_bytes_are_never_overwritten \
  tests/test_shared_artifacts.py::test_partial_write_never_publishes_and_retries_without_deleting_evidence \
  tests/orchestration/dagster/test_definitions.py::test_definitions_reject_registry_config_drift \
  tests/orchestration/dagster/test_definitions.py::test_job_level_disabled_setting_is_transparent_to_dagster \
  tests/orchestration/dagster/test_definitions.py::test_environment_dependency_is_required_or_transparently_disabled \
  tests/orchestration/dagster/test_definitions.py::test_owasp_follows_tag_cloud_and_precedes_hunt_in_both_graphs \
  --deselect=tests/test_wave1_resume.py::test_catalog_path_index_accepts_structured_inventory_gaps \
  --deselect=tests/test_runtime_launch.py::test_every_registered_job_outside_the_target_set_is_named \
  --basetemp=test/tmp/recovery-final-61162 --tb=short --maxfail=4
```

Configured Ruff checks passed on all changed Python paths (**0.105 s**), and the affected public
Job mypy check passed (**3.015 s**). Two real source-release generations produced identical
canonical bytes over **1,612 files/46 jobs** in **44.898 s**, with identity
`b52f5b59d8c3fa0bcbd9d5084feba93089c110dc435db1d4691dc51d7bbc4fd5`.

The narrowly necessary additional implementation surfaces are `runtime/handoff.py` and
`storage/shared.py`. The latter's previously committed CRLF bytes were normalized to the required
portable LF while adding the guard; ignoring end-of-line differences shows only 20 added logical
lines in that file. No byte-pinned rule pack, fixture or customer artifact was normalized.
This follow-up does not relax either WSL-master blocker.

The verified closure follow-up landed on Windows main at
**`cebb231b80582da9f9dc49be0e87aa774d160243`**, tree
`9c9926d107243f9a6270e2e5868d57c49ddc06b6`, by exact fast-forward from `455ea837`.
The existing exclusive gate was held
`2026-11-06T13:14:59.5438092Z`–`2026-11-06T13:15:05.4939744Z`; branch, clean status,
ancestry, exact file bytes, LF and diffcheck were verified and the lock was released in `finally`.
Package03's integration worker confirmed no competing Windows reservation or freeze.

The same commit was preserved in WSL **only** at `refs/remotes/package-01/ready`, with an
expected-old fast-forward from `455ea837`. The verified bundle SHA-256 was
`b4c74e8c2cd13ac68f6773440f1e5e32945edd0903297cce3de75ceb4ca6ffd8`.
WSL main/HEAD remain `dc263b30`; index, exact nine-file status and all provenance hashes,
unrelated refs and FETCH_HEAD remained unchanged. All 19 existing `rebase-apply` files and
directory metadata were also protected and unchanged. Their aggregate content identity
(SHA-256 of sorted compact JSON mapping relative paths to content SHA-256s) is
`07066a87f115d9a89241982d322853d45c2890750ffb4947f51383f487606412`.
No am/rebase control command or WSL-main update occurred. Ready ancestry to WSL main still
returns 1. The master landing remains blocked, not completed.

The development selector's shared `recovery-admission` contract now includes the eight new
provenance-closure cases as exact selectors (14 shared cases total), without relabeling generic
coverage as handler-specific coverage. The document-issue handler gap and manual mappings remain
unchanged. Its isolated verification command passed **104 tests in 5.762 s**:

```sh
.venv/bin/python -m pytest -q tests/test_job_test_selection.py \
  --basetemp=test/tmp/job-test-selection-66e4291a-shared-coverage-01
```

That selector verification did not execute the mapped recovery cases or any integration,
acceptance or live suite. Only selector metadata/tests/documentation changed after the frozen
runtime verification above.

### Superseding six-package integration and Windows/WSL parity

The user subsequently requested all six named packages on both local mains, with a local commit
and no agent push. This section supersedes the earlier unresolved-landing status without
removing its historical receipts.

The conflict-free combined merge is **`dc44a6528aa4472d54b39c8f9d1b921c1f2e5f8b`**, tree
**`d6b6422a459e885b12c4d2da33ef0cba3a45e27d`**. It was authored and verified in the isolated
Ubuntu-22.04 worktree `/home/wsollers/appsec-worktrees/six-package-integration-a29d9039`,
with its own Linux virtual environment and editable installation. Its parents are the final
Operations candidate and the final Bounded Worker candidate. All six owner-confirmed ready tips
are ancestors of the merge:

| Package | Ready commit |
| --- | --- |
| Recovery and repair admission | `b561817f578133bc0ecb578faa7951337eb7e65a` |
| Operations and quality tracking | `5170d7e61fab7dee681b76381e2ec795ffedb5d9` |
| Bounded worker execution | `5fda13d78286f1d0f4f6c254c12ed0298e5d2399` |
| Worker prompt contracts | `dc263b305e500df398b19398260e619253e855a7` |
| Operator MCP and development skills | `a79fe222e95d57fb336c7b18c557509089e52672` |
| Development quality gates | `0d2c6d7b8830436bda7eed3e2c66f89c6525a17d` |

The user explicitly approved both custody resolutions:

- Back up the stale WSL `git am` operation, then use `git am --quit`, not `--abort`, without
  changing HEAD, the index or the worktree.
- Preserve the nine untracked NVD provenance files in place during a non-overwriting
  fast-forward, as an exception limited to those exact files, with backup and before/after hashes.

Before quitting, stable patch ID `5b5d6dcb776d1ae8adec0e414f61e8d53ad55f99` was independently
verified against both existing WSL-main ancestors
`c13bfe94ddec7530e8fa0bbfe67fa3bf4785869f` and
`abb49695449d8f6c66859755d7c31dcaa7105d79`. All 19 operation files and nine provenance files were
backed up and byte-verified under
`/home/wsollers/projects/appsec-review/.git/appsec-integration-backups/a29d9039-20261106`.
Its `receipt.json` records unchanged HEAD/index/status/provenance/other refs across the quit.
No reset, abort, skip, continuation, stash, provenance relocation or ignore-rule change occurred.

Combined-tree verification ran this exact focused unit command at `dc44a6528`:

```sh
.venv/bin/python -m pytest -q \
  tests/test_repair_admission.py \
  tests/test_repair_dagster_contract.py \
  tests/test_job_test_selection.py \
  tests/test_job_runtime.py \
  tests/test_handoff_interchange.py \
  tests/test_review_run_cli.py \
  tests/test_wave1_resume.py \
  tests/test_runtime_launch.py \
  tests/test_source_history_analysis.py::test_job_binds_mainline_history_ranks_by_sii_and_feeds_the_plan \
  tests/test_shared_artifacts.py::test_same_request_can_preserve_different_results_and_pins_selection \
  tests/test_shared_artifacts.py::test_concurrent_writers_deduplicate_without_rebinding_receipts \
  tests/test_shared_artifacts.py::test_interrupted_publication_retains_complete_bytes_and_retries_idempotently \
  tests/test_shared_artifacts.py::test_missing_or_tampered_shared_state_never_silently_recomputes \
  tests/test_shared_artifacts.py::test_publication_rejects_noncanonical_or_escaping_paths \
  tests/test_shared_artifacts.py::test_publication_and_consumption_reject_symlinks_even_with_matching_bytes \
  tests/test_shared_artifacts.py::test_wrong_existing_object_bytes_are_never_overwritten \
  tests/test_shared_artifacts.py::test_partial_write_never_publishes_and_retries_without_deleting_evidence \
  tests/orchestration/dagster/test_definitions.py::test_definitions_reject_registry_config_drift \
  tests/orchestration/dagster/test_definitions.py::test_job_level_disabled_setting_is_transparent_to_dagster \
  tests/orchestration/dagster/test_definitions.py::test_environment_dependency_is_required_or_transparently_disabled \
  tests/orchestration/dagster/test_definitions.py::test_owasp_follows_tag_cloud_and_precedes_hunt_in_both_graphs \
  tests/test_operations_reporting.py \
  tests/test_operations_quality.py \
  tests/test_operations_retention.py \
  tests/test_pipeline_log.py \
  tests/test_operation_telemetry_gaps.py \
  tests/test_pytest_default_collection.py \
  tests/reporting/test_telemetry_inputs.py \
  tests/test_bounded_execution.py \
  tests/review/test_cells.py \
  tests/review/test_bounded_cells.py \
  tests/review/test_result_cache.py \
  tests/review/test_lead_triage.py \
  tests/review/test_budget.py \
  tests/review/test_budget_reservations.py \
  tests/review/test_execution_budget_wiring.py \
  tests/test_model_recording.py \
  tests/test_inference.py \
  tests/test_claude_cli_inference.py \
  tests/test_copilot_inference.py \
  tests/test_anthropic_inference.py \
  tests/test_inference_transport_failures.py \
  tests/test_bounded_worker_adapters.py \
  tests/test_poc_writer.py \
  tests/test_remediation_models.py \
  tests/test_native_inference_runtime.py \
  tests/test_build_topology_feedback.py \
  tests/test_post_build_security_assessment.py \
  tests/test_owasp_evidence_binding.py \
  tests/test_dependency_intelligence.py::test_model_resolution_is_validated_and_never_exact \
  tests/test_dependency_intelligence.py::test_native_inference_is_injectable_and_pins_registered_guidance \
  tests/test_worker_prompt_contracts.py \
  tests/test_capability_artifact_cards.py \
  tests/test_review_model_request.py \
  tests/test_review_data_indexing.py::test_model_recordings_written_by_a_parity_walk_are_claimed_not_unaccounted \
  tests/review/test_team_handler.py::test_blue_cells_never_see_each_other_and_the_verifier_is_blind \
  tests/review/test_team_handler.py::test_a_distinct_verifier_profile_is_recorded_without_changing_independence \
  tests/review/test_team_handler.py::test_provider_and_schema_failures_are_typed_gaps_with_terminal_records \
  tests/review/test_team_handler.py::test_budgets_end_cells_not_launched_or_timed_out_and_are_never_retried \
  tests/review/test_team_handler.py::test_rerunning_a_team_reuses_every_succeeded_cell \
  tests/review/test_team_handler.py::test_resuming_exhausted_team_reconstructs_prior_claims_without_new_calls \
  --basetemp=test/tmp/six-package-units-a29d9039 --tb=short --durations=10
```

Result: **1,334 passed, 2 failed, 1 warning**, pytest 445.48 s, wall **447.880 s**, exit 1.
No tests were skipped or deselected. The two failures are exactly the unchanged baseline failures
independently reproduced above: the `node_modules` inventory-gap assertion and the outdated
explicit target-independent-job set. Their assertions remain intact; this is not a claim that
all repository tests pass. The existing fork deprecation warning also remains visible.
No new cross-package failure was observed in this selection.

The existing static gate ran separately:

```sh
.venv/bin/python -m tools.quality check --static-only \
  --base b561817f578133bc0ecb578faa7951337eb7e65a
```

It passed in **35.730 s**, scanning **668 modules** with **zero new diagnostics** and
47 individually baselined legacy findings. Component times were Ruff 0.208 s, mypy 11.360 s,
Bandit 18.015 s and architecture 5.639 s. The isolated checkout stayed clean after both commands.
Exact commands, elapsed times and log hashes also remain in the integration session's
`six-package-units.json` and `six-package-static.json` receipts.

Under the existing Windows exclusive-file gate and WSL advisory gate, actual WSL `main` was
fast-forwarded from `dc263b305e500df398b19398260e619253e855a7` to the verified `dc44a6528` merge.
Actual Windows `main` was then fast-forwarded from `b561817f` to the **same full commit and tree**,
using a local Git bundle rather than requiring an intermediate push/pull. Both remained on
`main`; every ready tip above was rechecked as an ancestor of both. Windows status was clean.
WSL tracked status was clean and its exact nine approved untracked files remained byte-identical.
Their parent paths did not intersect any incoming change. Unrelated refs and FETCH_HEAD were
preserved; the stale `rebase-apply` state remained absent.

The operations fixture `tests/fixtures/operations-quality.json` retains its committed CRLF bytes
because `tests/fixtures/**` is byte-pinned with `-text`. Ordinary whitespace checks passed on all
other changed paths; the fixture passed with `cr-at-eol` recognized, without suppressing other
whitespace errors or normalizing its bytes. Changed Windows files matched their committed blobs.

This appended receipt is documentation-only after the verified runtime merge. **Windows/WSL
local-main parity is now achieved; the earlier blocked entries are historical.** Both locks were
released. No push, pull request, live review, deployment or image build occurred.
**Integration, acceptance and live validation remain NOT RUN.**
