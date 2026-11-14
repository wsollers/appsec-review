---
title: "Job pass 20: preserve project-relative Infer observations"
kind: "task"
subsystem: "code intelligence"
status: "historical"
jobs: ["job_cpp_compiled_analysis"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job pass 20: preserve project-relative Infer observations

This T-057 repair follows nineteen individually checked and accepted jobs in the
user-authorized scoped run `2026-11-12-0002`. Security inference and the full corpus
have not started. No image rebuild or acceptance bypass is authorized.

## Observed defect

Dispatch `3a034d7e-ac98-48ae-b26b-8d8409fd2cb0` completed
`job_cpp_compiled_analysis/attempt_0001` with gaps in 87.023 s, but was not
operator-accepted. All eight translation units were captured by Infer. The native report
contained two candidate observations:

| Native rule | Native path | Line |
| --- | --- | ---: |
| `NULLPTR_DEREFERENCE` | `source/src/main.cpp` | 58 |
| `USE_AFTER_DELETE` | `source/src/notes.cpp` | 8 |

The index contained **zero** Infer observations because `_infer_index` recognized only
absolute `/target/source/` paths, not the project-relative `source/` paths emitted by
this real execution. It retained gaps but dropped both records from retrieval.
These are tool observations, not adjudicated vulnerability claims.

Evidence is under `runs/2026-11-12-0002/`:

```text
data/cpp/projects/build-unit-adf13d8306cb272dea43/analysis/infer-run/infer-out/report.json
data/jobs/job_cpp_compiled_analysis/attempts/attempt_0001/steps/infer/tasks/projects/result.json
```

The first persisted manual rejection receipt is
`runs/metadata/stepwise/2026-11-12-0002/checks/cpp-content-attempt_0001.json`.
Its `recorded_at` is not misrepresented as the earlier discovery time.
All twenty-one dispatch workers, including the history retry, were verified stopped
before production-source edits.

## Narrow repair and tests

Normalize only the optional exact `/target/` prefix, then require `source/` and an exact
entry in the existing prepared mapping. Retain the existing source-file, symlink and
SHA-256 checks. There is no basename/suffix search, guessed project root, traversal
normalization, expanded permission or schema change.

The Infer branch identity advances to `infer-cpp-adapter/2`, and that identity is also
included in the observation-index fingerprint. Both branch checkpoints and previously
empty indices therefore invalidate without changing unrelated branch identities.

The regression uses real central configuration, `JobRunner`, the actual Infer execution
adapter/indexer and `RetrievalCore`; only the external executor is fake. It covers absolute,
project-relative and backslash forms, and rejects foreign roots, traversal and bare paths.
Assertions include captured/expected source counts, indexed observation count, target path
and source hash. The fake Infer boundary now derives its capture count from the supplied
compile database, including nested source paths.

Common command prefix:

```text
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests N --parallel --test-workers 2 --shuffle-seed 11120 --strict --
```

| Selection | Result | Elapsed / report under `test/tmp/reports/` |
| --- | --- | --- |
| `tests/test_cpp_compiled_analysis.py::test_infer_paths_resolve_only_through_the_published_source_mapping[relative]` (`N=1`, before fix) | reproduced the lost observation: zero indexed instead of one | 3.13 s; `tests-custom-20261111-204551-020447-89356.json` |
| Path regression, stable Infer compile-database test, checkpoint-release test and `tests/test_todo_registry.py` (`N=16`, after fix) | 16 passed | 5.00 s; `tests-custom-20261111-204718-436620-89399.json` |

No case exceeded ten seconds. Full compiler-analysis, integration and acceptance suites
were not run as automatic gates. Live repair acceptance still requires source-only reload,
inspection/admission of the exact compatible repair and a checked rerun.

## Recovery-context discrepancy

The Infer fix and nineteen accepted scoped-v4 keys were committed as `8aed19924`.
Source-only reload produced
`4a2dff8f7422d554e07f4fa36f14f71f317c6d9deaa4322c78959d6bd46ef610`;
the tooling image and resolved configuration remain unchanged.

The inspected repair plan
`b9ab8c1eb8527de8fb57d5575d1cca782246514409634c4286b7f8416491581d`
is admissible, but it was **not admitted**: it incorrectly reruns planning for
`planning environment availability identity changed`, invalidating its descendants.
Unlike the earlier artifact-indexing repair, there is no planning implementation or
validator change in this plan.

The saved planning claim records workflow `target_analysis_plan`, mode `EXPECTED_CURRENT`
and the exact accepted environment handoff. `plan_repair` constructs `ResumePlanner`
without orchestration; `environment_contract` therefore substitutes workflow `standalone`.
A read-only reproduction through the real environment reader confirmed that **only the
`workflow` field differs**. The producer, mode, reference, artifact and evidence are identical.
The ordinary CLI exposes no workflow option.

The candidate plan is retained at
`runs/metadata/stepwise/2026-11-12-0002/checks/infer-repair-plan.json`.
The nineteen current acceptances remain intact; no rewind or another prerequisite walk
has been started. Restoring validated frozen orchestration context is a separate recovery
tooling correction, not permission to ignore identity differences. That next change is
being brought to the user before altering recovery behavior.

## Recovery correction checkpoint

The user approved the correction, then requested committing and merging current work
for their own push. `plan_repair` now restores only the verified planning claim's
workflow/environment-selection fields. Publication, claim identity and original launch
contract checks remain mandatory; ordinary resume behavior is unchanged.

The focused command uses the guarded runner with `--parallel --test-workers 2`,
`--shuffle-seed 11121 --strict`, selecting
`tests/test_repair_admission.py::test_repair_preserves_verified_planning_launch_context`
and `tests/test_repair_admission.py::test_repair_context_does_not_authorize_changed_claim_or_environment`.

| Report under `test/tmp/reports/` | Result | Elapsed |
| --- | --- | ---: |
| `tests-custom-20261112-011820-093922-90871.json` | Single-job baseline reproduced unnecessary planner `RUN` | 11.72 s |
| `tests-custom-20261112-012224-874467-90954.json` | Six failures exposed an incorrect handoff-reference reader; replaced it with the existing verified reader | 28.76 s |
| `tests-custom-20261112-012413-850595-91022.json` | Four passed; optional-prior setup was rejected before repair and the changed-environment assertion incorrectly expected an exception instead of invalidation | 33.31 s |
| `tests-custom-20261112-012839-320019-91216.json` | Five passed: three workflow modes, changed-claim refusal and changed-environment invalidation | 35.70 s |

The retained five cases still take **11.12-12.57 s each**, above the ten-second unit
budget. Their fixture narrowing is unfinished; passing assertions do not satisfy that
timing requirement. Optional-prior restoration was not added, and its setup rejection
was not hidden with a skip or xfail. This checkpoint is not live repair acceptance.
The run remains paused with nineteen acceptances, and nothing was pushed or restarted.

The subsequent requested merge imports `origin/main` at `5ffc78e42`. Three code conflicts
were the same already-implemented input-boundary fixes plus upstream explanatory comments;
the shared fixes and comments were retained. The recovery documentation keeps both the
verified-context paragraph and the new upstream `review-recover` instructions.
The environment test fixture now uses the newly declared central release IDs rather than
inserting duplicate TOML keys.

Merged configuration/registry parity, the three overlapping job contracts, documentation
links and `git diff --check` passed. The required registry command
`.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests 5 --parallel --test-workers 2 --shuffle-seed 11122 --strict -- tests/test_todo_registry.py`
passed five cases in 2.03 s, none over ten seconds; report:
`test/tmp/reports/tests-custom-20261112-013926-168366-93340.json`.
The broader incoming changes and the known-slow recovery cases were not rerun as a merge
gate. The merged configuration and code have not been deployed into the paused review.
