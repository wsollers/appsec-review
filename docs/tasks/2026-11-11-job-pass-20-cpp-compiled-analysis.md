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
