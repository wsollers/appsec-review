---
title: "Job pass 14: catalog-only artifact input"
kind: "task"
subsystem: "scanners and evidence collection"
status: "historical"
jobs: ["job_artifact_indexing", "job_review_intake", "job_target_analysis_plan"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Job pass 14: catalog-only artifact input

This T-057 repair continues the user-authorized serial c094 walk. Run `2026-11-11-0004`
has thirteen operator-accepted jobs; the full corpus and security inference have not started.

## Failure and cause

On source `395e02fd5`, dispatch `14e5d609-f64d-49d3-866d-74d9a9e4f6c3`
started `job_artifact_indexing/attempt_0001` at 22:52:49.281754 UTC and failed at
22:53:02.185434 UTC (12.903 s). `load.accepted_builds` raised:

```text
undeclared consumption by job_artifact_indexing: job_review_intake/handoff
```

The attempt and operator check are preserved under
`runs/2026-11-11-0004/data/jobs/job_artifact_indexing/attempts/attempt_0001/` and
`runs/metadata/stepwise/2026-11-11-0004/checks/`.
All fourteen dispatch workers were verified stopped before editing; job 14 was not accepted.

The target-artifact loader needs only the accepted catalog's retained object references.
Its shared `load_target_catalog` call unnecessarily requested the intake target path.
The existing `intake_target_root=False` option, already used by CI analysis, avoids that
unused read. The one-line repair uses it; no input contract, schema, permission or integrity
check changes. Other direct callers were checked: evidence collection and CodeQL declare
the intake inputs they use.

## Focused regression

The new case uses real configuration and runner publication, real intake/catalog producers,
and recorded language-build inputs published through a fixture job. It executes the real
artifact-indexing job and checks both a produced Wasm artifact and a prebuilt target Wasm
artifact survive indexing with their proper source identity. Its observed reads must be
exactly catalog and language build, with no intake pin or read.

Common command prefix:

```text
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests N --parallel --test-workers 2 --shuffle-seed 11114 --strict --
```

| Selection | Result | Elapsed / report under `test/tmp/reports/` |
| --- | --- | --- |
| `tests/test_artifact_input_contracts.py::test_artifact_indexing_reads_catalog_without_undeclared_intake` (`N=1`, before fix) | exact live undeclared-read failure reproduced | 8.11 s; `tests-custom-20261111-180155-138790-79532.json` |
| `tests/test_artifact_input_contracts.py tests/test_todo_registry.py` (`N=13`, after fix) | 13 passed, including required-input, stale, tampered and missing-summary refusals | 9.30 s; `tests-custom-20261111-180242-167238-79576.json` |

No individual case exceeded ten seconds. No broad suite, image build or live restart was
part of those tests. The production change is one reader argument; the existing contract
and topology are unchanged, so the next step is source-only reload and inspection of the
existing repair planner, not a fabricated acceptance or topology rewrite.

## Admitted replay and current stop

Fix and accepted-key receipt commit: `8c887be79`. Source-only reload produced release
`6bfb8daf7a313d5dc0064b712f1e6ce796fb56c33c29b3cf3e52ea5d4e4a68bd`,
with unchanged image `sha256:29682648dd80ac803efe7cde0ce362098782312b7f44a1a658873823ac522d2b`
and configuration `9988548fec8e92de1c0d8ec298b2600814a4adb95b31893e680253a068cbf1d8`.
The inspected, admissible same-contract repair
`e7a41d913ad8cb0951528b2d1c81a0a062612815160b06b3a5412b00f8fc4335`
was explicitly admitted and applied with `stepwise.py recover`.
Its plan and admission receipt are in
`runs/metadata/stepwise/2026-11-11-0004/checks/artifact-index-repair-{plan,admission}.json`.

The static implementation/validator import closures invalidated history, CI and environment
analysis and their descendants. Only intake and catalog were reusable; the three readiness
gates also reran by their existing always-execute policy. Replays of jobs 1-3 and 6-8 all passed
their preserved-key comparisons with zero differences and were reaccepted. Original keys,
provenance and seeds were retained, not overwritten.

Planner replay `a1bfed24-cd63-43a5-90a8-f22e73175a7d`, `attempt_0002`,
completed successfully but its operator comparison failed at **23:36:10.450182 UTC**.
There are fifteen nonvolatile differences: the new model recipe omits
`-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, its explanation and response-byte count changed,
and plan/inherited receipt signatures differ. The full preserved comparison is
`runs/metadata/stepwise/2026-11-11-0004/checks/job_target_analysis_plan-a1bfed24-cd63-43a5-90a8-f22e73175a7d.json`.
No difference was waived and the replay was not accepted. This is a content-comparison stop,
not a running or stuck model worker.

The current accepted frontier is job 8; the original thirteen acceptances remain archived
under the admitted rewind. Job 14 has not yet rerun with the repair. A fresh scoped walk
would avoid rewriting the preserved key, but rechecking jobs 1-13 previously took about
45 minutes. Further restart direction is being requested from the user rather than silently
starting another long prerequisite walk or weakening comparison.

## Fresh-run live acceptance

The user authorized a fresh scoped walk at 19:15 EST. Run `2026-11-12-0002`
uses namespace `appsec-multi-vuln-c094-scoped-v4` on unchanged source release `6bfb8daf...`.
The history job needed one same-source retry after one unavailable GitHub page; the retry
had no indeterminate enrichment records. No source edit, reload or whole-walk restart was
used for that transient failure.

Job 14 dispatch `1b16c2b4-7915-4ddd-aa4c-e17a73a69060` completed in 41.363 s and was
operator-accepted after input/output verification. Its actual reads are exactly the
language-build and target-catalog handoffs, with no intake lookup. All ten build artifacts
are indexed. A real `RetrievalCore.find` resolves the c094 executable as
`asr:executable:63cfcce7a546defc554d4204013969fb5ed62e9b20572aaef0558970142e0918`
with SHA-256 `569b207768a1fc228d1642429657e920133ce1674705361edff69fb72bbdd347`,
160384 bytes and `analysis_lane=target`.

Five canonical gap declarations retain unknown shipment intent and ambiguous producing-action
attribution for CMake's `compile_commands.json`; neither is missing binary or compile-data
capture. The correlated compile database uses
`appsec-review/native-component-compile-database/2` with eight `entries`, not a bare JSON
array. An operator verification initially assumed an array and stopped before acceptance;
the corrected check verified the actual envelope, entry count and byte hash.

Jobs 15-19 subsequently received content acceptance with their explicit coverage limits.
Debug symbols produced 6914 records and binary-specific retrieval, but source/address/type
coverage is partial and `main.cpp.o` has unsupported ambiguous ELF sections. Coverage and
profile jobs correctly published unavailable data, not invented scores. Artifact scanning
retained two native-report-backed Blint compatibility observations. Static evidence retained
67 records (66 source-bound, one artifact-only Checkov finding); Cppcheck's C-mode diagnostic
for a C++ header was not treated as a confirmed vulnerability. Its content receipt is
`runs/metadata/stepwise/2026-11-12-0002/checks/evidence-content-attempt_0001.json`.
The next observed defect is documented in `2026-11-11-job-pass-20-cpp-compiled-analysis.md`.
