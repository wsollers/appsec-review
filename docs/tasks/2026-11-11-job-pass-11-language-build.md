---
title: "Job pass 11: admitted environment inputs and captured-build consumption"
kind: "task"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_build_environment_analysis", "job_language_build"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job pass 11: admitted environment inputs and captured-build consumption

This T-057 continuation follows the accepted c094 project-build pass. It retains the
T-047 rule that unchanged baseline failures are not speculative repair work. The user
authorized a serial c094 walk through document-issue analysis, stopping before security
inference, followed by a separate full-corpus walk only after the scoped checks succeed.
No push, image rebuild, capture bypass or frozen-run rewrite is authorized.

**Live result: accepted** in fresh run `2026-11-11-0004` at
2026-11-11 22:45:17.753270 UTC. The original project receipt, binary, eight compile entries
and proven enforcement were retained exactly; no second compilation or internal build
iteration ran. The operational environment read is now present in the actual input receipts.

## Observed failure and repair

On main `9e31a83233783114a8f57e1be9cdaa9c4d7c18a1`, run `2026-11-11-0003`
retained its ten accepted jobs. Dispatch `343e2a7d-114a-4457-9074-95ad26c18c1f`
launched `job_language_build/attempt_0001` at 21:47:28.315943 UTC and failed
at 21:47:41.631313 UTC (13.315 s). Its `iterations.dispatch` unit raised:

```text
undeclared consumption by job_language_build: job_build_environment_analysis/handoff
```

Resolving evidence is under
`runs/2026-11-11-0003/data/jobs/job_language_build/attempts/attempt_0001/`:
`status.json` and `steps/iterations/tasks/dispatch/status.json`.
The step's actual read receipts retain the project-build and planning handoff hashes.
The failed environment read was not converted into success or an absent-family disposition.
The operator check failed; there is no accepted language-build handoff. All eleven
dispatch workers were verified stopped with `stepwise.py recover --app-run 2026-11-11-0003`.

The execution guard loads the accepted plan, which revalidates its pinned environment
handoff. Language build omitted this transitive read from its typed input contract.
Evidence collection calls the same plan reader in its validator and scan handlers and
had the same omission. Both now declare the environment handoff and
`build_environment` artifact with **operational**, not producer-evidence, authority.
Internal build iterations inherit the language-build contract. Availability remains
conditional on the existing plan/environment modes; no integrity check or reader was
weakened.

## Focused verification

All commands used main's own Linux environment. The common runner prefix is:

```text
.venv/bin/python deploy/dagster/bin/ops.py run-tests --expect-tests N --parallel --test-workers 2 --shuffle-seed SEED --strict --
```

Reports below are in `test/tmp/reports/`; each records the complete command, selectors,
counts, logs, junit and timings. No broad suite was run.

| Report suffix | Selection / result | Elapsed |
| --- | --- | ---: |
| `tests-custom-20261111-165200-804351-74883.json` | Temporary whole-chain reproduction: exact live undeclared-read failure | 22.59 s |
| `tests-custom-20261111-165657-674452-75050.json` | Two existing capture-consumption cases passed; two new fixture setup failures | 19.11 s |
| `tests-custom-20261111-165747-615272-75112.json` | Two fixture admission failures, corrected without changing production validation | 12.67 s |
| `tests-custom-20261111-170008-425612-75167.json` | Both focused environment-reader cases passed | 10.22 s |
| `tests-custom-20261111-170143-359096-75257.json` | 12 passed; one topology assertion also fails on unchanged baseline | 20.24 s |
| `tests-custom-20261111-170252-012774-75305.json` | Isolated baseline confirmation of that same topology failure | 2.57 s |

The temporary whole-chain test took 20.42 s for its individual case; an intermediate
fixture took 10.81 s. Neither remains. The retained regression uses real configuration,
real intake/catalog/environment publication, the real environment reader and runner,
and each consumer's unchanged complete typed contract. Only unrelated upstream project
input data and the unused external-feed identity are fixtures. It checks admitted hashes,
operational authority, actual read receipts and the source-bound SDK declaration.
Existing native-consumer cases separately exercise captured build reuse and mixed-target
gaps. No final selected case exceeded ten seconds.

The final 13-case selection (seed 11112) was:

```text
tests/test_build_environment_analysis.py::test_plan_consumer_admits_and_records_bound_environment
tests/test_project_build_capture.py::test_language_job_consumes_the_authoritative_project_capture
tests/orchestration/test_topology.py::test_wave1_order_is_topological_and_closure_follows_propagation
tests/test_input_contract_admission.py::test_real_admission_and_reader_observation_are_separate
tests/test_input_contract_admission.py::test_reader_rejects_undeclared_actual_consumption
tests/test_input_contract_admission.py::test_contract_change_refuses_reuse_but_historical_bytes_remain
tests/test_todo_registry.py
```

The unchanged topology assertion expects ancestry-wide supply for change-context analysis,
but current code supplies its declared inputs. To establish attribution, only this repair's
eight production lines were temporarily removed; `git diff --exit-code -- src/appsec_review`
confirmed exact baseline runtime source, and the same isolated assertion failed. The repair
was then restored. That unrelated expectation was not changed to obtain a green report.
These focused results do not claim historical T-047 baseline completion or full pipeline coverage.

## Continuation boundary

Adding the missing inputs changes the immutable job contract/topology. The stepwise
operator refuses to continue a walk under a different topology; the supported continuation
is a fresh scoped run after source-only reload. Run `2026-11-11-0003`, its ten acceptances,
binary and failed job-11 attempt remain evidence.

Before accepting job 11 on the fresh walk, verify that its published receipt retains the
project binary, captured compile database and proven enforcement identity without rebuilding
the independent c094 unit, and that it records the newly admitted environment read. Classify
all canonical gaps and every absent-family disposition before proceeding to job 12.
Live repaired acceptance is established by
`runs/metadata/stepwise/2026-11-11-0004/checks/language-build-content-attempt_0001.json`
and the accepted operator state, separately from the unit results above.

## Repaired live walk

Repair commit `395e02fd5` was source-reloaded without rebuilding the application image.
Measured release:
`ded5204765f8878d6bf203d1f4e89895585b592a4cc31f44562ba9d195e3a9c1`.
Run `2026-11-11-0004` uses new keys `appsec-multi-vuln-c094-scoped-v3`, the same clean
target tag and fingerprint, and the same image pins. Jobs 1-10 were checked individually
again because the input contract changed; their canonical gap counts were
`0, 0, 0, 0, 28, 6, 0, 0, 18, 0`.

Job 10 compiled the binary in 17.119 s. Its SHA-256 remained
`569b207768a1fc228d1642429657e920133ce1674705361edff69fb72bbdd347`,
160384 bytes. Job 11 dispatch `54af6ffc-4a54-4161-8f4a-a12fa9eb7ef1`
took 89.239 s and published the exact project receipt, including enforcement
`b6a78309eab638c3d369e866ce722338e8b59f112f7dde117ceb83a858be3f7a`.
The binary remains in the target-analysis lane. Two canonical records report its unknown
shipment intent (`delivery_fact_unavailable`); this is not missing compiler capture or
permission to exclude the binary from analysis.

The preserved failed check on run `0003` is timestamped 21:48:11.386155 UTC.
To first repaired job-11 acceptance is **3426.367115 s (57 min 6 s)**, including
the fresh prerequisite walk, not just repair or compilation time.

Subsequent live input/output checks, on the same frozen source:

| Job | Result | Canonical gaps / evidence |
| --- | --- | --- |
| 12 Tree-sitter AST | accepted 22:48:31.208091 UTC | 12: Git exclusion and propagated generated-source/delivery uncertainty. Two untruncated C/C++ scopes parsed all nine files into 3008 nodes with zero diagnostics; every record's file hash matched source. |
| 13 change context | accepted 22:52:13.102055 UTC | 18: disabled deployment/organization inputs, missing time zone, inherited history limits and function mapping unavailable for seven non-code documents/descriptors. No unmapped contributor identities; 17 files and 21 functions represented. |
| 14 artifact indexing | stopped, not accepted | Separate undeclared intake-target-path read; see `2026-11-11-job-pass-14-artifact-indexing.md`. |

All fourteen dispatch workers were verified stopped after job 14 failed. No security-inference
or full-corpus job was launched. Unchanged jobs 12/13 received live content checks, not a claim
that their entire unit/integration suites were executed.
