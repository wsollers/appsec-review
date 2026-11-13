---
title: "Job pass 02 — `job_image_pin_verification`"
kind: "task"
subsystem: "images and deployment"
status: "historical"
jobs: ["job_image_pin_verification", "job_review_intake", "job_target_acquisition"]
last reconciled: "aba6bbb6bef1763a17e5bb8bc94fdd0d13e1d8d4"
---
# Job pass 02 — `job_image_pin_verification`

Second job of the job-by-job pass (fix, audit the unit tests, add tests). Advances T-047 (two
stale tests). Previous: `2026-11-08-job-pass-01-model-connectivity.md`. Next: `job_target_acquisition`.

## What the job does

Three units: `selection.resolve_pins` (every enabled `containers/catalog.toml` image not marked
`manual`, plus every enabled job's `tag`/`image_id` and `source_image_tag`/`source_image_id`
pairs, read from the run's frozen configuration), `verification.inspect_images` (`docker image
inspect` per distinct tag through an injectable runner), `publication.publish_handoff`.
`always_execute`, `propagate_handoff=False`, `strict_gaps=True`; it gates by failing. It builds
nothing; the operator rebuilds and re-pins on the host (`appsec-review update-image-pins`).

For the monorepo question: Android (`audit-buildenv-android`, SDK 35, Gradle 8.9) and PHP with
Composer (`audit-buildenv-php`) *are* pinned profiles and pass this gate. Unity is an
operator-provisioned editor image by design (T-044), iOS has no Linux image (T-036 disposition),
and the Windows/MSVC profile kind is T-041/T-042. Nothing in this job changes for those.

## Fixed

1. **The plan now hashes the catalog it read.** `image-pin-plan.json` recorded the configuration's
   SHA-256 but only the catalog's path; the existing test asserted `catalog.sha256` and had been
   failing since the fleet merge. Both inputs to the pin list are now identified.
2. **Typed failure with one `producer-gap/1` record per failing pin.** `ImagePinVerificationFailed`
   replaces a bare `RuntimeError`; the verification record carries `gaps` (`producer_blocked`,
   retryable, `scope_id` = the pin's source) beside the human-readable lines, so operator tooling
   reads which pins to fix without parsing the message. A passing record has `gaps: []`.
3. **An unwired runner is refused at claim time**, not inside `inspect_images` (same shape as job
   pass 01).
4. `schema_identity` → `appsec-review/image-pin-verification-job/2`.
5. Alignment from job pass 01: `required_models()` now uses `runtime.selection.resolved_job_is_enabled`,
   the same rule `configured_pins()` uses, instead of a local reading of `settings.enabled`.

## Test audit

Before: `tests/test_image_pin_verification.py` (16 tests) was already a real unit file: a
fixture catalog and configuration under `tmp_path`, the real `GraphRunner`, a `FakeDocker` runner
at the only external boundary; ~0.15 s per test. It covered pin selection, matched/present/missing/
mismatched/uninspectable/raising-runner, ordering in the graph, settings validation and the
Dagster composite graphs (skipped here: Dagster is not installed). One test was failing (the
catalog hash, above); two "failures" seen while running neighbours were Dagster-import tests that
skip when run alone and fail only after another file imports a Dagster stub — environment, not
the job.

Missing before, added now:

| Behaviour | Test |
| --- | --- |
| Unwired runner refused before any unit runs | `test_an_unwired_job_is_refused_at_claim_time_before_any_unit_runs` (replaces the mid-run version) |
| Typed failure; one gap record per failing pin; no handoff | `test_a_failed_pin_is_a_typed_failure_with_one_gap_record_per_pin` |
| Passing record has no gaps; plan hashes catalog and frozen configuration | `test_a_passing_record_carries_no_gaps_and_the_plan_hashes_what_it_read` |
| Failed gate → operator fixes the image → `resume` publishes a second attempt | `test_the_gate_passes_on_resume_after_the_operator_re_pins_the_moved_tag` |

`tests/test_image_pin_update.py` (the operator's `update-image-pins` CLI): one test faked
`cli.load_config` with a one-argument lambda; the CLI has passed `profile=` since the fleet merge.
Stale fixture (T-047), fixed.

Coverage (`--cov=appsec_review.jobs.job_image_pin_verification`): `job.py` 95 % (uncovered: the
topology-mismatch validator branches and the "no catalog file" / "no pins" refusals — the latter
two are worth a test when the fixture helper grows a knob for an empty catalog), `pins.py` 95 %
(uncovered lines are re-pin edit edge cases exercised by `test_image_pin_update.py` only partly).

Commands and results (cloud clone, Python 3.13, no Dagster):

```
pytest tests/test_image_pin_verification.py                                  20 passed, 2 skipped   3.3 s
   shuffled seeds 5, 99                                                       20 passed, 2 skipped
pytest tests/test_image_pin_update.py                                         8 passed              0.7 s
pytest tests/test_image_pin_verification.py tests/test_image_pin_update.py tests/test_model_connectivity.py
       tests/test_model_preflight.py tests/test_gap_contract.py tests/test_target_acquisition.py
                                                                             107 passed, 1 failed  23 s
```

The one failure is `tests/test_target_acquisition.py::test_acquisition_gate_composes_the_system_before_intake`
(`job_review_intake` decided `RUN` where the test expects `REUSE`); it fails on `fe328d76` too and
is the next job's.

Not run: parallel (`-n`, xdist absent); Dagster composite-graph tests; integration/live.

## Carried forward

- Empty-catalog / no-pins refusal tests (small; needs a fixture knob).
- Windows profile kind and daemon selection for this gate: T-041.

## WSOLLERS1 c094 run, 2026-11-10

T-051 (`e99bde016`; `2026-11-10-t051-host-local-pins.md`) replaces committed image observations
with a frozen host-pins layer. The plan is now `/2`, and job identity `/3`; image verification and
handoff remain `/1`. The pre-dispatch criterion was the exact configured set of 58 references
across 47 tags, every expected ID equal to the local observation, zero gaps/audit findings and
matching frozen hashes plus start/completion telemetry counts.

Application run `2026-11-10-0003`, dispatch `08169779-713f-468b-8ff9-74b3ed8ee1e2`, attempt 1:
Dagster `SUCCESS`, job `SUCCEEDED`, 42,589 ms. The real plan, verification record and handoff match
all 58 references, all `matched`; both pin-count events report 58. Frozen host bytes and resolved
configuration hashes match the deployed binding. The criterion held and the job was accepted
with `stepwise.py accept --job job_image_pin_verification --tag appsec-multi-vuln-c094-v1
--app-run 2026-11-10-0003`.

No live fault, image build or signing-policy change occurred. No turnaround is counted for T-057.
Next: `job_target_acquisition`; T-051 no longer blocks the run-first loop.
