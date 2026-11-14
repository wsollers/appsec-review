---
title: "Job pass 03 — `job_target_acquisition`"
kind: "task"
subsystem: "target acquisition and build"
status: "historical"
jobs: ["job_change_context_analysis", "job_review_intake", "job_target_acquisition"]
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# Job pass 03 — `job_target_acquisition`

Third job of the pass (`docs/processes/job-pass-checklist.md`). Advances T-047; shrinks the legacy
free-text gap list (T-038's declared-build block on system components will land here later).
Previous: `2026-11-08-job-pass-02-image-pin-verification.md`. Next: `job_review_intake`.

## What the job does

Three units: `selection.resolve_system` (the `APPSEC_REVIEW_SYSTEM` / `start --system` id against
`[[target_acquisition.systems]]` in the frozen configuration; `NOT_REQUESTED` for `--target` runs),
`acquisition.acquire_components` (`acquire_system`: components in parallel, bounded; an existing
checkout is only re-verified; the composed `targets/<system>/` root and the system manifest under
`data/target-acquisitions/<system>/`), `publication.publish_handoff`. `always_execute`,
`propagate_handoff=False`. Intake binds its external input identity to the system manifest's bytes.

## Fixed

1. **Re-verification rewrote the system manifest, so a resumed run could never reuse intake — or
   anything after it.** `acquire_system` wrote `completed_at`, each component's `action`
   (`acquired`/`verified`) and a `VERIFIED` status into `manifest.json` on every pass. Intake's input
   identity is the SHA-256 of that file, so every `resume` of a `--system` run decided
   `job_review_intake: RUN ("input identity changed")`, which re-fingerprinted the target, produced a
   new intake handoff, and invalidated every downstream job through their pinned upstream digests.
   This is the mechanism behind "a resume restarts from the top" for system-based reviews. Now the
   manifest holds only what identifies the acquired system (spec, component identities, tree hash,
   acquisition status, gaps) and is rewritten only when those bytes differ; what a pass did and when
   goes to a `verification.json` sidecar (`appsec-review/target-system-verification/1`). The failing
   test `test_acquisition_gate_composes_the_system_before_intake` (intake `RUN` where `REUSE` was
   expected) now passes for the right reason; it also needed `write_release(...)` for the two jobs,
   since reuse requires measured implementation identities (a fixture gap, T-047).
2. **Gaps are `producer-gap/1` records and the job is `strict_gaps`.** The acquisition library's
   `{path, reason, detail}` gaps become `producer_failed` (component acquisition failed, retryable)
   or `producer_reported_gap` records with `scope_id` = the component or path; the raw list is kept
   in the record as `acquisition_gaps`. `job_target_acquisition` leaves the legacy list in
   `tests/test_gap_contract.py` (42 → 41).
3. **Typed failure** (`TargetAcquisitionFailed`) when no component is available; `terminal_status`
   on every path (`NOT_APPLICABLE` when no system is requested, `COMPLETED_WITH_GAPS` for a
   `PARTIAL` system); `TARGET_ACQUISITION_COMPLETED` carries `component_count`, `verified_count`,
   `acquired_count` beside `gap_count`; the record names the verification sidecar and `completed_at`.
4. `schema_identity` → `appsec-review/target-acquisition-job/2`.

## Test audit

Before: `tests/test_target_acquisition.py` (29 tests) covers the acquisition library thoroughly —
git pinning and submodules, size bounds, Perforce digests and refusals, review exports (GitLab,
Gerrit, Azure DevOps) with drift/redirect/size refusals, system composition in parallel, user-owned
directory refusal, no-component failure — with real `git` (skipped by name when absent) and a local
HTTP server at the network boundary; 0.1–1 s each. Through the *job* it had: composes-then-resume
(failing), no-system no-op, topology order, target/system disagreement, and the Dagster mount test.
Missing: any failure path through the runner, the PARTIAL path, an unconfigured system id, and all
telemetry.

Added:

| Behaviour | Test |
| --- | --- |
| Manifest bytes stable across re-verification; sidecar records actions; two attempts' lifecycle and `TARGET_ACQUISITION_COMPLETED` counts (acquired 2/verified 0 → acquired 0/verified 2) | `test_acquisition_gate_composes_the_system_before_intake` (extended) |
| PARTIAL system publishes `COMPLETED_WITH_GAPS` with one `producer_failed` record, raw gaps kept, publication adds no gaps, event counts | `test_acquisition_gate_publishes_a_partial_system_with_gap_records` |
| No component available → `TargetAcquisitionFailed`, record kept with gap records, no handoff, `TARGET_ACQUISITION_FAILED` event, lifecycle | `test_acquisition_gate_fails_typed_when_no_component_is_available` |
| Unconfigured system id refused by name | `test_acquisition_gate_refuses_an_unconfigured_system_id` |

Coverage: `job.py` 95 % (uncovered: topology-mismatch validator branches, the `APPSEC_REVIEW_SYSTEM`
syntax refusal, the target/system-root disagreement and the "manifest changed while being recorded"
guard — the disagreement case is covered through the CLI test elsewhere; the other two are worth
two small tests when the file is next touched), `target_acquisition/acquire.py` 89 %.

Commands and results (cloud clone, Python 3.13, git 2.x present, no Dagster):

```
pytest tests/test_target_acquisition.py                                        51 passed   8.1 s
   shuffled seeds 11, 2026                                                      51 passed
pytest tests/test_target_acquisition.py tests/test_gap_contract.py tests/test_model_preflight.py
       tests/test_image_pin_verification.py tests/test_wave1_resume.py tests/test_change_context_analysis.py
                                                                               122 passed, 2 failed, 2 skipped  57 s
```

The 2 failures are `tests/test_change_context_analysis.py::{test_git_only_run_publishes_git_signals_and_names_every_missing_source,
test_external_sources_drive_review_deployment_schedule_ownership_and_function_signals}`; they fail
identically on the base commit and belong to `job_change_context_analysis` (T-047). Both also exceed
the 10 s unit budget (14.9 s, 10.9 s) — noted for that job's audit.

Not run: parallel (`-n`), Dagster mount test's live half, integration/live.

## Carried forward

- Two small refusal tests for `job.py` (system id syntax; target/system-root disagreement through the
  job rather than the CLI).
- T-038 (declared builds) adds a `build` block to `[[target_acquisition.systems]].components`; the
  manifest's `spec` already carries the component list the plan will read.

## WSOLLERS1 c094 criterion, 2026-11-10

For run `2026-11-10-0003`, the deployed `requested_system()` returns `None`; this is an existing
`--target` checkout, not a request to acquire a system. Before dispatch, target `HEAD` equals
`appsec-multi-vuln-c094-v1` (`bd69bfe83fec49155366303604475512c98c4ce6`) with no tracked changes.
The plan must say `requested: false`, `system_id: null`; the acquisition result must be
`NOT_REQUESTED`, with unit disposition `NOT_APPLICABLE`; the handoff must retain that no-op status,
no component/system manifest and no gaps. The job must succeed with complete lifecycle metrics,
without acquisition start/completion events or target mutation. A check passing alone does not
satisfy this criterion.

The criterion held. Dispatch `91e12330-0334-4b2e-af4c-eaf3b093119c`, attempt 1, succeeded in
39,415 ms; `stepwise check` reports zero gaps and audit findings. The real plan, result and handoff
record the explicit no-op, lifecycle/status/metrics agree, no acquisition events were emitted,
and target `HEAD`/tracked working files are unchanged. Accepted on `2026-11-10-0003`.
Logs: `runs/c094-target-acquisition-{run,accept}.log`.

No code defect, unit-test repair or turnaround occurred. Acceptance provenance records the
pending criterion-document edit as a dirty checkout; deployed application sources were unchanged.
Next: `job_review_intake`.
