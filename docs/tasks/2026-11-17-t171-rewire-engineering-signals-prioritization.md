---
title: "Task plan T-171: Rewire change context test coverage and profile data into review prioritization"
kind: "task"
subsystem: "review inference and guidance"
status: "current"
jobs: ["job_change_context_analysis", "job_inference_security_review", "job_profile_data", "job_review_data_indexing", "job_review_prioritization", "job_source_history_analysis", "job_test_coverage"]
last reconciled: "5dddbe5dd49bb7c5b3202b56802a1f9c1c2aaa73"
---
# Task plan T-171: Rewire change context test coverage and profile data into review prioritization

This plan implements **T-171** (`docs/TODO.md`): wiring orphaned engineering-signal producers
(`job_change_context_analysis`, `job_test_coverage`, and `job_profile_data`) into
`job_review_prioritization`, scaling `job_source_history_analysis` hotspot bounds proportionally to
repository size, and introducing an explicit **SAST-silence hunt boost** so Lane B focuses on
high-exposure, under-tested code where static rules went silent.

**History as-built clarification (T-5229):** the proportional default proposed below was not
made the job's shipped default. `HistorySettings.proportional_ratio` defaults to `None`, the
shipped TOML profiles leave it unset, and the job explicitly passes that value to selection.
Fixed `hotspot_count` therefore remains the default; proportional selection is opt-in.
This clarification changes no configuration or behavior and does not reopen T-171.

## Problem and motivation

- Our 47-job functional audit found three producers executing without influencing prioritization:
  - `job_change_context_analysis` (PR/commit deltas, recently modified files) was consumed by zero
    downstream jobs;
  - `job_test_coverage` and `job_profile_data` published line-coverage and hot-path datasets that
    `job_review_prioritization` did not declare or weight.
- `job_source_history_analysis` used a fixed `max_hotspots = 250` cap, starving large codebases
  while over-selecting noisy churn in tiny smoke repositories.
- `job_review_prioritization` boosted files with high SAST counts, inadvertently **deprioritizing**
  complex authentication, parser, state-machine, and RPC entry points where SAST had no matching
  syntactic rule—the exact blind spots Lane B exists to hunt!

## Technical design and dataflow changes

1. **Contract rewiring via `accepted_upstream` (`job_review_prioritization`):**
   - Declare optional accepted inputs in `job_review_prioritization`'s typed `Job.contract` for
     `job_change_context_analysis`, `job_test_coverage`, and `job_profile_data` (alongside existing
     `job_source_history_analysis`, `job_code_graph_index`, and scanner/dependency handoffs).
   - Enhance `job_change_context_analysis` diff classification to flag **security-guard mutations**
     (removed/weakened auth decorators, bounds checks, CSRF/CORS middleware, crypto primitives, or
     unsafe/FFI blocks).
2. **Proportional hotspot scaling (`job_source_history_analysis`):**
   - Compute effective hotspot cap as `min(max(min_hotspots, ceil(hotspot_fraction * first_party_files)), max_hotspots_ceiling)`
     (default `hotspot_fraction = 0.10`, floor `50` for small targets, ceiling `2000` for large
     monorepos) while keeping configured explicit overrides deterministic.
3. **Dual-score prioritization (`lead_triage_score` + `sast_silence_hunt_score`):**
   - Compute separate explicit scores per unit/file:
     - **`lead_triage_score` (Lane A):** weights critical/high corroborated scanner clusters,
       `codeFlows` presence, reachable CVEs, guard-removal deltas, and runtime hotness.
     - **`sast_silence_hunt_score` (Lane B):** boosts first-party units combining
       `entry_point_or_trust_boundary_exposure + dangerous_sink_or_auth_state_complexity + low_or_zero_sast_hits + low_line_coverage + recent_change_or_bugfix_churn`.

## Schema and telemetry specification

```text
New / updated versioned schemas:
- appsec-review/change-context-signals/2   (adds guard_removal_signals[], touched_security_surfaces[])
- appsec-review/review-prioritization/2    (adds lead_triage_score, sast_silence_hunt_score, signal_contributions{})

Telemetry & metrics recorded per attempt:
- prioritization.units_scored, prioritization.sast_silence_boosted_units,
  prioritization.change_context_signals_applied, prioritization.coverage_signals_applied,
  prioritization.profile_signals_applied, history.proportional_hotspot_cap
```

## Seven-point acceptance criteria

1. **Documentation & dataflow updates:** Update [`../operations/review-prioritization.md`](../operations/review-prioritization.md),
   [`../operations/change-context-analysis.md`](../operations/change-context-analysis.md),
   [`../operations/source-history-analysis.md`](../operations/source-history-analysis.md),
   [`../operations/test-coverage-ingestion.md`](../operations/test-coverage-ingestion.md),
   [`../operations/profile-data.md`](../operations/profile-data.md), `docs/docs-ledger.json`, and
   regenerate `CONSUMES` / `CONSUMED BY` blocks via `scripts/generate-docs.py`.
2. **Full indexing for downstream inference:** Index `change_context`, `coverage`, `profile`, and
   v2 prioritization factor breakdowns in `job_review_data_indexing` so review cells can
   query `query_hotspots`, `coverage`, and `query_precomputed`.
3. **Fast, isolated unit tests (`<10s`):** Add unit tests under
   `tests/unit/job_review_prioritization/`, `tests/unit/job_change_context_analysis/`, and
   `tests/unit/job_source_history_analysis/` verifying `accepted_upstream` read receipts,
   guard-removal detection, proportional hotspot caps across 20-file vs 20,000-file fixtures, and
   SAST-silence hunt ranking—`<10s` per test under `-n 8 --shuffle-seed`.
4. **Common querying & indexing skills doc alignment:** Document `query_hotspots`, `coverage`, and
   prioritization signal querying in
   [`../architecture/querying-and-indexing-skills.md`](../architecture/querying-and-indexing-skills.md).
5. **Frontier prompting, roles & skills alignment:** Surface concise `signal_contributions` (such
   as uncovered entry handler or recent guard modification) in Lane B `hunter` unit context without
   biasing final verification standards.
6. **Metrics & telemetry:** Emit per-signal contribution counters and SAST-silence unit counts in
   `job_review_prioritization` telemetry.
7. **Proper schema versioning:** Validate `change-context-signals` v2 and `review-prioritization` v2
   at publication with backward-compatible replay readers.
