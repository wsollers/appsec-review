# Job pass 06 — `job_build_environment_analysis`

Sixth job of the pass (`docs/processes/job-pass-checklist.md`). Converts the job to typed failures
and `producer-gap/1` records (removing it from the legacy free-text gap list, T-047's sibling debt),
adds its analysis telemetry, and gives it runner-driven tests. Previous:
`2026-11-08-job-pass-05-target-catalog.md`. Next: `job_ci_configuration_analysis`,
`job_source_history_analysis`, then `job_target_analysis_plan` (T-035/036/037).

## What the job does

Two units in one step. `analyze_scripts` loads the accepted catalog (it must carry the claim's source
fingerprint), selects the inventory's `.sh/.bash/.bat/.cmd` scripts whose stem names an environment
(`env`, `setup`, `setvars`, `bootstrap`), reads each under the typed bounds
(`BuildEnvironmentSettings`: script count, bytes, sourcing depth, assignments, deadline), verifies the
bytes against the catalog hash, and records every `NAME=value` assignment as a declaration —
`declared` with its literal value only when the script has no context that could change it, `unknown`
otherwise, `redacted` when the name or a URL credential is sensitive — plus one bounded gap string per
construct it will not reason about. `publish_handoff` writes `build-environment.json`
(`build-environment-analysis/1`: fingerprint, catalog handoff, availability, coverage, declarations,
gaps, bounds) and the handoff. The plan consumes it through `load_environment` under the launch
contract (`EXPECTED_CURRENT`, `OPTIONAL_PRIOR`, `DISABLED`, `NOT_RUN`); its declarations are advisory
and never recipe-enforced.

## Fixed

1. **Typed failure.** `BuildEnvironmentAnalysisFailed(RuntimeError)` replaces the bare `ValueError`s
   inside the units: catalog source mismatch, missing target custody, an accepted script missing
   (now naming the path), accepted bytes changed since the catalog, the reader breaking its byte
   contract, the publication over its reader bound. The claim-time validator (topology and bounded
   settings) is unchanged.
2. **Gaps as records; strict job.** The unit result's `gaps` are `producer-gap/1` records
   (`gap_records`): `producer_reported_gap`, `scope_id` the script path for `<path>: <reason>` gaps and
   none for the global bounds, never retryable (bounded by design). `strict_gaps=True`; the job leaves
   `LEGACY_FREE_TEXT_GAPS`. The artifact keeps its own gap strings (its format; the plan reads
   `evidence.gaps` from the artifact, not from the unit result).
3. **The analysis unit's result is a payload.** `analyze_scripts` now returns
   `{"schema", "environment": value}`; its gap strings are the artifact's, not control fields, so the
   strict unit-output contract holds.
4. **Telemetry.** `BUILD_ENVIRONMENT_ANALYSIS_STARTED` (inventory files, selected scripts,
   `max_scripts`) and `BUILD_ENVIRONMENT_ANALYZED` (availability, coverage, inspected scripts,
   declaration and gap counts) beside the existing `BUILD_ENVIRONMENT_PUBLISHED` (now with the unit
   id). No event carries a script value.
5. **A test seam for the external condition.** `build_job(before_reading=...)` runs a callable after the
   catalog is loaded and before any script is read, so a test can change or remove a script under
   the accepted inventory — the only honest way to reach the bytes-changed and missing-script
   failures, since intake refuses a target that changed between runs.

## Not changed here

The plan-side reader (`environment_contract`, `load_environment`, `planning_environment_inputs`) is
unchanged; its `ValueError`s are the plan's input validation and are that job's pass.

## Test audit

Before: `tests/test_build_environment_analysis.py` (74) covers the static analysis rules, redaction,
the typed bounds, the plan-side reader and the launch contract thoroughly, and runs the producer
through the real `GraphRunner` for publication shape — but nothing drove a failure path through the
runner, asserted the lifecycle or the job's events, or checked the gap records.

Added `tests/test_build_environment_analysis_job.py` (11):

| Behaviour | Test |
| --- | --- |
| Clean scripts: `SUCCEEDED`, complete coverage, declarations, strict current reader resolves it, the three events, lifecycle | `test_clean_scripts_publish_complete_coverage_with_no_gaps_and_the_lifecycle_telemetry` |
| Bounded gaps → `COMPLETED_WITH_GAPS`; records vs artifact strings, scopes, not retryable; the secret reaches neither artifact nor pipeline | `test_bounded_gaps_are_producer_gap_records_and_the_attempt_completes_with_gaps` |
| Bytes changed under the accepted inventory: typed failure in the receipt, no handoff, no publish event, lifecycle FAILED; cause removed → resume REUSE/REUSE/RUN publishes attempt 2, lifecycle 2 attempts | `test_a_script_whose_bytes_changed_after_the_catalog_fails_the_attempt_and_resume_republishes` |
| Missing accepted script: typed failure naming the path | `test_a_missing_accepted_script_is_the_jobs_own_failure` |
| No environment scripts: `not_applicable`, no gaps, zero inspected | `test_no_environment_scripts_is_not_applicable_coverage_without_gaps` |
| Configured topology = units; the job is strict | `test_configured_topology_matches_the_job_and_the_job_is_strict` |
| Gap record scoping (5 cases) | `test_gap_records_scope_script_gaps_to_their_path` |

`tests/test_gap_contract.py`: the job moves from the legacy list to the converted set.

Coverage (`--cov=appsec_review.jobs.job_build_environment_analysis`, both files, the 12 plan-side
tests excluded): 89 %. Uncovered: the plan-side reader's integrity refusals (lines 95–232: pointer
and reference bounds, handoff/artifact/catalog identity disagreements — exercised by the plan-side
tests when they run), three analysis edges (the deadline firing inside the line loop, a non-UTF-8
script, a value over 2 KiB), and three unit guards that need an inconsistent runtime state (catalog
source mismatch, missing custody, a 16 MiB publication).

Commands (cloud clone, Python 3.13, no Dagster, no Docker):

```
pytest tests/test_build_environment_analysis_job.py -n 2                              11 passed   10 s
pytest tests/test_build_environment_analysis_job.py tests/test_build_environment_analysis.py
       tests/test_gap_contract.py -n 2                                                 79 passed, 12 failed   52 s
pytest … --shuffle-seed=<n> -n 2                                                       same set
```

The 12 failures are `test_optional_prior_host_identity_survives_direct_launch_and_reuse[*]` and
`test_unscheduled_optional_host_reference_survives_actual_graph_plan_and_run[*]`: the *plan* job
consuming this producer in `OPTIONAL_PRIOR` mode fails in `catalog_summary.load_accepted_catalog`
("consumed handoff is not the supplied immutable input: job_build_environment_analysis") — the typed
input contract rejects an optional upstream the launch deliberately omits from `upstream_handoffs`.
They fail on the baseline (`/home/claude/sweep-base.txt`, before this pass) and belong to
`job_target_analysis_plan`'s pass (T-047 attribution).

Not run: integration/live.

## Carried forward

- `job_target_analysis_plan`: optional-prior consumption of this producer under the typed input
  contract (the 12 failures above).

## WSOLLERS1 c094 criterion, 2026-11-11

For application run `2026-11-10-0003`, the accepted catalog has 344 files and handoff
`3c72fcf59141a780efde24e5d67ca65756ef72fc95094f9e40fc37c970b8106b`.
None is a supported shell/batch environment script selected by the documented
`env|setup|setvars|bootstrap` stem rule. Five cataloged PowerShell files exist:
`projects/powershell/case-{020,054,062}/run.ps1`, `scripts/build.ps1` and `scripts/smoke.ps1`.
They are unsupported data, not permission to execute Windows or target scripts.

Before acceptance, require zero selected/inspected scripts and declarations, the exact catalog
handoff and target fingerprint, and the explicit sole gap
`PowerShell environment scripts are not supported`. The expected payload is
`availability: UNAVAILABLE`, `coverage: partial`; this is not a clean or not-applicable claim.
The publication must carry that limitation as one nonretryable `producer_reported_gap` record
and complete with gaps. No missing-source, hash, parser, tool-startup or bound-exhaustion error
is acceptable. Verify the artifact hash, configured bounds (64 scripts, 262144 bytes, depth 4,
4096 assignments, 30 seconds), claim's admitted catalog pin, and all three telemetry events
against the actual payload. The target must remain unchanged.
