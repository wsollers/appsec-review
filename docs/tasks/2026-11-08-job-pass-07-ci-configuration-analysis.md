# Job pass 07 — `job_ci_configuration_analysis`

Seventh job of the pass (`docs/processes/job-pass-checklist.md`). Converts the job to typed failures
and `producer-gap/1` records (removing it from the legacy free-text gap list), fixes an undeclared
upstream read and a phantom-observation parser defect found while doing so, adds its telemetry, and
gives it runner-driven tests. Previous: `2026-11-08-job-pass-06-build-environment-analysis.md`.
Next: `job_source_history_analysis`, then `job_target_analysis_plan` (T-035/036/037).

## What the job does

Six steps. `ci_discovery` catalogs CI definitions from the accepted catalog's file inventory under
`max_files` and classifies them by provider. `ci_analysis` runs one scan unit per provider/tool branch
(`SPECS`): `discovery` branches only record that a definition exists with no linter, `static` branches
parse the definition with the reviewed static rules, `external` branches launch the pinned linter
(Zizmor, Checkov, actionlint) once per supported definition through the container executor.
`ci_normalization` normalizes each branch's raw observations; `ci_enrichment` builds the conservative
pipeline/job/step hierarchy; `ci_observation_publication` writes one immutable `observations/ci_*`
shard per branch; `ci_correlation` writes the exact-only canonical findings shard; `ci_coverage` joins
coverage and `publish_handoff` writes the handoff.

## Fixed

1. **Undeclared upstream read.** `validate` and `discover_definitions` called
   `job_evidence_collection.job.load_target_catalog`, which also reads the accepted
   `job_review_intake` handoff for the target path — an input this job's `CONTRACT` does not declare.
   Under the typed input contract every such run failed with `UpstreamNotPinnedError: undeclared
   consumption by job_ci_configuration_analysis: job_review_intake/handoff`. The loader gained
   `intake_target_root: bool = True`; this job passes `False` (it uses the graph-provided target
   root, never `ScanCatalog.target_root`). Existing callers are unchanged. `job_artifact_indexing`
   calls the same loader without declaring intake and has the same defect — its pass (T-054).
2. **Typed failure.** `CiConfigurationAnalysisFailed(RuntimeError)` for the job's own defects (no
   argv for an external tool, a normalized record without its raw artifact). Linter failures,
   unreadable definitions and exhausted bounds are gaps, never this.
3. **Gaps as records; strict job.** Every gap is a `producer-gap/1` record declared by the unit that
   found it: `producer_blocked` (retryable) when the pinned image is not on the local daemon;
   `producer_failed` scoped to the definition for a linter exception or an exit code outside the
   accepted set; `producer_reported_gap` scoped to the definition for an unreadable or
   over-`max_file_bytes` definition and for a cataloged definition with no enabled linter;
   `parser_error` for a static parse failure; `truncated` for the `max_files` and
   `max_observations_per_tool` bounds. `NOT_APPLICABLE` branches (no definitions, or none the linter
   supports) declare no gap. `strict_gaps=True`; the job leaves `LEGACY_FREE_TEXT_GAPS`.
4. **A unit declares only its own gaps.** Normalization, indexing, coverage and publication used to
   re-emit the scan's gaps (and the scan's `terminal_status`) as their own; with records the handoff
   rejects that ("declared producer gap belongs to another unit"), and with strings it double-counted.
   They now return `SUCCEEDED` with `gaps: []` and carry the scan's status and records as payload
   (`scan_terminal_status`, `scan_gap_records`; `gap_records` on classification and coverage). The
   written documents keep their human `gaps` reason lists; the handoff adds `gap_count`. The job's
   coverage disposition comes from the declaring units through the handoff.
5. **Empty linter output is not an observation.** `_generic_external_records` turned `{}` (the linter
   ran and found nothing) into one "CI linter observation" at line 1 per definition per tool, which
   then correlated across tools into a phantom finding. A record is an observation only when it names
   a rule, a message or a location (`_FINDING_FIELDS`).
6. **Settings validated at claim time.** `analysis_bounds(settings)` range-checks `max_files`,
   `max_file_bytes` and `max_observations_per_tool` in `validate` as well as in the units.
7. **Telemetry.** `CI_DEFINITIONS_DISCOVERED` (counts by provider, `max_files`, gap count), one
   `CI_TOOL_SCANNED` per branch (mode, terminal status, definition/record/gap/execution counts, image
   id), `CI_ANALYSIS_PUBLISHED` (finding count, coverage status, gap count, definitions by provider,
   artifact). No event carries definition text or linter output.
8. **`join_coverage` depends on `ci_enrichment.build_hierarchy`**, whose gaps it joins; before, the
   dependency was implicit through the index units.

## Not changed here

The static rule set, the provider parsers' recognised shapes, the hierarchy builder, the exact-only
correlation, the retrieval shard format and the MCP query surface. `job_artifact_indexing`'s
undeclared intake read (item 1) is that job's pass.

## Test audit

Before: `tests/test_ci_configuration_analysis.py` (6; 3 need `targets/appsec-multi-vuln` and skip
here) ran the job through the real `GraphRunner` on the fixture target with a `FakeExecutor` and
asserted shard shapes and MCP queries; `tests/test_tool_input_support.py` covered input support and a
single injected failure. Nothing asserted gap records, the lifecycle, the job's events, the image-
unavailable or exit-code paths, the bounds, or that an empty linter document is clean. The
`FakeExecutor` moved to `tests/ci_support.py` (shared; `stdout` is bytes or a `{tool_id: bytes}`
mapping, `exit_code` configurable) so one linter can speak while the others stay silent.

Added `tests/test_ci_configuration_analysis_job.py` (12), each a full run of intake → catalog → this
job through the real runner on a synthetic target (GitHub workflow, GitLab, Jenkinsfile, Travis):

| Behaviour | Test |
| --- | --- |
| Mixed target: every branch scanned, `NOT_APPLICABLE` branches without gaps, the Travis no-linter gap is the one record in coverage, publication `SUCCEEDED` with `gap_count` 1, handoff keeps the reason, the three events, lifecycle `COMPLETED_WITH_GAPS` | `test_a_mixed_target_publishes_definitions_observations_findings_and_coverage` |
| GitHub-only target with every linter clean: no gaps anywhere, `SUCCEEDED` | `test_a_github_only_target_with_every_linter_succeeding_is_a_clean_success` |
| Pinned image missing: `producer_blocked`, retryable, on that branch; siblings unaffected | `test_an_unavailable_pinned_image_is_a_retryable_producer_blocked_gap` |
| Linter exception: `producer_failed` scoped to the definition; siblings survive; lifecycle | `test_a_failing_linter_is_a_producer_failed_gap_and_its_siblings_survive` |
| Exit code outside the accepted set: one scoped `producer_failed` per external branch | `test_a_linter_exit_code_outside_the_accepted_set_is_a_producer_failed_gap_per_definition` |
| Checkov output parsed, severity lowered, span kept, `cio:` ids, correlated with the static rule at the same span; the silent tools produce nothing | `test_linter_observations_are_parsed_redacted_and_correlated_with_the_static_rules` |
| No CI definitions: every branch `NOT_APPLICABLE`, zero gaps, `SUCCEEDED` | `test_a_target_without_ci_definitions_is_not_applicable_everywhere_and_succeeds` |
| `max_files = 1`: `truncated` on the discovery unit, present in the coverage join | `test_discovery_bound_is_a_truncated_gap_on_the_discovery_unit` |
| `max_file_bytes = 16`: scoped `producer_reported_gap` on the static scan and the hierarchy, no records, `COMPLETED_WITH_GAPS` | `test_a_definition_over_the_file_bound_is_a_scoped_reported_gap_on_every_static_reader` |
| `max_observations_per_tool = 1`: first observation kept, `truncated`, branch `PARTIAL` | `test_the_observation_bound_keeps_the_first_observations_and_declares_truncation` |
| Out-of-range bounds refused by the validator | `test_out_of_range_bounds_are_refused_at_claim_time_not_inside_a_unit` |
| Configured topology = units; the job is strict | `test_configured_topology_matches_the_job_and_the_job_is_strict` |

`tests/test_tool_input_support.py`: the three CI tests read records (`gap["reason"]`, `scope_id`,
`gap_records`); `test_ci_supported_definition_failure_is_still_a_gap`, failing on the baseline, passes.
`tests/test_gap_contract.py`: the job moves from the legacy list to the converted set.

Coverage (`--cov=appsec_review.jobs.job_ci_configuration_analysis`, both CI test files): 93 % on
`job.py`. Uncovered: the NDJSON fallback when a linter prints one JSON document per line, an
unreadable (non-UTF-8) definition, the claim-time topology/fingerprint refusals, and the typed
failure for a tool without argv.

Commands (cloud clone, Python 3.13, no Dagster, no Docker):

```
pytest tests/test_ci_configuration_analysis_job.py -n 2                                12 passed    ~45 s
pytest tests/test_ci_configuration_analysis_job.py tests/test_ci_configuration_analysis.py
       tests/test_gap_contract.py -n 2 --shuffle-seed=7                                22 passed, 3 skipped   52 s
pytest tests/test_gap_contract.py tests/test_job_runtime.py tests/test_review_integrity_bindings.py
       tests/test_security_tagging.py tests/test_target_artifact_intake.py
       tests/test_tool_input_support.py -n 4                                            74 passed, 11 failed  114 s
```

The 11 failures are all on the baseline (`/home/claude/sweep-base.txt`; T-047) and none touch this
job; the differential against the baseline is 0 new failures.

Each runner test takes ~7 s serially (10–11 s under `-n 2` contention). A profile of one run puts
half of it in `storage.shared.safe_path` (14.7k calls per run, each a per-component symlink walk)
and the rest in the handoff's reference verification — runtime cost, not this job's. Recorded under
T-048.

Not run: integration/live (the three skipped tests need `targets/appsec-multi-vuln`; the live
linters need their pinned images).

## Carried forward

- `job_artifact_indexing` (T-054): pass `intake_target_root=False` to `load_target_catalog` or
  declare the intake inputs; today every run under the typed input contract fails as this job's did.
- T-048: `safe_path` dominates runner-driven unit tests.
