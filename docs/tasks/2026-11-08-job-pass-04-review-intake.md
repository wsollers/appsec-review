# Job pass 04 — `job_review_intake`

Fourth job of the pass (`docs/processes/job-pass-checklist.md`). Closes T-053; advances T-047;
shrinks the legacy free-text gap list (41 → 40). Previous: `2026-11-08-job-pass-03-target-acquisition.md`.
Next: `job_target_catalog`.

## What the job does

Four independent steps and a publication: `model_preflight` (resolve/verify the configured models
— the same `verify_configured_models` as the connectivity gate), `resolve_configuration` (the base
file plus at most one runtime profile and one capacity overlay, each verified against the run's
frozen `resolved.json` and manifest), `prepare_target` (resolve, bounded inventory, fingerprint;
copies the acquisition manifest for an acquired target and names drift), `binary_evidence` (freeze
the verified decompilation publication of every configured binary), `publish_intake`
(`review-intake/1`). It is reusable on resume; its external input identity is the acquisition
manifest's and the binary publications' hashes (computed at claim time).

## Decision: T-053 — keep the intake preflight (done)

The intake's model preflight duplicates `job_model_connectivity`'s live check. It stays, for one
structural reason: the intake handoff must be self-contained to be reusable. The connectivity gate is
`always_execute` and `propagate_handoff=False`; if intake pinned the gate's handoff it would inherit
a new digest on every dispatch and never be reused — the same cascade job pass 03 removed for the
acquisition manifest. The downstream contracts (`job_target_analysis_plan`, `job_project_build`,
…) declare intake's `model_preflight` dataset as their recorded model evidence, so it is also what
the run cites. The cost is one list call per provider per fresh intake, not per resume. The two
checks share code, so they cannot disagree; the hard gate is connectivity, which refuses an unwired
claim. The intake keeps the unwired → `NOT_APPLICABLE` behaviour because 99 call sites in 39 test
files build intake without a provider check as the producer for downstream jobs; the result is now
explicit (`reason`, empty `verified`, no `MODEL_PREFLIGHT_COMPLETED` event) and a test pins it.

## Fixed

1. **Gaps are `producer-gap/1` records and the job is `strict_gaps`.** Three units produced raw
   gaps: `validate_target` (inventory `{path, reason}`), `resolve_publications` (binary
   `{kind, binary_id, …}`) and `publish_handoff` (coverage + acquisition). All are records now with
   `scope_id` = the path or binary id; the raw lists stay in the artifacts (`coverage_gaps`,
   `binary_gaps`, the acquisition manifest copy). Configured exclusions (`excluded_directory`) are
   policy, not lost coverage, and produce no record. `interchange.path_gap_records(...)` is the one
   converter for `{path, reason[, detail]}` gaps; job pass 03's acquisition job uses it too.
2. **Typed failures**: `ModelPreflightBlocked` (a required model down), `TargetIntakeError` (no
   bounded text files; target changed after resume planning). A required binary with no
   publication already refused at claim time (external input identity) and still does.
3. **`terminal_status` on every unit that can have gaps**; `MODEL_PREFLIGHT_COMPLETED` carries
   `unavailable_not_required_count`.
4. Two `__import__` calls replaced by the module's own imports; `schema_identity` →
   `appsec-review/review-intake-job/2`.

The one behaviour change a consumer can see: an intake whose target carries an acquisition gap or
a symlink/oversize coverage gap now publishes `COMPLETED_WITH_GAPS` instead of `SUCCEEDED`-with-a-
list. `tests/test_target_acquisition.py::test_review_intake_publishes_the_acquisition_record`
asserts the new status and the record.

## Test audit

Before: no file for the job. Pieces were covered elsewhere — `test_model_preflight.py` (the
preflight decision, registry wiring, reuse across dispatches), `test_runtime_profiles.py` (profile
and overlay layers), `test_target_acquisition.py` (acquisition record and drift),
`test_binary_evidence_indexing.py` (resolved publications; currently failing on the base for a
downstream contract reason, see below). Nothing drove the target step's failures, the symlink gap,
the unwired fixture behaviour, or telemetry through the job.

Added — `tests/test_review_intake.py` (11 tests, 6 s):

| Behaviour | Test |
| --- | --- |
| Success: handoff, `review-intake.json` content (target, fingerprint, frozen configuration hash, profile, preflight, binaries), no gaps, lifecycle, `MODEL_PREFLIGHT_COMPLETED` and `BINARY_EVIDENCE_RESOLVED` details | `test_intake_publishes_configuration_target_models_and_binaries_with_telemetry` |
| Reused on resume when nothing changed (one attempt) | `test_intake_is_reused_on_resume_when_nothing_changed` |
| Coverage gap records; configured exclusions are not gaps | `test_coverage_gaps_are_path_scoped_records_and_configured_exclusions_are_not_gaps` |
| Symlink → `symlink_excluded` record, `COMPLETED_WITH_GAPS`, intake still publishes | `test_a_symlink_in_the_target_is_a_named_coverage_gap_and_the_intake_still_publishes` |
| Empty target → `TargetIntakeError`, no handoff, other steps' evidence kept, lifecycle FAILED | `test_an_empty_target_fails_intake_typed_and_publishes_nothing` |
| Target changed after planning → `TargetIntakeError` at `fingerprint_target` | `test_a_target_that_changed_after_planning_fails_the_fingerprint_unit` |
| Required model down → `ModelPreflightBlocked`, evidence kept, event count | `test_a_required_model_down_at_intake_fails_typed` |
| Unwired check → `NOT_APPLICABLE` with reason, no preflight event | `test_an_unwired_check_is_recorded_as_not_applicable_not_hidden` |
| Optional binary without publication → `input_unavailable` retryable record, event counts | `test_an_optional_binary_without_a_publication_is_a_retryable_gap` |
| Required binary without publication → refused at claim, no attempt | `test_a_required_binary_without_a_publication_fails_intake` |
| Configured topology = units; strict, reusable, propagating | `test_configured_topology_matches_the_job_and_the_job_is_strict` |

Coverage: `job.py` 84 % from this file alone, 91 % with `test_model_preflight.py`,
`test_runtime_profiles.py` and `test_target_acquisition.py`. Uncovered: the resolved-binary
publication path (owned by `test_binary_evidence_indexing.py`), the configuration-layer mismatch
refusals (each a one-line `raise`; a parametrized corruption test is the natural addition), the
acquisition settings fallback when the resolved configuration is unreadable.

Commands and results (cloud clone, Python 3.13, no Dagster):

```
pytest tests/test_review_intake.py                                             11 passed   6.3 s
pytest tests/test_review_intake.py tests/test_model_preflight.py  (shuffled 7, 31)   27 passed
pytest tests/test_review_intake.py tests/test_model_preflight.py tests/test_runtime_profiles.py
       tests/test_target_acquisition.py tests/test_gap_contract.py tests/test_wave1_resume.py
       tests/test_model_connectivity.py tests/test_image_pin_verification.py tests/test_job_control_schema.py
                                                                            214 passed, 4 failed, 2 skipped  75 s
```

The 4 failures are the pre-existing `test_runtime_profiles.py::test_package_budget_profile_selection_preserves_other_safeguards[*]`
(OWASP enabled in configuration; review-job audit).

Pre-existing failures seen in neighbours and attributed:

- `tests/test_binary_evidence_indexing.py` (6): `undeclared consumption by job_binary_evidence_indexing:
  job_target_catalog/handoff` — that job reads the catalog without declaring it in its contract.
  Runtime regression from the fleet merge, not a fixture; filed as T-054.
- `tests/test_target_artifact_intake.py` (2): `undeclared consumption by job_artifact_indexing:
  job_review_intake/handoff` on the prebuilt (buildless) path — same class; folded into T-054.
- `tests/test_input_contract_admission.py::test_dagster_definition_edges_match_direct_contract_without_execution`:
  Dagster not installed here.

Not run: parallel (`-n`), integration/live.

## Carried forward

- Parametrized configuration-layer corruption tests for `resolve_layers` (profile hash, keys,
  overlay) through the job.
- T-054: undeclared consumption in `job_binary_evidence_indexing` and `job_artifact_indexing`.

## WSOLLERS1 c094 criterion, 2026-11-10

Before dispatch on `2026-11-10-0003`, the tagged target contains 348 tracked files, all bounded
text, no untracked/ignored working files and no tracked modifications. Global `.gitignore`
exclusion applies to four files (root, `projects/northwinds-v1`, `projects/php-extension/case-090`,
`projects/polyglot/case-093`), leaving **344 inventoried files**. All eleven case-094 files,
including its CMake descriptor and eight `.cpp` files plus `tool.h`/README, remain in scope.

The intake must bind `/opt/app/targets/appsec-multi-vuln-c094` and its unchanged raw source
fingerprint; record exactly 344 retained files, the four configured exclusions, complete
descriptor discovery and no coverage gaps; freeze the base/profile/capacity-overlay/host-pins
layers with matching hashes; verify both required Copilot models; and report zero configured,
resolved or unavailable binary publications. No system acquisition record is expected.
The handoff, model/binary events and lifecycle metrics must agree. These are intake criteria,
not a claim that the fixture's seven defects have been found.
