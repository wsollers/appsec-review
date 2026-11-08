# Job pass 01 — `job_model_connectivity`

First job of the job-by-job pass (fix, then audit the unit tests, then add tests). Advances
T-047 (the gate's stale tests) and files T-053. Order of the pass follows the `wave1_review`
graph: model_connectivity → image_pin_verification → target_acquisition → review_intake →
target_catalog → build_environment_analysis / ci_configuration_analysis / source_history_analysis →
target_analysis_plan → project_build → language_build → sanitizer_build / artifact_indexing.

## What the job does

Three units: `connectivity.resolve_models` (every provider/model pair any job setting names, from the
run-owned resolved configuration), `connectivity.verify_models` (one tool-disabled availability
request per provider), `publication.publish_handoff`. `always_execute`, `propagate_handoff=False`,
`strict_gaps=True`; nothing consumes it — it gates by failing.

## Fixed

1. **A model named only by a disabled job or a disabled model setting no longer blocks the review.**
   The gate required every configured pair, including `job_post_build_security_assessment`'s
   `settings.model` (`enabled = false` in the repository configuration) and any job with
   `settings.enabled = false`. The earlier preflight test asserted this ("a model only a disabled
   job names still has to exist"); that decision is reversed here, deliberately: a live review must
   not stop for a model no job in the run can use. The configuration-integrity value is kept —
   every configured pair is still *checked* — but a not-required pair that does not answer is
   recorded under `unavailable_not_required` with a retryable `producer-gap/1` record and the unit
   publishes `COMPLETED_WITH_GAPS`. Only a required pair fails the gate.
   `job_review_intake.job.required_models(document)` is the single decision; both gates use it.
2. **One implementation for both gates.** `verify_configured_models(...)` in the intake module is
   called by `job_model_connectivity` and by `job_review_intake.model_preflight`; the two copies had
   already drifted in their handling of an unwired check (see T-053).
3. **An unwired check is refused at claim time.** `check_models is None` was a `RuntimeError`
   inside `verify_models` (an attempt with a traceback); it is now an input-validator refusal, so
   no unit runs. The intake copy still returns `NOT_APPLICABLE` — unchanged here, on record in T-053.
4. **Typed failure.** `ModelConnectivityBlocked(RuntimeError)`; the task receipt's `error.type`
   names it.
5. `schema_identity` bumped to `appsec-review/model-connectivity-job/2` (new output fields:
   `not_required`, `unavailable_not_required`, `gaps`, `terminal_status`).

## Test audit

Before: no test file for the job. It was exercised indirectly by `test_runtime_profiles.py` (one
happy path through `GraphRunner`), `test_model_preflight.py` (registry wiring, repeated-run
reuse), and topology/ordering tests. No test covered an unavailable model through this job, the
timeout bound, the topology validator, resume after a failed gate, or what the artifact and
handoff actually carry.

Are they unit tests? Yes by the pass's definition: the real `appsec-review.toml`, the real
`JobRunner`/`GraphRunner`, a fake only at the provider boundary (`check_models`); no Docker, no
model, no network, no target checkout; ~0.2 s each.

After — `tests/test_model_connectivity.py` (11 tests, 2.0 s):

| Behaviour | Test |
| --- | --- |
| `required_models` splits disabled jobs / disabled settings / nested tables | `test_required_models_excludes_disabled_jobs_and_disabled_settings` |
| Every configured model is checked; required/not-required split in artifact and handoff | `test_gate_checks_every_configured_model_and_publishes_the_required_split` |
| Not-required unavailable → gap record, `COMPLETED_WITH_GAPS`, handoff published, outcomes carry the gap | `test_a_missing_model_that_only_a_disabled_setting_names_is_a_gap_not_a_block` |
| Required unavailable → attempt fails, artifact kept, receipt names `ModelConnectivityBlocked`, no `latest.json` | `test_an_unavailable_required_model_fails_the_gate_with_a_named_gap_record` |
| Provider transport error reported per model from the report error | `test_a_provider_transport_error_is_reported_per_model_from_the_report_error` |
| Failed gate, provider recovers, resume publishes a second attempt | `test_the_gate_succeeds_again_on_resume_when_the_provider_recovers` |
| Unwired check refused before any unit runs | `test_an_unwired_check_is_refused_before_any_unit_runs` |
| Timeout not an int / 0 / 601 refused | `test_timeout_outside_the_bound_is_refused[string,zero,too-large]` |
| Configured steps/tasks match the job's units; job flags | `test_configured_topology_matches_the_job` |

Coverage (`pytest --cov=appsec_review.jobs.job_model_connectivity`): 97 % of `job.py`; the two
uncovered lines are the topology-mismatch validator branches, which the repository configuration
cannot trigger without a second configuration file — covered indirectly by
`test_configured_topology_matches_the_job`.

`tests/test_model_preflight.py` updated for the decision above: the "disabled-job model still has
to exist" case became "checked and recorded but never blocks"; a same-provider and a
second-provider *required* case still block; the unwired-intake and configured-count assertions
count `required + not_required`. `test_check_models_reports_provider_failures_instead_of_raising`
asserted a pre-fleet-merge error string (`RuntimeError: ANTHROPIC_API_KEY is unavailable`); the
typed `ProviderError("Anthropic API authentication is unavailable")` is the intended contract and
the assertion now follows it (T-047: stale fixture, not a regression).

Commands and results (cloud clone, Python 3.13, no Dagster installed):

```
pytest tests/test_model_connectivity.py                                  11 passed   2.0 s
pytest tests/test_model_preflight.py tests/test_model_connectivity.py     27 passed   5.4 s  (shuffled, seeds 3 and 20261107)
pytest tests/test_model_preflight.py tests/test_model_connectivity.py tests/test_runtime_profiles.py
       tests/test_gap_contract.py tests/test_job_control_schema.py tests/test_handoff_interchange.py
       tests/test_downstream_input_contracts.py tests/test_inventory_publication.py
                                                                          255 passed, 4 failed  38 s
```

The 4 failures are `test_runtime_profiles.py::test_package_budget_profile_selection_preserves_other_safeguards[*]`,
which assert `job_owasp_control_assessment.settings.enabled is False` while the configuration has
it enabled; they fail identically on `fe328d76` and belong to the review-job audit (T-047).

Not run: parallel (`-n`) — pytest-xdist is not installed here; integration/live paths.

## Carried forward

- T-053: the second model gate inside `job_review_intake` (same check, weaker unwired behaviour,
  one more live provider round-trip per run). Decide at the intake audit.
- The three `test_image_pin_verification.py` failures seen while running neighbours are the next
  job's; they fail on `fe328d76` too.
