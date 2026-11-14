---
title: "T-051 - Host-local image pins on WSOLLERS1"
kind: "task"
subsystem: "images and deployment"
status: "historical"
jobs: ["job_image_pin_verification", "job_model_connectivity", "job_target_acquisition"]
last reconciled: "d622f50750ae0c1583d6dac5a0acb0643ea18bcc"
---
# T-051 - Host-local image pins on WSOLLERS1

T-051 moves host image observations out of tracked recipes before continuing T-057's c094
job-by-job acceptance loop. T-051 is complete: the implementation is committed and both fresh-run
gates are accepted against their content-level criteria.

## Cutover decision

William authorized this session to operate in the mounted Linux checkout
`/home/wsollers/projects/appsec-review`, overriding the app session's worktree-only restriction.
He separately approved implementing T-051 and starting a fresh c094 run afterward, preserving
`2026-11-10-0002` and its frozen configuration. The existing repair planner rejects configuration
changes (`runtime/repair.py`); that guard is not weakened and accepted output is not migrated.

The old run has accepted `job_model_connectivity`; `job_image_pin_verification` has a passing check
(`0e95c497-6b54-457c-bf9b-46f391fa68ca`, attempt 1), but is not accepted. No later job has run.
This is not yet a content-level verification of either job. Existing untracked acceptance files,
seeds and `data/feeds/` belong to the operator and are left alone.

The mounted checkout initially lacked `d4bec8358`, `7174b0fbe` and `b69184714`. After the Dagster
instance reported zero nonterminal dispatches, its local re-pin was rebased onto the already
fetched `origin/main` at `b69184714`. The resulting development base is `c39e88082`.
No image was built, pulled, removed or transferred.

After another session relayed a run-first priority correction, William was asked directly whether
to preserve this partial work separately and resume the old loop, or finish the cutover. He selected
"Finish the T-051 cutover before resuming jobs". After this bounded prerequisite, the parent runs
jobs serially; an observed failure selects a dedicated job-specific repair context and its focused
unit tests. Upstream defects are repaired upstream and followed forward, not papered over by
changing downstream expectations. Unrelated baseline failures do not select work.

The C094 job acceptance session released ownership. The Host operations design session owns
an unpublished documentation proposal at `2d67dfa81fffec184b1345c98231ed07fc9528d2`.
Its proposed T-060 and design file are outside this implementation. When integrating that
proposal, preserve this explicitly approved fresh-run cutover rather than promising uninterrupted
reuse across the configuration change.

## Correctness criterion before the new image-pin gate

For c094 on WSOLLERS1/default, every enabled, non-manual catalog image and every enabled job image
reference must have a frozen host binding. Each distinct tag must resolve to that exact ID;
no missing, moved or uninspectable image is acceptable. The plan must identify the frozen resolved
configuration and host-pins bytes. The verification and handoff must contain the complete selected
set, all statuses `matched`, no producer gaps, and consistent started/completed telemetry counts.
The inspected configuration selects **58 references across 47 distinct tags**, including the
enabled telemetry renderer. The host file's SHA-256 is
`f5ea6a78d4d0fc1e9adb88bd9cddff68d9608c513172c58eda994db45eef73bf`.
The host file must not affect tracked recipes or asset payload hashes, and a later host-file change
must neither rewrite the run-owned copy nor allow reuse under a different resolved identity.

CodeQL preinstalled runtime declarations must describe images actually present on this daemon;
foreign declarations are not copied from the committed configuration. An empty declared set retains
the configured derive policy rather than claiming installed runtimes exist.

## Found before implementation

- The prompt's image-pin job state was stale: its check already passed, acceptance remains pending.
- T-051 cannot be admitted as a source-only repair of the old run; a new run is authorized.
- The historical T-047 baseline named by earlier task documents is on another host. A focused
  pre-change differential was captured on this checkout; it is not the historical full-suite
  baseline and does not establish full-suite health.

## Implementation

The ignored host file is a closed, bounded `host-pins/1` document containing tag-to-ID bindings
and typed CodeQL runtime declarations. The loader merges it before typed validation, freezes
its content/hash in the resolved configuration, and the runner retains the exact original bytes.
Intake and the image gate verify the run-owned copy. A different host file changes configuration
identity and cannot overwrite or resume the old run under new bindings.

The updater inspects each tag once, validates the entire candidate configuration, rejects
missing images or stale preinstalled runtime declarations, then atomically writes only the host
file. Recipe files and payload hashes are not rewritten. Removing the host ID from the CodeQL
asset-lock metadata changes that file's aggregate hash; the configured lock hash was updated,
without changing any licensed payload, query, image or release. No query recompile is required
for this metadata-only change.

Gate, signer, preflight, build/CodeQL executors and both LaTeX consumers use the same effective
bindings. Compose mounts the selected host file read-only without creating it when missing;
submission identity records its hash. Key provisioning still works before inventory exists by
reading the typed signing policy alone. Neither image-signature enforcement nor mounted-module
signing enforcement changed. The gate's plan is `/2`, job identity `/3`; intake job identity is `/3`.

Unit sessions supply inert, deterministic host bindings under `test/tmp/`; they never inherit
this host's production pins. Installed-runtime tests use explicit synthetic declarations and
Docker boundary fakes. Empty-runtime behavior is tested separately. The live fixture opt-in
temporary re-pin was removed; those fixtures were edited but not executed.

## Focused unit receipts

All commands ran in `/home/wsollers/projects/appsec-review` using its own Python 3.12 environment,
with `APPSEC_REVIEW_PROFILE`, `APPSEC_REVIEW_CONFIG_OVERLAY` and `DAGSTER_HOME` unset.
The tested delta is above `c39e88082`; logs and JSON reports are under `test/tmp/`.

The pre-change selector was:

```bash
scripts/run-tests.sh --test-workers 4 --shuffle-seed 20261110 -- \
  tests/test_config.py tests/test_runtime_profiles.py tests/test_image_pin_verification.py \
  tests/test_image_pin_update.py tests/signing/test_cli.py tests/test_operator_scripts.py \
  tests/test_codeql_preinstalled.py
```

`--test-workers` alone does not enable xdist. The first two wrapper runs were serial; later runs
explicitly added `--parallel`. A direct `-n 4` invocation first failed because xdist was missing;
it was installed only after that failure. Coverage similarly required installing pytest-cov after
the requested `--cov` invocation was refused. Neither missing-plugin invocation ran tests.

| Invocation / artifact stem | Result | Elapsed |
| --- | --- | --- |
| Baseline, `tests-custom-20261110-120933` | 396 passed, 5 failed, 19 skipped | 165.11 s |
| `test_host_pins.py -n 4 --shuffle-seed=20261110`, base temp `t051-host-pins-first` | 7 passed, 1 new test-helper signature error | 4.98 s |
| `test_host_pins.py -n 4 --shuffle-seed=42`, `t051-host-pins-fixed` | 8 passed | 5.71 s |
| `test_image_pin_update.py -n 4 --shuffle-seed=42`, `t051-pin-update-first` | 7 passed | 3.70 s |
| Initial expanded differential, `tests-custom-20261110-123332` | 402 passed, 21 failed, 19 skipped; 16 new fixture/layer expectations corrected | 183.67 s |
| Parallel expanded differential, `tests-custom-20261110-124236` | 587 passed, 6 failed, 20 skipped; one new signing-policy parser argument error corrected | 65.58 s |
| `test_host_pins.py -n 4 --shuffle-seed=9`, `t051-host-pins-bootstrap` | 9 passed | 4.77 s |
| Coverage/differential, `tests-custom-20261110-125326` | 637 passed, 6 failed, 20 skipped; one new expected-mount assertion corrected | 82.16 s |
| `test_dagster_signing.py -n 4 --shuffle-seed=20261111`, `t051-compose-final` | 35 passed, including the corrected exact read-only mount assertion | 3.26 s |

Every direct invocation used `.venv/bin/python -m pytest -q` and
`--basetemp=test/tmp/<stem>`. No measured test exceeded ten seconds.

The final broad command was:

```bash
COVERAGE_FILE=test/tmp/t051.coverage scripts/run-tests.sh --parallel --test-workers 4 \
  --shuffle-seed 20261111 --baseline test/tmp/t051-baseline.txt -- \
  tests/test_000_unit_environment_guard.py tests/test_config.py tests/test_runtime_profiles.py \
  tests/test_host_pins.py tests/test_image_pin_verification.py tests/test_image_pin_update.py \
  tests/signing/test_cli.py tests/test_operator_scripts.py tests/test_codeql_preinstalled.py \
  tests/test_codeql_shipped_config_coverage.py tests/test_review_intake.py tests/test_dagster_host.py \
  tests/test_dagster_signing.py tests/test_container_builds.py tests/test_codeql_derived_go.py \
  tests/test_codeql_derived_native.py tests/test_codeql_derived_jspy.py \
  tests/test_codeql_derived_csharp.py tests/test_codeql_derived_java.py tests/test_todo_registry.py \
  tests/test_documentation.py tests/test_skill_separation.py \
  --cov=appsec_review.config.host_pins --cov=appsec_review.jobs.job_image_pin_verification \
  --cov-report=term-missing
```

The only new failure in that run was the exact Compose mount-set expectation. Its correction
asserts the new mount's source, target, read-only flag and refusal to create a missing source,
then retains every existing signing-mount assertion. Only that affected file was rerun afterward.
The five baseline failures were not changed: four OWASP-enabled expectations in
`test_runtime_profiles.py::test_package_budget_profile_selection_preserves_other_safeguards`
and `test_image_pin_verification.py::test_a_disabled_gate_is_transparent_to_every_composite_graph`.

Coverage: host-pins module 93%, gate 94%, pin updater/inspector 95%, combined 94%. Uncovered branches
are oversized/empty malformed host inventories, selected identity/legacy-placement refusals,
missing/malformed frozen catalog bindings, gate topology/missing-input refusals, inspection timeout,
unavailable declared runtimes and concurrent-input-change refusal. These are coverage gaps, not
proof that those branches were exercised.

The 20 named skips are 18 missing PowerShell checks, one Bash/PowerShell launcher-parity check and
one missing shellcheck check. No full-suite, integration suite or live build fixture was run.

## Host observation

`python -m appsec_review update-image-pins` and `--write`, through `.venv/bin/python`, both
inspected 47 tags with zero failures. Reports are `runs/t051-pin-plan.json` and
`runs/t051-pin-write.json`. The tracked diff's SHA-256 before/after pinning was identical
(`runs/t051-tracked-{before,after}.sha256`). The new host file declares no preinstalled runtime;
it does not copy the other host's declarations.

Target `HEAD` and `refs/tags/appsec-multi-vuln-c094-v1` both resolve to
`bd69bfe83fec49155366303604475512c98c4ce6`. No target files were changed.

## Live cutover

Implementation commit: `e99bde0160aff45c0c559f98a104f2c82ce79dd6`.
`scripts/stack-restart.sh --code-location-only` succeeded, retaining tooling image
`sha256:29682648dd80ac803efe7cde0ce362098782312b7f44a1a658873823ac522d2b`.
Mounted sources were signed and all services became healthy; no image build was needed.
The existing `copilot-prod` profile, `prod-capacity-overlay.toml`, c094 target and recording
mode were carried forward rather than silently changed. Log: `runs/t051-reload.log`.

The deployed loader reports resolved configuration
`9988548fec8e92de1c0d8ec298b2600814a4adb95b31893e680253a068cbf1d8`
and the expected host-pins hash above.

Before the new connectivity dispatch, its criterion is: both distinct required pairs
`copilot-sdk/claude-opus-5.5` and `copilot-sdk/claude-sonnet-5.5` must be checked and available;
no unavailable required pair, no gap, no failed/skipped unit, and retained lifecycle plus
model-connectivity start/completion events. Disabled references to Sonnet remain classified
as not required without hiding the same model's required use. This gate establishes availability,
not the correctness of later model inference.

Fresh application run **`2026-11-10-0003`**:

| Job | Dispatch | Result and verified criterion |
| --- | --- | --- |
| `job_model_connectivity` | `786afa1f-290f-4a4b-ab85-7f2d087d1b57` | Accepted, attempt 1, 40,211 ms; exactly the two required Copilot models available, one provider, no gaps/audit findings; lifecycle and model-completion metrics agree. |
| `job_image_pin_verification` | `08169779-713f-468b-8ff9-74b3ed8ee1e2` | Accepted, attempt 1, 42,589 ms; exact 58-reference/47-tag set, every expected ID equals the observed ID, all `matched`, no gaps/audit findings; plan/handoff/frozen bytes and telemetry agree. |

Connectivity acceptance is commit `41def63a1`. Image-pin acceptance and this completion receipt
are committed together. Logs are `runs/t051-connectivity-{run,accept}.log` and
`runs/t051-image-pin-{run,accept}.log`. The prior answer key, provenance and seed are preserved
under `runs/t051-precutover-acceptance/`; the old run tree was not edited.
No live fault or repair turnaround occurred, so this does not count toward T-057's three measured
break/fix cycles. Next job: `job_target_acquisition`.
