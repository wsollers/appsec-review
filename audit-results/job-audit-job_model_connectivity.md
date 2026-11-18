# Job 1/50 audit — job_model_connectivity

## Scope and verdict

- Audited checkout: `/home/wsollers/projects/appsec-review`, Ubuntu-22.04 on WSOLLERS1, through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and its WSL UNC path.
- Required and observed revision: **`3d1dc3d7304b829bd9750e359cb417661af54b9a`**, branch **main**. `git status --short` was empty before collection, before execution and at final verification.
- `.venv/bin/python` imports `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read-only functional audit. No source edits, commits, pushes, deployment/service operations, target access, real model calls or integration/acceptance/live job executions.
- **64 focused unit cases passed.** One previously recorded medium-severity normalization defect is still reproducible; two low-severity documentation discrepancies remain. No new high-severity runtime defect was established.
- This establishes bounded handler/contract behavior, not successful live provider inference or whole-job publication.

## Registration, activation and contract

`runtime/registry.py:118` registers the factory with the real `inference.check_models` callback. `appsec-review.toml:511-526` declares one worker, two steps, three tasks and a 120-second timeout. There is no job-level `settings.enabled=false`, so the job is enabled under `runtime/selection.py:11-24`. An actual registry/topology metadata inspection placed it first, with no predecessors and `job_image_pin_verification` as its immediate successor.

`jobs/job_model_connectivity/datasets.py:24-33` declares:

- Review-graph dispatch; no semantic upstream inputs; no target access.
- `always_execute=True`, `propagate_handoff=False`.
- Frozen `data/configuration/manifest.json` and `resolved.json` are the operational input. The latter's SHA-256 is verified before parsing (`jobs/job_review_intake/job.py:228-235`).
- Operational, internal, artifact-only dataset **model_connectivity**, stage **publication**, schema identifier **appsec-review/model-preflight/1**. No retrieval index or target-security evidence.
- Both actual artifact locations match declared globs:
  - `data/jobs/job_model_connectivity/attempts/*/steps/connectivity/tasks/verify_models/model-connectivity.json`
  - `data/jobs/job_model_connectivity/attempts/*/steps/publication/tasks/publish_handoff/model-connectivity-handoff.json`

Base TOML inspection, not an assessment of a live frozen run, found 12 required setting references and one disabled setting reference. The two distinct required pairs are `claude-cli/claude-haiku-5-5` and `claude-cli/claude-sonnet-5-5`; the disabled post-build assessment also references the required Haiku pair.

The image gate schedules after this job (`jobs/job_image_pin_verification/datasets.py:31`). Review-data indexing explicitly declares this job's handoff and dataset as operational inputs (`jobs/job_review_data_indexing/datasets.py:58-61`); no claim that it actually consumed a particular run's output is made.

## Complete step/task trace

All three declared tasks have handlers and dependency edges. There are no role/persona/runtime-skill bindings or review-task prompts for this job. The CLI availability prompt is hard-coded transport data, not review-worker guidance.

| Step / task | Actual implementation and output | Mismatch or coverage limit |
| --- | --- | --- |
| connectivity / resolve_models | `job.py:53-57`; shared `job_review_intake/job.py:141-183`. Verifies frozen configuration, recursively visits mapping-valued job settings, excludes pending jobs, preserves setting references, splits required/disabled references and counts unique pairs. | Direct tests cover nested tables, disabled jobs/settings, shared pairs, empty input and hash/missing-file rejection. `not_required_count` excludes pairs also required; its difference from reference-list length is intentional. |
| connectivity / verify_models | `job.py:59-87`; shared `job_review_intake/job.py:190-225`. Calls each provider once with sorted distinct names and the configured timeout; retains raw report and completion counts; only literal `True` is available; optional failures produce scoped retryable gaps; required failures raise `ModelConnectivityBlocked` after the diagnostic write. | MC-F01 affects the retained report. MC-D02 distinguishes catalog lookup from inference and opt-in first-error behavior. Safe tests inject providers; live CLI/API/SDK behavior was not exercised. |
| publication / publish_handoff | `job.py:89-103`. Depends on successful verify output, writes the summary and hash/size-bound original artifact reference, returns `SUCCEEDED` with no repeated gaps. | Both paths, schema identifiers and content hashes verified by direct tests. Full JobRunner/Dagster finalization was deliberately not executed. |

Claim-time validation (`job.py:41-51`) rejects changed step/task order, non-integer/out-of-range timeout (1–600 inclusive), and an unwired callback. `UnitExecutor` has the correct linear dependency order. Dagster projects these same units into guarded ops and calls `execute_or_reuse_unit` (`orchestration/dagster/adapter.py:250-278`).

The runner checks dependency success and result hashes before exposing outputs (`runtime/runner.py:639-669`). Control status/gap validation occurs through `runtime/handoff.py:196-205` and `interchange.py:511-550`; the latter explicitly does not validate domain payload keys. This job installs no custom output validator. The schema identifier and artifact paths are tested, but a dedicated model-preflight JSON schema was not found under `docs/schemas`.

Freshness is supported by `runtime/resume.py:80-81`, which refuses prior accepted whole-job reuse for `always_execute`. Normal unit claims start with RUN (`runtime/runner.py:327-331`); repair-admitted portable checkpoints can reuse deterministic model resolution, but verify/publication results have an `artifact` field and are nonportable (`runtime/checkpoints.py:25-41`). No stale successful availability reuse was found in this trace.

## Findings

### MC-F01 — Medium — Unrelated advertised models still change accepted-content comparison

- **Classification/confidence:** Existing functional defect; high confidence from source and an in-memory reproducer. Not new.
- **Evidence:** `src/appsec_review/inference/copilot_sdk.py:90-100` retains the entire catalog under `listed`; `src/appsec_review/jobs/job_review_intake/job.py:207-208` preserves that report; `src/appsec_review/jobs/job_model_connectivity/job.py:65-67` writes it as the published diagnostic artifact. `src/appsec_review/acceptance/normalize.py:249-263` hashes the full normalized JSON, and `:324-333` includes that signature in the compared artifact set.
- **Trigger:** The account catalog adds/removes an unrelated model while every configured model and availability result is unchanged.
- **Expected / actual:** Connectivity content comparisons should reflect configured pair identities, dispositions, errors and gaps. The unrelated `listed` entry also changes the normalized artifact digest.
- **Impact:** False baseline differences during otherwise equivalent gate replays; not evidence of a changed ability to serve a configured model. `propagate_handoff=False` limits semantic downstream invalidation and does not eliminate this comparison drift.
- **Reproduction:** Identical required pair `copilot-sdk/used`, identical `available=True`, zero gaps; changing only `listed` from `["used"]` to `["unrelated-new-model","used"]` changed normalized digest from `1d0cb49daa7c416fe3e8d4d76334bbc98ce41c9e960192f441a025d6efdc8132` to `2d92aec0fb1f89d7dc43631cc8eeb7d2d6a18596b432b1a500c98e783124da9d`.
- **Smallest recommended correction:** Separate full advertised-catalog diagnostics from compared configured-model results, without indirectly reintroducing the catalog through artifact hashes. Retain strict comparison of checked identities, availability, errors and gaps.
- **Existing tracking:** **T-057**, specifically the normalization-defect section in `docs/tasks/2026-11-08-job-pass-01-model-connectivity.md`. This audit does not change its temporary comparison exemption or any stored baseline.

### MC-D01 — Low — Architecture documentation describes superseded gate failure behavior

- **Classification/confidence:** Documentation drift; high.
- **Evidence:** `docs/architecture/jobs-and-runtime.md:498-504` says any unavailable configured model fails the gate and an unwired standalone instance reports `NOT_APPLICABLE`. Actual `src/appsec_review/jobs/job_model_connectivity/job.py:49-51,75-87` refuses unwired instances and publishes optional failures as gaps.
- **Trigger:** An operator follows the architecture page to interpret an optional-model failure or builds an unwired instance.
- **Expected / actual:** The architecture should match the required/optional split and claim-time refusal already correctly described by `docs/operations/job_model_connectivity.md:89-100,127-133`.
- **Impact:** Incorrect expectations about which failures block a review and why standalone validation fails.
- **Smallest recommended correction:** Replace the stale paragraph with the current required/optional distinction and unwired refusal; preserve intake's deliberately different behavior.
- **Existing tracking:** **T-053 is done** and records the decision to retain intake's second, self-contained check. Do not reopen that decision as a new duplicate-preflight defect. No dedicated documentation TODO located.

### MC-D02 — Low — Operations page overgeneralizes probes and optional-error handling

- **Classification/confidence:** Documentation qualification gap; high. The reproduced first-error stop is **not** classified as a runtime defect.
- **Evidence:** `docs/operations/job_model_connectivity.md:160-164` calls the checks tool-disabled connectivity requests; `appsec-review.toml:516` likewise says every model gets a live tool-disabled request. In reality `src/appsec_review/inference/copilot_sdk.py:90-100` only lists the account catalog, `inference/anthropic_api.py:184-204` uses model-list/lookup endpoints, and only `inference/claude_cli.py:308-343` makes a minimal inference probe.
- **Further qualification:** The page's unconditional non-required failure discussion (`:95-100,127-133`) omits the opt-in first-error policy. `inference/__init__.py:113-119` and `runtime/execution_safety.py:361-384` stop on a provider exception when safety is active, before the shared helper can write a provider-gap report. `orchestration/dagster/fail_fast.py:61-72` installs that scope. This agrees with `docs/operations/operator-scripts.md:297-320`, which explicitly intercepts producer failures before failure-to-gap conversion.
- **Trigger:** A catalog-only provider is selected, or an optional-only provider raises an authentication/transport exception under `--stop-on-first-error`.
- **Expected / actual:** Documentation should distinguish “listed/enabled” from “answered inference,” and state the exceptional fail-fast policy. A catalog success is not proof of inference; an optional provider exception can stop an explicitly first-error run.
- **Impact:** Operators can overinterpret availability evidence or expect a gap handoff that this launch mode intentionally prevents.
- **Reproduction:** With the real selection/check/classification functions and fake provider/admission boundaries, an optional-only provider exception yielded one optional gap with safety inactive, but `ReviewStopped` and a `model_catalog.anthropic-api` failure admission with safety active.
- **Smallest recommended correction:** Document per-provider evidence methods and link the first-error override. **Do not weaken the explicitly selected safety policy.**
- **Existing tracking:** T-147 covers undeclared task-binding metadata, not this wording. No exact existing TODO located.

## Previously reported issues and preserved boundaries

The relevant historical report sections were compared with current source rather than accepted as proof:

- `docs/reviews/system-review-2026-11-13.md`, **C13-F04**: configured model selection still does not validate supported reasoning efforts. This is a known capability-validation gap, not fresh availability evidence; no unsupported model/effort pair was tested against a provider here.
- **C13-F09**: CLI probes and Anthropic lookups still apply the timeout per request, not across the entire gate. Current architecture explicitly describes a per-request/probe bound (`jobs-and-runtime.md:503-504`); this audit does not invent a total-job timeout requirement.
- **C02-F10** describes standalone `copilot_sdk.verify`, not the registered gate path. Its current signature accepts a profile. It was not exercised or used to assert a defect in this job.
- Duplicate intake preflight is the recorded T-053 decision. Disabled-reference/shared-pair counts are intentional. Unknown generated task bindings are the existing T-147 limit.

## Validation: commands and outcomes

All shell blocks ran in the authorized WSL checkout through the brief's base64-to-bash SSH transport. No dependencies were installed.

### Environment and collection

```bash
cd /home/wsollers/projects/appsec-review
[ "$(git rev-parse HEAD)" = 3d1dc3d7304b829bd9750e359cb417661af54b9a ]
[ -z "$(git status --porcelain)" ]
unset APPSEC_REVIEW_PROFILE APPSEC_REVIEW_OVERLAY APPSEC_REVIEW_CONFIG APPSEC_HOST_PINS \
  DAGSTER_HOME APPSEC_ACCEPTANCE_ROOT APPSEC_ACCEPTANCE_RUNS_DIR PYTEST_ADDOPTS
for name in ${!APPSEC_NATIVE_@}; do unset "$name"; done
export PYTHONDONTWRITEBYTECODE=1
/usr/bin/time -f 'COLLECTION_WALL_SECONDS=%e' timeout --kill-after=3s 27s \
  .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_model_connectivity-20261118-collect \
  -p no:cacheprovider \
  tests/unit/job_model_connectivity/test_contract.py \
  tests/unit/job_model_connectivity/test_job_graph.py \
  tests/unit/job_model_connectivity/test_steps.py
```

**Outcome:** 64 cases collected in 0.34 s; wall 1.33 s; exit 0. One `PytestConfigWarning: Unknown config option: cache_dir` resulted from disabling the cache plugin, not a test failure. Collection executes no cases.

### Guarded unit execution

Same environment setup as above, plus:

```bash
export APPSEC_PYTHON="$PWD/.venv/bin/python"
/usr/bin/time -f 'VALIDATION_WALL_SECONDS=%e' scripts/run-tests.sh \
  --expect-tests 64 --parallel --test-workers 2 --shuffle-seed 20261118 --strict -- \
  tests/unit/job_model_connectivity/test_contract.py \
  tests/unit/job_model_connectivity/test_job_graph.py \
  tests/unit/job_model_connectivity/test_steps.py
```

**Outcome:** 64 passed, 0 failed/errors, 0 skips, 0 known failures; pytest elapsed **3.15 s**, wall **8.97 s**; no test exceeded 10 s. The xdist controller's environment-guard preflight ran before starting workers; it is not an extra counted test. Collection count was exactly 64; process cleanup was confirmed.

**Rejected invocation, recorded rather than hidden:** The first execution attempt used the identical command with appended `-o cache_dir=test/tmp/job-audit-job_model_connectivity-20261118-cache`. The wrapper rejected `-o` as an unsupported focused option, exit 2, wall 0.16 s; **zero tests ran**. The successful retry above used supported arguments and unchanged selectors/bounds.

**Scratch naming limitation:** The brief's job-prefixed scratch was used for explicit collection. The wrapper rejects caller-controlled basetemp/report/cache overrides, so execution necessarily used its own unique `test/tmp/tests-custom-20261117-232645-108998-69413` prefix. No guard was modified or bypassed. Retained evidence:

- `test/tmp/logs/tests-custom-20261117-232645-108998-69413.log`
- `test/tmp/tests-custom-20261117-232645-108998-69413.junit.xml`
- `test/tmp/tests-custom-20261117-232645-108998-69413.timings.sqlite`
- `test/tmp/tests-custom-20261117-232645-108998-69413.collection.json`
- `test/tmp/reports/tests-custom-20261117-232645-108998-69413.json`

After verification, only this audit's disposable fixture directory and generated host-pin fixtures were removed. The evidence files above remain. Final revision and tracked/untracked cleanliness checks passed again; unrelated root entries were left untouched.

### In-memory behavioral reproducer: optional provider and first-error policy

Ran `.venv/bin/python -` with the following body; exit 0, measured body **0.0028 s**. The provider and admission client are fake; selection, classification, inference entry point and safety operation are real. No provider, socket/controller, job or artifact publication was launched.

```python
from unittest.mock import patch
from time import monotonic
from appsec_review.inference import check_models, MODEL_CHECKS
from appsec_review.inference.errors import ProviderError
from appsec_review.jobs.job_review_intake.job import required_models, verify_configured_models
from appsec_review.runtime import execution_safety as safety
start = monotonic()
document = {'jobs': {'job_post_build_security_assessment': {'settings': {
    'enabled': False, 'model': {'provider': 'anthropic-api', 'model': 'optional-fixture'}}}}}
required, optional = required_models(document)
assert not required and len(optional) == 1
calls = []
def unavailable(names, *, timeout_seconds):
    calls.append((tuple(names), timeout_seconds))
    raise ProviderError('fixture authentication unavailable', code='authentication_missing')
class FakeAdmission:
    def __init__(self): self.requests = []
    def request(self, operation, **kw):
        self.requests.append((operation, kw))
        return {'permit': 'fixture-permit'} if operation == 'admit' else {}
with patch.dict(MODEL_CHECKS, {'anthropic-api': unavailable}):
    report = verify_configured_models(check_models, required, optional,
        timeout_seconds=1, unit_id='connectivity.verify_models')
    assert report['unavailable'] == [] and len(report['gaps']) == 1
    print('inactive safety: unavailable_required=0 optional_gaps=1')
    client = FakeAdmission()
    token = safety._ACTIVE.set(client)
    try:
        try:
            verify_configured_models(check_models, required, optional,
                timeout_seconds=1, unit_id='connectivity.verify_models')
        except safety.ReviewStopped as exc:
            print('active safety:', type(exc).__name__, str(exc))
        else:
            raise AssertionError('expected reproduction did not stop')
    finally:
        safety._ACTIVE.reset(token)
    failures = [(op, kw['action']) for op, kw in client.requests if op == 'failure']
    assert failures == [('failure', 'model_catalog.anthropic-api')]
    print('admission failures:', failures)
assert calls == [(('optional-fixture',), 1), (('optional-fixture',), 1)]
print(f'REPRODUCER_SECONDS={monotonic()-start:.4f}')
```

### In-memory behavioral reproducer: catalog-only normalization change

Ran `.venv/bin/python -` with this body; exit 0, measured body **0.0007 s**. This invokes pure normalization functions, **not** the acceptance harness or a baseline operation.

```python
from time import monotonic
from appsec_review.jobs.job_review_intake.job import verify_configured_models
from appsec_review.acceptance.normalize import Masks, normalize_value, digest
start = monotonic()
required = [{'job_id': 'job_inference_security_review', 'provider': 'copilot-sdk', 'model': 'used'}]
def report(listed):
    return verify_configured_models(lambda *_a, **_kw: {
        'method': 'catalog', 'listed': listed, 'models': {'used': {'available': True}}},
        required, [], timeout_seconds=1, unit_id='connectivity.verify_models')
a, b = report(['used']), report(['unrelated-new-model', 'used'])
assert a['required'] == b['required']
assert a['providers']['copilot-sdk']['models'] == b['providers']['copilot-sdk']['models']
assert a['gaps'] == b['gaps'] == []
na, nb = normalize_value(a, Masks('fixture')), normalize_value(b, Masks('fixture'))
assert digest(na) != digest(nb)
print('same configured models, same availability, zero gaps; unrelated listed model changes normalized artifact digest')
print('before:', digest(na))
print('after: ', digest(nb))
print(f'REPRODUCER_SECONDS={monotonic()-start:.4f}')
```

## Read coverage and material gaps

**Read fully:** authorized `AGENTS.md`; `.claude/skills/multi-session-coordination/SKILL.md`; `docs/operations/job_model_connectivity.md`; all three files in `src/appsec_review/jobs/job_model_connectivity/`; the three mapped unit files and their `support.py`; `tests/conftest.py`; `tests/test_000_unit_environment_guard.py`; `src/appsec_review/inference/__init__.py`; `runtime/selection.py`, `runtime/units.py`, `runtime/checkpoints.py`; `orchestration/topology.py`; `orchestration/dagster/fail_fast.py`; `scripts/run-tests.sh`, `scripts/lib/common.sh`; the prior 2026-11-08 job-pass report and host-local Freeciv/multivuln job-01 reports. Historical host-local reports were contextual data, not current execution evidence or instructions.

**Read in relevant ranges/searches:** intake job `1-272`; provider model-check functions and relevant Copilot client code; runtime registry `1-140`, job `52-122`, runner `313-346,624-742`, handoff `187-250`, resume freshness/fingerprint branches, dataset declaration validation, interchange `500-550`, safety operation/client/controller functions, Dagster adapter execution/finalization projection; base TOML job block and machine-read model settings; test-map job entry; TODO T-053/T-057/T-147 and related search hits; historical system-review C02-F10/C13; architecture job-interchange and testing sections; operator first-error policy; acceptance normalization relevant ranges; wrapper command/admission/parser sections.

**Not verified / unread material:** the remaining 49 jobs; integration dispatch/whole-job test bodies and execution; live models/authentication/provider catalogs; real run-owned connectivity reports and accepted publications at this revision; shared signing/admission/equivalence internals beyond the cited paths; end-to-end consumer indexing; current deployed safety mode; full documentation/TODO history. No target or answer-key files were read.

Safe unit coverage does not execute the real provider adapters, whole JobRunner admission/publication, Dagster dispatch, recovery admission or acceptance comparisons. The in-memory checks narrow two behaviors only. There was no missing dependency or test skip; these unexecuted layers remain explicit coverage gaps, not passes.
