# Job 3/50 functional audit — job_target_acquisition

## Scope and outcome

- Audited **main, `3d1dc3d7304b829bd9750e359cb417661af54b9a`**, in `/home/wsollers/projects/appsec-review` through SSH `wsl-ubuntu` and the authorized Ubuntu-22.04 UNC root. The Windows default checkout was not audited or tested.
- HEAD, clean tracked/untracked status, required-base ancestry, and editable import location were checked. Python resolved `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. HEAD and cleanliness remained unchanged after validation and cleanup.
- Read-only functional audit. No repository source edits, commits, target acquisition, target execution, provider requests, models, Docker/service operations, integration/acceptance/live tests or Dagster runs.
- **Three medium findings** in the acquisition helper path, all reproduced with in-memory fake external boundaries. The three declared job handlers and their dependencies were traced.
- **88 tests passed**: 85 mapped job units plus three environment-guard tests; pytest **5.53 s**, supervised command shell **13.509 s**. Zero failures, skips, xfails, or cases over ten seconds.
- Passing these units does not establish real provider correctness, actual materialization, immutable publication through the whole runner, or live downstream output quality.

## Registration, activation and contract

`runtime/registry.py:120` registers the real factory. `appsec-review.toml:554-576` enables it and declares one worker per step, with three tasks. The typed contract (`jobs/job_target_acquisition/datasets.py:41-49`) has **no upstream semantic inputs**, `schedule_after=('job_image_pin_verification',)`, review-graph dispatch, `target_access=none`, `always_execute=True`, and `propagate_handoff=False`. The latter target-access flag means the runner does not supply an already-fingerprinted checkout; the producer itself creates/verifies the configured composed root.

Configuration selection honors `settings.enabled` via `runtime/selection.py:11-44`; CLI graph selection and `--system` refusal when disabled are at `cli.py:390-409`. Dagster filters disabled registered jobs before constructing definitions (`orchestration/dagster/adapter.py:409-411`). `orchestration/topology.py:47-83` projects scheduling/input edges, including transparent disabled vertices. No actual Dagster definition/run was executed.

Inputs are:

1. `APPSEC_REVIEW_SYSTEM`, or the explicitly injected environment, validated as an exact safe system id; absence/empty means no acquisition, never a default system (`job.py:64-71`).
2. Frozen `data/configuration/appsec-review.toml`; its exact bytes are SHA-256 bound and parsed using the repository root (`job.py:81-87`). Runtime binds and verifies this source file separately from resolved JSON (`runtime/runner.py:61-105`). Profile/overlay allowlists do not permit acquisition-table overrides.
3. Configured component pins and bounded provider settings; named credential environment values are used at provider boundaries. Existing checkout/record pairs are external operational state, not an upstream job-handoff grant.
4. Optional injected fetcher factory, used only by API review exports, not as a model/tool instruction channel.

No model, persona, role task, runtime skill, or prompt is dispatched by any of these handlers. Missing generated tool-binding declarations are the already-recorded **T-147** limitation, not evidence of an unreachable task.

## Every declared step/task

All paths below are relative to `src/appsec_review/` unless another prefix is shown.

| Step/task | Actual dispatch and processing | Inputs / outputs / validation | Observed mismatch or coverage limit |
|---|---|---|---|
| `selection.resolve_system` | Closure at `jobs/job_target_acquisition/job.py:90-111`; first unit in `:181-185`. `_validate` checks exact step/task order and unknown job settings (`:53-61`). | Reads selector and frozen TOML. Resolves configured system; checks composed-root agreement when a target was supplied. Writes `target-acquisition-plan.json`: schema, configuration path/hash, requested flag, system id; requested plans add component specs, target path and `min(max_parallel_components, component_count)`. Returns run-relative artifact/hash/size. | No defect found in this handler. Unit tests cover absence, selector syntax, unknown system, target disagreement, frozen-byte identity and malformed configuration. In ordinary target-independent launch the target-root check is not reached because the runtime supplies `None`; driver target selection is therefore also relevant. |
| `acquisition.acquire_components` | Closure at `job.py:113-168`, dependent on selection. Calls `target_acquisition.acquire.acquire_system`, then projects per-component results and canonical gaps. | Unrequested path writes `NOT_REQUESTED`, returns `NOT_APPLICABLE`, and never calls acquisition. Requested path reloads frozen settings, emits lifecycle events, writes result with raw/canonical gaps, component identities and external verification reference. Copies system manifest only when referenced/present and SHA-256 matches. Only `COMPLETE`/`PARTIAL` continue; other statuses raise typed failure after writing result. | Findings **TA-01–TA-03** are in called review-export helpers. Existing mapped units fake `acquire_system`, so they cannot expose these provider-transform defects. Hash mismatch and whole-system failure are covered at handler level. |
| `publication.publish_handoff` | Closure at `job.py:170-179`, dependent on acquisition. | Writes `target-acquisition-handoff.json` preserving result reference, optional copied manifest, status, identities, components and raw acquisition-unit gaps. Return changes `artifact` to the final handoff, adds `result`, and returns empty `gaps` so canonical outcomes are not duplicated. Publication task reports `SUCCEEDED`; acquisition task retains `NOT_APPLICABLE`/`COMPLETED_WITH_GAPS`. | No defect found in projection. Final task success does not erase the acquisition task's gaps. Full runner publication/admission was read, not executed. |

`UnitContext.output` rejects missing dependency outputs (`runtime/units.py:26-31`). Normal launch topologically orders units and finalizes only when the dependent chain succeeds (`runtime/launch.py:106-145`). `runner.py:644-669` verifies dependency receipt/result hashes before dispatch, `:686-728` calls handlers and retains receipts, and `:960-1041` verifies results, summarizes outcomes, and checks publication. `interchange.py:511-606` validates control statuses/gaps and converts component/path reasons.

### Acquisition engine substeps and all setting families

| Engine path | Actual behavior and relevant boundary |
|---|---|
| Configuration | `config/target_acquisition.py` validates systems/components, kinds, pins, provider-specific patchset/iteration fields, executable/path settings, unknown keys, unique ids, bounds, and credential-variable names. Git is default; supported kinds are Git, Perforce, and review export; API/bundle review sources are separate. |
| System layout and dispatch | `acquire.py:92-108,386-453` resolves repository-contained target/record roots, refuses an unowned or non-directory system root, selects every configured component for this job, and uses a bounded `ThreadPoolExecutor`. Both checkout and record present selects verification; otherwise acquisition refuses a one-sided preexisting pair rather than editing it. |
| New component | `acquire.py:120-185` creates component/record staging, materializes, enforces tree bounds, computes raw fingerprint and manifest, checks credential leakage in that manifest, then renames checkout and record into place. Caught failures clean staging and retain a component failure record. No such operation was executed in this audit. |
| Existing component | `acquire.py:341-372` checks recorded spec, target path/type, raw tree fingerprint, and every recorded auxiliary artifact hash; returns `VERIFIED` with original acquisition status/gaps or a refusal/mismatch. It does not fetch. Live Git metadata verification belongs to downstream source-history logic and was not certified here. |
| Git | `git_source.py:35-122,136-205` uses configured executable/command timeout/local-source policy, pins commit/object format, fetches branches/tags/extra refs, verifies checked-out HEAD, follows gitlinks with depth/path bounds, and records symlink-text, submodule and LFS gaps. `max_files`, total/file bytes and path bytes are inspected after materialization by `safety.inspect_tree`. Real Git execution was not run. |
| Perforce | `perforce.py:40-188` reads named user/ticket, configured executable/timeout and SSL fingerprint, verifies submitted changelist/effective change, enumerates scoped files, prints selected revisions, validates paths/case collisions, applies file/total/count bounds, verifies MD5/size and records SHA-256. Missing/purged/symlink/unverifiable translations are named. Real server semantics and file bytes were not validated. |
| Review API | `acquire.py:263-279` passes HTTP timeout/response-byte bound/local-source policy/auth to `http_fetcher`; calls `collect` with the review-count bound. GitLab/ADO paginate; Gerrit collects ALL_REVISIONS/ALL_COMMITS. **TA-01**: count bound ignored by Gerrit. |
| Review bundle | `acquire.py:280-296` checks regular file, fixed 256-MiB bundle bound, exact configured SHA-256, JSON schema/provider/change, then normalizes. No configured record-count limit reaches normalization (**TA-01**, static bundle subcase). |
| Review normalization and diff | `review_exports.py:173-327` validates provider change/head or patchset/iteration identity, emits normalized review records and gaps. `acquire.py:298-326` writes bundle/records, materializes head/base via Git, retains changed paths and bounded accepted patch. **TA-02**: Gerrit alternative patchsets get current review/merge facts; **TA-03**: first diff failure bypasses gap conversion. |
| Composition | `acquire.py:446-505` combines available identities, reports unconfigured/unselected entries, fingerprints composed root, chooses FAILED/PARTIAL/COMPLETE, preserves canonical manifest bytes when unchanged, and writes invocation-specific verification separately. Explicit subset/verify-only support is a standalone-helper feature; this job does not use it. |

Settings traced: `targets_dir`, `records_dir`, Git/P4 executables, command and HTTP timeouts, HTTP response bytes, review commit count, file count/total/file/path bytes, submodule depth, diff bytes, local-source permission, parallel component count, and every Git/Perforce/review-export source field. The advertised maximum review count is the verified ignored setting. Resource byte limits enforced only after capture/materialization are not certified here as streaming resource limits.

### Every published dataset and downstream expectation

All four declarations have operational authority, internal sensitivity, artifact-only disposition, and no index payload route (`jobs/job_target_acquisition/datasets.py:8-34`). Under `data/jobs/job_target_acquisition/attempts/*/`:

| Dataset | Exact suffix | Schema |
|---|---|---|
| `target_acquisition_plan` | `steps/selection/tasks/resolve_system/target-acquisition-plan.json` | `appsec-review/target-acquisition-job/2` |
| `target_acquisition_result` | `steps/acquisition/tasks/acquire_components/target-acquisition-result.json` | same `/2` |
| `target_acquisition_system_manifest` | `steps/acquisition/tasks/acquire_components/system-manifest.json` | `appsec-review/target-system-acquisition/1` |
| `target_acquisition` | `steps/publication/tasks/publish_handoff/target-acquisition-handoff.json` | `appsec-review/target-acquisition-job/2` |

The manifest is conditional, not a mandatory dataset. Tests explicitly cover absent reference, absent file, and exact-byte copying, so its conditional absence is not reported as a new schema defect. The prior aggregate declaration mismatch was repaired in Wave 1a; it is not re-reported.

Intake instead reads/copies the external system/component acquisition manifest (`jobs/job_review_intake/job.py:90-110`, `target_acquisition/acquire.py:543-584`) and declares its external `/1` schemas (`job_review_intake/datasets.py:35-46`). It carries raw gaps and compares the composed tree. Indexing declares the operational acquisition envelope and final `/2` dataset, not blanket access to plan/result/manifest payloads. Review-record output is consumed by change-context normalization (`jobs/job_change_context_analysis/sources.py:81-125`), exercised directly for TA-02.

Fresh graph dispatch is required (`runtime/resume.py:80-81`). Artifact-bearing results are not portable failed-attempt checkpoints (`runtime/checkpoints.py:25-41`). The system manifest excludes per-invocation timestamps/actions, preserving the previous fixed resume behavior; full acquire/resume was not rerun.

## Findings

### TA-01 — Medium — Review-count bound is ignored for Gerrit and bypassed by bundles

- **Evidence:** `src/appsec_review/target_acquisition/acquire.py:274-279` passes `settings.max_review_commits`; `review_exports.py:105-126` applies it to GitLab/ADO pagination but not the Gerrit branch. `review_exports.py:263-267` processes every revision and hardcodes `truncated=False`. Bundle dispatch goes from `acquire.py:294-296` directly into normalization without a limit.
- **Trigger:** A Gerrit response containing more patchset revisions than configured `max_review_commits`; separately, a hash-pinned bundle whose commit/revision collection exceeds that bound.
- **Expected:** Deterministic bounded normalized output, with explicit omitted-coverage accounting when the configured cap is reached, consistent with `docs/operations/target-acquisition.md`'s review commit cap.
- **Actual:** With configured cap **1**, fake Gerrit response containing **2** revisions produced **2** records and **zero gaps**. API metadata remains subject to HTTP byte limits, but that is not the configured record limit. Bundle count bypass is verified statically, not separately executed.
- **Impact:** Operator sizing/coverage expectations are violated; output and subsequent per-record work exceed the requested cap without reporting truncation.
- **Confidence:** High for code behavior; no live Gerrit or large-response resource test performed.
- **Smallest correction:** Carry the limit into the common normalized-output boundary for every provider/source, preserve the requested revision, deterministically bound additional records, and emit `review_commits_truncated` when records are omitted. Coordinate with TA-02 so obsolete Gerrit patchsets are not treated as ordinary reviewed commits.
- **Existing work:** No matching defect found in acquisition-related TODO/report searches. T-113 covers unit-suite migration; T-030 already acknowledges missing live adapter validation, not this known ignored setting.

### TA-02 — Medium — Gerrit current approvals/merge state are attributed to superseded patchsets

- **Evidence:** `src/appsec_review/target_acquisition/review_exports.py:240-243` validates only that requested revision maps to the requested patchset. `:248-262` takes change-level current labels and merge facts and sets `head_sha` to that requested revision. `:263-267` generates records for **all alternative patchset revisions** using the same raw record; `_records` at `:191-202` copies it unchanged. There is no `current_revision` comparison. Consumer `jobs/job_change_context_analysis/sources.py:99-110` accepts nonempty approvals and those fields as complete.
- **Trigger:** Change has old patchset A and current patchset B, B is merged/approved, acquisition pins A.
- **Expected:** Acquisition may retain historical A if supported, but must not assert B's approvals/merge as facts about A without revision-specific evidence; unavailable historical review facts need a gap. Alternative patchsets are not a set of commits collectively merged by the change.
- **Actual reproduction:** `current_revision=B`, pin A/patchset 1: normalized A has `approved_by_other=True`, a merge timestamp and `complete=True`; no acquisition gaps or consumer problems. The emitted record keyed B even claims `head_sha=A`.
- **Impact:** Operational review evidence can make superseded/unmerged source appear approved and merged, and distort downstream approval/staleness/review-time metrics.
- **Confidence:** High for transform and consumer acceptance; synthetic provider-shaped records, not a live-server observation.
- **Smallest correction:** Bind approval and merge facts to the revision they actually describe; do not fan current facts over every patchset. Emit unknown/scoped gaps for historical revision facts not supplied by the API, or obtain explicitly revision-bound metadata. Preserve supported historical acquisition rather than silently forcing a newer revision.
- **Existing work:** No matching item found. T-030's live adapter validation remains relevant but does not address the reproduced transformation.

### TA-03 — Medium — Changed-path diff failure discards an otherwise materializable review component

- **Evidence:** `src/appsec_review/target_acquisition/git_source.py:214-215` calls the first `git diff --name-status` with default `check=True`; Git delegates to `safety.run_command` (`git_source.py:64-68`, `safety.py:125-142`) which raises on failure. Only the second binary diff uses `check=False` and emits `change_diff_failed` (`git_source.py:224-228`). Caller `acquire.py:303-314` has already checked out the head, but the exception reaches component-wide cleanup/failure at `:173-183`.
- **Trigger:** Git can inspect/check out the pinned head but cannot produce the base-to-head changed-path listing, e.g. an unavailable/corrupt base tree or diff-command I/O failure.
- **Expected:** Retain the independently materialized head as partial with `change_diff_failed`, no claimed complete diff; this is the documented diff-gap behavior.
- **Actual reproduction:** Real `change_diff` with a fake Git boundary raising on the initial listing propagates `AcquisitionError`; it returns no scoped gap and never reaches the handled patch failure branch.
- **Impact:** Instead of retaining source plus missing change context, acquisition removes staging and marks the entire component failed. A one-component review therefore cannot proceed; multi-component reviews lose a source component unnecessarily.
- **Confidence:** High for branch behavior; the end-to-end cleanup consequence is static, not an executed acquisition.
- **Smallest correction:** Handle first-command nonzero/error results consistently with the binary-diff branch and return a scoped diff gap while preserving independently verified head data. Add a focused fake-command regression.
- **Existing work:** No matching TODO or historical acquisition report item found.

## Existing reports and non-findings

Read both historical acquisition reports fully:

- `docs/tasks/2026-11-08-job-pass-03-target-acquisition.md`: previously repaired manifest instability, typed gap migration and typed whole-system failure. Those fixes are present. Its prior claim of thorough helper coverage does not establish coverage of the branches reproduced here.
- `docs/tasks/2026-11-11-freeciv-walk-03-target-acquisition.md`: explicitly only a no-request gate; acquisition path was not verified.

Searched TODO for acquisition/Perforce/Gerrit/review bounds/diff, and reviewed T-113, T-114/Wave 1a references, T-147, T-027/T-028/T-030. T-147 undeclared execution bindings and T-030 live adapter validation remain known gaps. Perforce/submodule history is explicitly deferred and is not an acquisition defect. Existing model/image-gate session reports were searched for overlap; no duplicate of TA-01–TA-03 was found. Recent cloud/local history queries found no additional matching acquisition assignment.

No new documentation-only discrepancy was isolated beyond documentation making stronger bounded/partial-output claims than the three code paths actually satisfy. No TODO was added or changed.

## Focused validation

All Linux commands ran through:

```powershell
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu `
    "printf %s $encoded | base64 -d | bash"
```

The command scripts used `set -eu`, changed to `/home/wsollers/projects/appsec-review`, verified exact HEAD and clean `git status --porcelain`, and set `PYTHONDONTWRITEBYTECODE=1`. No inherited `APPSEC_*`, `DAGSTER_HOME`, `PYTEST*`, or `PYTHON*` selectors were present in the inspected SSH environment. The real environment guard ran, including pre-xdist preflight. Dependencies were already available; nothing was installed.

### Collection

```bash
TIMEFORMAT='collection shell elapsed: %3R seconds'
time .venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_target_acquisition-collect-20261118 \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_target_acquisition/test_configuration.py \
  tests/unit/job_target_acquisition/test_contract.py \
  tests/unit/job_target_acquisition/test_handlers.py \
  tests/unit/job_target_acquisition/test_job_graph.py
```

**88 collected**, pytest collection **2.34 s**, shell **3.748 s**, exit 0.

### Execution

```bash
TIMEFORMAT='wrapper shell elapsed: %3R seconds'
time scripts/run-tests.sh --expect-tests 88 --parallel --test-workers 2 \
  --shuffle-seed 20261118 --strict -- \
  tests/test_000_unit_environment_guard.py \
  tests/unit/job_target_acquisition/test_configuration.py \
  tests/unit/job_target_acquisition/test_contract.py \
  tests/unit/job_target_acquisition/test_handlers.py \
  tests/unit/job_target_acquisition/test_job_graph.py
```

**88 passed**, pytest **5.53 s**, shell **13.509 s**, exit 0. Supervised collection **3.755047 s**, supervised execution **9.222276 s**. Unchanged wrapper bounds: max 200 tests, 30-s collection, 300-s total. Both process-supervision phases confirmed cleanup and zero remaining processes.

| File | Passed |
|---|---:|
| `test_configuration.py` | 17 |
| `test_contract.py` | 6 |
| `test_handlers.py` | 32 |
| `test_job_graph.py` | 30 |
| `tests/test_000_unit_environment_guard.py` | 3 |

No FAILED/ERROR nodes, skipped/xfail cases, or >10-s cases. Slowest measured case was the environment guard, **0.370867 s** including setup/call/teardown.

The four job test files and their support module were read fully before execution: they use synthetic per-test paths and fake the actual source-control/acquisition boundary. No loopback servers or real Git/P4 commands are launched by this selection.

**Scratch-name limitation:** explicit collection used the requested job-prefixed scratch. The required wrapper owns/rejects basetemp overrides and generated its own unique `tests-custom-*` path; its guard was not bypassed. Owned disposable pytest fixture directories and corresponding host-pin files were removed after results were gathered; logs/reports/junit/timing evidence was retained.

Retained under the authorized checkout:

- `test/tmp/logs/tests-custom-20261117-234327-421201-143662.log`
- `test/tmp/logs/tests-custom-20261117-234327-421201-143662.collection.log`
- `test/tmp/tests-custom-20261117-234327-421201-143662.collection.json`
- `test/tmp/tests-custom-20261117-234327-421201-143662.junit.xml`
- `test/tmp/tests-custom-20261117-234327-421201-143662.timings.sqlite`
- `test/tmp/reports/tests-custom-20261117-234327-421201-143662.json`

### In-memory reproductions — exact command

```bash
TIMEFORMAT='reproducer shell elapsed: %3R seconds'
time .venv/bin/python - <<'PY'
import json
from pathlib import Path
from time import perf_counter
from appsec_review.config.target_acquisition import TargetAcquisitionSettings
from appsec_review.target_acquisition import review_exports as reviews
from appsec_review.target_acquisition.git_source import change_diff
from appsec_review.target_acquisition.safety import AcquisitionError
from appsec_review.jobs.job_change_context_analysis.sources import review_records_from_export
start = perf_counter()
old, current, base = 'a'*40, 'b'*40, 'c'*40
change = {'_number':31, 'current_revision':current, 'status':'MERGED',
          'created':'2024-01-02 03:00:00', 'submitted':'2024-01-02 04:00:00',
          'owner':{'_account_id':100}, 'submitter':{'_account_id':200},
          'labels':{'Code-Review':{'values':{'+2':'approved'},'all':[
              {'_account_id':200,'value':2,'date':'2024-01-02 03:30:00'}]}},
          'revisions':{rev:{'_number':i,'commit':{'parents':[{'commit':base}],
              'committer':{'date':'2024-01-02 03:04:05'}}} for i, rev in enumerate((old,current),1)}}
settings = TargetAcquisitionSettings(max_review_commits=1)
urls = []
def fake_fetch(url):
    urls.append(url)
    return change
responses = reviews.collect('gerrit',fake_fetch,api_url='https://example.invalid', project='',
    repository='',change=31,patchset=1,iteration=None,max_commits=settings.max_review_commits)
metadata = reviews.normalize('gerrit',responses,change=31,revision=old,patchset=1,iteration=None)
records, problems = review_records_from_export(reviews.review_records_document(metadata))
assert len(metadata.records) == 2 > settings.max_review_commits
assert not any(g['reason']=='review_commits_truncated' for g in metadata.gaps)
print('F01',json.dumps({'configured_max_review_commits':1,'actual_record_count':len(metadata.records),
    'gaps':metadata.gaps,'fake_fetch_calls':len(urls)}))
assert change['current_revision'] != metadata.head
assert records[old]['approved_by_other'] is True and records[old]['complete'] is True
assert records[old]['merged_at'] is not None and not problems and not metadata.gaps
assert records[current]['head_sha'] == old
print('F02',json.dumps({'pinned_revision':old,'current_revision':current,
    'state':metadata.state,'old_record_complete':records[old]['complete'],
    'old_approved_by_other':records[old]['approved_by_other'],
    'old_merged_at':records[old]['merged_at'],'current_record_head':records[current]['head_sha'],
    'gaps':metadata.gaps,'consumer_problems':problems}))
class BrokenNameDiff:
    def __init__(self): self.calls=[]
    def has_commit(self,repo,commit): return True
    def __call__(self,*args,**kwargs):
        self.calls.append((args,kwargs))
        assert '--name-status' in args
        raise AcquisitionError('fixture git diff name listing failed')
git = BrokenNameDiff()
try:
    change_diff(git,Path('test/tmp/job-audit-job_target_acquisition-in-memory'),base,old,1024)
except AcquisitionError as exc:
    print('F03',json.dumps({'exception':type(exc).__name__,'message':str(exc),
        'diff_calls':len(git.calls),'returned_scoped_gap':False}))
else:
    raise AssertionError('expected reproduction of unhandled name-diff failure')
print(f'3 reproductions confirmed; Python elapsed {perf_counter()-start:.6f}s; no network, processes or files created')
PY
```

Exit 0; **three defect reproductions confirmed**, measured body **0.000328 s**, shell **0.559 s**. These are not three additional passing regression tests: the assertions deliberately characterize the current incorrect behavior. No acquisition, file writes, external process launches from the tested functions, or network calls occurred.

## Read coverage and remaining gaps

**Read fully:** shared brief; authorized `AGENTS.md`; canonical multi-session skill; both target-acquisition operations pages; all three job-package Python files; `config/target_acquisition.py`; all five implementation modules in `target_acquisition` (`acquire`, `git_source`, `perforce`, `review_exports`, `safety`); four mapped job unit files plus `support.py`; shared `tests/unit/runtime/test_wave1a_contracts.py`; environment guard; `tests/conftest.py`; `runtime/selection.py` and `runtime/checkpoints.py`; job-input-contract architecture page; the two historical acquisition task reports; shell test wrapper and common shell helper.

**Read in ranges/searches:** acquisition TOML and exact test-map entry; runtime registry/topology/graph/launch/units/runner/resume; gap construction/control validation; catalog raw snapshot and JSON writer; intake external-acquisition reader and dataset contract; indexing acquisition inputs; change-context normalized-record reader; config profile/overlay restrictions; Dagster disabled selection; CLI system/graph selection; test-wrapper collection/worker/report code and produced report; TODO relevant entries/references; existing session reports. `tests/test_target_acquisition.py` was sampled at configuration/Git setup and provider fixture/review-export tests (lines 1-240 and 432-644), with test names searched elsewhere.

**Material unread or unexecuted scope:**

- Mapped shared Wave 1a runner/publication/admission tests were read but not executed: most run full jobs via `JobRunner`, outside the conservative handler-only selection used here. No claim of an additional passing publication test.
- Legacy `tests/test_target_acquisition.py` includes real local Git, fake executable P4 and loopback HTTP. It was not executed because the assignment disallows target acquisition/network. Some of its Perforce/system-composition fixture details remain unread.
- No full schema-payload validator audit, all-host deployment/mount audit, complete downstream source-history/indexing audit, or full CLI/Dagster integration execution. Necessary interfaces were traced, not every unrelated consumer implementation.
- No real source revisions, submodule checkouts, Perforce changelist snapshots, historical provider exports, interrupted materialization recovery, concurrency races, or accepted run output were independently verified. Real provider semantics remain the T-030 validation gap.
- No complete live acquire/reverify/resume cycle was performed; historical reports are history, not current validation.

Final root inspection found no new root-level material from this audit. `git diff --check` passed and the authorized checkout remained clean at the exact required SHA. Only this individual session report and retained ignored test evidence were produced.
