# Job 8/47 — job_build_environment_analysis

## Scope, identity and result

- **Revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`, `/home/wsollers/projects/appsec-review` on `wsl-ubuntu` (Ubuntu-22.04). Exact HEAD, required ancestry, clean status and editable import were checked. Final HEAD/status were unchanged and `git diff --check` passed.
- **Read-only functional audit:** all three job-package files and all three job-specific unit files read fully. No repository edits, commits, pushes, service/container/provider operations, target-code execution, integration/acceptance tests or live reviews.
- **Result:** three medium functional findings, one low functional finding, and one low documentation/diagnostic observation. Findings were reproduced using the real parser/gap functions with in-memory synthetic input; the documentation observation used a fake catalog-loader failure.
- **Focused tests:** **59 passed**, no failures/errors/skips, no cases over 10 seconds; pytest **5.43 s**, supervised wrapper **13.72 s**. This is 56 job-specific cases, two pure shared-contract cases, and one environment guard.
- Passing tests do not certify exact shell/batch interpretation, end-to-end admission or useful live planning output.

## Registration, intended contract and complete dispatch inventory

`runtime/registry.py:72,125` imports/registers the factory. `appsec-review.toml:942-957` enables it with one worker, one step and two tasks. The typed contract is `jobs/job_build_environment_analysis/datasets.py:20-47`: review-graph dispatch, checkout access, reusable whole-job output, handoff propagation and `schedule_after=('job_target_catalog',)`.

The sole intended product is **bounded, redacted, source-resolving static declarations**, not effective environment values or compiler-target proof.

### Inputs and configuration

- Required `job_target_catalog/handoff`, schema `appsec-review/job-handoff/2`, producer-evidence authority, reject missing.
- Optional/gap catalog datasets: `target_artifact_inputs` (`target-artifact-intake/1`), `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` (all `retrieval-index/2`), and `catalog_documents` (`target-catalog/1`). All are handoff-channel producer evidence; all permit partial coverage.
- Actual producer read: `job.py:363` calls planner `_accepted_catalog` (`job_target_analysis_plan/job.py:95-146`). It resolves the admitted catalog digest, verifies the catalog and six child artifact hashes/schemas/source relationships, then returns the partition's file inventory. The environment job itself uses only `files`, `source_fingerprint`, and `catalog_handoff_sha256`. It does not query the declared SQLite source/symbol/document datasets.
- The shared loader reads catalog documents through its private `_read_artifact`, not `observe_output`; only the envelope read is instrumented there. `docs/architecture/job-input-contracts.md` explicitly describes this bounded private-reader instrumentation limitation, so this is not reported as a new defect or as proof of dataset-level reads.
- Typed bounds (`config/loader.py:501-507,524-539`): `max_scripts=64`, `max_script_bytes=262144`, `max_assignments=4096`, `max_depth=4`, `deadline_seconds=30`. Every bound can tighten only to an integer in `[1, default]`; boolean/noninteger/unknown keys fail. `enabled` must be boolean and is removed before constructing parser settings.
- `runtime/selection.py:11-30` removes disabled graph jobs. `orchestration/topology.py:48-84` projects disabled predecessors transparently. `orchestration/dagster/adapter.py:474-494` includes this job between catalog and planning in `project_build_review` only when enabled; wave1 uses the typed topology. No Dagster execution was performed.

### Every declared step/task

| Step/task | Real implementation and data processing | Output/coverage limit |
| --- | --- | --- |
| Configuration admission (not an extra task) | `job.py:354-359`: reject any step/task ordering other than the single `environment_analysis` step with `analyze_scripts`, then `publish_handoff`; revalidate typed bounds. | Tested with shipped config, wrong steps, wrong tasks and oversized settings. |
| `environment_analysis.analyze_scripts` | Handler `job.py:361-396`; parser `247-346`. Resolve accepted catalog; compare claim source; require target custody. Select sorted accepted `.sh/.bash/.bat/.cmd` whose stem matches `env|setup|setvars|bootstrap`. Read only accepted inventory members using canonical nonsymlink paths and `bound+1` reads, verify raw SHA-256, decode UTF-8. Traverse bounded literal `source`/`.`/`call` references; inspect assignment lines, uncertainty, secret names/credential URLs, declaration-value size, count/depth/internal-time exhaustion. Deduplicate/sort gap strings and validate the closed result. Emits STARTED/ANALYZED metrics without values. | `{"schema": ..., "environment": value}`. Hash/read-contract errors become `BuildEnvironmentAnalysisFailed`; unexpected errors propagate. No scripts or models executed. **BE-01–BE-03** affect declaration correctness. Existing T-110 covers conservative selection/whole-script uncertainty, not these false-known outputs. |
| `environment_analysis.publish_handoff` | Handler `job.py:398-413`, dependency at `415-418`. Load analysis task output, validate again, canonicalize, reject payload over 16 MiB, atomically write task-local `build-environment.json`, hash/read back, map artifact gaps to strict canonical producer gaps and emit publication event. | Exact declared artifact glob; SUCCEEDED without gaps, COMPLETED_WITH_GAPS otherwise. **BE-04** loses scope for uppercase root-level extensions. No unrelated output store/index/model task. Handler publication/schema/glob/hash/status tests pass; framework finalization was not executed. |

There are no job-level model bindings, prompts, worker guidance or runtime skills on either handler's execution path. The guidance registry has no job entry. Generated documentation's “Undeclared” binding is existing **T-147**, not evidence of hidden model execution.

### Output schema and downstream use

- `datasets.py:4-13` declares one optional artifact-only, sensitive, operational dataset: `build_environment`, step `environment_analysis`, schema `appsec-review/build-environment-analysis/1`.
- Glob: `data/jobs/job_build_environment_analysis/attempts/*/steps/environment_analysis/tasks/publish_handoff/build-environment.json`. No index shards, public payload MCP route or native-tool output.
- `validate_environment` (`job.py:156-202`) enforces exact top-level/declaration/bounds keys, source and catalog identities, rules `static-environment/1`, AVAILABLE/UNAVAILABLE, complete/partial/not_applicable consistency, count ceilings, canonical paths, line/hash identity, and withheld values for unknown/redacted declarations. The JSON Schema was also read fully. Runtime validation is stricter than the schema's per-declaration constraints; real handler output passes both.
- No selected scripts/no gaps gives AVAILABLE/not_applicable **within accepted inventory only**. PowerShell, unsupported/dynamic statements, resource bounds and internal deadlines yield named partial gaps. Secret redaction is not itself a fabricated coverage gap.
- `environment_contract`, `planning_environment_inputs`, `optional_prior_environment_handoffs`, `_read`, and `load_environment` were all read fully. EXPECTED_CURRENT checks exact environment/catalog pins and source consistency. OPTIONAL_PRIOR retains separate admitted pins and checks integrity before reporting wrong-source evidence UNAVAILABLE. DISABLED and NOT_RUN do not read/import environment evidence. Current and prior handoff/output receipts are explicitly observed. Unit tests cover moved `latest.json` pointers, stale source and conflicting modes.
- Planner `job.py:184-193,284-288,308-317,400-405` reloads/verifies the same environment, retains it in the plan/model request, and carries gaps forward. Build graph evidence carries the environment; declarations are not directly installed into the compiler process environment. Thus false-known declarations can mislead planning, but this audit does not claim they automatically change compilation.
- Whole-job reuse compares source/configuration/schema/implementation/dataset/upstream identities and publication integrity (`runtime/resume.py:73-202`). Planner reuse additionally reloads the environment and compares persisted availability/evidence (`136-144`). `runtime/checkpoints.py:25-41` rejects path/artifact-coupled unit outputs; the analysis also contains slash-bearing rules/inventory scope. No per-script cache was found.

## Findings

### BE-01 — Medium — Shell and batch assignment grammars are conflated

- **Evidence:** `src/appsec_review/jobs/job_build_environment_analysis/job.py:30,61-68,312,327-337`.
- **Trigger:** accepted `setup.sh` contains `set CC=clang`; or accepted `.cmd/.bat` contains bare `CC=clang` or `export CC=clang`.
- **Expected:** classify using the file's supported language. Shell `set CC=clang` sets positional parameters, not `CC`; batch bare/export forms are not CMD environment assignments. Unsupported forms should not become known environment declarations or gap-free coverage.
- **Actual/reproduction:** all three synthetic inputs produce `CC`, value `clang`, status `declared`, coverage `complete`, no gaps. A real publication would therefore select SUCCEEDED.
- **Impact:** positively incorrect developer-environment advice reaches planning with no coverage warning. This is not merely an unevaluated dynamic value.
- **Confidence:** high; real parser output reproduced and asserted; no shell or batch execution needed/performed.
- **Smallest correction:** make analysis assignment recognition dialect-specific (including appropriate keyword case rules); preserve broad cross-format secret redaction as a separate boundary. Add cross-dialect negative examples alongside the existing valid quoted-batch tests.
- **Existing TODO/prior report:** no matching defect found. Related **T-110** addresses selection/uncertainty policy, not treating nonassignments as declarations; **T-147** concerns binding metadata.

### BE-02 — Medium — Script/depth bounds suppress required taint of already inventoried scripts

- **Evidence:** `src/appsec_review/jobs/job_build_environment_analysis/job.py:264-270,301-309`.
- **Trigger:** `env.sh` contains `CC=clang`, `setup.sh` contains `source env.sh`, and `max_scripts=2`. Both scripts are initially selected; `env.sh` is visited first. The same threshold occurs with 64 selected scripts under the default setting.
- **Expected:** propagate sourcing uncertainty to existing selected/seen targets without requiring an additional script read or slot. The documented contract explicitly includes previously inspected sources.
- **Actual/reproduction:** at two slots, the source edge hits `len(seen)+len(pending) >= max_scripts` and is discarded before the revisit/taint branch. `env.sh` remains `declared=clang`; only the caller gets source-bound/context gaps. With unchanged source and `max_scripts=3`, the child correctly becomes `unknown`, value null.
- **Impact:** tightening an allowed resource bound upgrades uncertain source evidence to a known value. A generic caller-side bound gap does not repair the falsely known child declaration.
- **Confidence:** high; both limit values reproduced/asserted.
- **Smallest correction:** separate uncertainty propagation for existing inventory nodes from bounded scheduling of new reads, including at depth exhaustion; ensure already selected/seen targets are tainted even when no new traversal is possible.
- **Existing TODO/prior report:** no matching defect found. **T-110** is related context; it does not document this nonmonotonic taint behavior.

### BE-03 — Medium — Unsupported conditional/continued contexts still publish known assignments

- **Evidence:** `src/appsec_review/jobs/job_build_environment_analysis/job.py:289-295,312-315,327-337`.
- **Triggers:** shell `until true` / `do` / `CC=clang` / `done`; batch `@if exist flag (` / `set CC=clang` / `)`; shell `echo \` followed by newline and `CC=clang`.
- **Expected:** conditions and unresolved statement contexts keep values unknown; a continued command argument is not an independent assignment.
- **Actual/reproduction:** the uncertainty regex omits `until`, leading batch `@` control keywords and continuation state. All three examples publish `CC=clang` as `declared`; their only gap is `unsupported_script_statement`. The shell continuation example is an argument to `echo`, not an assignment.
- **Impact:** partial coverage contains unjustifiably known declarations; downstream consumers cannot rely on declaration status to distinguish unsupported control flow from literals.
- **Confidence:** high; all three real-parser examples reproduced/asserted.
- **Smallest correction:** conservatively taint unsupported control/continuation contexts before accepting line assignments, with focused regressions; do not implement arbitrary shell evaluation or broaden worker authority.
- **Existing TODO/prior report:** **T-110** recognizes excessive whole-script uncertainty and proposes a policy decision. This is the opposite defect—missed uncertainty—not a request to relax that policy or support full shell syntax.

### BE-04 — Low — Uppercase root-level script extensions lose canonical gap scope

- **Evidence:** `src/appsec_review/jobs/job_build_environment_analysis/job.py:56`, compared with case-insensitive extension selection at `251-254,304`.
- **Trigger:** root-level `SETUP.SH` contains an unresolved source; `.BASH/.BAT/.CMD` have the same mismatch.
- **Expected:** canonical gap `scope_id` identifies every script-path reason.
- **Actual/reproduction:** `gap_records` returns `scope_id=None` for `SETUP.SH`, but `setup.sh` and `dir/SETUP.SH` retain their paths. A real uppercase script fed through analysis then gap conversion also loses every path scope.
- **Impact:** per-script canonical coverage grouping is inconsistent, although the human-readable reason still includes the path.
- **Confidence:** high; real analysis and gap conversion reproduced/asserted.
- **Smallest correction:** normalize suffix case when recognizing scoped script paths (or carry structured path/reason pairs internally before canonical publication).
- **Existing TODO/prior report:** no matching item found.

### BE-D01 — Low — Documentation overstates the job-specific failure type for invalid catalogs

- **Evidence:** `docs/operations/job_build_environment_analysis.md:159-160` promises `BuildEnvironmentAnalysisFailed` for invalid catalog binding. `src/appsec_review/jobs/job_build_environment_analysis/job.py:363` invokes the catalog loader before the translation block at `384-389`; planner `job.py:102-108,123-126` raises plain `ValueError` for unsupported/mismatched catalog documents.
- **Expected versus actual:** those loader errors remain shared `ValueError`/integrity exceptions, not the documented job-specific class. A fake loader `ValueError` passed through the real analysis handler unchanged.
- **Impact:** diagnostic/runbook error-type expectation only; the attempt still fails rather than publishing success. No lost-failure claim.
- **Confidence:** high static evidence plus boundary reproduction.
- **Smallest correction:** narrow the prose to errors translated by the handler, or consistently wrap the intended catalog failure classes without hiding unexpected errors.
- **Existing TODO/prior report:** no matching entry found; `284855f57` introduced the named failure/telemetry behavior.

## Validation record

### Source/transport and clean unit environment

Linux commands were delivered with the brief's base64 transport:

```powershell
$encoded = [Convert]::ToBase64String(
  [Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

The collection and execution scripts started with:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
while IFS= read -r name; do unset "$name"; done < <(compgen -v APPSEC_NATIVE_)
unset APPSEC_REVIEW_PROFILE APPSEC_REVIEW_CONFIG_OVERLAY APPSEC_REVIEW_CONFIG \
  DAGSTER_HOME APPSEC_ACCEPTANCE_ROOT APPSEC_ACCEPTANCE_RUNS_DIR APPSEC_HOST_PINS \
  PYTEST_ADDOPTS PYTHONPATH APPSEC_PYTHON
export PYTHONDONTWRITEBYTECODE=1
```

Initial `git merge-base --is-ancestor` succeeded. `.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'` printed `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.

### Exact collection

```bash
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-build-environment-analysis-collect-20261118 \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_build_environment_analysis/test_analysis.py \
  tests/unit/job_build_environment_analysis/test_contract.py \
  tests/unit/job_build_environment_analysis/test_handlers.py \
  tests/unit/runtime/test_wave4_contracts.py::test_checkpoints_input_key_distinguishes_optional_prior_without_changing_empty_digest \
  tests/unit/runtime/test_wave4_contracts.py::test_upstream_scope_separates_current_and_optional_prior_and_rejects_overlap
```

**59 collected, 2.63 s**, exit 0; no tests executed during this command.

### Supervised shuffled execution

```bash
scripts/run-tests.sh --parallel --test-workers 4 --shuffle-seed 81118 \
  --max-tests 59 --expect-tests 59 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_build_environment_analysis/test_analysis.py \
  tests/unit/job_build_environment_analysis/test_contract.py \
  tests/unit/job_build_environment_analysis/test_handlers.py \
  tests/unit/runtime/test_wave4_contracts.py::test_checkpoints_input_key_distinguishes_optional_prior_without_changing_empty_digest \
  tests/unit/runtime/test_wave4_contracts.py::test_upstream_scope_separates_current_and_optional_prior_and_rejects_overlap
```

**59 passed in 5.43 s**, 0 failures/errors/skips/known failures, no test over 10 s, exit 0. Wrapper total 13.720987 s, collection count/proofs verified, owned-process cleanup confirmed. Slowest: `test_contract.py::test_load_environment_validates_contract_pointers_lineage_and_source`, **0.339076 s**.

| Selected file | Passed | Maximum per-test time |
| --- | ---: | ---: |
| `tests/test_000_unit_environment_guard.py` | 1 | 0.266 s |
| `tests/unit/job_build_environment_analysis/test_analysis.py` | 33 | 0.318 s |
| `tests/unit/job_build_environment_analysis/test_contract.py` | 21 | 0.339 s |
| `tests/unit/job_build_environment_analysis/test_handlers.py` | 2 | 0.070 s |
| `tests/unit/runtime/test_wave4_contracts.py` (two named cases only) | 2 | 0.004 s |

The wrapper owns and refuses overrides of its uniquely generated basetemp, so execution used its `test/tmp/tests-custom-20261118-111257-412957-2409375` namespace rather than the collection's `job-audit-...` prefix. No scratch escaped `test/tmp`.

Retained Linux evidence:

- `test/tmp/logs/tests-custom-20261118-111257-412957-2409375.log`
- `test/tmp/logs/tests-custom-20261118-111257-412957-2409375.collection.log`
- `test/tmp/tests-custom-20261118-111257-412957-2409375.collection.json`
- `test/tmp/tests-custom-20261118-111257-412957-2409375.junit.xml`
- `test/tmp/tests-custom-20261118-111257-412957-2409375.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-111257-412957-2409375.json`

Owned disposable basetemp directories, temporary host-pin fixtures and wrapper process bookkeeping were removed. Logs/junit/timings/collection/report were retained. Repository root inspected; no audit-created root artifacts or source changes.

### Offline defect reproductions

Initial parser probe: eight printed cases (three dialect errors, two taint limits, three unsupported-context errors), real parser time **0.002483 s**, exit 0. Initial gap-formatting probe failed in audit-only printing with `KeyError: 'message'` because canonical records do not expose that field; elapsed was not captured. It did not establish a product failure. Corrected scope-only printing succeeded in **0.000433 s**: lowercase and nested uppercase scoped, root uppercase null.

The following final self-contained assertion command reconfirmed all four functional defects and the diagnostic observation, **0.168801 s**, exit 0. Inputs remain byte strings; no target script is executed and no file is written.

```bash
cd /home/wsollers/projects/appsec-review
export PYTHONDONTWRITEBYTECODE=1
.venv/bin/python - <<'PY'
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib, json, time
from appsec_review.config import BuildEnvironmentSettings
from appsec_review.jobs.job_build_environment_analysis.job import analyze_environment, build_job, gap_records
started=time.monotonic()
def analyze(files, **limits):
    payloads={p:t.encode() for p,t in files.items()}
    catalog={'source_fingerprint':'audit-synthetic','catalog_handoff_sha256':'c'*64,
             'files':[{'path':p,'size_bytes':len(t),'sha256':hashlib.sha256(t).hexdigest()} for p,t in payloads.items()]}
    return analyze_environment(catalog,lambda i,b:payloads[i['path']][:b+1],replace(BuildEnvironmentSettings(),**limits))
for path,text in [('setup.sh','set CC=clang\n'),('setup.cmd','CC=clang\n'),('setup.bat','export CC=clang\n')]:
    v=analyze({path:text})
    assert v['coverage']=='complete' and not v['gaps'] and v['declarations'][0]['value']=='clang'
files={'env.sh':'CC=clang\n','setup.sh':'source env.sh\n'}
assert analyze(files,max_scripts=2)['declarations'][0]['status']=='declared'
assert analyze(files,max_scripts=3)['declarations'][0]['status']=='unknown'
for path,text in [('setup.sh','until true\ndo\nCC=clang\ndone\n'),('setup.cmd','@if exist flag (\nset CC=clang\n)\n'),('setup.sh','echo \\\nCC=clang\n')]:
    v=analyze({path:text})
    assert v['declarations'][0]['status']=='declared'
    assert v['gaps']==[path+': unsupported_script_statement']
value=analyze({'SETUP.SH':'source missing.sh\n'})
assert all(r['scope_id'] is None for r in gap_records(value['gaps'],'environment_analysis.publish_handoff'))
unit=SimpleNamespace(job=SimpleNamespace(run_root=Path('test/tmp/nonexistent-audit-input')))
with patch('appsec_review.jobs.job_target_analysis_plan.job._accepted_catalog',side_effect=ValueError('accepted catalog and handoff source identities differ')):
    try:
        build_job().units[0].handler(unit)
    except Exception as error:
        assert type(error) is ValueError
        print('catalog_error_class',type(error).__name__)
    else:
        raise AssertionError('catalog error unexpectedly hidden')
print('All four defect reproductions and diagnostic-type observation confirmed')
print('elapsed_seconds',round(time.monotonic()-started,6))
PY
```

## Existing work and explicit coverage limits

- Read relevant **T-110** and **T-147** entries fully; searched the TODO registry for environment/script/sourcing and job references, including T-113's historical 54-case job-pass record and the Wave 4 input migration. Current job-folder collection is 56, not that historical count. T-110's conservative selection/unknown behavior is a decided bounded limitation pending policy work, not re-reported as a new bug.
- Inspected recent job-local history (`4ab4a1ebe`, `36eb325da`, `1a4d3f67f`, `284855f57`, `3613a7f3d`) and searched all-branch log subjects for prior environment audits. Searched the seven available preceding session reports and reviewed finding headings/relevant matches; no identical finding was found. Their historical validation does not validate this revision.
- **Read fully:** shared audit brief, authorized `AGENTS.md`, canonical multi-session skill; all job-package files; both environment operations pages; build-environment JSON Schema; three job-specific unit files; shared Wave 4 unit file; unit conftest; environment-guard test; `tests/handoff_fixture.py`; `runtime/consume.py`; topology module; job-input-contract architecture; shell test wrapper and common shell helper.
- **Read in relevant ranges/searches:** base config block; typed loader settings/parser/registration; registry and selection; planner accepted-catalog reader, accepted-plan environment validation and planning/model propagation; build-topology environment references; runtime input selection/read instrumentation, resume and checkpoints; dataset type/artifact-only helper; safe paths; core exact-prior handoff reader; Dagster adapter placement; test map and guidance registry; root conftest except its omitted collection/timing-hook tail segment; wrapper implementation/admission/report sections; testing and jobs/runtime architecture sections; TODO/prior report/history excerpts.
- **Material unread/unexecuted:** full shared-runtime/publication/signing/admission implementations, the complete downstream planner/build jobs and graph refinement, unrelated job tests, real shell/CMD interpreters, actual target inventory/scripts, models, native tools and live output quality. These are not implied to pass.
- The remaining four parameterized/shared Wave 4 executions that seed real JobRunner catalog/environment/planner fixtures were **not selected**; only its two pure contract cases ran. The mapped three integration files, legacy downstream consumer tests, Dagster wiring execution, resume/restart execution and full publication acceptance were not run. Job-local contract fixtures directly test publication and readers, not an end-to-end run.
- No declared environment step/task was omitted from static tracing. All findings concern known/unknown/scoped output or diagnostic semantics; no penetration testing or speculative security-hardening recommendations were performed. **Stopped after this job.**
