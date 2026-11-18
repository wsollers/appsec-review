# Job 29/47 — job_codeql_analysis

## Scope and result

- Read-only audit on WSL `/home/wsollers/projects/appsec-review`, branch `main`, exact revision **0e54e40b8530639f114fb0cbadb3633f9d3a4cfe**. HEAD, ancestry and clean tracked state verified before work and HEAD/cleanliness checked again after validation.
- Python import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The Windows default checkout was not audited or tested.
- **Five reproduced functional defects:** one high, four medium. Two additional documentation/contract inconsistencies are separated below.
- **34 focused unit cases passed in 4.38 seconds**, shuffled with two workers; no failures, skips or tests over ten seconds. In-memory probes exposed behaviors absent from those assertions.
- No code/configuration/environment installation changes, target execution, CodeQL invocation or compilation, Docker/image/provider operation, nested agent, integration/acceptance/live/Dagster run. Only the authorized report and harness-owned `test/tmp` validation artifacts were written.

This is not certification of the language/query matrix or actual CodeQL output quality.

## Registration and intended contract

`runtime/registry.py:96,166` registers `build_job`. `job.py:1793-1804` declares exactly three units:
`plan.inventory` → `execution.scopes` → `acceptance.publish_handoff`.
`appsec-review.toml:1870-2241` enables the job; `runtime/selection.py:11-23` removes it from graph selection when its job-level setting is disabled. Step and task workers must each be one; action fan-out is `settings.concurrency`, shipped as two (`job.py:1462-1477`). There are no model calls or runtime prompt bindings in these handlers.

The typed contract declares **90 inputs across 17 producers**, all optional/GAP by default, six output datasets, review-graph dispatch, checkout target access and propagating handoff. Topology includes both `schedule_after` and input producers, then removes transitive edges (`orchestration/topology.py:46-81`). The operation page's generated predecessor list describes all registered rather than necessarily enabled predecessors; retired CPG/SVF jobs are separately default-disabled.

Actual input reads:

- `load_target_catalog` reads the accepted catalog, partition/project/build/compile-command artifacts, and optional review-intake target metadata (`job_evidence_collection/job.py:167-206`).
- `load_accepted_language_build` requires the accepted receipt-set artifact, checks its schema and build outcomes (`job_language_build/job.py:136-172`). CodeQL checks catalog/build/actual target fingerprints, duplicate build IDs, each selected source hash, accepted workspace manifest/tree, protected command hashes/argv/working directory/image (`job.py:170-390,1525-1540`).
- Plan explicitly requires catalog, language-build, artifact-index and C++-compiled handoffs; optionally retains artifact-security, post-build assessment, static evidence, Tree-sitter, clangd, CPG and change-context manifests (`job.py:1586-1608`). Other declared datasets are availability/admission declarations, not proof of individual payload consumption. No claim is made that all 90 are actually read.
- Predecessor databases are a separate explicitly authorized path: same private run store/project/tenant/assurance/snapshot, pinned predecessor handoff/result/config/claim, selected scope/database identities and aggregate metadata/file/byte/deadline bounds; detached copies and new local checkpoints, not imported observations (`codeql/predecessor.py`).

Intended output: per-scope database/query identities and native receipts/SARIF, normalized observation shards and supporting flow spans, bounded optional graph exports, explicit scope/processing/seed/export coverage, acceptance manifest and summary, and **no confirmed security findings**.

### Every declared task and its actual dispatch

| Declared task | Actual implementation and products | Findings / verification limit |
|---|---|---|
| `plan.inventory` | `job.py:1525-1611`: accepted-input/snapshot checks; runtime resolution; runner `inventory`; deterministic language/build scope planning; query/export lock declaration comparison; `plan.json`, inventory, upstream identities/manifests and export dispositions. | CQ-01 omits compiled source with no matching receipt. CQ-04 concerns legacy gaps. Capability inventory and real image compatibility were not executed. |
| `execution.scopes` — admission/scheduling | `job.py:1613-1714`, `codeql/scheduler.py`: runtime preflight and explicit predecessor import; bounded shared reservation; deterministic output order, query/normalization prioritized after each database; export waits for that scope's normalizations. | CQ-03 export admission fallback crashes. No real resource contention or safety controller exercised. |
| `execution.scopes` — database action | `job.py:615-744`, runner `database` at `codeql_runner.py:144-205`: immutable runtime resolution, database identity/checkpoint/tree verification, clean-target manual replay or accepted source-workspace staging, exact ordered configure/build commands, init/trace/finalize or source create. Save only successful database checkpoint. | Manual C/C++, Go, Java/Kotlin, C#; no-build JS/TS, Python, Ruby, Rust, Actions. Source/build code traced, native extraction not validated. |
| `execution.scopes` — query action | `job.py:747-883`, runner `query` at `codeql_runner.py:208-238`: default/additional/custom profiles; failed-database skip; isolated database copy; exact pack/version/suite or custom suite path; independent checkpoints; bounded SARIF; native output retained as incomplete when a failed action leaves bounded bytes. | Fresh/reuse/provenance paths covered with fake executor. No standard or CERT suite executed. |
| `execution.scopes` — normalization | `job.py:1316-1459`, `sarif.py`: exact native selectors, mapped source hashes, observation/evidence/source entities and supporting flow spans; first-party filtering/counts; unavailable coverage for failed queries; zero-result not-clean gap; per-profile SQLite shard. | CQ-02 corrupts leading-dot paths. This producer preserves native SARIF rather than elevating alerts to findings. |
| `execution.scopes` — graph export | `job.py:887-1244,1033-1047,1667-1692`: optional pack, failed DB/no-seed dispositions, accepted plus own normalized observation seeds and structural fallbacks, staged database/pack/CSV, separately bounded precompile, query execution/decoding, manifests/checkpoints/seed reports; `graph-exports.json`. | CQ-05 false global seed gaps. Eight configured packs each reference nine QL files/twelve result sets; file existence inventoried, not compiled/evaluated. |
| `acceptance.publish_handoff` | `job.py:1716-1791`: require index or explicit normalization failure; verify current and retained upstream manifests; publish own observation manifest with upstream references; finalize processing decisions; summary/counts/dispositions. Generic runner validates control records, freezes artifacts and publishes accepted pointers (`runtime/runner.py:990-1098`). | CQ-01/CQ-04 status/coverage defects. Full immutable admission is an unexecuted integration boundary. |

`_export_scopes` (`job.py:1270-1300`) still implements the old `database.scopes`/`export.scopes` interface, but is **not a declared/reachable unit** of the current factory. Its separate test does not establish coverage of the current export-admission wrapper.

### Configuration, identities, bounds and publication seams

- Typed mode/platform/language/schema/positive-bound checks live in `config/codeql.py`; legacy `manual`/`none` normalize to `build`/`source`. Applicability chooses only declared capabilities. No missing manual replay is replaced by autobuild.
- Shipped bounds: inventory 300 s; DB/query 1800 s; output stream 8 MiB; DB 200,000 files/8 GiB; SARIF 256 MiB/100,000 results; two threads/4 GiB RAM; four paths. Export: 200,000 rows/query, aggregate 256 MiB, 1800 s, seeded depth 3 with ceiling 8 and 200 seeds. Compile: 3600 s/eight threads/8 GiB; export reservation accounts for the larger compile resource request.
- Image resolver checks exact source/build tag-to-ID binding, signature policy and selected preinstalled runtime ID; absent/conflicting declarations follow explicit fail/derive policy. Runtime selection, source image, nominal/effective user, component/runner releases and runner source participate in identities. Application-mounted runner is read-only and unavailable in native mode (`codeql/runtime.py:186-377,462-523`).
- **Intentional boundary, not a finding:** supplied platform/pack payloads are availability-checked, not re-fingerprinted during customer review. Database/query/export identities use operator releases; query material strips hash fields. This agrees with `docs/operations/codeql-analysis.md:30-35,78-85,181-207` and the existing unit test named `test_runner_has_no_supplied_tree_fingerprinter`. Missing release declarations disable eligible reuse. I did not treat this as an unrequested signing/integrity redesign.
- Database tree and retained checkpoint/SARIF/export bytes are hash-checked. Query identity includes DB tree/profile/query release and limits; normalizer release affects indexing, not database/query execution. Export identity includes database, declared export/runner releases, settings and sorted seed rows. Success-only checkpoints; corruption is not silently treated as a miss.
- Runtime actions retain bounded head/tail streams, timeout/resource/cleanup facts and image identity. Database/query use disposable DB storage; compile-cache identity uses CodeQL release/effective user and records volume initialization. Safety-active failures can intentionally stop before scope-local fallback; CQ-03 specifically concerns safety-inactive fallback.
- Dataset globs cover predecessor import, graph exports, indexed `codeql-` observation shards, plan/summary/inventory, cache initialization and protected scope material. Graph export claims precede broad scope claims. Unit tests check representative ownership paths, **not every native-mode output**.
- Graph consumer `job_code_graph_index/scopes.py:138-236` requires an accepted CodeQL handoff/result/plan/export index, exact scope-set agreement and bound export manifests; source bytes are rechecked at `scopes.py:239-257`. `RetrievalCore.query_codeql` (`retrieval/core.py:1086-1147`) reads only indexed observations with exact filters, bounded cursors and gaps, never runs CodeQL. Other consumer contracts were searched, not fully re-audited.
- Generic handoff coverage remains partial when textual gaps exist, even if terminal status is SUCCEEDED (`runtime/handoff.py:196-259`). This limits—but does not eliminate—the CQ-04 status inconsistency.

## Findings

### CQ-01 — High — Compiled source without a matching build receipt disappears from the plan

- **Evidence:** `jobs/job_codeql_analysis/planning.py:269-354` discovers compiled-language scopes only while iterating receipts. The unassigned-source pass at `planning.py:357-404` covers only JavaScript, Python, Ruby and Rust. Actions/unsupported-language tails do not reconcile remaining C/C++, Go, Java/Kotlin or C# files. Acceptance matches/finalizes existing decisions only (`job.py:1753-1769`), and `publication_status([], [])` succeeds (`job.py:1508-1521`).
- **Trigger:** accepted catalog contains `src/a.cpp`, `main.go`, `Main.java` or `Program.cs`, but no matching language-build receipt; also applies to a compiled subtree outside the roots of present receipts.
- **Expected/actual:** missing replay/build environment must be a named uncovered input, not autobuild. Actual: **zero scopes, zero decisions, zero gaps, SUCCEEDED**, reproduced independently for all four extractor families.
- **Impact:** absent analysis is omitted from this producer's coverage and status; graph consumer derives its scope universe from the same incomplete plan. This does not prove that every other producer/final report is clean.
- **Confidence:** high, direct planner/status reproduction.
- **Smallest correction:** reconcile accepted compiled files against planned/explicitly decided scope coverage; emit missing-build/replay decisions for leftovers, including language-policy skips where appropriate. No new buildless execution authorization is needed.
- **TODO overlap:** T-169 (marked done) mentions degraded/buildless fallback and truthful source coverage; T-5016 concerns coverage quality. Neither inspected entry documents this zero-decision omission. New relative to the consulted individual audit reports.

### CQ-02 — Medium — SARIF mapping strips meaningful leading dots, losing Actions locations or binding the wrong source

- **Evidence:** `jobs/job_codeql_analysis/sarif.py:49-74`, especially **line 57**: `raw = raw.lstrip("./")`. This removes a character set, not an exact `./` prefix. Mapped hashes are then trusted by `_location` at `job.py:1303-1313`.
- **Trigger:** a valid URI `.github/workflows/ci.yml` (the exact Actions paths selected at `planning.py:406-414`) or `.hidden/tool.py`.
- **Expected/actual:** preserve target-relative path components. Actual: `.github/workflows/ci.yml` becomes `github/workflows/ci.yml` and is unmapped when only the real workflow exists. With accepted Python files `.hidden/tool.py` and `hidden/tool.py`, the former maps to the latter's **different hash at confidence 1.0**.
- **Impact:** Actions observations lose source resolution; hidden-code findings can receive incorrect source identities and flow/first-party attribution. The wrong-Python-source scenario is feasible within a single root scope; the Actions scope itself contains only workflow paths, so its demonstrated effect is unmapped locations.
- **Confidence:** high, direct real mapper reproduction.
- **Smallest correction:** normalize exact transport/workspace and `./` prefixes without stripping filename characters; retain hidden components and distinguish parent traversal from a dot-prefixed filename.
- **TODO overlap:** no matching item found; T-5016 is related source-attribution/first-party work, not this defect.

### CQ-03 — Medium — Export admission timeout raises KeyError instead of returning the scoped failure

- **Evidence:** current nested `admitted` handler constructs export fallback using `_export_base` at `job.py:1644-1645`; that base has flat `scope_id/language/root` fields (`job.py:985-988`), not `scope`. It immediately dereferences `base["scope"]` at **job.py:1651**. The successful-export admission path is `job.py:1686-1691`.
- **Trigger:** export resource admission raises TimeoutError/RuntimeError while DB/query/normalization are otherwise successful and execution-safety fail-stop is not active. Real admission can time out at `runtime/resources.py:506-510`.
- **Expected/actual:** failed export record with a named operational gap, retaining successful SARIF work. Actual: **KeyError 'scope'** escapes before `graph-exports.json` and acceptance.
- **Impact:** an optional graph-export capacity failure aborts the whole execution unit and suppresses its otherwise usable query publication.
- **Confidence:** high; real declared execution handler and its actual nested export callback reproduced with only resource admission and unrelated stage boundaries faked.
- **Smallest correction:** derive logging scope from the original database argument in the export branch, or retain a consistent scope value separately from the output base.
- **Limit:** an active safety policy intentionally raises `ReviewStopped` before this fallback; this is not a recommendation to weaken that policy.
- **TODO overlap:** no exact item found. T-147's missing task bindings do not cover this dispatch error.

### CQ-04 — Medium — Plan-only coverage gaps do not affect acceptance terminal status

- **Evidence:** VB/F#/Swift are appended as plain plan gaps without decisions (`planning.py:432-450`). Publish gathers those gaps (`job.py:1752,1770-1776`) but calls `publication_status(processing_decisions, scopes, exports=...)` without them (`job.py:1784`). The status helper checks decisions/scope outcomes/export gaps only (`job.py:1517-1521`).
- **Trigger:** otherwise empty or successful plan with these unsupported inputs; similarly, an upstream build gap that lives only in `plan.gaps` and whose runnable query scopes are complete.
- **Expected/actual:** retained uncovered input makes acceptance COMPLETED_WITH_GAPS. Direct real acceptance-handler probe returned **SUCCEEDED** with both explicit Visual Basic and Swift missing-coverage reasons and no processing decisions.
- **Impact:** task/job success events and terminal disposition can disagree with recorded coverage. **The gap strings are not erased**: generic handoff coverage still classifies them partial, so this is not a claim of total gap suppression.
- **Confidence:** high; planner plus actual publisher reproduced with artifact/manifest boundaries faked.
- **Smallest correction:** include substantive plan gaps in status reduction or give every such input a typed coverage/processing decision and reduce over it.
- **TODO overlap:** T-157 language/applicability metadata is related but not an exact defect entry; T-169 also overlaps the general coverage goal.

### CQ-05 — Medium — Per-scope seed extraction falsely reports other valid scopes as absent from every database

- **Evidence:** current exporter calls `_seed_plan(unit, [scope], ...)` at **job.py:1683**, while `_seed_plan` passes all accepted upstream manifests (`job.py:1033-1046`). `seeding/ledger.py:303-309,331-334` builds owners from only the passed scope and counts other files as `not_in_database`; `ledger.py:119-132,456` emits the global claim “lie in no CodeQL database scope.”
- **Trigger:** two planned databases with accepted SAST findings in their respective files. Each independently scheduled export sees the other scope's finding in the global observation manifests.
- **Expected/actual:** findings that belong to another planned database should not be global missing-database gaps. Same two fake accepted observations and real seed extractor: passing both scopes gives `not_in_database=0`; passing only scope A (the current call shape) gives **1** and the false global gap.
- **Impact:** healthy multi-scope exports accumulate misleading coverage gaps/ledger counts; they propagate through export status and graph cards. The accepted seed belonging to the current scope is still selected.
- **Confidence:** high; caller/dataflow traced and extractor behavior reproduced with only accepted-index access faked.
- **Smallest correction:** retain whole-plan ownership for the global missing-database accounting while selecting each scope's own seeds/own normalized shards, or compute truly global outside-scope counts once.
- **TODO overlap:** T-169 added dual/structural seeding; the older architecture description predates that change. No exact multi-scope accounting item found.

## Separate documentation / contract inconsistencies

1. **CQ-D01 (low): stale scheduler and seed-source descriptions.** `docs/architecture/code-graph-precomputation.md:697-715` still declares database/query/normalize/export units and concurrent query/export execution. Actual factory has three units and `codeql/scheduler.py:14-25,52-71` waits for the scope's normalizations before export. `docs/architecture/seeded-codeql-neighborhoods.md:68-71` and `seeding/ledger.py:12-13` say own CodeQL findings are excluded universally, whereas `job.py:1675-1683` supplies them explicitly. Update these descriptions; do not remove the implemented dual-seed behavior. Related T-147/T-157/T-169.
2. **CQ-D02 (low): optional contract versus required loader reads.** All 90 declarations default to OPTIONAL/GAP (`datasets.py`, `runtime/contracts.py:56-65`), but CodeQL's plan demands four producer handoffs (`job.py:1586-1591`) and its catalog/build loaders default to required. A missing optional declaration can therefore pass input availability admission and fail in the handler. Align the genuinely required producer requirements with current behavior, or intentionally handle absence as a gap. This was identified statically, not through an integration launch.

Existing separate report IP-F02 already documents that image-pin verification omits preinstalled CodeQL runtime IDs. It is **not counted again here**; CodeQL's own runtime does inspect/reject missing IDs.

## Focused validation record

All Linux commands were transported over:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Working directory for every command: `/home/wsollers/projects/appsec-review`.

### Environment

```bash
git rev-parse HEAD
git status --short
git branch --show-current
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Exit 0; exact SHA, `main`, empty status, expected Linux import path. Repeated HEAD/status after probes: unchanged/clean.

### Collection

```bash
start=$(date +%s)
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-codeql-collect-20261118-1322 \
  tests/unit/job_codeql_analysis
printf 'COLLECTION_WALL_SECONDS=%s\n' "$(( $(date +%s)-start ))"
```

Exit 0; **34 collected in 0.63 s**, wall counter **1 s**. One `Unknown config option: cache_dir` warning because this collection disabled the cache provider. No tests executed.

### Wrapper selector correction

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 29047 \
  --max-tests 34 --expect-tests 34 --timeout-seconds 180 -- \
  tests/unit/job_codeql_analysis
```

Exit 2 **before pytest**: wrapper requires existing test-file selectors, not a directory. No test result or elapsed test time exists for this rejected command.

### Executed unit selection

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 29047 \
  --max-tests 34 --expect-tests 34 --timeout-seconds 180 -- \
  tests/unit/job_codeql_analysis/test_contract.py \
  tests/unit/job_codeql_analysis/test_datasets.py \
  tests/unit/job_codeql_analysis/test_first_party_results.py \
  tests/unit/job_codeql_analysis/test_handlers.py \
  tests/unit/job_codeql_analysis/test_planning.py \
  tests/unit/job_codeql_analysis/test_sarif.py
```

Exit 0; exact count guard 34; **34 passed in 4.38 s**; failures 0; skips 0; >10 s tests 0.
The wrapper owned the unique directory `test/tmp/tests-custom-20261118-130135-030337-3149319`, reusing it sequentially for its own collection/execution as authorized. Cleanup confirmed no surviving process.

- Log: `test/tmp/logs/tests-custom-20261118-130135-030337-3149319.log`
- JUnit: `test/tmp/tests-custom-20261118-130135-030337-3149319.junit.xml`
- Timing DB: `test/tmp/tests-custom-20261118-130135-030337-3149319.timings.sqlite`
- Collection: `test/tmp/tests-custom-20261118-130135-030337-3149319.collection.json`
- Report: `test/tmp/reports/tests-custom-20261118-130135-030337-3149319.json`

Fixtures were inspected first. The real job-handler test replaces image resolution and the CodeQL executor; test inputs are private tiny files. `tests/unit/conftest.py` refuses real engine/network/Dagster entry points and disables durability flushing. Passing these fixtures is not a native CodeQL test.

### Bounded reproduction commands

Every probe used `.venv/bin/python -B - <<'PY'` over the same SSH transport. They used no real executor, no source modifications, and no actual scratch files.

**Planner and mapper probe body (CQ-01/CQ-02):**

```python
from appsec_review.jobs.job_codeql_analysis import job as j
from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.jobs.job_codeql_analysis.sarif import map_location
import json
image = 'sha256:' + '1' * 64
file = lambda p: {'path': p, 'sha256': 'a'*64, 'size_bytes': 32}
for language, path in [('cpp','src/a.cpp'), ('go','main.go'),
                       ('java','Main.java'), ('csharp','Program.cs')]:
    p = build_codeql_plan(source_fingerprint='snapshot', files=[file(path)],
        receipts=[], projects=[{'root':'.'}],
        supported_extractors=[language], source_image_id=image)
    print('MISSING_BUILD', json.dumps({'language': language, 'scopes': len(p.scopes),
        'gaps': p.gaps, 'decisions': p.decisions,
        'publication_status': j.publication_status(p.decisions, [])}))
files = [file('.github/workflows/ci.yml'), file('github/workflows/ci.yml')]
for accepted in [files[:1], files]:
    loc = map_location({'artifactLocation': {'uri': '.github/workflows/ci.yml'},
        'region': {'startLine': 3}}, files=accepted, root='.')
    print('HIDDEN_PATH', json.dumps({'accepted': [f['path'] for f in accepted],
        'mapped': loc.path, 'confidence': loc.confidence, 'candidates': loc.candidates}))
```

Observed all four `MISSING_BUILD` rows with `scopes=0, gaps=[], decisions=[], publication_status=SUCCEEDED`; hidden workflow mapped `null` alone and `github/workflows/ci.yml` with a collision. This was the first part of an initial combined probe: its subsequent acceptance fixture omitted `unit_id`, so that **initial invocation exited 1 with AttributeError**, before export/seed probes or its elapsed-time print. This fixture error is not a repository failure. The corrected continuation below was then executed.

**Corrected real-handler and seed-extractor probe body (CQ-03/CQ-04/CQ-05):**

```python
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import json, time
from appsec_review.jobs.job_codeql_analysis import job as j
from appsec_review.jobs.job_codeql_analysis.planning import (
    build_codeql_plan, CodeQLScope, SCOPE_SCHEMA)
from appsec_review.seeding import ledger
start=time.perf_counter()
file=lambda p:{'path':p,'sha256':'a'*64,'size_bytes':32}
run=Path('test/tmp/job-audit-codeql-memory-20261118').resolve()
p=build_codeql_plan(source_fingerprint='snapshot',
    files=[file('legacy/A.vb'),file('ios/A.swift')],receipts=[],
    supported_extractors=['cpp'],source_image_id='sha256:'+'1'*64)
unit=NS(unit_id='acceptance.publish_handoff',job=NS(run_root=run,
    attempt_root=run/'attempt',attempt_id='attempt_0001',run_id='toy',
    source_fingerprint='snapshot',target_root=run/'target',
    events=NS(write=lambda *a,**k:None)),output=lambda key:{
        'scopes':[],'exports':[],'gaps':[],'observation_count':0}
        if key=='execution.scopes' else {'upstream_manifests':[]})
with ExitStack() as stack:
    for name,value in {
        '_plan_from':lambda u:p,
        'resolve_context_manifest':lambda c:(run/'manifest.json','b'*64),
        'load_verified_manifest':lambda *a:None,
        'write_manifest':lambda *a,**k:None,
        '_artifact':lambda *a:{'path':'toy','sha256':'b'*64},
        '_json_artifact':lambda *a:{'path':'toy','sha256':'b'*64}
    }.items():
        stack.enter_context(patch.object(j,name,value))
    out=j.build_job().units[2].handler(unit)
    print('LEGACY_GAPS_STATUS',json.dumps({'status':out['terminal_status'],
        'gaps':out['gaps'],'decisions':out['processing_decisions']}))
scope=CodeQLScope(SCOPE_SCHEMA,'scope-a','python',('Python',),'none','a',
    (file('a/app.py'),),None,None,'e'*64,False)
db={'scope':asdict(scope),'terminal_status':'SUCCEEDED','database_identity':'db'}
settings=NS(threads=2,ram_mb=4096,compile_threads=8,compile_ram_mb=8192,
    database_timeout_seconds=1,concurrency=1,
    export_queries=NS(enabled=True,mode='whole_program'))
unit.job.review_policy=NS(resources=NS(staging_memory_mb=1))
unit.job.metadata_root=run/'metadata'
unit.unit_id='execution.scopes'
def fail_reserve(*a,**k):
    raise TimeoutError('bounded export admission timeout')
with ExitStack() as stack:
    patches={
        '_plan_from':lambda u:NS(scopes=[scope]),'_receipt_map':lambda u:{},
        '_settings':lambda u:settings,
        '_preflight_runtime_environments':lambda *a:None,
        '_import_predecessor_databases':lambda *a:None,
        '_export_profile':lambda *a:{'query_id':'graph-export-python'},
        'ResourceAdmission':lambda *a:NS(reserve=fail_reserve),
        'ready_scopes':lambda *a,**k:k['export'](db)}
    for name,value in patches.items():
        stack.enter_context(patch.object(j,name,value))
    try:
        j.build_job().units[1].handler(unit)
    except Exception as exc:
        print('EXPORT_ADMISSION',type(exc).__name__,str(exc))
scope_b=CodeQLScope(SCOPE_SCHEMA,'scope-b','python',('Python',),'none','b',
    (file('b/app.py'),),None,None,'f'*64,False)
entities=[{'identity':f'obs-{n}','payload':{'producer':'semgrep','rule_id':'toy'},
    'location':{'path':f'{n}/app.py','start_line':1,'end_line':1}}
    for n in ['a','b']]
with patch.object(ledger,'observation_shards',lambda *a:[{}]), \
     patch.object(ledger,'ShardSet',lambda *a:NS(
         shards=[{}],entities=lambda *a,**k:iter(entities))):
    for scopes in [[scope,scope_b],[scope]]:
        plan=ledger.extract_seeds(run,[],scopes,seed_limit=10)
        print('SEED_SCOPE_SET',json.dumps({'scopes':[s.scope_id for s in scopes],
            'not_in_database':plan.not_in_database,'gaps':plan.shared_gaps()}))
print('PROBES_ELAPSED_SECONDS',round(time.perf_counter()-start,4))
```

Exit 0, **0.0019 s** measured body:

```text
LEGACY_GAPS_STATUS status=SUCCEEDED; Visual Basic and Swift gap strings; decisions=[]
EXPORT_ADMISSION KeyError 'scope'
SEED_SCOPE_SET [scope-a,scope-b]: not_in_database=0, gaps=[]
SEED_SCOPE_SET [scope-a]: not_in_database=1,
  "seed_file_not_in_database: 1 finding locations lie in no CodeQL database scope and cannot seed a neighborhood"
```

**Feasible same-scope Python collision and declaration count follow-up:**

```python
import time
from appsec_review.jobs.job_codeql_analysis.sarif import map_location
from appsec_review.jobs.job_codeql_analysis.datasets import CONTRACT, DATASETS
start=time.perf_counter()
files=[{'path':'.hidden/tool.py','sha256':'a'*64},
       {'path':'hidden/tool.py','sha256':'b'*64}]
mapped=map_location({'artifactLocation':{'uri':'.hidden/tool.py'}},
                    files=files,root='.')
print('PYTHON_HIDDEN_COLLISION',mapped.path,mapped.file_sha256,mapped.confidence)
print('DECLARATIONS',len(CONTRACT.inputs),len(CONTRACT.consumes),len(DATASETS))
print('PROBES_ELAPSED_SECONDS',round(time.perf_counter()-start,4))
```

Exit 0, **0.0005 s**; wrong path `hidden/tool.py`, hash `"b"*64`, confidence `1.0`; declaration counts `90 17 6`.

An additional read-only Python inventory parsed `assets.lock.json` and `columns.json`, enumerated each configured pack's query-file existence and printed no missing files. It found the fifteen locked extractor names (including auxiliary csv/html/properties/xml/yaml and unconfigured Swift) and eight configured graph packs, each nine query files/twelve result sets. **No compilation, syntax/type validation, pack payload re-hash or actual extractor inventory was performed.** No separate elapsed measurement was taken for this source inventory.

## Read coverage and honest gaps

**Read fully:** authorized brief and WSL `AGENTS.md`/coordination skill; canonical `docs/operations/job_codeql_analysis.md`; job package `__init__.py`, `job.py`, `planning.py`, `sarif.py`, `datasets.py`; `config/codeql.py`; CodeQL shared `__init__.py`, `runtime.py`, `scheduler.py`, `predecessor.py`, `execution_metrics.py`; `containers/tools/codeql/codeql_runner.py`; `seeding/ledger.py`; all six executed unit files; `tests/unit/conftest.py`; `scripts/run-tests.sh`; `runtime/selection.py`.

**Sampled / targeted reads:** base TOML CodeQL block; `docs/operations/codeql-analysis.md:1-235`; seeded-CodeQL architecture `1-190`; code-graph architecture search hits plus `691-763`; `tests/job-test-map.json` job row; root test safety fixtures/hooks; `tests/test_codeql_analysis.py:451-765` plus helper/test-name searches; registry/topology/contract defaults; accepted catalog/build loaders; generic runtime execution/publication/outcome normalization; graph-input and source-verification consumer; `RetrievalCore.query_codeql`; graph export validator; resource and safety error functions; shared copy/snapshot helpers; C++ `GraphExport.qll:1-210` and Python `GraphExport.qll:1-160`; relevant TODO entries and current report search hits, including IP-F02. Asset lock/column matrices were machine-read for declarations/existence, not semantically reviewed in full.

**Material unread/unexecuted matrix:**

- The remaining twelve mapped root-level test files were not executed. Only the stated range of `tests/test_codeql_analysis.py` was read semantically; other test files were not audited exhaustively.
- No real C/C++, Go, Java/Kotlin/Android, C#, JS/TS, Python, Ruby, Rust or Actions extraction/query run. No Gradle/Maven/.NET/Go/Cargo/native dependency compatibility or build replay runtime validated.
- None of the nine QL query bodies per language, CERT C++ 1,971-file pack, standard query suites, bundled extractor internals or all column/catalog semantic decisions were fully reviewed. Only the two specified common QLL portions were sampled. File existence is not query correctness.
- Existing T-115/T-118/T-119/T-122/T-123 concern live provenance, JS/C# and cross-language export acceptance; T-120/T-121 concern unclassified models; T-124/T-125 concern Rust model/sanitizer gaps. Their recorded status is not evidence that this audit ran or resolved them.
- No full native-mode dataset inventory, race/stale-cache/permission/process-cleanup stress test, all configuration permutations, per-language image identity inspection, signature/live source-mount verification, or predecessor store integration.
- No complete generic storage/admission/input-receipt/runtime-release closure or downstream job/final-report audit. No target/run outputs, answer keys or historical live artifacts were inspected.
- The 34 cases ran once with one shuffle seed; not a proof of all orderings, comprehensive branch coverage or real-world correctness.

Report complete; stopped after this job. No fixes or TODO changes made.
