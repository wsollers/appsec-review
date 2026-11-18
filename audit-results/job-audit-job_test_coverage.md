# Job 16/47 — job_test_coverage correctness audit

## Scope and result

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review`, through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized UNC view. HEAD and clean tracked/untracked status were checked before tests and again after the reproductions. The dirty Windows checkout was not audited.
- Editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- **Eight reproduced functional findings: one high (previously reported), four medium, three low.** Two documentation discrepancies and two explicitly non-defect limitations are separated below.
- **69 selected tests passed**: all 66 job-folder cases, two coverage-specific shared runtime cases, and the production-environment guard. Pytest: **7.37 s**, zero failures/skips, zero cases over 10 s; two workers, shuffle seed 1618. This is not proof of live coverage accuracy.
- No source/configuration/environment installation changes, commits, services, containers, providers, target execution, integration/live runs, or nested agents. Writes were confined to this report and invocation-owned `test/tmp/` test/reproduction artifacts.

## Registration, contract, and complete task inventory

`runtime/registry.py:152` registers the factory. `datasets.py:27-79` declares review-graph dispatch, checkout target access, propagation, and `always_execute=False`; its scheduling predecessor is artifact indexing. `orchestration/topology.py:46-86` also projects semantic input dependencies. The dev recipe enables the job; there is no job-specific model/guidance binding or model/tool call in its handlers. The missing declarative internal-task binding is existing **T-147**, not evidence of an unimplemented handler.

Central configuration (`appsec-review.toml:1591-1623`) declares families `native`, `go`, `dotnet`, `node`, `python`, `rust`, `php`, `java`, `wasm`; bounds are 10,000 candidate artifacts per receipt, 268,435,456 bytes per artifact, 1,000,000 parser rows/nodes, 100,000 source-file rows, and 32 retained path candidates. All four configured steps/tasks are present and dispatched:

| Declared step/task | Actual implementation and dependencies | Input/processing/output observations |
|---|---|---|
| `load.accepted_inputs` | `job.py:337-364`; first unit | Reads pinned target-catalog envelope, verifies its publication, partition paths/hashes and optional snapshot; reads available language-build and artifact-index accepted loaders; checks their snapshots; retains receipts, catalog hash map, upstream handoff hashes, verified manifest. Disabled upstreams produce named gaps and the catalog/attempt-manifest fallback. No target-tree discovery. |
| `normalize.coverage` | `job.py:366-370`; depends on load | Calls `_settings` and `ingest_coverage_artifacts`. Sorts receipts by build-unit ID, filters families, selects only receipt-enumerated coverage kinds/names, applies bounds and verifies report bytes/origin. Detects/parses four formats, binds paths, retains unresolved/ambiguous rows, sums bound rows. Findings **TC-01, TC-05–TC-07**. |
| `index.coverage` | `job.py:372-428`; depends on load and normalize | Verifies inherited manifest, removes only prior `analysis/test-coverage-*` shards, creates/reuses one immutable analysis shard per included build unit, emits file and aggregate `coverage_cell` records and a scoped coverage row, composes/verifies a new manifest. **TC-02** prevents publication for duplicated report bytes at different paths. **TC-03/TC-04** concern the advertised/actual consumption of these rows. |
| `acceptance.publish_handoff` | `job.py:430-453`; depends on all three | Writes `accepted-test-coverage.json`, sums build-unit counters, includes upstream hashes/identities/gaps/manifest; publishes **unit count**, not file count. Chooses `COMPLETED_WITH_GAPS`, `SUCCEEDED`, or `NOT_APPLICABLE` as documented. **TC-08** is a downstream status-field mismatch, not a wrong status emitted here. |

The `Unit` dependency declarations at `job.py:455-465` match the configured order; the direct executor executes these handlers in dependency order and skips a blocked successor (`runtime/units.py:83-120`). Job validation checks topology/task order and identity constants; bounds and family validation are applied before ingestion (`job.py:307-333`). Step worker numbers represent configuration capacity, not additional undeclared tasks.

### Accepted inputs: every declaration

All 19 inputs are handoff-channel producer evidence and allow partial coverage. Schema matching/admission is tested against the real producer declarations.

| Producer | Exact declared datasets | Requirement and actual access |
|---|---|---|
| `job_target_catalog` | `handoff` (`job-handoff/2`); `target_artifact_inputs` (`target-artifact-intake/1`); `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units` (`retrieval-index/2`); `catalog_documents` (`target-catalog/1`) | Envelope required/reject; seven datasets optional/gap. Handler actually reads the envelope, catalog JSON, and its hash-bound `repository_discovery.partition_repository` inventory; catalog manifest is the disabled-upstream fallback. It does not query all the declared catalog indexes or directly ingest standalone target-artifact coverage. Reports must be in accepted build receipts. |
| `job_language_build` | `handoff`; `topology_refinement_inputs` (`build-topology-refinement/1`); `build_actions`, `jvm_build_actions` (`retrieval-index/2`); `language_build_receipts` (`language-build-handoff/2`); `build_workspaces` (`application/octet-stream`) | Envelope when enabled/reject; five datasets optional/gap. `load_accepted_language_build` supplies the accepted receipt document and handoff hash; ingestion opens only enumerated candidate artifacts. Workspace/action indexes are not independently queried. |
| `job_artifact_indexing` | `handoff`; `artifact_catalog`, `archive_members`, `artifact_relationships` (`retrieval-index/2`); `artifact_index_summary` (`artifact-indexing/1`) | Envelope when enabled/reject; four datasets optional/gap. Accepted summary and full composed manifest are verified. Coverage does not scan artifact-catalog entities to discover additional reports. |

All schema IDs above have the `appsec-review/` prefix except the octet-stream type. `runtime.consume.accepted_upstream` uses typed declarations and admitted digests, records envelope access, and does not grant runtime access from a mutable latest pointer alone (`runtime/consume.py:162-229`). Broad optional declarations are availability, not proof that every dataset was consumed. Private JSON/report reads do not independently report every payload access; this is the documented reader-instrumentation boundary.

### Formats, mapping, bounds, and publication

- **LCOV:** strict UTF-8/BOM decoding; physical-line bound; `SF`, `DA`, `BRDA`, `FN`, `FNDA`; ignores summary/unknown tags. Per-record line/branch/function accounting, then same-source merging. TC-01 and TC-07 identify incorrect edge cases.
- **Cobertura:** XML root check, DTD/entity refusal, node count; per-class line maxima, per-line branch counters, method coverage from contained hits. Same-source class totals are added. TC-01 and TC-06 apply.
- **JaCoCo:** package/sourcefile `LINE` and `BRANCH` counters plus class `METHOD` counters keyed by source filename. Ordinary counter fixtures pass. The declared DTD prohibition is an interoperability limitation, described separately.
- **LLVM JSON:** file summaries for lines/branches/functions; mapping/list checks, per-file-row bound. Missing metric summaries default to zeros/rate null. TC-05 demonstrates non-integer coercion and an escaping exception.
- Artifact detection uses receipt kind or the exact exchange-name helper (`job_language_build/node.py:42-57`), then bounded prefix/content detection (`job.py:138-162`). Unsupported or `ValueError`-malformed reports become gaps; integrity errors stop. Candidate count is **per receipt**, not global. File truncation follows parser merging/sorting. XML/JSON decoding occurs before structural row counting; no stress/OOM validation was performed.
- Binding normalizes slashes/file URI/drive prefixes, tries catalog exact and build-root variants, then unique suffix matches (`job.py:165-208`). Ambiguous/unresolved rows retain null path/hash and do not enter totals. Candidate lists are bounded. No line-range-to-source validation is performed; these are reported file-level counts, not resolving line-level execution traces.
- Additive overlaps **between reports** are explicitly documented and retain an `overlapping_coverage_reports` gap. This audit does not redefine that decided policy as a new defect. TC-01 is the unmarked duplication **within one report**.
- Declared outputs are `test_coverage` (`index`, indexed, `analysis/test-coverage-*`, `retrieval-index/2`) and `test_coverage_handoff` (`acceptance`, artifact-only, `test-coverage-handoff/1`, `data/jobs/job_test_coverage/attempts/*/artifacts/test-coverage/*.json`). Actual generated paths/schemas match these globs. The indexed route does not work: TC-03.
- Domain JSON carries the schema identity constant and is built from normalized rows; the accepted loader checks publication membership, hashes, schema ID, and the full manifest (`job.py:468-486`). It is not an independent counter recalculator or full domain-record schema validator. Shared runtime validates the control envelope/outcomes; this job retains legacy text gaps rather than `strict_gaps=True`.
- Downstream declarations include review-data indexing, prioritization, package assembly, security tagging, OWASP assessment, document-issue analysis, and inference review. The materially traced consumers are `review/units.py` (TC-04), prioritization's real coverage reader/factor (TC-08), and retrieval's advertised/engineering-signal routes (TC-03). Their entire jobs were not audited here.

## Findings

### TC-01 — High — Repeated source records silently inflate file denominators

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/parsers.py:74-78,95-102,144,170-198`; `src/appsec_review/jobs/job_test_coverage/job.py:283-294`.
- **Trigger:** one LCOV artifact has two test-name/SF records for the same source line, or one Cobertura artifact repeats that line in classes sharing a filename.
- **Expected:** union executable line identities and covered hits within that source file, or explicitly report unsupported overlap. One line covered by either suite must not become two physical lines at 50%.
- **Actual:** both small fixtures produced `lines_total=2`, `lines_covered=1`, `lines_rate=0.5`, **`coverage_state="complete"` and no gaps**; the correct unique-line result is 1/1. Per-record deduplication is discarded when `_merge` adds aggregate totals.
- **Impact:** incorrect coverage counts/rates feed indexed cells, review context, and the numeric uncovered-risk factor (`job_review_prioritization/composite.py:627-655,719-724`).
- **Confidence:** reproduced with real parser and ingestion functions.
- **Smallest correction:** preserve line/branch/function identities until same-source records are merged; union compatible LCOV and Cobertura observations before computing totals. Preserve the separately documented cross-artifact policy.
- **Known overlap:** **existing C10-F01**, `docs/reviews/system-review-2026-11-13.md:1849-1859`; narrowed reconfirmation, **not new**. T-026 concerns evidence acquisition, not this arithmetic defect. No exact dedicated TODO found.

### TC-02 — Medium — Identical reports at different artifact paths abort indexing

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/job.py:267-274,398-405,414`; `src/appsec_review/retrieval/index.py:113-122`.
- **Trigger:** one accepted build lists two different report paths with identical bytes, hence the same artifact SHA and source rows.
- **Expected:** retain both report provenances and the documented overlap gap, producing a partial accepted result.
- **Actual:** ingestion correctly emits `overlapping_coverage_reports`; index identity includes report SHA but **not report path**, while entity payload includes `artifact_path`. Both rows get the same logical identity with different payloads. Real `IndexBuilder` raises `ValueError: index shard analysis/test-coverage-u has conflicting entities for identity ...`.
- **Impact:** harmless duplicated report copies turn an otherwise recoverable overlap into a failed index task and block normal handoff publication.
- **Confidence:** reproduced through real ingestion, real index handler, and real SQLite builder.
- **Smallest correction:** include the complete report identity needed to distinguish the retained rows, or explicitly coalesce identical report content while retaining all provenance references and compatible accounting.
- **Known overlap:** no exact TODO/prior finding found. C10-F01 covers additive overlap accounting, not this entity collision.

### TC-03 — Medium — The published dataset advertises an invalid retrieval route

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/datasets.py:10-13`; `src/appsec_review/retrieval/precomputed.py:17-24`; `src/appsec_review/retrieval/core.py:1260-1292`.
- **Trigger:** follow the published `query_precomputed query_set=test_coverage` route.
- **Expected:** retrieve the dataset's coverage cells.
- **Actual:** the real entry-point guard immediately raises **`ValueError: invalid precomputed query set`**. `test_coverage` is absent from `QUERY_SETS`; this route also selects only `precomputed_fact` rows in `precomputed` shards, whereas the producer emits `coverage_cell` rows in `analysis`.
- **Impact:** inventory-guided retrieval cannot use the advertised route even for correct accepted coverage.
- **Confidence:** reproduced entry-point rejection plus static storage/query mismatch.
- **Smallest correction:** advertise the existing `query_engineering_signals signal_family=test_coverage` route, which selects this producer's analysis shards (`core.py:1974-2038`), and test dataset-to-real-route compatibility.
- **Known overlap:** T-147 broadly covers declaration fidelity; no exact coverage-route TODO/prior finding found. Existing contract tests assert the incorrect string rather than invoke it.

### TC-04 — Medium — File coverage cells are mistaken for build aggregates and broadcast

- **Evidence:** producer `src/appsec_review/jobs/job_test_coverage/job.py:398-411`; consumer `src/appsec_review/review/units.py:73-84,266-268`.
- **Trigger:** an accepted build has coverage rows for multiple source files.
- **Expected:** each review unit receives its matching file cells plus one build aggregate. Unrelated file cells must not masquerade as aggregates.
- **Actual:** `_engineering_context` decides `aggregate = payload.get("totals") is not None`. **Every file cell also has `totals`.** A real generated shard for `src/a.c` and `src/b.c` produced build-wide context `[aggregate, a.c, b.c]`; context for a.c therefore included b.c.
- **Impact:** unrelated coverage is attached across all same-build review units and consumes their bounded context budget. Unresolved source cells also satisfy this aggregate test.
- **Confidence:** reproduced using real producer SQLite rows and the real consumer; only the accepted-scope access wrapper was faked.
- **Smallest correction:** publish/check an explicit aggregate discriminator, or distinguish the aggregate by the absence of a file-record discriminator such as `producer_path`. Do not use null `path` alone, since unresolved file rows have null paths.
- **Known overlap:** C10-F02 (`system-review-2026-11-13.md:1863-1872`) describes the analogous **profile** broadcast and incorrectly treats the coverage aggregate check as protective. This is a distinct coverage-specific defect; T-171 is related downstream wiring, not an exact fix.

### TC-05 — Medium — LLVM count validation truncates invalid values and lets overflow escape

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/parsers.py:62-71,238-244,267-271`; `src/appsec_review/jobs/job_test_coverage/job.py:253-257`.
- **Trigger:** a retained LLVM JSON summary contains a fractional count or JSON numeric token `1e309`.
- **Expected:** reject invalid nonnegative integer counters as `ValueError`, letting ingestion produce the normal artifact-scoped `malformed_coverage` gap.
- **Actual:** count `1.9` becomes 1; **negative `-0.5` becomes 0**. Both publish complete/no-gap normalized rows. `1e309` decodes to infinity; `int()` raises **`OverflowError: cannot convert float infinity to integer`**, which escapes the `ValueError` boundary and aborts ingestion.
- **Impact:** malformed reports either manufacture trusted-looking counters or prevent processing/publication of the remaining accepted reports.
- **Confidence:** reproduced through real receipt ingestion using tiny JSON artifacts.
- **Smallest correction:** validate integer representation, finiteness and sign before conversion; normalize conversion overflow to the parser's `ValueError` contract. Preserve ordinary integer text support for XML/LCOV.
- **Known overlap:** no exact TODO/prior finding found. Existing `_checked_int` tests cover bool/string/None/negative integer, not fractional or overflowing JSON numbers.

### TC-06 — Low — Unparseable Cobertura branch annotations silently become zero branches

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/parsers.py:181-186,192-198`; `src/appsec_review/jobs/job_test_coverage/job.py:253-257,290-294`.
- **Trigger:** a covered source line has `branch="true"` and an invalid/missing `condition-coverage` fraction.
- **Expected:** preserve a named parsing/coverage gap rather than claim complete branch accounting.
- **Actual:** the regex miss is silently ignored. A real fixture with `condition-coverage="not-a-count"` normalized to `branches_total=0`, `branches_covered=0`, rate null, **complete/no gaps**.
- **Impact:** missing branch coverage is indistinguishable from an instrumented file with no branches. Null rate is not itself a completeness warning.
- **Confidence:** reproduced parser-to-ingestion output.
- **Smallest correction:** reject the unparseable branch annotation via `ValueError`, or retain a parser gap and explicitly propagate it through ingestion.
- **Known overlap:** no exact TODO/prior finding found. `test_parsers.py` currently includes an `"unparsed"` branch annotation without asserting an accounting gap.

### TC-07 — Low — LCOV function records before SF are assigned to the next source

- **Evidence:** `src/appsec_review/jobs/job_test_coverage/parsers.py:95-110,128-138`; contrast the required-SF checks at `111-120`.
- **Trigger:** malformed LCOV contains `FN:1,ghost` and `FNDA:1,ghost` before its first `SF`.
- **Expected:** reject invalid record ordering, as DA/BRDA already do.
- **Actual:** the function dictionary is populated while `path is None`; entering the first SF does not clear it. The following source acquires one covered function it never declared. The real parser returned functions 1/1.
- **Impact:** wrong per-file function attribution/counts without a malformed-report disposition.
- **Confidence:** reproduced with the real parser.
- **Smallest correction:** require an active SF in FN and FNDA handling.
- **Known overlap:** no exact TODO/prior finding found. Existing malformed-order tests only cover DA and BRDA.

### TC-08 — Low — Prioritization labels successfully consumed coverage UNAVAILABLE

- **Evidence:** `src/appsec_review/jobs/job_review_prioritization/composite.py:207-214,824`; `src/appsec_review/jobs/job_review_prioritization/inputs.py:43-45`; producer `job_test_coverage/job.py:450-453`.
- **Trigger:** consume an actual accepted coverage handoff using the current `/2` envelope.
- **Expected:** report its real completion/availability status consistently with the imported cells.
- **Actual:** the consumer reads `handoff["terminal_status"]`, but the shared envelope carries `completion_status`; domain `terminal_status` is in `outputs["acceptance.publish_handoff"]`. From this audit's real runtime-unit fixture, both valid publication fields were `COMPLETED_WITH_GAPS`, one file with 2/1 covered-line counts was imported, but the consumer returned **`UNAVAILABLE`**.
- **Impact:** `engineering_sources.test_coverage` contradicts actual consumption. This status is metadata; the uncovered-risk calculation still uses the imported rows, so this finding does not claim the numeric boost is disabled.
- **Confidence:** reproduced against the exact untampered handoff emitted by the selected runtime unit test.
- **Smallest correction:** use the current envelope completion/coverage fields or the domain publication status, with an explicit legacy fallback.
- **Known overlap:** related **T-171** is marked done; no exact status-field TODO/prior finding found.

## Documentation drift and consciously excluded claims

**TC-D1 — Low documentation drift:** `docs/operations/test-coverage-ingestion.md:79,88` recommends nonexistent `tests/test_test_coverage.py` and `tests/test_multivuln_coverage_fixtures.py`. The former is now the four unit files; the latter is under `tests/live/` and still requires explicit live authorization. `docs/architecture/engineering-security-signals.md:320-321` repeats stale paths. No nonexistent/live command was executed. Related T-113 records the move.

**TC-D2 — Low documentation drift:** `docs/architecture/engineering-security-signals.md:280,293-295` still says coverage does not modify numeric prioritization. Current `composite.py:690,719-724` loads coverage and applies the configured uncovered-risk boost. This is subsequent **T-171** implementation, not a new request to change ranking policy.

**Documented JaCoCo restriction, not a new defect:** `_xml_root` deliberately rejects all DTD/entity declarations. A tiny JaCoCo report containing the standard-shaped public report DOCTYPE produced `malformed_coverage`/unavailable (reproduced). This limits ordinary DOCTYPE-bearing export compatibility, but follows the explicit architecture policy. Supporting such exports requires an explicit safe normalization/format decision; this audit does not recommend removing entity protections or treating this as a new bug.

**Conditional local-key concern, not an admitted stale-reuse finding:** `job.py:383-394` omits bounds/normalized rows from its local shard fingerprint. Directly invoking the index handler with the same report and a 2-file versus 1-file normalized result reused the same shard SHA: narrow handoff had one file, existing shard two. This is deliberately a helper-only reproduction; no frozen configuration was changed. `docs/architecture/scanners-and-evidence-collection.md:135-158` explains that the real runner rejects same-run config changes and successor runs do not import those shards. No authorized/admitted stale-reuse path was demonstrated. Do not count this as a runtime defect.

The previously proposed C10-F06 policy change (make absent coverage not-applicable) is **not** re-reported: current canonical docs explicitly require `missing_applicable_coverage` for a successful applicable build with no report. Disabled producers also have explicit gap semantics covered by the selected tests. These decided boundaries were preserved.

## Validation evidence

### Host verification and fixture inspection

Before execution:

```sh
cd /home/wsollers/projects/appsec-review
git rev-parse HEAD
git status --short
git branch --show-current
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Outputs: exact required SHA, clean status, `main`, ancestor success, authorized source import. A direct `offending_environment(os.environ)` assertion passed before pytest; no environment variables were repaired. Inspected both conftests, all selected test bodies, synthetic handoff/release helpers and recorded-producer fixture. Unit guards block real engines/non-loopback networks/Dagster execution; those boundaries were not reached.

One initial inventory shell used unavailable Linux `rg` (`bash: rg: command not found`); later searches used the authorized UNC rg tool or Python. No dependency was installed.

### Exact focused test command

All Linux commands were transported by the brief's base64-to-bash SSH pattern, not native Windows pytest or `wsl -e`.

```sh
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 1618 \
  --max-tests 69 --expect-tests 69 --timeout-seconds 180 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_test_coverage/test_contract.py \
  tests/unit/job_test_coverage/test_parsers.py \
  tests/unit/job_test_coverage/test_ingestion.py \
  tests/unit/job_test_coverage/test_job_graph.py \
  'tests/unit/runtime/test_wave3_contracts.py::test_coverage_and_profile_publish_unavailable_gaps_when_build_and_artifact_indexing_disabled[coverage]' \
  'tests/unit/runtime/test_wave3_contracts.py::test_coverage_and_profile_ingest_language_receipts_when_only_artifact_indexing_disabled[coverage]'
```

The wrapper owned unique run stem **`tests-custom-20261118-121526-162783-2768511`**. Its serial collection and subsequent execution both explicitly used `--basetemp=test/tmp/<stem>`; no shared default base temp was used. Collection removed `-n 2`, added `--collect-only`, and verified 69 exact nodes. Execution used two workers. The wrapper pins config/root and clears implicit addopts.

- Collection: 69 nodes, exit 0, **6.197 s** wall.
- Execution: **69 passed in 7.37 s** pytest time; **11.899 s** supervised wall, exit 0.
- No skipped/xfail cases, failures or errors; no case over 10 seconds.
- Wrapper cleanup confirmed no surviving supervised processes.
- Log: `test/tmp/logs/tests-custom-20261118-121526-162783-2768511.log`.
- JUnit: `test/tmp/tests-custom-20261118-121526-162783-2768511.junit.xml`.
- Timings: `test/tmp/tests-custom-20261118-121526-162783-2768511.timings.sqlite`.
- Collected nodes: `test/tmp/tests-custom-20261118-121526-162783-2768511.collection.json`.
- Fixed report: `test/tmp/reports/tests-custom-20261118-121526-162783-2768511.json`.

### Offline reproducer command

Executed `.venv/bin/python - <<'PY' ... PY` from the authorized checkout, with the following body. **Exit 0, 0.056 s measured body time**. It creates only a unique descendant of `test/tmp/`; no real external boundaries execute. Output was the results described in TC-01–TC-07 and the two separated limitations.

```python
from pathlib import Path
from types import SimpleNamespace
import json, sqlite3, time, uuid
from appsec_review.jobs.job_test_coverage import CoverageBounds, parse_coverage, ingest_coverage_artifacts, build_job
from appsec_review.retrieval import write_manifest
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.units import _engineering_context
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256
start = time.perf_counter()
root = Path('test/tmp') / ('job-audit-job_test_coverage-repro-' + uuid.uuid4().hex)
root.mkdir(parents=True)
root = root.resolve()
results = {}

def ref(path):
    return {'path': path.relative_to(root).as_posix(), 'sha256': file_sha256(path), 'size_bytes': path.stat().st_size}

def artifact(name, data):
    p = root / 'reports' / name
    p.parent.mkdir(exist_ok=True)
    p.write_bytes(data)
    return {**ref(p), 'workspace_path': name, 'kind': 'test-coverage', 'artifact_origin': 'build-output'}

def receipt(arts):
    return [{'build_unit_id':'u', 'root':'.', 'family':'native', 'terminal_status':'SUCCEEDED','artifacts':arts}]

hashes = {'src/a.c':'1'*64, 'src/b.c':'2'*64}
m = root / 'data/indices/manifests/upstream.json'
write_manifest(m, run_id=root.name, target_snapshot='snap', target_root=root, indexes=())
loaded = {'upstream_manifest':ref(m), 'upstream_handoffs':{}, 'gaps':[]}
handlers = {u.unit_id: u.handler for u in build_job().units}

def unit(uid, outputs, attempt):
    step, task = uid.split('.')
    ar = root / 'data/jobs/job_test_coverage/attempts' / attempt
    ctx = SimpleNamespace(run_root=root, run_id=root.name, source_fingerprint='snap',
                          attempt_id=attempt, attempt_root=ar, target_root=root, repository_root=root)
    return UnitContext(job=ctx, unit_id=uid, step_id=step, task_id=task,
                       unit_root=ar/'steps'/step/'tasks'/task, outputs=outputs)

lcov = b'TN:first\nSF:src/a.c\nDA:1,1\nend_of_record\nTN:second\nSF:src/a.c\nDA:1,0\nend_of_record\n'
cob = b'<coverage><class filename="src/a.c"><lines><line number="1" hits="1"/></lines></class><class filename="src/a.c"><lines><line number="1" hits="0"/></lines></class></coverage>'
for fmt, data in [('lcov',lcov),('cobertura',cob)]:
    doc = parse_coverage(data,fmt)
    got = ingest_coverage_artifacts(root,receipt([artifact('duplicate-'+fmt+('.info' if fmt=='lcov' else '.xml'),data)]),hashes)
    results['duplicate_'+fmt] = {'expected_unique_lines':1,'expected_covered_lines':1,
                                'actual':doc.files[0].totals.as_dict(),'state':got['units'][0]['coverage_state'], 'gaps':got['gaps']}

one = b'SF:src/a.c\nDA:1,1\nend_of_record\n'
normalized = ingest_coverage_artifacts(root,receipt([artifact('one.info',one),artifact('copy.info',one)]),hashes)
outputs = {'load.accepted_inputs':loaded, 'normalize.coverage':normalized}
try:
    handlers['index.coverage'](unit('index.coverage',outputs,'duplicate-reports'))
    results['identical_report_index'] = {'unexpected':'did not raise'}
except ValueError as exc:
    results['identical_report_index'] = {'ingestion_gaps':normalized['gaps'],'actual_error':str(exc)}

try:
    RetrievalCore.query_precomputed(SimpleNamespace(),query_set='test_coverage')
except ValueError as exc:
    results['declared_query_route'] = str(exc)

for value, label in [(1.9,'fraction'),(-0.5,'negative_fraction'),(float('inf'),'overflow')]:
    llvm = json.dumps({'type':'llvm.coverage.json.export','version':'2.0.1','data':[{'files':[{
        'filename':'src/a.c','summary':{'lines':{'count':value,'covered':0}}}]}]}).replace('Infinity','1e309').encode()
    try:
        got = ingest_coverage_artifacts(root,receipt([artifact(label+'.coverage.json',llvm)]),hashes)
        results[label] = {'totals':got['units'][0]['totals'],'state':got['units'][0]['coverage_state'],'gaps':got['gaps']}
    except Exception as exc:
        results[label] = {'exception':type(exc).__name__,'message':str(exc)}

results['lcov_function_before_source'] = parse_coverage(
    b'FN:1,ghost\nFNDA:1,ghost\nSF:src/a.c\nDA:1,1\nend_of_record\n','lcov').files[0].totals.as_dict()

branch = b'<coverage><class filename="src/a.c"><lines><line number="1" hits="1" branch="true" condition-coverage="not-a-count"/></lines></class></coverage>'
got = ingest_coverage_artifacts(root,receipt([artifact('branch.xml',branch)]),hashes)
results['invalid_branch_annotation'] = {'totals':got['units'][0]['totals'],'state':got['units'][0]['coverage_state'],'gaps':got['gaps']}

jac = b'<?xml version="1.0"?><!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd"><report name="fixture"><package name=""><sourcefile name="src/a.c"><counter type="LINE" missed="0" covered="1"/></sourcefile></package></report>'
got = ingest_coverage_artifacts(root,receipt([artifact('jacoco.xml',jac)]),hashes)
results['documented_doctype_limit'] = {'state':got['units'][0]['coverage_state'],'gaps':got['gaps']}

two = b'SF:src/a.c\nDA:1,1\nend_of_record\nSF:src/b.c\nDA:1,0\nend_of_record\n'
norm = ingest_coverage_artifacts(root,receipt([artifact('two.info',two)]),hashes)
out = {'load.accepted_inputs':loaded,'normalize.coverage':norm}
idx = handlers['index.coverage'](unit('index.coverage',out,'context'))
shard = idx['indexes'][0]
with sqlite3.connect(root/shard['relative_path']) as db:
    real_rows=[{'identity':identity,'payload':json.loads(payload)} for identity,payload in db.execute('SELECT identity,payload_json FROM entities')]
class Store:
    def entities(self,shards,**kw):
        return iter(real_rows) if shards else iter(())
class Scope:
    store=Store()
    def producer(self,name):
        return SimpleNamespace(shards=(shard,) if name=='test_coverage' else ())
    def shard_sha256(self,shard):
        return shard['sha256']
by_path, by_build, _ = _engineering_context(Scope())
ids_to_path={r['identity']:r['payload'].get('path','<aggregate>') for r in real_rows}
results['coverage_broadcast']={'expected_build_only':['<aggregate>'],
 'actual_build_only':[ids_to_path[e.id] for e in by_build['u']],
 'actual_context_for_a':sorted(set(ids_to_path[e.id] for e in [*by_path['src/a.c'],*by_build['u']]))}

narrow = ingest_coverage_artifacts(root,receipt([artifact('two.info',two)]),hashes,bounds=CoverageBounds(max_files_per_artifact=1))
out_narrow={'load.accepted_inputs':loaded,'normalize.coverage':narrow}
idx_narrow = handlers['index.coverage'](unit('index.coverage',out_narrow,'narrow'))
out_narrow['index.coverage']=idx_narrow
pub = handlers['acceptance.publish_handoff'](unit('acceptance.publish_handoff',out_narrow,'narrow'))
doc = json.loads((root/pub['artifact']['path']).read_text())
results['settings_reuse_handler_only']={'same_shard_sha':shard['sha256']==idx_narrow['indexes'][0]['sha256'],
 'normalized_file_count':len(doc['build_units'][0]['files']), 'existing_shard_file_count':sum(bool(r['payload'].get('path')) for r in real_rows),
 'runtime_reachability':'not established; immutable per-run configuration was not changed'}
results['scratch'] = root.relative_to(Path.cwd()).as_posix()
results['elapsed_seconds'] = round(time.perf_counter()-start,3)
print(json.dumps(results,indent=2))
```

The created scratch directory was `test/tmp/job-audit-job_test_coverage-repro-5103c05da96444b8a790d4c1770bd136`; it was removed after preserving the reproducer/results here. Wrapper-owned validation logs and fixtures were retained. Final root inspection and Git checks confirmed the same clean SHA; unrelated existing files were left untouched.

### TC-08 runtime-fixture probe, including failed exploratory pass

The first probe walked only this audit's pytest scratch, using:

```python
base = Path('test/tmp/tests-custom-20261118-121526-162783-2768511').resolve()
for hp in sorted(base.rglob('job_test_coverage/attempts/*/handoff.json')):
    doc = json.loads(hp.read_text())
    root = hp.parents[5]
    if doc.get('execution_status') != 'SUCCEEDED':
        continue
    with validation_scope(root):
        status, files = _load_test_coverage(root, True)
```

This printed the TC-08 mismatch from the valid runtime fixture, then **exited 1** on another test's deliberately tampered publication, `ValueError: accepted artifact identity changed`. The timer's final print was not reached; elapsed is not available. That exception is expected fixture damage from `test_accepted_publication_verifies_handoff_artifact_and_manifest`, **not a newly discovered runtime defect or failing pytest case**.

The retry selected the exact untampered fixture and ran this body with `.venv/bin/python -`:

```python
from pathlib import Path
import json, time
from appsec_review.jobs.job_review_prioritization.composite import _load_test_coverage
from appsec_review.storage.validation import validation_scope
start = time.perf_counter()
root = Path('test/tmp/tests-custom-20261118-121526-162783-2768511/popen-gw0/test_coverage_and_profile_inge0/runs/2026-11-18-0001').resolve()
hp = root/'data/jobs/job_test_coverage/attempts/attempt_0001/handoff.json'
doc = json.loads(hp.read_text())
with validation_scope(root):
    status, files = _load_test_coverage(root, True)
assert status == 'UNAVAILABLE' and files['src/main.c']['lines_total'] == 2
assert doc['completion_status'] == 'COMPLETED_WITH_GAPS'
print(json.dumps({'published_status':doc['outputs']['acceptance.publish_handoff']['terminal_status'],
 'consumer_status':status, 'file_count':len(files), 'elapsed_seconds':round(time.perf_counter()-start,3)}))
```

Result: **exit 0, 0.006 s**, published `COMPLETED_WITH_GAPS`, consumer `UNAVAILABLE`, file count 1. The same command read the fixed test report's stage durations and rechecked HEAD/clean status.

## Read coverage, prior work, and remaining gaps

**Read fully:**

- Assigned audit brief; authorized `AGENTS.md`; canonical multi-session coordination skill.
- All four files in `src/appsec_review/jobs/job_test_coverage/`: `__init__.py`, `datasets.py`, `job.py`, `parsers.py`.
- All four job unit test files; `tests/unit/runtime/test_wave3_contracts.py` (executed only its two coverage-parameter cases).
- `tests/conftest.py`, `tests/unit/conftest.py`, `tests/test_000_unit_environment_guard.py`, `tests/handoff_fixture.py`, `tests/release_support.py`, `tests/artifact_input_support.py`.
- Canonical `docs/operations/job_test_coverage.md`, `docs/architecture/test-coverage-ingestion.md`, `docs/operations/test-coverage-ingestion.md`, `docs/architecture/engineering-security-signals.md`, `docs/architecture/job-input-contracts.md`.
- `src/appsec_review/retrieval/precomputed.py`, `jobs/engineering_contracts.py`, `jobs/job_review_prioritization/inputs.py`; test wrapper shell entry and `scripts/lib/common.sh`.

**Read relevant ranges/search matches, not their entire subsystems:**

- `appsec-review.toml:1591-1623`; test-map coverage entry; registry import/registration; topology `1-95`; generic runtime job worker/strict-gap definitions and unit executor `1-150`; consume `85-256`.
- Accepted upstream loaders: language build `100-210`, artifact indexing `940-1040`; candidate-name helper `job_language_build/node.py:1-155`.
- Index fingerprint/build/reuse `retrieval/index.py:68-225`; retrieval construction/access `core.py:299-452`, precomputed `1250-1347`, engineering signals `1960-2086`.
- Coverage downstream consumer ranges in `review/units.py` and prioritization `composite.py`; seven downstream dataset declaration matches. Guidance registry was searched/parsed for job-specific bindings; no runtime skill/prompt was loaded as instructions.
- Wrapper `ops_tests.py` scope, command construction, execution/collection and CLI-option ranges; conftest support imports were inspected, but time-budget and host-pin helper implementations were not re-audited.
- Architecture job interchange `1-240`; scanner architecture `1-205`, including its conditional-key analysis.
- Relevant prior review C10-F01/F02/F06/F07 sections and coverage-related search matches in `docs/reviews/`; related TODO sections **T-026, T-147, T-171**, and coverage portion of **T-113**. Existing session audit reports were searched for coverage-related overlap; other jobs were not re-audited.

**Material unread/unexecuted scope:**

- No target checkout, checked-in target coverage reports, native coverage executables, real build receipts, active review output, provider/model behavior, or live JaCoCo/LLVM/Cobertura/LCOV export was inspected or executed. Synthetic inputs prove the specific functions, not production acquisition or report truth.
- No `tests/integration/test_signal_job_acceptance.py`, live multivuln suite, full downstream job, full Dagster graph, acceptance lane, schema-wide full suite, stress/large-report run, exhaustive parser-version matrix, or second shuffle seed.
- No independent coverage instrumentation was run; T-113's historical 100% line/branch claim is not adopted as this audit's result. Passing all 66 job cases did not cover the reproduced defects.
- Full source custody/admission/repair internals were not re-audited. The same-run-bounds helper collision is explicitly **not** evidence of an admitted stale shard.
- No fixes were made. Coordinator owns accumulation and any subsequent explicitly authorized repair. This auditor stops after job_test_coverage.
