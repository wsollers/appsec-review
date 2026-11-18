# Job 33/47 — job_owasp_control_assessment

## Scope and verdict

Read-only functional audit of **main, 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe**, in the authorized WSL checkout `/home/wsollers/projects/appsec-review`. HEAD and clean tracked/untracked status were checked before collection/execution and again after the probes. The editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The Windows checkout was not audited.

**125 focused unit cases passed in 72.28 seconds; zero failures, skips, or cases over 10 seconds. This does not establish pipeline correctness.** Seven functional findings below were established by source tracing and bounded offline probes: one high, five medium, one low. Several additional known limitations remain. No source/configuration/environment files were changed, no dependencies installed, no nested agents launched, and no actual models, providers, target programs, tools, services, integration, acceptance, or live reviews ran. Synthetic test/probe artifacts are confined to private `test/tmp/` descendants.

## Registration, contracts, and actual evidence

- Registered by `src/appsec_review/runtime/registry.py:99,170`; the configured job is enabled in assessment mode (`appsec-review.toml:2731-2773`), with **15 tasks in eight steps**. `config/loader.py:1452-1454` parses its closed settings. `_validate_config` checks exact step/task ordering, parser-version equality, enabled state, full nonfixture catalogs and supported selected providers (`jobs/job_owasp_control_assessment/job.py:78-100`).
- `CONTRACT`: **143 total requirements** covering **28 handoff producers** and the external third-party `feed_snapshot` requirement. Review-graph dispatch, checkout target access, not always-execute, propagating handoff. The inputs are predominantly optional/gap; native-advisory outputs are when-declared/not-applicable. Schedule predecessors are post-build assessment, evidence collection, artifact security, Tree-sitter, CodeQL, prioritization, code graph and security tagging. `CONSUMES` is contract-derived.
- Input discovery uses the attempt-pinned retrieval manifest and verifies the authenticated target snapshot, then `accept_manifest` and `EvidenceResolver`; it does not run an OWASP scan against a target. Qualification instead requires its explicitly selected run-owned JSON input and disabled worker/reviewer models.
- Actual accepted index allowlist: source, components, build, artifacts, build_security, compiled, analysis, evidence, inventory, observations, documents, tags, priority and graph (`owasp_workbench/evidence.py:24-28`). The resolver additionally filters by declared producer. `accept_manifest` first checks **all** embedded shards, including ones the resolver subsequently excludes (`review/scope.py:345-400`). This retains the known overbroad read/contract coupling, and exposes F01.
- Actual receipt enforcement is not merely `CONSUMES`: `runtime/inputs.py:330-385,474-499` resolves a pinned producer and its dataset owner, requires the exact input declaration/schema/authority, verifies the handoff artifact and bytes, then records producer/output-kind/schema/channel/authority, `read=True`, `cited=None`, artifact path/hash, handoff hash, attempt and target snapshot. Reads do not prove citation. Most selected job tests bypass that production input-read context: their `context_for` gives an empty `upstream_handoffs` mapping and does not attach the typed job contract (`tests/test_owasp_assessment_job.py:54-92`).
- Citation identity binds run, target, component, build unit, environment (`unestablished`), logical source, original index/shard/manifest hashes, file or structured locator, content hash and source custody (`evidence.py:265-393`). Resolution reopens the original accepted payload, rejects conflicting ownership/records and rechecks exact reference equality. Routing/model/precomputed conclusions are not original control proof.
- Four Python procedures and nineteen C/C++ procedures produce named source obligations. Runtime MASVS has no accepted adapter, even with dynamic authorization. Catalog text/version must match a reviewed procedure. No recognizer proves a security predicate: outcome entailment is analyst-assessed after application custody/subject checks.

### Every declared task and its execution

All handler references below are in `src/appsec_review/jobs/job_owasp_control_assessment/job.py`.

| Step.task | Actual implementation and disposition |
|---|---|
| standards_selection.ingest_catalogs | `ingest`, 144-148: loads every configured catalog, verifies independent inventory/content/license pins, writes standards manifest; qualification catalogs produce gaps. No network acquisition is dispatched. |
| standards_selection.select_profiles | `select`, 150-154: actual ASVS level selection; MASVS L1/L2 are local all-control aliases; MASTG supports, Top Tens route. Records per-family reasons and selection fingerprint. |
| characterization.load_inputs | `load_inputs`, 156-161; `_fixture_or_accepted_inputs`, 103-122: explicit qualification or pinned accepted evidence, tag/graph context and counted discovery. **F01**, **F04**. |
| characterization.classify_components | `classify`, 163-173: reads accepted derived target/facet tags, maps roles and keeps citations, confidence, source support and gaps; no model classifier. Enforces 1..max_components. |
| applicability.build_matrix | `applicability`, 175-188: every selected control × component. Class first: web API admits ASVS; network-service admits V1/V2/V5/V7/V16; mobile admits MASVS. Unknown class is unresolved, not N/A. Procedure/language/runtime gate; target-class ledger. Component gap propagation is incomplete (**F04**). |
| batching.partition_work | `partition`, 190-196; `engine.partition_work`: deterministic grouping by project/component/standard/version/profile/domain/evidence mode/tools/role/persona, chunking and exact dispatch accounting. Group key includes component, so max_components_per_batch is currently a ceiling over singleton-component batches, not a multi-component grouping target. Unsupported-obligation batches remain a known issue. |
| batching.build_packages | `packages`, 198-234: original control text, roles, context and versioned subject obligations. Evidence count/subject bounds; obligation evidence prioritized within half the worker input-byte estimate divided among rows; omitted evidence identities remain expansion candidates. Pins package-time guidance, which is not the actual call guidance (K02). |
| validation.cell_01 | `make_cell`, 236-284: positions congruent to 0 modulo four; max_batches admits the sorted global prefix. Actual request-sized worker parts, bounded expansion/retry and application validation; capped/injected-failure rows remain unresolved. **F02/F03/F05**. |
| validation.cell_02 | Same closure, positions 1 modulo four, independent result list and failure count. Same findings and bounds. |
| validation.cell_03 | Same closure, positions 2 modulo four. Same findings and bounds. |
| validation.cell_04 | Same closure, positions 3 modulo four. Same findings and bounds. |
| verification.independent_review | `verify`, 286-324: serially reviews all cell batch results with a freshly resolved evidence scope per batch. Blinded independent inference receives original packages, not worker answer/transcript; failed/capped batches without worker state pass through. **F02/F03/F05**; known serial-pool limitation. |
| join.deterministic_join | `join`, 326-333; `engine.py:728-775`: missing/duplicate/unexpected validator rows rejected, non-dispatch rows retained, result set identity and accounting emitted. No missing row is treated clean. Handler coverage status can miss characterization-only gaps (**F04**). |
| publication.publish_indexes | `publish_indexes`, 335-380: six immutable shard families, content/config/input/guidance fingerprints, run-bound manifest and accepted pointer. Actual source-line bound stored for later re-resolution. Package-time versus actual guidance mismatch K02. |
| publication.publish_handoff | `publish`, 382-470: workbench result, coverage/telemetry/ledger and independently-assessed adverse gap projection; validates the dedicated gap schema. **F03/F04/F07**. Generic runner publishes the actual accepted job handoff afterward. |

Direct `UnitExecutor.execute` runs these ordered tasks serially; Dagster binds each declared dependency to `execute_or_reuse_unit` (`orchestration/dagster/adapter.py:250-277`). Configured validator/verification pools are 4/2 (`appsec-review.toml:290-291`), assigned at adapter lines 133-140. There is only one independent-review task: a pool of two does not make its batch loop parallel. No Dagster execution was performed.

## Findings

### OCA-F01 — High — Current graph publication is undeclared at OWASP's actual read boundary

- **Evidence:** OWASP `datasets.py:105-114` declares four legacy graph outputs but not `alternate_cpg_index`. Producer `job_code_graph_index/datasets.py:50-54` owns `analysis/alternate-cpg`; `job_code_graph_index/job.py:415-435` publishes and embeds it. `review/scope.py:345-400` opens embedded shards, `indexing/store.py:85-87` observes the read, and `runtime/inputs.py:359-366,474-499` requires its exact dataset.
- **Trigger:** an assessment reaches characterization with the current accepted code-graph manifest (or its propagated descendant) containing that shard.
- **Expected/actual:** an intentionally admitted graph input should be consumable. The real read boundary raises `undeclared consumption by job_owasp_control_assessment: job_code_graph_index/alternate_cpg_index`, before database access. A declaration comparison found this is the sole currently missing indexed output among OWASP's declared producers.
- **Impact:** characterization cannot complete, so no assessment/publication follows. An earlier consumer may encounter the same family of contract failure first; this audit did not run a pipeline to establish which fails first.
- **Confidence/repro:** high; R1 declaration lookup and R3 actual `observe_shard`, with only accepted-producer custody supplied in memory.
- **Smallest correction:** declare the intended alternate indexed input with matching schema/authority, or exclude it through an explicit accepted-manifest source view before opening it. Add a real input-read-context regression with a graph-produced alternate shard.
- **Overlap:** **same defect family as prior code-graph auditor CGI-F12**, which reproduced inference/package consumers; this report adds the OWASP consumer. Related T-169 and T-5004, not a claim of a wholly new defect family.

### OCA-F02 — Medium — Malformed JSON field types escape model error handling and fail a whole cell

- **Evidence:** `owasp_workbench/assessment.py:76-90` performs hash/set membership on unchecked model `row_id`, obligation id and outcome. Lines 330-342 translate only `ValueError` into `ModelOutputError` and do not catch the resulting `TypeError`. `job.py:249-279` has no per-batch exception containment; `runtime/units.py:161-177` marks the entire task failed, blocking verification and publication.
- **Trigger:** a valid JSON final turn containing `{"row_id":[],"obligations":[]}` for one expected row.
- **Expected/actual:** malformed output should follow the configured retry and named unresolved-result path. Actual `investigate` raises **TypeError: unhashable type: 'list'**.
- **Impact:** one malformed model field bypasses bounded model-output recovery, can discard earlier completed batches in that cell's unreturned list, and blocks the common join instead of preserving scoped results.
- **Confidence/repro:** high; R2a runs actual investigation with a synthetic Infer returning the malformed turn. Existing malformed-output test only covers a missing result list.
- **Smallest correction:** validate scalar identifier/outcome types before membership and translate all contract-shape failures at the model boundary into the existing model-output error path.
- **Overlap:** no exact entry in inspected OWASP TODOs/prior reports.

### OCA-F03 — Medium — Part splitting reports undispatched rows as dispatched/reviewed and undercounts partial coverage

- **Evidence:** `assessment.py:548-562` selects row-specific execution status but copies the **whole batch** attempt list length into every ready row. `job.py:397,401` derives dispatched/review-attempted coverage from those counts. `job.py:404-405` counts only `unresolved` completeness or `cannot_verify`, excluding adverse rows whose completeness is `partial`.
- **Trigger:** a multi-row batch splits; one oversized row still cannot fit after trimming, while another is actually sent.
- **Expected/actual:** only the sent row should have attempts. R2b sends **only row-01**, once to each role, yet row-00 reports `execution_completion=input_budget`, `worker_attempt_count=1`, `reviewer_attempt_count=1`.
- **Impact:** publication/telemetry overstate actual row dispatch and review. Independently, the passing C++ job fixture has **17 partial adverse rows** omitted from its `unresolved_rows=316` denominator (R5). These omissions do not make the overall coverage disposition complete when other gaps remain.
- **Confidence:** high; actual request capture, real batch aggregator, and inspected unit-generated result artifacts.
- **Smallest correction:** retain part/row membership on attempts and calculate counts per actual dispatched row; explicitly include partial obligation coverage in the unresolved denominator.
- **Overlap:** T-5073 covers part/call multiplication, not these incorrect per-row counts; T-5078 is a broad misleading-output follow-up.

### OCA-F04 — Medium — Characterization gaps disappear from the published coverage/status

- **Evidence:** `evidence.py:620-626,674-675` retains omitted component-classification tags as gaps; `engine.py:202-230` retains them on classification. Applicability creates fresh gap arrays (`engine.py:336-427`); final publication takes row/catalog gaps only (`job.py:390,408-423`), never `characterization.load_inputs.gaps`.
- **Trigger:** at least one class survives the tag cap, another component-level target/facet is omitted, and retained classes make every family N/A. First-party-exclusion-only gaps are another affected path.
- **Expected/actual:** a declared unread-classification gap must remain visible and force partial publication. R2b passes that gap through actual classification and matrix/join, then the real publish handler returns **SUCCEEDED / complete / gap_count=0**, with `document.gaps=[]`.
- **Impact:** the published result and final task disagree with the load task's `COMPLETED_WITH_GAPS`. The generic executor still aggregates the earlier task's gap status, so this is **not** a claim that its overall job status necessarily becomes SUCCEEDED.
- **Confidence:** high; the probe uses synthetic component/custody inputs and real transformation/publication logic, no model.
- **Smallest correction:** carry input/classification coverage gaps into the final result and disposition, preserving deliberate N/A separately from unread evidence.
- **Overlap:** T-5004 broadly covers gap propagation/shape; T-5008 covers classification; no exact retained-class-plus-dropped-tag case found.

### OCA-F05 — Medium — Required caller/callee prerequisite citations cannot pass subject acceptance

- **Evidence:** `c_procedures.py:5-6,29-34,181-197` requires resolved caller/provenance evidence and describes citing caller/callee excerpts. But `assessment.py:442-476` requires **every** supporting/contradictory reference to independently contain the exact same named subject id. There is no separate prerequisite-citation slot in the final contract (`assessment.py:150-160`).
- **Trigger:** a named copy function and its concrete input-supplying caller are in different complete accepted source excerpts.
- **Expected/actual:** the invariant's primary subject must remain bound, while related prerequisite evidence should have an explicit verifiable representation. R3 resolves both citations; `copy.c` passes subject binding, `caller.c` is rejected as not containing the copy subject, and the whole outcome becomes `cannot_verify`.
- **Impact:** the workbench cannot retain a fully cited multi-function prerequisite proof in the contract it asks workers to satisfy. This is an acquisition/acceptance capability mismatch, **not** a claim that the synthetic adverse proposal establishes an exploitable bug or that unrelated citations should be accepted.
- **Confidence:** high for rejection/capability mismatch. The probe deliberately does not use a model to prove semantic entailment.
- **Smallest correction:** distinguish primary subject evidence from typed, source-bound prerequisite evidence and validate its relationship; do not weaken the current same-subject check indiscriminately.
- **Overlap:** related T-146/T-5013 scope, no exact inspected TODO/prior finding.

### OCA-F06 — Low — Advertised workbench filters miss finding-package records

- **Evidence:** packages store `component.component_id`, `component.project_id` and `control.identity/id` (`engine.py:541-549`). `indexes.py:123-138` only checks top-level aliases and assignment fields; query filtering at lines 178-181 therefore rejects these records. MCP advertises component/project/control filters without a family restriction (`mcp/owasp.py:14-23`).
- **Trigger:** query `family=finding-package` plus its actual component, project or control identity.
- **Expected/actual:** R5 publishes one package, unfiltered query returns **1**, each of those matching filters returns **0**.
- **Impact:** operator/application workbench navigation falsely appears empty. Control-result filtering is not implicated.
- **Confidence:** high, actual immutable publication and WorkbenchIndex query.
- **Smallest correction:** family-aware extraction of nested identities (and explicit semantics for plural component_ids), with focused matching/nonmatching queries.
- **Overlap:** T-5007 concerns tool advertisement but not this filter implementation.

### OCA-F07 — Medium — Adverse qualification rows wrongly require a target evidence resolver at publication

- **Evidence:** explicit qualification input loading needs only the run-owned fixture (`job.py:103-114`); qualification can produce `not_satisfied` from synthetic refutations (`engine.py:649-670`). `job.py:428-433` eagerly calls `_resolver` whenever any row is adverse, **before** `extract_verified_control_gaps` skips qualification at `engine.py:875-876`.
- **Trigger:** an otherwise valid qualification-only run has an adverse synthetic row but no accepted target index.
- **Expected/actual:** publish a qualification result and empty production gap projection. R6's real publish handler raises **RetrievalGap: accepted index manifest is unavailable**.
- **Impact:** supported synthetic qualification output fails at the last task because production evidence is requested unnecessarily. Existing assessment tests give qualification a complete accepted-index fixture and therefore hide this condition.
- **Confidence:** high; direct publication repro, no actual target/model.
- **Smallest correction:** construct the resolver only for assessment-mode candidate rows needing original-evidence resolution.
- **Overlap:** no exact inspected TODO/prior finding.

## Reconfirmed existing issues and nondefects

| ID / severity | Current evidence, trigger and consequence | Existing work / minimum correction |
|---|---|---|
| K01 / medium | No-supported-subject applicable batches still enter cells and log workers; `assessment.py:494-498,578-579` calls the empty case `missing_evidence`/failed, despite zero model calls. `job.py:250-254,280-284` counts worker failure. | T-5003, old process review F2. Partition after readiness or keep explicit non-dispatch dispositions; reserve failure for attempted work. |
| K02 / medium | Package-time bundle from `job.py:211-230` is fingerprinted at 343-351/368-370, but actual inference composes another at `assessment.py:112-127,203`. Actual test artifacts showed **3 package hashes, 2 call hashes, zero shared hashes**. Model receipt keys do bind actual call guidance, so this is published fingerprint/provenance mismatch, not demonstrated stale model reuse. | T-5005, old F5. Pin and propagate the actual per-role bundles once. |
| K03 / low | `strict_gaps` remains default false; literal valid producer status strings and free-text gaps remain (`job.py:499-503`; `tests/test_gap_contract.py:20`). `accept_manifest` checks every embedded shard before resolver filtering. | T-5004, old F3/F4. Typed strict gap controls and intentional accepted source views; do not claim absent citations from read receipts. |
| K04 / medium | `indexing/products.py:1289-1324` still projects every non-N/A row, including unsupported/subjectless rows; `review/packages.py:1517-1528,1985,2133` adds component-wide control context. This can consume context capacity without assessed evidence. | T-5009/T-5006. Separate coverage ledger from subject-bound assessed package context. N/A exclusion is implemented and tested; old blanket “277 every target” statements are not current facts. |
| K05 / low | Role text still says reviewer reviews elevated proposed claims, though actual request is blinded fresh assessment (`pipeline/guidance/registry.json:41-48` vs `assessment.py:114-119`). Workbench reference advertises `query_owasp_workbench` (`products.py:1333`) excluded from worker in-process tools (`review/capability.py:47`). | T-5007. Reconcile responsibility text and application-side/worker-side tool routes. |

Other already recorded constraints: T-5014 serial independent review/repeated resolver; T-5067 K&R/macro recognition; T-5073 split-part multiplication; T-5079 real-provider output budgets. They were not fixed or live-tested. T-5002's original whole-batch duplication is partly repaired by request assembly/splitting; do not repeat the old “nothing can dispatch” conclusion. Parser-version equality is now checked, although T-5063 requests broader contract identities. **T-5076's benign-counterevidence test passed in this audit**; its historical failure is not reproduced here.

Dissent/pending adverse hypotheses can still become provisional leads (`assessment.py:517-570`, `products.py:1190-1196`). This is documented conservative provisional behavior; T-5006 requests ranking/eligibility changes. It is not counted as a new final-verdict or exploit-confirmation defect.

## Publication and review consumers

Four output datasets agree with current emitted locations:

1. Protected `owasp_model_receipts`: `data/indexes/owasp/receipts/*.json`, actual proposal/attempt/usage/reuse records, not original target evidence.
2. Indexed `owasp_workbench`: standards, component-classification, applicability, validation-work, finding-package and control-result shards, manifests and accepted pointer under `data/indexes/owasp/`.
3. Artifact-only `owasp_documents`: the attempt's `artifacts/owasp-workbench/*.json` (standards, selection, classifications, applicability, target-class ledger, work, packages, verified results, joined results, final result).
4. Artifact-only `owasp_control_gaps`: the attempt's `artifacts/owasp-control-gaps/owasp-control-gaps.json`.

`publish_shard` binds records/gaps/schema/fingerprint inputs and refuses immutable byte conflicts (`indexes.py:34-60`). Manifest records run, mode, exact accepted upstream, configuration hash and source-line bound; the pointer is written after the immutable manifest. Model reuse keys bind semantic package/evidence/routing, actual role guidance, model policy and typed bounds; reuse re-resolves/rebinds citations and reports zero new calls. Worker/reviewer contexts remain blinded; original source proof is rechecked at acceptance and downstream projection.

The dedicated control-gap schema is validated before publication; its projection requires assessment/applicable-or-conditional/not_satisfied/independently_assessed and re-resolving references (`engine.py:804-925`). It does not certify vulnerabilities. Workbench result-set schema validates scoped/partial/unresolved/N/A/fixture distinctions; the job itself does not attach general output validators to every Unit.

`job_review_data_indexing.job.owasp_status:164-194` takes the manifest from the **admitted producer handoff**, verifies and observes the `owasp_workbench` output, not the floating workbench pointer. `indexing/products.py:1099-1369` reopens the original upstream manifest with its stored max_source_lines, resolves complete citation sets, and preserves lossless authority via workbench references. `review/lead_families.py:685-728` reopens those records for provisional adverse leads; `review/packages.py:1517-1528` does so for control context. Per-operation caches do not persist cross-run trust. `retrieval/core.py:1828-1868` implements `query_owasp_gaps` over the precomputed control evidence, not by reading the new gap-summary artifact; it requires independently-assessed adverse results with resolving evidence. That artifact is declared to review indexing but is not the payload this query reads.

## Validation commands and results

All Linux blocks below ran in the authorized checkout using its `.venv`; complex commands were transported with:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Preflight: `git rev-parse HEAD; git status --short; .venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'`; branch `main`, exact SHA above, empty status, correct import. Immediately before collection, `env | cut -d= -f1 | grep -E '^(APPSEC|DAGSTER|PYTEST)'` printed no matching inherited variable names. No shell environment was changed to bypass the guard.

### Focused units

The exact selection was reviewed before execution: root and job conftests, six selected files, and the fixture-builder/downstream helpers actually invoked. Source strings remain data; `ScriptedAssessment`/test `Infer` doubles replace external inference, and index/storage transformations remain real. No acquisition/provider/service fixture was selected.

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
.venv/bin/python -m pytest -q --collect-only -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-owasp-33-20261118-collect1 \
  tests/unit/job_owasp_control_assessment/test_contract.py \
  tests/unit/job_owasp_control_assessment/test_request_batching.py \
  tests/unit/job_owasp_control_assessment/test_target_class_job.py \
  tests/unit/job_owasp_control_assessment/test_c_subjects.py \
  tests/test_owasp_assessment_job.py tests/test_owasp_indexes.py
```

**125 collected, 0.57 s, exit 0.** One warning: `Unknown config option: cache_dir`, because cacheprovider was disabled. Collection ids for C snippet parametrization are long escaped source strings; no nondeterministic collection was observed.

```bash
set -eu
cd /home/wsollers/projects/appsec-review
test "$(git rev-parse HEAD)" = 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe
test -z "$(git status --porcelain)"
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3318 \
  --expect-tests 125 --max-tests 125 --strict -- \
  tests/unit/job_owasp_control_assessment/test_contract.py \
  tests/unit/job_owasp_control_assessment/test_request_batching.py \
  tests/unit/job_owasp_control_assessment/test_target_class_job.py \
  tests/unit/job_owasp_control_assessment/test_c_subjects.py \
  tests/test_owasp_assessment_job.py tests/test_owasp_indexes.py
```

Wrapper owned fresh base `test/tmp/tests-custom-20261118-131320-229209-3259985`; sequential collection/execution used that private directory. Guard fixed root/config, cleared inherited addopts, collected exactly 125, ran `-n 2 --shuffle-seed=3318`, and confirmed process cleanup. **125 passed; elapsed 72.28 s; failures 0; skipped 0; slower than 10 s none; exit 0.** No baseline exemptions used.

Persistent evidence:

- `test/tmp/logs/tests-custom-20261118-131320-229209-3259985.log`
- `test/tmp/logs/tests-custom-20261118-131320-229209-3259985.collection.log`
- `test/tmp/tests-custom-20261118-131320-229209-3259985.collection.json`
- `test/tmp/tests-custom-20261118-131320-229209-3259985.junit.xml`
- `test/tmp/tests-custom-20261118-131320-229209-3259985.timings.sqlite`
- `test/tmp/reports/tests-custom-20261118-131320-229209-3259985.json`

### Bounded probe commands

Each probe used `set -eu; cd /home/wsollers/projects/appsec-review` then `.venv/bin/python - <<'PY'` with the body below. Timings are measured probe-body monotonic times, not SSH startup. All exited 0 after printing the expected observed failure/result; no error was converted into a passing pytest case.

**R1 — declaration mismatch, 1.0148 s:**

```python
from appsec_review.runtime.registry import builtin_registry
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT
from appsec_review.runtime.datasets import shard_owner
from appsec_review.runtime.inputs import InputReads
from appsec_review.runtime.contracts import InputChannel
from types import SimpleNamespace
from pathlib import Path
import time
start=time.monotonic()
r=builtin_registry()
expected={(i.producer,i.output_kind) for i in CONTRACT.inputs}
for producer in sorted(CONTRACT.consumes):
    job=r.build(producer)
    for d in job.datasets:
        if getattr(d,'indexes',()) and (producer,d.output_kind) not in expected:
            print('missing indexed dataset',producer,d.output_kind, d.indexes)
graph=r.build('job_code_graph_index')
owned=shard_owner(graph.datasets,'analysis','alternate-cpg')
ctx=SimpleNamespace(contract=CONTRACT,config=SimpleNamespace(job_id='job_owasp_control_assessment'))
try: InputReads(ctx).requirement('job_code_graph_index', owned.output_kind, InputChannel.HANDOFF)
except ValueError as e: print('reproduced:',str(e))
print('elapsed',round(time.monotonic()-start,4))
```

Result: only `job_code_graph_index alternate_cpg_index ('analysis',)` missing; exact undeclared-consumption error reported in F01.

**R2a — malformed turn and initial counter probe, 0.2132 s:**

```python
from pathlib import Path
import json,time
from types import SimpleNamespace
from unittest.mock import patch
from dataclasses import replace
from appsec_review.owasp_workbench import assessment as a
from appsec_review.config.owasp import AssessmentMode,OwaspSettings
from appsec_review.inference import ModelResult
from tests.unit.job_owasp_control_assessment.test_request_batching import package
start=time.monotonic()
root=Path('test/tmp/job-audit-owasp-33-20261118-repros1').resolve()
root.mkdir(parents=True,exist_ok=False)
settings=OwaspSettings(True,AssessmentMode.ASSESSMENT,'reviewer',60,120,8,10,2,2)
profile={'provider':'offline-test','model':'synthetic','reasoning':'low','retries':0,'timeout_seconds':5,'max_input_tokens':6000,'max_output_tokens':5000}
batch={'batch_id':'bounded-repro','assignment':{'persona':None},'fingerprint':'x'}
resolver=SimpleNamespace(scope=SimpleNamespace(run_id='unit-run'), metrics={'attempts':0,'denials':0,'truncations':0,'missing':0})
p=package(0)
def malformed(request,*,timeout_seconds):
    return ModelResult({'schema':a.TURN_SCHEMA,'action':'final','results':[{'row_id':[], 'obligations':[]}]})
with patch.object(a,'_guidance',lambda *args: ({'bundle_sha256':'a'*64},'guidance')):
    try:
        a.investigate(repository_root=Path.cwd(),run_root=root/'malformed',batch=batch,packages=[p],role='control_assessor',profile=profile,settings=settings,resolver=resolver,infer=malformed)
    except Exception as exc:
        print('malformed turn escaped:',type(exc).__name__,str(exc))
    calls=[]
    def final(request,*,timeout_seconds):
        calls.append([r['row_id'] for r in request.task_input['packages']])
        return ModelResult({'schema':a.TURN_SCHEMA,'action':'final','results':[{'row_id':r['row_id'],'obligations':[{'obligation_id':o['obligation_id'],'subject_id':o['subject_id'],'outcome':'cannot_verify','rationale':'No decisive accepted evidence.','supporting':[],'contradictory':[],'assumptions':[],'evidence_requests':['Need source.'],'hypotheses':[],'limitations':[]} for o in r['proof_obligations'] if o.get('supported')]} for r in request.task_input['packages']]})
    huge=package(0); huge['control']['text']='x'*100000
    result=a.run_batch(repository_root=Path.cwd(),run_root=root/'counts',batch=batch,packages=[huge,package(1)],settings=settings,worker_profile=profile,reviewer_profile=profile,resolver=resolver,infer=final)
    print('actual requests row IDs:',calls)
    print('row reports:',json.dumps([{k:r[k] for k in ('row_id','execution_completion','worker_attempt_count','reviewer_attempt_count','verification_status')} for r in result['results']]))
print('elapsed',round(time.monotonic()-start,4))
```

Result: malformed turn escaped with TypeError; only row-01 was sent, but row-00 worker count was 1. **Probe limitation:** this first double deliberately returned one constant guidance hash for both roles, causing reviewer reuse (count 0). That artificial cross-role reuse is **not a finding**. R2b corrected the double to distinct role hashes and confirmed the count defect for both roles.

**R2b — distinct-role counters and dropped classification gaps, 0.4107 s:**

```python
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import json,time,tomllib
from appsec_review.owasp_workbench import assessment as a
from appsec_review.owasp_workbench.engine import classify_components,select_profiles,build_applicability,deterministic_join,target_class_ledger
from appsec_review.owasp_workbench.standards import load_catalogs,standards_manifest
from appsec_review.config.owasp import AssessmentMode,OwaspSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_owasp_control_assessment import job as j
from tests.unit.job_owasp_control_assessment.test_request_batching import package
start=time.monotonic()
root=Path('test/tmp/job-audit-owasp-33-20261118-repros2').resolve(); root.mkdir(parents=True,exist_ok=False)
settings=OwaspSettings(True,AssessmentMode.ASSESSMENT,'reviewer',60,120,8,10,2,2)
profile={'provider':'offline-test','model':'synthetic','reasoning':'low','retries':0,'timeout_seconds':5,'max_input_tokens':6000,'max_output_tokens':5000}
batch={'batch_id':'bounded-repro','assignment':{'persona':None},'fingerprint':'x'}
resolver=SimpleNamespace(scope=SimpleNamespace(run_id='unit-run'), metrics={'attempts':0,'denials':0,'truncations':0,'missing':0})
calls=[]
def final(request,*,timeout_seconds):
    calls.append((request.role,[r['row_id'] for r in request.task_input['packages']]))
    return ModelResult({'schema':a.TURN_SCHEMA,'action':'final','results':[{'row_id':r['row_id'],'obligations':[{'obligation_id':o['obligation_id'],'subject_id':o['subject_id'],'outcome':'cannot_verify','rationale':'No decisive accepted evidence.','supporting':[],'contradictory':[],'assumptions':[],'evidence_requests':['Need source.'],'hypotheses':[],'limitations':[]} for o in r['proof_obligations'] if o.get('supported')]} for r in request.task_input['packages']]})
with patch.object(a,'_guidance',lambda repo,run,batch,role: ({'bundle_sha256':('a' if role=='control_assessor' else 'b')*64},'guidance')):
    huge=package(0); huge['control']['text']='x'*100000
    result=a.run_batch(repository_root=Path.cwd(),run_root=root/'counts',batch=batch,packages=[huge,package(1)],settings=settings,worker_profile=profile,reviewer_profile=profile,resolver=resolver,infer=final)
print('actual requests:',calls)
print('counts:',[{k:r[k] for k in ('row_id','execution_completion','worker_attempt_count','reviewer_attempt_count')} for r in result['results']])
configured=tomllib.loads(Path('appsec-review.toml').read_text())['jobs']['job_owasp_control_assessment']['settings']
gap='cli: tag record cap omitted 1 target class or facet records; the component classification is unread'
raw={'component_id':'cli','project_id':'project','target_id':'target','evidence':[{'schema':'appsec-review/owasp-evidence-reference/1'}],'routing_context':[{'identity':'tag-cli','name':'target:cli','basis':'derived','subject':{'kind':'component'}}], 'gaps':[gap], 'tag_records_omitted':1}
classes=classify_components([raw],assessment_mode='assessment')
catalogs=load_catalogs(Path.cwd(),configured['standards']); selection=select_profiles(catalogs)
rows=build_applicability(catalogs,classes,selection,assessment_mode='assessment'); joined=deterministic_join(rows,[])
outputs={'join.deterministic_join':{'joined':joined,'artifact':{}}, 'standards_selection.select_profiles':{'selection':selection}, 'standards_selection.ingest_catalogs':{'manifest':standards_manifest(catalogs)},'characterization.load_inputs':{'gaps':[gap],'limitations':[],'terminal_status':'COMPLETED_WITH_GAPS'},'publication.publish_indexes':{'manifest':{}},'applicability.build_matrix':{'ledger':target_class_ledger(classes,rows)},'verification.independent_review':{'batch_results':[]},**{f'validation.{cell}':{'failed_batch_count':0} for cell in j.CELLS}}
unit=SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(settings=configured),repository_root=Path.cwd(),run_root=root,run_id='unit-run',attempt_root=root/'gap-report',events=SimpleNamespace(write=lambda *args,**kwargs:None)),unit_id='publication.publish_handoff',output=outputs.__getitem__)
published=next(u.handler for u in j.build_job().units if u.unit_id==unit.unit_id)(unit)
doc=json.loads((root/published['artifact']['path']).read_text())
print('input gap:',gap)
print('classification gaps:',classes[0]['gaps'])
print('published:',{k:published[k] for k in ('terminal_status','coverage_disposition','gap_count')},'document gaps:',doc['gaps'])
print('elapsed',round(time.monotonic()-start,4))
```

Results: actual requests `[('control_assessor',['row-01']), ('independent_reviewer',['row-01'])]`; both rows nevertheless have worker/reviewer counts 1. Classification retains the named omitted-tag gap; final output is `SUCCEEDED`, `complete`, 0 gaps. Custody inputs here are synthetic; the transformation and publication code are real.

**R3 — actual dataset-read check and prerequisite citation rejection, 0.0053 s:**

```python
from pathlib import Path
from types import SimpleNamespace
import time
from pytest import MonkeyPatch
from tests.unit.job_owasp_control_assessment.conftest import accepted
from appsec_review.config.owasp import AssessmentMode,OwaspSettings
from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.owasp_workbench.obligations import instantiate
from appsec_review.owasp_workbench.c_procedures import C_PROCEDURE_FIELDS
from appsec_review.owasp_workbench.assessment import accept_obligations
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT
from appsec_review.jobs.job_code_graph_index.datasets import DATASETS
from appsec_review.runtime import inputs
start=time.monotonic(); root=Path('test/tmp/job-audit-owasp-33-20261118-repros3').resolve()
root.mkdir(parents=True,exist_ok=False)
ctx=SimpleNamespace(contract=CONTRACT,config=SimpleNamespace(job_id='job_owasp_control_assessment'),run_root=root,upstream_handoffs={'job_code_graph_index':'a'*64})
reads=inputs.InputReads(ctx); reads.producers['job_code_graph_index']=({},DATASETS)
token=inputs._READS.set(reads)
try:
    try: inputs.observe_shard(root,{'name':'analysis','shard_id':'alternate-cpg','producer':{'job':'job_code_graph_index'}})
    except ValueError as e: print('real read boundary:',str(e))
finally: inputs._READS.reset(token)
with MonkeyPatch.context() as mp:
    fixture=accepted.__wrapped__(mp,root)({'copy.c':'void copy(char *s) {\n char b[8]; strcpy(b,s);\n}\n','caller.c':'void serve(int fd) {\n char in[32]; recv(fd,in,sizeof(in),0);\n copy(in);\n}\n'},languages={'copy.c':'C','caller.c':'C'})
    settings=OwaspSettings(True,AssessmentMode.ASSESSMENT,'reviewer',60,120,8,10,2,2)
    evidence,gaps=component_evidence(fixture.resolver,'api',fixture.files,settings)
    rule=next(r for r in C_PROCEDURE_FIELDS if r['control']=='V1.4.1')
    control={'family':'ASVS','version':'5.0.0','id':'V1.4.1','text':rule['control_text']}
    row={'row_id':'row','control_identity':'ASVS:5.0.0:V1.4.1','component_id':'api','target_id':fixture.scope.target_snapshot}
    obligations=instantiate(control,row,evidence,max_subjects=8); obligation=next(o for o in obligations if o['supported'])
    primary=next(e['reference'] for e in evidence if e['reference']['locator']['path']=='copy.c')
    caller=next(e['reference'] for e in evidence if e['reference']['locator']['path']=='caller.c')
    item={'obligation_id':obligation['obligation_id'],'subject_id':obligation['subject_id'],'outcome':'not_satisfied','rationale':'Synthetic proposal cites the copy and its concrete input caller.','supporting':[],'contradictory':[primary,caller],'assumptions':[],'evidence_requests':[],'hypotheses':[],'limitations':[]}
    package={'control':control,'component':{'component_id':'api'},'proof_obligations':[obligation]}
    result=accept_obligations(package,{'obligations':[item]},fixture.resolver)[0]
    print('cross-function prerequisite:',result['outcome'],result['gaps'])
    print('citation checks:',[(c['reference']['locator']['path'],c['resolution'],c['subject_binding']) for c in result['citation_checks']])
print('elapsed',round(time.monotonic()-start,4))
```

Results: undeclared alternate dataset; caller and copy both `resolved`, subject bindings respectively false/true; outcome `cannot_verify` with the exact named-subject error. Only original index/byte access is faked by the inspected existing fixture; selection, reference creation/re-resolution, procedure instantiation and acceptance are real.

**R4 — actual versus package guidance, 0.2694 s:**

```python
from pathlib import Path
import json,time
start=time.monotonic(); root=Path('test/tmp/tests-custom-20261118-131320-229209-3259985')
for path in sorted(root.rglob('finding-packages.json')):
    packages=json.loads(path.read_text()).get('batches',{})
    if not packages: continue
    attempt=path.parents[2]
    results=attempt/'steps/verification/tasks/independent_review/result.json'
    if not results.exists(): continue
    batches=json.loads(results.read_text()).get('batch_results',[])
    actual={a['guidance'] for b in batches for a in b['metrics'].get('attempts',[])}
    pinned={p['guidance']['bundle_sha256'] for ps in packages.values() for p in ps}
    if actual:
        print('fixture:',path)
        print('package guidance count',len(pinned),'actual guidance count',len(actual),'shared',len(pinned&actual))
        break
mapping=json.loads(Path('tests/job-test-map.json').read_text())['jobs']['job_owasp_control_assessment']['unit'] if False else None
print('elapsed',round(time.monotonic()-start,4))
```

Result: first matching fixture was `popen-gw0/test_assumed_material_prerequi0/.../finding-packages.json`: package guidance 3, actual guidance 2, intersection 0.

**R5 — real workbench filtering and partial-row denominator, 0.2764 s:**

```python
from pathlib import Path
import json,time
from appsec_review.owasp_workbench.indexes import WorkbenchIndex,publish_shard,publish_manifest
start=time.monotonic()
root=Path('test/tmp/job-audit-owasp-33-20261118-filter-repro').resolve(); root.mkdir(parents=True,exist_ok=False)
run=root/'unit-run'
record={'row_id':'row','component':{'component_id':'component:1','project_id':'project:1'},'control':{'id':'V1.2.4','identity':'ASVS:5.0.0:V1.2.4'}}
shard=publish_shard(run,family='finding-package',shard_id='one',records=[record],fingerprint_inputs={})
publish_manifest(run,run_id='unit-run',shards=[shard],accepted_upstream_manifest={},configuration_sha256='a'*64)
index=WorkbenchIndex(root,'unit-run')
print('all packages',len(index.query(family='finding-package')['results']))
for key,value in [('component','component:1'),('project','project:1'),('control','ASVS:5.0.0:V1.2.4')]:
    print(key,len(index.query(family='finding-package',**{key:value})['results']))
base=Path('test/tmp/tests-custom-20261118-131320-229209-3259985')
for path in sorted(base.rglob('control-results.json')):
    if 'test_cpp_network_service' not in str(path): continue
    rows=json.loads(path.read_text())['results']
    partial=[r for r in rows if r['coverage_completeness']=='partial' and r['control_status']=='not_satisfied']
    report=json.loads(path.with_name('owasp-workbench-result.json').read_text())
    print('CPP fixture',str(path),'unresolved_rows',report['coverage']['unresolved_rows'],'partial_adverse_excluded',len(partial))
print('elapsed',round(time.monotonic()-start,4))
```

Result: 1 unfiltered, 0 for each matching nested filter. C++ fixture `popen-gw0/test_cpp_network_service_is_as0/.../control-results.json`: unresolved_rows 316, partial adverse excluded 17.

**R6 — qualification adverse publication, 0.1719 s:**

```python
from pathlib import Path
from types import SimpleNamespace
import json,time,tomllib
from appsec_review.jobs.job_owasp_control_assessment import job as j
from appsec_review.owasp_workbench.standards import load_catalogs,standards_manifest
start=time.monotonic(); root=Path('test/tmp/job-audit-owasp-33-20261118-qualification-repro').resolve();root.mkdir(parents=True,exist_ok=False)
settings=tomllib.loads(Path('appsec-review.toml').read_text())['jobs']['job_owasp_control_assessment']['settings']
settings['mode']='qualification';settings['model']['enabled']=False;settings['models']['reviewer']['enabled']=False
row={'applicability':'applicable','control_status':'not_satisfied','assessment_mode':'qualification','worker_attempt_count':0,'reviewer_attempt_count':0,'execution_completion':'qualification_completed','verification_status':'qualification_only','coverage_completeness':'fixture_only','lead_eligible':False,'gaps':[]}
outputs={'join.deterministic_join':{'joined':{'results':[row],'accounting':{'selected':1,'joined':1,'exactly_once':True}},'artifact':{}},'standards_selection.select_profiles':{'selection':{'control_count':1}},'standards_selection.ingest_catalogs':{'manifest':standards_manifest(load_catalogs(Path.cwd(),settings['standards']))},'characterization.load_inputs':{'limitations':[]},'publication.publish_indexes':{'manifest':{}},'applicability.build_matrix':{'ledger':{}},'verification.independent_review':{'batch_results':[]},**{f'validation.{cell}':{'failed_batch_count':0} for cell in j.CELLS}}
unit=SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(settings=settings),repository_root=Path.cwd(),run_root=root,run_id='unit-run',attempt_root=root/'attempt',events=SimpleNamespace(write=lambda *args,**kwargs:None)),unit_id='publication.publish_handoff',output=outputs.__getitem__)
try: next(u.handler for u in j.build_job().units if u.unit_id==unit.unit_id)(unit)
except Exception as exc: print('qualification adverse publication:',type(exc).__name__,str(exc))
print('elapsed',round(time.monotonic()-start,4))
```

Result: `RetrievalGap accepted index manifest is unavailable`.

An additional read-only inventory/filter-alias probe took 0.0030 s, printed 143 inputs/28 producers/four outputs, compared `tests/job-test-map.json` against `tests/unit/job_owasp_control_assessment/test_*.py`, and inspected `WorkbenchIndex._value`; the actual-query R5 above supersedes that alias-only check.

```python
from pathlib import Path
import json,time
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT,DATASETS
from appsec_review.owasp_workbench.indexes import WorkbenchIndex
start=time.monotonic()
print('input requirements',len(CONTRACT.inputs),'handoff producer count',len(CONTRACT.consumes),'datasets',len(DATASETS))
print('handoff producers',','.join(sorted(CONTRACT.consumes)))
mapping=json.loads(Path('tests/job-test-map.json').read_text())
print('mapping keys',list(mapping))
item=(mapping.get('jobs') or mapping)['job_owasp_control_assessment']
actual={p.as_posix() for p in Path('tests/unit/job_owasp_control_assessment').glob('test_*.py')}
print('unmapped existing job unit files:',sorted(actual-set(item['unit'])))
record={'component':{'component_id':'component:1','project_id':'project:1'},'control':{'id':'V1.2.4','identity':'ASVS:5.0.0:V1.2.4'}}
print('finding-package filters:',{k:WorkbenchIndex._value(record,k) for k in ('component','project','control')})
print('elapsed',round(time.monotonic()-start,4))
```

## Read coverage and material limits

**Read fully:** root AGENTS and coordination skill; shared audit brief; OWASP job.py/datasets.py; config/owasp.py; every Python module in `owasp_workbench/` (`__init__`, acquisition, assessment, batching, c_procedures, c_subjects, engine, evidence, guidance, indexes, obligations, standards, subject_selection, versions); architecture/owasp-control-workbench.md; both OWASP workbench/result and dedicated gap schemas; MCP owasp.py; six selected test files; root tests/conftest.py and job conftest; scripts/run-tests.sh and scripts/lib/common.sh. Runtime governing-rules, effective-control-verification and predicate-verification were read **as worker prompt data**, not agent instructions.

**Sampled/traced:** canonical generated job operations page 1-150 and search hits; hand-written OWASP operations 1-190; previous process review 1-190 and value review 1-170; relevant TODO entries T-146/147/165/169/172, T-5002..5014, T-5063..5067, T-5073..5079; prior session reports searched for overlap, CGI-F12 read; registry, TOML OWASP/pool settings, config loader, Dagster adapter; runtime units 1-245 and runtime inputs 330-502; retrieval core manifest/database and OWASP-query sections; review scope 327-end; indexing store open/summary; indexing products control section 1099-1369; review-indexing owasp_status; review lead and package control paths; builder fixture 1-352 plus call sites, downstream helper 1-180. No inherited old-checkout source was used.

**Material unread/unexecuted:** most dedicated evidence-binding/proof/telemetry/catalog test cases and job-unit files outside the six-file selection; other test tiers; complete runtime admission/resume/signing implementation; all provider transport implementations; deployment behavior beyond static pool/adapter wiring; every persona fragment's prose; catalog raw upstream source inventories/bytes beyond loader checks; full reporting/rendering and red/blue/verifier execution paths. Actual catalogs were loaded and validated by selected units, but not reacquired. No current target/run outputs or private walk answer keys were read. The source supports bounded static analyst questions, not live efficacy or exact whole-target correctness.

The mapping omits six existing job-local unit files: `test_c_subjects.py`, `test_control_roles.py`, `test_network_service_class.py`, `test_parser_versions.py`, `test_request_batching.py`, `test_tag_discovery.py`. Two were explicitly included despite that omission; mapping omissions are not missing tests.

No integration, acceptance, live model, runtime adapter, service, full-suite or production-run validation is claimed. Report completed for this job only; no fixes, commits or pushes.
