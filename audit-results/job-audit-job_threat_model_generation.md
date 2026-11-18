# Functional audit: job_threat_model_generation (34/47)

Date: 2026-11-18. Authorized checkout: `/home/wsollers/projects/appsec-review`, Ubuntu-22.04, accessed through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the brief's UNC path.

**Exact revision:** `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`, branch `main`. HEAD, clean `git status --short`, and ancestor check passed before validation; HEAD and cleanliness were unchanged afterward. `.venv/bin/python` imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. The unit environment detector reported no production bindings. The Windows working checkout was not audited.

**Result:** four reproduced functional defects (one high, three medium), plus two stale test assertions grouped as one low-severity test defect. All 298 mapped unit cases executed: **296 passed, 2 failed, no skips/errors, no tests over ten seconds**. No source/environment edits, installs, providers, target execution, integration/acceptance/live reviews, services, containers, commits, or subagents.

## Contract and intentional limits

- Registered factory: `src/appsec_review/runtime/registry.py:102,173`; job construction: `src/appsec_review/jobs/job_threat_model_generation/job.py:323-335`.
- Disabled by default: `appsec-review.toml:1089-1133`. Job workers = 2; each configured step = 1. Typed settings validate exactly seven integer bounds, a Boolean `enabled`, and a closed resource reservation (`config/loader.py:550-601`). Defaults: processes 200, entry points 4000, flows 8000, threats 4000, query rows 2000, references per element 8, render nodes 120; reservation 2 CPUs/1024 MiB/one I/O slot/600-second admission timeout.
- Contract: `TargetAccess.ACCEPTED_EVIDENCE`, `DispatchClass.REVIEW_GRAPH`, strict structured gaps. `schedule_after` names OWASP assessment, dependency intelligence and security tagging; graph reduction leaves OWASP as the direct predecessor. A scheduling edge is not input permission.
- There are **seven producer envelopes and ten dataset inputs**. Only the target-catalog envelope is required/reject; all dataset inputs and other envelopes are optional/gap with partial coverage permitted.
- The job is **deterministic**, not model-assisted. No elaboration/declarations task exists and no provider/model/tool dispatcher is called by its eight handlers. The guidance registry permits `evidence-and-graph-querying` for this job (`pipeline/guidance/registry.json:758-763`), but this job does not load or select that skill. Permission is not execution.
- **Architecture documents, security tags, OWASP workbench/control results, dependency classifications, deployment descriptors and mitigation observations are not accepted/read inputs in this slice.** Historical design sections proposing them are not implemented requirements silently assumed satisfied. Assets and supplied-document lists are empty; mitigation is always `not_examined`; related controls are empty. The crosswalk is static reference data, not the run's OWASP assessment.
- T-107 explicitly leaves declaration/mitigation/asset enrichment and real-run usefulness unaccepted. T-108 owns the unregistered deployment producer. Every execution emits its deployment gap and cannot represent complete deployment coverage.

### Accepted inputs and actual use

| Producer / datasets | Actual read and transformation |
| --- | --- |
| Target catalog / `build_units`, `components` | Structure reads `build_action` payloads/build points and component roots. Executable declarations become process facts; library declarations become library facts. Root matching attaches deepest components. |
| Target catalog / `source_files` | Load records input availability/coverage only. No source-file entity query or original source-byte read is commissioned. Its ledger can say `read` with `records_read = 0`; do not interpret that state alone as source consumption. |
| Artifact indexing / `artifact_catalog`, `artifact_relationships` | Reads executable/library rows and `LINKS_INTO` relations. Target-intake artifacts do not establish a built process. |
| Language build / `build_actions` | Reads executable/library rows with workspace path/build-unit identity; merges named declared and built things. |
| C++ compiled analysis / `cpp_build_graph` | Reads executable/library/compile-unit rows and `COMPILES_TO`/`LINKS_INTO`. Unique names join established things; otherwise project-scoped identities are used. |
| Code graph / `code_graph_facts` | Reads entry and sink entities; maps source/sink class to interaction. **Eligibility and weaker producer origin are not retained: TM-02.** |
| Tree-sitter / `tree_sitter_ast` | Exact written-name call queries, one per catalog callee. **Language restriction ignored: TM-03; sites merged too coarsely: TM-04.** |
| Review prioritization / `priority_items` | Reads published `review_signal` entities and maps category/surface; most unmatched signals yield no interaction. Retains source location and inferred symbol. |

`IndexEvidenceView` declares these pairs (`threat_model/index_view.py:79-90`), loads accepted handoffs with claim pins, selects shards using the producing claim's dataset contract, verifies handoff-bound path/hash custody, opens SQLite read-only, and records shard reads through `indexing.store.open_shard` / `runtime.inputs.observe_shard`. Missing optional inputs become ledger/gap states; admitted byte changes raise rather than becoming ordinary absence. Queries sort by entity identity/shard digest, request limit+1, and report truncation. These are bounded index reads, not a target-tree scan.

Actual upstream emission excerpts were checked, not just lane comments: target catalog `job.py:603-613,775-785`; artifact indexing `job.py:617-631,857-890`; language build `job.py:1809-1825`; compiled analysis `job.py:458-517`; Tree-sitter `normalize.py:206-217`; prioritization `job.py:789-818`; graph `scopes.py:741-779`.

## Every declared task/step

Paths in this table are beneath `src/appsec_review/`.

| Step.task | Handler and dispatch | Processing, output and coverage limit |
| --- | --- | --- |
| `load.accepted_inputs` | `jobs/job_threat_model_generation/job.py:205-224`; no dependencies | Validates three reference JSON files and requires the attempt snapshot. Builds generated/routing-only origin with all three hashes and `model=null`. Records source-files ledger state and explicit deployment-unregistered gap. Writes canonical `work/inputs.json`. |
| `facts.structure` | `job.py:226-238`; depends on load | Holds configured resource reservation and validation scope. `threat_model/lanes/structure.py` derives/merges build-point, artifact, library and link facts; records redacted-name/path provenance loss; caps processes and queries. Writes `work/structure.json`, counts and lane-owned gaps. No original build/target execution. |
| `facts.interactions` | `job.py:240-243`; depends on load | Rechecks reference hashes, holds reservation, executes three input lanes in `threat_model/lanes/interactions.py`. Missing locations are gaps. Caps queries and total interaction facts via `max_entry_points`; strongest basis first. Writes `work/interactions.json`. TM-02/03/04 affect this stage. |
| `assembly.dfd` | `job.py:245-253`; depends on both fact tasks | Rechecks references and digest-checked working records. `threat_model/assemble.py` folds libraries transitively into processes; attributes sites by build unit narrowed with source paths, then exact path, then longest root. Derives peers, flows, boundaries, inbound entry points, actor-position candidates and explicit unknowns. Caps flows and entries, creates boundaries only for retained crossing flows. Writes `work/assembly.json`. |
| `threats.enumerate` | `job.py:255-260`; depends on assembly | Rechecks references. `threat_model/threats.py` applies matching interaction/boundary/direction templates; ID = template+flow, candidate state, unchanged flow evidence, `not_examined` mitigation. Caps by deterministic threat-ID ordering. Writes `work/threats.json`. Datastore/file-write flows deliberately have no boundary/template in this slice. |
| `validation.resolve_citations` | `job.py:262-274`; depends on threats | Reads assembly/threat work records and resolves distinct references against admitted shard/entity/kind/locator identities. Removes unsupported records; cascades endpoint/flow/peer/boundary/actor/threat removals and emits demotion unknowns/gaps. Writes `work/validated.json`. Resolving a record's existence does not repair the semantic errors above. |
| `publication.render` | `job.py:276-284`; depends on validation | Joins preceding gaps, builds documents, renders Mermaid and Markdown. Node-bound overflow gets one new structured gap and a rerender naming it. Writes `views/dfd.mmd`, `views/threat-model.md`, and bounded per-process diagrams when needed. Labels/prose sanitized; identifiers derived, not target names. |
| `publication.publish_handoff` | `job.py:286-321`; depends on render | Rebuilds canonical documents; schema/cross-reference validation; compares document payloads for purity and all rendered bytes for equality/custody. Publishes DFD/model/evidence/result and artifact references; emits publication event. Returns `gaps=[]`, `SUCCEEDED` **only for this joining unit**; upstream task gaps remain in result and job accounting. TM-01 affects the subsequent indexed consumer, not these canonical files. |

All eight unit functions were exercised by the mapped handler tests with synthetic attempt-owned evidence and fake external boundaries. This is not JobRunner admission/integration or a real threat-model review.

### Identities, validation and publication

- Process identities are build-unit/name (or project/name; redacted names use record identity); flow = process/peer/interaction; boundary = process/kind; entry = process/fact; actor = external entity; threat = template/flow.
- Evidence references bind entity identity, shard digest and optional locator; locators include file digest, line span and available byte span. Evidence basis/rule remains separate. Merge limits intentionally retain bounded strongest references.
- `resolve_citations` resolves to accepted index records; it does not read/check original source bytes or establish that a cited call really implements a template's concern. Generated facts are routing context, not findings.
- Closed document schemas reject extra top-level/record keys, unknown vocabularies, missing evidence, bad origin authority and malformed IDs. `validate_documents` also checks sorted/unique record IDs, endpoints, boundary membership, process/external references and cited-reference membership.
- **Validation limitation, not separately promoted as a currently produced corrupt-output defect:** `validate_documents` does not recompute result counts or verify artifact bytes; counts are constructed by `build_documents`, and artifact/render custody is enforced separately in the job. The operations page's blanket “validate … counts and artifact bindings” description is broader than that helper alone. It also does not compare every inline evidence object byte-for-byte with its evidence-registry entry; the behavior consumer adds a critical-field comparison.
- Three reference files are closed/duplicate-key checked and hash-pinned; class-vocabulary parity is validated on load. Crosswalk catalog coverage is checked by focused tests. Source/template/schema files participate in `release-dependencies.json`; no model receipts exist. Working-file paths/hashes are attempt-bound; cross-attempt reuse/admission was not executed.

Five datasets, all `artifact_only`, authority `routing_context`, sensitivity `internal`, family `threat_model`, publication step (`jobs/job_threat_model_generation/datasets.py:24-59`):

| Dataset | Payload patterns relative to attempt `artifacts/threat-model/` |
| --- | --- |
| `generated_dfd` | `dfd.json` |
| `generated_threat_model` | `threat-model.json` |
| `generated_model_evidence` | `evidence.json` |
| `generated_model_views` | `views/*.mmd`, `views/*.md` |
| `threat_model_documents` | `result.json`, `work/*.json` |

The patterns matched generated handler outputs in tests. No generated model is inserted into the target-owner `documents` index. The direct inference behavior loader (`review/behavior.py:161-274`) admits/hash-checks all four files, checks run/snapshot/authority, joins only original operation anchor identities, enforces byte/context bounds and preserves partial-map gaps. Separately, review-data indexing now accepts these datasets and builds `threat_boundaries`; that consumer is broken for the producer's actual schema (TM-01). Source comments claiming “no consumer” and the old contract assertions are stale (TM-05).

## Findings

### TM-01 — High: indexed consumer drops actual generated threats and loses boundary/source ownership

- **Evidence:** `src/appsec_review/indexing/products.py:1515-1542,1572-1599,1648-1702`; producer record fields in `src/appsec_review/threat_model/contract.py:346-415,455-474`; accepted load path `src/appsec_review/jobs/job_review_data_indexing/job.py:198-238`.
- **Trigger:** enable this job and supply its valid canonical documents to the registered review-data-indexing consumer.
- **Expected:** actual `Boundary.inside`, `Element.component_ids`, `EntryPoint.process`, `Threat.boundary_ids`, and citation `locator`/`entity_id` must bind indexed boundary members, entry points, candidate threats and source relationships.
- **Actual:** consumer searches alternative fields (`elements`/`node_ids`/`members`, singular `component_id`, `element_id`/`node_id`, `boundaries`/singular `boundary_id`, and `evidence.path`). It never reads the corresponding current producer fields. Every generated threat falls through to `unassigned_threat`; entries land in invented `boundary:entry_surface`; source/component attribution is empty. The consumer reports partial/gaps, but still loses the useful indexed content.
- **Cheap reproduction R4:** build schema-valid documents with the real assembly/template/document functions: one network boundary, one entry, six candidate threats. Feed them to `_build_threat_boundaries` with a real empty `ShardSet`. Result: two indexed rows, zero threats, zero member/component/source-path lists; one entry on the synthetic boundary, zero on the actual boundary; six `unassigned_threat` gaps.
- **Impact:** canonical artifact views remain useful, and the independent behavior loader is a different route, but the advertised indexed threat-boundary retrieval cannot return the generated threat questions or correct ownership.
- **Correction:** consume the published contract fields directly, retaining multi-boundary membership and resolving citation entity/location identity; test with `build_documents` outputs, not a hand-authored alternate shape.
- **Test masking:** `tests/unit/test_t172_indexing_and_retrieval.py:235-261` labels an incompatible `trust_boundaries`/`nodes`/`target_id` fixture as the current schema and never validates it against the producer schemas.
- **Confidence:** reproduced, high. **TODO overlap:** T-172 is marked done for this exact consumer capability; T-107/T-146 are related context. Not a request for a new index/consumer.

### TM-02 — Medium: inexact analyzer-only graph records are promoted to verified semantic interactions

- **Evidence:** `src/appsec_review/threat_model/lanes/interactions.py:113-130` assigns `Basis.VERIFIED_SEMANTIC` solely because the row was retrieved as a graph entry/sink. It ignores exactness, coverage, cross-check disagreement/partial state, admissibility and originating producer.
- **Reachable producer evidence:** `src/appsec_review/graph/analyzers.py:177-220` intentionally creates analyzer-only sinks with `exact=False`, partial coverage/cross-check and `direct_eligible=False`; `jobs/job_code_graph_index/scopes.py:765-776` publishes every fact of the family, not only eligible ones. Eligibility semantics are explicit in `graph/contract.py:263-296`.
- **Expected:** preserve this limitation and do not label an inexact diagnostic point as a verified semantic interaction; reject/demote with a named gap or retain an explicitly weaker evidence basis.
- **Actual / R2:** real `apply_analyzer_sinks` builds a `cert-env33-c` diagnostic-only sink; `GraphFact.to_entity()` validates it. The interaction lane returns `process_spawn`, basis `verified_semantic`, rule `graph.sink_site.command_execution`, with no fact-specific qualification gap.
- **Impact:** overstated basis wins strongest-first merges/bounds and propagates into flows/template evidence. This does **not** make generated output direct finding evidence; the error is the strength and meaning of the routing model's evidence label.
- **Correction:** apply producer/eligibility checks before selecting semantic basis and preserve partial/inexact reasons. Add an analyzer-only and a disagreeing graph-fact regression.
- **Confidence:** reproduced, high. **TODO overlap:** T-107 covers broader enrichment/acceptance, not this label conversion. Prior code-graph audit describes these records as deliberately ineligible; that producer behavior is not re-counted as a producer defect.

### TM-03 — Medium: interaction catalog language restrictions are ignored

- **Evidence:** `src/appsec_review/threat_model/reference.py:93,119-120,264-265` loads/exposes per-callee languages; `threat_model/lanes/interactions.py:133-142,222-230` never checks them; `threat_model/index_view.py:99-105,286-312` filters only call category and exact written name. Tree-sitter supplies the language at `jobs/job_tree_sitter_ast/normalize.py:206-217`.
- **Trigger:** a supported non-C language has a call whose written name matches a catalog entry, e.g. JavaScript `bind`; the catalog's `bind` entry is C/C++ only (`data/reference/threat-model/interaction-catalog.json:249-255`).
- **Expected:** the language-bounded catalog rule should not apply to that record.
- **Actual / R1:** change a synthetic call's language to `javascript`, retain written name `bind`, and run the real reference-backed lane: one `network_listen`/`observed_syntax` fact is emitted despite allowed languages `["c","cpp"]`.
- **Impact:** unrelated non-C calls manufacture network/process/file interactions and derived boundaries/threat questions; changing the configured reference-language list does not change selection.
- **Correction:** filter by the published language and the selected callee's allowed language list, preferably before query bounds are consumed; account for missing language rather than guessing.
- **Confidence:** reproduced, high. **TODO overlap:** no exact matching entry found; T-107 is the owning feature umbrella. This is narrower than the deliberately approximate unresolved-name matching within supported languages.

### TM-04 — Medium: same-line interaction deduplication loses distinct sites and build ownership

- **Evidence:** `src/appsec_review/threat_model/lanes/interactions.py:83-95,165-173,245-247`. Group key contains only interaction/path/start-line; byte range, file digest, enclosing function and build scope are excluded. One strongest/rank-selected candidate supplies **all** attributes. Downstream owner choice and flow site count use that merged fact (`threat_model/assemble.py:140-148,193-222,239-250`).
- **Trigger:** two `recv` sites on one source line, in different functions and/or accepted build scopes.
- **Expected:** preserve distinct physical sites/owners; only merge multiple producer observations of the same supported site.
- **Actual / R3:** source spans `shared.h:1 #b0-9` and `#b30-39`, symbols `readA`/`readB`, units `unit-a`/`unit-b`: two records read, one interaction fact, only `readA` retained, one entry/flow with `site_count=1`. Both locators remain in that single fact, but the second process loses its entry/flow and its evidence is attributed to the winner.
- **Impact:** incorrect entry counts and per-process routing; missing site/ownership is not identified by a merge/truncation gap. Canonical sorting makes the wrong result repeatable, not correct.
- **Correction:** use a physical-site identity with source digest/span and appropriate scope; make any cross-producer normalization explicit and retain all supported ownership when truly identical observations merge.
- **Confidence:** reproduced, high. **TODO overlap:** no precise matching entry found; T-107 owns the feature. This is not the intentionally coarse “one flow per process/peer/interaction” rule; separate entry sites are lost before that assembly.

### TM-05 — Low: mapped contract tests still assert that the delivered indexed consumer does not exist

- **Evidence:** `tests/test_threat_model_generation_job.py:62` and `tests/unit/job_threat_model_generation/test_contract.py:81`; actual new inputs are `src/appsec_review/jobs/job_review_data_indexing/datasets.py:374-385`.
- **Expected:** tests recognize accepted consumption, distinguish it from scheduling, and preserve routing-only assertions.
- **Actual:** both fail on `JOB_ID not in jobs["job_review_data_indexing"]["upstream_handoffs"]`. The first message is `scheduling only: no consumer yet`. These are source/test drift, not a reason to remove the consumer.
- **Impact:** the mapped unit selection is red and those tests' later assertions are not reached. Source module docstring `jobs/job_threat_model_generation/job.py:3-5` also says no consumer; the current subsystem architecture correctly says otherwise.
- **Correction:** update the assertions and stale current-code prose to the delivered T-172 contract, with a real producer-shaped consumer regression from TM-01.
- **Confidence:** observed test failures, high. **TODO overlap:** T-172 delivered consumer; T-147 concerns broader authoritative task/publication bindings, not permission to treat missing bindings as no execution.

## Validation record

All commands below ran through the brief's base64-preserving SSH transport, in `/home/wsollers/projects/appsec-review`, using its `.venv`. No dependency installation or environment repair was required. Wrapper runs were sequential, each with **two** workers and an independently generated private scratch directory. The normal wrapper's sequential collection/execution reuse of its own directory was retained.

### Explicit collection (no tests executed)

```bash
.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-threat-model-collect-a-20261118-341 \
  --override-ini addopts='' \
  tests/unit/job_threat_model_generation/test_contract.py \
  tests/unit/job_threat_model_generation/test_handlers.py \
  tests/test_threat_model_generation_job.py tests/test_threat_model_index_view.py \
  tests/test_threat_model_lane_structure.py tests/test_threat_model_lane_interactions.py \
  tests/test_threat_model_assembly.py tests/test_threat_model_threats.py \
  tests/test_threat_model_validation.py tests/test_threat_model_documents.py \
  tests/test_threat_model_render.py

.venv/bin/python -m pytest --collect-only -q -p no:cacheprovider \
  --basetemp=test/tmp/job-audit-threat-model-collect-b-20261118-342 \
  --override-ini addopts='' \
  tests/test_threat_model_contract.py tests/test_threat_model_codec.py \
  tests/test_threat_model_schemas.py tests/test_threat_model_reference.py
```

Observed: **125 collected in 3.29 s**; **173 collected in 0.68 s**. The transmitted collection commands piped output through `tail -n 5`; those summaries contained an unknown-config-option warning but not the option name. This warning's detail was not retained. Wrapper collection subsequently completed with exact count proofs and execution did not report a warning in its saved logs.

### Execution A

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 34047 \
  --expect-tests 125 --strict -- \
  tests/unit/job_threat_model_generation/test_contract.py \
  tests/unit/job_threat_model_generation/test_handlers.py \
  tests/test_threat_model_generation_job.py tests/test_threat_model_index_view.py \
  tests/test_threat_model_lane_structure.py tests/test_threat_model_lane_interactions.py \
  tests/test_threat_model_assembly.py tests/test_threat_model_threats.py \
  tests/test_threat_model_validation.py tests/test_threat_model_documents.py \
  tests/test_threat_model_render.py
```

- Exit **1**: **123 passed, 2 failed**, 125 total. Pytest elapsed **11.32 s**, wrapper total **20.8338 s**, wrapper collection **4.9364 s**.
- Failed nodes, verbatim:
  - `tests/test_threat_model_generation_job.py::test_job_is_registered_configured_and_in_the_graph_after_owasp_and_before_indexing`
  - `tests/unit/job_threat_model_generation/test_contract.py::test_job_registry_topology_and_contract_invariants`
- Both fail on the missing-consumer assertion documented in TM-05. First failure E lines: `AssertionError: scheduling only: no consumer yet`; `assert 'job_threat_model_generation' not in [...]`. Second E line: `AssertionError: assert 'job_threat_model_generation' not in [...]`.
- No skips/errors/slow cases. Slowest own setup+call+teardown: `tests/unit/job_threat_model_generation/test_handlers.py::test_publish_and_upstream_integrity_guards_fail_closed`, **1.2300 s**.
- Artifact stem: `test/tmp/tests-custom-20261118-132001-046752-3299191`.
  - Log: `test/tmp/logs/tests-custom-20261118-132001-046752-3299191.log`
  - JUnit: `<stem>.junit.xml`; timings: `<stem>.timings.sqlite`; collection proof: `<stem>.collection.json`
  - Fixed JSON report: `test/tmp/reports/tests-custom-20261118-132001-046752-3299191.json`

### Execution B

```bash
bash scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 34048 \
  --expect-tests 173 --strict -- \
  tests/test_threat_model_contract.py tests/test_threat_model_codec.py \
  tests/test_threat_model_schemas.py tests/test_threat_model_reference.py
```

- Exit **0**: **173 passed**. Pytest elapsed **4.53 s**, wrapper total **10.8615 s**, wrapper collection **1.8709 s**.
- No failures/skips/errors/slow cases. Slowest own phases: `tests/test_threat_model_schemas.py::test_an_element_flow_boundary_or_threat_with_empty_evidence_fails[element]`, **0.1893 s**.
- Artifact stem: `test/tmp/tests-custom-20261118-132022-105459-3300314`.
  - Log: `test/tmp/logs/tests-custom-20261118-132022-105459-3300314.log`
  - JUnit: `<stem>.junit.xml`; timings: `<stem>.timings.sqlite`; collection proof: `<stem>.collection.json`
  - Fixed JSON report: `test/tmp/reports/tests-custom-20261118-132022-105459-3300314.json`

Both wrapper reports recorded confirmed owned-process cleanup. Their internal pytest command pins `-c pyproject.toml`, `--rootdir`, `-o addopts=`, `-p ops_test_guard`, `-n 2`, exact selectors, the unique base temp and JUnit file. Total executed-unit pytest elapsed = **15.85 s**, combined wrapper elapsed = **31.6953 s**; explicit preliminary collection is additional.

### Pure-function reproductions

The successful command below executed **four assertions/reproductions in 0.1291 s after imports**, exit 0. It creates no files, opens no target, and calls no analyzer/provider: `apply_analyzer_sinks` only transforms an in-memory diagnostic row.

An initial version ran R1/R2/R3 successfully but failed R4 because its handwritten empty-shard fake lacked `coverage()`. That **audit harness error** was corrected by using the real empty `ShardSet`; it is not a product defect or a passed first attempt. The failed attempt did not reach its elapsed-time print, so that timing was not captured.

```bash
.venv/bin/python - <<'PY'
from dataclasses import replace
from pathlib import Path
from time import perf_counter
import json
from appsec_review.threat_model.assemble import assemble
from appsec_review.threat_model.contract import Basis, LaneResult, Limits, Origin, SourceSpan
from appsec_review.threat_model.documents import build_documents, plain
from appsec_review.threat_model.lanes.interactions import interactions
from appsec_review.threat_model.threats import enumerate_threats
from appsec_review.threat_model.validate import validate_documents
from appsec_review.graph.analyzers import apply_analyzer_sinks
from appsec_review.indexing.products import ProductContext, _build_threat_boundaries
from appsec_review.indexing.store import ShardSet
from tests.test_threat_model_assembly import process, reference
from tests.test_threat_model_lane_interactions import call_site
from tests.threat_model_support import FakeEvidenceView, record
start=perf_counter(); ref=reference(); limits=Limits()
js=call_site('js-bind','bind','app.js')
js=replace(js,payload={**js.payload,'language':'javascript'})
lane=interactions(FakeEvidenceView().add_call('bind',js),ref,limits)
assert len(lane.facts)==1
print('R1',json.dumps({'catalog_languages':ref.languages_for_callee('bind'),'input_language':'javascript','facts':[(x.attributes['interaction'],x.basis.value) for x in lane.facts]}))
row={'identity':'diag1','payload':{'scanner':'clang-tidy','native_rule_id':'cert-env33-c'},'location':{'path':'main.c','file_sha256':'b'*64,'start_byte':0,'start_line':1,'start_column':1}}
fact=apply_analyzer_sinks([], [row], [], target_snapshot='snapshot-1',scope={'scope_id':'scope1','language':'cpp','build_unit_id':'unit-a','component_id':None}).facts[0]
ent=fact.to_entity()
rec=record('job_code_graph_index','code_graph_facts','sink_site',ent.identity.value,ent.payload,at=SourceSpan('main.c','b'*64,1,1,0,0))
lane=interactions(FakeEvidenceView().add(rec),ref,limits)
assert lane.facts[0].basis is Basis.VERIFIED_SEMANTIC
print('R2',json.dumps({'input_exact':ent.payload['exact'],'input_admissibility':ent.payload['admissibility'],'output_basis':lane.facts[0].basis.value,'output_rule':lane.facts[0].evidence[0].rule,'specific_gap':[g['reason'] for g in lane.gaps if g['code']!='input_unavailable']}))
a=replace(call_site('site-a','recv','shared.h',1,enclosing='readA',build_unit_id='unit-a'),span=SourceSpan('shared.h','b'*64,1,1,0,9))
b=replace(call_site('site-b','recv','shared.h',1,enclosing='readB',build_unit_id='unit-b'),span=SourceSpan('shared.h','b'*64,1,1,30,39))
lane=interactions(FakeEvidenceView().add_call('recv',a,b),ref,limits)
assembly=assemble([LaneResult((process('a',unit='unit-a'),process('b',unit='unit-b'))),lane],ref,limits)
assert len(lane.facts)==len(assembly.entry_points)==1
print('R3',json.dumps({'sites_read':lane.ledger[1].records_read,'facts':len(lane.facts),'retained_symbols':[x.attributes['enclosing_symbol'] for x in lane.facts],'entries':len(assembly.entry_points),'flows':len(assembly.flows),'site_count':[x.attributes['site_count'] for x in assembly.flows],'located_refs':[x.locator for x in lane.facts[0].evidence]}))
p=process('service',unit='unit-a',paths=('main.c',))
p=replace(p,attributes={**p.attributes,'component_ids':('component-a',)})
recv=call_site('real-recv','recv','main.c',2,build_unit_id='unit-a')
lane=interactions(FakeEvidenceView().add_call('recv',recv),ref,limits)
assembly=assemble([LaneResult((p,)),lane],ref,limits)
threats,gaps=enumerate_threats(assembly,ref,limits)
docs=build_documents(Origin('audit','attempt','snapshot-1',ref.sha256s),assembly,threats,(),gaps)
dfd,model,evidence,result=(plain(getattr(docs,k)) for k in ('dfd','threat_model','evidence','result'))
validate_documents(dfd,model,evidence,result)
ctx=ProductContext(Path('.'),'snapshot-1',ShardSet(Path('.'),()),{},{},{},100,rule_version='audit',threat_model={'status':'accepted','dfd':dfd,'threat_model':model,'gaps':[]})
derived=_build_threat_boundaries(ctx,())
assert len(threats)==6 and sum(r.payload['result']['threat_count'] for r in derived.entities)==0
print('R4',json.dumps({'producer_boundaries':len(dfd['boundaries']),'producer_threats':len(model['threats']),'producer_entries':len(model['entry_points']),'retrieval_rows':[{k:r.payload['result'][k] for k in ('boundary_id','element_ids','component_ids','source_paths','entry_point_count','threat_count')} for r in derived.entities],'unassigned_threats':len([g for g in derived.gaps if g.startswith('unassigned_threat')])}))
print('REPRO_ELAPSED_SECONDS',round(perf_counter()-start,4))
PY
```

## Read scope and remaining gaps

**Read fully:**

- Shared brief; authorized `AGENTS.md`; authorized `.claude/skills/multi-session-coordination/SKILL.md`.
- `docs/operations/job_threat_model_generation.md` and historical `docs/architecture/dfd-and-threat-model-generation.md`.
- All three Python files in `src/appsec_review/jobs/job_threat_model_generation/`.
- `src/appsec_review/threat_model/{contract,view,index_view,reference,codec,assemble,threats,validate,documents,render,schemas}.py` and both `lanes/{structure,interactions}.py`.
- `src/appsec_review/review/behavior.py`; `release-dependencies.json`; interaction catalog JSON.
- All 15 unit files listed in commands A/B, `tests/threat_model_support.py`, `tests/handoff_fixture.py`, `tests/conftest.py`, `tests/test_000_unit_environment_guard.py`, `scripts/run-tests.sh`, `scripts/lib/common.sh`.

**Read in targeted ranges or structured projections:**

- Central TOML job block; config parser/reservation; registry entries; topology edge construction; dataset declarations from consuming jobs; shared runtime contracts and accepted-handoff/shard helpers.
- Upstream producer emission excerpts listed above; graph analyzer conversion and eligibility rules; indexing `ProductContext`, `_build_threat_boundaries`, `Derived`/`fact`; index consumer artifact loader.
- Four raw JSON schemas: required top-level fields, key Origin/EvidenceRef/ledger/artifact definitions, with all schema shapes/vocabularies additionally exercised by the 173-case unit group. Not every raw schema line was independently read.
- Every threat-template applicability/question and every crosswalk mapping/unmapped list via compact JSON projections. Template obligation/mitigation prose was sampled; tests exercised nonempty shapes and pinned-catalog coverage. OWASP pinned catalog source files were consumed by tests, not independently reviewed in full.
- `tests/unit/test_t172_indexing_and_retrieval.py:205-325` (not run), `tests/job-test-map.json` job entry, relevant current subsystem architecture and TODO entries T-107/108/147/172/173. Prior session/cumulative reports searched for symptom overlap; code-graph report's eligibility notes sampled. No matching prior threat-model defect report found.
- Wrapper implementation `ops_tests.py:90-180,330-572` and `ops_test_guard.py:1-200`; local branch list and recent pertinent history. No fetch or branch movement.

**Material unread/unexecuted scope:**

- No integration/acceptance/live tests, JobRunner full admission/reuse/restart cycle, Dagster dispatch, actual providers/tools, real threat-model run artifacts, target checkout/source contents, or deployed DFD/mitigation usefulness.
- Not an independent re-audit of upstream producers, whole shared runtime/storage/signing/resource-admission machinery, retrieval/MCP implementation, every consumer/hunting workflow, or every schema/template sentence. Downstream scope was limited to compatibility expectations and the reproduced product error.
- No standalone rerun of the two stale assertions, full suite, coverage-percentage measurement, benchmark near maximum bounds, mutation testing, or exhaustive permutations. No claim that passing pure/unit checks establishes review-output correctness.
- No repository files were edited. Only this session report and normal authorized test scratch/report artifacts were created. Existing unrelated root files were left untouched.

Audit stops after this job. Coordinator owns cumulative attribution and any later repair/acceptance decision.
