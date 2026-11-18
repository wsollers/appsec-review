# Job 36/47 — job_review_package_assembly

## Scope and verdict

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review` through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu`. Reads used the corresponding Ubuntu-22.04 UNC checkout, **not** the Windows working checkout.
- HEAD, clean status, branch, and editable import were checked; final checks returned the same SHA, `main`, no status entries, and `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- **Three local findings: two medium, one low.** Prior **CGI-F12** and **RP-01** are confirmations/boundary clarifications, not new findings.
- **8 focused tests passed in 6.40 s**, no failures/skips or tests over 10 s. Separate offline probes reproduced the findings, exercised the document-record bound, and obtained actual typed dataset read receipts.
- No source/configuration/environment changes, installs, services, external tools/models/providers, target execution, integration/acceptance/live/Dagster runs, commits, or nested agents. Only private fixture/probe state under `test/tmp/` and this report were written.
- Passing these tests does **not** certify correctness or live review quality.

## Registration and intended contract

`src/appsec_review/runtime/registry.py:104,175` registers the factory. It is enabled in the dev recipe; no job-level `enabled` setting disables it. Configuration is `appsec-review.toml:1210-1219`.

The job has **one step, one task, no model/prompt/skill dispatch**:
`publication.publish_packages`. The guidance registry has no binding for this job; the missing declarative deterministic-task binding is existing **T-147**, not a claim that a hidden model runs.

`jobs/job_review_package_assembly/job.py:106-110` declares `strict_gaps=True`, `review_package_assembly`, and result identity `appsec-review/review-package-assembly/1`. Its contract has **140 handoff-channel input requirements across 26 producers**: one required/reject envelope (`job_review_data_indexing/handoff`), two conditional native-advisory declarations, and 137 optional/gap declarations. Dispatch is `REVIEW_GRAPH`, target access `CHECKOUT`, `always_execute=False`, `propagate_handoff=True`.

The contract-derived reduced graph has **review-data indexing → package assembly → document-issue analysis**. Direct declared consumers are document-issue analysis and inference security review; inference's dependency is transitively reduced through document analysis. Availability/scheduling is not actual payload consumption.

The only dataset is artifact-only `review_packages`, schema `appsec-review/review-package-manifest/2`, glob **`data/review-packages/*/*.json`** (`datasets.py:5-12`). This includes the manifest and individual `/3` package bodies. Nothing is indexed as general retrieval text.

### Important boundary: these are not inference `/7` packages

This job calls **`src/appsec_review/review_packages.py`**, whose constants are package `/3`, assembly `/3`, manifest `/2` (`:23-25`). It emits catalog-derived scanner `finding_lead`, scanner-menu `hunt`, and `document_hunt` packages.

It does **not** call `review/units.py`, `review/packages.py`, `rank_hunt_candidates`, any slice strategy, unit-context publication, or model-facing package-view construction. There are no ranked operation/file-batch units, source slices, lead-site clustering, KEV admission, first-party/stylistic exclusions, or hunt cutoffs in this producer. Those are the separate inference job's assembly, with its own settings and manifest. This is an implemented separation stated by the canonical operations page, not itself a defect.

## Every declared step/task and internal stage

| Declared task / internal stage | Actual implementation and inputs | Validation/output/limits |
|---|---|---|
| `publication.publish_packages` — configuration | `job.py:25-32`; exact step/task parity, integer `max_page_size` in 1–100 | A single `Unit`, with `_validate_output`; no conditional hidden tasks |
| Same task — accepted scope | `_core:35-46`, handler `:66-80`; attempt-pinned manifest, `RetrievalCore`, indexing envelope; manifest target must match job snapshot; manifest or its lineage must intersect indexing's bound artifacts | Run containment, exact manifest hash, shared-handoff integrity. Core cached only within run validation scope |
| Same task — scanner/document membership | `review_packages.py:234-286`; scanner-correlation lead/menu/audit facts and document route/boundary facts from accepted precomputed shards | Duplicate leads, missing/duplicate audit, invented/cross-component menu members, incomplete/duplicate menu coverage rejected; ≤2,000 document subjects |
| Same task — context materialization | `:289-441`; source-file locations, priority function spans, history metric vectors, safe build-action facts, tag assignments, Clang function declarations; all shard coverage tables | Exact path/hash/span matching for function attribution; smallest unique containing span, otherwise explicit ambiguity/unavailability. Context caps fail closed. **RPA-02**, **RPA-03** |
| Same task — scanner packages | `:443-473`; one finding package for **every** accepted source-SAST lead, one hunt per high/critical or unknown scanner-menu partition | Keeps suppression/duplicate state and observation IDs; deterministic identity ordering; no severity-based exclusion from finding packages |
| Same task — document packages | `:474-499`; accepted route/boundary context fact, accepted member map, required anchor | Exactly one anchor plus ≤63 other source records; missing anchor/member rejected; omissions and unknown implementation mapping become gaps. Probe confirms 66→64 records, anchor retained, two omitted |
| Same task — membership/schema and manifest | `:166-231,500-511`; closed `/3` package definitions; exact finding and document sets; menu sets and audit counts | Manifest counts, logical package hashes, union of package gaps; **RPA-01** loses run gaps when there are no packages |
| Same task — immutable publication | `:514-535`; authenticated admission projection, canonical JSON + LF, content-addressed directory, named immutable package/manifest publication | Page bound enters admission-projection identity. Package body enters package ID; manifest content enters directory identity |
| Same task — verification and receipt | `:538-612`; exact directory contents, canonical bytes, hashes, projection authentication, package schemas, membership, counts, accepted lead equality; `job.py:49-62,81-103` | Receipt revalidated before success; all JSON file refs emitted; structured producer gaps retain original producer/scope/reason/gap ID; status is `COMPLETED_WITH_GAPS` iff manifest gaps exist |

`UnitExecutor.execute` runs this one handler and its output validator, writes task receipts, and converts exceptions to a failed task (`runtime/units.py:83-210`). There is no unreachable declared unit.

## Accepted manifests versus actual payload reads

The full declarations were read. Most declared raw artifacts are **not parsed** by this job. Actual behavior:

| Read boundary | Actual content consumed |
|---|---|
| Indexing envelope and manifest | `resolve_context_manifest`; explicit immutable attempt manifest, otherwise operator-style accepted pointer fallback. `indexing.store.accepted_handoff` delegates to `accepted_upstream` and verifies/consumes the handoff. Within runtime, claim pins and typed declarations apply |
| Every manifest shard | `_coverage_gaps` reads shard gap metadata **and every shard's coverage table**, regardless of whether package context uses its payload. Thus metadata-only coverage reads can exercise an otherwise unused dataset's permission |
| `precomputed` payloads | Only producer query sets `scanner_correlation`, `document_context`, `history_context`, `build_provenance`; required fact types selected within each |
| `source` payloads | `source_file` identities and indexed locations; builds path→source-ID map. Does not read raw target source text |
| `priority` payloads | `priority_item` records and function spans for context binding. **Does not transform or rank the score** |
| `tags` payloads | `tag_assignment` joined by lead identity or same-hash source-file subject |
| `analysis` payloads | `ast_node` of `FunctionDecl`/`CXXMethodDecl`, joined to resolved function spans |
| `documents` payloads | `document_record` identities/locations for document grants |
| Artifacts/build/history/observations/etc. | Their coverage tables may be read, but original scanner results, protected argv/env, build receipts, compiled files, raw history, graph facts, reference feed payloads, and source text are not directly parsed here. Safe command/environment facts already projected into `build_provenance` are parsed |

`AcceptedShards` delegates to `ShardSet`; both entity and coverage iteration open shards through `open_shard`, which calls `runtime.inputs.observe_shard` (`indexing/store.py:85-99,160-216`). That enforces producer pin, actual dataset ownership, schema/authority, artifact binding/hash and records reads (`runtime/inputs.py:474-499`). This is **not** the envelope-only payload-reader defect seen in several earlier jobs.

A dedicated offline probe used the real assembly handler inside `input_read_scope` with all synthetic producer pins and real registry-derived producer declarations. It completed with gaps and recorded **18 reads, 14 distinct producer/dataset pairs**:

- CI `ci_observations`; CodeQL `codeql_observations`; evidence collection `static_tool_observations`;
- indexing `handoff`, `dataset_inventory`, `precomputed_products`;
- prioritization `priority_items`; tagging `tag_assignments`; history `history_signals`;
- catalog `build_units`, `components`, `declaration_symbols`, `source_files`, `target_documents`.

Many are coverage-only reads, not evidence used in a package. Receipt `cited` remains `null`, correctly distinguishing consumption from citation. The other synthetic probes intentionally use a compact accepted-storage fixture without full production input admission; only this dedicated probe establishes actual typed-read enforcement.

## Bounds, selection and identities

- Configured `max_page_size=20`; inherited scanner menus must already fit it (`_membership:273-275`). Shipped indexing `menu_partition_size=20` agrees (`appsec-review.toml:1150`). A smaller individually valid consumer page bound can reject larger upstream menus rather than repartitioning them. The existing parity test checks the shipped configuration, not every runtime override.
- Fixed bounds: 2,000 document subjects; anchor +63 records; 200 metrics, 100 commands, 100 environment names, 200 tags, 100 compiled references. Retrieval grants have five pages, depth two and 131,072 response bytes. Only page size is a setting of **this** job.
- Overlarge scanner context fails with “partition the source scope”; this job does not implement adaptive byte trimming or source-scope repartitioning. The response-byte limit is **not** a package-body byte limit. This is a named sizing/large-corpus validation gap; do not claim the separate inference `max_package_bytes` applies here.
- Finding membership includes all source-SAST severities. Scanner hunts include only high/critical or unknown memberships. Duplicate/suppressed records remain. There is no all-family review-lead normalization here.
- Scanner partition keys are `menu:component:NNNNN`; continuation is inherited from accepted menus. Document keys are `subject_type:key`; unmapped implementation component remains a material gap, not a guessed boundary.
- Stable IDs derive from canonical bodies; `input_fingerprint` includes manifest, sorted shard identities, partition, entity IDs and assembly rule. No timestamps enter those identities. Logical package SHA excludes publication LF; artifact references separately record physical file SHA/size.
- `_validate_output` repeats manifest/receipt integrity checks. Invalid membership/hash/schema blocks output; normal coverage limitations are standardized `producer-gap/1`, code `producer_reported_gap`.

## Findings

### RPA-01 — Medium — An empty package set erases accepted coverage gaps and publishes success

- **Evidence:** `src/appsec_review/review_packages.py:67-77,295,500-511,581-582`; `src/appsec_review/jobs/job_review_package_assembly/job.py:81-82,95-103`.
- **Trigger:** a valid scanner-correlation audit contains zero leads/menus, no document subjects exist, and any accepted shard has incomplete coverage. This is possible when there is an observation shard but no source-SAST rows: `indexing/sast.py:95-108,236-246` still emits the zero-count audit, retaining missing/partial scanner or suppression coverage.
- **Expected:** empty findings must preserve known missing/failed work and cause `COMPLETED_WITH_GAPS`.
- **Actual:** assembly computes the input gaps, but the manifest is built only from the union of individual package gaps. With no packages the union is empty. Verification recomputes the same empty union, so the loss passes validation and the handler reports `SUCCEEDED`.
- **Reproduction:** real tiny SQLite/handoff fixture with zeroed scanner audit and one partial scanner-correlation coverage row. `_coverage_gaps` returned **one** gap (“scanner failed; no completed source scan”); real handler + output validator + `verify_review_packages` published **0 packages, 0 gaps, `SUCCEEDED`**.
- **Impact:** this job's accepted completion/accounting can falsely present an incomplete empty review input as gap-free. Downstream inference has independent scope coverage, so this is not proof that the final report also becomes clean.
- **Confidence:** high, reproduced.
- **Smallest correction:** retain the run-level input gap set independently of package membership and include it in the manifest even when no packages exist; verification must compare against that independent set.
- **TODO/duplicates:** no exact entry found in the inspected TODO/prior reports. Existing T-095 is intake duplication, not this omission.

### RPA-02 — Medium — Selected partial build facts lose their omitted-work qualifications

- **Evidence:** `review_packages.py:67-77,332-339,360-441`; concrete producer layout `indexing/build_facts.py:252-293`; `indexing/products_base.py:124-141`.
- **Trigger:** accepted `build_provenance/build_action` has row `coverage_status="partial"` and `result.gaps`, while its shard-level coverage is complete. This is a real producer shape when the per-action command limit is reached.
- **Expected:** retain the selected fact's limitations when copying its safe commands/environment into a package, and reflect omitted work in package/manifest gaps.
- **Actual:** `context_for` copies selected result fields but ignores the fact's `coverage_status`, top-level gaps and nested `result.gaps`. `_coverage_gaps` only sees shard metadata/tables. If some command matches the file, the “no command” fallback does not fire. Packages have `omitted_context=0` and no truncation gap.
- **Reproduction:** real `build_command_facts` over three supplied exec records with `max_commands=1` emitted product/shard **complete**, row **partial**, reason **“2 exec command(s) omitted by the per-action bound”**. Separately, an actual accepted fixture carrying that partial shape passed the real package handler and verifier with **two packages, zero gaps, `SUCCEEDED`**.
- **Impact:** published command context appears unqualified despite known omitted commands; coverage accounting loses accepted producer information. Current inference does not consume these scanner package bodies, so no direct model conclusion is claimed.
- **Confidence:** high, real producer reducer plus real package publication reproduced.
- **Smallest correction:** propagate selected fact-level status/reasons into scoped package gaps, including nested build result gaps; independently fix upstream aggregate coverage if needed. Preserve omission counts when supplied.
- **TODO/duplicates:** no exact entry found. **Coordinate with the review-data-indexing auditor** if it reports the same command-fact aggregate gap: the package consumer omission and producer aggregate weakness belong to one propagation chain, not two independent upstream discoveries. T-5062 is a different inference package-byte bound.

### RPA-03 — Low — Scoped artifact IDs are omitted from scanner-package retrieval grants

- **Evidence:** `review_packages.py:135-149,375-379`; capability enforcement `mcp/capability.py:206-213`.
- **Trigger:** matched accepted build provenance names a produced artifact.
- **Expected:** a package's explicit `scope.artifact_ids` should be addressable through its bounded grant, just as the included source and action IDs are.
- **Actual:** `_package` includes source IDs, context IDs, action IDs, metrics/tags/compiled IDs and flows in `retrieval.entity_ids`, but omits `build_context["artifact_ids"]`. The artifact remains displayed in scope yet `find` is rejected before retrieval.
- **Reproduction:** an actual `build_artifact` row in an accepted synthetic artifact shard resolves through unscoped `RetrievalCore.find`. The real published scanner package contains its ID in `scope.artifact_ids`, not in its grant; `ScopedRetrievalMcpAdapter.find` raises **“entity is outside review package”**.
- **Impact/severity limit:** a real package capability seam is broken. The current production consumer only analyzes document hunts, and inference independently reassembles its own packages; therefore this is a **low-severity latent scanner-package consumption defect**, not an observed failure of current inference.
- **Confidence:** high, reproduced after correcting an initial probe's invalid artifact-kind fixture.
- **Smallest correction:** include accepted scoped artifact identities in the grant and add a package-to-scoped-retrieval regression.
- **TODO/duplicates:** no exact entry found.

## Prior findings confirmed; do not count again

| Prior finding | Confirmation and boundary |
|---|---|
| **CGI-F12 — High** | Assembly declarations at `jobs/job_review_package_assembly/datasets.py:77-86` omit `alternate_cpg_index`. This job's `_coverage_gaps` opens **all** manifest shards, and its analysis-context scan also opens all `analysis` shards (`review_packages.py:72,328`). Thus the already-reported missing declaration can fail assembly during a coverage/context read, before any inference query. Actual enforcement is `runtime/inputs.py:474-499`; prior graph report's real query reproduction was read, not rerun. Same producer/consumer admission group; not a new issue. |
| **RP-01 — High** | `review/units.py:188-196,429-437` still infers percentage scale above one. Confirmed source and prior 356→11 repro reviewed. **This job does not call that converter or rank units**; it only uses priority function spans. The defect belongs to subsequent inference package ranking, not this `/3` assembly. No duplicate finding or test rerun. |

## Downstream consumption

- Document issue analysis is the actual `/2` manifest consumer: `jobs/job_document_issue_analysis/job.py:83-123` verifies the assembly handoff/result, exact accepted manifest and manifest artifact binding, then invokes `analyze_document_hunts`.
- `document_issues.py:131-148` verifies **the entire package manifest** but processes only `kind=="document_hunt"`. Its selected package body contributes the route/boundary key, document evidence, obligations and gaps (`:150-184`). Scanner package bodies are verified, not reviewed by that path.
- Inference declares assembly's required handoff plus optional package dataset (`jobs/job_inference_security_review/datasets.py:337-341`), but no package-body reader was found in its implementation. Its `scope.accept_manifest` reopens the accepted retrieval scope (`job.py:143-151,280-304`), and `packages.assemble_*` independently calls `review.packages.assemble_packages` (`:397-425`).
- Operation units, prioritization scores, exclusions, slicing, unit-context documents and model-facing views therefore belong to that next job. Its seam was inspected to establish consumption, **not re-audited or executed**.

## Documentation and test-map drift, not additional runtime finding counts

1. `docs/operations/job_review_package_assembly.md:966-968` still says handler gaps are legacy string IDs; the current handler uses structured reason-preserving producer gaps and `strict_gaps=True`.
2. `tests/job-test-map.json` lists `tests/review/test_packages.py`, but that file exercises **`review/packages.py`**, the separate inference assembler. Dedicated job tests exercise this job; tests elsewhere using `review_packages.py` include integration-tier suites and mixed GraphRunner tests. They were inspected as navigation, **not executed without authorization**.
3. T-113's historical “109-input” count is stale; the current actual contract has **140** declarations. T-5064 already records the lineage fixture's slow-test risk; here it took **2.055 s**, below both its proposed five-second goal and ten-second unit budget. This does not close its cross-host issue.
4. T-165/T-167 apply to inference review lanes. Their exclusions not occurring in catalog scanner packages is not incorrectly reported as a new exclusion bug.
5. The architecture opening text says “schema version 6” alongside `/7`; the distinction between catalog `/3` and inference `/7` remains clear from code and the dedicated operations page.

## Focused validation

### Transport and preflight

All Linux commands used this transport; no WSL service operations or `wsl -e` calls:

```powershell
$script = @'
set -eu
cd /home/wsollers/projects/appsec-review
# Linux command body
'@
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

`offending_environment(os.environ)` returned `[]`; interpreter import resolved into the authorized checkout. No dependencies were installed or environment repaired.

Inspected test boundaries: tiny synthetic source/index/handoff fixtures; full accepted-index fixture with fake offline reference clients; real schema/hash/publication code; no external executor. `tests/unit/conftest.py` blocks real engines/network and disables fsync for unit tests. The root harness owns private test host pins and umask.

### Exact focused test command

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3636 \
  --max-tests 8 --expect-tests 8 --strict -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_review_package_assembly/test_contract.py \
  tests/unit/job_review_package_assembly/test_handlers.py
```

**8 collected, 8 passed, 0 failed/error/skipped, 0 over 10 s; exit 0.**
Pytest **6.40 s**; collection **4.623 s**, execution process **10.587 s**, total wrapper **15.577 s**.

Private stem: **`test/tmp/tests-custom-20261118-132349-252781-3340805`**. The wrapper's sequential collection/execution used only its unique stem, never another auditor's base.

- Log: `test/tmp/logs/tests-custom-20261118-132349-252781-3340805.log`
- Collection log: same stem with `.collection.log`
- JUnit: `<stem>.junit.xml`
- Timings: `<stem>.timings.sqlite`
- Collection manifest: `<stem>.collection.json`
- Fixed report: `test/tmp/reports/tests-custom-20261118-132349-252781-3340805.json`

The seven job tests cover registration/contract, config bounds, validation-scope cache, lineage, nonzero-gap and zero-gap publication, bad snapshot/handoff/lineage, and receipt hash/count mismatches. The eighth is the environment guard.

### Offline probe outcomes

All probe commands were `.venv/bin/python - <<'PY' ... PY` from the checkout, via the same transport. Their only state is **`test/tmp/job-audit-review-package-assembly-probes-20261118-1330`**. `results.json` and `typed-reads.json` retain outputs; fixture package manifests, unit results and SQLite rows remain available there. These are probes, **not additional pytest passes**.

| Probe | Actual result | Measured body time |
|---|---|---:|
| A1: zero leads + partial scanner coverage | one input gap → zero published gaps, `SUCCEEDED` | 1.370 s |
| A2: selected partial build fact | two packages, no gaps, `SUCCEEDED` | 0.575 s |
| A3: initial artifact-grant shape | grant rejection, but initial `asr:artifact:` kind was not a real entity kind; superseded by B1 | 0.523 s |
| B1: accepted actual `build_artifact` row | unscoped resolution succeeds; scoped retrieval denied | 1.308 s |
| B2: 66 document records | anchor retained, 64 records granted, two omitted with gap; deterministic reassembly; `COMPLETED_WITH_GAPS` | 0.859 s |
| C1: actual build-command reducer | complete product/shard, partial row, two omitted commands | 0.00164 s |
| C2: actual handler under typed input read scope | `COMPLETED_WITH_GAPS`; 18 reads / 14 dataset pairs | 1.793 s, excludes fixture creation |

Exploratory failures were not concealed:

- A preflight imported nonexistent `orchestration.topology.topology`; `ImportError`, exit 1, before tests. Corrected to `wave1_dependencies`; successful configuration/topology probe preceded the test run.
- The first B attempt tried `LogicalIdentity.parse("asr:artifact:…")`, which correctly failed with “unknown logical identifier kind” (exit 1, timer not reached). Corrected to `build_artifact` and built a real artifact row.
- The first C attempt successfully printed the real producer result in **0.00190 s**, then tried to assign to frozen `JobContext.upstream_handoffs`: `FrozenInstanceError`, exit 1. Corrected with `dataclasses.replace` and reused only that probe's freshly created private fixture. These are probe construction errors, not repository defects or failed unit tests.
- One navigation search named nonexistent `src/appsec_review/operations`; no test or file change resulted.

### Probe A — exact successful body

```python
import copy,json,os,time
from pathlib import Path
from dataclasses import replace
from unittest.mock import patch
from appsec_review.retrieval import IndexBuilder
from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.review_packages import _coverage_gaps, verify_review_packages
from tests.unit.job_review_package_assembly.test_handlers import _seed_zero_gap_run,_make_job_context,_make_unit_context,_core,build_job
os.umask(0o022)
base=Path('test/tmp/job-audit-review-package-assembly-probes-20261118-1330').resolve();base.mkdir(parents=True,exist_ok=False)
original_entity=IndexBuilder.add_entity; original_coverage=IndexBuilder.add_coverage
summary={}
for case in ('zero_leads_partial_coverage','partial_build_context','artifact_grant'):
 started=time.perf_counter()
 def add_entity(builder,entity):
  payload=copy.deepcopy(entity.payload)
  if payload.get('query_set')=='scanner_correlation' and case=='zero_leads_partial_coverage':
   if payload.get('fact_type') in {'lead','menu'}: return None
   if payload.get('fact_type')=='audit':
    payload['result']['counts']={'source_sast_observations':0,'high_critical':0,'unknown_severity':0}
  if payload.get('query_set')=='build_provenance':
   if case=='partial_build_context':
    payload['coverage_status']='partial'
    payload['result']['gaps']=['2 exec command(s) omitted by the per-action bound']
   if case=='artifact_grant':
    payload['result']['produced_artifact_ids']=['asr:artifact:'+'9'*64]
  return original_entity(builder,replace(entity,payload=payload))
 def add_coverage(builder,area,status,gap):
  if case=='zero_leads_partial_coverage' and area=='precomputed:qs-scanner-correlation':
   status,gap='partial','scanner failed; no completed source scan'
  return original_coverage(builder,area,status,gap)
 with patch.object(IndexBuilder,'add_entity',add_entity),patch.object(IndexBuilder,'add_coverage',add_coverage):
  run,target,snapshot,manifest_path,manifest_sha,shards=_seed_zero_gap_run(base/case)
 ctx=_make_job_context(run,target,source_fingerprint=snapshot,manifest_path=manifest_path,manifest_sha=manifest_sha)
 core,_,_=_core(_make_unit_context(ctx));before=_coverage_gaps(AcceptedShards(run,core.manifest['indexes'],snapshot))
 result=build_job().handler(ctx);pub=result['outputs']['publication.publish_packages']
 manifest=verify_review_packages(core,run/pub['package_directory'])
 data={'status':pub['terminal_status'],'packages':pub['package_count'],'input_shard_gaps':before,'published_gaps':manifest['coverage_gaps']}
 if case=='zero_leads_partial_coverage':
  assert before and pub['package_count']==0 and pub['terminal_status']=='SUCCEEDED' and not manifest['coverage_gaps']
 if case=='partial_build_context':
  data['partial_facts']=[row.payload for row in AcceptedShards(run,core.manifest['indexes'],snapshot).entities(core.manifest['indexes'],('precomputed_fact',)) if row.payload.get('coverage_status')=='partial']
  assert data['partial_facts'] and not manifest['coverage_gaps'] and pub['terminal_status']=='SUCCEEDED'
 if case=='artifact_grant':
  path=run/pub['package_directory']/(manifest['packages'][0]['package_id']+'.json');package=json.loads(path.read_bytes()); artifact='asr:artifact:'+'9'*64
  data['scope_artifacts']=package['scope']['artifact_ids'];data['artifact_in_grant']=artifact in package['retrieval']['entity_ids']
  from appsec_review.mcp.capability import issue_capability,ScopedRetrievalMcpAdapter
  from appsec_review.mcp.adapter import RetrievalMcpAdapter
  token=issue_capability(package,role='red',round_id='1',secret=b's'*32,expires_at=int(time.time())+300)
  adapter=ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core),package,capability=token,secret=b's'*32,role='red',round_id='1')
  try: adapter.call('find',{'identity':artifact})
  except ValueError as error: data['find_error']=str(error)
  assert data['scope_artifacts']==[artifact] and not data['artifact_in_grant'] and data['find_error']=='entity is outside review package'
 data['elapsed_seconds']=time.perf_counter()-started;summary[case]=data
 print(case,json.dumps(data,sort_keys=True))
(base/'results.json').write_text(json.dumps(summary,indent=2)+'\n')
```

### Probe B — exact corrected body

```python
import copy,json,os,time,hashlib
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from appsec_review.retrieval import IndexBuilder,IndexIdentity,EntityKind,EntityRecord,LogicalIdentity,SourceLocation,RetrievalCore,write_manifest
from appsec_review.storage import atomic_json,file_sha256
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.review_packages import assemble_review_packages,verify_review_packages
from appsec_review.mcp.capability import issue_capability,ScopedRetrievalMcpAdapter
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_review_package_assembly.test_handlers import _seed_zero_gap_run,_make_job_context,build_job
os.umask(0o022)
base=Path('test/tmp/job-audit-review-package-assembly-probes-20261118-1330').resolve()
results=json.loads((base/'results.json').read_bytes())

def add_shard(run,snapshot,name,shard_id,entities,extra=None):
 fp=hashlib.sha256((name+shard_id).encode()).hexdigest();path=run/'data/indices'/name/shard_id/(fp+'.sqlite')
 b=IndexBuilder(path,name=name,fingerprint=fp,target_snapshot=snapshot,shard_id=shard_id)
 for e in entities:b.add_entity(e)
 b.add_coverage(shard_id,'complete',None)
 return IndexIdentity(name,'appsec-review/retrieval-index/2',b.build(),fp,path.relative_to(run).as_posix(),{'job':'job_review_data_indexing','unit':'precompute.fixture',**(extra or {})},(),shard_id)

def accept(run,target,snapshot,shards,label):
 path=run/'data/indices/manifests'/(label+'.json');write_manifest(path,run_id=run.name,target_snapshot=snapshot,target_root=target,indexes=shards)
 ref={'path':path.relative_to(run).as_posix(),'sha256':file_sha256(path)}
 handoff=run/'data/jobs/job_review_data_indexing/attempts/attempt_0002/handoff.json'
 write_fixture_handoff(run,handoff,{'job_id':'job_review_data_indexing','source_fingerprint':snapshot,'completion_status':'SUCCEEDED',
  'artifacts':[ref,*({'path':s.relative_path,'sha256':s.sha256} for s in shards)],'outputs':{'publish.inventory_index':{'index_manifest':ref}}})
 atomic_json(run/'data/jobs/job_review_data_indexing/latest.json',{'handoff_path':handoff.relative_to(run).as_posix(),'handoff_sha256':file_sha256(handoff)})
 return path,ref['sha256']

start=time.perf_counter();artifact='asr:build_artifact:'+'9'*64;original=IndexBuilder.add_entity
def with_artifact(builder,entity):
 payload=copy.deepcopy(entity.payload)
 if payload.get('query_set')=='build_provenance':payload['result']['produced_artifact_ids']=[artifact]
 return original(builder,replace(entity,payload=payload))
with patch.object(IndexBuilder,'add_entity',with_artifact):
 run,target,snapshot,mp,ms,shards=_seed_zero_gap_run(base/'accepted_artifact')
shards.append(add_shard(run,snapshot,'artifacts','audit-artifact',[EntityRecord(LogicalIdentity.parse(artifact),'artifact1','app.bin','compiled artifact',{'sha256':'7'*64})]))
mp,ms=accept(run,target,snapshot,shards,'with-artifact');core=RetrievalCore(run.parent,run.name,manifest_path=mp,manifest_sha256=ms)
ctx=_make_job_context(run,target,source_fingerprint=snapshot,manifest_path=mp,manifest_sha=ms);pub=build_job().handler(ctx)['outputs']['publication.publish_packages']
m=verify_review_packages(core,run/pub['package_directory']);package=json.loads((run/pub['package_directory']/(m['packages'][0]['package_id']+'.json')).read_bytes())
assert core.find(identity=artifact)['results'][0]['identity']==artifact
assert artifact in package['scope']['artifact_ids'] and artifact not in package['retrieval']['entity_ids']
secret=b's'*32;token=issue_capability(package,role='red',round_id='1',secret=secret,expires_at=int(time.time())+300)
adapter=ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core),package,capability=token,secret=secret,role='red',round_id='1')
try:adapter.call('find',{'identity':artifact});raise AssertionError('grant should be missing')
except ValueError as error:assert str(error)=='entity is outside review package'
results['artifact_grant_accepted']={'unscoped_find_resolves':True,'scoped_find':'entity is outside review package','elapsed_seconds':time.perf_counter()-start}
print('artifact_grant_accepted',results['artifact_grant_accepted'])

start=time.perf_counter();run,target,snapshot,mp,ms,shards=_seed_zero_gap_run(base/'document_bound')
data=(target/'svc/app.py').read_bytes();loc=SourceLocation(snapshot,'svc/app.py',hashlib.sha256(data).hexdigest(),0,len(data),1,2,1,1,{},'exact',1.0)
docs=[]
for n in range(66):
 identity=LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD,snapshot,{'audit_record':n})
 docs.append(EntityRecord(identity,str(n),'route declaration','fixture document',{'record':n},loc))
ids=sorted(d.identity.value for d in docs);anchor=ids[-1]
fact_id=LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT,snapshot,{'audit_context':'GET /fixture'})
fact=EntityRecord(fact_id,'route','route','fixture route',{'schema':FACT_SCHEMA,'query_set':'document_context','fact_type':'route_context','subject_identity':anchor,'gaps':[],
 'result':{'subject_type':'route','key':'GET /fixture','members':{'design':ids}}},None)
shards.append(add_shard(run,snapshot,'documents','audit-documents',docs))
shards.append(add_shard(run,snapshot,'precomputed','qs-document-context',[fact],{'query_set':'document_context'}))
mp,ms=accept(run,target,snapshot,shards,'with-documents');core=RetrievalCore(run.parent,run.name,manifest_path=mp,manifest_sha256=ms)
ctx=_make_job_context(run,target,source_fingerprint=snapshot,manifest_path=mp,manifest_sha=ms);pub=build_job().handler(ctx)['outputs']['publication.publish_packages'];m=verify_review_packages(core,run/pub['package_directory'])
entry=next(p for p in m['packages'] if p['kind']=='document_hunt');p=json.loads((run/pub['package_directory']/(entry['package_id']+'.json')).read_bytes())
assert anchor in p['context_ids'] and len(p['context_ids'])==65 and p['truncation']['omitted_context']==2
assert not p['lead_menu'] and p['retrieval']['query_sets']==['document_context']
assert any(g['state']=='truncated' for g in p['coverage_gaps']) and any('not been mapped' in g['reason'] for g in p['coverage_gaps'])
a,b=assemble_review_packages(core);aa,bb=assemble_review_packages(core);assert (a,b)==(aa,bb)
results['document_bound']={'source_records':66,'retained_source_records':64,'anchor_retained':True,'omitted_context':2,'deterministic_reassembly':True,'status':pub['terminal_status'],'elapsed_seconds':time.perf_counter()-start}
print('document_bound',results['document_bound']);(base/'results.json').write_text(json.dumps(results,indent=2)+'\n')
```

### Probe C — exact corrected body

The previous failed C command had already built the private typed-read fixture with:
`build_accepted_index_set(base/'typed_reads', publish_v1_packages=False)`. Nothing outside that private fixture was reused or changed.

```python
import json,os,time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from appsec_review.indexing.build_facts import build_command_facts
from appsec_review.indexing.products_base import to_derived
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage.validation import validation_scope
from appsec_review.storage import file_sha256
from tests.unit.job_review_package_assembly.test_handlers import _make_job_context,build_job
os.umask(0o022)
base=Path('test/tmp/job-audit-review-package-assembly-probes-20261118-1330').resolve();results=json.loads((base/'results.json').read_bytes())
start=time.perf_counter();sha='a'*64
class Shards:
 def select(self,*args,**kwargs):return ({'name':'build','shard_id':'a','sha256':sha},)
 def relations(self,*args,**kwargs):return ()
 def entities(self,*args,**kwargs):return [SimpleNamespace(identity='asr:build_action:'+'b'*64,payload={'tool':'cc','execution_capture':{'events_sha256':sha}})]
records=[{'argv':['cc','-c','src/'+name+'.c'],'envp':[]} for name in ('one','two','three')]
with patch('appsec_review.indexing.build_facts.capture_events',return_value={sha:base}),patch('appsec_review.indexing.build_facts._exec_events',return_value=(records,False)):
 product=build_command_facts(Shards(),base,{},max_events=100,max_commands=1)
derived=to_derived(product,'target-sha256:'+'7'*64,100)
assert product.status=='complete' and product.facts[0].coverage=='partial'
assert derived.entities[0].payload['coverage_status']=='partial' and '2 exec command(s)' in product.facts[0].result['gaps'][0]
results['real_context_producer']={'product_status':product.status,'row_status':product.facts[0].coverage,'row_gaps':product.facts[0].result['gaps'],'derived_coverage':derived.coverage,'elapsed_seconds':time.perf_counter()-start}
print('real_context_producer',results['real_context_producer'])
start=time.perf_counter();run=base/'typed_reads/runs/2026-10-12-0001';mp=run/'data/indices/manifests/fixture.json';manifest=json.loads(mp.read_bytes())
ctx=_make_job_context(run,base/'typed_reads/target',source_fingerprint=manifest['target_snapshot'],manifest_path=mp,manifest_sha=file_sha256(mp))
pins={p.parent.name:json.loads(p.read_bytes())['handoff_sha256'] for p in (run/'data/jobs').glob('*/latest.json')}
ctx=replace(ctx,upstream_handoffs=pins)
with validation_scope(run),input_read_scope(ctx) as reads:
 outcome=build_job().handler(ctx)
 assert outcome['status']=='COMPLETED_WITH_GAPS',outcome
 receipts=reads.document()
summary=sorted({(r['producer'],r['output_kind']) for r in receipts['reads']})
results['typed_reads']={'status':outcome['status'],'read_count':len(receipts['reads']),'datasets':[list(r) for r in summary],'elapsed_seconds':time.perf_counter()-start}
print('typed_reads',results['typed_reads']);(base/'typed-reads.json').write_text(json.dumps(receipts,indent=2)+'\n');(base/'results.json').write_text(json.dumps(results,indent=2)+'\n')
```

## Read coverage and material gaps

**Read fully:** updated audit brief; authorized AGENTS and multi-session skill; all three job modules; `review_packages.py`; `indexing/products_base.py`, `indexing/store.py`; `mcp/capability.py`; both dedicated job unit files; unit conftest; unit environment guard; accepted-index fixture builder; offline reference-feed fixtures; handoff fixture helper; shell wrapper/common launcher; architecture review-package contract; prior prioritization report.

**Read relevant ranges/searches:** canonical operations purpose/contracts/process/gaps/acceptance/resume (skipped the remaining repetitive generated Mermaid declarations after the authoritative table); entire `/3` schema definitions, not the full `/7` definitions; root conftest through timing/collection hooks; wrapper `ops_tests.py` command/collection/worker/report paths; registry/config/test-map entries; topology graph construction; runtime Job/Unit/consume/input observation boundaries; retrieval manifest resolution/composition/core construction; shared publication/admission projection; scanner-correlation reducer and build-command producer; inference accept/assembly seam and datasets; document-analysis consumer seam; relevant TODO T-147/T-165/T-167/T-173/T-5062/T-5064 and title/term searches; graph report CGI-F12 and cumulative dedup notes; modern review-unit score conversion; tests/review package imports/test inventory; mixed target-document tests through document-package case; compiled-function producer identifiers.

**Material unread/unverified:** full upstream jobs and their other findings; full modern inference package/ranking/slicing/view implementation; whole shared runtime/admission/import-signing machinery; full TODO registry; generated inventory bodies; actual target/run-owned production package evidence; large-corpus byte/memory costs and context-cap behavior; real crash/restart/concurrent publication/release replay; every possible dataset combination; real graph/alternate shard assembly under this job (CGI-F12 previously reproduced in inference, confirmed here statically); complete end-to-end document adjudication and final reporting. No integration/acceptance/live/model validation was authorized or run.

No repository changes or TODO edits. This auditor stops after this one job; the coordinator owns accumulation and final deduplication.
