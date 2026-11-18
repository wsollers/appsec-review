# Job 37/47 — job_document_issue_analysis

## Identity, authority, and result

- Audited **`0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, clean `main`, in `/home/wsollers/projects/appsec-review` through `ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu` and the authorized Ubuntu-22.04 UNC root. HEAD and cleanliness were checked before and after validation. Python imported `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`.
- Read the updated shared brief, authorized `AGENTS.md`, and canonical multi-session coordination skill. This was one read-only functional audit, not an exploit review. No source/configuration/environment edits, installs, subagents, real models, external tools, services, target execution, integration, acceptance, or live runs.
- **One high and nine medium findings below.** DI-F02 is a continuing previously reported integration gap, not a newly discovered independent defect. DI-F03–F06 and DI-F08–F10 are latent helper defects demonstrated with the currently expected synthetic document shape; DI-F01 presently prevents the canonical catalog shape from reaching them. DI-F07 affects the active candidate-ledger path.
- **Validation:** 24 inspected units passed, including one environment guard; pytest 6.60 s, wrapper 15.2245 s; zero failures/skips/tests over 10 s. Nine bounded reproductions completed in 0.767 s. An earlier reproduction stopped on an overly narrow assertion, documented below.
- Passing units do **not** establish correct production drift results: the new drift test constructs a different document payload from the real producer.

## Intended and actual contract

In the compact trace below, `job.py` means `src/appsec_review/jobs/job_document_issue_analysis/job.py`; other abbreviated Python module paths are relative to `src/appsec_review/`. Finding evidence uses full repository-relative paths for the primary defect sites.

Registration is explicit in `src/appsec_review/runtime/registry.py:105,176`. The job is enabled by the dev recipe, with one worker, one step, and one task (`appsec-review.toml:1221-1231`). It has no model/prompt/response binding and its traced implementation makes no inference call. Missing generated task-binding metadata remains T-147; that missing declaration is not the basis for the no-inference conclusion.

The typed contract declares **142 handoff-channel input requirements over 27 producers** (`jobs/job_document_issue_analysis/datasets.py:26-356`). Only `job_review_package_assembly/handoff` is required/reject. The two dependency-native-advisory datasets are when-declared/not-applicable; the other 139 requirements are optional/gap. `schedule_after` is package assembly, target access is `CHECKOUT`, `always_execute=False`, and handoff propagation is enabled. Topology derives dependency edges from both scheduling and consumption (`orchestration/topology.py:46-81`); there is not a second independent task graph.

Actual semantic reads:

1. The claim-pinned retrieval manifest is resolved and hash-checked (`retrieval/core.py:112-125`), then its snapshot must equal the job fingerprint.
2. `indexing.store.accepted_handoff` calls `runtime.consume.accepted_upstream`, verifies shared evidence, and records shared consumption (`indexing/store.py:35-50`). The handler resolves package assembly's result through the accepted handoff, checks artifact membership/hash and containment, and requires the package manifest to be hash-bound to both the handoff and accepted index set (`job.py:78-101`).
3. Package verification rechecks canonical bytes, manifest/projection identities, complete directory membership, package hashes, document/scanner membership and counts; accepted named package objects are consumed (`review_packages.py:538-605`). Document hunts derive from accepted `document_context` route/boundary facts and grant at most 64 exact document-record identities (`review_packages.py:94-128,476-498`).
4. Mapping reads accepted `job_target_catalog` source rows. Drift additionally selects that producer's document rows. `AcceptedShards` delegates to `ShardSet`; actual shard opens call `observe_shard` (`indexing/products_base.py:48-80`; `indexing/store.py:86-96,149-175`). This is not evidence that every one of the 142 declared inputs is semantically read.
5. The internal package-result read remains coupled to `outputs["publication.publish_packages"]`; it does not use an explicit `observe_output` call for the package payload. Historical C10-F07 already discusses this coupling/read-accounting issue. Do not repeat the old report's claim that the handoff reader itself bypasses `accepted_upstream`: the current helper does call it.

### Every declared task, with its internal phases

| Step/task | Actual implementation | Observed boundary / coverage |
|---|---|---|
| `analysis.map_and_adjudicate` — admission | `job.py:45-52,75-101`; topology/settings validation, pinned manifest, snapshot, accepted package handoff and artifact hashes | Unit tests cover malformed config, escaped/missing/unbound references, snapshot and count mismatches. No connected producer pipeline executed. |
| Same task — ledger cache | `job.py:102-131`; fingerprint includes accepted index/package manifests, settings, snapshot, schema, implementation/platform and validation releases; lookup only when releases permit reuse | Cache hit still verifies bounded package/source inputs and the ledger. Tests cover job release, platform fallback, missing releases, computed/reused receipt provenance. Drift is recomputed even when the ledger is reused. |
| Same task — candidate mapping | `document_issues.py:37-73,128-189`; bounded accepted source scan, literal route matching, one candidate per document hunt, explicit unique/ambiguous/unmapped status | Source bytes/hash/paths, oversized/undecodable files and source cap tested. DI-F07 loses registrations on one line. Dynamic mounts, semantic boundaries, handler bodies and nonliteral forms remain documented limits, not proven absence. |
| Same task — adjudication gate | `document_issues.py:76-125,175-187` | Helper can check optional red/blue/verifier decisions and resolving proof lines, but the job supplies none. All automatic candidates stay `insufficient_evidence`; `proof_evidence`, findings and scoring inputs are empty. No independent review is commissioned. |
| Same task — API/spec drift | `document_issues.py:234-750`, invoked at `job.py:133-148` | Separate nine-language regex extraction and OpenAPI/GraphQL/protobuf parsing; no AST query despite T-172 design prose. DI-F01 and the latent defects below. |
| Same task — publication/validation | `job.py:55-72,125-175`; ledger JSON Schema, drift JSON Schema, immutable ledger object/receipt and attempt-addressed drift artifact | Both artifacts declared `artifact_only` and `PROVISIONAL`. Output validation verifies artifact hashes/containment, ledger identity/candidate count/no finding publication, and drift identity fields. No retrieval shard is produced. |
| Same task — status | `job.py:165-175`; `runtime/units.py:142-171,178-216` | Successful processing intentionally returns `COMPLETED_WITH_GAPS`; first gap is `UNADJUDICATED_GAP`, then candidate gap IDs and drift strings. Exceptions fail the unit. Legacy free-text gaps are a documented existing boundary, not a new custom terminal status. |

### Evidence, classification, schemas, and consumers

- Candidate IDs bind package ID, matching source registrations and rule; document nomination/qualification evidence remains separate from exact source entity/shard/path/hash/line evidence. A unique mapping does not establish insecure behavior. No CWE, severity score, or confirmed finding is synthesized.
- `adjudicate` verifies accepted source identity/hash/nonempty proof lines, requires a unique map, proof within 100 lines after a matching registration, intersecting review evidence references, matching red/verifier claim text and no unresolved blue refutation. This narrow gate is **not invoked with review decisions by this job**. Unit tests exercise the helper's positive and refusal cases; they do not prove semantic independence of arbitrary supplied reviews.
- Ledger publication uses `data/shared/objects/<exact-byte-sha256>` plus an attempt-local `shared/document-issues/<fingerprint>.json` receipt; legacy `data/document-issues/<content-hash>/ledger.json` remains readable. Dataset globs explicitly claim the legacy file and shared receipt; generic shared-object ownership is protected. Drift uses `data/document-issues/<attempt_id>/drift-issues.json`, matching its declaration. `storage/shared.py:97-120` refuses conflicting immutable publication.
- Ledger `/1` schema is closed at the top level and evidence/candidate objects; its findings/scoring arrays remain empty by verifier policy. Drift `/1` is closed, declares five possible kinds, and carries provisional authority, identifiers, paths, handler line, auth flag, schemes/guards and telemetry. `parameter_constraint_drift` is declared but never emitted: required parameters are parsed then unused.
- Bounds: default 20,000 source files and 1,048,576 bytes/file; central typed settings cap these at 100,000 and 16 MiB (`config/loader.py:97-105,1420-1425`). The candidate mapper counts source rows before filtering; drift counts only successfully read files, retains their text in `source_by_path`, and can reread documents outside that successful-source count. No distinct drift-operation/mismatch/output cap exists.
- The inference job now declares this producer's handoff, ledger and drift datasets and schedules after it (`job_inference_security_review/datasets.py:416-428`). Declaration is not actual delivery: DI-F02 remains. Normal `document_context` facts carry members/intent, not drift classifications (`indexing/products.py:1727-1802`).

## Findings

### DI-F01 — High: real catalog document payloads are all skipped by drift analysis

- **Evidence:** `src/appsec_review/jobs/job_target_catalog/job.py:716-720` emits `record_type="target_document"`, `document_kind`, `subtype`, `authority`, `fields`. `src/appsec_review/document_issues.py:581-587` reads nonexistent `format`/`document_class` and continues. Contrast `tests/unit/test_t172_indexing_and_retrieval.py:120-127`, which invents a top-level `format`.
- **Trigger:** ordinary accepted OpenAPI/GraphQL/protobuf catalog records.
- **Expected / actual:** recognize the accepted producer format; instead, no canonical record qualifies. Two genuine collected OpenAPI operations plus one matching source handler produced `specs_parsed=0`, `mismatches=[]`, `gaps=[]`.
- **Impact:** the newly added drift path is effectively empty for its actual producer. The global job still says `COMPLETED_WITH_GAPS` because of adjudication; that does not disclose this lost analysis.
- **Confidence:** high, source-verified and reproduced using the real collector, real immutable indexes and exact production payload shape, without a connected pipeline.
- **Smallest correction:** consume the canonical record fields and add a producer-shape regression, preferably using existing collected operation facts instead of an incompatible duplicate document representation.
- **Overlap:** T-172 says this work is done; no exact existing entry found for this mismatch. Historical C10-F04 predates this drift implementation.

### DI-F02 — Medium, existing: declarations do not deliver document results to inference

- **Evidence:** `src/appsec_review/jobs/job_document_issue_analysis/datasets.py:7-18` declares both datasets artifact-only; `src/appsec_review/jobs/job_document_issue_analysis/job.py:133-175` publishes JSON, no index identity/manifest. `src/appsec_review/retrieval/core.py:1895-1905,1921-1929,1945-1960` reads only `document_context` precomputed rows and document-observation shards for `query_doc_drift`. The real `document_context` producer emits no `drift_kind` (`src/appsec_review/indexing/products.py:1763-1788`). Inference assembles its own packages from accepted scope/lead collection (`src/appsec_review/jobs/job_inference_security_review/job.py:280-298,397-415`; `src/appsec_review/review/packages.py:2264-2280,2291-2318`), with no reader for this ledger/drift JSON.
- **Trigger:** a document ledger/drift artifact is successfully published.
- **Expected / actual:** T-172 promises indexed drift leads/hunt-package admission. The new scheduling/input declarations exist, but no payload-to-shard or payload-to-package path exists. A source search for the exact dataset/artifact identifiers found only producer/contract sites, not an inference payload reader.
- **Impact:** document computation remains absent from the inference lead path; a query test over hand-built drift shards does not establish publication wiring.
- **Confidence:** high static finding; actual inference/models were not run.
- **Smallest correction:** add a bounded accepted-payload projection/read at the appropriate downstream seam, preserving provisional authority and source identities, and test producer output through that seam. Do not feed raw unadjudicated ledger claims into confirmed findings.
- **Overlap:** **C10-F04, T-059, T-172**. This is continuation of the known unconsumed-result problem, not “zero declared consumers” or “zero unit tests” at this revision.

### DI-F03 — Medium, latent: document fallback reads changed bytes without checking accepted document hashes

- **Evidence:** `src/appsec_review/document_issues.py:588-598`; compare source-file hash verification at `:558-564`. The document fallback uses containment/existence/size checks but never compares bytes against `doc_row.location["file_sha256"]`.
- **Trigger:** a recognized document row is not present in the successfully bounded source-file map—for example an optional missing source row or source-window omission.
- **Expected / actual:** fail on changed accepted document bytes; instead, altered `/changed` operations were parsed and published under the unchanged accepted-manifest identity, with no drift gap.
- **Impact:** a provisional report can cite the old accepted document identity while analyzing a different file. Normal source-map inclusion protects many files, but not this explicit fallback.
- **Confidence:** high, reproduced; requires the recognized synthetic shape now or DI-F01 to be corrected.
- **Smallest correction:** read/hash-check the exact accepted document bytes once, reuse that checked value, and retain the relevant document-record/source-location identity.
- **Overlap:** T-172 scope; no exact prior finding found.

### DI-F04 — Medium, latent: one whole spec is expanded once per document record, duplicating drift IDs and work

- **Evidence:** `src/appsec_review/document_issues.py:579-624` parses the complete file for every document row; `seen_spec_paths` affects only the telemetry count, not extraction. Mismatches are appended and sorted without deduplication at `:635-735`. Catalog produces one row per operation (`src/appsec_review/indexing/target_documents.py:232-236`).
- **Trigger:** two or more accepted operation records from one recognized spec file.
- **Expected / actual:** each operation/drift identity once. A two-operation spec yielded four mismatches but only two unique `drift_id`s, while `specs_parsed=1`.
- **Impact:** inflated mismatch telemetry, duplicate leads if consumers are added, and approximately quadratic parsing/comparison work for large single specs. No operation/mismatch cap contains the expansion.
- **Confidence:** high, reproduced with canonical record multiplicity plus the currently expected format field.
- **Smallest correction:** group accepted records by exact file identity before parsing, bound extraction, and deduplicate final records by an identity that preserves distinct spec provenance.
- **Overlap:** T-172; no exact existing entry found.

### DI-F05 — Medium, latent: unrelated route-local guards become file-global protection

- **Evidence:** `src/appsec_review/document_issues.py:334,385-391` harvests every auth-looking token from the first 35 lines and uses it when a route window has no local guard; `:664-707` bases drift classification on those guards/roles.
- **Trigger:** a protected route or merely an auth-related token near the beginning of a file and an unprotected route elsewhere.
- **Expected / actual:** a route-local middleware is not a global middleware registration. A plain `/orders/:id` at line 42 inherited `["requireAuth", "secured"]` from a different route at line 1, outside its own window. `secured` was itself recognized from text, not established enforcement.
- **Impact:** missing-auth navigation leads are suppressed by unrelated code; nearby-route windows can similarly leak guards, role words and anonymous overrides.
- **Confidence:** high, pure extractor reproduction; reporting consequences depend on recognized specs.
- **Smallest correction:** separate explicit framework-wide middleware from route-local guards; otherwise classify enforcement as unresolved, with a named heuristic limit, rather than borrowing any early token.
- **Overlap:** T-172; documented regex limits do not justify attributing a different route's middleware as this route's guard.

### DI-F06 — Medium, latent: optional OpenAPI authentication is classified as required

- **Evidence:** `src/appsec_review/document_issues.py:449-476` recognizes anonymous access only for `security: []`, then requires auth whenever a nonempty alternative names a scheme. The existing canonical parser handles empty alternatives correctly at `src/appsec_review/indexing/document_interfaces.py:144-153`.
- **Trigger:** `security: [{}, {"bearerAuth": []}]`.
- **Expected / actual:** authentication is optional because one alternative is anonymous. The drift parser returns `requires_auth=True`, enabling a false missing-auth lead.
- **Impact:** explicitly public/optionally authenticated endpoints are mislabeled as contradicting their specification.
- **Confidence:** high, direct parser reproduction.
- **Smallest correction:** share the canonical security-state interpretation, including OR alternatives and operation-level overrides.
- **Overlap:** T-172; distinct from historical C10-F05's lost producer fields.

### DI-F07 — Medium, active: multiple literal registrations on one line falsely become a unique mapping

- **Evidence:** `src/appsec_review/document_issues.py:66-72` uses one `_ROUTE.search` per line; `:151-164` selects `unique` from the resulting count and removes the premapping gap.
- **Trigger:** `router.get('/orders/:id', h1); router.get('/orders/:id', h2);` on one accepted source line.
- **Expected / actual:** two literal matches must not establish uniqueness. The real ledger reports `mapping_status="unique"` with one evidence record.
- **Impact:** valid ambiguity is lost; only the first registration is represented. A different second route on the same line is instead silently left unmapped. Candidates remain insufficient evidence, so this is not a confirmed-finding false positive.
- **Confidence:** high, reproduced through real package publication/verification and `analyze_document_hunts`.
- **Smallest correction:** iterate all registrations and retain an occurrence discriminator where multiple matches share a line.
- **Overlap:** T-059/C10-F04 cover broad mapping limitations; this specific false-unique case was not identified there.

### DI-F08 — Medium, latent: matched-handler deduplication drops the HTTP method

- **Evidence:** `src/appsec_review/document_issues.py:633,663,712-713` tracks matched handlers only as `(path, route, line)` even though extraction produces one row per method (`:394-411`).
- **Trigger:** Flask `@app.route("/orders/<id>", methods=["GET", "POST"])`, with only GET documented.
- **Expected / actual:** POST is an undocumented route-method pair. The report scans two handlers but emits zero mismatches because matching GET also marks POST matched.
- **Impact:** entire undocumented methods disappear, especially relevant for mutating methods sharing a path.
- **Confidence:** high, reproduced using real extraction and drift comparison.
- **Smallest correction:** include method in both matched-key construction and lookup; explicitly handle an `ANY` handler's method coverage rather than erasing it.
- **Overlap:** T-172; no exact prior entry found.

### DI-F09 — Medium, latent: parse failures are counted as parsed specs without coverage gaps

- **Evidence:** `src/appsec_review/document_issues.py:419-438` collapses JSON/YAML parse errors and unsupported shapes into `[]`; `:621-624` counts any non-null raw text as a parsed spec. Missing/escaped/undecodable source paths also silently continue at `:558-570`; document fallback omissions at `:591-598` add no cause.
- **Trigger:** recognized spec text that cannot be parsed, including a changed fallback document.
- **Expected / actual:** a named parse/unavailable gap and no successful parse count. `openapi: [broken` yielded `specs_parsed=1`, `mismatches=[]`, `gaps=[]`.
- **Impact:** per-domain telemetry cannot distinguish processed-with-no-drift from unparsed/no-coverage. The global unadjudicated gap does not identify this missing work.
- **Confidence:** high, reproduced. The bounded fixture mutated accepted text to isolate this parser branch; DI-F03 separately addresses why that read should fail integrity first.
- **Smallest correction:** return explicit parse outcome/reason, increment parsed counts only after valid supported structure, and account for every omitted accepted input.
- **Overlap:** T-172; no exact prior entry found.

### DI-F10 — Medium, latent: GraphQL/protobuf extraction loses enclosing operation context

- **Evidence:** `src/appsec_review/document_issues.py:489-510` matches all field-like lines, not only root GraphQL operations; `:511-530` finds the first protobuf service and assigns every RPC to it. Caller computes a source ID/path at `:585-590`, but the GraphQL/protobuf branch passes only `dp` at `:602-603`, whose parser expects top-level path/source IDs (`:485-487`).
- **Trigger:** GraphQL object fields alongside root fields; multiple protobuf services; location-only document identities.
- **Expected / actual:** `User.id` is not a `/graphql#id` root operation, and `B.Two` is not `/A/Two`. The direct helper returned both invented associations; top-level IDs absent from `dp` also become empty/null even when the caller resolved a location.
- **Impact:** incorrect operation navigation/citation provenance if this path is wired. Unmatched non-OpenAPI operations are silently omitted (`:639-660`), so the “nine-language” happy-path test does not prove GraphQL/protobuf comparison coverage.
- **Confidence:** high for helper outputs, reproduced; no production non-HTTP integration run.
- **Smallest correction:** reuse the bounded canonical interface parser's enclosing-type/service facts, pass resolved document identity explicitly, and name unsupported implementation mapping as coverage rather than silently discarding it.
- **Overlap:** T-172; no exact prior entry found.

## Existing boundaries and documentation/test-map drift

- **Not a new bug:** the candidate ledger intentionally has no independent review, supported findings, or scoring inputs. This is accurately stated in `docs/architecture/document-evidence-analysis.md`, canonical job purpose, and `docs/operations/document-issue-analysis.md`, and historically tracked by C10-F04/T-059.
- **Not all old C10-F04 assertions remain true:** there are now unit tests, a shared accepted-upstream handoff reader, and declared inference consumers. Its broad “142 unused” wording is not adopted: package verification and manifest assembly read several input families indirectly.
- **Prose drift:** canonical job process/acceptance/resume sections (`docs/operations/job_document_issue_analysis.md:936-1024`) still describe only the candidate ledger, omitting the new always-executed drift phase, its schema, recomputation, counts and failure modes. `docs/operations/document-issue-analysis.md` likewise describes the older boundary. T-172 task prose promises AST cross-reference, security documents, input-constraint drift and downstream indexing not present in this implementation.
- **Mapping gap:** `tests/job-test-map.json:276-287` correctly maps all three job unit files but omits the only new drift-specific test, `tests/unit/test_t172_indexing_and_retrieval.py::test_t172_nine_language_api_spec_drift_and_schema_validation`. It was inspected and included manually.
- The handler fixture uses documents produced by synthetic `job_document_analysis` with no `format`; the new drift branch therefore does no actual spec comparison there. The T-172 test supplies `format` and one document row per file, hiding both DI-F01 and DI-F04. It checks a set of three kinds, not exact per-language results, duplicate IDs, optional-auth semantics, source tampering or non-HTTP operation correctness.

## Focused validation, exact commands, and outcomes

All Linux commands below were transported with the brief's base64 PowerShell wrapper:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Initial and pre-test admission:

```bash
set -eu
cd /home/wsollers/projects/appsec-review
git rev-parse HEAD
git branch --show-current
git status --short
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
```

Result: exact SHA, `main`, no tracked/untracked changes, imported authorized source.

### Existing units

```bash
scripts/run-tests.sh --parallel --test-workers 2 --shuffle-seed 3718 \
  --max-tests 24 --expect-tests 24 -- \
  tests/test_000_unit_environment_guard.py::test_unit_session_does_not_inherit_production_sizing \
  tests/unit/job_document_issue_analysis/test_contract.py \
  tests/unit/job_document_issue_analysis/test_document_issues.py \
  tests/unit/job_document_issue_analysis/test_handlers.py \
  tests/unit/test_t172_indexing_and_retrieval.py::test_t172_nine_language_api_spec_drift_and_schema_validation
```

- Collection **24**, execution **24 passed**, no skips/errors/failed/slow cases.
- 13 contract/config cases, 4 mapping/adjudication/ledger cases, 5 handler/cache/validation cases, 1 drift case, 1 environment guard.
- Pytest elapsed **6.60 s**; collection supervisor **4.2631 s**, execution supervisor **10.6234 s**, total wrapper **15.2245 s**.
- Wrapper-owned unique collection/execution base: `test/tmp/tests-custom-20261118-132811-256808-3397848`.
- Logs: `test/tmp/logs/tests-custom-20261118-132811-256808-3397848.log` and `.collection.log`.
- JUnit: `test/tmp/tests-custom-20261118-132811-256808-3397848.junit.xml`.
- Timings: `test/tmp/tests-custom-20261118-132811-256808-3397848.timings.sqlite`.
- Report: `test/tmp/reports/tests-custom-20261118-132811-256808-3397848.json`; collection node manifest uses the same basename and `.collection.json`.
- No standalone/shared-default pytest collection was used. Both wrapper stages reused only this wrapper's private directory, as authorized.

### Bounded reproductions

The successful nine-check command was `.venv/bin/python - <<'PY'` with the following body, after `set -eu; cd /home/wsollers/projects/appsec-review`. It uses the already inspected local fixture builder, real collector/index/manifest/package functions, and only local synthetic files. No target contents are executed. Scratch was a UUID descendant of `test/tmp/` and removed in `finally`.

```python
import dataclasses, hashlib, json, os, shutil, time, uuid
from pathlib import Path
from appsec_review import document_issues as d
from appsec_review.indexing.target_documents import collect_target_documents
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation, write_manifest
from appsec_review.review_packages import publish_review_packages
from appsec_review.storage import file_sha256
from tests.unit.job_document_issue_analysis.test_document_issues import _build_core
start=time.monotonic(); os.umask(0o022)
root=Path('test/tmp')/('job-audit-document-issues-repro-'+uuid.uuid4().hex)
root.mkdir(parents=True)
rows=[]
def emit(name, value):
    rows.append({'check':name, 'observed':value}); print(json.dumps(rows[-1],sort_keys=True))
spec='''openapi: 3.0.3
paths:
  /orders/{id}:
    get:
      security:
        - bearerAuth: []
  /ghost:
    get: {}
'''
def fixture(label, text=spec, canonical=True, count=None, sources=None):
    core,target,snapshot=_build_core(root/label,source_files=sources)
    path=target/'api/openapi.yaml'; path.write_text(text,encoding='utf-8')
    records=collect_target_documents(target,snapshot,[{'path':'api/openapi.yaml','sha256':file_sha256(path),'kind':'openapi'}]).records
    fp=hashlib.sha256(label.encode()).hexdigest(); db=core.run_root/'data'/'indices'/f'{label}.sqlite'
    builder=IndexBuilder(db,name='documents',fingerprint=fp,target_snapshot=snapshot,shard_id='real-shape')
    selected=list(records) if count is None else list(records)[:count]
    for rec in selected:
        identity=LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD,snapshot,{'record_id':rec['id']})
        payload={'record_type':'target_document','document_kind':rec['kind'],'subtype':rec['subtype'],'authority':rec['authority'],'fields':rec['fields']}
        if not canonical: payload.update(format=rec['kind'],path=rec['path'])
        location=SourceLocation(snapshot,rec['path'],rec['file_sha256'],0,path.stat().st_size,rec['line'],rec['end_line'],1,1,{},'exact',1.0)
        builder.add_entity(EntityRecord(identity,rec['id'],rec['text'],rec['text'],payload,location))
    builder.add_coverage('documents','complete',None); sha=builder.build()
    indices=[IndexIdentity(**{**v,'gaps':tuple(v.get('gaps',()))}) for v in core.manifest['indexes'] if v['name']!='documents']
    indices.append(IndexIdentity('documents','appsec-review/retrieval-index/2',sha,fp,db.relative_to(core.run_root).as_posix(),{'job':'job_target_catalog'},(),'real-shape'))
    manifest=core.run_root/'data'/'indices'/f'{label}-manifest.json'
    write_manifest(manifest,run_id=core.run_id,target_snapshot=snapshot,target_root=target,indexes=indices)
    return RetrievalCore(core.run_root.parent,core.run_id,manifest_path=manifest,manifest_sha256=file_sha256(manifest)),path,len(records)
try:
    core,path,n=fixture('canonical')
    report=d.analyze_api_spec_drift(core)
    assert n==2 and report['specs_parsed']==0 and report['mismatches']==[] and report['gaps']==[]
    emit('canonical_catalog_shape',{'catalog_operations':n,'specs_parsed':0,'handlers_scanned':report['handlers_scanned'],'mismatches':[],'gaps':[]})
    core,path,n=fixture('format-fixture',canonical=False)
    report=d.analyze_api_spec_drift(core); ids=[v['drift_id'] for v in report['mismatches']]
    assert len(ids)==4 and len(set(ids))==2
    emit('duplicate_document_row_expansion',{'specs_parsed':report['specs_parsed'],'mismatches':len(ids),'unique_ids':len(set(ids))})
    before=file_sha256(path); path.write_text('openapi: 3.0.3\npaths:\n  /changed:\n    get: {}\n',encoding='utf-8')
    mutated=d.analyze_api_spec_drift(core)
    assert file_sha256(path)!=before and any(v['route']=='/changed' for v in mutated['mismatches'])
    emit('changed_spec_fallback',{'changed_bytes_accepted':True,'routes':sorted({v['route'] for v in mutated['mismatches']}),'gaps':mutated['gaps']})
    core,path,n=fixture('malformed',canonical=False,count=1)
    path.write_text('openapi: [broken',encoding='utf-8'); report=d.analyze_api_spec_drift(core)
    assert report['specs_parsed']==1 and report['mismatches']==[] and report['gaps']==[]
    emit('malformed_spec_false_parsed',{'specs_parsed':report['specs_parsed'],'mismatches':report['mismatches'],'gaps':report['gaps']})
    text="router.get('/secured', requireAuth, secured);\n"+'\n'*40+"router.get('/orders/:id', plain);\n"
    handlers=d.extract_multilang_route_handlers('src/routes.ts',text)
    observed=next(v for v in handlers if v['route']=='/orders/:id')
    assert 'requireAuth' in observed['observed_guards']
    emit('unrelated_route_guard_leak',{'route':observed['route'],'line':observed['line'],'observed_guards':observed['observed_guards']})
    optional=d._parse_openapi_spec_operations(json.dumps({'openapi':'3.0.3','paths':{'/orders':{'get':{'security':[{}, {'bearerAuth':[]}]}}}}),'api/openapi.json','source-id')
    assert optional[0]['requires_auth'] is True
    emit('optional_auth_misclassified',{'security':[{}, {'bearerAuth':[]}],'requires_auth':optional[0]['requires_auth']})
    core,_,_=_build_core(root/'same-line',source_files=[('src/orders.ts',b"router.get('/orders/:id', h1); router.get('/orders/:id', h2);\n",'TypeScript')])
    ledger=d.analyze_document_hunts(core,publish_review_packages(core)); candidate=ledger['candidates'][0]
    assert candidate['mapping_status']=='unique' and len(candidate['implementation_evidence'])==1
    emit('same_line_false_unique',{'literal_registrations':2,'mapping_status':candidate['mapping_status'],'evidence_count':len(candidate['implementation_evidence'])})
    one='openapi: 3.0.3\npaths:\n  /orders/{id}:\n    get: {}\n'
    py=[('src/routes.py',b'@app.route("/orders/<id>", methods=["GET", "POST"])\ndef orders():\n    return "ok"\n','Python')]
    core,_,_=fixture('methods',text=one,canonical=False,sources=py)
    report=d.analyze_api_spec_drift(core)
    assert report['handlers_scanned']==2 and report['mismatches']==[]
    emit('undocumented_method_lost',{'handlers_scanned':2,'documented_method':'GET','mismatches':[]})
    graphql=d._parse_graphql_or_proto_operations({'format':'graphql'},'type User {\n  id: ID!\n}\ntype Query {\n  user: User\n}\n')
    proto=d._parse_graphql_or_proto_operations({'format':'protobuf'},'service A { rpc One (Req) returns (Rsp); }\nservice B { rpc Two (Req) returns (Rsp); }')
    assert [v['route'] for v in graphql]==['/graphql#id','/graphql#user'] and [v['route'] for v in proto]==['/A/One','/A/Two']
    emit('non_http_spec_extraction',{'graphql_routes':[v['route'] for v in graphql],'protobuf_routes':[v['route'] for v in proto]})
    print(json.dumps({'checks':len(rows),'elapsed_seconds':round(time.monotonic()-start,3),'scratch':str(root),'cleanup':'removed'},sort_keys=True))
finally:
    shutil.rmtree(root)
```

Successful result: **9 checks**, **0.767 s**, exit 0; scratch `test/tmp/job-audit-document-issues-repro-c2a1ca1fd8be437987917a6464485185` removed. These assertions deliberately confirm buggy outputs; they are **not nine passing correctness regressions**.

Earlier attempt used the identical body except `assert observed['observed_guards']==['requireAuth']`. It completed the first four checks, then failed that assertion (exit 1); elapsed was not emitted because the assertion preceded the final timer. Cleanup still ran. The following read-only diagnostic confirmed the extra matched `secured` token:

```bash
.venv/bin/python - <<'PY'
from appsec_review.document_issues import extract_multilang_route_handlers
text="router.get('/secured', requireAuth, secured);\n"+'\n'*40+"router.get('/orders/:id', plain);\n"
print(extract_multilang_route_handlers('src/routes.ts',text))
PY
```

Diagnostic exit 0; elapsed not captured. The rerun corrected the reproduction's expected token set, not repository behavior or test assertions.

## Read scope and material gaps

**Read fully:** updated brief; authorized AGENTS and multi-session skill; all three production files in `jobs/job_document_issue_analysis/`; all of `document_issues.py`; both ledger/drift JSON Schemas; all three job unit test files and unit-package `__init__`; all of `tests/unit/test_t172_indexing_and_retrieval.py`; `tests/unit/conftest.py`; environment guard; `tests/handoff_fixture.py`; `indexing/store.py`; `indexing/products_base.py`; `runtime/units.py`; document-evidence architecture, authored document-issue operations page, and T-172 task document; wrapper shell scripts.

**Read targeted sections/searches:** canonical generated operations page lines 1-230 and 936-1024 (middle generated Mermaid duplicates already-read contract declarations); config loader/TOML; registry/topology; `review_packages.py` document-hunt construction, membership, publication and complete verification paths; source/document producer publication; canonical collector parsing/emission; canonical security-state parser; `products.py` document-context derivation; retrieval manifest resolution/materialization and complete `query_doc_drift`; immutable/shared-cache implementation; runtime input observation boundaries and inventory ownership; inference scope/package seams; review package rank/assembly entry points; wrapper Python supervisor/report; root conftest first 280 lines; TODO T-059/T-147/T-172 and relevant searches; historical C10-F04/F05/F07 and prior session-report searches.

**Unread/unexecuted gaps:** full generic runtime runner/admission/repair implementation, every transitive producer/parser, full inference package/cell/claim pipeline, the rest of the large generated diagram, broad architecture beyond directly relevant pages, unrelated T-172 tests, cross-job schema/read-receipt suites, production dataset inventory and handoff publication via JobRunner, all integration/acceptance/live tests, replay under real runtime interruption, installed framework/tool behavior, real target output and independent finding usefulness. `tests/test_target_document_pipeline.py` was inspected through its graph-building fixture and not executed; its mapped tests are integration paths, not a means to obtain green unit coverage.

No model response contracts apply to the job's own task. Optional adjudication dictionaries are not model invocations. No code was fixed; no TODO or cumulative report was edited. Final repository HEAD remained exact and `git status --short` empty. Only this session report and wrapper-owned ignored test artifacts were retained; reproduction scratch was removed.
