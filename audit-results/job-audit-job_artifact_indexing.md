# Job 14/47 audit — job_artifact_indexing

## Scope and verdict

- Audited **main, `0e54e40b8530639f114fb0cbadb3633f9d3a4cfe`**, in `/home/wsollers/projects/appsec-review` on `wsl-ubuntu` / Ubuntu-22.04, not the dirty Windows checkout.
- HEAD and tracked/untracked Git cleanliness were verified before collection, execution and at the end. The editable import resolved to `/home/wsollers/projects/appsec-review/src/appsec_review/__init__.py`. Required ancestor check passed; production-environment detector returned `[]`.
- This is a read-only functional source audit, not live acceptance or a vulnerability assessment. No source/configuration/environment installation, service operation, real scanner/compiler/provider, integration test, target execution or nested agent was used.
- **Three medium findings**, demonstrated in six small synthetic reproductions: stale shard reuse, batch-ordinal cache collisions, and incorrect exact link attribution. All **190 existing focused units passed**. Passing units do not cover these failing behavioral expectations or certify real review outputs.
- Only this report was added outside test scratch. Reproducer scratch was removed; wrapper evidence remains under its unique `test/tmp/` run names. No commit or push.

## Registration, configuration and contract

`runtime/registry.py:80,150` imports/registers the real factory. `datasets.py:35-76` declares review-graph dispatch, target checkout access, `schedule_after=("job_language_build",)`, `always_execute=False`, and propagated handoffs. The executable graph projection returned exactly `("job_language_build",)` as immediate predecessors; target catalog is a semantic input available through the preceding graph, not an undeclared intake read.

The dev job is **registered and enabled**: `appsec-review.toml:1535-1559` supplies no `settings.enabled`; `runtime/selection.py:11-24` therefore enables it. There is no job-local optional feature flag or configurable inventory limit. The job validator accepts exactly six nonempty identity strings and exact step/task order (`job.py:944-955`):

| Setting | Actual use |
| --- | --- |
| `catalog_parser_identity` | Produced and target catalog fingerprints, `job.py:608,649` |
| `member_extractor_identity` | Member entity payload and batch fingerprint, `:765,816` |
| `member_parser_identity` | Member batch fingerprint, `:817` |
| `relationship_parser_identity` | Relationship batch fingerprint, `:931` |
| `normalizer_identity` | Produced/target catalog and batch fingerprints, `:609,650,738` |
| `mapping_identity` | Produced catalog and batch fingerprints, `:610,739`; target intake deliberately uses `exact-target-path/1` |

These are version identity labels for the implemented functions, not dynamically selected parsers. Job/index-step worker budgets are 8; load/acceptance step budgets are 1; each empty task table defaults to one worker (`config/loader.py:1231,1236`). Direct `UnitExecutor.execute` walks declared units serially (`runtime/units.py:83-145`); Dagster creates one op per unit/dependency and calls the real runner (`orchestration/dagster/adapter.py:250-278`). Per-receipt shard work remains sequential as documented. No model, task prompt, persona or runtime-skill call was found in this job; its ID has no guidance-registry entry. Missing authoritative no-launch task bindings remain **T-147**, not evidence derived merely from absent documentation.

### Admitted inputs and actual reads

All 14 requirements use the handoff channel, producer-evidence authority and allow-partial coverage:

| Producer | Dataset and schema | Availability |
| --- | --- | --- |
| language build | `handoff`: `appsec-review/job-handoff/2`; `language_build_receipts`: `appsec-review/language-build-handoff/2` | Required / reject |
| language build | `topology_refinement_inputs`: `appsec-review/build-topology-refinement/1` | Optional / gap |
| language build | `build_actions`, `jvm_build_actions`: `appsec-review/retrieval-index/2` | Optional / gap |
| language build | `build_workspaces`: `application/octet-stream` | Optional / gap |
| target catalog | `handoff`: `appsec-review/job-handoff/2` | Optional / gap |
| target catalog | `target_artifact_inputs`: `appsec-review/target-artifact-intake/1` | Optional / gap |
| target catalog | `source_files`, `declaration_symbols`, `components`, `target_documents`, `build_units`: `appsec-review/retrieval-index/2` | Optional / gap |
| target catalog | `catalog_documents`: `appsec-review/target-catalog/1` | Optional / gap |

Evidence: `jobs/job_artifact_indexing/datasets.py:36-69`; all producer dataset/schema matches are asserted by the focused contract tests.

Actual loading follows `load_accepted_language_build` (`jobs/job_language_build/job.py:136-173`), the accepted language manifest (`job_artifact_indexing/job.py:374-390`), receipt workspace manifests and individual artifact bytes (`:393-516`), and `_target_artifacts` (`:123-164`). The latter calls `load_target_catalog(..., intake_target_root=False)`: the shared reader reads the catalog document plus partition/projects/build-targets/compile-command JSON (`job_evidence_collection/job.py:167-205`), **not** `job_review_intake`.

`runtime/consume.py:162-201,228-230` requires a declared envelope and claim-admitted digest, and records envelope reads. Manifest verification checks all referenced shards; declaring all upstream datasets does not establish that every one was queried or cited. Raw private artifact reads do not individually prove dataset consumption; that shared instrumentation limitation is documented in `docs/architecture/job-input-contracts.md`. No other-job `latest.json` lookup is present in this job.

## Every step/task and processing boundary

All five units are reachable and match TOML order. Publication depends on all three index units; each index unit depends on load. There are no per-unit validators, job output validator, or result transform; `_validate_config` is the job input validator (`job.py:1050-1066`).

| Step/task | Actual implementation and outputs | Mismatch or coverage limit |
| --- | --- | --- |
| `load.accepted_builds` | Nested `load`, `job.py:980-1002`; pins source fingerprint, language manifest and receipt set; validates receipts; reads optional target intake; returns receipts/count, target records/catalog hash, language hash, manifest and deduplicated reasons. | Required absence rejects; optional/legacy intake and empty receipt set become gaps. Handler and validation units passed; real admission/whole-job execution not run. |
| `index.catalogs` | `_catalogs`, `:591-671`; groups validated artifacts by canonical family within each receipt, one family shard; separate target-intake shard. Filters produced payload fields, retains scope/mapping/source-map/package metadata; returns index identities, shard/reuse counts and load gaps. | **AI-01:** fingerprints omit indexed payload fields. Target-intake coverage is partial with unknown-delivery reasons; loader carries those into job gaps. |
| `index.members` | `_members`, `:783-823`; joins `package_members` by normalized package path; sorts member rows, validates path/size/hash, creates archive-member entities plus exact `CONTAINS` relations; batches packages per receipt. | **AI-01/02.** No archive opening occurs. Only produced package artifacts are enumerated; target intake contributes catalog rows, not invented member manifests. Missing member rows yield partial coverage. |
| `index.relationships` | `_relationships`, `:906-936`; one receipt lookup context, per-artifact producing-action and linker relationships, deterministic batches. `_artifact_relations`, `:826-904`, retains heuristic/exact distinctions, strongest duplicate link observations, capped provenance. | **AI-01/02/03.** Unattributed outputs fan out to all command candidates at 0.25 with a gap; no commands yield a missing-provenance gap. This known O(outputs × commands) behavior is not a new finding. |
| `acceptance.publish_handoff` | Nested `publish`, `:1004-1048`; verifies inherited manifest, retains all non-`artifacts` indexes, replaces the artifact set, writes/verifies the composite manifest and summary; deduplicates all load/branch reasons. | Existing tests verify replacement, manifest/hash refusal, logical and shard counts, target/repository root and gap status. No real runner acceptance or corpus-output comparison performed. |

### Inventories, identities, counts and bounds

- Produced artifact identity binds snapshot, receipt build unit, normalized workspace path, SHA-256 and format (`:104-114`). Target identity instead binds `origin=target-intake`, target path/hash/format (`:117-121`). The two origins stay distinct even for equal bytes.
- Classification (`:70-87`): object → object_file; static/shared/library → library; executable/native-output → executable; wheel/sdist/JAR/WAR/EAR/package/archive → package; bytecode/Python bytecode/JVM class/DEX/LLVM bitcode → bytecode_module; managed assembly and Wasm module/component have separate families; other retained kinds → build_artifact. The code does not rediscover or silently exclude upstream artifacts by directory.
- Receipt validation (`:412-516`) rejects schema/unit duplicates, conflicting source identity, malformed artifact lists, artifacts on non-`SUCCEEDED` receipts, missing/changed workspace manifests, invalid bytes/size/membership and duplicate canonical artifact identities. Node additionally requires exact unit/path mapping, recognized origin and bounded integrity metadata. Retained shared-object references are verified through the real shared-store reader.
- Archive-member identity binds parent/path/size/optional SHA-256; unsafe paths and duplicate *identities* reject (`:167-197,761-780`). Rows with no corresponding package are not separately inventoried. Same member path with different size/hash is not the duplicate-identity case; this ambiguity was not promoted to a new defect without an established unique-path requirement.
- `_ReceiptContext.build` indexes commands, outputs, relationships and artifacts once (`:247-281`). Producing build-action identities (`:283-290`) match the upstream aggregate build-action identity at `job_language_build/job.py:1792-1794`.
- Batches sort artifacts by `(workspace_path, sha256)` and greedily pack at 5,000 artifacts / 100,000 rows (`:690-706`). One oversized artifact receives a lone shard; these are packing targets, not hard per-artifact row caps. Link observations retain at most 500 entries and preserve total observation count plus a truncation gap (`:877-890`).
- `receipt_count` counts receipts, including unsuccessful receipts. `artifact_count` sums validated receipt artifacts plus target-intake artifacts. `artifact_shard_count` and publication `item_count` count **shards**, not artifacts/members/links. `reused_shard_count` sums all index branches (`:1026-1045`). No independent overall member/link count is asserted in the summary.
- Telemetry declares/counts processed artifacts and receipts; relationship invocations are counted once per receipt (`:595-604,789-810,912-919`). Existing tests check receipt-pass complexity and logical row counts, not live telemetry completeness or throughput.

## Schemas, publication and consumers

| Output | Actual layout and declaration |
| --- | --- |
| `artifact_catalog` | `artifacts` retrieval index `/2`, `catalog-` shard prefix |
| `archive_members` | Same index/schema, `members-` prefix |
| `artifact_relationships` | Same index/schema, `relations-` prefix |
| `artifact_index_summary` | `appsec-review/artifact-indexing/1`; `data/jobs/job_artifact_indexing/attempts/*/artifacts/artifact-indexing/*.json`; artifact-only declaration also claims `data/indices/artifacts/*.lock` |

Evidence: `datasets.py:12-29`; focused tests verified emitted shard-prefix ownership and summary glob/schema. Shards live at `data/indices/artifacts/<fingerprint>.sqlite`; the merged manifest is `data/indices/manifests/artifact-indexing-<attempt>.json`; summary is `accepted-index.json` (`job.py:585-588,1017-1043`). Lock claims are artifact-only metadata, not JSON summary payloads. No separate closed domain-summary schema validator was found; explicit schema checks and shared control-record validation have distinct scope.

Under a shard lock, `_finish_shard` verifies existing metadata/SQLite integrity, hashes and attests the existing bytes, otherwise builds (`:519-571`). `IndexBuilder.build` provides deterministic row sorting/deduplication, atomic placement and owner-dependent custody (`retrieval/index.py:112-218,230-250`). The manifest verifier checks hash/schema/snapshot/upstreams/shard metadata and complete relation endpoint closure (`retrieval/index.py:389-532`); it does not establish that the producer selected the right rows, which is why AI-01/03 survive structural checks.

Success/empty/partial branches use valid `SUCCEEDED`, `NOT_APPLICABLE`, `COMPLETED_WITH_GAPS` values. The job retains legacy string reasons (`strict_gaps=False`); publication normalizes them to `producer_reported_gap` records, normally nonretryable. Focused `assert_published_gaps` tests exercise the real normalization boundary. Missing receipt/intake/member/provenance work is not declared clean. Do not reinterpret nonretryable legacy reasons as advisory.

`load_accepted_artifact_index` (`job.py:958-976`) requires accepted publication, summary artifact binding/hash/schema and a verified manifest. Thirteen registered consumer contracts name this producer:

`job_artifact_security_analysis`, `job_codeql_analysis`, `job_debug_symbol_indexing`, `job_dependency_intelligence`, `job_document_issue_analysis`, `job_inference_security_review`, `job_owasp_control_assessment`, `job_profile_data`, `job_review_data_indexing`, `job_review_package_assembly`, `job_security_tagging`, `job_test_coverage`, `job_threat_model_generation`.

Material consumer boundaries inspected:

- Artifact security compares accepted language and index hashes/snapshot, verifies manifest, and combines language artifacts with target-intake references (`job_artifact_security_analysis/job.py:86-139`).
- Debug indexing compares run/snapshot/manifest and language hash before joining retained references (`job_debug_symbol_indexing/job.py:112-144`).
- Coverage/profile optionally inherit the manifest and expose disabled-producer gaps (`job_test_coverage/job.py:337-365`; `job_profile_data/job.py:292-318`).
- Dependency intelligence records the artifact-index handoff hash (`job_dependency_intelligence/job.py:313-330`).
- `RetrievalCore.query_artifacts` filters indexed payload facets and uses `GENERATED_FROM` endpoints for producing-action queries (`retrieval/core.py:885-994`). The threat-model structure lane explicitly consumes `artifact_catalog` and `LINKS_INTO` records (`threat_model/lanes/structure.py:25-45,94-95,384-385`, sampled). Wrong/stale facts therefore affect semantic consumers, not just filenames.

## Findings

### AI-01 — Medium: changed indexed facts reuse stale catalog/member/relationship shards

- **Evidence:** `src/appsec_review/jobs/job_artifact_indexing/job.py:200-232,322-350,608-610,618-629,732-741,549-563`; `src/appsec_review/jobs/job_language_build/job.py:652-688`.
- **Trigger:** same build unit/artifact bytes/configuration but changed accepted metadata, member-manifest rows or link-input/provenance rows on a later attempt.
- **Expected:** facts that change emitted entities, relations or coverage change the shard fingerprint, so a reused shard represents the current receipt.
- **Actual:** artifact fingerprint input retains path/hash/size/format and a partial receipt projection, not catalog payload fields, `package_members`, receipt relationship rows, or invocation `inputs`/observation fields. `_write_batches` passes artifacts and layout, **not the generated row content**. The upstream `receipt["fingerprint"]` is a pre-execution recipe/dependency/configuration fingerprint, not a hash of the receipt contents; it cannot repair this omission.
- **Reproductions:** (1) changed `delivery_status` unknown→delivered: `reused_count=1`, stored payload remained unknown; (2) member old.py→new.py: `reused_count=1`, SQLite retained old.py; (3) removed link input: fresh pure builder expected zero `LINKS_INTO`, rerun reused one old link.
- **Impact:** a new accepted summary/manifest can refer to stale scope, members, producing/link facts or coverage under a valid structural/hash identity. Row counts need not change, and current tests of identical-input reuse miss this.
- **Confidence:** high for the real helper/cache behavior, not a claim that a live retry exhibited it.
- **Smallest correction:** bind the complete canonical emitted entity/relation/coverage projection, or all fields that determine it, into each shard fingerprint. Add changed-input-after-reuse tests, not just fresh-index and identical-input tests.
- **TODO/prior overlap:** no matching artifact-index entry found in the searched TODO registry/reports. Prior language-build report **LB-F02** describes the same class of omission in a *different JVM producer*; this finding is not a duplicate of that code path. `docs/operations/job_artifact_indexing.md` “Resume and invalidation” incorrectly says member/relationship fingerprints bind row content; reconcile with the fix. T-147 does not resolve cache identity.

### AI-02 — Medium: adding an earlier batch makes a valid existing shard fail as corrupt metadata

- **Evidence:** `src/appsec_review/jobs/job_artifact_indexing/job.py:709-713,730-745,519-529,585-588`.
- **Trigger:** an existing package/member or relationship batch retains its artifact set but moves from ordinal N to N+1 after earlier sorted artifacts form a new complete batch.
- **Expected:** deterministic repartitioning either reuses a compatible identity or builds a new shard without treating valid old bytes as corruption.
- **Actual:** path/fingerprint bind artifact set and layout but omit batch ordinal/shard ID. The same fingerprint path is now opened with a different expected `members-...-NNNN` / `relations-...-NNNN`; `_verify_shard` rejects its old embedded shard ID.
- **Reproduction:** set the in-process packing limit to 1, index z.whl as batch 0000, add a.whl ahead of it, then re-index. The real `_members` raises `ArtifactIndexIntegrityError: completed artifact shard metadata changed` when z.whl becomes 0001. Same algorithm applies at the shipped limit; no source/configuration was edited.
- **Impact:** a legitimate incremental receipt can fail indexing/publication until cache identities are corrected; merely retrying unchanged input repeats the collision.
- **Confidence:** high; real SQLite-backed handler reproduction. Not a corrupt-disk or real-scale test.
- **Smallest correction:** include physical shard ID/batch ordinal in the fingerprint or use a content-stable shard-ID scheme, so the path and verified metadata describe the same identity. Cover full-batch insertion/removal before an unchanged later batch.
- **TODO overlap:** no matching entry found. This is separate from AI-01: even with row content fingerprinted, unchanged rows can move to another ordinal.

### AI-03 — Medium: conflicting or ambiguous link inputs become exact, order-dependent edges

- **Evidence:** `src/appsec_review/jobs/job_artifact_indexing/job.py:277-281,855-870`.
- **Trigger:** a captured link input names an existing workspace path with a different SHA-256, or its path is unknown while multiple validated artifacts have the same SHA-256.
- **Expected:** both supplied identity fields agree for exact attribution; duplicate-hash candidates must remain ambiguous rather than choosing a path by receipt order.
- **Actual:** path lookup ignores the supplied hash. Hash fallback uses a one-value dictionary, silently keeping the last artifact with that digest. It then trusts input `mapping_confidence=1.0` and emits `exact=True` with no gap.
- **Reproductions:** (1) changed input hash to 64 zeroes while retaining the object path: the unrelated current object received an exact 1.0 edge, gaps empty; (2) equal-byte a.o and b.o with unknown input path: order `[a,b]` selected b.o, reversed order selected a.o; both exact, gaps empty.
- **Impact:** retained build/link provenance can identify the wrong logical artifact and change with input order. Structural relation-closure checks still pass because the selected endpoints exist.
- **Confidence:** high; real pure relationship builder and canonical artifact identities.
- **Smallest correction:** require path/hash agreement when both exist; index digest to candidate lists; reject inconsistent identity or retain explicit ambiguous mappings/gaps when multiple candidates exist. Do not strengthen a hash-only ambiguous match from a confidence field.
- **TODO overlap:** no matching entry found; the documented all-command 0.25 attribution fallback is a different, explicitly ambiguous case.

## Known overlap and unresolved questions, not additional verified defects

- **T-054 / historical job pass 14:** catalog-only intake read is already repaired. `intake_target_root=False` is present and covered; do not reopen the old undeclared-intake defect.
- **T-113:** historical progress records 9 files/171 units and 40 failing old integration cases at `05ac85ae`; current map/collection has 10 files/190 units. Old integration failure statements are historical, not failures observed in this audit.
- **T-147:** authoritative task bindings remain undeclared. This audit established no-launch behavior by reading handlers, without adding a parallel registry.
- **T-164:** all newly constructed identities here include `producer["job"]`, so that known missing-owner defect was not reproduced for this producer.
- **T-5039:** `_validate_receipts` still uses `terminal_status == "SUCCEEDED"` rather than `build_outcome`. A synthetic built-with-gaps receipt containing artifacts would be refused, but the inspected current native enforcement path moves rejected artifacts out when it changes status (`job_language_build/job.py:1672-1687`). No current accepted producer path retaining artifacts with that status was established here. Treat as a known migration/contract question, **not** permission to restore rejected bytes or a claimed additional live failure.
- Duplicate member paths with different identities, raw noncanonical artifact path normalization, and independently valid-but-inconsistent summary/manifest fields were not exhaustively adversarially tested. No speculative integrity findings are counted for them.

## Focused validation record

All Linux commands were sent through the brief's PowerShell base64 transport:

```powershell
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script.Replace("`r",'')))
ssh -o BatchMode=yes -o ConnectTimeout=15 wsl-ubuntu "printf %s $encoded | base64 -d | bash"
```

Working directory for every Linux command: `/home/wsollers/projects/appsec-review`.

### Collection

```bash
git rev-parse HEAD
git branch --show-current
git status --short
.venv/bin/python -c 'import appsec_review; print(appsec_review.__file__)'
git merge-base --is-ancestor 0e54e40b8530639f114fb0cbadb3633f9d3a4cfe HEAD
.venv/bin/python -m pytest --collect-only -q \
  --basetemp=test/tmp/job-audit-job_artifact_indexing-collect-20261118-1741 \
  tests/unit/job_artifact_indexing
```

Environment preflight imported `offending_environment` from `tests.test_000_unit_environment_guard`, printed and asserted an empty result. Collection: **190 tests, 0.82 s pytest / 2.028 s shell**, exit 0. No tests executed at this stage.

### Refused initial wrapper selector

```bash
scripts/run-tests.sh --expect-tests 190 --parallel --test-workers 2 \
  --shuffle-seed 181114 --strict -- tests/unit/job_artifact_indexing | tail -n 38
```

The wrapper rejected the directory selector: `selector must name an existing, unredirected test file under tests/`. **No tests executed**, elapsed **0.190 s**. The first shell pipeline lacked `pipefail`, so the shell tool returned 0 from `tail`; that is not a validation pass. The corrected command below used `set -euo pipefail` and explicit reviewed files.

### Execution

```bash
scripts/run-tests.sh --expect-tests 190 --parallel --test-workers 2 \
  --shuffle-seed 181114 --strict -- \
  tests/unit/job_artifact_indexing/test_catalogs.py \
  tests/unit/job_artifact_indexing/test_contract.py \
  tests/unit/job_artifact_indexing/test_handler_wiring.py \
  tests/unit/job_artifact_indexing/test_identities.py \
  tests/unit/job_artifact_indexing/test_job_graph.py \
  tests/unit/job_artifact_indexing/test_members.py \
  tests/unit/job_artifact_indexing/test_receipt_validation.py \
  tests/unit/job_artifact_indexing/test_relationships.py \
  tests/unit/job_artifact_indexing/test_shards.py \
  tests/unit/job_artifact_indexing/test_target_artifacts.py | tail -n 40
```

The wrapper owned `test/tmp/tests-custom-20261118-121421-072661-2758794`, its collection proof and report; it never used the shared default base temp. Execution was `-n 2 --shuffle-seed=181114`; both collection and execution supervisors reported cleanup confirmed, zero remaining processes.

**190 passed, 0 failed/error/skipped, none >10 s.** Pytest **5.35 s**; wrapper report total **12.069 s**; measured shell **12.299 s**. Slowest case: `test_job_graph.py::test_shipped_configuration_passes_validation_and_names_the_six_identities`, **0.7361 s**.

| File under `tests/unit/job_artifact_indexing/` | Passed |
| --- | ---: |
| test_catalogs.py | 5 |
| test_contract.py | 10 |
| test_handler_wiring.py | 3 |
| test_identities.py | 61 |
| test_job_graph.py | 9 |
| test_members.py | 6 |
| test_receipt_validation.py | 49 |
| test_relationships.py | 21 |
| test_shards.py | 10 |
| test_target_artifacts.py | 16 |

Evidence paths, relative to the authorized checkout:

- `test/tmp/reports/tests-custom-20261118-121421-072661-2758794.json` — exact expanded pytest command, counts, supervisor outcomes and elapsed.
- `test/tmp/logs/tests-custom-20261118-121421-072661-2758794.log`
- `test/tmp/logs/tests-custom-20261118-121421-072661-2758794.collection.log`
- `test/tmp/tests-custom-20261118-121421-072661-2758794.collection.json`
- `test/tmp/tests-custom-20261118-121421-072661-2758794.junit.xml`
- `test/tmp/tests-custom-20261118-121421-072661-2758794.timings.sqlite`

### Six reproductions

Executed with `.venv/bin/python - <<'PY'` after exact-HEAD/cleanliness guards. The following code is the executed reproduction body (imports and scratch retained for rerun clarity); it exercises actual job helpers with synthetic receipt/context boundaries, not a whole job/runner:

```python
import copy, json, shutil, sqlite3, time
from pathlib import Path
from appsec_review.jobs.job_artifact_indexing import job as j
from appsec_review.retrieval import RelationKind
from tests.unit.job_artifact_indexing.support import SNAPSHOT, loaded_output, unit_context, validated_artifact, validated_receipt
root = Path('test/tmp/job-audit-job_artifact_indexing-repro-20261118-1748').resolve()
assert not root.exists()
root.mkdir(parents=True)
started = time.monotonic()
def ctx(area, task, receipt):
    return unit_context(root / area, task, {'load.accepted_builds': loaded_output([receipt])})
def sql(area, result, query):
    with sqlite3.connect(f"file:{root / area / result['indexes'][0]['relative_path']}?mode=ro", uri=True) as db:
        return db.execute(query).fetchall()
try:
    r = validated_receipt(0)
    r['validated_artifacts'][0]['delivery_status'] = 'unknown'
    first = j._catalogs(ctx('catalog', 'index.catalogs', r))
    r['validated_artifacts'][0]['delivery_status'] = 'delivered'
    again = j._catalogs(ctx('catalog', 'index.catalogs', r))
    value = json.loads(sql('catalog', again, 'SELECT payload_json FROM entities')[0][0])['delivery_status']
    assert again['reused_count'] == 1 and value == 'unknown'
    print('REPRO A1 catalog: requested delivered; reused=', again['reused_count'], 'stored=', value)

    r = validated_receipt(0)
    r['validated_artifacts'] = [validated_artifact('dist/a.whl', 'wheel', 'package')]
    r['package_members'] = [{'package_path':'dist/a.whl', 'member':'old.py', 'size_bytes':1}]
    first = j._members(ctx('members', 'index.members', r))
    r['package_members'] = [{'package_path':'dist/a.whl', 'member':'new.py', 'size_bytes':1}]
    again = j._members(ctx('members', 'index.members', r))
    names = sql('members', again, 'SELECT native_id FROM entities')
    assert again['reused_count'] == 1 and names == [('old.py',)]
    print('REPRO A2 members: requested new.py; reused=', again['reused_count'], 'stored=', names)

    r = validated_receipt(1)
    first = j._relationships(ctx('relations', 'index.relationships', r))
    r['tool_invocations'][-1]['inputs'] = []
    expected_links = [row for row in j._artifact_relations(j._ReceiptContext.build(r, SNAPSHOT), r['validated_artifacts'][-1]).relations if row.kind is RelationKind.LINKS_INTO]
    again = j._relationships(ctx('relations', 'index.relationships', r))
    links = sql('relations', again, "SELECT count(*) FROM relations WHERE kind='LINKS_INTO'")[0][0]
    assert not expected_links and again['reused_count'] == 1 and links == 1
    print('REPRO A3 relationships: expected links=0; reused=', again['reused_count'], 'stored links=', links)

    limit = j.MAX_ARTIFACTS_PER_SHARD
    j.MAX_ARTIFACTS_PER_SHARD = 1
    r = validated_receipt(0)
    r['validated_artifacts'] = [validated_artifact('z.whl', 'wheel', 'z')]
    r['package_members'] = [{'package_path':'z.whl', 'member':'z.py', 'size_bytes':1}]
    first = j._members(ctx('ordinal', 'index.members', r))
    r['validated_artifacts'].insert(0, validated_artifact('a.whl', 'wheel', 'a'))
    r['package_members'].insert(0, {'package_path':'a.whl', 'member':'a.py', 'size_bytes':1})
    try:
        j._members(ctx('ordinal', 'index.members', r))
    except j.ArtifactIndexIntegrityError as exc:
        assert str(exc) == 'completed artifact shard metadata changed'
        print('REPRO B batch insertion:', type(exc).__name__, str(exc))
    else:
        raise AssertionError('expected batch ordinal collision')
    j.MAX_ARTIFACTS_PER_SHARD = limit

    r = validated_receipt(1)
    source, output = r['validated_artifacts']
    r['tool_invocations'][-1]['inputs'][0]['sha256'] = '0' * 64
    rows = j._artifact_relations(j._ReceiptContext.build(r, SNAPSHOT), output)
    link, = [row for row in rows.relations if row.kind is RelationKind.LINKS_INTO]
    assert link.source_id == source['canonical_identity'] and link.exact and link.confidence == 1.0
    assert not rows.gaps
    print('REPRO C1 conflicting hash: input=', '0'*64, 'selected=', source['sha256'], 'exact=', link.exact, 'gaps=', rows.gaps)

    r = validated_receipt(0)
    output = r['validated_artifacts'][0]
    left = validated_artifact('a.o', 'object', 'same-bytes')
    right = validated_artifact('b.o', 'object', 'same-bytes')
    r['validated_artifacts'] = [left, right, output]
    r['tool_invocations'][-1]['inputs'] = [{'workspace_path':'missing.o', 'sha256':left['sha256'], 'mapping_confidence':1.0}]
    def chosen():
        rows = j._artifact_relations(j._ReceiptContext.build(r, SNAPSHOT), output)
        link, = [row for row in rows.relations if row.kind is RelationKind.LINKS_INTO]
        return link.source_id, link.exact, rows.gaps
    first = chosen()
    r['validated_artifacts'] = [right, left, output]
    second = chosen()
    assert first[0] == right['canonical_identity'] and second[0] == left['canonical_identity']
    assert first[1:] == second[1:] == (True, [])
    print('REPRO C2 duplicate hash: order a,b selects b.o; order b,a selects a.o; both exact=True; gaps=[]')
    print('reproductions: 6 assertions passed; elapsed_s=', round(time.monotonic()-started, 3))
finally:
    shutil.rmtree(root)
```

All six **defect-demonstrating assertions** passed, measured body elapsed **0.054 s**, exit 0. These are reproduced wrong behaviors, not six correctness tests passing. No real bytecode/package/linker artifact was executed or opened as an archive.

## Read scope and explicit gaps

**Read fully:** assigned brief; authorized `AGENTS.md`; multi-session coordination skill; job `__init__.py`, `datasets.py`, all `job.py`; both artifact-indexing operations documents; historical `docs/tasks/2026-11-11-job-pass-14-artifact-indexing.md`; all ten mapped job unit test files and `support.py`; unit-tier conftest; environment-guard test; `jobs/build_outcome.py`; `scripts/run-tests.sh`, `scripts/lib/common.sh`.

**Read in relevant ranges/searches:** central TOML job block; config loader records/defaults; registry imports/registration and contract projection; topology through graph-description setup; Dagster unit-op adapter; runtime selection, units, consume; interchange control/status validation; retrieval index builder/manifest verification and `query_artifacts`; language-build accepted loader/fingerprint/package-member generation/receipt/enforcement/build-index publisher; catalog shared loader; downstream loader boundaries above; structure-lane contract/read sites; test map job section; testing architecture beginning/working guidance; job-interchange control layer; job-input-contracts through admission discussion; accepted-index architecture sections; wrapper command/build/supervision/parser sections; root conftest through collection ordering. TODO searched by job/fingerprint/member/link/shard, with relevant T-054/T-113/T-147/T-164/T-5039 entries inspected. Prior session reports were searched for overlap; language-build LB-F01/F02 were read.

**Material unread/unexecuted scope:**

- No live or run-owned evidence, actual accepted artifact inventory, independently counted real corpus, real retry/recovery, throughput benchmark, durability/crash test or model/scanner output quality was verified.
- Four mapped integration files and two acceptance selectors were **not executed**. Their current assertions/fixtures were not read comprehensively; historical failure claims are not revalidated.
- Full runner/claim/admission/signing/custody internals and all 13 consumers were not audited end-to-end; only directly necessary boundaries were inspected. The focused tests mock accepted-upstream/context boundaries, so they do not validate complete dataset read receipts, admission or final acceptance.
- No domain-wide archive-format/extractor accuracy, full language-producer matrix, Swift-disabled pipeline, task scheduling/concurrency or genuine large-scale bounds validation was run. Shared helpers not listed above and the remainder of broad architecture/TODO documents remain unread.
- Searches initially attempted nonexistent schema/config paths (`schemas`, `src/appsec_review/interchange/`, `config/model.py`); these failed harmlessly and were followed by the actual `interchange.py`, `config/loader.py` and documented domain-owned schema boundary.

The report is the persistent deliverable; corrections and live validation require separate authorization.
